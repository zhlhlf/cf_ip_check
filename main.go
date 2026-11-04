// cfip 批量筛选 Cloudflare 优选 IP。
//
// 两种探测模式, 由 cf.env 里是否配置 PASSWORD 决定:
//
//   - 纯 TCP 模式 (PASSWORD 为空, 默认): 只做 TCP 三次握手。零配置即可运行,
//     但 TCP 握手在 Cloudflare anycast 网络里几乎恒定为 70ms 左右, 只能筛掉
//     完全不可达的 IP, 不反映真实可用性和速度。
//   - TLS+WS 模式 (配置了 PASSWORD): 执行完整握手 TCP -> TLS 1.3 -> HTTP
//     Upgrade 101, 只有真正返回 101 的 IP 才算可用, 并可继续用 xray 隧道做
//     真实吞吐测速。
//
// cf.env.example 已内嵌进二进制: 首次运行找不到 cf.env 时会自动生成一份。
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

// envTemplate 是编译进二进制的配置模板, 首次运行时写到 cf.env。
//
//go:embed cf.env.example
var envTemplate []byte

const (
	maxCIDRs   = 4096
	maxIPs     = 20000
	maxLineLen = 16384

	// clashIPCount 是写回 clash 配置时改写的代理条目数。
	clashIPCount = 16

	defaultPort    = 2096
	defaultPath    = "/"
	defaultSample  = 4096
	defaultRounds  = 3
	defaultTop     = 20
	defaultWorkers = 200

	// 默认超时按探测深度区分: 链路越长越容易在抖动时被误杀。
	tcpTimeout = time.Second
	tlsTimeout = 2 * time.Second
	wsTimeout  = 2200 * time.Millisecond

	// cidrFetchTimeout 是单个源的等待时间; 源之间串联, 最坏情况是条数 x 该值。
	cidrFetchTimeout = 5 * time.Second
)

// cidrSources 是在线 CIDR 列表的下载地址, 按顺序逐个尝试, 第一个可用的胜出。
//
// 第一条是 GitHub 直连; 后面是几个常用的加速镜像 (写法是把完整 URL 拼在域名后,
// jsdelivr 除外, 它有自己的 gh/<user>/<repo>@<ref> 路径)。镜像随时可能失效,
// 所以不做"首选某个镜像"的假设, 只保证一个挂了能自动试下一个。
const cidrRepoPath = "cmliu/cmliu/main/CF-CIDR.txt"

var cidrSources = []string{
	"https://raw.githubusercontent.com/" + cidrRepoPath,
	"https://ghfast.top/https://raw.githubusercontent.com/" + cidrRepoPath,
	"https://gh-proxy.com/https://raw.githubusercontent.com/" + cidrRepoPath,
	"https://ghproxy.net/https://raw.githubusercontent.com/" + cidrRepoPath,
	"https://cdn.jsdelivr.net/gh/cmliu/cmliu@main/CF-CIDR.txt",
}

// version 由构建时注入: -ldflags "-X main.version=xxx"
var version = "dev"

var fallbackCIDRs = []string{
	"162.159.32.0/20",
	"104.18.32.0/20",
	"172.64.144.0/22",
	"108.162.198.0/24",
	"8.35.211.0/24",
	"8.39.125.0/24",
	"188.164.248.0/24",
	"173.245.58.0/23",
	"104.26.0.0/20",
}

type cidrBlock struct {
	network   uint32
	prefix    int
	hostCount uint32
}

// probeMode 决定探测走到哪一步。WS 是在 TLS 之上再加一次 HTTP 升级。
type probeMode int

const (
	probeTCP probeMode = iota // TCP 握手
	probeTLS                  // TCP -> TLS 握手
	probeWS                   // TCP -> TLS -> HTTP 升级, 校验 101
)

func (m probeMode) String() string {
	switch m {
	case probeTLS:
		return "tls"
	case probeWS:
		return "ws"
	default:
		return "tcp"
	}
}

// probeTarget 描述一次探测需要的全部参数。
type probeTarget struct {
	port int
	// host 同时用作 TLS SNI (tlsSettings.serverName) 和 HTTP Host 头
	// (wsSettings.host): 两者在 CF 的 WS 节点上必然是同一个域名。
	host     string
	path     string
	insecure bool
	timeout  time.Duration
	mode     probeMode
}

// sample 是一轮探测的结果, 全部为相对开始的累计耗时。
type sample struct {
	tcp, tls, ws time.Duration
}

// total 返回这次探测的累计耗时。
func (s sample) total() time.Duration { return s.tcp + s.tls + s.ws }

type rank struct {
	ip      string
	total   time.Duration // 中位数握手总耗时
	best    time.Duration
	ok      int
	tries   int
	samples []sample
}

func main() {
	rand.Seed(time.Now().UnixNano())

	var (
		nSample   = flag.Int("n", defaultSample, "抽样候选 IP 数量")
		rounds    = flag.Int("rounds", defaultRounds, "精测轮数, 取中位数抗抖动")
		top       = flag.Int("top", defaultTop, "输出前 N 名")
		workers   = flag.Int("c", defaultWorkers, "阶段1快筛并发数")
		refineC   = flag.Int("rc", 8, "阶段2精测并发数 (高并发会排队, 污染延迟测量)")
		timeoutMs = flag.Int("timeout", 0, "单次探测超时(毫秒), 0 = 按模式取默认 (tcp 1000 / ws 2200)")
		verify    = flag.Bool("verify", false, "校验 TLS 证书 (仅 TLS+WS 模式; 默认跳过, 避免系统 CA 过旧导致误判)")
		refineN   = flag.Int("refine", 200, "进入精测的候选数量")
		cidrFlag  = flag.String("cidr", "", "限定网段, 逗号分隔 (如 172.64.229.0/24), 覆盖在线列表")
		noFetch   = flag.Bool("no-fetch", false, "不拉取在线 CIDR 列表, 只用内置网段")
		envFile   = flag.String("env", "cf.env", "配置文件, 内含 Host/端口/密码/测速参数")
		showVer   = flag.Bool("version", false, "打印版本号后退出")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "用法: %s [选项]\n\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
所有连接参数 (Host/端口/路径/密码/xray 路径) 都在 cf.env 里配置。
cf.env 不存在时会自动生成 (内置 cf.env.example)。

PASSWORD 为空 (默认) 时只做纯 TCP 探测; 配置 PASSWORD 后自动启用
TLS+WS 握手探测和 xray 隧道测速。

示例:
  %s
  %s -cidr 172.64.229.0/24 -n 254 -rounds 5
  %s -env /path/to/other.env
`, os.Args[0], os.Args[0], os.Args[0])
	}
	flag.Parse()

	if *showVer {
		fmt.Println(version)
		return
	}

	// ---- 读 cf.env: 连接参数 + 测速参数 ----
	// 只有默认的 cf.env 会被自动创建; 显式指定的 -env 路径不存在仍报错,
	// 避免路径写错时悄悄生成一个模板。
	conf, err := loadConfig(*envFile, filepath.Clean(*envFile) == "cf.env")
	if err != nil {
		die("%v", err)
	}
	sp := conf.Speed

	mode := conf.Mode()
	timeout := conf.ProbeTimeout()
	if *timeoutMs > 0 { // 命令行显式指定时覆盖模式默认值
		timeout = time.Duration(*timeoutMs) * time.Millisecond
	}

	target := probeTarget{
		port:     conf.Port,
		path:     conf.Path,
		host:     conf.Host,
		insecure: !*verify,
		timeout:  timeout,
		mode:     mode,
	}

	switch target.mode {
	case probeWS:
		fmt.Printf("\n目标   Host=%s  port=%d  path=%s  protocol=%s\n",
			target.host, target.port, target.path, conf.Protocol)
		fmt.Printf("探测   TCP + TLS1.3 + WS升级101   单次超时=%v  并发=%d\n", target.timeout, *workers)
	case probeTLS:
		fmt.Printf("\n目标   Host=%s  port=%d\n", target.host, target.port)
		fmt.Printf("探测   TCP + TLS1.3   单次超时=%v  并发=%d\n", target.timeout, *workers)
		fmt.Println("       未配置 PASSWORD, 只验证到 TLS 握手; 配置后加测 WS 升级与隧道测速")
	default:
		fmt.Printf("\n目标   纯 TCP  port=%d   单次超时=%v  并发=%d\n",
			target.port, target.timeout, *workers)
		fmt.Println("探测   仅 TCP 握手 (配置 HOST 加测 TLS, 再加 PASSWORD 加测 WS)")
	}
	if !conf.CanSpeed() {
		fmt.Printf("测速   ✗ 跳过%s\n", conf.SpeedSkipReason())
	} else {
		fmt.Printf("测速   ✓ 源=%s 前%d名 x%d次\n", sp.URL, sp.Top, sp.Repeats)
	}
	if conf.ClashYML != "" {
		fmt.Printf("写回   ✓ %s (前 %d 个节点的 IP+port)\n", conf.ClashYML, clashIPCount)
	} else {
		fmt.Println("写回   ✗ 未配置 CLASH_YML, 只打印结果")
	}

	// ---- 生成候选 ----
	var cidrs []cidrBlock
	if *cidrFlag != "" {
		cidrs = parseCIDRLines(strings.NewReader(strings.ReplaceAll(*cidrFlag, ",", "\n")))
		if len(cidrs) == 0 {
			die("-cidr 参数里没有合法网段: %s", *cidrFlag)
		}
	} else {
		cidrs = loadCIDRs(!*noFetch)
	}
	candidates := generateCandidateIPs(cidrs, *nSample, rand.New(rand.NewSource(time.Now().UnixNano())))
	fmt.Printf("候选   %d 个 (来自 %d 个 CIDR 网段)\n\n", len(candidates), len(cidrs))

	// ---- 阶段 1: 单轮快筛 ----
	fmt.Printf("阶段1  单轮快筛 %d 个 IP ...\n", len(candidates))
	t0 := time.Now()
	first := runProbe(candidates, target, 1, *workers)
	alive := make([]rank, 0, len(first))
	for _, r := range first {
		if r.ok > 0 {
			alive = append(alive, r)
		}
	}
	fmt.Printf("       可用 %d / %d, 耗时 %v\n\n", len(alive), len(candidates), time.Since(t0).Round(time.Millisecond))
	if len(alive) == 0 {
		switch target.mode {
		case probeWS:
			die("没有任何 IP 通过 WS 握手, 检查 Host/端口是否正确")
		case probeTLS:
			die("没有任何 IP 完成 TLS 握手, 检查 Host/端口是否正确")
		default:
			die("没有任何 IP 能建立 TCP 连接, 检查端口是否正确")
		}
	}

	// ---- 阶段 2: 多轮精测 ----
	sort.Slice(alive, func(i, j int) bool { return alive[i].best < alive[j].best })
	if len(alive) > *refineN {
		alive = alive[:*refineN]
	}
	fmt.Printf("阶段2  多轮精测 %d 个 IP x %d 轮 (并发 %d) ...\n", len(alive), *rounds, *refineC)
	t1 := time.Now()
	ips := make([]string, len(alive))
	for i, r := range alive {
		ips[i] = r.ip
	}
	final := runProbe(ips, target, *rounds, *refineC)
	sort.Slice(final, func(i, j int) bool {
		// 稳定优先: 成功率低的不排前面
		ra, rb := float64(final[i].ok)/float64(final[i].tries), float64(final[j].ok)/float64(final[j].tries)
		if math.Abs(ra-rb) > 1e-9 {
			return ra > rb
		}
		return final[i].total < final[j].total
	})
	fmt.Printf("       耗时 %v\n\n", time.Since(t1).Round(time.Millisecond))

	// ---- 输出 ----
	n := *top
	if n > len(final) {
		n = len(final)
	}
	switch target.mode {
	case probeWS:
		fmt.Printf("%-3s %-16s %8s %8s %8s %8s %7s\n", "#", "IP", "TCP", "TLS", "WS升级", "总计", "成功率")
	case probeTLS:
		fmt.Printf("%-3s %-16s %8s %8s %8s %7s\n", "#", "IP", "TCP", "TLS", "总计", "成功率")
	default:
		fmt.Printf("%-3s %-16s %8s %7s\n", "#", "IP", "TCP", "成功率")
	}
	fmt.Println(strings.Repeat("-", 68))
	for i := 0; i < n; i++ {
		r := final[i]
		if target.mode == probeTCP {
			fmt.Printf("%-3d %-16s %6.0fms %5d/%d\n", i+1, r.ip, ms(r.total), r.ok, r.tries)
			continue
		}
		med := func(get func(sample) time.Duration) time.Duration {
			ds := make([]time.Duration, len(r.samples))
			for k, s := range r.samples {
				ds[k] = get(s)
			}
			return medianDuration(ds)
		}
		tcp := ms(med(func(s sample) time.Duration { return s.tcp }))
		tls := ms(med(func(s sample) time.Duration { return s.tls }))
		if target.mode == probeTLS {
			fmt.Printf("%-3d %-16s %6.0fms %6.0fms %6.0fms %5d/%d\n",
				i+1, r.ip, tcp, tls, ms(r.total), r.ok, r.tries)
			continue
		}
		fmt.Printf("%-3d %-16s %6.0fms %6.0fms %6.0fms %6.0fms %5d/%d\n",
			i+1, r.ip, tcp, tls,
			ms(med(func(s sample) time.Duration { return s.ws })),
			ms(r.total), r.ok, r.tries)
	}

	// ---- 阶段 3: 真实吞吐测速 (可选, 由 cf.env 驱动) ----
	// 握手延迟只反映"连上 CF 边缘"的耗时, 不反映隧道内的实际转发能力:
	// 同一个 /24 里出现过握手 230ms 的 IP 下载速度只有另一个的 1/4。
	// 所以真正决定用哪个 IP 的必须是端到端吞吐。
	// ordered 是最终交付顺序: 测速成功的按吞吐排在前, 其余按握手排名补齐。
	ordered := make([]string, 0, len(final))
	for _, r := range final {
		ordered = append(ordered, r.ip)
	}
	if conf.CanSpeed() {
		ordered = runSpeedStage(sp, final, conf, target)
	}

	// 写回: 只改 clash 配置里节点的 server 字段, 不动 cf.env 本身。
	if conf.ClashYML != "" {
		n, err := writeClashIPs(conf.ClashYML, ordered, clashIPCount, conf.Port)
		if err != nil {
			die("写回 %s 失败: %v", conf.ClashYML, err)
		}
		fmt.Printf("\n已写回 %s: 前 %d 个节点, port=%d, %s ... %s\n",
			conf.ClashYML, n, conf.Port, ordered[0], ordered[n-1])
	}
}

// runSpeedStage 对握手排名靠前的候选做真实吞吐测试, 返回最终交付顺序。
//
// 顺序是: 测速成功的按吞吐从高到低排前面, 其余候选 (测速失败或没进测速名单)
// 按握手排名补齐。写回 clash 时直接取这个顺序的前 N 个。
func runSpeedStage(sp speedProfile, final []rank, conf *cfConfig, target probeTarget) []string {
	m := sp.Top
	if m > len(final) {
		m = len(final)
	}
	fmt.Printf("阶段3  真实吞吐测速 前 %d 名, 每名 %d 次 (走 %s 隧道)\n", m, sp.Repeats, conf.Protocol)

	results := measureThroughput(final[:m], conf, target, sp)
	sort.SliceStable(results, func(i, j int) bool {
		return score(results[i]) > score(results[j])
	})

	fmt.Printf("\n%-3s %-16s %8s %9s %9s %10s\n", "#", "IP", "握手", "首字节", "下载", "综合")
	fmt.Println(strings.Repeat("-", 62))
	for i, r := range results {
		firstByte := "-"
		if r.firstByte > 0 {
			firstByte = fmt.Sprintf("%.0fms", ms(r.firstByte))
		}
		fmt.Printf("%-3d %-16s %7.0fms %9s %6.2fMB/s %10.1f\n",
			i+1, r.ip, ms(r.handshake), firstByte, r.mbps, score(r))
	}

	ordered := make([]string, 0, len(final))
	seen := make(map[string]bool, len(final))
	for _, r := range results {
		if r.mbps > 0 && !seen[r.ip] {
			ordered = append(ordered, r.ip)
			seen[r.ip] = true
		}
	}
	if len(ordered) == 0 {
		fmt.Println("\n警告   所有测速均失败, 回退到握手排名")
	}
	for _, r := range final {
		if !seen[r.ip] {
			ordered = append(ordered, r.ip)
			seen[r.ip] = true
		}
	}
	return ordered
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// score 综合评分: 吞吐为主, 首字节延迟为辅。
//
// 吞吐权重远大于延迟 —— 实测过握手同样是 230ms 的两个 IP 下载速度差 4 倍,
// 而延迟差通常在 100ms 量级。用 10x 吞吐 - 0.1x 首字节(ms) 让速度主导。
func score(r speedResult) float64 {
	return r.mbps*10 - ms(r.firstByte)/100
}

// ---------------------------------------------------------------- cf.env

// speedProfile 是测速阶段的全部配置, 来自 cf.env。全空即表示"不测速"。
type speedProfile struct {
	URL     string
	Top     int           // 参与测速的候选数
	Repeats int           // 每个 IP 重复下载次数
	Timeout time.Duration // 单次下载超时
}

func (s speedProfile) Enabled() bool { return s.URL != "" }

// envOverrides 允许用真环境变量临时覆盖测速参数, 方便一次性试跑。
//
// 只放行 SPEED_* 这一组: 连接参数 (HOST/PORT/WS_PATH 等) 必须来自文件,
// 否则会和 shell 自己的同名变量撞车 —— PATH 就曾把 WS 路径覆盖成了 $PATH。
func envOverrides() map[string]string {
	out := map[string]string{}
	for _, k := range []string{"SPEED_URL", "SPEED_TOP", "SPEED_REPEATS", "SPEED_TIMEOUT"} {
		if v, ok := os.LookupEnv(k); ok {
			out[k] = v
		}
	}
	return out
}

// initConfig 在 cf.env 缺失时用内嵌模板创建它, 并返回解析结果。
func initConfig(path string) (map[string]string, error) {
	if err := os.WriteFile(path, envTemplate, 0o600); err != nil {
		// 只读目录等场景: 不停机, 直接拿模板内容当默认配置。
		fmt.Fprintf(os.Stderr, "警告: 无法创建 %s (%v), 使用内置默认配置\n", path, err)
		return parseEnvReader(bytes.NewReader(envTemplate))
	}
	fmt.Printf("配置   未找到 %s, 已按内置模板生成, 按需修改后重跑\n", path)
	vals, err := parseEnvFile(path)
	if err != nil {
		return nil, fmt.Errorf("生成 %s 后读取失败: %w", path, err)
	}
	return vals, nil
}

// parseEnvFile 解析简单的 KEY=VALUE 文件, 支持 # 注释和可选引号。
func parseEnvFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseEnvReader(f)
}

func parseEnvReader(r io.Reader) (map[string]string, error) {
	vals := map[string]string{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.Index(line, "=")
		if eq <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		val = strings.Trim(val, `"'`)
		vals[key] = val
	}
	return vals, sc.Err()
}

func die(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "\n错误: "+format+"\n", args...)
	os.Exit(1)
}

// ---------------------------------------------------------------- 探测

// runProbe 对每个 IP 执行 rounds 轮完整握手, 返回全部统计。
//
// 轮次放在外层做屏障, 每轮把所有 IP 各测一遍。这样网络抖动被均匀分摊到所有候选上,
// 而不是"某几个 IP 恰好赶上拥堵"。
func runProbe(ips []string, t probeTarget, rounds, workers int) []rank {
	if workers < 1 {
		workers = 1
	}
	out := make([]rank, len(ips))
	for i, ip := range ips {
		out[i] = rank{ip: ip, best: time.Duration(math.MaxInt64)}
	}

	for k := 0; k < rounds; k++ {
		jobs := make(chan int)
		var wg sync.WaitGroup
		for w := 0; w < workers && w < len(ips); w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for idx := range jobs {
					r := &out[idx]
					r.tries++
					s, err := probeOnce(r.ip, t)
					if err != nil {
						continue
					}
					r.ok++
					r.samples = append(r.samples, s)
					if sum := s.total(); sum < r.best {
						r.best = sum
					}
				}
			}()
		}
		for i := range ips {
			jobs <- i
		}
		close(jobs)
		wg.Wait()
	}

	for i := range out {
		r := &out[i]
		if r.ok > 0 {
			ds := make([]time.Duration, len(r.samples))
			for k, s := range r.samples {
				ds[k] = s.total()
			}
			r.total = medianDuration(ds)
		} else {
			r.total = time.Duration(math.MaxInt64)
		}
	}
	return out
}

// probeOnce 完成一次冷连接探测, 深度由 t.mode 决定:
//
//	probeTCP:  TCP 握手
//	probeTLS:  TCP -> TLS1.3, 证书校验默认跳过
//	probeWS:   再接 HTTP Upgrade, 校验 101
func probeOnce(ip string, t probeTarget) (sample, error) {
	var s sample
	addr := net.JoinHostPort(ip, strconv.Itoa(t.port))
	dialer := net.Dialer{Timeout: t.timeout}
	ctx, cancel := context.WithTimeout(context.Background(), t.timeout)
	defer cancel()

	start := time.Now()
	raw, err := dialer.DialContext(ctx, "tcp4", addr)
	if err != nil {
		return s, fmt.Errorf("tcp: %w", err)
	}
	defer raw.Close()
	if err := raw.SetDeadline(time.Now().Add(t.timeout)); err != nil {
		return s, err
	}
	s.tcp = time.Since(start)

	// 纯 TCP 模式: 只关心能否建立连接, 拿到 connect 耗时就可以收工。
	if t.mode == probeTCP {
		return s, nil
	}

	tlsConn := tls.Client(raw, &tls.Config{
		ServerName:         t.host,     // 与下面的 Host 头一致
		InsecureSkipVerify: t.insecure, //nolint:gosec // 探测工具, 默认跳过证书校验
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"http/1.1"},
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return s, fmt.Errorf("tls: %w", err)
	}
	s.tls = time.Since(start) - s.tcp

	// TLS 模式: 握手成功就算这个 IP 承载该域名 (证书跳过校验时的信任来源)。
	if t.mode == probeTLS {
		return s, nil
	}

	req := fmt.Sprintf(
		"GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\n"+
			"Upgrade: websocket\r\nConnection: Upgrade\r\n"+
			"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
		t.path, t.host)
	if _, err := tlsConn.Write([]byte(req)); err != nil {
		return s, fmt.Errorf("ws write: %w", err)
	}

	br := bufio.NewReader(tlsConn)
	line, err := br.ReadString('\n')
	if err != nil {
		return s, fmt.Errorf("ws read: %w", err)
	}
	s.ws = time.Since(start) - s.tcp - s.tls
	if !strings.Contains(line, " 101 ") && !strings.HasPrefix(line, "HTTP/1.1 101") {
		return s, fmt.Errorf("ws status: %s", strings.TrimSpace(line))
	}
	return s, nil
}

// speedResult 是走完隧道后的真实吞吐。
type speedResult struct {
	ip        string
	handshake time.Duration // 来自阶段2 的握手中位数
	firstByte time.Duration // 隧道内首字节延迟
	mbps      float64       // 多次下载的中位吞吐
	samples   []float64
	err       error
}

// measureThroughput 为每个候选 IP 起一个最小 xray 实例, 用本地 socks 入口下载测速。
//
// 单次测速噪声很大 (TCP 慢启动、途中丢包), 所以每个 IP 重复 sp.Repeats 次取中位数。
// 串行执行, 避免多个实例互相抢带宽。
func measureThroughput(ranks []rank, conf *cfConfig, t probeTarget, sp speedProfile) []speedResult {
	bin := conf.XrayBin
	if err := checkXray(bin); err != nil {
		fmt.Printf("       跳过测速: %v\n", err)
		return nil
	}

	out := make([]speedResult, 0, len(ranks))
	for _, r := range ranks {
		sr := speedResult{ip: r.ip, handshake: r.total}
		fmt.Printf("       %-16s ", r.ip)
		for k := 0; k < sp.Repeats; k++ {
			res, err := runSpeedTest(bin, conf, r.ip, t, sp)
			if err != nil {
				sr.err = err
				fmt.Printf("x ")
				continue
			}
			sr.samples = append(sr.samples, res.mbps)
			if sr.firstByte == 0 || res.firstByte < sr.firstByte {
				sr.firstByte = res.firstByte
			}
			fmt.Printf("%.1f ", res.mbps)
		}
		if len(sr.samples) > 0 {
			sr.mbps = medianFloat(sr.samples)
			fmt.Printf("=> %.2f MB/s\n", sr.mbps)
		} else {
			fmt.Printf("=> 失败 (%v)\n", sr.err)
		}
		out = append(out, sr)
	}
	return out
}

// checkXray 确认 xray 可执行文件存在。
func checkXray(bin string) error {
	if bin == "" {
		return fmt.Errorf("cf.env 里没配 XRAY_BIN")
	}
	if !fileExists(bin) {
		return fmt.Errorf("XRAY_BIN 指向的文件不存在: %s", bin)
	}
	return nil
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// runSpeedTest 用临时配置起一个只监听随机端口的 xray, 下载指定 URL 后关闭。
func runSpeedTest(bin string, conf *cfConfig, ip string, t probeTarget, sp speedProfile) (speedResult, error) {
	port, err := freePort()
	if err != nil {
		return speedResult{}, err
	}

	tmpCfg := buildMinimalConfig(conf, ip, t, port)
	dir, err := os.MkdirTemp("", "cfip-")
	if err != nil {
		return speedResult{}, err
	}
	defer os.RemoveAll(dir)
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, tmpCfg, 0o600); err != nil {
		return speedResult{}, err
	}

	cmd := exec.Command(bin, "run", "-c", cfgPath)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if err := cmd.Start(); err != nil {
		return speedResult{}, err
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	// 等 socks 入口起来
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	if err := waitPort(addr, 8*time.Second); err != nil {
		return speedResult{}, fmt.Errorf("xray 未就绪: %w", err)
	}

	return downloadVia(addr, sp)
}

func waitPort(addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
		if err == nil {
			c.Close()
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timeout")
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// buildMinimalConfig 只保留测速需要的部分: 一个 socks 入口 + 一个指向候选 IP 的 outbound。
func buildMinimalConfig(conf *cfConfig, ip string, t probeTarget, port int) []byte {
	raw := map[string]interface{}{
		"log": map[string]interface{}{"loglevel": "none"},
		"inbounds": []interface{}{
			map[string]interface{}{
				"port": port, "listen": "127.0.0.1", "protocol": "socks",
				"settings": map[string]interface{}{"auth": "noauth", "udp": false},
			},
		},
		"outbounds": []interface{}{conf.outbound(ip)},
	}
	b, _ := json.Marshal(raw)
	return b
}

// outbound 按 cf.env 里的参数生成一个完整的 outbound, address 用传入的候选 IP。
func (c *cfConfig) outbound(ip string) map[string]interface{} {
	return map[string]interface{}{
		"protocol": c.Protocol,
		"settings": map[string]interface{}{
			"servers": []interface{}{
				map[string]interface{}{
					"address":  ip,
					"port":     c.Port,
					"password": c.Password,
				},
			},
		},
		"streamSettings": map[string]interface{}{
			"network":  "ws",
			"security": "tls",
			"tlsSettings": map[string]interface{}{
				"serverName":    c.Host,
				"allowInsecure": false,
				"fingerprint":   "chrome",
			},
			"wsSettings": map[string]interface{}{
				"path": c.Path,
				"host": c.Host,
			},
		},
	}
}

// downloadVia 通过 socks5 代理下载 url, 返回吞吐和首字节延迟。
func downloadVia(proxyAddr string, sp speedProfile) (speedResult, error) {
	var res speedResult
	dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		return res, err
	}
	// proxy.SOCKS5 可能返回实现了 ContextDialer 的具体类型, 两者都要兼容。
	ctxDialer, _ := dialer.(proxy.ContextDialer)
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if ctxDialer != nil {
				return ctxDialer.DialContext(ctx, network, addr)
			}
			return dialer.Dial(network, addr)
		},
		ForceAttemptHTTP2: true,
	}
	client := &http.Client{Transport: tr, Timeout: sp.Timeout}
	defer tr.CloseIdleConnections()

	req, err := http.NewRequest(http.MethodGet, sp.URL, nil)
	if err != nil {
		return res, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return res, err
	}
	defer resp.Body.Close()
	res.firstByte = time.Since(start) // 包含隧道建立 + 首字节, 这才是用户体感延迟
	if resp.StatusCode != http.StatusOK {
		return res, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	n, err := io.Copy(io.Discard, resp.Body)
	elapsed := time.Since(start).Seconds()
	if err != nil {
		return res, err
	}
	if elapsed <= 0 || n == 0 {
		return res, fmt.Errorf("无数据")
	}
	res.mbps = float64(n) / elapsed / 1e6
	return res, nil
}

func medianFloat(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	cp := append([]float64(nil), xs...)
	sort.Float64s(cp)
	if len(cp)%2 == 0 {
		return (cp[len(cp)/2-1] + cp[len(cp)/2]) / 2
	}
	return cp[len(cp)/2]
}

func medianDuration(ds []time.Duration) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	cp := append([]time.Duration(nil), ds...)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	return cp[len(cp)/2]
}

// ---------------------------------------------------------------- CIDR

func loadCIDRs(fetch bool) []cidrBlock {
	if fetch {
		if cs, src := fetchCIDRs(); len(cs) > 0 {
			// 默认走直连, 只有回退到镜像时才提示一句, 正常情况不打扰。
			if src != cidrSources[0] {
				fmt.Printf("CIDR   直连 GitHub 失败, 在线列表来自镜像 %s\n", src)
			}
			return cs
		}
		fmt.Println("获取在线 CIDR 失败, 使用内置网段")
	}
	return parseCIDRLines(strings.NewReader(strings.Join(fallbackCIDRs, "\n")))
}

// fetchCIDRs 按 cidrSources 顺序尝试, 返回第一个能解析出合法网段的列表及其来源。
//
// 逐个串行是为了不放大请求; 单个源超时 5 秒, 解析不出网段也算失败 (镜像返回
// 错误页时通常是 200 + HTML, 只看 HTTP 状态会误判成功)。
func fetchCIDRs() ([]cidrBlock, string) {
	for _, src := range cidrSources {
		body, err := fetchURL(src, cidrFetchTimeout)
		if err != nil {
			continue
		}
		if cs := parseCIDRLines(strings.NewReader(body)); len(cs) > 0 {
			return cs, src
		}
	}
	return nil, ""
}

func fetchURL(url string, timeout time.Duration) (string, error) {
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "cfip/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("status %s", resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return string(b), err
}

func parseCIDRLines(r io.Reader) []cidrBlock {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024), maxLineLen)
	var out []cidrBlock
	for sc.Scan() && len(out) < maxCIDRs {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if c, err := parseCIDR(line); err == nil {
			out = append(out, c)
		}
	}
	return out
}

func parseCIDR(raw string) (cidrBlock, error) {
	ip, ipNet, err := net.ParseCIDR(raw)
	if err != nil {
		return cidrBlock{}, err
	}
	v4 := ip.To4()
	if v4 == nil {
		return cidrBlock{}, fmt.Errorf("not ipv4: %s", raw)
	}
	ones, bits := ipNet.Mask.Size()
	if bits != 32 {
		return cidrBlock{}, fmt.Errorf("bad prefix: %s", raw)
	}
	n := ipNet.IP.To4()
	network := uint32(n[0])<<24 | uint32(n[1])<<16 | uint32(n[2])<<8 | uint32(n[3])
	var hosts uint32
	size := uint64(1) << uint(32-ones)
	if size <= 2 {
		hosts = uint32(size)
	} else if size > math.MaxUint32 {
		hosts = math.MaxUint32
	} else {
		hosts = uint32(size - 2)
	}
	return cidrBlock{network: network, prefix: ones, hostCount: hosts}, nil
}

// generateCandidateIPs 按网段大小加权抽样, 保证每个网段至少有机会被抽到。
func generateCandidateIPs(cidrs []cidrBlock, n int, rng *rand.Rand) []string {
	if len(cidrs) == 0 || n <= 0 {
		return nil
	}
	if n > maxIPs {
		n = maxIPs
	}
	seen := make(map[uint32]struct{}, n)
	ips := make([]string, 0, n)

	quotas := make([]int, len(cidrs))
	var totalW uint64
	for _, c := range cidrs {
		w := uint64(c.hostCount)
		if w == 0 {
			w = 1
		}
		totalW += w
	}
	assigned := 0
	for i, c := range cidrs {
		w := uint64(c.hostCount)
		if w == 0 {
			w = 1
		}
		q := int(uint64(n) * w / totalW)
		if q < 1 {
			q = 1
		}
		quotas[i] = q
		assigned += q
	}
	for i := 0; assigned < n; i++ {
		quotas[i%len(quotas)]++
		assigned++
	}

	// 抽样时去重; 大网段重复概率极低, 小网段(如 /24)则可能打满。
	for attempts := 0; attempts < 8 && len(ips) < n; attempts++ {
		for i, q := range quotas {
			for j := 0; j < q && len(ips) < n; j++ {
				ip := randomIPFromCIDR(cidrs[i], rng)
				if _, dup := seen[ip]; dup {
					continue
				}
				seen[ip] = struct{}{}
				ips = append(ips, ipToString(ip))
			}
		}
	}
	rng.Shuffle(len(ips), func(i, j int) { ips[i], ips[j] = ips[j], ips[i] })
	return ips
}

func randomIPFromCIDR(c cidrBlock, rng *rand.Rand) uint32 {
	size := uint64(1) << uint(32-c.prefix)
	if size <= 2 {
		return c.network
	}
	return c.network + 1 + uint32(rng.Int63n(int64(size-2)))
}

func ipToString(ip uint32) string {
	return net.IPv4(byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip)).String()
}

// ---------------------------------------------------------------- cf.env 配置

// cfConfig 是 cf.env 解析后的结果: 连接参数 + xray 路径 + 测速参数。
type cfConfig struct {
	// Host 同时是 TLS SNI 和 HTTP Host 头; 只有这一个域名参数。
	Host     string
	Port     int
	Path     string
	Protocol string
	Password string
	XrayBin  string
	ClashYML string // 非空则把筛出的 IP 写回该 clash 配置
	Speed    speedProfile
}

// Mode 按配置决定探测深度:
//
//	无 HOST              -> 纯 TCP, 零配置可跑
//	有 HOST, 无 PASSWORD -> TCP + TLS, 验证 IP 确实承载该域名
//	有 HOST, 有 PASSWORD -> 再加 WS 升级, 确认节点接受 101 并可隧道测速
func (c *cfConfig) Mode() probeMode {
	switch {
	case c.Host == "":
		return probeTCP
	case c.Password == "":
		return probeTLS
	default:
		return probeWS
	}
}

// ProbeTimeout 返回当前模式默认的单次探测超时。
//
// 链路越长越容易在抖动时被误杀, 所以逐级放宽。
func (c *cfConfig) ProbeTimeout() time.Duration {
	switch c.Mode() {
	case probeTLS:
		return tlsTimeout
	case probeWS:
		return wsTimeout
	default:
		return tcpTimeout
	}
}

// CanSpeed 判断是否具备测速条件: 要有下载源、密码和真实存在的 xray 可执行文件。
func (c *cfConfig) CanSpeed() bool {
	return len(c.speedBlockers()) == 0
}

// speedBlockers 列出所有阻碍测速的原因, 空表示可测速。
func (c *cfConfig) speedBlockers() []string {
	var miss []string
	if c.Speed.URL == "" {
		miss = append(miss, "SPEED_URL 为空")
	}
	if c.Password == "" {
		miss = append(miss, "缺少 PASSWORD (纯 TCP 模式)")
	}
	if c.Password != "" && c.Host == "" {
		miss = append(miss, "缺少 HOST")
	}
	switch {
	case c.XrayBin == "":
		miss = append(miss, "缺少 XRAY_BIN")
	case !fileExists(c.XrayBin):
		miss = append(miss, "XRAY_BIN 文件不存在")
	}
	return miss
}

// SpeedSkipReason 说明为什么不测速, 面向用户直接展示。
func (c *cfConfig) SpeedSkipReason() string {
	miss := c.speedBlockers()
	if len(miss) == 0 {
		return ""
	}
	return " (" + strings.Join(miss, ", ") + ")"
}

// loadConfig 读取 cf.env, 其余字段都有默认值。
//
// create 为 true 且文件不存在时, 用内嵌的 cf.env.example 生成一份再读;
// 写不出来 (比如当前目录只读) 则直接拿模板内容继续跑, 不阻塞纯 TCP 模式。
func loadConfig(path string, create bool) (*cfConfig, error) {
	vals, err := parseEnvFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("读取 %s 失败: %w", path, err)
		}
		if !create {
			return nil, fmt.Errorf("配置文件不存在: %s (用默认 cf.env 运行会自动生成模板)", path)
		}
		vals, err = initConfig(path)
		if err != nil {
			return nil, err
		}
	}
	for k, v := range envOverrides() {
		vals[k] = v
	}

	// 旧版 cf.env 把 SNI 和 HOST 分成两个键。SNI 和 Host 在 WS 节点上必然是同一个
	// 域名, 现在只保留 HOST; 老配置里的 SNI 仍读一次作为回退, 避免升级后突然报缺 HOST。
	c := &cfConfig{
		Host:     vals["HOST"],
		Port:     defaultPort,
		Path:     defaultPath,
		Protocol: vals["PROTOCOL"],
		Password: vals["PASSWORD"],
		XrayBin:  vals["XRAY_BIN"],
		ClashYML: vals["CLASH_YML"],
	}
	if c.Host == "" {
		c.Host = vals["SNI"]
	}
	// 纯 TCP 模式用不到 HOST; 配了 PASSWORD 必有 HOST, 否则无从做 TLS/WS 握手。
	if c.Host == "" && c.Password != "" {
		return nil, fmt.Errorf("%s 缺少 HOST (配了 PASSWORD 就必须填 HOST)", path)
	}
	if c.Protocol == "" {
		c.Protocol = "trojan"
	}
	switch c.Protocol {
	case "trojan", "vless", "vmess":
	default:
		return nil, fmt.Errorf("%s: PROTOCOL 只支持 trojan/vless/vmess, 当前是 %q", path, c.Protocol)
	}
	if raw := vals["PORT"]; raw != "" {
		p, err := strconv.Atoi(raw)
		if err != nil || p <= 0 || p > 65535 {
			return nil, fmt.Errorf("%s: PORT 不合法: %q", path, raw)
		}
		c.Port = p
	}
	// 用 WS_PATH 而不是 PATH: PATH 是 shell 的保留变量, 容易读串。
	if raw := vals["WS_PATH"]; raw != "" {
		c.Path = raw
	}

	sp, err := parseSpeedProfile(vals, path)
	if err != nil {
		return nil, err
	}
	c.Speed = sp
	return c, nil
}

// parseSpeedProfile 从已解析的键值里提取测速参数。SPEED_URL 为空即不测速。
func parseSpeedProfile(vals map[string]string, path string) (speedProfile, error) {
	sp := speedProfile{Top: 5, Repeats: 3, Timeout: 40 * time.Second}
	sp.URL = vals["SPEED_URL"]

	for _, kv := range []struct {
		key string
		dst *int
	}{
		{"SPEED_TOP", &sp.Top},
		{"SPEED_REPEATS", &sp.Repeats},
	} {
		if raw, ok := vals[kv.key]; ok && raw != "" {
			n, err := strconv.Atoi(raw)
			if err != nil || n < 0 {
				return sp, fmt.Errorf("%s 里的 %s 不是合法正整数: %q", path, kv.key, raw)
			}
			*kv.dst = n
		}
	}
	if raw := vals["SPEED_TIMEOUT"]; raw != "" {
		secs, err := strconv.Atoi(raw)
		if err != nil || secs <= 0 {
			return sp, fmt.Errorf("%s 里的 SPEED_TIMEOUT 不是合法秒数: %q", path, raw)
		}
		sp.Timeout = time.Duration(secs) * time.Second
	}
	if sp.URL != "" && sp.Repeats == 0 {
		return sp, fmt.Errorf("%s: 配了 SPEED_URL 但 SPEED_REPEATS 为 0", path)
	}
	return sp, nil
}

// clashServerRe 匹配 clash 代理条目里的 IPv4 server 字段, 兼容无引号和带引号两种写法。
//
// 第 1 组是到 IP 为止的前缀 (含可能的引号), 第 2 组是 IP 本身; 只替换第 2 组,
// 前后引号和其余内容都留在原位。RE2 不支持反向引用, 所以不校验收尾引号。
var clashServerRe = regexp.MustCompile(
	`(?m)(\bserver:\s*["']?)(\d{1,3}(?:\.\d{1,3}){3})`)

// clashPortRe 匹配 port 字段, 写法同 clashServerRe (第 2 组是端口号)。
var clashPortRe = regexp.MustCompile(`(?m)(\bport:\s*["']?)(\d{1,5})`)

// clashItemRe 匹配 proxies 段里的列表项起始 (块列表的 "- name: ..." 或 "- {...}")。
//
// 按条目切分而不是按 server 匹配位置切分: 同一段的 port 可能在 server 前面
// (行内写法) 或后面 (块写法), 只有知道条目边界才能准确找到属于它的 port。
var clashItemRe = regexp.MustCompile(`(?m)^[ \t]*-[ \t]`)

// clashProxiesKeyRe 定位顶层 proxies: 键; clashTopKeyRe 匹配下一个顶格键。
//
// 用两步查找而不是一个带先行断言的正则: Go 的 RE2 不支持 (?=...)。不给段设边界
// 就会改到 dns/nameserver 里同样叫 server 的字段 —— 那些不是节点。
var (
	clashProxiesKeyRe = regexp.MustCompile(`(?m)^proxies:`)
	clashTopKeyRe     = regexp.MustCompile(`(?m)^[A-Za-z_-]+:`)
)

// clashProxiesSpan 返回 proxies 段在 data 中的 [start,end) 区间。
func clashProxiesSpan(data []byte) (int, int, bool) {
	h := clashProxiesKeyRe.FindIndex(data)
	if h == nil {
		return 0, 0, false
	}
	start := h[1]
	end := len(data)
	if m := clashTopKeyRe.FindIndex(data[start:]); m != nil {
		end = start + m[0]
	}
	return start, end, true
}

// clashEdit 是一次替换: 把 sec[start:end] 换成 text。
type clashEdit struct {
	start, end int
	text       string
}

// writeClashIPs 按顺序改写 clash 配置 proxies 段里前 n 个节点的 server IP 和 port,
// 返回实际改写数量。
//
// server 和 port 必须一起改: 探测是按 cf.env 的 PORT 做的, 只换 IP 而保留 yaml 里
// 的旧端口, 写进去的节点在旧端口上根本没验证过, 会变成一堆死节点。
//
// 其余内容 (name/password/sni/ws-opts/注释) 原样保留, 也不碰 proxies 段以外的同名键。
// 条目数多于 n 时只改前 n 个, 少于 n 个则全改并给出提示 —— 不静默截断。
func writeClashIPs(path string, ips []string, n, port int) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	ss, se, ok := clashProxiesSpan(data)
	if !ok {
		return 0, fmt.Errorf("没找到顶层 proxies: 段, 确认这是 clash 配置而不是别的 yaml")
	}

	sec := data[ss:se]
	items := clashItemRe.FindAllIndex(sec, -1)
	if len(items) == 0 {
		if len(clashServerRe.FindAllIndex(sec, -1)) > 0 {
			return 0, fmt.Errorf("proxies 段不是块列表格式 (每项以 \"- \" 开头), 不支持改写")
		}
		return 0, fmt.Errorf("proxies 段里没找到任何节点条目")
	}

	portStr := strconv.Itoa(port)
	var edits []clashEdit
	done, noPort := 0, 0
	for i, it := range items {
		if done >= n || done >= len(ips) {
			break
		}
		start, end := it[0], len(sec)
		if i+1 < len(items) {
			end = items[i+1][0]
		}
		item := sec[start:end]

		sv := clashServerRe.FindSubmatchIndex(item)
		if sv == nil {
			continue // 非节点条目 (比如只有 name 的分组项)
		}
		edits = append(edits, clashEdit{start + sv[4], start + sv[5], ips[done]})
		if pv := clashPortRe.FindSubmatchIndex(item); pv != nil {
			edits = append(edits, clashEdit{start + pv[4], start + pv[5], portStr})
		} else {
			noPort++
		}
		done++
	}
	if len(edits) == 0 {
		return 0, fmt.Errorf("proxies 段里没找到任何 server: <IPv4> 条目")
	}
	if done < n {
		fmt.Printf("警告   %s 的 proxies 段只有 %d 个节点, 少于预期的 %d 个, 只改写这些\n",
			path, done, n)
	}
	if noPort > 0 {
		fmt.Printf("警告   %d 个节点没有 port 字段, 只改了 IP (新 IP 未必在旧配置的端口上验证过)\n", noPort)
	}

	// edits 按条目顺序追加, 天然有序; 同一条目内 server 在 port 之前。
	sort.Slice(edits, func(i, j int) bool { return edits[i].start < edits[j].start })
	var sec2 bytes.Buffer
	last := 0
	for _, e := range edits {
		sec2.Write(sec[last:e.start])
		sec2.WriteString(e.text)
		last = e.end
	}
	sec2.Write(sec[last:])

	var out bytes.Buffer
	out.Write(data[:ss])
	out.Write(sec2.Bytes())
	out.Write(data[se:])

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out.Bytes(), 0o644); err != nil {
		return 0, err
	}
	return done, os.Rename(tmp, path)
}
