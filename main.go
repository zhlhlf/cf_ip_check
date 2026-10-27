// cfip 批量筛选 Cloudflare 优选 IP。
//
// 与上游 cf_ip_check 的区别: 上游只测 TCP connect, 而 TCP 三次握手在 Cloudflare
// anycast 网络里几乎恒定为 70ms 左右, 完全不反映真实可用性和体验。本工具改为执行
// 完整的 WebSocket 握手 (TCP -> TLS 1.3 -> HTTP Upgrade 101), 只有真正返回 101 的
// IP 才算可用, 并按握手总耗时排序。
package main

import (
	"bufio"
	"context"
	"crypto/tls"
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
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

const (
	maxCIDRs   = 4096
	maxIPs     = 20000
	maxLineLen = 16384

	defaultPort    = 2096
	defaultPath    = "/"
	defaultSample  = 4096
	defaultRounds  = 3
	defaultTop     = 20
	defaultWorkers = 200
	defaultTimeout = 5 * time.Second

	cidrURL = "https://ghfast.top/raw.githubusercontent.com/cmliu/cmliu/main/CF-CIDR.txt"
)

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

// probeTarget 描述一次探测需要的全部参数。
type probeTarget struct {
	port     int
	sni      string // TLS SNI, 对应 tlsSettings.serverName
	host     string // HTTP Host 头, 对应 wsSettings.host
	path     string
	insecure bool
	timeout  time.Duration
}

// sample 是一轮探测的结果, 全部为相对开始的累计耗时。
type sample struct {
	tcp, tls, ws time.Duration
}

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
		timeoutMs = flag.Int("timeout", 5000, "单次探测超时(毫秒)")
		verify    = flag.Bool("verify", false, "校验 TLS 证书 (默认跳过, 避免系统 CA 过旧导致误判)")
		refineN   = flag.Int("refine", 200, "进入精测的候选数量")
		cidrFlag  = flag.String("cidr", "", "限定网段, 逗号分隔 (如 172.64.229.0/24), 覆盖在线列表")
		noFetch   = flag.Bool("no-fetch", false, "不拉取在线 CIDR 列表, 只用内置网段")
		envFile   = flag.String("env", "cf.env", "配置文件, 内含 SNI/端口/密码/测速参数")
		apply     = flag.Bool("apply", false, "把最优 IP 写回 cf.env")
		showVer   = flag.Bool("version", false, "打印版本号后退出")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "用法: %s [选项]\n\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
所有连接参数 (SNI/Host/端口/路径/密码/xray 路径) 都在 cf.env 里配置。

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
	conf, err := loadConfig(*envFile)
	if err != nil {
		die("%v", err)
	}
	sp := conf.Speed

	target := probeTarget{
		port:     conf.Port,
		path:     conf.Path,
		sni:      conf.SNI,
		host:     conf.Host,
		insecure: !*verify,
		timeout:  time.Duration(*timeoutMs) * time.Millisecond,
	}

	fmt.Printf("\n目标   SNI=%s  Host=%s  port=%d  path=%s  protocol=%s\n",
		target.sni, target.host, target.port, target.path, conf.Protocol)
	fmt.Printf("探测   TCP + TLS1.3 + WS升级101   单次超时=%v  并发=%d\n", target.timeout, *workers)
	if !conf.CanSpeed() {
		fmt.Printf("测速   ✗ 跳过%s\n", conf.SpeedSkipReason())
	} else {
		fmt.Printf("测速   ✓ 源=%s 前%d名 x%d次\n", sp.URL, sp.Top, sp.Repeats)
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
		die("没有任何 IP 通过 WS 握手, 检查 SNI/Host/端口是否正确")
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
	fmt.Printf("%-3s %-16s %8s %8s %8s %8s %7s\n", "#", "IP", "TCP", "TLS", "WS升级", "总计", "成功率")
	fmt.Println(strings.Repeat("-", 68))
	for i := 0; i < n; i++ {
		r := final[i]
		med := func(get func(sample) time.Duration) time.Duration {
			ds := make([]time.Duration, len(r.samples))
			for k, s := range r.samples {
				ds[k] = get(s)
			}
			return medianDuration(ds)
		}
		fmt.Printf("%-3d %-16s %6.0fms %6.0fms %6.0fms %6.0fms %5d/%d\n",
			i+1, r.ip,
			ms(med(func(s sample) time.Duration { return s.tcp })),
			ms(med(func(s sample) time.Duration { return s.tls })),
			ms(med(func(s sample) time.Duration { return s.ws })),
			ms(r.total), r.ok, r.tries)
	}

	// ---- 阶段 3: 真实吞吐测速 (可选, 由 cf.env 驱动) ----
	// 握手延迟只反映"连上 CF 边缘"的耗时, 不反映隧道内的实际转发能力:
	// 同一个 /24 里出现过握手 230ms 的 IP 下载速度只有另一个的 1/4。
	// 所以真正决定用哪个 IP 的必须是端到端吞吐。
	applyIP := final[0].ip
	if conf.CanSpeed() {
		applyIP = runSpeedStage(sp, final, conf, target)
	} else {
		fmt.Println("\n提示   跳过测速" + conf.SpeedSkipReason())
		fmt.Println("       当前排名只按握手延迟, 不代表真实速度 (握手 230ms 的 IP 下载可能只有别人 1/4)")
	}

	// 写回: 直接改 cf.env 里的 IP 字段, 不碰 xray config.json
	if *apply {
		if err := conf.writeIP(*envFile, applyIP); err != nil {
			die("写回 %s 失败: %v", *envFile, err)
		}
		fmt.Printf("\n已写回 %s -> IP=%s\n", *envFile, applyIP)
	}
}

// runSpeedStage 对握手排名靠前的候选做真实吞吐测试, 返回综合最优 IP。
func runSpeedStage(sp speedProfile, final []rank, conf *cfConfig, target probeTarget) string {
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

	if len(results) == 0 || results[0].mbps <= 0 {
		fmt.Println("\n警告   所有测速均失败, 回退到握手排名")
		return final[0].ip
	}
	fmt.Printf("\n综合最优: %s  握手 %.0fms  下载 %.2f MB/s\n",
		results[0].ip, ms(results[0].handshake), results[0].mbps)
	return results[0].ip
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
	Source  string        // 配置来源, 用于提示信息
}

func (s speedProfile) Enabled() bool { return s.URL != "" }

// envOverrides 允许用真环境变量临时覆盖测速参数, 方便一次性试跑。
//
// 只放行 SPEED_* 这一组: 连接参数 (SNI/PORT/WS_PATH 等) 必须来自文件,
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

// parseEnvFile 解析简单的 KEY=VALUE 文件, 支持 # 注释和可选引号。
func parseEnvFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	vals := map[string]string{}
	sc := bufio.NewScanner(f)
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
					if sum := s.tcp + s.tls + s.ws; sum < r.best {
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
				ds[k] = s.tcp + s.tls + s.ws
			}
			r.total = medianDuration(ds)
		} else {
			r.total = time.Duration(math.MaxInt64)
		}
	}
	return out
}

// probeOnce 完成一次冷连接握手: TCP -> TLS1.3 -> HTTP Upgrade, 校验 101。
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

	tlsConn := tls.Client(raw, &tls.Config{
		ServerName:         t.sni,
		InsecureSkipVerify: t.insecure, //nolint:gosec // 探测工具, 默认跳过证书校验
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{"http/1.1"},
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return s, fmt.Errorf("tls: %w", err)
	}
	s.tls = time.Since(start) - s.tcp

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
				"serverName":    c.SNI,
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
		if body, err := fetchURL(cidrURL); err == nil {
			if cs := parseCIDRLines(strings.NewReader(body)); len(cs) > 0 {
				return cs
			}
		}
		fmt.Println("获取在线 CIDR 失败, 使用内置网段")
	}
	return parseCIDRLines(strings.NewReader(strings.Join(fallbackCIDRs, "\n")))
}

func fetchURL(url string) (string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
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
	SNI      string
	Host     string
	Port     int
	Path     string
	Protocol string
	Password string
	XrayBin  string
	Speed    speedProfile
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
		miss = append(miss, "缺少 PASSWORD")
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

// loadConfig 读取 cf.env。SNI 是必填项, 其余有默认值。
func loadConfig(path string) (*cfConfig, error) {
	vals, err := parseEnvFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("配置文件不存在: %s (复制 cf.env.example 或自己创建一个)", path)
		}
		return nil, fmt.Errorf("读取 %s 失败: %w", path, err)
	}
	for k, v := range envOverrides() {
		vals[k] = v
	}

	c := &cfConfig{
		SNI:      vals["SNI"],
		Host:     vals["HOST"],
		Port:     defaultPort,
		Path:     defaultPath,
		Protocol: vals["PROTOCOL"],
		Password: vals["PASSWORD"],
		XrayBin:  vals["XRAY_BIN"],
	}
	if c.SNI == "" {
		return nil, fmt.Errorf("%s 缺少 SNI", path)
	}
	if c.Host == "" {
		c.Host = c.SNI
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
	sp := speedProfile{Top: 5, Repeats: 3, Timeout: 40 * time.Second, Source: path}
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

// writeIP 把选出的 IP 写回 cf.env 的 IP 行 (没有就追加)。
func (c *cfConfig) writeIP(path, ip string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(data), "\n")
	replaced := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "IP=") || strings.HasPrefix(trimmed, "IP =") {
			lines[i] = "IP=" + ip
			replaced = true
			break
		}
	}
	if !replaced {
		lines = append(lines, "IP="+ip)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
