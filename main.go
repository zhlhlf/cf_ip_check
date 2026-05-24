package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxCIDRs   = 4096
	maxIPs     = 10000
	maxResults = 10000
	maxLineLen = 16384

	defaultPort    = 2096
	defaultCount   = 16
	defaultSamples = 512
	defaultThreads = 50
	defaultTimeout = 2 * time.Second
)

var fallbackCIDRs = []string{
	"108.162.198.0/24",
	"172.64.144.0/22",
	"104.18.32.0/20",
	"162.159.32.0/20",
	"173.245.58.0/23",
	"104.26.0.0/20",
}

var version = "dev"

type cidrBlock struct {
	network   uint32
	prefix    int
	hostCount uint32
}

type taskResult struct {
	ip      string
	port    int
	timeout time.Duration
	success bool
	delay   time.Duration
}

type bestNode struct {
	ip string
}

type options struct {
	configFile     string
	port           int
	password       string
	sni            string
	changeFile     bool
	changePort     bool
	changePassword bool
	changeSNI      bool
}

func main() {
	rand.Seed(time.Now().UnixNano())

	opts, err := parseArgs(os.Args)
	if err != nil {
		if errors.Is(err, errHelp) {
			printUsage(os.Args[0])
			return
		}
		fmt.Fprintln(os.Stderr, err)
		printUsage(os.Args[0])
		os.Exit(1)
	}

	fmt.Printf("\n开始优选 - 端口: %d\n", opts.port)
	if opts.changeFile {
		fmt.Printf("目标配置文件: %s\n", opts.configFile)
	} else {
		fmt.Println("未指定配置文件，仅打印优选结果")
	}
	fmt.Println()

	cidrs := loadCIDRs("https://ghfast.top/raw.githubusercontent.com/cmliu/cmliu/main/CF-CIDR.txt")
	candidates := generateCandidateIPs(cidrs, defaultSamples)
	fmt.Printf("生成 %d 个候选 IP，开始测试...\n\n", len(candidates))

	results := testCandidates(candidates, opts.port, defaultTimeout, defaultThreads)
	successes := make([]taskResult, 0, len(results))
	for _, result := range results {
		if result.success {
			fmt.Printf("成功 %s:%d - %.0fms\n", result.ip, result.port, float64(result.delay.Microseconds())/1000)
			successes = append(successes, result)
			continue
		}
		fmt.Printf("失败 %s:%d - 超时\n", result.ip, result.port)
	}

	sort.Slice(successes, func(i, j int) bool {
		return successes[i].delay < successes[j].delay
	})

	count := defaultCount
	if count > len(successes) {
		count = len(successes)
	}

	fmt.Print("\n优选结果\n\n")
	for i := 0; i < count; i++ {
		fmt.Printf("%s:%d# %.0fms\n", successes[i].ip, successes[i].port, float64(successes[i].delay.Microseconds())/1000)
	}

	if opts.changeFile {
		bestCount := min(len(successes), 16)
		nodes := make([]bestNode, bestCount)
		for i := 0; i < bestCount; i++ {
			nodes[i] = bestNode{ip: successes[i].ip}
		}

		if _, err := updateConfigYAML(opts.configFile, nodes, opts); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}

var errHelp = errors.New("help requested")

func parseArgs(args []string) (options, error) {
	opts := options{port: defaultPort}
	if len(args) >= 2 {
		if args[1] == "-h" || args[1] == "--help" {
			return opts, errHelp
		}
		if args[1] == "-v" || args[1] == "--version" {
			fmt.Println(version)
			os.Exit(0)
		}
		opts.configFile = args[1]
		opts.changeFile = true
		opts.changePort = true
	}
	if len(args) >= 3 {
		port, err := strconv.Atoi(args[2])
		if err != nil || port <= 0 || port > 65535 {
			return opts, fmt.Errorf("端口无效: %q", args[2])
		}
		opts.port = port
		opts.changePort = true
	}
	if len(args) >= 4 {
		opts.password = args[3]
		opts.changePassword = true
	}
	if len(args) >= 5 {
		opts.sni = args[4]
		opts.changeSNI = true
	}
	if len(args) > 5 {
		return opts, fmt.Errorf("参数过多")
	}
	return opts, nil
}

func printUsage(prog string) {
	fmt.Println("用法:")
	fmt.Printf("  %s [config文件] [端口] [password] [sni]\n", prog)
	fmt.Println()
	fmt.Println("示例:")
	fmt.Printf("  %s\n", prog)
	fmt.Printf("  %s config.yaml\n", prog)
	fmt.Printf("  %s config.yaml 2096\n", prog)
	fmt.Printf("  %s config.yaml 2096 YOUR_PASSWORD\n", prog)
	fmt.Printf("  %s config.yaml 2096 YOUR_PASSWORD YOUR_SNI_DOMAIN\n", prog)
}

func loadCIDRs(url string) []cidrBlock {
	if body, err := fetchURL(url); err == nil {
		cidrs := parseCIDRLines(body)
		if len(cidrs) > 0 {
			fmt.Printf("获取到 %d 个 CIDR 网段\n", len(cidrs))
			return cidrs
		}
	}

	fmt.Println("获取 CIDR 失败，使用备用网段")
	cidrs := parseCIDRLines(strings.NewReader(strings.Join(fallbackCIDRs, "\n")))
	fmt.Printf("使用备用 %d 个 CIDR 网段\n", len(cidrs))
	return cidrs
}

func fetchURL(url string) (io.Reader, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "cf-ip-select/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("unexpected status: %s", resp.Status)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return strings.NewReader(string(data)), nil
}

func parseCIDRLines(r io.Reader) []cidrBlock {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 1024), maxLineLen)

	cidrs := make([]cidrBlock, 0, 128)
	for scanner.Scan() && len(cidrs) < maxCIDRs {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		cidr, err := parseCIDR(line)
		if err == nil {
			cidrs = append(cidrs, cidr)
		}
	}
	return cidrs
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
	if bits != 32 || ones < 0 || ones > 32 {
		return cidrBlock{}, fmt.Errorf("bad prefix: %s", raw)
	}

	networkIP := ipNet.IP.To4()
	network := uint32(networkIP[0])<<24 | uint32(networkIP[1])<<16 | uint32(networkIP[2])<<8 | uint32(networkIP[3])

	var hostCount uint32
	numAddresses := uint64(1)
	if ones < 32 {
		numAddresses = 1 << uint(32-ones)
	}
	switch {
	case numAddresses <= 2:
		hostCount = uint32(numAddresses)
	case numAddresses > math.MaxUint32:
		hostCount = math.MaxUint32
	default:
		hostCount = uint32(numAddresses - 2)
	}

	return cidrBlock{
		network:   network,
		prefix:    ones,
		hostCount: hostCount,
	}, nil
}

func generateCandidateIPs(cidrs []cidrBlock, sampleSize int) []string {
	if len(cidrs) == 0 || sampleSize <= 0 {
		return nil
	}
	if sampleSize > maxIPs {
		sampleSize = maxIPs
	}

	var totalWeight uint64
	for _, cidr := range cidrs {
		weight := uint64(cidr.hostCount)
		if weight == 0 {
			weight = 1
		}
		totalWeight += weight
	}

	quotas := make([]int, len(cidrs))
	assigned := 0
	for i, cidr := range cidrs {
		weight := uint64(cidr.hostCount)
		if weight == 0 {
			weight = 1
		}
		quotas[i] = int((uint64(sampleSize) * weight) / totalWeight)
		if quotas[i] < 1 {
			quotas[i] = 1
		}
		assigned += quotas[i]
	}

	for i := 0; assigned < sampleSize; i++ {
		quotas[i%len(quotas)]++
		assigned++
	}

	ips := make([]string, 0, sampleSize)
	for i, quota := range quotas {
		for j := 0; j < quota && len(ips) < sampleSize; j++ {
			ips = append(ips, ipToString(randomIPFromCIDR(cidrs[i])))
		}
	}

	rand.Shuffle(len(ips), func(i, j int) {
		ips[i], ips[j] = ips[j], ips[i]
	})
	return ips
}

func randomIPFromCIDR(cidr cidrBlock) uint32 {
	numAddresses := uint64(1)
	if cidr.prefix < 32 {
		numAddresses = 1 << uint(32-cidr.prefix)
	}
	if numAddresses <= 2 {
		return cidr.network
	}

	rangeSize := uint32(numAddresses - 2)
	hostOffset := uint32(1) + uint32(rand.Int63n(int64(rangeSize)))
	return cidr.network + hostOffset
}

func ipToString(ip uint32) string {
	return net.IPv4(byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip)).String()
}

func testCandidates(ips []string, port int, timeout time.Duration, workers int) []taskResult {
	if len(ips) > maxResults {
		ips = ips[:maxResults]
	}
	if workers < 1 {
		workers = 1
	}

	results := make([]taskResult, len(ips))
	jobs := make(chan int)
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				ip := ips[idx]
				delay, err := tcpConnectTimeout(ip, port, timeout)
				results[idx] = taskResult{
					ip:      ip,
					port:    port,
					timeout: timeout,
					success: err == nil,
					delay:   delay,
				}
				if err != nil {
					results[idx].delay = time.Duration(math.MaxInt64)
				}
			}
		}()
	}

	for i := range ips {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	return results
}

func tcpConnectTimeout(ip string, port int, timeout time.Duration) (time.Duration, error) {
	address := net.JoinHostPort(ip, strconv.Itoa(port))
	dialer := net.Dialer{Timeout: timeout}
	start := time.Now()
	conn, err := dialer.DialContext(context.Background(), "tcp4", address)
	if err != nil {
		return 0, err
	}
	_ = conn.Close()
	return time.Since(start), nil
}

func updateConfigYAML(filename string, nodes []bestNode, opts options) (int, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Printf("未找到 %s，跳过配置更新\n", filename)
			return 0, nil
		}
		return 0, fmt.Errorf("打开配置文件失败: %w", err)
	}

	lines := strings.SplitAfter(string(data), "\n")
	replaced := 0
	for i := range lines {
		for n := 0; n < len(nodes) && n < 16; n++ {
			namePattern := fmt.Sprintf("name: CF官方优选%d", n+1)
			if strings.Contains(lines[i], namePattern) {
				lines[i] = replaceServerPortPasswordSNI(lines[i], nodes[n].ip, opts)
				replaced++
				fmt.Printf("已更新 %s -> %s", namePattern, nodes[n].ip)
				if opts.changePort {
					fmt.Printf(":%d", opts.port)
				}
				fmt.Println()
				break
			}
		}
	}

	if err := os.WriteFile(filename, []byte(strings.Join(lines, "")), 0644); err != nil {
		return replaced, fmt.Errorf("写入配置文件失败: %w", err)
	}

	fmt.Printf("%s 更新完成，共替换 %d 项\n", filename, replaced)
	return replaced, nil
}

func replaceServerPortPasswordSNI(line, newIP string, opts options) string {
	out := replaceFieldValue(line, "server:", newIP)
	if opts.changePort {
		out = replaceFieldValue(out, "port:", strconv.Itoa(opts.port))
	}
	if opts.changePassword && opts.password != "" {
		out = replaceFieldValue(out, "password:", opts.password)
	}
	if opts.changeSNI && opts.sni != "" {
		out = replaceFieldValue(out, "sni:", opts.sni)
		out = replaceHostHeader(out, opts.sni)
	}
	return out
}

func replaceFieldValue(line, key, newValue string) string {
	idx := strings.Index(line, key)
	if idx < 0 {
		return line
	}

	valStart := idx + len(key)
	for valStart < len(line) && line[valStart] == ' ' {
		valStart++
	}

	valEnd := valStart
	for valEnd < len(line) && line[valEnd] != ',' && line[valEnd] != '}' {
		valEnd++
	}

	return line[:valStart] + newValue + line[valEnd:]
}

func replaceHostHeader(line, newHost string) string {
	idx := strings.Index(line, "Host:")
	if idx < 0 {
		return line
	}

	valStart := idx + len("Host:")
	for valStart < len(line) && line[valStart] == ' ' {
		valStart++
	}

	valEnd := valStart
	for valEnd < len(line) && line[valEnd] != '}' && line[valEnd] != ',' {
		valEnd++
	}

	return line[:valStart] + newHost + line[valEnd:]
}
