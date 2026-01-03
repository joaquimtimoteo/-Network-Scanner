// Network Scanner Educacional v2.0
// Demonstra conceitos de: networking, concorrência, CLI em Go
//
// APENAS PARA FINS EDUCACIONAIS
// Use somente em redes que você tem permissão para escanear
package main

import (
	"bufio"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ============================================================================
// CONSTANTS & VERSION
// ============================================================================

const Version = "2.0.0"

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
)

// ============================================================================
// DATA STRUCTURES
// ============================================================================

// Config armazena configurações da linha de comando
type Config struct {
	Target      string
	Ports       string
	Timeout     int
	Workers     int
	ShowClosed  bool
	NoColor     bool
	Help        bool
	OutputJSON  string
	OutputHTML  string
	OutputCSV   string
	Fingerprint bool
	DetectOS    bool
	RateLimit   int
	Verbose     bool
}

// Target representa um alvo de escaneamento
type Target struct {
	IP   string
	Port int
}

// Result representa o resultado de uma tentativa de conexão
type Result struct {
	Target     Target
	Open       bool
	Banner     string
	Latency    time.Duration
	Error      error
	Service    string
	Product    string
	Version    string
	ExtraInfo  map[string]string
	Confidence float64
}

// ScanStats estatísticas do scan
type ScanStats struct {
	TotalTargets   int64
	ScannedTargets int64
	OpenPorts      int64
	ClosedPorts    int64
	StartTime      time.Time
	EndTime        time.Time
}

// Scanner é a estrutura principal do escaneador
type Scanner struct {
	Timeout      time.Duration
	Workers      int
	GrabBanner   bool
	Fingerprint  bool
	DetectOS     bool
	RateLimit    int
	Verbose      bool
	Stats        ScanStats
	ProgressFunc func(current, total int64)
}

// OSInfo contém informações do sistema operacional detectado
type OSInfo struct {
	Family     string
	TTL        int
	Confidence float64
	Method     string
	Details    string
}

// ServiceInfo contém informações detalhadas sobre um serviço
type ServiceInfo struct {
	Name       string
	Version    string
	Product    string
	Banner     string
	Protocol   string
	Confidence float64
	ExtraInfo  map[string]string
}

// ScanResult representa resultado completo de um scan (para output)
type ScanResult struct {
	Timestamp   time.Time    `json:"timestamp"`
	Duration    string       `json:"duration"`
	TargetRange string       `json:"target_range"`
	TotalHosts  int          `json:"total_hosts"`
	AliveHosts  int          `json:"alive_hosts"`
	TotalPorts  int          `json:"total_ports"`
	OpenPorts   int          `json:"open_ports"`
	Hosts       []HostResult `json:"hosts"`
}

// HostResult representa resultado de um host
type HostResult struct {
	IP       string       `json:"ip"`
	Hostname string       `json:"hostname,omitempty"`
	OS       OSResult     `json:"os,omitempty"`
	Ports    []PortResult `json:"ports"`
	Status   string       `json:"status"`
}

// PortResult representa resultado de uma porta
type PortResult struct {
	Port       int               `json:"port"`
	State      string            `json:"state"`
	Service    string            `json:"service"`
	Product    string            `json:"product,omitempty"`
	Version    string            `json:"version,omitempty"`
	Banner     string            `json:"banner,omitempty"`
	Latency    string            `json:"latency"`
	ExtraInfo  map[string]string `json:"extra_info,omitempty"`
	Confidence float64           `json:"confidence"`
}

// OSResult representa resultado de detecção de SO
type OSResult struct {
	Family     string  `json:"family"`
	TTL        int     `json:"ttl,omitempty"`
	Confidence float64 `json:"confidence"`
	Method     string  `json:"method"`
}

// ============================================================================
// MAIN
// ============================================================================

func main() {
	config := parseFlags()

	if config.Help {
		printHelp()
		return
	}

	// Exibe banner e aviso
	printBanner()
	printUsageWarning()

	// Valida entrada
	if config.Target == "" {
		fmt.Println("❌ Error: specify a target with -target")
		fmt.Println("Example: ./scanner -target 127.0.0.1")
		fmt.Println("         ./scanner -target 192.168.1.1-254")
		fmt.Println("         ./scanner -target 10.0.0.0/24")
		os.Exit(1)
	}

	// Parse do range de IPs
	ips, err := parseIPRange(config.Target)
	if err != nil {
		fmt.Printf("❌ Error parsing IP range: %v\n", err)
		os.Exit(1)
	}

	// Configura scanner
	s := NewScanner()
	s.Timeout = time.Duration(config.Timeout) * time.Millisecond
	s.Workers = config.Workers
	s.Fingerprint = config.Fingerprint
	s.DetectOS = config.DetectOS
	s.RateLimit = config.RateLimit
	s.Verbose = config.Verbose

	// Parse das portas
	ports := parsePorts(config.Ports)

	// Informações do scan
	fmt.Println()
	fmt.Printf("🎯 Target: %s\n", ipRangeSummary(ips))
	fmt.Printf("📊 Ports: %d\n", len(ports))
	fmt.Printf("🖥️  Hosts: %d\n", len(ips))
	fmt.Printf("⚡ Workers: %d\n", config.Workers)
	fmt.Printf("⏱️  Timeout: %dms\n", config.Timeout)

	if config.Fingerprint {
		fmt.Println("🔬 Fingerprinting: Enabled")
	}
	if config.DetectOS {
		fmt.Println("🖥️  OS Detection: Enabled")
	}
	if config.RateLimit > 0 {
		fmt.Printf("🚦 Rate Limit: %d/sec\n", config.RateLimit)
	}

	fmt.Println()
	fmt.Println("🔍 Starting scan...")
	fmt.Println()

	// Executa escaneamento
	start := time.Now()
	var allResults []Result
	var hostResults []HostResult

	// Progress tracking
	totalTargets := len(ips) * len(ports)

	s.ProgressFunc = func(current, total int64) {
		if current%100 == 0 || current == total {
			pct := float64(current) / float64(total) * 100
			bar := strings.Repeat("█", int(pct/5)) + strings.Repeat("░", 20-int(pct/5))
			fmt.Printf("\r  [%s] %.1f%% (%d/%d)", bar, pct, current, total)
		}
	}

	// Escaneia cada host
	for _, ip := range ips {
		targets := generateTargets(ip, ports)
		results := s.ScanRange(targets)
		allResults = append(allResults, results...)

		// Processa resultados do host
		hostResult := processHostResult(ip, results, config)
		hostResults = append(hostResults, hostResult)
	}

	duration := time.Since(start)

	// Limpa linha do progress
	if totalTargets > 100 {
		fmt.Println()
	}

	// Exibe resultados detalhados
	printDetailedResults(hostResults, config.ShowClosed)

	// Exibe resumo
	printSummary(allResults, duration, len(ips))

	// Salva outputs se solicitado
	if config.OutputJSON != "" || config.OutputHTML != "" || config.OutputCSV != "" {
		scanResult := buildScanResult(hostResults, config.Target, duration)

		if config.OutputJSON != "" {
			if err := saveJSON(scanResult, config.OutputJSON); err != nil {
				fmt.Printf("❌ Error saving JSON: %v\n", err)
			} else {
				fmt.Printf("💾 Saved: %s\n", config.OutputJSON)
			}
		}

		if config.OutputHTML != "" {
			if err := saveHTML(scanResult, config.OutputHTML); err != nil {
				fmt.Printf("❌ Error saving HTML: %v\n", err)
			} else {
				fmt.Printf("💾 Saved: %s\n", config.OutputHTML)
			}
		}

		if config.OutputCSV != "" {
			if err := saveCSV(scanResult, config.OutputCSV); err != nil {
				fmt.Printf("❌ Error saving CSV: %v\n", err)
			} else {
				fmt.Printf("💾 Saved: %s\n", config.OutputCSV)
			}
		}
	}
}

// ============================================================================
// SCANNER CORE
// ============================================================================

// NewScanner cria um novo scanner com configurações padrão
func NewScanner() *Scanner {
	return &Scanner{
		Timeout:     2 * time.Second,
		Workers:     100,
		GrabBanner:  true,
		Fingerprint: false,
		DetectOS:    false,
		RateLimit:   0,
		Verbose:     false,
	}
}

// ScanPort verifica se uma porta está aberta em um IP
func (s *Scanner) ScanPort(target Target) Result {
	result := Result{
		Target:    target,
		ExtraInfo: make(map[string]string),
	}

	address := fmt.Sprintf("%s:%d", target.IP, target.Port)
	start := time.Now()

	conn, err := net.DialTimeout("tcp", address, s.Timeout)
	result.Latency = time.Since(start)

	if err != nil {
		result.Open = false
		result.Error = err
		atomic.AddInt64(&s.Stats.ClosedPorts, 1)
		return result
	}
	defer conn.Close()

	result.Open = true
	atomic.AddInt64(&s.Stats.OpenPorts, 1)

	result.Service = getPortService(target.Port)

	if s.GrabBanner {
		result.Banner = grabBanner(conn)
		if result.Banner != "" {
			parseBannerInfo(&result)
		}
	}

	return result
}

// grabBanner tenta ler dados iniciais da conexão
func grabBanner(conn net.Conn) string {
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return ""
	}

	return string(buffer[:n])
}

// parseBannerInfo extrai informações do banner
func parseBannerInfo(result *Result) {
	banner := result.Banner

	// SSH
	if len(banner) > 4 && banner[:4] == "SSH-" {
		result.Service = "SSH"
		parts := strings.Split(banner, "-")
		if len(parts) >= 3 {
			result.Product = strings.TrimSpace(parts[2])
			if len(parts) > 3 {
				result.ExtraInfo["os_hint"] = strings.TrimSpace(strings.Split(parts[3], "\n")[0])
			}
		}
		result.Confidence = 0.9
	}

	// FTP
	if len(banner) >= 3 && banner[:3] == "220" {
		if strings.Contains(banner, "FTP") || result.Target.Port == 21 {
			result.Service = "FTP"
			result.Confidence = 0.8
		}
	}

	// HTTP
	if strings.Contains(banner, "HTTP/") {
		result.Service = "HTTP"
		result.Confidence = 0.9
	}

	// SMTP
	if len(banner) >= 3 && banner[:3] == "220" && result.Target.Port == 25 {
		result.Service = "SMTP"
		result.Confidence = 0.8
	}
}

// ScanRange escaneia múltiplos alvos usando worker pool
func (s *Scanner) ScanRange(targets []Target) []Result {
	var results []Result
	var mu sync.Mutex
	var wg sync.WaitGroup

	s.Stats.TotalTargets = int64(len(targets))
	s.Stats.StartTime = time.Now()

	jobs := make(chan Target, len(targets))

	var rateLimiter <-chan time.Time
	if s.RateLimit > 0 {
		rateLimiter = time.Tick(time.Second / time.Duration(s.RateLimit))
	}

	for i := 0; i < s.Workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for target := range jobs {
				if rateLimiter != nil {
					<-rateLimiter
				}

				result := s.ScanPort(target)

				current := atomic.AddInt64(&s.Stats.ScannedTargets, 1)
				if s.ProgressFunc != nil {
					s.ProgressFunc(current, s.Stats.TotalTargets)
				}

				mu.Lock()
				results = append(results, result)
				mu.Unlock()
			}
		}(i)
	}

	for _, target := range targets {
		jobs <- target
	}
	close(jobs)

	wg.Wait()

	s.Stats.EndTime = time.Now()

	return results
}

// generateTargets cria lista de alvos para um IP
func generateTargets(ip string, ports []int) []Target {
	var targets []Target
	for _, port := range ports {
		targets = append(targets, Target{IP: ip, Port: port})
	}
	return targets
}

// ============================================================================
// IP RANGE PARSING
// ============================================================================

// parseIPRange converte uma string de range em lista de IPs
func parseIPRange(input string) ([]string, error) {
	input = strings.TrimSpace(input)

	// Lista separada por vírgula
	if strings.Contains(input, ",") && !strings.Contains(input, "/") {
		return parseIPList(input)
	}

	// Notação CIDR
	if strings.Contains(input, "/") {
		return parseCIDR(input)
	}

	// Range com hífen (192.168.1.1-254)
	if strings.Contains(input, "-") {
		return parseHyphenRange(input)
	}

	// IP único
	if net.ParseIP(input) != nil {
		return []string{input}, nil
	}

	return nil, fmt.Errorf("invalid format: %s", input)
}

// parseIPList processa lista separada por vírgula
func parseIPList(input string) ([]string, error) {
	parts := strings.Split(input, ",")
	var ips []string

	for _, p := range parts {
		p = strings.TrimSpace(p)
		if net.ParseIP(p) != nil {
			ips = append(ips, p)
		} else {
			return nil, fmt.Errorf("invalid IP in list: %s", p)
		}
	}

	return ips, nil
}

// parseHyphenRange processa ranges como 192.168.1.1-254
func parseHyphenRange(input string) ([]string, error) {
	hyphenIdx := strings.LastIndex(input, "-")
	if hyphenIdx == -1 {
		return nil, fmt.Errorf("invalid range format: %s", input)
	}

	baseIP := input[:hyphenIdx]
	endPart := input[hyphenIdx+1:]

	endNum, err := strconv.Atoi(endPart)
	if err != nil {
		return nil, fmt.Errorf("invalid range end: %s", endPart)
	}

	startIP := net.ParseIP(baseIP)
	if startIP == nil {
		return nil, fmt.Errorf("invalid base IP: %s", baseIP)
	}

	ip4 := startIP.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("only IPv4 supported: %s", baseIP)
	}

	startNum := int(ip4[3])
	if endNum < startNum || endNum > 255 {
		return nil, fmt.Errorf("invalid range: %d-%d", startNum, endNum)
	}

	var ips []string
	for i := startNum; i <= endNum; i++ {
		ip := fmt.Sprintf("%d.%d.%d.%d", ip4[0], ip4[1], ip4[2], i)
		ips = append(ips, ip)
	}

	return ips, nil
}

// parseCIDR processa notação CIDR (192.168.1.0/24)
func parseCIDR(input string) ([]string, error) {
	_, ipnet, err := net.ParseCIDR(input)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR: %s", input)
	}

	var ips []string
	for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
		ipCopy := make(net.IP, len(ip))
		copy(ipCopy, ip)
		ips = append(ips, ipCopy.String())
	}

	// Remove endereço de rede e broadcast
	if len(ips) > 2 {
		ones, _ := ipnet.Mask.Size()
		if ones <= 30 {
			ips = ips[1 : len(ips)-1]
		}
	}

	return ips, nil
}

// incrementIP incrementa um IP em 1
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// ipRangeSummary retorna um resumo do range
func ipRangeSummary(ips []string) string {
	if len(ips) == 0 {
		return "No IPs"
	}
	if len(ips) == 1 {
		return ips[0]
	}
	return fmt.Sprintf("%s - %s (%d hosts)", ips[0], ips[len(ips)-1], len(ips))
}

// ============================================================================
// OS DETECTION
// ============================================================================

// TTL padrões por sistema operacional
var ttlDatabase = map[int]string{
	64:  "Linux/macOS/Android",
	128: "Windows",
	255: "Solaris/Cisco/Network Device",
	254: "Solaris/AIX",
	60:  "HP-UX",
}

// detectOS tenta identificar o SO do alvo
func detectOS(ip string, openPorts []int) OSInfo {
	info := OSInfo{
		Family:     "Unknown",
		Confidence: 0,
		Method:     "none",
	}

	// Método 1: TTL via ping
	ttl, err := getTTLFromPing(ip)
	if err == nil && ttl > 0 {
		info.TTL = ttl
		info.Family = guessOSFromTTL(ttl)
		info.Confidence = 0.6
		info.Method = "TTL"
	}

	// Método 2: Análise de portas abertas
	portHint := guessOSFromPorts(openPorts)
	if portHint != "" {
		if info.Family == "Unknown" {
			info.Family = portHint
			info.Confidence = 0.4
			info.Method = "Ports"
		} else if strings.Contains(info.Family, portHint) || strings.Contains(portHint, info.Family) {
			info.Confidence = 0.8
			info.Method = "TTL+Ports"
		}
	}

	return info
}

// getTTLFromPing executa ping e extrai TTL da resposta
func getTTLFromPing(ip string) (int, error) {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("ping", "-n", "1", "-w", "1000", ip)
	default:
		cmd = exec.Command("ping", "-c", "1", "-W", "1", ip)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return 0, err
	}

	return parseTTLFromPingOutput(string(output))
}

// parseTTLFromPingOutput extrai TTL do output do ping
func parseTTLFromPingOutput(output string) (int, error) {
	patterns := []string{
		`ttl=(\d+)`,
		`TTL=(\d+)`,
		`hlim=(\d+)`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(output)
		if len(matches) > 1 {
			ttl, err := strconv.Atoi(matches[1])
			if err == nil {
				return ttl, nil
			}
		}
	}

	return 0, nil
}

// guessOSFromTTL estima SO baseado no TTL
func guessOSFromTTL(ttl int) string {
	originalTTL := estimateOriginalTTL(ttl)

	if os, ok := ttlDatabase[originalTTL]; ok {
		return os
	}

	switch {
	case originalTTL >= 128:
		return "Windows"
	case originalTTL >= 64:
		return "Linux/Unix"
	case originalTTL >= 32:
		return "Embedded/Old System"
	default:
		return "Unknown"
	}
}

// estimateOriginalTTL estima o TTL original baseado no observado
func estimateOriginalTTL(observed int) int {
	standards := []int{32, 64, 128, 255}

	for _, std := range standards {
		if observed <= std && observed > std-30 {
			return std
		}
	}

	return observed
}

// guessOSFromPorts estima SO baseado em portas abertas
func guessOSFromPorts(ports []int) string {
	portSet := make(map[int]bool)
	for _, p := range ports {
		portSet[p] = true
	}

	if portSet[135] || portSet[139] || portSet[445] || portSet[3389] {
		return "Windows"
	}

	if portSet[22] && !portSet[3389] {
		return "Linux"
	}

	if portSet[548] || portSet[5900] {
		return "macOS"
	}

	if portSet[161] || portSet[162] {
		return "Network Device"
	}

	return ""
}

// getOSEmoji retorna emoji representativo do SO
func getOSEmoji(family string) string {
	family = strings.ToLower(family)

	switch {
	case strings.Contains(family, "windows"):
		return "🪟"
	case strings.Contains(family, "linux"):
		return "🐧"
	case strings.Contains(family, "macos"), strings.Contains(family, "darwin"):
		return "🍎"
	case strings.Contains(family, "bsd"):
		return "😈"
	case strings.Contains(family, "cisco"), strings.Contains(family, "network"):
		return "🌐"
	case strings.Contains(family, "android"):
		return "🤖"
	default:
		return "❓"
	}
}

// ============================================================================
// FINGERPRINTING
// ============================================================================

// fingerprint realiza fingerprinting completo de um serviço
func fingerprint(ip string, port int, timeout time.Duration) ServiceInfo {
	info := ServiceInfo{
		Name:      getPortService(port),
		Protocol:  "tcp",
		ExtraInfo: make(map[string]string),
	}

	address := fmt.Sprintf("%s:%d", ip, port)

	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return info
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	banner := readBanner(conn)

	if banner != "" {
		info.Banner = banner
		parseGenericBanner(&info)
	}

	// Probes específicos por porta
	switch port {
	case 80, 8080, 8000, 8888:
		probeHTTP(ip, port, &info, false)
	case 443, 8443:
		probeHTTP(ip, port, &info, true)
	case 22:
		parseSSHBanner(&info)
	case 21:
		parseFTPBanner(&info)
	case 25, 587:
		parseSMTPBanner(&info)
	}

	calculateConfidence(&info)

	return info
}

// readBanner lê banner inicial da conexão
func readBanner(conn net.Conn) string {
	reader := bufio.NewReader(conn)
	var lines []string

	for i := 0; i < 5; i++ {
		line, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		lines = append(lines, strings.TrimSpace(line))
	}

	return strings.Join(lines, "\n")
}

// probeHTTP faz probe HTTP/HTTPS
func probeHTTP(ip string, port int, info *ServiceInfo, useTLS bool) {
	scheme := "http"
	if useTLS {
		scheme = "https"
	}

	url := fmt.Sprintf("%s://%s:%d/", scheme, ip, port)

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	info.Name = "HTTP"
	if useTLS {
		info.Name = "HTTPS"
		info.ExtraInfo["tls"] = "true"
	}

	if server := resp.Header.Get("Server"); server != "" {
		info.Product = server
		info.ExtraInfo["server"] = server

		// Extrai versão
		if strings.Contains(strings.ToLower(server), "nginx") {
			info.Product = "nginx"
			if match := regexp.MustCompile(`nginx/([\d.]+)`).FindStringSubmatch(server); len(match) > 1 {
				info.Version = match[1]
			}
		} else if strings.Contains(strings.ToLower(server), "apache") {
			info.Product = "Apache"
			if match := regexp.MustCompile(`Apache/([\d.]+)`).FindStringSubmatch(server); len(match) > 1 {
				info.Version = match[1]
			}
		}
	}

	if powered := resp.Header.Get("X-Powered-By"); powered != "" {
		info.ExtraInfo["powered_by"] = powered
	}

	info.ExtraInfo["status"] = fmt.Sprintf("%d", resp.StatusCode)
}

// parseSSHBanner extrai info do banner SSH
func parseSSHBanner(info *ServiceInfo) {
	if info.Banner == "" {
		return
	}

	info.Name = "SSH"

	re := regexp.MustCompile(`SSH-([\d.]+)-(\S+)(?:\s+(.+))?`)
	matches := re.FindStringSubmatch(info.Banner)

	if len(matches) > 2 {
		info.ExtraInfo["protocol"] = matches[1]
		info.Product = matches[2]

		if verMatch := regexp.MustCompile(`[\d.]+`).FindString(matches[2]); verMatch != "" {
			info.Version = verMatch
		}

		if len(matches) > 3 && matches[3] != "" {
			info.ExtraInfo["os_hint"] = matches[3]
		}
	}
}

// parseFTPBanner extrai info do banner FTP
func parseFTPBanner(info *ServiceInfo) {
	info.Name = "FTP"
	banner := strings.ToLower(info.Banner)

	switch {
	case strings.Contains(banner, "vsftpd"):
		info.Product = "vsftpd"
	case strings.Contains(banner, "proftpd"):
		info.Product = "ProFTPD"
	case strings.Contains(banner, "filezilla"):
		info.Product = "FileZilla Server"
	case strings.Contains(banner, "pure-ftpd"):
		info.Product = "Pure-FTPd"
	}
}

// parseSMTPBanner extrai info do banner SMTP
func parseSMTPBanner(info *ServiceInfo) {
	info.Name = "SMTP"
	banner := strings.ToLower(info.Banner)

	switch {
	case strings.Contains(banner, "postfix"):
		info.Product = "Postfix"
	case strings.Contains(banner, "exim"):
		info.Product = "Exim"
	case strings.Contains(banner, "sendmail"):
		info.Product = "Sendmail"
	case strings.Contains(banner, "exchange"):
		info.Product = "Microsoft Exchange"
	}
}

// parseGenericBanner parsing genérico de banner
func parseGenericBanner(info *ServiceInfo) {
	banner := info.Banner

	patterns := map[string]*regexp.Regexp{
		"SSH":        regexp.MustCompile(`^SSH-`),
		"FTP":        regexp.MustCompile(`^220[- ].*FTP`),
		"SMTP":       regexp.MustCompile(`^220[- ].*SMTP|^220[- ].*mail`),
		"HTTP":       regexp.MustCompile(`^HTTP/`),
		"MySQL":      regexp.MustCompile(`mysql|MariaDB`),
		"PostgreSQL": regexp.MustCompile(`PostgreSQL`),
		"Redis":      regexp.MustCompile(`redis_version`),
		"MongoDB":    regexp.MustCompile(`MongoDB|mongod`),
	}

	for service, pattern := range patterns {
		if pattern.MatchString(banner) {
			info.Name = service
			break
		}
	}
}

// calculateConfidence calcula confiança da detecção
func calculateConfidence(info *ServiceInfo) {
	confidence := 0.0

	if info.Product != "" {
		confidence += 0.4
	}
	if info.Version != "" {
		confidence += 0.3
	}
	if info.Banner != "" {
		confidence += 0.2
	}
	if len(info.ExtraInfo) > 0 {
		confidence += 0.1
	}

	if confidence > 1.0 {
		confidence = 1.0
	}

	info.Confidence = confidence
}

// ============================================================================
// PORT SERVICES
// ============================================================================

// getPortService retorna nome padrão do serviço por porta
func getPortService(port int) string {
	services := map[int]string{
		20:    "FTP-Data",
		21:    "FTP",
		22:    "SSH",
		23:    "Telnet",
		25:    "SMTP",
		53:    "DNS",
		67:    "DHCP",
		68:    "DHCP",
		69:    "TFTP",
		80:    "HTTP",
		110:   "POP3",
		119:   "NNTP",
		123:   "NTP",
		135:   "MSRPC",
		137:   "NetBIOS-NS",
		138:   "NetBIOS-DGM",
		139:   "NetBIOS-SSN",
		143:   "IMAP",
		161:   "SNMP",
		162:   "SNMP-Trap",
		389:   "LDAP",
		443:   "HTTPS",
		445:   "SMB",
		465:   "SMTPS",
		514:   "Syslog",
		587:   "SMTP-Submission",
		636:   "LDAPS",
		993:   "IMAPS",
		995:   "POP3S",
		1433:  "MSSQL",
		1521:  "Oracle",
		1723:  "PPTP",
		3306:  "MySQL",
		3389:  "RDP",
		5432:  "PostgreSQL",
		5900:  "VNC",
		6379:  "Redis",
		8080:  "HTTP-Alt",
		8443:  "HTTPS-Alt",
		27017: "MongoDB",
	}

	if name, ok := services[port]; ok {
		return name
	}
	return "Unknown"
}

// commonPorts retorna portas comumente escaneadas
func commonPorts() []int {
	return []int{
		21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
		3306, 3389, 5432, 6379, 8080, 8443,
	}
}

// top100Ports retorna as 100 portas mais comuns
func top100Ports() []int {
	return []int{
		7, 9, 13, 21, 22, 23, 25, 26, 37, 53,
		79, 80, 81, 82, 83, 84, 85, 88, 89, 90,
		99, 100, 106, 110, 111, 113, 119, 125, 135, 139,
		143, 144, 146, 161, 163, 179, 199, 211, 212, 222,
		254, 255, 256, 259, 264, 280, 301, 306, 311, 340,
		366, 389, 406, 407, 416, 417, 425, 427, 443, 444,
		445, 458, 464, 465, 481, 497, 500, 512, 513, 514,
		515, 524, 541, 543, 544, 545, 548, 554, 555, 563,
		587, 593, 616, 617, 625, 631, 636, 646, 648, 666,
		667, 668, 683, 687, 691, 700, 705, 711, 714, 720,
	}
}

// ============================================================================
// OUTPUT FUNCTIONS
// ============================================================================

// saveJSON salva resultados em formato JSON
func saveJSON(result ScanResult, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("error creating file: %w", err)
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	if err := encoder.Encode(result); err != nil {
		return fmt.Errorf("error encoding JSON: %w", err)
	}

	return nil
}

// saveCSV salva resultados em formato CSV
func saveCSV(result ScanResult, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("error creating file: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	header := []string{"IP", "Hostname", "OS", "Port", "State", "Service", "Product", "Version", "Banner", "Latency"}
	if err := writer.Write(header); err != nil {
		return err
	}

	for _, host := range result.Hosts {
		for _, port := range host.Ports {
			row := []string{
				host.IP,
				host.Hostname,
				host.OS.Family,
				fmt.Sprintf("%d", port.Port),
				port.State,
				port.Service,
				port.Product,
				port.Version,
				port.Banner,
				port.Latency,
			}
			if err := writer.Write(row); err != nil {
				return err
			}
		}
	}

	return nil
}

// HTML template para relatório
const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Scanner Report</title>
    <style>
        :root {
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --accent-green: #3fb950;
            --accent-red: #f85149;
            --accent-yellow: #d29922;
            --accent-blue: #58a6ff;
            --border-color: #30363d;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        header { text-align: center; padding: 40px 0; border-bottom: 1px solid var(--border-color); margin-bottom: 30px; }
        h1 { font-size: 2.5em; margin-bottom: 10px; background: linear-gradient(135deg, var(--accent-blue), var(--accent-green)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .meta { color: var(--text-secondary); font-size: 0.9em; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 40px; }
        .summary-card { background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 8px; padding: 20px; text-align: center; }
        .summary-card .value { font-size: 2.5em; font-weight: bold; color: var(--accent-blue); }
        .summary-card .label { color: var(--text-secondary); font-size: 0.9em; margin-top: 5px; }
        .summary-card.open .value { color: var(--accent-green); }
        .summary-card.closed .value { color: var(--accent-red); }
        .host-card { background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 8px; margin-bottom: 20px; overflow: hidden; }
        .host-header { background: var(--bg-tertiary); padding: 15px 20px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-color); }
        .host-ip { font-size: 1.3em; font-weight: bold; font-family: 'Consolas', monospace; }
        .host-os { display: flex; align-items: center; gap: 8px; color: var(--text-secondary); }
        .os-icon { font-size: 1.5em; }
        .ports-table { width: 100%; border-collapse: collapse; }
        .ports-table th, .ports-table td { padding: 12px 20px; text-align: left; border-bottom: 1px solid var(--border-color); }
        .ports-table th { background: var(--bg-tertiary); color: var(--text-secondary); font-weight: 600; text-transform: uppercase; font-size: 0.8em; }
        .ports-table tr:last-child td { border-bottom: none; }
        .ports-table tr:hover { background: var(--bg-tertiary); }
        .port-number { font-family: 'Consolas', monospace; font-weight: bold; }
        .state-open { color: var(--accent-green); font-weight: bold; }
        .state-closed { color: var(--accent-red); }
        .service-name { color: var(--accent-blue); }
        .banner { font-family: 'Consolas', monospace; font-size: 0.85em; color: var(--text-secondary); max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        footer { text-align: center; padding: 40px 0; color: var(--text-secondary); border-top: 1px solid var(--border-color); margin-top: 40px; }
        .warning { background: rgba(210, 153, 34, 0.1); border: 1px solid var(--accent-yellow); border-radius: 8px; padding: 15px 20px; margin-bottom: 30px; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 Network Scanner Report</h1>
            <p class="meta">Generated: {{.Timestamp.Format "2006-01-02 15:04:05"}} | Duration: {{.Duration}} | Target: {{.TargetRange}}</p>
        </header>
        <div class="warning">⚠️ <strong>EDUCATIONAL PURPOSES ONLY</strong> - Use only on authorized networks</div>
        <section class="summary">
            <div class="summary-card"><div class="value">{{.TotalHosts}}</div><div class="label">Total Hosts</div></div>
            <div class="summary-card"><div class="value">{{.AliveHosts}}</div><div class="label">Alive Hosts</div></div>
            <div class="summary-card open"><div class="value">{{.OpenPorts}}</div><div class="label">Open Ports</div></div>
            <div class="summary-card closed"><div class="value">{{minus .TotalPorts .OpenPorts}}</div><div class="label">Closed Ports</div></div>
        </section>
        {{range .Hosts}}{{if hasOpenPorts .Ports}}
        <div class="host-card">
            <div class="host-header">
                <div><span class="host-ip">{{.IP}}</span>{{if .Hostname}} <span>({{.Hostname}})</span>{{end}}</div>
                <div class="host-os"><span class="os-icon">{{osEmoji .OS.Family}}</span><span>{{.OS.Family}}</span></div>
            </div>
            <table class="ports-table">
                <thead><tr><th>Port</th><th>State</th><th>Service</th><th>Product/Version</th><th>Banner</th><th>Latency</th></tr></thead>
                <tbody>
                {{range .Ports}}{{if eq .State "open"}}
                <tr>
                    <td class="port-number">{{.Port}}</td>
                    <td class="state-{{.State}}">{{.State}}</td>
                    <td class="service-name">{{.Service}}</td>
                    <td>{{.Product}}{{if .Version}} <small>v{{.Version}}</small>{{end}}</td>
                    <td class="banner" title="{{.Banner}}">{{truncate .Banner 40}}</td>
                    <td>{{.Latency}}</td>
                </tr>
                {{end}}{{end}}
                </tbody>
            </table>
        </div>
        {{end}}{{end}}
        <footer><p>🔍 Network Scanner Educational v2.0</p><p>Developed for educational purposes in Go</p></footer>
    </div>
</body>
</html>`

// saveHTML salva resultados em formato HTML
func saveHTML(result ScanResult, filename string) error {
	funcMap := template.FuncMap{
		"minus": func(a, b int) int { return a - b },
		"osEmoji": func(family string) string {
			switch {
			case strings.Contains(strings.ToLower(family), "windows"):
				return "🪟"
			case strings.Contains(strings.ToLower(family), "linux"):
				return "🐧"
			case strings.Contains(strings.ToLower(family), "macos"):
				return "🍎"
			default:
				return "💻"
			}
		},
		"truncate": func(s string, n int) string {
			if len(s) <= n {
				return s
			}
			return s[:n] + "..."
		},
		"hasOpenPorts": func(ports []PortResult) bool {
			for _, p := range ports {
				if p.State == "open" {
					return true
				}
			}
			return false
		},
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("error parsing template: %w", err)
	}

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("error creating file: %w", err)
	}
	defer file.Close()

	if err := tmpl.Execute(file, result); err != nil {
		return fmt.Errorf("error executing template: %w", err)
	}

	return nil
}

// ============================================================================
// DISPLAY FUNCTIONS
// ============================================================================

// printBanner exibe o banner inicial do programa
func printBanner() {
	banner := `
    _   __     __  _____                                    ___   ____ 
   / | / /__  / /_/ ___/_________ _____  ____  ___  _____  |__ \ / __ \
  /  |/ / _ \/ __/\__ \/ ___/ __ '/ __ \/ __ \/ _ \/ ___/  __/ // / / /
 / /|  /  __/ /_ ___/ / /__/ /_/ / / / / / / /  __/ /     / __// /_/ / 
/_/ |_/\___/\__//____/\___/\__,_/_/ /_/_/ /_/\___/_/     /____/\____/  
                                                         
    ╔═══════════════════════════════════════════════════════════╗
    ║  EDUCATIONAL TOOL - FOR STUDY PURPOSES ONLY              ║
    ║  Use only on networks where you have permission!         ║
    ╚═══════════════════════════════════════════════════════════╝
`
	fmt.Println(banner)
}

// printUsageWarning exibe aviso de uso ético
func printUsageWarning() {
	fmt.Println(`
┌─────────────────────────────────────────────────────────────┐
│                    ⚠️  IMPORTANT NOTICE                      │
├─────────────────────────────────────────────────────────────┤
│ This tool is for EDUCATIONAL purposes ONLY.                 │
│                                                             │
│ ✓ USE on: your own network, lab environments, CTFs          │
│ ✗ DO NOT USE on: networks without explicit authorization    │
│                                                             │
│ Unauthorized scanning may be ILLEGAL in your country.       │
│ You are responsible for the use of this tool.               │
└─────────────────────────────────────────────────────────────┘
`)
}

// processHostResult processa resultados de um host
func processHostResult(ip string, results []Result, config Config) HostResult {
	host := HostResult{
		IP:     ip,
		Status: "down",
		Ports:  make([]PortResult, 0),
	}

	var openPorts []int
	for _, r := range results {
		port := PortResult{
			Port:      r.Target.Port,
			State:     "closed",
			Service:   getPortService(r.Target.Port),
			Latency:   r.Latency.String(),
			ExtraInfo: make(map[string]string),
		}

		if r.Open {
			port.State = "open"
			host.Status = "up"
			openPorts = append(openPorts, r.Target.Port)

			if config.Fingerprint {
				fp := fingerprint(ip, r.Target.Port, time.Duration(config.Timeout)*time.Millisecond)
				port.Service = fp.Name
				port.Product = fp.Product
				port.Version = fp.Version
				port.Banner = fp.Banner
				port.ExtraInfo = fp.ExtraInfo
				port.Confidence = fp.Confidence
			} else {
				port.Banner = r.Banner
				port.Service = r.Service
				if port.Service == "" {
					port.Service = getPortService(r.Target.Port)
				}
			}
		}

		host.Ports = append(host.Ports, port)
	}

	if config.DetectOS && len(openPorts) > 0 {
		osInfo := detectOS(ip, openPorts)
		host.OS = OSResult{
			Family:     osInfo.Family,
			TTL:        osInfo.TTL,
			Confidence: osInfo.Confidence,
			Method:     osInfo.Method,
		}
	}

	return host
}

// printDetailedResults exibe resultados detalhados
func printDetailedResults(hosts []HostResult, showClosed bool) {
	fmt.Println()

	for _, host := range hosts {
		hasOpenPorts := false
		for _, p := range host.Ports {
			if p.State == "open" {
				hasOpenPorts = true
				break
			}
		}

		if !hasOpenPorts && !showClosed {
			continue
		}

		fmt.Printf("\n%s═══════════════════════════════════════════════════════════%s\n",
			colorCyan, colorReset)
		fmt.Printf("  🖥️  Host: %s", host.IP)
		if host.Hostname != "" {
			fmt.Printf(" (%s)", host.Hostname)
		}
		fmt.Println()

		if host.OS.Family != "" {
			emoji := getOSEmoji(host.OS.Family)
			fmt.Printf("  %s OS: %s (%.0f%% confidence)\n",
				emoji, host.OS.Family, host.OS.Confidence*100)
		}
		fmt.Printf("%s═══════════════════════════════════════════════════════════%s\n",
			colorCyan, colorReset)

		sort.Slice(host.Ports, func(i, j int) bool {
			return host.Ports[i].Port < host.Ports[j].Port
		})

		for _, p := range host.Ports {
			if p.State == "open" {
				fmt.Printf("  %s[OPEN]%s  Port %-5d  %-12s", colorGreen, colorReset, p.Port, p.Service)

				if p.Product != "" {
					fmt.Printf("  %s", p.Product)
					if p.Version != "" {
						fmt.Printf(" v%s", p.Version)
					}
				}

				fmt.Printf("  Latency: %s\n", p.Latency)

				if p.Banner != "" {
					banner := strings.TrimSpace(p.Banner)
					banner = strings.ReplaceAll(banner, "\n", " ")
					if len(banner) > 60 {
						banner = banner[:60] + "..."
					}
					fmt.Printf("          Banner: %s\n", banner)
				}

				for k, v := range p.ExtraInfo {
					if k != "server" && k != "status" {
						fmt.Printf("          %s: %s\n", k, v)
					}
				}
			} else if showClosed {
				fmt.Printf("  %s[CLOSED]%s Port %-5d  %s\n", colorRed, colorReset, p.Port, p.Service)
			}
		}
	}
}

// printSummary exibe resumo do scan
func printSummary(results []Result, duration time.Duration, totalHosts int) {
	openCount := 0
	for _, r := range results {
		if r.Open {
			openCount++
		}
	}

	fmt.Println()
	fmt.Printf("%s═══════════════════════════════════════════════════════════%s\n",
		colorCyan, colorReset)
	fmt.Printf("%s  📊 SUMMARY%s\n", colorCyan, colorReset)
	fmt.Printf("%s═══════════════════════════════════════════════════════════%s\n",
		colorCyan, colorReset)
	fmt.Println()
	fmt.Printf("  Hosts scanned:              %s%d%s\n", colorBlue, totalHosts, colorReset)
	fmt.Printf("  Total ports scanned:        %s%d%s\n", colorBlue, len(results), colorReset)
	fmt.Printf("  Open ports:                 %s%d%s\n", colorGreen, openCount, colorReset)
	fmt.Printf("  Closed ports:               %s%d%s\n", colorRed, len(results)-openCount, colorReset)
	fmt.Printf("  Total time:                 %s%v%s\n", colorYellow, duration.Round(time.Millisecond), colorReset)
	fmt.Printf("  Rate:                       %s%.2f ports/sec%s\n",
		colorYellow, float64(len(results))/duration.Seconds(), colorReset)
	fmt.Println()
}

// buildScanResult constrói resultado para output
func buildScanResult(hosts []HostResult, target string, duration time.Duration) ScanResult {
	result := ScanResult{
		Timestamp:   time.Now(),
		Duration:    duration.String(),
		TargetRange: target,
		TotalHosts:  len(hosts),
		Hosts:       hosts,
	}

	for _, h := range hosts {
		if h.Status == "up" {
			result.AliveHosts++
		}
		for _, p := range h.Ports {
			result.TotalPorts++
			if p.State == "open" {
				result.OpenPorts++
			}
		}
	}

	return result
}

// ============================================================================
// CLI PARSING
// ============================================================================

func parseFlags() Config {
	config := Config{}

	flag.StringVar(&config.Target, "target", "", "IP, range or CIDR (e.g., 192.168.1.1, 192.168.1.1-254, 10.0.0.0/24)")
	flag.StringVar(&config.Target, "t", "", "Target IP (short form)")

	flag.StringVar(&config.Ports, "ports", "common", "Ports: 'common', 'top100', 'full', '1-1000', '22,80,443'")
	flag.StringVar(&config.Ports, "p", "common", "Ports (short form)")

	flag.IntVar(&config.Timeout, "timeout", 2000, "Timeout in milliseconds")
	flag.IntVar(&config.Workers, "workers", 100, "Number of concurrent workers")
	flag.IntVar(&config.RateLimit, "rate", 0, "Rate limit (packets/sec, 0=unlimited)")

	flag.BoolVar(&config.ShowClosed, "closed", false, "Show closed ports")
	flag.BoolVar(&config.NoColor, "no-color", false, "Disable colors")
	flag.BoolVar(&config.Fingerprint, "fingerprint", false, "Enable service fingerprinting")
	flag.BoolVar(&config.Fingerprint, "sV", false, "Fingerprinting (nmap style)")
	flag.BoolVar(&config.DetectOS, "os", false, "Detect operating system")
	flag.BoolVar(&config.DetectOS, "O", false, "Detect OS (nmap style)")
	flag.BoolVar(&config.Verbose, "verbose", false, "Verbose output")
	flag.BoolVar(&config.Verbose, "v", false, "Verbose (short form)")

	flag.StringVar(&config.OutputJSON, "oJ", "", "Save result to JSON")
	flag.StringVar(&config.OutputHTML, "oH", "", "Save result to HTML")
	flag.StringVar(&config.OutputCSV, "oC", "", "Save result to CSV")

	flag.BoolVar(&config.Help, "help", false, "Show help")
	flag.BoolVar(&config.Help, "h", false, "Show help (short form)")

	flag.Parse()

	if config.Target == "" && flag.NArg() > 0 {
		config.Target = flag.Arg(0)
	}

	return config
}

func parsePorts(portStr string) []int {
	switch portStr {
	case "common":
		return commonPorts()
	case "top100":
		return top100Ports()
	case "full":
		ports := make([]int, 1000)
		for i := 0; i < 1000; i++ {
			ports[i] = i + 1
		}
		return ports
	case "all":
		ports := make([]int, 65535)
		for i := 0; i < 65535; i++ {
			ports[i] = i + 1
		}
		return ports
	}

	var ports []int

	if strings.Contains(portStr, "-") && !strings.Contains(portStr, ",") {
		parts := strings.Split(portStr, "-")
		if len(parts) == 2 {
			start, _ := strconv.Atoi(parts[0])
			end, _ := strconv.Atoi(parts[1])
			for p := start; p <= end; p++ {
				ports = append(ports, p)
			}
			return ports
		}
	}

	if strings.Contains(portStr, ",") {
		parts := strings.Split(portStr, ",")
		for _, p := range parts {
			port, err := strconv.Atoi(strings.TrimSpace(p))
			if err == nil {
				ports = append(ports, port)
			}
		}
		return ports
	}

	port, err := strconv.Atoi(portStr)
	if err == nil {
		return []int{port}
	}

	return commonPorts()
}

func printHelp() {
	printBanner()

	fmt.Printf("\n  Version: %s\n", Version)
	fmt.Println(`
USAGE:
    ./scanner -target <IP/RANGE/CIDR> [options]
    ./scanner <IP> [options]

TARGETS:
    Single IP:      192.168.1.1
    Range:          192.168.1.1-254
    CIDR:           10.0.0.0/24
    List:           192.168.1.1,192.168.1.2

BASIC OPTIONS:
    -target, -t    Target(s) to scan (required)
    -ports, -p     Ports: 'common', 'top100', 'full', '1-1000', '22,80,443'
    -timeout       Timeout in ms (default: 2000)
    -workers       Concurrent workers (default: 100)
    -rate          Rate limit in packets/sec (0 = unlimited)
    -closed        Show closed ports
    -no-color      Disable colors
    -help, -h      Show this help

DETECTION:
    -fingerprint   Service fingerprinting (identify versions)
    -sV            Alias for -fingerprint (nmap style)
    -os, -O        Detect operating system

OUTPUT:
    -oJ <file>     Save to JSON
    -oH <file>     Save to HTML (visual report)
    -oC <file>     Save to CSV

EXAMPLES:
    # Basic scan
    ./scanner -t 127.0.0.1

    # Range scan with fingerprinting
    ./scanner -t 192.168.1.1-254 -sV -O

    # Full scan with HTML report
    ./scanner -t 10.0.0.0/24 -p 1-1000 -sV -oH report.html

    # Fast scan
    ./scanner -t 192.168.1.1 -timeout 500 -workers 200

    # Rate limited scan (avoid detection)
    ./scanner -t 192.168.1.1 -rate 100

DEMONSTRATED CONCEPTS:
    ┌─────────────────────────────────────────────────────────┐
    │ 🔄 Goroutines & Channels (worker pool pattern)         │
    │ 🔒 sync.WaitGroup & Mutex for synchronization          │
    │ 🌐 net.DialTimeout for TCP connections                 │
    │ 📊 HTML Templates for reports                          │
    │ 🔍 Service fingerprinting                              │
    │ 🖥️  OS detection via TTL & port analysis               │
    └─────────────────────────────────────────────────────────┘
`)
}
