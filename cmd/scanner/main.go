// Network Scanner Educacional v2.0
// Demonstra conceitos de: networking, concorrência, CLI em Go
//
// APENAS PARA FINS EDUCACIONAIS
// Use somente em redes que você tem permissão para escanear
package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"network-scanner-edu/pkg/fingerprint"
	"network-scanner-edu/pkg/iprange"
	"network-scanner-edu/pkg/osdetect"
	"network-scanner-edu/pkg/output"
	"network-scanner-edu/pkg/reporter"
	"network-scanner-edu/pkg/scanner"
)

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

// Version do scanner
const Version = "2.0.0"

func main() {
	config := parseFlags()

	if config.Help {
		printHelp()
		return
	}

	// Exibe banner e aviso
	reporter.PrintBanner()
	reporter.PrintUsageWarning()

	// Valida entrada
	if config.Target == "" {
		fmt.Println("❌ Erro: especifique um alvo com -target")
		fmt.Println("Exemplo: ./scanner -target 127.0.0.1")
		fmt.Println("         ./scanner -target 192.168.1.1-254")
		fmt.Println("         ./scanner -target 10.0.0.0/24")
		os.Exit(1)
	}

	// Parse do range de IPs
	ips, err := iprange.ParseRange(config.Target)
	if err != nil {
		fmt.Printf("❌ Erro ao parsear range de IPs: %v\n", err)
		os.Exit(1)
	}

	// Configura scanner
	s := scanner.NewScanner()
	s.Timeout = time.Duration(config.Timeout) * time.Millisecond
	s.Workers = config.Workers
	s.Fingerprint = config.Fingerprint
	s.DetectOS = config.DetectOS
	s.RateLimit = config.RateLimit
	s.Verbose = config.Verbose

	// Configura reporter
	rep := reporter.NewReporter()
	rep.ShowClosed = config.ShowClosed
	rep.Colorize = !config.NoColor

	// Parse das portas
	ports := parsePorts(config.Ports)

	// Informações do scan
	fmt.Println()
	fmt.Printf("🎯 Alvo: %s\n", iprange.Summary(ips))
	fmt.Printf("📊 Portas: %d\n", len(ports))
	fmt.Printf("🖥️  Hosts: %d\n", len(ips))
	fmt.Printf("⚡ Workers: %d\n", config.Workers)
	fmt.Printf("⏱️  Timeout: %dms\n", config.Timeout)
	
	if config.Fingerprint {
		fmt.Println("🔬 Fingerprinting: Habilitado")
	}
	if config.DetectOS {
		fmt.Println("🖥️  Detecção de SO: Habilitado")
	}
	if config.RateLimit > 0 {
		fmt.Printf("🚦 Rate Limit: %d/seg\n", config.RateLimit)
	}

	fmt.Println()
	fmt.Println("🔍 Iniciando escaneamento...")
	fmt.Println()

	// Executa escaneamento
	start := time.Now()
	var allResults []scanner.Result
	var hostResults []output.HostResult

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
		targets := scanner.GenerateTargets(ip, ports)
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
	printDetailedResults(hostResults, rep)

	// Exibe resumo
	printSummary(allResults, duration, len(ips))

	// Salva outputs se solicitado
	if config.OutputJSON != "" || config.OutputHTML != "" || config.OutputCSV != "" {
		scanResult := buildScanResult(hostResults, config.Target, duration)

		if config.OutputJSON != "" {
			if err := output.SaveJSON(scanResult, config.OutputJSON); err != nil {
				fmt.Printf("❌ Erro ao salvar JSON: %v\n", err)
			} else {
				fmt.Printf("💾 Salvo: %s\n", config.OutputJSON)
			}
		}

		if config.OutputHTML != "" {
			if err := output.SaveHTML(scanResult, config.OutputHTML); err != nil {
				fmt.Printf("❌ Erro ao salvar HTML: %v\n", err)
			} else {
				fmt.Printf("💾 Salvo: %s\n", config.OutputHTML)
			}
		}

		if config.OutputCSV != "" {
			if err := output.SaveCSV(scanResult, config.OutputCSV); err != nil {
				fmt.Printf("❌ Erro ao salvar CSV: %v\n", err)
			} else {
				fmt.Printf("💾 Salvo: %s\n", config.OutputCSV)
			}
		}
	}
}

func processHostResult(ip string, results []scanner.Result, config Config) output.HostResult {
	host := output.HostResult{
		IP:     ip,
		Status: "down",
		Ports:  make([]output.PortResult, 0),
	}

	// Coleta portas abertas
	var openPorts []int
	for _, r := range results {
		port := output.PortResult{
			Port:       r.Target.Port,
			State:      "closed",
			Service:    scanner.PortService(r.Target.Port),
			Latency:    r.Latency.String(),
			ExtraInfo:  make(map[string]string),
		}

		if r.Open {
			port.State = "open"
			host.Status = "up"
			openPorts = append(openPorts, r.Target.Port)

			// Fingerprinting avançado
			if config.Fingerprint {
				fp := fingerprint.Fingerprint(ip, r.Target.Port, time.Duration(config.Timeout)*time.Millisecond)
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
					port.Service = scanner.PortService(r.Target.Port)
				}
			}
		}

		host.Ports = append(host.Ports, port)
	}

	// Detecção de SO
	if config.DetectOS && len(openPorts) > 0 {
		osInfo := osdetect.DetectOS(ip, openPorts)
		host.OS = output.OSResult{
			Family:     osInfo.Family,
			TTL:        osInfo.TTL,
			Confidence: osInfo.Confidence,
			Method:     osInfo.Method,
		}
	}

	return host
}

func printDetailedResults(hosts []output.HostResult, rep *reporter.Reporter) {
	fmt.Println()
	
	for _, host := range hosts {
		hasOpenPorts := false
		for _, p := range host.Ports {
			if p.State == "open" {
				hasOpenPorts = true
				break
			}
		}

		if !hasOpenPorts && !rep.ShowClosed {
			continue
		}

		// Header do host
		fmt.Printf("\n%s═══════════════════════════════════════════════════════════%s\n", 
			"\033[36m", "\033[0m")
		fmt.Printf("  🖥️  Host: %s", host.IP)
		if host.Hostname != "" {
			fmt.Printf(" (%s)", host.Hostname)
		}
		fmt.Println()
		
		if host.OS.Family != "" {
			emoji := osdetect.GetOSEmoji(host.OS.Family)
			fmt.Printf("  %s SO: %s (%.0f%% confiança)\n", 
				emoji, host.OS.Family, host.OS.Confidence*100)
		}
		fmt.Printf("%s═══════════════════════════════════════════════════════════%s\n", 
			"\033[36m", "\033[0m")

		// Ordena portas
		sort.Slice(host.Ports, func(i, j int) bool {
			return host.Ports[i].Port < host.Ports[j].Port
		})

		// Exibe portas
		for _, p := range host.Ports {
			if p.State == "open" {
				fmt.Printf("  \033[32m[OPEN]\033[0m  Port %-5d  %-12s", p.Port, p.Service)
				
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
				
				// Extra info
				for k, v := range p.ExtraInfo {
					if k != "server" && k != "status" {
						fmt.Printf("          %s: %s\n", k, v)
					}
				}
			} else if rep.ShowClosed {
				fmt.Printf("  \033[31m[CLOSED]\033[0m Port %-5d  %s\n", p.Port, p.Service)
			}
		}
	}
}

func printSummary(results []scanner.Result, duration time.Duration, totalHosts int) {
	openCount := 0
	for _, r := range results {
		if r.Open {
			openCount++
		}
	}

	fmt.Println()
	fmt.Printf("%s═══════════════════════════════════════════════════════════%s\n", 
		"\033[36m", "\033[0m")
	fmt.Printf("\033[36m  📊 RESUMO\033[0m\n")
	fmt.Printf("%s═══════════════════════════════════════════════════════════%s\n", 
		"\033[36m", "\033[0m")
	fmt.Println()
	fmt.Printf("  Hosts escaneados:           \033[34m%d\033[0m\n", totalHosts)
	fmt.Printf("  Total de portas escaneadas: \033[34m%d\033[0m\n", len(results))
	fmt.Printf("  Portas abertas:             \033[32m%d\033[0m\n", openCount)
	fmt.Printf("  Portas fechadas:            \033[31m%d\033[0m\n", len(results)-openCount)
	fmt.Printf("  Tempo total:                \033[33m%v\033[0m\n", duration.Round(time.Millisecond))
	fmt.Printf("  Taxa:                       \033[33m%.2f portas/seg\033[0m\n", 
		float64(len(results))/duration.Seconds())
	fmt.Println()
}

func buildScanResult(hosts []output.HostResult, target string, duration time.Duration) output.ScanResult {
	result := output.ScanResult{
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

func parseFlags() Config {
	config := Config{}

	flag.StringVar(&config.Target, "target", "", "IP, range ou CIDR (ex: 192.168.1.1, 192.168.1.1-254, 10.0.0.0/24)")
	flag.StringVar(&config.Target, "t", "", "IP ou hostname alvo (forma curta)")

	flag.StringVar(&config.Ports, "ports", "common", "Portas: 'common', 'top100', 'full', '1-1000', '22,80,443'")
	flag.StringVar(&config.Ports, "p", "common", "Portas (forma curta)")

	flag.IntVar(&config.Timeout, "timeout", 2000, "Timeout em millisegundos")
	flag.IntVar(&config.Workers, "workers", 100, "Número de workers concorrentes")
	flag.IntVar(&config.RateLimit, "rate", 0, "Rate limit (pacotes/seg, 0=ilimitado)")

	flag.BoolVar(&config.ShowClosed, "closed", false, "Mostrar portas fechadas")
	flag.BoolVar(&config.NoColor, "no-color", false, "Desabilitar cores")
	flag.BoolVar(&config.Fingerprint, "fingerprint", false, "Habilitar fingerprinting de serviços")
	flag.BoolVar(&config.Fingerprint, "sV", false, "Fingerprinting (estilo nmap)")
	flag.BoolVar(&config.DetectOS, "os", false, "Detectar sistema operacional")
	flag.BoolVar(&config.DetectOS, "O", false, "Detectar SO (estilo nmap)")
	flag.BoolVar(&config.Verbose, "verbose", false, "Output detalhado")
	flag.BoolVar(&config.Verbose, "v", false, "Verbose (forma curta)")

	flag.StringVar(&config.OutputJSON, "oJ", "", "Salvar resultado em JSON")
	flag.StringVar(&config.OutputHTML, "oH", "", "Salvar resultado em HTML")
	flag.StringVar(&config.OutputCSV, "oC", "", "Salvar resultado em CSV")

	flag.BoolVar(&config.Help, "help", false, "Mostrar ajuda")
	flag.BoolVar(&config.Help, "h", false, "Mostrar ajuda (forma curta)")

	flag.Parse()

	// Target pode vir como argumento posicional
	if config.Target == "" && flag.NArg() > 0 {
		config.Target = flag.Arg(0)
	}

	return config
}

func parsePorts(portStr string) []int {
	switch portStr {
	case "common":
		return scanner.CommonPorts()
	case "top100":
		return scanner.Top100Ports()
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

	// Range: 1-100
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

	// Lista: 22,80,443
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

	// Porta única
	port, err := strconv.Atoi(portStr)
	if err == nil {
		return []int{port}
	}

	return scanner.CommonPorts()
}

func printHelp() {
	reporter.PrintBanner()

	fmt.Printf("\n  Version: %s\n", Version)
	fmt.Println(`
USO:
    ./scanner -target <IP/RANGE/CIDR> [opções]
    ./scanner <IP> [opções]

ALVOS:
    IP único:       192.168.1.1
    Range:          192.168.1.1-254
    CIDR:           10.0.0.0/24
    Lista:          192.168.1.1,192.168.1.2

OPÇÕES BÁSICAS:
    -target, -t    Alvo(s) para escanear (obrigatório)
    -ports, -p     Portas: 'common', 'top100', 'full', '1-1000', '22,80,443'
    -timeout       Timeout em ms (padrão: 2000)
    -workers       Workers concorrentes (padrão: 100)
    -rate          Rate limit em pacotes/seg (0 = sem limite)
    -closed        Mostrar portas fechadas
    -no-color      Desabilitar cores
    -help, -h      Mostrar esta ajuda

DETECÇÃO:
    -fingerprint   Fingerprinting de serviços (identifica versões)
    -sV            Alias para -fingerprint (estilo nmap)
    -os, -O        Detectar sistema operacional

OUTPUT:
    -oJ <file>     Salvar em JSON
    -oH <file>     Salvar em HTML (relatório visual)
    -oC <file>     Salvar em CSV

EXEMPLOS:
    # Scan básico
    ./scanner -t 127.0.0.1

    # Scan de range com fingerprinting
    ./scanner -t 192.168.1.1-254 -sV -O

    # Scan completo com relatório HTML
    ./scanner -t 10.0.0.0/24 -p 1-1000 -sV -oH report.html

    # Scan rápido
    ./scanner -t 192.168.1.1 -timeout 500 -workers 200

    # Scan com rate limiting (evita detecção)
    ./scanner -t 192.168.1.1 -rate 100

CONCEITOS DEMONSTRADOS:
    ┌─────────────────────────────────────────────────────────┐
    │ 🔄 Goroutines e Channels (worker pool pattern)         │
    │ 🔒 sync.WaitGroup e Mutex para sincronização           │
    │ 🌐 net.DialTimeout para conexões TCP                   │
    │ 📊 Templates HTML para relatórios                      │
    │ 📦 Organização em múltiplos packages                   │
    │ 🔍 Fingerprinting de serviços de rede                  │
    │ 🖥️  Detecção de SO via TTL e análise de portas         │
    └─────────────────────────────────────────────────────────┘
`)
}
