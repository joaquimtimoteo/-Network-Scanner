# 🔍 Network Scanner Educacional

> **⚠️ AVISO**: Esta ferramenta é **APENAS para fins educacionais**. Use somente em redes que você tem permissão explícita para testar.

Um scanner de portas simples em Go, desenvolvido para demonstrar conceitos fundamentais de programação concorrente e networking.

---

## 📚 Conceitos Demonstrados

### 1. **Concorrência em Go**
- **Goroutines**: Funções executadas concorrentemente
- **Channels**: Comunicação entre goroutines
- **Worker Pool Pattern**: Limitar goroutines ativas
- **sync.WaitGroup**: Sincronização de goroutines
- **sync.Mutex**: Proteção de dados compartilhados

### 2. **Networking**
- Conexões TCP com `net.Dial`
- Timeouts com `net.DialTimeout`
- Banner grabbing (identificação de serviços)

### 3. **Organização de Código**
- Estrutura de projeto Go
- Separação em packages
- CLI com `flag` package

---

## 🏗️ Arquitetura do Projeto

```
network-scanner-edu/
├── go.mod                    # Definição do módulo Go
├── README.md                 # Esta documentação
├── cmd/
│   └── scanner/
│       └── main.go           # Ponto de entrada, CLI
└── pkg/
    ├── scanner/
    │   └── scanner.go        # Lógica de escaneamento
    └── reporter/
        └── reporter.go       # Formatação de resultados
```

---

## 🔧 Compilação e Execução

### Compilar
```bash
cd network-scanner-edu
go build -o scanner ./cmd/scanner
```

### Executar
```bash
# Escanear localhost
./scanner -t 127.0.0.1

# Portas específicas
./scanner -t 127.0.0.1 -p 22,80,443

# Range de portas
./scanner -t 127.0.0.1 -p 1-100

# Com mais workers (mais rápido)
./scanner -t 127.0.0.1 -workers 200 -timeout 500
```

---

## 🧠 Explicação dos Conceitos-Chave

### Worker Pool Pattern

```go
// Limita goroutines ativas para não sobrecarregar o sistema
for i := 0; i < s.Workers; i++ {
    wg.Add(1)
    go func(workerID int) {
        defer wg.Done()
        for target := range jobs {  // Recebe jobs do channel
            result := s.ScanPort(target)
            // ...
        }
    }(i)
}
```

**Por que usar?**
- Sem limite, 65535 goroutines simultâneas sobrecarregariam o SO
- Worker pool controla recursos de forma eficiente

### Channel como Job Queue

```go
jobs := make(chan Target, len(targets))

// Produtor: envia trabalho
for _, target := range targets {
    jobs <- target
}
close(jobs)  // Sinaliza fim

// Consumidores (workers): processam trabalho
for target := range jobs {
    // processar...
}
```

### Mutex para Thread Safety

```go
var mu sync.Mutex
var results []Result

// Em cada worker:
mu.Lock()
results = append(results, result)
mu.Unlock()
```

**Por que?** Múltiplas goroutines escrevendo no mesmo slice causaria race condition.

---

## 📊 Fluxo de Execução

```
┌─────────────┐
│   main()    │
└──────┬──────┘
       │
       ▼
┌─────────────────┐
│  Parse flags    │
│  Configuração   │
└────────┬────────┘
         │
         ▼
┌─────────────────────────┐
│   GenerateTargets()     │
│   Cria lista de alvos   │
└───────────┬─────────────┘
            │
            ▼
┌───────────────────────────────────┐
│         ScanRange()               │
│  ┌─────────────────────────────┐  │
│  │      Channel (jobs)         │  │
│  │  [target1, target2, ...]    │  │
│  └──────────┬──────────────────┘  │
│             │                     │
│    ┌────────┼────────┐            │
│    ▼        ▼        ▼            │
│ ┌──────┐ ┌──────┐ ┌──────┐       │
│ │Worker│ │Worker│ │Worker│  ...   │
│ │  1   │ │  2   │ │  3   │       │
│ └──┬───┘ └──┬───┘ └──┬───┘       │
│    │        │        │            │
│    └────────┴────────┘            │
│             │                     │
│             ▼                     │
│    ┌─────────────────┐            │
│    │ results []Result│            │
│    └─────────────────┘            │
└───────────────────────────────────┘
            │
            ▼
┌─────────────────────────┐
│    PrintResults()       │
│    Exibe formatado      │
└─────────────────────────┘
```

---

## 🔐 Como Funcionam Scanners Reais (Teoria)

### 1. Descoberta de Hosts (Host Discovery)
- **ICMP Echo**: Ping tradicional
- **TCP SYN**: Envia SYN, espera SYN-ACK
- **ARP**: Em redes locais

### 2. Escaneamento de Portas
| Técnica | Descrição |
|---------|-----------|
| TCP Connect | Conexão completa (3-way handshake) - **nosso método** |
| SYN Scan | Meio-aberto, mais furtivo |
| UDP Scan | Para serviços UDP |
| FIN/NULL/Xmas | Técnicas de evasão |

### 3. Identificação de Serviços
- **Banner Grabbing**: Ler resposta inicial
- **Probe Responses**: Enviar requests específicos
- **Fingerprinting**: Analisar comportamento

---

## 🛡️ Defesas (Para Administradores)

O documento do Reddit menciona várias defesas:

| Defesa | Descrição |
|--------|-----------|
| **Fail2ban** | Bloqueia IPs após tentativas falhas |
| **Port Knocking** | Sequência secreta para abrir porta |
| **Mudar porta SSH** | Reduz ruído (não é segurança real) |
| **Autenticação por chave** | Elimina ataques de senha |
| **Firewall restritivo** | Whitelist de IPs permitidos |
| **VPN** | SSH só acessível via VPN |

---

## 🎓 Exercícios Sugeridos

1. **Adicionar detecção de SO** baseada em TTL da resposta
2. **Implementar SYN scan** usando raw sockets (requer root)
3. **Adicionar output JSON** para integração com outras ferramentas
4. **Implementar rate limiting** configurável
5. **Adicionar scan de range de IPs** (ex: 192.168.1.1-254)

---

## 📖 Referências

- [zmap](https://github.com/zmap/zmap) - Scanner de alta performance
- [zgrab2](https://github.com/zmap/zgrab2) - Application layer scanner
- [nmap](https://nmap.org/) - O clássico scanner de rede
- [Go by Example: Goroutines](https://gobyexample.com/goroutines)
- [Go by Example: Channels](https://gobyexample.com/channels)

---

## ⚖️ Aspectos Legais

> **Escaneamento não autorizado de redes é ilegal em muitas jurisdições.**

✅ **Permitido:**
- Sua própria rede/equipamentos
- Ambientes de laboratório
- CTFs e plataformas de prática
- Com autorização por escrito

❌ **Proibido:**
- Redes de terceiros sem permissão
- Infraestrutura pública
- Sistemas de produção sem autorização

---

**Desenvolvido para fins educacionais** 📚
