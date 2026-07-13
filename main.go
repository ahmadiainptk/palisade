// Intra-linux: DNS-over-HTTPS tunnel for Linux
// Adapted from Jigsaw-Code/Intra (Apache 2.0)
//
// Transparent DNS interception via nftables — no system DNS changes needed.
// All port 53 traffic is silently redirected through the DoH tunnel.
package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"palisade/internal/doh"
	"palisade/internal/intra"
	"palisade/internal/intra/protect"
	"palisade/internal/logging"
	"palisade/internal/tuntap"

	"golang.org/x/net/dns/dnsmessage"
)

//go:embed webui/*
var webUI embed.FS

const (
	vpnGateway = "10.111.222.1"
	vpnDNS     = "10.111.222.3"
	vpnPrefix  = 24
	tunMTU     = 1500
	dnsPort    = 53
	maxLog     = 100
)

var (
	port   = flag.Int("port", 8453, "Web UI port")
	listen = flag.String("listen", "127.0.0.1", "Listen address")
	noWeb  = flag.Bool("no-web", false, "Run without web UI (daemon mode)")
	dohURL = flag.String("url", "https://cloudflare-dns.com/dns-query", "DoH server URL")
)

var knownServers = []struct{ Name, URL string }{
	{"Cloudflare", "https://cloudflare-dns.com/dns-query"},
	{"Google", "https://dns.google/dns-query"},
	{"Quad9", "https://dns.quad9.net/dns-query"},
	{"OpenDNS", "https://doh.opendns.com/dns-query"},
	{"Mullvad", "https://doh.mullvad.net/dns-query"},
	{"NextDNS", "https://dns.nextdns.io"},
}

// ─── Query Log ────────────────────────────────────────────────────

type QueryEntry struct {
	Time      time.Time `json:"time"`
	Domain    string    `json:"domain"`
	Server    string    `json:"server"`
	LatencyMs float64   `json:"latency_ms"`
	Success   bool      `json:"success"`
	Status    string    `json:"status"`
}

// ─── Tunnel Manager ───────────────────────────────────────────────

type TunnelManager struct {
	mu            sync.Mutex
	running       bool
	startTime     time.Time
	lastError     string
	currentURL    string
	tunActualName string
	tunFile       *os.File
	tunnel        *intra.Tunnel
	cancel        context.CancelFunc

	queryCount   atomic.Int64
	successCount atomic.Int64
	failCount    atomic.Int64
	totalLatency atomic.Int64

	logMu     sync.Mutex
	queryLog  []QueryEntry
	logCursor int
}

func NewTunnelManager() *TunnelManager {
	return &TunnelManager{
		currentURL: *dohURL,
		queryLog:   make([]QueryEntry, maxLog),
	}
}

func (tm *TunnelManager) Status() map[string]interface{} {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	s := map[string]interface{}{
		"running":       tm.running,
		"doh_url":       tm.currentURL,
		"tun":           tm.tunActualName,
		"query_count":   tm.queryCount.Load(),
		"success_count": tm.successCount.Load(),
		"fail_count":    tm.failCount.Load(),
	}
	if tm.running {
		s["uptime"] = time.Since(tm.startTime).Round(time.Second).String()
		total := tm.successCount.Load() + tm.failCount.Load()
		if total > 0 {
			s["avg_latency_ms"] = float64(tm.totalLatency.Load()/total) / 1e6
		}
	} else if tm.lastError != "" {
		s["error"] = tm.lastError
	}
	return s
}

func (tm *TunnelManager) QueryLog() []QueryEntry {
	tm.logMu.Lock()
	defer tm.logMu.Unlock()
	var entries []QueryEntry
	for i := 0; i < maxLog; i++ {
		idx := (tm.logCursor + i) % maxLog
		if !tm.queryLog[idx].Time.IsZero() {
			entries = append(entries, tm.queryLog[idx])
		}
	}
	return entries
}

func (tm *TunnelManager) addLog(domain, server string, latencyMs float64, success bool, status string) {
	tm.logMu.Lock()
	defer tm.logMu.Unlock()
	tm.queryLog[tm.logCursor] = QueryEntry{
		Time: time.Now(), Domain: domain, Server: server,
		LatencyMs: latencyMs, Success: success, Status: status,
	}
	tm.logCursor = (tm.logCursor + 1) % maxLog
}

// doh.Listener
func (tm *TunnelManager) OnQuery(url string) doh.Token  { return time.Now() }
func (tm *TunnelManager) OnResponse(token doh.Token, s *doh.Summary) {
	tm.queryCount.Add(1)
	domain := parseQueryDomain(s.Query)
	latencyMs := s.Latency * 1000
	tm.totalLatency.Add(int64(s.Latency * 1e9))
	success := s.Status == doh.Complete
	if success {
		tm.successCount.Add(1)
	} else {
		tm.failCount.Add(1)
	}
	statusStr := "OK"
	switch s.Status {
	case doh.SendFailed:
		statusStr = "SendFailed"
	case doh.HTTPError:
		statusStr = fmt.Sprintf("HTTP %d", s.HTTPStatus)
	case doh.BadQuery:
		statusStr = "BadQuery"
	case doh.BadResponse:
		statusStr = "BadResponse"
	case doh.InternalError:
		statusStr = "Error"
	}
	tm.addLog(domain, s.Server, latencyMs, success, statusStr)
}

func parseQueryDomain(q []byte) string {
	if len(q) < 12 {
		return "?"
	}
	var msg dnsmessage.Message
	if err := msg.Unpack(q); err != nil {
		return "?"
	}
	if len(msg.Questions) == 0 {
		return "?"
	}
	return strings.TrimSuffix(msg.Questions[0].Name.String(), ".")
}

func (tm *TunnelManager) OnTCPSocketClosed(*intra.TCPSocketSummary) {}
func (tm *TunnelManager) OnUDPSocketClosed(*intra.UDPSocketSummary) {}

// ─── Tunnel Lifecycle ─────────────────────────────────────────────

func (tm *TunnelManager) Start() error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if tm.running {
		return fmt.Errorf("tunnel already running")
	}

	tm.lastError = ""
	tm.successCount.Store(0)
	tm.failCount.Store(0)
	tm.totalLatency.Store(0)

	tunFile, actualName, err := tuntap.CreateTUN("intra0")
	if err != nil {
		tm.lastError = fmt.Sprintf("TUN: %v", err)
		return fmt.Errorf("TUN: %w", err)
	}

	if err := setupTUN(actualName); err != nil {
		tunFile.Close()
		teardownTUN(actualName)
		tm.lastError = fmt.Sprintf("TUN config: %v", err)
		return fmt.Errorf("TUN config: %w", err)
	}

	resolver, err := createResolver(tm.currentURL, tm)
	if err != nil {
		tunFile.Close()
		teardownTUN(actualName)
		tm.lastError = fmt.Sprintf("DoH resolver: %v", err)
		return fmt.Errorf("DoH resolver: %w", err)
	}

	fakeDNS := fmt.Sprintf("%s:%d", vpnDNS, dnsPort)
	tunnel, err := intra.NewTunnel(fakeDNS, resolver, tunFile, &protect.LinuxProtector{}, tm)
	if err != nil {
		tunFile.Close()
		teardownTUN(actualName)
		tm.lastError = fmt.Sprintf("Tunnel create: %v", err)
		return fmt.Errorf("Tunnel create: %w", err)
	}

	// Enable nftables redirect
	if err := setupNftables(); err != nil {
		tunnel.Disconnect()
		tunFile.Close()
		teardownTUN(actualName)
		tm.lastError = fmt.Sprintf("nftables: %v", err)
		return fmt.Errorf("nftables: %w", err)
	}

	// Set local DNS resolver to TUN IP
	if err := setLocalDNS(); err != nil {
		log.Printf("WARNING: /etc/resolv.conf update failed: %v", err)
	}

	_, cancel := context.WithCancel(context.Background())
	go copyUntilEOF(tunnel, tunFile)
	go copyUntilEOF(tunFile, tunnel)

	tm.tunnel = tunnel
	tm.tunFile = tunFile
	tm.tunActualName = actualName
	tm.cancel = cancel
	tm.running = true
	tm.startTime = time.Now()

	log.Printf("Tunnel started — all DNS → DoH via %s", tm.currentURL)
	return nil
}

func (tm *TunnelManager) Stop() {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if !tm.running {
		return
	}

	tm.cancel()
	teardownNftables()
	restoreLocalDNS()
	if tm.tunnel != nil {
		tm.tunnel.Disconnect()
	}
	if tm.tunFile != nil {
		tm.tunFile.Close()
	}
	teardownTUN(tm.tunActualName)

	tm.tunnel = nil
	tm.tunFile = nil
	tm.tunActualName = ""
	tm.running = false
	log.Printf("Tunnel stopped")
}

func (tm *TunnelManager) SetDoHURL(url string) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	tm.currentURL = url
	if tm.running {
		resolver, err := createResolver(url, tm)
		if err != nil {
			return err
		}
		tm.tunnel.SetDNS(resolver)
	}
	return nil
}

// ─── nftables Redirect ─────────────────────────────────────────────

var savedResolvConf []byte

func setLocalDNS() error {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return err
	}
	savedResolvConf = data
	content := fmt.Sprintf("# Managed by intra-linux\nnameserver %s\n", vpnDNS)
	return os.WriteFile("/etc/resolv.conf", []byte(content), 0644)
}

func restoreLocalDNS() {
	if len(savedResolvConf) > 0 {
		os.WriteFile("/etc/resolv.conf", savedResolvConf, 0644)
		savedResolvConf = nil
	}
}

func setupNftables() error {
	rules := []string{
		"add table inet intra-dns",
		// PREROUTING: catch DNS from forwarded traffic
		"add chain inet intra-dns prerouting { type nat hook prerouting priority dstnat; policy accept; }",
		fmt.Sprintf("add rule inet intra-dns prerouting ip daddr != %s udp dport 53 dnat to %s:%d", vpnDNS, vpnDNS, dnsPort),
		fmt.Sprintf("add rule inet intra-dns prerouting ip daddr != %s tcp dport 53 dnat to %s:%d", vpnDNS, vpnDNS, dnsPort),
	}
	for _, rule := range rules {
		cmd := exec.Command("nft", strings.Fields(rule)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			// "File exists" means table/chain already exists — that's OK
			if !strings.Contains(string(out), "exists") {
				return fmt.Errorf("nft %s: %w\n%s", rule, err, out)
			}
		}
	}
	log.Printf("nftables: all port 53 traffic redirected to %s", vpnDNS)
	return nil
}

func teardownNftables() {
	cmd := exec.Command("nft", "delete", "table", "inet", "intra-dns")
	if out, err := cmd.CombinedOutput(); err != nil {
		// Table doesn't exist → fine
		if !strings.Contains(string(out), "No such file") {
			log.Printf("nftables cleanup: %v", err)
		}
	}
}

// ─── Server Probing ────────────────────────────────────────────────

type ProbeResult struct {
	Name      string  `json:"name"`
	URL       string  `json:"url"`
	LatencyMs float64 `json:"latency_ms"`
	Error     string  `json:"error,omitempty"`
	OK        bool    `json:"ok"`
}

func probeServers() []ProbeResult {
	dialer := net.Dialer{Timeout: 3 * time.Second}
	var results []ProbeResult
	for _, s := range knownServers {
		r := ProbeResult{Name: s.Name, URL: s.URL}
		resolver, err := doh.NewResolver(s.URL, nil, &dialer, nil, nil)
		if err != nil {
			r.Error = err.Error()
			results = append(results, r)
			continue
		}
		q := []byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'y', 'o', 'u', 't', 'u', 'b', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1}
		start := time.Now()
		_, err = resolver.Query(context.Background(), q)
		elapsed := time.Since(start)
		if err != nil {
			r.Error = err.Error()
		} else {
			r.OK = true
			r.LatencyMs = float64(elapsed.Microseconds()) / 1000
		}
		results = append(results, r)
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].OK != results[j].OK {
			return results[i].OK
		}
		return results[i].LatencyMs < results[j].LatencyMs
	})
	return results
}

// ─── Web Server ───────────────────────────────────────────────────

func startWebServer(tm *TunnelManager) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, tm.Status())
	})
	mux.HandleFunc("/api/log", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, tm.QueryLog())
	})
	mux.HandleFunc("/api/probe", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, probeServers())
	})
	mux.HandleFunc("/api/start", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", 405)
			return
		}
		if err := tm.Start(); err != nil {
			writeJSON(w, map[string]interface{}{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, map[string]interface{}{"ok": true})
	})
	mux.HandleFunc("/api/stop", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", 405)
			return
		}
		tm.Stop()
		writeJSON(w, map[string]interface{}{"ok": true})
	})
	mux.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", 405)
			return
		}
		var cfg struct{ DoHURL string `json:"doh_url"` }
		json.NewDecoder(r.Body).Decode(&cfg)
		if cfg.DoHURL != "" {
			if err := tm.SetDoHURL(cfg.DoHURL); err != nil {
				writeJSON(w, map[string]interface{}{"ok": false, "error": err.Error()})
				return
			}
		}
		writeJSON(w, map[string]interface{}{"ok": true})
	})

	webFS, _ := fs.Sub(webUI, "webui")
	mux.Handle("/", http.FileServer(http.FS(webFS)))

	addr := fmt.Sprintf("%s:%d", *listen, *port)
	log.Printf("Web UI: http://%s", addr)
	go http.ListenAndServe(addr, mux)
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// ─── TUN Setup ────────────────────────────────────────────────────

func setupTUN(name string) error {
	for _, cmd := range [][]string{
		{"ip", "addr", "add", fmt.Sprintf("%s/%d", vpnGateway, vpnPrefix), "dev", name},
		{"ip", "link", "set", name, "up"},
		{"ip", "link", "set", name, "mtu", fmt.Sprintf("%d", tunMTU)},
	} {
		c := exec.Command(cmd[0], cmd[1:]...)
		if out, err := c.CombinedOutput(); err != nil {
			return fmt.Errorf("%s: %w\n%s", strings.Join(cmd, " "), err, out)
		}
	}
	return nil
}

func teardownTUN(name string) {
	if name == "" {
		return
	}
	for _, cmd := range [][]string{
		{"ip", "link", "set", name, "down"},
		{"ip", "link", "del", name},
	} {
		exec.Command(cmd[0], cmd[1:]...).Run()
	}
}

// ─── Resolver ─────────────────────────────────────────────────────

func createResolver(rawURL string, listener doh.Listener) (doh.Resolver, error) {
	return doh.NewResolver(rawURL, nil, protect.MakeLinuxDialer(), nil, listener)
}

// ─── I/O Relay ────────────────────────────────────────────────────

func copyUntilEOF(dst, src io.ReadWriteCloser) {
	buf := make([]byte, tunMTU)
	for {
		_, err := io.CopyBuffer(dst, src, buf)
		if err == nil || errors.Is(err, os.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
			return
		}
	}
}

// ─── Main ─────────────────────────────────────────────────────────

func main() {
	flag.Parse()

	if *noWeb {
		tm := NewTunnelManager()
		if err := tm.Start(); err != nil {
			log.Fatalf("Failed: %v", err)
		}
		log.Printf("Intra-linux running. Ctrl+C to stop.")
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		tm.Stop()
		return
	}

	logging.SetLevel(logging.LevelInfo)
	tm := NewTunnelManager()
	startWebServer(tm)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	log.Printf("Intra-linux ready — open http://%s:%d", *listen, *port)
	<-sigCh
	log.Printf("Shutting down...")
	tm.Stop()
}
