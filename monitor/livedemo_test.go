// +build livedemo

package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestLiveDemo starts a real metrics server with sample data and opens your browser.
// Run with: go test -v -tags=livedemo -run TestLiveDemo ./monitor/
//
// The server will run until you press Ctrl+C.
// Browse to:
//   - http://localhost:9099/         - Dashboard with DoS detection views
//   - http://localhost:9099/metrics  - Prometheus metrics
//   - http://localhost:9099/metrics/json - JSON export
func TestLiveDemo(t *testing.T) {
	tracker := NewTracker()

	// Populate with sample data that demonstrates DoS scenarios
	populateDemoData(tracker)

	// Start metrics server
	addr := ":9099"
	mux := createMetricsMux(tracker)

	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// Start server in background
	go func() {
		log.Printf("Starting metrics server on http://localhost%s", addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Server error: %v", err)
		}
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Open browser
	url := fmt.Sprintf("http://localhost%s", addr)
	openBrowser(url)

	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("SSHadow Live Demo")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("\nServer running at: %s\n", url)
	fmt.Println("\nEndpoints:")
	fmt.Printf("  Dashboard:  %s/\n", url)
	fmt.Printf("  Prometheus: %s/metrics\n", url)
	fmt.Printf("  JSON:       %s/metrics/json\n", url)
	fmt.Println("\nSample data includes:")
	fmt.Println("  - Single IP with multiple connections (DoS scenario 1)")
	fmt.Println("  - Same key used from multiple IPs (DoS scenario 2)")
	fmt.Println("  - Mixed authentication types")
	fmt.Println("\nPress Ctrl+C to stop...")
	fmt.Println(strings.Repeat("=", 70))

	// Wait for Ctrl+C
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	fmt.Println("\nShutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server.Shutdown(ctx)
}

// TestLiveDemoSimulateAttack demonstrates real-time DoS detection by simulating an attack
// Run with: go test -v -tags=livedemo -run TestLiveDemoSimulateAttack ./monitor/
func TestLiveDemoSimulateAttack(t *testing.T) {
	tracker := NewTracker()

	// Start with some baseline connections
	baselineConnections(tracker)

	// Start metrics server
	addr := ":9099"
	mux := createMetricsMux(tracker)

	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("Starting metrics server on http://localhost%s", addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("Server error: %v", err)
		}
	}()

	time.Sleep(100 * time.Millisecond)

	url := fmt.Sprintf("http://localhost%s", addr)
	openBrowser(url)

	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("SSHadow Attack Simulation Demo")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Printf("\nServer running at: %s\n", url)
	fmt.Println("\nWatch the dashboard - attack simulation will begin in 3 seconds...")
	fmt.Println("The dashboard auto-refreshes every 5 seconds.")
	fmt.Println(strings.Repeat("=", 70))

	time.Sleep(3 * time.Second)

	// Simulate single-IP DoS attack
	fmt.Println("\n[ATTACK] Simulating single-IP DoS attack from 10.0.0.99...")
	for i := 0; i < 15; i++ {
		event := &LogEvent{
			Username:  "attacker",
			SourceIP:  "10.0.0.99",
			Port:      40000 + i,
			AuthType:  AuthPassword,
			Timestamp: time.Now(),
		}
		tracker.AddConnectionFromLog(fmt.Sprintf("attack-conn-%d", i), event)
		time.Sleep(200 * time.Millisecond)
		fmt.Printf("  Added connection %d/15 from 10.0.0.99\n", i+1)
	}

	fmt.Println("\n[INFO] Single-IP attack complete. Check the dashboard - 10.0.0.99 should show warning.")
	fmt.Println("[INFO] Waiting 5 seconds before distributed attack...")
	time.Sleep(5 * time.Second)

	// Simulate distributed attack using same key
	fmt.Println("\n[ATTACK] Simulating distributed attack using stolen key 'compromised-key'...")
	distributedIPs := []string{"192.168.1.50", "192.168.2.50", "192.168.3.50", "192.168.4.50",
		"172.16.1.10", "172.16.2.10", "172.16.3.10", "172.16.4.10"}

	for i, ip := range distributedIPs {
		event := &LogEvent{
			Username:    "service-account",
			SourceIP:    ip,
			Port:        22,
			AuthType:    AuthPublicKey,
			KeyType:     "RSA",
			Fingerprint: "SHA256:COMPROMISED-KEY-abc123xyz",
			Timestamp:   time.Now(),
		}
		tracker.AddConnectionFromLog(fmt.Sprintf("distributed-conn-%d", i), event)
		time.Sleep(300 * time.Millisecond)
		fmt.Printf("  Added connection from %s using compromised-key\n", ip)
	}

	fmt.Println("\n[INFO] Distributed attack complete. Check the dashboard:")
	fmt.Println("  - 'By User/Key' should show 'service-account' and 'compromised-key' with high counts")
	fmt.Println("  - These would trigger alerts in Prometheus")
	fmt.Println("\nPress Ctrl+C to stop...")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	fmt.Println("\nShutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server.Shutdown(ctx)
}

// populateDemoData creates sample data demonstrating both DoS scenarios
func populateDemoData(tracker *Tracker) {
	baseTime := time.Now()

	// Normal connections - various auth types
	normalConnections := []struct {
		id    string
		event *LogEvent
	}{
		// Certificate auth users
		{"cert-1", &LogEvent{Username: "alice", SourceIP: "192.168.1.100", Port: 54321, AuthType: AuthCert, KeyType: "ED25519", Fingerprint: "SHA256:alice-key-fp", CertID: "alice-laptop", CertSerial: 12345, CAFingerprint: "SHA256:CORP-CA", Timestamp: baseTime.Add(-2 * time.Hour)}},
		{"cert-2", &LogEvent{Username: "alice", SourceIP: "192.168.1.100", Port: 54322, AuthType: AuthCert, KeyType: "ED25519", Fingerprint: "SHA256:alice-key-fp", CertID: "alice-laptop", CertSerial: 12345, CAFingerprint: "SHA256:CORP-CA", Timestamp: baseTime.Add(-1 * time.Hour)}},

		// Public key auth users
		{"pk-1", &LogEvent{Username: "bob", SourceIP: "10.0.0.50", Port: 22, AuthType: AuthPublicKey, KeyType: "RSA", Fingerprint: "SHA256:bob-key-fp", Timestamp: baseTime.Add(-90 * time.Minute)}},
		{"pk-2", &LogEvent{Username: "eve", SourceIP: "10.0.0.51", Port: 22, AuthType: AuthPublicKey, KeyType: "ED25519", Fingerprint: "SHA256:eve-key-fp", Timestamp: baseTime.Add(-45 * time.Minute)}},

		// Password auth users
		{"pwd-1", &LogEvent{Username: "charlie", SourceIP: "172.16.0.1", Port: 22, AuthType: AuthPassword, Timestamp: baseTime.Add(-30 * time.Minute)}},
	}

	for _, c := range normalConnections {
		tracker.AddConnectionFromLog(c.id, c.event)
	}

	// DoS Scenario 1: Single IP with many connections
	dosIP := "10.0.0.99"
	for i := 0; i < 8; i++ {
		event := &LogEvent{
			Username:  "suspicious-user",
			SourceIP:  dosIP,
			Port:      40000 + i,
			AuthType:  AuthPassword,
			Timestamp: baseTime.Add(-time.Duration(10-i) * time.Minute),
		}
		tracker.AddConnectionFromLog(fmt.Sprintf("dos-ip-%d", i), event)
	}

	// DoS Scenario 2: Same key from distributed IPs (compromised key)
	compromisedKey := "SHA256:STOLEN-KEY-xyz789"
	distributedIPs := []string{"192.168.10.1", "192.168.20.1", "192.168.30.1", "192.168.40.1", "192.168.50.1", "192.168.60.1"}
	for i, ip := range distributedIPs {
		event := &LogEvent{
			Username:    "deploy-bot",
			SourceIP:    ip,
			Port:        22,
			AuthType:    AuthPublicKey,
			KeyType:     "RSA",
			Fingerprint: compromisedKey,
			Timestamp:   baseTime.Add(-time.Duration(5-i) * time.Minute),
		}
		tracker.AddConnectionFromLog(fmt.Sprintf("distributed-%d", i), event)
	}
}

// baselineConnections creates minimal baseline data
func baselineConnections(tracker *Tracker) {
	baseTime := time.Now()

	connections := []struct {
		id    string
		event *LogEvent
	}{
		{"baseline-1", &LogEvent{Username: "alice", SourceIP: "192.168.1.100", Port: 22, AuthType: AuthCert, KeyType: "ED25519", CertID: "alice-laptop", Timestamp: baseTime.Add(-1 * time.Hour)}},
		{"baseline-2", &LogEvent{Username: "bob", SourceIP: "10.0.0.50", Port: 22, AuthType: AuthPublicKey, KeyType: "RSA", Fingerprint: "SHA256:bob-key", Timestamp: baseTime.Add(-30 * time.Minute)}},
		{"baseline-3", &LogEvent{Username: "charlie", SourceIP: "172.16.0.1", Port: 22, AuthType: AuthPassword, Timestamp: baseTime.Add(-15 * time.Minute)}},
	}

	for _, c := range connections {
		tracker.AddConnectionFromLog(c.id, c.event)
	}
}

// createMetricsMux creates the HTTP handlers (duplicated from metrics.go for standalone test)
func createMetricsMux(tracker *Tracker) *http.ServeMux {
	mux := http.NewServeMux()

	// JSON endpoint
	mux.HandleFunc("/metrics/json", func(w http.ResponseWriter, r *http.Request) {
		stats := tracker.GetStats()
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.Encode(stats)
	})

	// Prometheus endpoint
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")

		stats := tracker.GetStats()
		activeConns := tracker.GetActiveConnections()

		// Overall
		fmt.Fprintf(w, "# HELP ssh_active_connections Total number of active SSH connections\n")
		fmt.Fprintf(w, "# TYPE ssh_active_connections gauge\n")
		fmt.Fprintf(w, "ssh_active_connections %d\n\n", activeConns)

		// Aggregations for DoS detection
		byIP := make(map[string]int)
		byUser := make(map[string]int)
		byKey := make(map[string]int)
		for _, stat := range stats {
			byIP[stat.SourceIP] += stat.ActiveCount
			byUser[stat.Username] += stat.ActiveCount
			if stat.KeyID != "" {
				byKey[stat.KeyID] += stat.ActiveCount
			}
		}

		fmt.Fprintf(w, "# HELP ssh_connections_by_ip Active connections by source IP (DoS detection)\n")
		fmt.Fprintf(w, "# TYPE ssh_connections_by_ip gauge\n")
		for ip, count := range byIP {
			fmt.Fprintf(w, "ssh_connections_by_ip{source_ip=\"%s\"} %d\n", ip, count)
		}

		fmt.Fprintf(w, "\n# HELP ssh_connections_by_user Active connections by username\n")
		fmt.Fprintf(w, "# TYPE ssh_connections_by_user gauge\n")
		for user, count := range byUser {
			fmt.Fprintf(w, "ssh_connections_by_user{username=\"%s\"} %d\n", user, count)
		}

		fmt.Fprintf(w, "\n# HELP ssh_connections_by_key Active connections by key ID\n")
		fmt.Fprintf(w, "# TYPE ssh_connections_by_key gauge\n")
		for keyID, count := range byKey {
			fmt.Fprintf(w, "ssh_connections_by_key{key_id=\"%s\"} %d\n", keyID, count)
		}

		// Detailed
		fmt.Fprintf(w, "\n# HELP ssh_user_active_connections Detailed active connections\n")
		fmt.Fprintf(w, "# TYPE ssh_user_active_connections gauge\n")
		for _, stat := range stats {
			labels := fmt.Sprintf(`username="%s",source_ip="%s",auth_type="%s",key_id="%s"`,
				stat.Username, stat.SourceIP, stat.AuthType, stat.KeyID)
			fmt.Fprintf(w, "ssh_user_active_connections{%s} %d\n", labels, stat.ActiveCount)
		}

		fmt.Fprintf(w, "\n# HELP ssh_user_total_connections Total connections per combination\n")
		fmt.Fprintf(w, "# TYPE ssh_user_total_connections counter\n")
		for _, stat := range stats {
			labels := fmt.Sprintf(`username="%s",source_ip="%s",auth_type="%s",key_id="%s"`,
				stat.Username, stat.SourceIP, stat.AuthType, stat.KeyID)
			fmt.Fprintf(w, "ssh_user_total_connections{%s} %d\n", labels, stat.TotalCount)
		}
	})

	// Dashboard
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		stats := tracker.GetStats()
		activeConns := tracker.GetActiveConnections()

		byIP := make(map[string]int)
		byUser := make(map[string]int)
		byKey := make(map[string]int)
		for _, stat := range stats {
			byIP[stat.SourceIP] += stat.ActiveCount
			byUser[stat.Username] += stat.ActiveCount
			if stat.KeyID != "" {
				byKey[stat.KeyID] += stat.ActiveCount
			}
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")

		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
    <title>SSHadow - Live Demo</title>
    <meta http-equiv="refresh" content="5">
    <style>
        body { font-family: monospace; margin: 20px; background: #1e1e1e; color: #d4d4d4; }
        h1 { color: #4ec9b0; }
        h2 { color: #569cd6; margin-top: 30px; }
        h3 { color: #9cdcfe; margin-top: 20px; }
        table { border-collapse: collapse; width: 100%%; margin-top: 10px; }
        th { background: #252526; padding: 10px; text-align: left; border-bottom: 2px solid #4ec9b0; }
        td { padding: 8px; border-bottom: 1px solid #3e3e42; }
        tr:hover { background: #2d2d30; }
        .active { color: #4ec9b0; font-weight: bold; }
        .warning { color: #f48771; font-weight: bold; background: #3e2526; }
        .header-info { color: #858585; margin: 10px 0; }
        .cert { color: #c586c0; }
        .publickey { color: #4fc1ff; }
        .password { color: #ce9178; }
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        .card { background: #252526; padding: 15px; border-radius: 4px; }
        .alert { background: #4e2526; border: 1px solid #f48771; padding: 10px; margin: 10px 0; border-radius: 4px; }
        @media (max-width: 900px) { .grid { grid-template-columns: 1fr; } }
    </style>
</head>
<body>
    <h1>SSHadow - SSH Connection Monitor</h1>
    <div class="header-info">
        Last updated: %s | Total active: <span class="active">%d</span> | Auto-refresh: 5s
    </div>
`, time.Now().Format("2006-01-02 15:04:05"), activeConns)

		// Check for alerts
		var alerts []string
		for ip, count := range byIP {
			if count > 5 {
				alerts = append(alerts, fmt.Sprintf("High connection count from IP %s: %d connections", ip, count))
			}
		}
		for user, count := range byUser {
			if count > 5 {
				alerts = append(alerts, fmt.Sprintf("High connection count for user '%s': %d connections", user, count))
			}
		}
		for key, count := range byKey {
			if count > 5 {
				alerts = append(alerts, fmt.Sprintf("High connection count for key '%s': %d connections", truncateString(key, 30), count))
			}
		}

		if len(alerts) > 0 {
			fmt.Fprintf(w, `    <div class="alert">
        <strong>Potential DoS Detected:</strong><br>
`)
			for _, alert := range alerts {
				fmt.Fprintf(w, "        - %s<br>\n", alert)
			}
			fmt.Fprintf(w, "    </div>\n")
		}

		fmt.Fprintf(w, `
    <h2>DoS Detection Views</h2>
    <div class="grid">
        <div class="card">
            <h3>By Source IP (Single Host Attack)</h3>
            <table>
                <tr><th>Source IP</th><th>Active Connections</th></tr>
`)

		type ipCount struct {
			ip    string
			count int
		}
		var ips []ipCount
		for ip, count := range byIP {
			ips = append(ips, ipCount{ip, count})
		}
		sort.Slice(ips, func(i, j int) bool { return ips[i].count > ips[j].count })

		for _, ic := range ips {
			class := "active"
			if ic.count > 5 {
				class = "warning"
			}
			fmt.Fprintf(w, "                <tr><td>%s</td><td class=\"%s\">%d</td></tr>\n", ic.ip, class, ic.count)
		}

		fmt.Fprintf(w, `            </table>
        </div>
        <div class="card">
            <h3>By User (Distributed Attack)</h3>
            <table>
                <tr><th>Username</th><th>Active Connections</th></tr>
`)

		type userCount struct {
			user  string
			count int
		}
		var users []userCount
		for user, count := range byUser {
			users = append(users, userCount{user, count})
		}
		sort.Slice(users, func(i, j int) bool { return users[i].count > users[j].count })

		for _, uc := range users {
			class := "active"
			if uc.count > 5 {
				class = "warning"
			}
			fmt.Fprintf(w, "                <tr><td>%s</td><td class=\"%s\">%d</td></tr>\n", uc.user, class, uc.count)
		}

		fmt.Fprintf(w, `            </table>
        </div>
    </div>

    <div class="card" style="margin-top: 20px;">
        <h3>By Key ID (Compromised Key Detection)</h3>
        <table>
            <tr><th>Key ID / Fingerprint</th><th>Active Connections</th></tr>
`)

		type keyCount struct {
			key   string
			count int
		}
		var keys []keyCount
		for key, count := range byKey {
			keys = append(keys, keyCount{key, count})
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i].count > keys[j].count })

		for _, kc := range keys {
			class := "active"
			if kc.count > 5 {
				class = "warning"
			}
			fmt.Fprintf(w, "            <tr><td>%s</td><td class=\"%s\">%d</td></tr>\n",
				truncateString(kc.key, 50), class, kc.count)
		}

		fmt.Fprintf(w, `        </table>
    </div>

    <h2>Detailed Connections</h2>
    <table>
        <tr>
            <th>Username</th>
            <th>Source IP</th>
            <th>Auth Type</th>
            <th>Key ID</th>
            <th>Active</th>
            <th>Total</th>
        </tr>
`)

		type statEntry struct {
			key  string
			stat *UserStats
		}
		var entries []statEntry
		for k, v := range stats {
			entries = append(entries, statEntry{k, v})
		}
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].stat.ActiveCount > entries[j].stat.ActiveCount
		})

		for _, e := range entries {
			s := e.stat
			authClass := string(s.AuthType)
			keyDisplay := s.KeyID
			if keyDisplay == "" {
				keyDisplay = "-"
			} else {
				keyDisplay = truncateString(keyDisplay, 35)
			}
			fmt.Fprintf(w, `        <tr>
            <td>%s</td>
            <td>%s</td>
            <td class="%s">%s</td>
            <td style="font-size:0.85em">%s</td>
            <td class="active">%d</td>
            <td>%d</td>
        </tr>
`, s.Username, s.SourceIP, authClass, s.AuthType, keyDisplay, s.ActiveCount, s.TotalCount)
		}

		fmt.Fprintf(w, `    </table>
    <p class="header-info" style="margin-top: 30px;">
        <a href="/metrics" style="color: #4ec9b0;">Prometheus metrics</a> |
        <a href="/metrics/json" style="color: #4ec9b0;">JSON export</a>
    </p>
</body>
</html>`)
	})

	return mux
}

// openBrowser opens the specified URL in the default browser
func openBrowser(url string) {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", url)
	default:
		log.Printf("Cannot open browser on %s - please open %s manually", runtime.GOOS, url)
		return
	}

	if err := cmd.Start(); err != nil {
		log.Printf("Failed to open browser: %v - please open %s manually", err, url)
	}
}