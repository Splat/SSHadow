package monitor

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"
)

// ServeMetrics starts an HTTP server that exposes connection metrics
func ServeMetrics(addr string, tracker *Tracker) {
	mux := http.NewServeMux()

	// JSON endpoint for all stats
	mux.HandleFunc("/metrics/json", func(w http.ResponseWriter, r *http.Request) {
		stats := tracker.GetStats()
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(stats); err != nil {
			log.Printf("Error encoding JSON: %v", err)
		}
	})

	// Prometheus-style metrics endpoint
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")

		stats := tracker.GetStats()
		activeConns := tracker.GetActiveConnections()

		// Overall metrics
		fmt.Fprintf(w, "# HELP ssh_active_connections Total number of active SSH connections\n")
		fmt.Fprintf(w, "# TYPE ssh_active_connections gauge\n")
		fmt.Fprintf(w, "ssh_active_connections %d\n\n", activeConns)

		// Pre-aggregated metrics for DoS detection
		// Aggregate by source IP (detect single host opening many connections)
		byIP := make(map[string]int)
		// Aggregate by username (detect distributed attack using same user)
		byUser := make(map[string]int)
		// Aggregate by key_id (detect distributed attack using same key/cert)
		byKey := make(map[string]int)

		for _, stat := range stats {
			byIP[stat.SourceIP] += stat.ActiveCount
			byUser[stat.Username] += stat.ActiveCount
			if stat.KeyID != "" {
				byKey[stat.KeyID] += stat.ActiveCount
			}
		}

		fmt.Fprintf(w, "# HELP ssh_connections_by_ip Active connections aggregated by source IP (for DoS detection)\n")
		fmt.Fprintf(w, "# TYPE ssh_connections_by_ip gauge\n")
		for ip, count := range byIP {
			fmt.Fprintf(w, "ssh_connections_by_ip{source_ip=\"%s\"} %d\n", ip, count)
		}

		fmt.Fprintf(w, "\n# HELP ssh_connections_by_user Active connections aggregated by username (for distributed attack detection)\n")
		fmt.Fprintf(w, "# TYPE ssh_connections_by_user gauge\n")
		for user, count := range byUser {
			fmt.Fprintf(w, "ssh_connections_by_user{username=\"%s\"} %d\n", user, count)
		}

		fmt.Fprintf(w, "\n# HELP ssh_connections_by_key Active connections aggregated by key ID (for distributed attack detection)\n")
		fmt.Fprintf(w, "# TYPE ssh_connections_by_key gauge\n")
		for keyID, count := range byKey {
			fmt.Fprintf(w, "ssh_connections_by_key{key_id=\"%s\"} %d\n", sanitizeLabel(keyID), count)
		}

		// Detailed per-connection metrics (original)
		fmt.Fprintf(w, "\n# HELP ssh_user_active_connections Number of active connections per user/ip/key combination\n")
		fmt.Fprintf(w, "# TYPE ssh_user_active_connections gauge\n")

		for _, stat := range stats {
			labels := fmt.Sprintf(`username="%s",source_ip="%s",auth_type="%s",key_id="%s"`,
				stat.Username, stat.SourceIP, stat.AuthType, sanitizeLabel(stat.KeyID))
			fmt.Fprintf(w, "ssh_user_active_connections{%s} %d\n", labels, stat.ActiveCount)
		}

		fmt.Fprintf(w, "\n# HELP ssh_user_total_connections Total number of connections per user/ip/key combination\n")
		fmt.Fprintf(w, "# TYPE ssh_user_total_connections counter\n")

		for _, stat := range stats {
			labels := fmt.Sprintf(`username="%s",source_ip="%s",auth_type="%s",key_id="%s"`,
				stat.Username, stat.SourceIP, stat.AuthType, sanitizeLabel(stat.KeyID))
			fmt.Fprintf(w, "ssh_user_total_connections{%s} %d\n", labels, stat.TotalCount)
		}
	})

	// Human-readable HTML dashboard
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		stats := tracker.GetStats()
		activeConns := tracker.GetActiveConnections()

		// Pre-aggregate for DoS detection views
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
    <title>SSH Connection Monitor</title>
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
        .inactive { color: #858585; }
        .warning { color: #f48771; font-weight: bold; }
        .header-info { color: #858585; margin: 10px 0; }
        .cert { color: #c586c0; }
        .pubkey { color: #4fc1ff; }
        .password { color: #ce9178; }
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        .card { background: #252526; padding: 15px; border-radius: 4px; }
        .card table { width: 100%%; }
        @media (max-width: 900px) { .grid { grid-template-columns: 1fr; } }
    </style>
</head>
<body>
    <h1>SSH Connection Monitor</h1>
    <div class="header-info">
        Last updated: %s | Total active connections: <span class="active">%d</span>
    </div>

    <h2>DoS Detection Views</h2>
    <div class="grid">
        <div class="card">
            <h3>By Source IP (Single Host Attack)</h3>
            <table>
                <tr><th>Source IP</th><th>Active Connections</th></tr>
`, time.Now().Format("2006-01-02 15:04:05"), activeConns)

		// Sort IPs by connection count (highest first)
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
			countClass := "active"
			if ic.count > 5 {
				countClass = "warning"
			}
			fmt.Fprintf(w, "                <tr><td>%s</td><td class=\"%s\">%d</td></tr>\n",
				ic.ip, countClass, ic.count)
		}

		fmt.Fprintf(w, `            </table>
        </div>
        <div class="card">
            <h3>By User/Key (Distributed Attack)</h3>
            <table>
                <tr><th>Username</th><th>Key ID</th><th>Active</th></tr>
`)

		// Sort users by connection count
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
			countClass := "active"
			if uc.count > 5 {
				countClass = "warning"
			}
			fmt.Fprintf(w, "                <tr><td>%s</td><td>-</td><td class=\"%s\">%d</td></tr>\n",
				uc.user, countClass, uc.count)
		}

		// Add key-based entries
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
			countClass := "active"
			if kc.count > 5 {
				countClass = "warning"
			}
			fmt.Fprintf(w, "                <tr><td>-</td><td>%s</td><td class=\"%s\">%d</td></tr>\n",
				truncateString(kc.key, 30), countClass, kc.count)
		}

		fmt.Fprintf(w, `            </table>
        </div>
    </div>

    <h2>Detailed Connection Statistics</h2>
    <table>
        <tr>
            <th>Username</th>
            <th>Source IP</th>
            <th>Auth Type</th>
            <th>Key ID / Fingerprint</th>
            <th>Principals</th>
            <th>Active</th>
            <th>Total</th>
            <th>First Seen</th>
            <th>Last Seen</th>
        </tr>
`)

		// Sort stats by last seen (most recent first)
		type statEntry struct {
			key  string
			stat *UserStats
		}
		var entries []statEntry
		for k, v := range stats {
			entries = append(entries, statEntry{k, v})
		}
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].stat.LastSeen.After(entries[j].stat.LastSeen)
		})

		for _, entry := range entries {
			stat := entry.stat
			activeClass := "inactive"
			if stat.ActiveCount > 0 {
				activeClass = "active"
			}

			authClass := string(stat.AuthType)
			principals := strings.Join(stat.Principals, ", ")
			if principals == "" {
				principals = "-"
			}

			fmt.Fprintf(w, `        <tr>
            <td>%s</td>
            <td>%s</td>
            <td class="%s">%s</td>
            <td style="font-size: 0.8em;">%s</td>
            <td>%s</td>
            <td class="%s">%d</td>
            <td>%d</td>
            <td>%s</td>
            <td>%s</td>
        </tr>
`,
				stat.Username,
				stat.SourceIP,
				authClass, stat.AuthType,
				truncateString(stat.KeyID, 40),
				principals,
				activeClass, stat.ActiveCount,
				stat.TotalCount,
				stat.FirstSeen.Format("01-02 15:04:05"),
				stat.LastSeen.Format("01-02 15:04:05"))
		}

		fmt.Fprintf(w, `    </table>
    <p class="header-info" style="margin-top: 30px;">
        Auto-refreshes every 5 seconds | 
        <a href="/metrics" style="color: #4ec9b0;">Prometheus metrics</a> | 
        <a href="/metrics/json" style="color: #4ec9b0;">JSON export</a>
    </p>
</body>
</html>`)
	})

	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Metrics server error: %v", err)
	}
}

func sanitizeLabel(s string) string {
	return strings.ReplaceAll(s, `"`, `\"`)
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
