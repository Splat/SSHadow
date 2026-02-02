package monitor

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestIntegrationAllAuthMethods creates sample data for all authentication types
// and outputs the metrics in all formats. Run with -v flag to see sample output:
//
//	go test -v -run TestIntegrationAllAuthMethods ./monitor/
func TestIntegrationAllAuthMethods(t *testing.T) {
	tracker := NewTracker()

	// Simulate connections for each auth type
	setupSampleConnections(tracker)

	// Capture and display output in all formats
	t.Run("JSON Output", func(t *testing.T) {
		output := captureJSONOutput(tracker)
		t.Logf("\n=== JSON Output (/metrics/json) ===\n%s", output)
	})

	t.Run("Prometheus Output", func(t *testing.T) {
		output := capturePrometheusOutput(tracker)
		t.Logf("\n=== Prometheus Output (/metrics) ===\n%s", output)
	})

	t.Run("Dashboard HTML Output", func(t *testing.T) {
		output := captureDashboardOutput(tracker)
		t.Logf("\n=== Dashboard HTML Output (/) ===\n%s", output)
	})
}

// TestIntegrationPasswordAuth demonstrates password authentication output
func TestIntegrationPasswordAuth(t *testing.T) {
	tracker := NewTracker()

	// Add password auth connections
	events := []*LogEvent{
		{
			Username:  "charlie",
			SourceIP:  "172.16.0.1",
			Port:      22222,
			AuthType:  AuthPassword,
			Timestamp: time.Now().Add(-30 * time.Minute),
		},
		{
			Username:  "charlie",
			SourceIP:  "172.16.0.1",
			Port:      22223,
			AuthType:  AuthPassword,
			Timestamp: time.Now().Add(-15 * time.Minute),
		},
		{
			Username:  "david",
			SourceIP:  "10.0.0.25",
			Port:      33333,
			AuthType:  AuthPassword,
			Timestamp: time.Now().Add(-5 * time.Minute),
		},
	}

	for i, event := range events {
		tracker.AddConnectionFromLog(fmt.Sprintf("pwd-conn-%d", i+1), event)
	}

	t.Logf("\n=== Password Authentication Sample ===")
	t.Logf("\nJSON Output:\n%s", captureJSONOutput(tracker))
	t.Logf("\nPrometheus Output:\n%s", capturePrometheusOutput(tracker))
}

// TestIntegrationPublicKeyAuth demonstrates public key authentication output
func TestIntegrationPublicKeyAuth(t *testing.T) {
	tracker := NewTracker()

	// Add public key auth connections
	events := []*LogEvent{
		{
			Username:    "bob",
			SourceIP:    "10.0.0.50",
			Port:        12345,
			AuthType:    AuthPublicKey,
			KeyType:     "RSA",
			Fingerprint: "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8",
			Timestamp:   time.Now().Add(-2 * time.Hour),
		},
		{
			Username:    "bob",
			SourceIP:    "10.0.0.51",
			Port:        12346,
			AuthType:    AuthPublicKey,
			KeyType:     "RSA",
			Fingerprint: "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8",
			Timestamp:   time.Now().Add(-1 * time.Hour),
		},
		{
			Username:    "eve",
			SourceIP:    "192.168.50.10",
			Port:        44444,
			AuthType:    AuthPublicKey,
			KeyType:     "ED25519",
			Fingerprint: "SHA256:uH7kzJxNShdLrqKdF9c8SLsYdCPmHgR2V4FYhw6E3Kc",
			Timestamp:   time.Now().Add(-10 * time.Minute),
		},
	}

	for i, event := range events {
		tracker.AddConnectionFromLog(fmt.Sprintf("pk-conn-%d", i+1), event)
	}

	t.Logf("\n=== Public Key Authentication Sample ===")
	t.Logf("\nJSON Output:\n%s", captureJSONOutput(tracker))
	t.Logf("\nPrometheus Output:\n%s", capturePrometheusOutput(tracker))
}

// TestIntegrationCertAuth demonstrates certificate authentication output
func TestIntegrationCertAuth(t *testing.T) {
	tracker := NewTracker()

	// Add certificate auth connections
	events := []*LogEvent{
		{
			Username:      "alice",
			SourceIP:      "192.168.1.100",
			Port:          54321,
			AuthType:      AuthCert,
			KeyType:       "ED25519",
			Fingerprint:   "SHA256:abc123def456ghi789jkl012mno345pqr678stu901vwx",
			CertID:        "alice-laptop",
			CertSerial:    12345,
			CAFingerprint: "SHA256:CORPORATE-CA-2024-abc123def456ghi789",
			Timestamp:     time.Now().Add(-45 * time.Minute),
		},
		{
			Username:      "alice",
			SourceIP:      "192.168.1.100",
			Port:          54322,
			AuthType:      AuthCert,
			KeyType:       "ED25519",
			Fingerprint:   "SHA256:abc123def456ghi789jkl012mno345pqr678stu901vwx",
			CertID:        "alice-laptop",
			CertSerial:    12345,
			CAFingerprint: "SHA256:CORPORATE-CA-2024-abc123def456ghi789",
			Timestamp:     time.Now().Add(-20 * time.Minute),
		},
		{
			Username:      "frank",
			SourceIP:      "10.100.200.5",
			Port:          55555,
			AuthType:      AuthCert,
			KeyType:       "RSA",
			Fingerprint:   "SHA256:xyz789abc012def345ghi678jkl901mno234pqr567stu",
			CertID:        "prod-deploy-key",
			CertSerial:    99999,
			CAFingerprint: "SHA256:PRODUCTION-CA-2024-xyz789abc012def345",
			Timestamp:     time.Now().Add(-3 * time.Minute),
		},
	}

	for i, event := range events {
		tracker.AddConnectionFromLog(fmt.Sprintf("cert-conn-%d", i+1), event)
	}

	t.Logf("\n=== Certificate Authentication Sample ===")
	t.Logf("\nJSON Output:\n%s", captureJSONOutput(tracker))
	t.Logf("\nPrometheus Output:\n%s", capturePrometheusOutput(tracker))
}

// TestIntegrationMixedAuthWithDisconnects demonstrates a realistic scenario
// with mixed auth types and some disconnections
func TestIntegrationMixedAuthWithDisconnects(t *testing.T) {
	tracker := NewTracker()

	// Add various connections
	connections := []struct {
		id    string
		event *LogEvent
	}{
		{
			id: "conn-alice-1",
			event: &LogEvent{
				Username:      "alice",
				SourceIP:      "192.168.1.100",
				Port:          54321,
				AuthType:      AuthCert,
				KeyType:       "ED25519",
				Fingerprint:   "SHA256:abc123def456",
				CertID:        "alice-laptop",
				CertSerial:    12345,
				CAFingerprint: "SHA256:CORPORATE-CA",
				Timestamp:     time.Now().Add(-1 * time.Hour),
			},
		},
		{
			id: "conn-bob-1",
			event: &LogEvent{
				Username:    "bob",
				SourceIP:    "10.0.0.50",
				Port:        12345,
				AuthType:    AuthPublicKey,
				KeyType:     "RSA",
				Fingerprint: "SHA256:xyz789abc012",
				Timestamp:   time.Now().Add(-45 * time.Minute),
			},
		},
		{
			id: "conn-charlie-1",
			event: &LogEvent{
				Username:  "charlie",
				SourceIP:  "172.16.0.1",
				Port:      22222,
				AuthType:  AuthPassword,
				Timestamp: time.Now().Add(-30 * time.Minute),
			},
		},
		{
			id: "conn-alice-2",
			event: &LogEvent{
				Username:      "alice",
				SourceIP:      "192.168.1.100",
				Port:          54322,
				AuthType:      AuthCert,
				KeyType:       "ED25519",
				Fingerprint:   "SHA256:abc123def456",
				CertID:        "alice-laptop",
				CertSerial:    12345,
				CAFingerprint: "SHA256:CORPORATE-CA",
				Timestamp:     time.Now().Add(-15 * time.Minute),
			},
		},
		{
			id: "conn-bob-2",
			event: &LogEvent{
				Username:    "bob",
				SourceIP:    "10.0.0.51",
				Port:        12346,
				AuthType:    AuthPublicKey,
				KeyType:     "RSA",
				Fingerprint: "SHA256:xyz789abc012",
				Timestamp:   time.Now().Add(-10 * time.Minute),
			},
		},
	}

	// Add all connections
	for _, c := range connections {
		tracker.AddConnectionFromLog(c.id, c.event)
	}

	t.Logf("\n=== Mixed Auth Types - Before Disconnects ===")
	t.Logf("Active connections: %d", tracker.GetActiveConnections())
	t.Logf("\nJSON Output:\n%s", captureJSONOutput(tracker))

	// Simulate some disconnections
	tracker.RemoveConnection("conn-bob-1")
	tracker.RemoveConnection("conn-charlie-1")

	t.Logf("\n=== Mixed Auth Types - After 2 Disconnects ===")
	t.Logf("Active connections: %d", tracker.GetActiveConnections())
	t.Logf("\nJSON Output:\n%s", captureJSONOutput(tracker))
	t.Logf("\nPrometheus Output:\n%s", capturePrometheusOutput(tracker))
}

// TestIntegrationLogParsingToOutput demonstrates the full flow from log lines to output
func TestIntegrationLogParsingToOutput(t *testing.T) {
	tracker := NewTracker()

	// Realistic sshd log lines
	logLines := []string{
		// Certificate auth
		`Jan 30 10:15:23 bastion sshd[12345]: Accepted publickey for alice from 192.168.1.100 port 54321 ssh2: ED25519-CERT SHA256:abc123def456 ID "alice-laptop" serial 12345 CA ED25519 SHA256:CORPORATE-CA`,
		// Public key auth
		`Jan 30 10:16:00 bastion sshd[12346]: Accepted publickey for bob from 10.0.0.50 port 12345 ssh2: RSA SHA256:xyz789abc012`,
		// Password auth
		`Jan 30 10:17:30 bastion sshd[12347]: Accepted password for charlie from 172.16.0.1 port 22222 ssh2`,
		// Another cert auth
		`Jan 30 10:18:45 bastion sshd[12348]: Accepted publickey for frank from 10.100.200.5 port 55555 ssh2: RSA-CERT SHA256:prodkey123 ID "prod-deploy-key" serial 99999 CA RSA SHA256:PRODUCTION-CA`,
		// Keyboard-interactive (treated as password)
		`Jan 30 10:19:00 bastion sshd[12349]: Accepted keyboard-interactive/pam for david from 10.0.0.25 port 33333 ssh2`,
	}

	t.Logf("\n=== Parsing Real Log Lines ===\n")

	for i, line := range logLines {
		event := ParseLogLine(line)
		if event.EventType == EventAccepted {
			connID := fmt.Sprintf("log-conn-%d", i+1)
			tracker.AddConnectionFromLog(connID, event)
			t.Logf("Parsed: user=%s ip=%s auth=%s keyid=%s",
				event.Username, event.SourceIP, event.AuthType, event.CertID)
		}
	}

	t.Logf("\n=== Resulting Output ===")
	t.Logf("\nJSON:\n%s", captureJSONOutput(tracker))
	t.Logf("\nPrometheus:\n%s", capturePrometheusOutput(tracker))
}

// setupSampleConnections populates the tracker with sample data for all auth types
func setupSampleConnections(tracker *Tracker) {
	baseTime := time.Now()

	// Certificate authentication - alice with SSH cert
	certEvent1 := &LogEvent{
		Username:      "alice",
		SourceIP:      "192.168.1.100",
		Port:          54321,
		AuthType:      AuthCert,
		KeyType:       "ED25519",
		Fingerprint:   "SHA256:abc123def456ghi789jkl012mno345pqr678stu901vwx",
		CertID:        "alice-laptop",
		CertSerial:    12345,
		CAFingerprint: "SHA256:CORPORATE-CA-2024-abc123def456ghi789jkl012",
		Timestamp:     baseTime.Add(-45 * time.Minute),
	}
	tracker.AddConnectionFromLog("cert-conn-1", certEvent1)

	// Second connection from same cert
	certEvent2 := &LogEvent{
		Username:      "alice",
		SourceIP:      "192.168.1.100",
		Port:          54322,
		AuthType:      AuthCert,
		KeyType:       "ED25519",
		Fingerprint:   "SHA256:abc123def456ghi789jkl012mno345pqr678stu901vwx",
		CertID:        "alice-laptop",
		CertSerial:    12345,
		CAFingerprint: "SHA256:CORPORATE-CA-2024-abc123def456ghi789jkl012",
		Timestamp:     baseTime.Add(-20 * time.Minute),
	}
	tracker.AddConnectionFromLog("cert-conn-2", certEvent2)

	// Public key authentication - bob with RSA key
	pubkeyEvent1 := &LogEvent{
		Username:    "bob",
		SourceIP:    "10.0.0.50",
		Port:        12345,
		AuthType:    AuthPublicKey,
		KeyType:     "RSA",
		Fingerprint: "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8",
		Timestamp:   baseTime.Add(-2 * time.Hour),
	}
	tracker.AddConnectionFromLog("pk-conn-1", pubkeyEvent1)

	// Public key authentication - eve with ED25519 key
	pubkeyEvent2 := &LogEvent{
		Username:    "eve",
		SourceIP:    "192.168.50.10",
		Port:        44444,
		AuthType:    AuthPublicKey,
		KeyType:     "ED25519",
		Fingerprint: "SHA256:uH7kzJxNShdLrqKdF9c8SLsYdCPmHgR2V4FYhw6E3Kc",
		Timestamp:   baseTime.Add(-10 * time.Minute),
	}
	tracker.AddConnectionFromLog("pk-conn-2", pubkeyEvent2)

	// Password authentication - charlie
	pwdEvent1 := &LogEvent{
		Username:  "charlie",
		SourceIP:  "172.16.0.1",
		Port:      22222,
		AuthType:  AuthPassword,
		Timestamp: baseTime.Add(-30 * time.Minute),
	}
	tracker.AddConnectionFromLog("pwd-conn-1", pwdEvent1)

	// Password authentication - david
	pwdEvent2 := &LogEvent{
		Username:  "david",
		SourceIP:  "10.0.0.25",
		Port:      33333,
		AuthType:  AuthPassword,
		Timestamp: baseTime.Add(-5 * time.Minute),
	}
	tracker.AddConnectionFromLog("pwd-conn-2", pwdEvent2)

	// Certificate auth - frank with production deploy key
	certEvent3 := &LogEvent{
		Username:      "frank",
		SourceIP:      "10.100.200.5",
		Port:          55555,
		AuthType:      AuthCert,
		KeyType:       "RSA",
		Fingerprint:   "SHA256:xyz789abc012def345ghi678jkl901mno234pqr567stu",
		CertID:        "prod-deploy-key",
		CertSerial:    99999,
		CAFingerprint: "SHA256:PRODUCTION-CA-2024-xyz789abc012def345ghi678",
		Timestamp:     baseTime.Add(-3 * time.Minute),
	}
	tracker.AddConnectionFromLog("cert-conn-3", certEvent3)
}

// captureJSONOutput captures the JSON metrics output
func captureJSONOutput(tracker *Tracker) string {
	stats := tracker.GetStats()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.Encode(stats)
	return buf.String()
}

// capturePrometheusOutput captures the Prometheus metrics output
func capturePrometheusOutput(tracker *Tracker) string {
	var buf bytes.Buffer

	stats := tracker.GetStats()
	activeConns := tracker.GetActiveConnections()

	fmt.Fprintf(&buf, "# HELP ssh_active_connections Total number of active SSH connections\n")
	fmt.Fprintf(&buf, "# TYPE ssh_active_connections gauge\n")
	fmt.Fprintf(&buf, "ssh_active_connections %d\n\n", activeConns)

	// Pre-aggregated metrics for DoS detection
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

	fmt.Fprintf(&buf, "# HELP ssh_connections_by_ip Active connections by source IP (DoS detection)\n")
	fmt.Fprintf(&buf, "# TYPE ssh_connections_by_ip gauge\n")
	for ip, count := range byIP {
		fmt.Fprintf(&buf, "ssh_connections_by_ip{source_ip=\"%s\"} %d\n", ip, count)
	}

	fmt.Fprintf(&buf, "\n# HELP ssh_connections_by_user Active connections by username (distributed attack detection)\n")
	fmt.Fprintf(&buf, "# TYPE ssh_connections_by_user gauge\n")
	for user, count := range byUser {
		fmt.Fprintf(&buf, "ssh_connections_by_user{username=\"%s\"} %d\n", user, count)
	}

	fmt.Fprintf(&buf, "\n# HELP ssh_connections_by_key Active connections by key ID (compromised key detection)\n")
	fmt.Fprintf(&buf, "# TYPE ssh_connections_by_key gauge\n")
	for keyID, count := range byKey {
		fmt.Fprintf(&buf, "ssh_connections_by_key{key_id=\"%s\"} %d\n", sanitizeLabel(keyID), count)
	}

	fmt.Fprintf(&buf, "\n# HELP ssh_user_active_connections Detailed active connections per user/ip/key\n")
	fmt.Fprintf(&buf, "# TYPE ssh_user_active_connections gauge\n")
	for _, stat := range stats {
		labels := fmt.Sprintf(`username="%s",source_ip="%s",auth_type="%s",key_id="%s"`,
			stat.Username, stat.SourceIP, stat.AuthType, sanitizeLabel(stat.KeyID))
		fmt.Fprintf(&buf, "ssh_user_active_connections{%s} %d\n", labels, stat.ActiveCount)
	}

	fmt.Fprintf(&buf, "\n# HELP ssh_user_total_connections Total connections per user/ip/key\n")
	fmt.Fprintf(&buf, "# TYPE ssh_user_total_connections counter\n")
	for _, stat := range stats {
		labels := fmt.Sprintf(`username="%s",source_ip="%s",auth_type="%s",key_id="%s"`,
			stat.Username, stat.SourceIP, stat.AuthType, sanitizeLabel(stat.KeyID))
		fmt.Fprintf(&buf, "ssh_user_total_connections{%s} %d\n", labels, stat.TotalCount)
	}

	return buf.String()
}

// captureDashboardOutput captures a simplified dashboard output (text representation)
func captureDashboardOutput(tracker *Tracker) string {
	var buf bytes.Buffer

	stats := tracker.GetStats()
	activeConns := tracker.GetActiveConnections()

	fmt.Fprintf(&buf, "╔══════════════════════════════════════════════════════════════════════════════════╗\n")
	fmt.Fprintf(&buf, "║                           SSH CONNECTION MONITOR                                  ║\n")
	fmt.Fprintf(&buf, "╠══════════════════════════════════════════════════════════════════════════════════╣\n")
	fmt.Fprintf(&buf, "║ Active Connections: %-5d                                                         ║\n", activeConns)
	fmt.Fprintf(&buf, "╠══════════════════════════════════════════════════════════════════════════════════╣\n")
	fmt.Fprintf(&buf, "║ USER       │ SOURCE IP       │ AUTH     │ KEY ID/FINGERPRINT       │ ACT │ TOT  ║\n")
	fmt.Fprintf(&buf, "╠════════════╪═════════════════╪══════════╪══════════════════════════╪═════╪══════╣\n")

	for _, stat := range stats {
		keyID := stat.KeyID
		if len(keyID) > 24 {
			keyID = keyID[:21] + "..."
		}
		if keyID == "" {
			keyID = "-"
		}

		fmt.Fprintf(&buf, "║ %-10s │ %-15s │ %-8s │ %-24s │ %3d │ %4d ║\n",
			truncStr(stat.Username, 10),
			truncStr(stat.SourceIP, 15),
			stat.AuthType,
			keyID,
			stat.ActiveCount,
			stat.TotalCount,
		)
	}

	fmt.Fprintf(&buf, "╚══════════════════════════════════════════════════════════════════════════════════╝\n")

	return buf.String()
}

func truncStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

// TestHTTPEndpoints tests the actual HTTP endpoints
func TestHTTPEndpoints(t *testing.T) {
	tracker := NewTracker()
	setupSampleConnections(tracker)

	// Create test server with the same handlers as ServeMetrics
	mux := http.NewServeMux()

	mux.HandleFunc("/metrics/json", func(w http.ResponseWriter, r *http.Request) {
		stats := tracker.GetStats()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(stats)
	})

	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		stats := tracker.GetStats()
		activeConns := tracker.GetActiveConnections()

		fmt.Fprintf(w, "# HELP ssh_active_connections Total number of active SSH connections\n")
		fmt.Fprintf(w, "# TYPE ssh_active_connections gauge\n")
		fmt.Fprintf(w, "ssh_active_connections %d\n", activeConns)

		fmt.Fprintf(w, "# HELP ssh_user_active_connections Number of active connections per user\n")
		fmt.Fprintf(w, "# TYPE ssh_user_active_connections gauge\n")

		for _, stat := range stats {
			labels := fmt.Sprintf(`username="%s",source_ip="%s",auth_type="%s",key_id="%s"`,
				stat.Username, stat.SourceIP, stat.AuthType, sanitizeLabel(stat.KeyID))
			fmt.Fprintf(w, "ssh_user_active_connections{%s} %d\n", labels, stat.ActiveCount)
		}
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	t.Run("JSON Endpoint", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/metrics/json")
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		contentType := resp.Header.Get("Content-Type")
		if !strings.Contains(contentType, "application/json") {
			t.Errorf("Expected JSON content type, got %s", contentType)
		}

		body, _ := io.ReadAll(resp.Body)
		t.Logf("JSON Response:\n%s", string(body))

		// Verify it's valid JSON
		var result map[string]interface{}
		if err := json.Unmarshal(body, &result); err != nil {
			t.Errorf("Invalid JSON response: %v", err)
		}
	})

	t.Run("Prometheus Endpoint", func(t *testing.T) {
		resp, err := http.Get(server.URL + "/metrics")
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)
		t.Logf("Prometheus Response:\n%s", bodyStr)

		// Verify expected metrics are present
		if !strings.Contains(bodyStr, "ssh_active_connections") {
			t.Error("Missing ssh_active_connections metric")
		}
		if !strings.Contains(bodyStr, "ssh_user_active_connections") {
			t.Error("Missing ssh_user_active_connections metric")
		}
	})
}