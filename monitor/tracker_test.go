package monitor

import (
	"testing"
	"time"
)

func TestTrackerAddRemoveConnection(t *testing.T) {
	tracker := NewTracker()

	// Add a connection via log event
	event := &LogEvent{
		Username:  "alice",
		SourceIP:  "192.168.1.100",
		Port:      54321,
		AuthType:  AuthPassword,
		Timestamp: time.Now(),
	}
	tracker.AddConnectionFromLog("conn1", event)

	// Verify active connections
	if count := tracker.GetActiveConnections(); count != 1 {
		t.Errorf("Expected 1 active connection, got %d", count)
	}

	// Verify stats
	stats := tracker.GetStats()
	if len(stats) != 1 {
		t.Errorf("Expected 1 stat entry, got %d", len(stats))
	}

	// Check stats details
	for _, stat := range stats {
		if stat.Username != "alice" {
			t.Errorf("Expected username 'alice', got '%s'", stat.Username)
		}
		if stat.ActiveCount != 1 {
			t.Errorf("Expected active count 1, got %d", stat.ActiveCount)
		}
		if stat.TotalCount != 1 {
			t.Errorf("Expected total count 1, got %d", stat.TotalCount)
		}
	}

	// Remove the connection
	tracker.RemoveConnection("conn1")

	// Verify no active connections
	if count := tracker.GetActiveConnections(); count != 0 {
		t.Errorf("Expected 0 active connections, got %d", count)
	}

	// Stats should still exist but with 0 active
	stats = tracker.GetStats()
	if len(stats) != 1 {
		t.Errorf("Expected 1 stat entry, got %d", len(stats))
	}
	for _, stat := range stats {
		if stat.ActiveCount != 0 {
			t.Errorf("Expected active count 0, got %d", stat.ActiveCount)
		}
	}
}

func TestTrackerMultipleConnections(t *testing.T) {
	tracker := NewTracker()

	// Add multiple connections from same user/IP
	event1 := &LogEvent{Username: "alice", SourceIP: "192.168.1.100", Port: 54321, AuthType: AuthPassword}
	event2 := &LogEvent{Username: "alice", SourceIP: "192.168.1.100", Port: 54322, AuthType: AuthPassword}
	event3 := &LogEvent{Username: "bob", SourceIP: "192.168.1.101", Port: 54323, AuthType: AuthPassword}

	tracker.AddConnectionFromLog("conn1", event1)
	tracker.AddConnectionFromLog("conn2", event2)
	tracker.AddConnectionFromLog("conn3", event3)

	// Verify active connections
	if count := tracker.GetActiveConnections(); count != 3 {
		t.Errorf("Expected 3 active connections, got %d", count)
	}

	// Verify stats (should have 2 entries: alice@192.168.1.100 and bob@192.168.1.101)
	stats := tracker.GetStats()
	if len(stats) != 2 {
		t.Errorf("Expected 2 stat entries, got %d", len(stats))
	}

	// Find alice's stats
	var aliceStats *UserStats
	for _, stat := range stats {
		if stat.Username == "alice" {
			aliceStats = stat
			break
		}
	}

	if aliceStats == nil {
		t.Fatal("Alice's stats not found")
	}

	if aliceStats.ActiveCount != 2 {
		t.Errorf("Expected alice to have 2 active connections, got %d", aliceStats.ActiveCount)
	}
	if aliceStats.TotalCount != 2 {
		t.Errorf("Expected alice to have 2 total connections, got %d", aliceStats.TotalCount)
	}

	// Remove one of alice's connections
	tracker.RemoveConnection("conn1")

	if count := tracker.GetActiveConnections(); count != 2 {
		t.Errorf("Expected 2 active connections, got %d", count)
	}

	stats = tracker.GetStats()
	for _, stat := range stats {
		if stat.Username == "alice" {
			if stat.ActiveCount != 1 {
				t.Errorf("Expected alice to have 1 active connection, got %d", stat.ActiveCount)
			}
			if stat.TotalCount != 2 {
				t.Errorf("Expected alice to have 2 total connections, got %d", stat.TotalCount)
			}
		}
	}
}

func TestTrackerPublicKeyAuth(t *testing.T) {
	tracker := NewTracker()

	event := &LogEvent{
		Username:    "alice",
		SourceIP:    "192.168.1.100",
		Port:        54321,
		AuthType:    AuthPublicKey,
		KeyType:     "ED25519",
		Fingerprint: "SHA256:abc123def456",
	}
	tracker.AddConnectionFromLog("conn1", event)

	stats := tracker.GetStats()
	if len(stats) != 1 {
		t.Fatalf("Expected 1 stat entry, got %d", len(stats))
	}

	for _, stat := range stats {
		if stat.AuthType != AuthPublicKey {
			t.Errorf("Expected auth type 'publickey', got '%s'", stat.AuthType)
		}
		if stat.KeyID == "" {
			t.Error("Expected non-empty key ID")
		}
		if stat.Fingerprint != "SHA256:abc123def456" {
			t.Errorf("Expected fingerprint 'SHA256:abc123def456', got '%s'", stat.Fingerprint)
		}
	}
}

func TestTrackerCertAuth(t *testing.T) {
	tracker := NewTracker()

	event := &LogEvent{
		Username:      "alice",
		SourceIP:      "192.168.1.100",
		Port:          54321,
		AuthType:      AuthCert,
		KeyType:       "ED25519",
		Fingerprint:   "SHA256:abc123",
		CertID:        "test-key-id",
		CertSerial:    12345,
		CAType:        "ED25519",
		CAFingerprint: "SHA256:ca-fingerprint",
	}
	tracker.AddConnectionFromLog("conn1", event)

	stats := tracker.GetStats()
	if len(stats) != 1 {
		t.Fatalf("Expected 1 stat entry, got %d", len(stats))
	}

	for _, stat := range stats {
		if stat.AuthType != AuthCert {
			t.Errorf("Expected auth type 'cert', got '%s'", stat.AuthType)
		}
		if stat.KeyID != "test-key-id" {
			t.Errorf("Expected key ID 'test-key-id', got '%s'", stat.KeyID)
		}
		if stat.CAFingerprint != "SHA256:ca-fingerprint" {
			t.Errorf("Expected CA fingerprint 'SHA256:ca-fingerprint', got '%s'", stat.CAFingerprint)
		}
	}
}

func TestTrackerRemoveByUser(t *testing.T) {
	tracker := NewTracker()

	event := &LogEvent{
		Username: "alice",
		SourceIP: "192.168.1.100",
		Port:     54321,
		AuthType: AuthPassword,
	}
	tracker.AddConnectionFromLog("conn1", event)

	// Remove by user/IP/port
	tracker.RemoveConnectionByUser("alice", "192.168.1.100", 54321)

	if count := tracker.GetActiveConnections(); count != 0 {
		t.Errorf("Expected 0 active connections, got %d", count)
	}
}

func TestTrackerUpdateActivity(t *testing.T) {
	tracker := NewTracker()

	event := &LogEvent{
		Username: "alice",
		SourceIP: "192.168.1.100",
		Port:     54321,
		AuthType: AuthPassword,
	}
	tracker.AddConnectionFromLog("conn1", event)

	// Wait a bit
	time.Sleep(10 * time.Millisecond)

	// Update activity
	tracker.UpdateActivity("conn1")

	// Check that connection exists and was updated
	if count := tracker.GetActiveConnections(); count != 1 {
		t.Errorf("Expected 1 active connection, got %d", count)
	}
}

func TestTrackerConcurrency(t *testing.T) {
	tracker := NewTracker()

	// Add connections concurrently
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			connID := string(rune('A' + id))
			event := &LogEvent{
				Username: "user",
				SourceIP: "192.168.1.100",
				Port:     50000 + id,
				AuthType: AuthPassword,
			}
			tracker.AddConnectionFromLog(connID, event)
			tracker.UpdateActivity(connID)
			tracker.RemoveConnection(connID)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify no active connections remain
	if count := tracker.GetActiveConnections(); count != 0 {
		t.Errorf("Expected 0 active connections, got %d", count)
	}
}
