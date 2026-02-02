package monitor

import (
	"testing"
)

func TestParseAcceptedCert(t *testing.T) {
	line := `Jan 30 10:15:23 bastion sshd[12345]: Accepted publickey for alice from 192.168.1.100 port 54321 ssh2: ED25519-CERT SHA256:abc123def456 ID "alice-laptop" serial 12345 CA ED25519 SHA256:cafingerprint`

	event := ParseLogLine(line)

	if event.EventType != EventAccepted {
		t.Errorf("Expected EventAccepted, got %v", event.EventType)
	}
	if event.Username != "alice" {
		t.Errorf("Expected username 'alice', got '%s'", event.Username)
	}
	if event.SourceIP != "192.168.1.100" {
		t.Errorf("Expected IP '192.168.1.100', got '%s'", event.SourceIP)
	}
	if event.Port != 54321 {
		t.Errorf("Expected port 54321, got %d", event.Port)
	}
	if event.AuthType != AuthCert {
		t.Errorf("Expected auth type 'cert', got '%s'", event.AuthType)
	}
	if event.KeyType != "ED25519" {
		t.Errorf("Expected key type 'ED25519', got '%s'", event.KeyType)
	}
	if event.CertID != "alice-laptop" {
		t.Errorf("Expected cert ID 'alice-laptop', got '%s'", event.CertID)
	}
	if event.CertSerial != 12345 {
		t.Errorf("Expected cert serial 12345, got %d", event.CertSerial)
	}
	if event.CAFingerprint != "SHA256:cafingerprint" {
		t.Errorf("Expected CA fingerprint 'SHA256:cafingerprint', got '%s'", event.CAFingerprint)
	}
	if event.PID != 12345 {
		t.Errorf("Expected PID 12345, got %d", event.PID)
	}
	if event.Hostname != "bastion" {
		t.Errorf("Expected hostname 'bastion', got '%s'", event.Hostname)
	}
}

func TestParseAcceptedPubkey(t *testing.T) {
	line := `Jan 30 10:15:23 bastion sshd[12345]: Accepted publickey for bob from 10.0.0.50 port 12345 ssh2: RSA SHA256:xyz789abc`

	event := ParseLogLine(line)

	if event.EventType != EventAccepted {
		t.Errorf("Expected EventAccepted, got %v", event.EventType)
	}
	if event.Username != "bob" {
		t.Errorf("Expected username 'bob', got '%s'", event.Username)
	}
	if event.SourceIP != "10.0.0.50" {
		t.Errorf("Expected IP '10.0.0.50', got '%s'", event.SourceIP)
	}
	if event.AuthType != AuthPublicKey {
		t.Errorf("Expected auth type 'publickey', got '%s'", event.AuthType)
	}
	if event.KeyType != "RSA" {
		t.Errorf("Expected key type 'RSA', got '%s'", event.KeyType)
	}
	if event.Fingerprint != "SHA256:xyz789abc" {
		t.Errorf("Expected fingerprint 'SHA256:xyz789abc', got '%s'", event.Fingerprint)
	}
}

func TestParseAcceptedPassword(t *testing.T) {
	line := `Jan 30 10:15:23 bastion sshd[12345]: Accepted password for charlie from 172.16.0.1 port 22222 ssh2`

	event := ParseLogLine(line)

	if event.EventType != EventAccepted {
		t.Errorf("Expected EventAccepted, got %v", event.EventType)
	}
	if event.Username != "charlie" {
		t.Errorf("Expected username 'charlie', got '%s'", event.Username)
	}
	if event.SourceIP != "172.16.0.1" {
		t.Errorf("Expected IP '172.16.0.1', got '%s'", event.SourceIP)
	}
	if event.AuthType != AuthPassword {
		t.Errorf("Expected auth type 'password', got '%s'", event.AuthType)
	}
}

func TestParseDisconnected(t *testing.T) {
	line := `Jan 30 10:20:00 bastion sshd[12345]: Disconnected from user alice 192.168.1.100 port 54321`

	event := ParseLogLine(line)

	if event.EventType != EventDisconnected {
		t.Errorf("Expected EventDisconnected, got %v", event.EventType)
	}
	if event.Username != "alice" {
		t.Errorf("Expected username 'alice', got '%s'", event.Username)
	}
	if event.SourceIP != "192.168.1.100" {
		t.Errorf("Expected IP '192.168.1.100', got '%s'", event.SourceIP)
	}
	if event.Port != 54321 {
		t.Errorf("Expected port 54321, got %d", event.Port)
	}
}

func TestParseDisconnectedOldFormat(t *testing.T) {
	line := `Jan 30 10:20:00 bastion sshd[12345]: Disconnected from 192.168.1.100 port 54321`

	event := ParseLogLine(line)

	if event.EventType != EventDisconnected {
		t.Errorf("Expected EventDisconnected, got %v", event.EventType)
	}
	if event.SourceIP != "192.168.1.100" {
		t.Errorf("Expected IP '192.168.1.100', got '%s'", event.SourceIP)
	}
	if event.Port != 54321 {
		t.Errorf("Expected port 54321, got %d", event.Port)
	}
}

func TestParseSessionClosed(t *testing.T) {
	line := `Jan 30 10:20:00 bastion sshd[12345]: pam_unix(sshd:session): session closed for user alice`

	event := ParseLogLine(line)

	if event.EventType != EventSessionClosed {
		t.Errorf("Expected EventSessionClosed, got %v", event.EventType)
	}
	if event.Username != "alice" {
		t.Errorf("Expected username 'alice', got '%s'", event.Username)
	}
}

func TestParseFailedPassword(t *testing.T) {
	line := `Jan 30 10:15:23 bastion sshd[12345]: Failed password for alice from 192.168.1.100 port 54321 ssh2`

	event := ParseLogLine(line)

	if event.EventType != EventFailed {
		t.Errorf("Expected EventFailed, got %v", event.EventType)
	}
	if event.Username != "alice" {
		t.Errorf("Expected username 'alice', got '%s'", event.Username)
	}
	if event.AuthType != AuthPassword {
		t.Errorf("Expected auth type 'password', got '%s'", event.AuthType)
	}
}

func TestParseInvalidUser(t *testing.T) {
	line := `Jan 30 10:15:23 bastion sshd[12345]: Invalid user baduser from 192.168.1.100 port 54321`

	event := ParseLogLine(line)

	if event.EventType != EventInvalidUser {
		t.Errorf("Expected EventInvalidUser, got %v", event.EventType)
	}
	if event.Username != "baduser" {
		t.Errorf("Expected username 'baduser', got '%s'", event.Username)
	}
	if event.SourceIP != "192.168.1.100" {
		t.Errorf("Expected IP '192.168.1.100', got '%s'", event.SourceIP)
	}
}

func TestParseUnknownLine(t *testing.T) {
	line := `Jan 30 10:15:23 bastion sshd[12345]: Some other message we don't care about`

	event := ParseLogLine(line)

	if event.EventType != EventUnknown {
		t.Errorf("Expected EventUnknown, got %v", event.EventType)
	}
}

func TestParseJournaldFormat(t *testing.T) {
	line := `2024-01-30T10:15:23.123456+00:00 bastion sshd[12345]: Accepted password for alice from 192.168.1.100 port 54321 ssh2`

	event := ParseLogLine(line)

	if event.EventType != EventAccepted {
		t.Errorf("Expected EventAccepted, got %v", event.EventType)
	}
	if event.Username != "alice" {
		t.Errorf("Expected username 'alice', got '%s'", event.Username)
	}
}

func TestParseKeyboardInteractive(t *testing.T) {
	line := `Jan 30 10:15:23 bastion sshd[12345]: Accepted keyboard-interactive/pam for alice from 192.168.1.100 port 54321 ssh2`

	event := ParseLogLine(line)

	if event.EventType != EventAccepted {
		t.Errorf("Expected EventAccepted, got %v", event.EventType)
	}
	if event.Username != "alice" {
		t.Errorf("Expected username 'alice', got '%s'", event.Username)
	}
	if event.AuthType != AuthPassword {
		t.Errorf("Expected auth type 'password' (for kbd-interactive), got '%s'", event.AuthType)
	}
}
