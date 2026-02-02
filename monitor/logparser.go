package monitor

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// LogEvent represents a parsed sshd log entry
type LogEvent struct {
	Timestamp   time.Time
	Hostname    string
	PID         int
	EventType   EventType
	Username    string
	SourceIP    string
	Port        int
	AuthType    AuthType
	KeyType     string
	Fingerprint string
	CertID      string
	CertSerial  uint64
	CAType      string
	CAFingerprint string
	RawLine     string
}

type EventType int

const (
	EventUnknown EventType = iota
	EventAccepted
	EventFailed
	EventDisconnected
	EventSessionOpened
	EventSessionClosed
	EventInvalidUser
)

// Common sshd log patterns
var (
	// Accepted publickey for alice from 192.168.1.100 port 54321 ssh2: ED25519-CERT SHA256:abc123 ID "key-id" serial 0 CA ED25519 SHA256:def456
	acceptedCertPattern = regexp.MustCompile(
		`Accepted\s+publickey\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)\s+ssh2:\s+(\S+)-CERT\s+(\S+)\s+ID\s+"([^"]+)"\s+serial\s+(\d+)\s+CA\s+(\S+)\s+(\S+)`,
	)

	// Accepted publickey for bob from 10.0.0.50 port 12345 ssh2: RSA SHA256:xyz789
	acceptedPubkeyPattern = regexp.MustCompile(
		`Accepted\s+publickey\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)\s+ssh2:\s+(\S+)\s+(\S+)`,
	)

	// Accepted password for charlie from 172.16.0.1 port 22222 ssh2
	acceptedPasswordPattern = regexp.MustCompile(
		`Accepted\s+password\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)`,
	)

	// Accepted keyboard-interactive/pam for user from IP port PORT ssh2
	acceptedKbdIntPattern = regexp.MustCompile(
		`Accepted\s+keyboard-interactive/\S+\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)`,
	)

	// Disconnected from user alice 192.168.1.100 port 54321
	disconnectedPattern = regexp.MustCompile(
		`Disconnected\s+from\s+user\s+(\S+)\s+(\S+)\s+port\s+(\d+)`,
	)

	// Disconnected from 192.168.1.100 port 54321 (older format)
	disconnectedOldPattern = regexp.MustCompile(
		`Disconnected\s+from\s+(\S+)\s+port\s+(\d+)`,
	)

	// pam_unix(sshd:session): session opened for user alice
	sessionOpenedPattern = regexp.MustCompile(
		`pam_unix\(sshd:session\):\s+session\s+opened\s+for\s+user\s+(\S+)`,
	)

	// pam_unix(sshd:session): session closed for user alice
	sessionClosedPattern = regexp.MustCompile(
		`pam_unix\(sshd:session\):\s+session\s+closed\s+for\s+user\s+(\S+)`,
	)

	// Failed password for alice from 192.168.1.100 port 54321 ssh2
	failedPasswordPattern = regexp.MustCompile(
		`Failed\s+password\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)`,
	)

	// Failed publickey for alice from 192.168.1.100 port 54321 ssh2
	failedPubkeyPattern = regexp.MustCompile(
		`Failed\s+publickey\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)`,
	)

	// Invalid user baduser from 192.168.1.100 port 54321
	invalidUserPattern = regexp.MustCompile(
		`Invalid\s+user\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+)`,
	)

	// Syslog prefix: Jan 30 10:15:23 hostname sshd[12345]:
	syslogPrefixPattern = regexp.MustCompile(
		`^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+sshd\[(\d+)\]:\s*(.*)`,
	)

	// Systemd journal prefix: 2024-01-30T10:15:23.123456+00:00 hostname sshd[12345]:
	journaldPrefixPattern = regexp.MustCompile(
		`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^\s]*)\s+(\S+)\s+sshd\[(\d+)\]:\s*(.*)`,
	)
)

// ParseLogLine parses a single sshd log line
func ParseLogLine(line string) *LogEvent {
	event := &LogEvent{
		RawLine:   line,
		EventType: EventUnknown,
	}

	// Extract syslog prefix
	var message string
	if matches := syslogPrefixPattern.FindStringSubmatch(line); matches != nil {
		event.Timestamp = parseSyslogTime(matches[1])
		event.Hostname = matches[2]
		event.PID, _ = strconv.Atoi(matches[3])
		message = matches[4]
	} else if matches := journaldPrefixPattern.FindStringSubmatch(line); matches != nil {
		event.Timestamp, _ = time.Parse(time.RFC3339, matches[1])
		event.Hostname = matches[2]
		event.PID, _ = strconv.Atoi(matches[3])
		message = matches[4]
	} else {
		// Try parsing without prefix (for testing or custom formats)
		message = line
		event.Timestamp = time.Now()
	}

	// Try to match against known patterns
	if matches := acceptedCertPattern.FindStringSubmatch(message); matches != nil {
		event.EventType = EventAccepted
		event.Username = matches[1]
		event.SourceIP = matches[2]
		event.Port, _ = strconv.Atoi(matches[3])
		event.AuthType = AuthCert
		event.KeyType = matches[4]
		event.Fingerprint = matches[5]
		event.CertID = matches[6]
		event.CertSerial, _ = strconv.ParseUint(matches[7], 10, 64)
		event.CAType = matches[8]
		event.CAFingerprint = matches[9]
		return event
	}

	if matches := acceptedPubkeyPattern.FindStringSubmatch(message); matches != nil {
		// Make sure this isn't a cert (already handled above)
		if !strings.Contains(message, "-CERT") {
			event.EventType = EventAccepted
			event.Username = matches[1]
			event.SourceIP = matches[2]
			event.Port, _ = strconv.Atoi(matches[3])
			event.AuthType = AuthPublicKey
			event.KeyType = matches[4]
			event.Fingerprint = matches[5]
			return event
		}
	}

	if matches := acceptedPasswordPattern.FindStringSubmatch(message); matches != nil {
		event.EventType = EventAccepted
		event.Username = matches[1]
		event.SourceIP = matches[2]
		event.Port, _ = strconv.Atoi(matches[3])
		event.AuthType = AuthPassword
		return event
	}

	if matches := acceptedKbdIntPattern.FindStringSubmatch(message); matches != nil {
		event.EventType = EventAccepted
		event.Username = matches[1]
		event.SourceIP = matches[2]
		event.Port, _ = strconv.Atoi(matches[3])
		event.AuthType = AuthPassword // Treat keyboard-interactive as password-like
		return event
	}

	if matches := disconnectedPattern.FindStringSubmatch(message); matches != nil {
		event.EventType = EventDisconnected
		event.Username = matches[1]
		event.SourceIP = matches[2]
		event.Port, _ = strconv.Atoi(matches[3])
		return event
	}

	if matches := disconnectedOldPattern.FindStringSubmatch(message); matches != nil {
		event.EventType = EventDisconnected
		event.SourceIP = matches[1]
		event.Port, _ = strconv.Atoi(matches[2])
		return event
	}

	if matches := sessionOpenedPattern.FindStringSubmatch(message); matches != nil {
		event.EventType = EventSessionOpened
		event.Username = matches[1]
		return event
	}

	if matches := sessionClosedPattern.FindStringSubmatch(message); matches != nil {
		event.EventType = EventSessionClosed
		event.Username = matches[1]
		return event
	}

	if matches := failedPasswordPattern.FindStringSubmatch(message); matches != nil {
		event.EventType = EventFailed
		event.Username = matches[1]
		event.SourceIP = matches[2]
		event.Port, _ = strconv.Atoi(matches[3])
		event.AuthType = AuthPassword
		return event
	}

	if matches := failedPubkeyPattern.FindStringSubmatch(message); matches != nil {
		event.EventType = EventFailed
		event.Username = matches[1]
		event.SourceIP = matches[2]
		event.Port, _ = strconv.Atoi(matches[3])
		event.AuthType = AuthPublicKey
		return event
	}

	if matches := invalidUserPattern.FindStringSubmatch(message); matches != nil {
		event.EventType = EventInvalidUser
		event.Username = matches[1]
		event.SourceIP = matches[2]
		event.Port, _ = strconv.Atoi(matches[3])
		return event
	}

	return event
}

// parseSyslogTime parses syslog timestamp format (assumes current year)
func parseSyslogTime(s string) time.Time {
	// Syslog format: "Jan 30 10:15:23"
	now := time.Now()
	t, err := time.Parse("Jan 2 15:04:05", s)
	if err != nil {
		return now
	}
	// Add current year
	return time.Date(now.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, time.Local)
}
