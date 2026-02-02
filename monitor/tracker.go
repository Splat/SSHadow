package monitor

import (
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// AuthType represents the authentication method used
type AuthType string

const (
	AuthPassword AuthType = "password"
	AuthPublicKey AuthType = "publickey"
	AuthCert     AuthType = "cert"
	AuthNone     AuthType = "none"
)

// ConnectionInfo holds metadata about an SSH connection
type ConnectionInfo struct {
	SourceIP      string
	Port          int
	Username      string
	AuthType      AuthType
	KeyType       string   // e.g., "ED25519", "RSA"
	KeyID         string   // For certs, this is the key ID; for pubkeys, this is the fingerprint
	Fingerprint   string   // Key fingerprint (SHA256:...)
	Principals    []string // For certs
	CertSerial    uint64   // Certificate serial number
	CAFingerprint string   // CA fingerprint for certs
	ConnectedAt   time.Time
	LastSeen      time.Time
	PID           int // sshd process ID
}

// UserStats aggregates connection statistics per user/key
type UserStats struct {
	SourceIP      string
	Username      string
	AuthType      AuthType
	KeyType       string
	KeyID         string
	Fingerprint   string
	Principals    []string
	CAFingerprint string
	ActiveCount   int
	TotalCount    int64
	FirstSeen     time.Time
	LastSeen      time.Time
}

// Tracker monitors active SSH connections
type Tracker struct {
	mu          sync.RWMutex
	connections map[string]*ConnectionInfo // key: connection ID
	stats       map[string]*UserStats      // key: user identifier (username:keyid or username:ip)
}

// NewTracker creates a new connection tracker
func NewTracker() *Tracker {
	return &Tracker{
		connections: make(map[string]*ConnectionInfo),
		stats:       make(map[string]*UserStats),
	}
}

// AddConnectionFromLog registers a new SSH connection from a parsed log event
func (t *Tracker) AddConnectionFromLog(connID string, event *LogEvent) {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	if !event.Timestamp.IsZero() {
		now = event.Timestamp
	}

	// Store connection info
	info := &ConnectionInfo{
		SourceIP:      event.SourceIP,
		Port:          event.Port,
		Username:      event.Username,
		AuthType:      event.AuthType,
		KeyType:       event.KeyType,
		KeyID:         event.CertID,
		Fingerprint:   event.Fingerprint,
		CertSerial:    event.CertSerial,
		CAFingerprint: event.CAFingerprint,
		ConnectedAt:   now,
		LastSeen:      now,
		PID:           event.PID,
	}
	t.connections[connID] = info

	// Use fingerprint as keyID if no cert ID
	keyID := event.CertID
	if keyID == "" {
		keyID = event.Fingerprint
	}

	// Update stats
	statsKey := t.getStatsKey(event.Username, keyID, event.SourceIP)
	if stats, exists := t.stats[statsKey]; exists {
		stats.ActiveCount++
		stats.TotalCount++
		stats.LastSeen = now
	} else {
		t.stats[statsKey] = &UserStats{
			SourceIP:      event.SourceIP,
			Username:      event.Username,
			AuthType:      event.AuthType,
			KeyType:       event.KeyType,
			KeyID:         keyID,
			Fingerprint:   event.Fingerprint,
			CAFingerprint: event.CAFingerprint,
			ActiveCount:   1,
			TotalCount:    1,
			FirstSeen:     now,
			LastSeen:      now,
		}
	}
}

// AddConnectionFromProxy registers a new SSH connection from the proxy
func (t *Tracker) AddConnectionFromProxy(connID, sourceIP, username string, authType AuthType, pubKey ssh.PublicKey, fingerprint string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()

	// Extract certificate details if available
	var keyID string
	var keyType string
	var principals []string
	var certSerial uint64
	var caFingerprint string

	if pubKey != nil {
		if cert, ok := pubKey.(*ssh.Certificate); ok {
			keyID = cert.KeyId
			principals = cert.ValidPrincipals
			certSerial = cert.Serial
			keyType = cert.Key.Type()
			// Get CA fingerprint
			if cert.SignatureKey != nil {
				caFingerprint = ssh.FingerprintSHA256(cert.SignatureKey)
			}
			authType = AuthCert
		} else {
			keyType = pubKey.Type()
			authType = AuthPublicKey
		}
	}

	// Use fingerprint as keyID if no cert key ID
	if keyID == "" {
		keyID = fingerprint
	}

	info := &ConnectionInfo{
		SourceIP:      sourceIP,
		Username:      username,
		AuthType:      authType,
		KeyType:       keyType,
		KeyID:         keyID,
		Fingerprint:   fingerprint,
		Principals:    principals,
		CertSerial:    certSerial,
		CAFingerprint: caFingerprint,
		ConnectedAt:   now,
		LastSeen:      now,
	}
	t.connections[connID] = info

	// Update stats
	statsKey := t.getStatsKey(username, keyID, sourceIP)
	if stats, exists := t.stats[statsKey]; exists {
		stats.ActiveCount++
		stats.TotalCount++
		stats.LastSeen = now
		// Update with cert details if available
		if keyID != "" && stats.KeyID == "" {
			stats.KeyID = keyID
		}
		if len(principals) > 0 && len(stats.Principals) == 0 {
			stats.Principals = principals
		}
		if caFingerprint != "" && stats.CAFingerprint == "" {
			stats.CAFingerprint = caFingerprint
		}
	} else {
		t.stats[statsKey] = &UserStats{
			SourceIP:      sourceIP,
			Username:      username,
			AuthType:      authType,
			KeyType:       keyType,
			KeyID:         keyID,
			Fingerprint:   fingerprint,
			Principals:    principals,
			CAFingerprint: caFingerprint,
			ActiveCount:   1,
			TotalCount:    1,
			FirstSeen:     now,
			LastSeen:      now,
		}
	}
}

// RemoveConnection unregisters an SSH connection
func (t *Tracker) RemoveConnection(connID string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	info, exists := t.connections[connID]
	if !exists {
		return
	}

	// Update stats
	keyID := info.KeyID
	if keyID == "" {
		keyID = info.Fingerprint
	}
	statsKey := t.getStatsKey(info.Username, keyID, info.SourceIP)
	if stats, exists := t.stats[statsKey]; exists {
		stats.ActiveCount--
		if stats.ActiveCount < 0 {
			stats.ActiveCount = 0
		}
	}

	delete(t.connections, connID)
}

// RemoveConnectionByUser finds and removes a connection by user/IP/port
// Used when processing disconnect events from logs
func (t *Tracker) RemoveConnectionByUser(username, sourceIP string, port int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Find matching connection
	var matchedID string
	var matchedInfo *ConnectionInfo

	for id, info := range t.connections {
		if info.Username == username && info.SourceIP == sourceIP {
			// If port is specified, match it; otherwise match any
			if port == 0 || info.Port == port {
				matchedID = id
				matchedInfo = info
				break
			}
		}
	}

	if matchedInfo == nil {
		// No matching connection found - might have already been removed
		// or the log format didn't include username
		if username == "" && sourceIP != "" {
			// Try matching by IP only (for older disconnect format)
			for id, info := range t.connections {
				if info.SourceIP == sourceIP && (port == 0 || info.Port == port) {
					matchedID = id
					matchedInfo = info
					break
				}
			}
		}
		if matchedInfo == nil {
			return
		}
	}

	// Update stats
	keyID := matchedInfo.KeyID
	if keyID == "" {
		keyID = matchedInfo.Fingerprint
	}
	statsKey := t.getStatsKey(matchedInfo.Username, keyID, matchedInfo.SourceIP)
	if stats, exists := t.stats[statsKey]; exists {
		stats.ActiveCount--
		if stats.ActiveCount < 0 {
			stats.ActiveCount = 0
		}
	}

	delete(t.connections, matchedID)
}

// UpdateActivity updates the last seen time for a connection
func (t *Tracker) UpdateActivity(connID string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if info, exists := t.connections[connID]; exists {
		info.LastSeen = time.Now()
	}
}

// GetStats returns a snapshot of all user statistics
func (t *Tracker) GetStats() map[string]*UserStats {
	t.mu.RLock()
	defer t.mu.RUnlock()

	// Create a copy to avoid race conditions
	result := make(map[string]*UserStats, len(t.stats))
	for k, v := range t.stats {
		statsCopy := *v
		statsCopy.Principals = append([]string(nil), v.Principals...)
		result[k] = &statsCopy
	}
	return result
}

// GetActiveConnections returns the number of currently active connections
func (t *Tracker) GetActiveConnections() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.connections)
}

// getStatsKey generates a unique key for stats tracking
// Uses username:keyid for cert/pubkey auth, username:sourceip for password
func (t *Tracker) getStatsKey(username, keyID, sourceIP string) string {
	if keyID != "" {
		return fmt.Sprintf("%s:%s", username, keyID)
	}
	return fmt.Sprintf("%s:%s", username, sourceIP)
}

