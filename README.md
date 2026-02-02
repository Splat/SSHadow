# SSH Connection Monitor (SSHadow)

![logo](SSHadpw_clear.png)

A security-focused SSH connection monitoring tool for bastion/jump hosts. Tracks SSH connections and correlates users, authentication methods (password/key/cert), source IPs, and active connection counts. 

Key components built:
- `proxy/server.go` - SSH proxy that extracts authentication details
- `monitor/tracker.go` - Connection tracking with concurrent-safe counters
- `monitor/logparser.go` - Parses sshd auth.log for cert details (key ID, serial, CA)
- `monitor/watcher.go` - Watches log files or journald
- `monitor/metrics.go` - HTTP server with dashboard, Prometheus, and JSON endpoints

## Features

- **Real-time monitoring** of SSH connections through a bastion host
- **Multi-auth support**: Tracks password, public key, and certificate authentication
- **Certificate awareness**: Extracts key IDs and principals from SSH certificates
- **Connection correlation**: Links users to source IPs and tracks connection counts
- **Multiple export formats**:
  - Web dashboard (HTML with auto-refresh)
  - Prometheus metrics endpoint
  - JSON API
- **Low overhead**: Minimal performance impact on SSH traffic
- **Concurrent-safe**: Proper locking for high-traffic environments

## Architecture

SSHadow operates as an SSH proxy that sits between clients and your actual SSH service:

```
Client → SSHadow (port 2222) → actual sshd (port 22)
              ↓
         Metrics Server (port 9090)
```

The proxy performs the SSH handshake to capture authentication metadata, then forwards the connection to the real SSH service.

## Quick Start

### 1. Generate a host key

```bash
ssh-keygen -t ed25519 -f ssh_host_key -N ""
```

### 2. Build and run

```bash
go build -o SSHadow .
./SSHadow -hostkey ssh_host_key -listen :2222 -target localhost:22 -metrics :9090
```

### 3. View dashboard

Open http://localhost:9090 in your browser to see active connections.

### 4. Test it

From another terminal:
```bash
ssh -p 2222 username@localhost
```

## Installation

```bash
git clone <repo>
cd SSHadow
go mod download
go build -o SSHadow .
```

## Usage

### Command-line options

```
-listen string
    Address to listen on for SSH connections (default ":2222")
    
-target string
    Address of the target SSH server (default "localhost:22")
    
-hostkey string
    Path to SSH host private key (required)
    
-metrics string
    Address for metrics HTTP server (default ":9090")
    
-mode string
    Operating mode: "proxy" or "metrics-only" (default "proxy")
```

### Running in production

**systemd service example:**

```ini
[Unit]
Description=SSH Connection Monitor
After=network.target

[Service]
Type=simple
User=SSHadow
ExecStart=/usr/local/bin/SSHadow -hostkey /etc/SSHadow/ssh_host_key -listen :2222 -target localhost:22 -metrics :9090
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

**Security considerations:**

1. Run as non-root user (use systemd socket activation for privileged ports)
2. Restrict file permissions on host key: `chmod 600 ssh_host_key`
3. Use firewall rules to limit access to metrics endpoint
4. Consider TLS termination for metrics endpoint in production

## Monitoring Endpoints

### Dashboard (/)
Human-readable HTML dashboard with auto-refresh:
- Active connection count
- **DoS Detection Views**: Aggregated by IP, user, and key
- Per-user statistics
- Auth method breakdown
- Visual alerts when thresholds exceeded

### Prometheus metrics (/metrics)

**DoS Detection Metrics** (pre-aggregated for easy alerting):
```
# Single-host attack detection - connections per source IP
ssh_connections_by_ip{source_ip="10.0.0.99"} 8

# Distributed attack detection - connections per user
ssh_connections_by_user{username="deploy-bot"} 6

# Compromised key detection - connections per key
ssh_connections_by_key{key_id="SHA256:STOLEN-KEY-xyz789"} 6
```

**Detailed Metrics**:
```
ssh_active_connections 15
ssh_user_active_connections{username="alice",source_ip="192.168.1.100",auth_type="cert",key_id="alice-laptop"} 2
ssh_user_total_connections{username="alice",source_ip="192.168.1.100",auth_type="cert",key_id="alice-laptop"} 47
```

### JSON export (/metrics/json)
```json
{
  "alice:prod-key-1": {
    "SourceIP": "192.168.1.100",
    "Username": "alice",
    "AuthType": "cert",
    "KeyID": "prod-key-1",
    "Principals": ["alice", "developers"],
    "ActiveCount": 2,
    "TotalCount": 15,
    "FirstSeen": "2026-01-30T10:00:00Z",
    "LastSeen": "2026-01-30T14:30:00Z"
  }
}
```

## Deployment Strategies

### 1. Transparent Proxy (Recommended)

Move your existing sshd to a different port and run SSHadow on port 22:

```bash
# In /etc/ssh/sshd_config
Port 2222

# Restart sshd
systemctl restart sshd

# Run SSHadow on port 22
./SSHadow -hostkey /etc/SSHadow/host_key -listen :22 -target localhost:2222
```

**Pros**: No client configuration changes
**Cons**: Requires modifying sshd configuration

### 2. Alternative Port

Run SSHadow on a different port:

```bash
./SSHadow -hostkey host_key -listen :2222 -target localhost:22
```

Clients connect to port 2222 instead of 22.

**Pros**: No changes to existing sshd
**Cons**: Clients need to specify port

### 3. Metrics-Only Mode

If you want to monitor connections through other means (e.g., parsing auth logs), you can run just the metrics server:

```bash
./SSHadow -mode metrics-only -metrics :9090
```

Then feed connection data to the tracker via your own integration.

## Authentication Method Detection

### Password Authentication
Tracked by username + source IP

### Public Key Authentication
Tracked by username + key fingerprint (SHA256)

### Certificate Authentication
Tracked by username + certificate key ID
- Extracts principals from certificate
- Shows cert key ID in dashboard
- Ideal for tracking which cert authorized the connection

## Testing

Run unit tests:

```bash
go test ./...
```

Run with coverage:

```bash
go test -cover ./...
```

### Integration Tests

Run integration tests with verbose output to see sample metrics for all authentication methods:

```bash
# See all auth methods with sample output
go test -v -run TestIntegrationAllAuthMethods ./monitor/

# See password auth output only
go test -v -run TestIntegrationPasswordAuth ./monitor/

# See public key auth output only
go test -v -run TestIntegrationPublicKeyAuth ./monitor/

# See certificate auth output only
go test -v -run TestIntegrationCertAuth ./monitor/

# See mixed auth with connect/disconnect simulation
go test -v -run TestIntegrationMixedAuthWithDisconnects ./monitor/

# See full flow from log parsing to output
go test -v -run TestIntegrationLogParsingToOutput ./monitor/
```

### Live Demo (Opens Browser)

Run an interactive demo that starts a real metrics server and opens your browser:

```bash
# Basic demo with pre-populated DoS scenario data
go test -v -tags=livedemo -run TestLiveDemo ./monitor/

# Attack simulation - watch the dashboard update in real-time
go test -v -tags=livedemo -run TestLiveDemoSimulateAttack ./monitor/
```

The live demo will:
- Start a metrics server on http://localhost:9099
- Open your browser automatically
- Show the dashboard with DoS detection views
- The attack simulation adds connections in real-time so you can watch alerts appear

Press `Ctrl+C` to stop the demo.

## Sample Output by Authentication Method

### Password Authentication

**JSON Output:**
```json
{
  "charlie:172.16.0.1": {
    "SourceIP": "172.16.0.1",
    "Username": "charlie",
    "AuthType": "password",
    "KeyType": "",
    "KeyID": "",
    "Fingerprint": "",
    "Principals": null,
    "CAFingerprint": "",
    "ActiveCount": 1,
    "TotalCount": 1,
    "FirstSeen": "2026-01-30T10:17:30Z",
    "LastSeen": "2026-01-30T10:17:30Z"
  }
}
```

**Prometheus Output:**
```
ssh_user_active_connections{username="charlie",source_ip="172.16.0.1",auth_type="password",key_id=""} 1
ssh_user_total_connections{username="charlie",source_ip="172.16.0.1",auth_type="password",key_id=""} 1
```

### Public Key Authentication

**JSON Output:**
```json
{
  "bob:SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8": {
    "SourceIP": "10.0.0.50",
    "Username": "bob",
    "AuthType": "publickey",
    "KeyType": "RSA",
    "KeyID": "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8",
    "Fingerprint": "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8",
    "Principals": null,
    "CAFingerprint": "",
    "ActiveCount": 1,
    "TotalCount": 1,
    "FirstSeen": "2026-01-30T10:16:00Z",
    "LastSeen": "2026-01-30T10:16:00Z"
  }
}
```

**Prometheus Output:**
```
ssh_user_active_connections{username="bob",source_ip="10.0.0.50",auth_type="publickey",key_id="SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8"} 1
ssh_user_total_connections{username="bob",source_ip="10.0.0.50",auth_type="publickey",key_id="SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8"} 1
```

### Certificate Authentication

**JSON Output:**
```json
{
  "alice:alice-laptop": {
    "SourceIP": "192.168.1.100",
    "Username": "alice",
    "AuthType": "cert",
    "KeyType": "ED25519",
    "KeyID": "alice-laptop",
    "Fingerprint": "SHA256:abc123def456ghi789jkl012mno345pqr678stu901vwx",
    "Principals": null,
    "CAFingerprint": "SHA256:CORPORATE-CA-2024-abc123def456ghi789jkl012",
    "ActiveCount": 2,
    "TotalCount": 2,
    "FirstSeen": "2026-01-30T10:15:23Z",
    "LastSeen": "2026-01-30T10:45:00Z"
  }
}
```

**Prometheus Output:**
```
ssh_user_active_connections{username="alice",source_ip="192.168.1.100",auth_type="cert",key_id="alice-laptop"} 2
ssh_user_total_connections{username="alice",source_ip="192.168.1.100",auth_type="cert",key_id="alice-laptop"} 2
```

### Dashboard View (All Auth Types)

```
╔══════════════════════════════════════════════════════════════════════════════════╗
║                           SSH CONNECTION MONITOR                                 ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║ Active Connections: 7                                                            ║
╠══════════════════════════════════════════════════════════════════════════════════╣
║ USER       │ SOURCE IP      │ AUTH      │ KEY ID/FINGERPRINT        │ ACT │ TOT  ║
╠════════════╪════════════════╪═══════════╪═══════════════════════════╪═════╪══════╣
║ alice      │ 192.168.1.100  │ cert      │ alice-laptop              │   2 │    2 ║
║ bob        │ 10.0.0.50      │ publickey │ SHA256:nThbg6kXUpJWGl...  │   1 │    1 ║
║ eve        │ 192.168.50.10  │ publickey │ SHA256:uH7kzJxNShdLrq...  │   1 │    1 ║
║ charlie    │ 172.16.0.1     │ password  │ -                         │   1 │    1 ║
║ david      │ 10.0.0.25      │ password  │ -                         │   1 │    1 ║
║ frank      │ 10.100.200.5   │ cert      │ prod-deploy-key           │   1 │    1 ║
╚══════════════════════════════════════════════════════════════════════════════════╝
```

## Integration Examples

### Prometheus

Add to `prometheus.yml`:
```yaml
scrape_configs:
  - job_name: 'SSHadow'
    static_configs:
      - targets: ['bastion.example.com:9090']
```

### Alerting

**DoS Detection Alerts** (using pre-aggregated metrics):

```yaml
groups:
  - name: ssh_dos_detection
    rules:
      # Scenario 1: Single IP opening too many connections
      - alert: SSHSingleHostDoS
        expr: ssh_connections_by_ip > 10
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Potential DoS: {{ $labels.source_ip }} has {{ $value }} connections"
          description: "Single host opening excessive SSH connections - possible DoS attack"

      # Scenario 2: Same user from many IPs (distributed attack)
      - alert: SSHDistributedAttackByUser
        expr: ssh_connections_by_user > 10
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Potential distributed attack: user '{{ $labels.username }}' has {{ $value }} connections"
          description: "Same username connecting from multiple sources - possible credential compromise"

      # Scenario 3: Same key used from many IPs (compromised key)
      - alert: SSHCompromisedKey
        expr: ssh_connections_by_key > 5
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Potential compromised key: {{ $labels.key_id }} used {{ $value }} times"
          description: "Same SSH key connecting from multiple sources - possible key theft"

      # General high connection warning
      - alert: HighSSHConnections
        expr: ssh_active_connections > 50
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High total SSH connections: {{ $value }}"
```

### Log Analysis

Export JSON and feed to your SIEM:
```bash
curl http://localhost:9090/metrics/json | jq '.' | logger -t SSHadow
```

## Limitations and Considerations

1. **Password forwarding**: The proxy captures passwords to forward them. In high-security environments, consider key/cert-only auth.
2. **Host key verification**: The proxy presents its own host key. Clients will need to accept this key.
3. **Connection multiplexing**: SSH ControlMaster creates multiple logical sessions over one TCP connection. The tracker counts TCP connections.
4. **Performance**: Adds minimal latency (typically <1ms) but all SSH traffic flows through the proxy.
5. **High availability**: For HA setups, run multiple instances behind a load balancer. Connection stats won't be aggregated across instances.

## Future Enhancements

- [ ] Session recording integration
- [ ] Geo-IP lookup for source addresses
- [ ] Connection time tracking and idle detection
- [ ] Configurable alerting thresholds
- [ ] Database backend for historical data
- [ ] Integration with PAM/LDAP for user enrichment
- [ ] TLS for metrics endpoint

## Security Notes

This tool is designed for security monitoring but has some important considerations:

- **Credential exposure**: The proxy sees passwords during authentication. Ensure the host running SSHadow is properly secured.
- **Certificate validation**: Currently uses `InsecureIgnoreHostKey()` for target connections. In production, implement proper host key validation.
- **Metrics endpoint**: Contains sensitive information (usernames, IPs). Restrict access appropriately.

## License

MIT

## Contributing

Contributions welcome! Please:
1. Add unit tests for new features
2. Follow Go best practices
3. Update documentation
4. Keep it simple and focused

## Related Work

- NDPeekr: Network Discovery Protocol monitor (see 2600 article)
- OpenSSH logging and auditing
- bastillion/ssh-multiplexer projects
