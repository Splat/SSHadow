# SSH Connection Monitor (SSHadow) - Project Summary

## Overview

**SSHadow** is a security-focused SSH connection monitoring tool designed for bastion/jump hosts. It provides real-time visibility into SSH connections, tracking users, authentication methods, source IPs, and connection patterns through multiple operating modes.

## Quick Facts

- **Language**: Go 1.21+
- **Dependencies**: `golang.org/x/crypto/ssh`
- **License**: MIT
- **Purpose**: Security monitoring and auditing for SSH bastion hosts
- **Modes**: Proxy, Log Monitor, or Hybrid

## Operating Modes

### Proxy Mode
Intercepts SSH connections, extracts metadata, and forwards to sshd.
- Real-time connection tracking
- Captures: username, source IP, auth type, key fingerprint
- Password auth forwarding works
- Public key/cert auth: observable but not forwardable (see Future Enhancements)

### Log Monitor Mode
Passively monitors sshd logs for authentication events.
- No connection interception
- Full certificate details (key ID, serial, CA)
- Requires `LogLevel VERBOSE` in sshd

### Hybrid Mode
Runs both proxy and log monitor simultaneously.
- Best of both: real-time tracking + full cert details
- Same metrics endpoint consolidates data
- Recommended for maximum visibility

## Architecture

```
Proxy Mode:
Client --> SSHadow Proxy --> sshd --> Target
               |
               v
          Tracker --> Metrics

Log Monitor Mode:
Client --> sshd --> auth.log
                       |
                       v
               Log Parser --> Tracker --> Metrics

Hybrid Mode:
Client --> SSHadow Proxy --> sshd --> auth.log
               |                          |
               v                          v
          Tracker <---- Log Parser <------+
               |
               v
           Metrics (:9090)
```

## Key Features

### Authentication Tracking
- Password authentication
- Public key authentication (with SHA256 fingerprints)
- SSH certificate authentication (key ID, serial, CA - via log monitor)
- Real-time connection state

### Monitoring Capabilities
- Active connection counts per user
- Correlation of users to source IPs
- Authentication method breakdown
- Connection history and patterns
- Failed authentication attempts (log mode)
- Real-time dashboard with auto-refresh

### Export Formats
- **HTML Dashboard**: Human-readable, auto-refreshing interface
- **Prometheus Metrics**: For time-series monitoring
- **JSON API**: For programmatic access and integration

## Project Structure

```
SSHadow/
├── main.go                    # Entry point and CLI
├── go.mod / go.sum            # Go module files
├── proxy/
│   └── server.go             # SSH proxy implementation
├── monitor/
│   ├── tracker.go            # Connection tracking logic
│   ├── tracker_test.go       # Tracker unit tests
│   ├── logparser.go          # sshd log parsing
│   ├── logparser_test.go     # Parser unit tests
│   ├── watcher.go            # Log file/journald watching
│   └── metrics.go            # HTTP metrics server
├── README.md                 # User documentation
├── ARCHITECTURE.md           # Technical design details
├── SECURITY.md               # Security considerations
└── [deployment files]        # Docker, Makefile, etc.
```

## Quick Start

### 1. Build
```bash
go build -o SSHadow .
```

### 2. Generate Host Key (for proxy/hybrid mode)
```bash
ssh-keygen -t ed25519 -f ssh_host_key -N ""
```

### 3. Configure sshd (for log monitor/hybrid mode)
```bash
# Add to /etc/ssh/sshd_config:
LogLevel VERBOSE

# Restart sshd
systemctl restart sshd
```

### 4. Run

**Proxy Mode** (intercepts connections):
```bash
./SSHadow -mode proxy -hostkey ssh_host_key -listen :2222 -target localhost:22 -metrics :9090
```

**Log Monitor Mode** (passive monitoring):
```bash
./SSHadow -mode logmon -log /var/log/auth.log -metrics :9090
# or with journald:
./SSHadow -mode logmon -log journald -metrics :9090
```

**Hybrid Mode** (both):
```bash
./SSHadow -mode hybrid -hostkey ssh_host_key -listen :2222 -target localhost:22 -log /var/log/auth.log -metrics :9090
```

### 5. Test
```bash
# Connect through proxy
ssh -p 2222 user@localhost

# View dashboard
open http://localhost:9090
```

## Command-Line Options

| Flag | Default | Description |
|------|---------|-------------|
| `-mode` | `proxy` | Operating mode: `proxy`, `logmon`, or `hybrid` |
| `-listen` | `:2222` | SSH proxy listen address |
| `-target` | `localhost:22` | Target SSH server address |
| `-hostkey` | (required for proxy) | Path to SSH host private key |
| `-log` | `/var/log/auth.log` | Log source: file path or `journald` |
| `-metrics` | `:9090` | Metrics HTTP server address |

## What Each Mode Captures

| Data | Proxy | LogMon | Hybrid |
|------|-------|--------|--------|
| Source IP | ✓ | ✓ | ✓ |
| Username | ✓ | ✓ | ✓ |
| Auth type | ✓ | ✓ | ✓ |
| Key fingerprint | ✓ | ✓ | ✓ |
| Cert key ID | - | ✓ | ✓ |
| Cert serial | - | ✓ | ✓ |
| CA fingerprint | - | ✓ | ✓ |
| Real-time tracking | ✓ | ~100ms delay | ✓ |
| Password forwarding | ✓ | N/A | ✓ |

## Limitations

### Proxy Mode
1. **Public key/cert forwarding**: Cannot forward pubkey/cert authentication without the client's private key or SSH agent forwarding
2. **Password auth only**: Only password authentication can be forwarded to the target

### Log Monitor Mode
1. **Log-dependent**: Requires sshd to log authentication details
2. **Slight delay**: Based on log flush interval (~100ms)

### Both Modes
1. **Session content**: Does not inspect or log session data
2. **Single instance stats**: No cross-instance aggregation

## Future Enhancements

- [ ] **SSH Agent Forwarding (-A support)**: Enable pubkey/cert auth forwarding via client's SSH agent
- [ ] Session recording integration
- [ ] Geo-IP lookup for source addresses
- [ ] Database backend for historical data
- [ ] Built-in alerting
- [ ] TLS for metrics endpoint

## Security Considerations

See `SECURITY.md` for detailed security information.

**Proxy Mode**:
- Acts as MITM for SSH connections
- Sees passwords during authentication
- Cannot access private keys (unless agent forwarding added)

**Log Monitor Mode**:
- Read-only access to logs
- No credential exposure
- Minimal attack surface

## Example Metrics Output

### Prometheus Format
```
ssh_active_connections 5
ssh_user_active_connections{username="alice",source_ip="192.168.1.100",auth_type="cert",key_id="prod-key-1"} 2
ssh_user_total_connections{username="alice",source_ip="192.168.1.100",auth_type="cert",key_id="prod-key-1"} 47
```

### JSON Format
```json
{
  "alice:prod-key-1": {
    "Username": "alice",
    "SourceIP": "192.168.1.100",
    "AuthType": "cert",
    "KeyID": "prod-key-1",
    "Fingerprint": "SHA256:...",
    "CAFingerprint": "SHA256:...",
    "ActiveCount": 2,
    "TotalCount": 47
  }
}
```

## Use Cases

1. **Security Auditing**: Track all SSH access through a central bastion
2. **Compliance**: Maintain records for PCI DSS, SOC 2, HIPAA
3. **Anomaly Detection**: Identify unusual connection patterns
4. **Certificate Management**: Monitor SSH certificate usage
5. **Capacity Planning**: Understand connection patterns

## Why SSHadow?

- **Flexible**: Choose proxy, log monitoring, or both
- **Lightweight**: Minimal resource usage
- **Observable**: Prometheus-compatible metrics
- **Secure**: Log mode has no credential exposure
- **Simple**: Easy to deploy and understand

## License

MIT License - See LICENSE file for details.

---

Built with security in mind for security researchers and system administrators who need visibility into SSH access patterns.
