# Security Considerations for SSH Connection Monitor

## Overview

SSHadow provides SSH connection monitoring through three modes, each with different security characteristics:

| Mode | Security Profile |
|------|------------------|
| **Proxy** | MITM position, sees passwords, real-time |
| **Log Monitor** | Read-only, no credentials, passive |
| **Hybrid** | Combines both profiles |

## Threat Model

### What SSHadow protects against:
- **Unauthorized access monitoring**: Track who is connecting and from where
- **Anomaly detection**: Identify unusual connection patterns
- **Audit trail**: Maintain records of authentication attempts
- **Certificate tracking**: Monitor which SSH certificates are being used

### What SSHadow does NOT protect against:
- **Compromised credentials**: If an attacker has valid credentials, SSHadow logs but doesn't block
- **Lateral movement**: Once authenticated, session contents aren't monitored
- **Zero-day exploits**: In the SSH protocol or implementation

## Mode-Specific Security Analysis

### Proxy Mode Security

**Risk Level**: MEDIUM-HIGH

The proxy terminates SSH connections, placing it in a man-in-the-middle position.

**What proxy mode sees**:
- Passwords (temporarily cached during auth)
- Public keys and certificates (but not private keys)
- All SSH channel data (but doesn't inspect it)
- Connection metadata (user, IP, timing)

**What proxy mode CANNOT see**:
- Private keys (never transmitted)
- SSH agent contents (unless agent forwarding is implemented)

**Risks**:
1. **Password exposure**: Passwords are visible during authentication
2. **Host key confusion**: Clients see SSHadow's host key, not sshd's
3. **Compromise impact**: If SSHadow is compromised, all proxied connections are at risk

**Mitigations**:
- Run SSHadow on a hardened, dedicated system
- Use certificate-based authentication where possible
- Implement strict access controls
- Monitor SSHadow host for compromise
- Don't log passwords (current implementation doesn't persist them)

### Log Monitor Mode Security

**Risk Level**: LOW

Log monitor mode only reads authentication logs—it never sees credentials.

**What log mode sees**:
- Usernames and source IPs
- Authentication methods and results
- Certificate details (key ID, CA, serial)
- Connection timing

**What log mode CANNOT see**:
- Passwords (never logged by sshd)
- Private keys
- Session contents

**Risks**:
1. **Metadata exposure**: Connection patterns are visible
2. **Log tampering**: If attacker has root, logs could be modified

**Mitigations**:
- Run with minimal privileges (read-only log access)
- Forward logs to remote syslog
- Implement log integrity monitoring

### Hybrid Mode Security

Combines the security profiles of both modes. Use the stricter mitigations from proxy mode.

## Security Comparison

| Aspect | Proxy Mode | Log Mode |
|--------|------------|----------|
| Credential exposure | Passwords visible | None |
| Private key access | None | None |
| MITM capability | Yes | No |
| Attack surface | Full SSH stack | Log parsing only |
| Session hijacking risk | If compromised | None |
| Required privileges | Network + host key | Log read access |

## Deployment Security Best Practices

### 1. System Hardening

```bash
# Create dedicated user
useradd -r -s /sbin/nologin -d /nonexistent sshadow

# Proxy mode: needs host key access
chmod 600 /etc/sshadow/ssh_host_key
chown sshadow:sshadow /etc/sshadow/ssh_host_key

# Log mode: needs log read access
usermod -a -G adm sshadow  # or systemd-journal for journald
```

**systemd hardening**:
```ini
[Service]
User=sshadow
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
# For log mode:
ReadOnlyPaths=/var/log
# For proxy mode:
ReadWritePaths=/etc/sshadow
```

### 2. Network Segmentation

```
Internet → [Firewall] → Bastion (SSHadow + sshd)
                              │
                              ├── Internal Network
                              │
                              └── Monitoring Network
                                   └── Prometheus/Grafana
```

### 3. Metrics Endpoint Protection

The metrics endpoint exposes connection metadata.

```bash
# Restrict to monitoring network
iptables -A INPUT -p tcp --dport 9090 -s 10.1.0.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 9090 -j DROP
```

**Exposed data**:
- Usernames
- Source IPs
- Connection patterns
- Certificate key IDs
- Authentication methods

### 4. Host Key Management (Proxy Mode)

**Issue**: Clients see SSHadow's host key, not the target sshd's key.

**Mitigations**:
- Distribute SSHadow's host key fingerprint securely
- Document the expected key change for users
- Consider using the same host key as sshd (if on same host)
- Use SSH certificate authorities

### 5. Logging and Auditing

```bash
# Audit SSHadow execution
auditctl -w /usr/local/bin/SSHadow -p x -k sshadow-exec

# Forward logs remotely
./SSHadow 2>&1 | logger -t sshadow -p auth.info
```

## Compliance Considerations

### PCI DSS
- ✓ Access logging and monitoring
- ✓ Audit trails
- ⚠ Credential exposure (proxy mode) - document and mitigate
- ⚠ Metrics authentication - must implement

### SOC 2
- ✓ Monitoring and logging
- ✓ Incident response capability
- ⚠ Access controls for metrics endpoint

### HIPAA
- ✓ Audit controls
- ✓ Access logging
- ⚠ Minimum necessary - consider log mode for less exposure

## Incident Response

### If SSHadow host is compromised

**Proxy mode implications**:
- All proxied passwords potentially exposed
- Force password changes for all users
- Revoke and reissue SSH certificates
- Review connection logs for unauthorized access

**Log mode implications**:
- Connection metadata exposed (same as log access)
- No credential exposure
- Review for unauthorized access patterns

### Recovery Steps

1. **Immediate**: Isolate the host
2. **Assess**: Determine which mode was running
3. **Credential rotation**: Required for proxy mode
4. **Rebuild**: From known-good image
5. **Rekey**: Generate new host keys
6. **Monitor**: Enhanced monitoring post-incident

## Security Checklist

### Proxy Mode Deployment
- [ ] Dedicated, hardened host
- [ ] Host key with restricted permissions (0600)
- [ ] Network segmentation
- [ ] Metrics endpoint restricted
- [ ] Log forwarding enabled
- [ ] Monitoring of SSHadow process
- [ ] Incident response plan for credential exposure

### Log Monitor Mode Deployment
- [ ] Minimal privilege user
- [ ] Read-only log access
- [ ] Metrics endpoint restricted
- [ ] sshd LogLevel VERBOSE configured
- [ ] Remote log forwarding
- [ ] Log integrity monitoring

### Hybrid Mode Deployment
- [ ] All items from both checklists above

## Future Security Enhancements

### SSH Agent Forwarding
When implemented, will add considerations:
- Agent socket exposure while session active
- Document `-A` flag implications
- Consider `ssh-add -c` for confirmation
- Clean up agent on session close

## Responsible Disclosure

If you discover a security vulnerability:

1. Do NOT open a public GitHub issue
2. Email: [your-security-email]
3. Include: description, reproduction steps, impact assessment
4. We will acknowledge within 48 hours

## Conclusion

**Choose your mode based on security requirements**:

- **Maximum security, less visibility**: Log monitor mode
- **Maximum visibility, more risk**: Proxy mode
- **Balanced approach**: Hybrid mode with proxy hardening

For environments where credential exposure is unacceptable, use log monitor mode exclusively. The proxy mode should only be deployed on hardened, trusted infrastructure with appropriate access controls and monitoring.
