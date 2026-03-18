# Interpretation Guide

Reference for interpreting VPS security audit results. For each phase, this guide describes
what-good-looks-like, severity classifications, common false positives, and remediation patterns.

---

## Table of Contents

1. [System Snapshot](#1-system-snapshot)
2. [Network Exposure](#2-network-exposure)
3. [SSH Hardening](#3-ssh-hardening)
4. [Fail2ban](#4-fail2ban)
5. [Rootkit Scan](#5-rootkit-scan-rkhunter)
6. [Lynis Audit](#6-lynis-audit)
7. [Package Updates](#7-package-updates)
8. [Users & Auth](#8-users--auth)

---

## 1. System Snapshot

**What to check:**

- **OS version**: Is it still receiving security updates? Ubuntu LTS releases get 5 years of
  standard support. If the version is EOL, that's a CRITICAL finding.
  - Ubuntu 24.04 LTS: supported until Apr 2029
  - Ubuntu 22.04 LTS: supported until Apr 2027
  - Ubuntu 20.04 LTS: supported until Apr 2025 (standard), Apr 2030 (ESM)
  - Debian 12 (bookworm): supported until ~Jun 2026
- **Uptime**: Very high uptime (>90 days) with pending kernel updates means the server hasn't
  rebooted to activate patches. Flag as MEDIUM.
- **Disk usage**: If root is >90% full, the server may not be able to write logs or create
  temp files needed by security tools. Flag as HIGH.
- **Recent logins**: Check source IPs. Flag any login from an unexpected IP or by an unexpected
  user as HIGH.

---

## 2. Network Exposure

This is the highest-impact section. Every publicly-listening port is attack surface.

### ss output interpretation

Each line of `ss -tlnp` looks like:
```
LISTEN  0  128  0.0.0.0:22  0.0.0.0:*  users:(("sshd",pid=1234,fd=3))
```

**Listen address meanings:**
- `0.0.0.0:PORT` or `[::]:PORT` → listening on ALL interfaces (public)
- `127.0.0.1:PORT` or `[::1]:PORT` → localhost only (safe from external)

**Expected ports for a VPN server:**
| Port | Process | Notes |
|---|---|---|
| 22/tcp | sshd | Expected. Better on non-standard port. |
| 1194/udp | openvpn | Expected for VPN. |
| 80/tcp | nginx/certbot | Only if serving web content or ACME challenges |
| 443/tcp | nginx | Only if serving web content |

**Red flags (CRITICAL or HIGH):**
- Port 3306 (MySQL) on 0.0.0.0 → databases must never be public
- Port 5432 (PostgreSQL) on 0.0.0.0 → same
- Port 6379 (Redis) on 0.0.0.0 → Redis has no auth by default, this is CRITICAL
- Port 9200 (Elasticsearch) on 0.0.0.0 → CRITICAL, commonly exploited
- Any service you didn't intentionally install listening publicly

### Firewall interpretation

**Good UFW state:**
```
Status: active
Default: deny (incoming), allow (outgoing), deny (routed)
```

**Bad states:**
- `Status: inactive` → CRITICAL, no firewall
- `Default: allow (incoming)` → CRITICAL, firewall is open by default
- Rules allowing `Anywhere` to sensitive ports → HIGH

**iptables NAT for VPN:**
A MASQUERADE rule on the VPN subnet (e.g., 10.8.0.0/24) going out through the main interface
(eth0/ens3) is normal for OpenVPN. Example:
```
MASQUERADE  all  --  10.8.0.0/24  0.0.0.0/0
```
Flag unexpected DNAT (port forwarding) rules as HIGH.

---

## 3. SSH Hardening

### Setting-by-setting guide

| Setting | Secure | Insecure | Severity if insecure |
|---|---|---|---|
| permitrootlogin | no | yes / without-password | CRITICAL if yes, HIGH if without-password |
| passwordauthentication | no | yes | HIGH — enables brute-force |
| pubkeyauthentication | yes | no | CRITICAL — no secure auth method |
| permitemptypasswords | no | yes | CRITICAL |
| maxauthtries | 3-5 | >6 or 0 (unlimited) | MEDIUM |
| x11forwarding | no | yes | LOW (attack surface, rarely exploited) |
| clientaliveinterval | 60-600 | 0 (disabled) | LOW |
| clientalivecountmax | 2-3 | >5 | LOW |
| logingracetime | 30-60 | >120 or 0 | LOW |
| allowusers / allowgroups | (set) | (not set) | MEDIUM — all users can SSH |

### Remediation pattern

```bash
# Edit sshd_config
sudo nano /etc/ssh/sshd_config
# ... make changes ...

# Test config before restarting (prevents lockout!)
sudo sshd -t

# Restart only if test passes
sudo systemctl restart sshd
```

Always warn the user: test SSH config before restarting, and keep an existing session open as
a safety net in case the new config locks them out.

---

## 4. Fail2ban

### Health checks

- **Service active?** If `systemctl is-active fail2ban` is not `active`, that's HIGH.
- **sshd jail enabled?** Minimum requirement. If not enabled, HIGH.
- **Ban parameters:**
  - `bantime`: Recommend ≥86400 (1 day). Under 3600 (1 hour) is too short → MEDIUM
  - `findtime`: Recommend 600 (10 min). Over 3600 may be too forgiving → LOW
  - `maxretry`: Recommend 3-5. Over 10 is too lenient → MEDIUM
- **Currently banned count**: Not a problem indicator by itself. Zero banned with hundreds
  of failed logins means fail2ban isn't catching them → HIGH.

### Additional jails to recommend

If the server runs web services, recommend enabling jails for:
- `nginx-http-auth` — blocks brute-force on HTTP basic auth
- `nginx-botsearch` — blocks scanners probing for common vuln paths

---

## 5. Rootkit Scan (rkhunter)

### Exit codes

- 0 → Clean, no warnings
- 1 → Warnings found (not necessarily a compromise — read each one)
- 2+ → Errors during scan

### Common false positives

rkhunter frequently flags these after normal package updates:
- `/usr/bin/lwp-request` — Perl module, harmless
- "The file properties have changed" for recently-updated binaries — cross-check with
  `dpkg -V <package>` or look at `/var/log/dpkg.log`
- Hidden directories like `/dev/.udev` or `/etc/.java` — these are standard

### Genuine warnings (investigate immediately)

- "Rootkit X found" → CRITICAL, investigate immediately
- Binary replaced by a script → HIGH, could be a trojan wrapper
- Unexpected network-facing process in `/proc` → HIGH
- Unknown files in `/tmp` with execute permissions → HIGH

### After confirming false positives

Update the baseline so they don't appear again:
```bash
sudo rkhunter --propupd
```

---

## 6. Lynis Audit

### Hardening index

| Score | Rating | Action |
|---|---|---|
| 80-100 | Excellent | Maintain current practices |
| 70-79 | Good | Address suggestions at next maintenance |
| 60-69 | Fair | Prioritize the warnings and top suggestions |
| 40-59 | Poor | Needs significant hardening work |
| 0-39 | Critical | Server is poorly secured, address immediately |

### Priority order for suggestions

1. **Kernel hardening** (sysctl) — MEDIUM per item
   - `net.ipv4.conf.all.rp_filter = 1` (reverse path filtering)
   - `net.ipv4.conf.all.accept_redirects = 0`
   - `net.ipv4.conf.all.send_redirects = 0`
   - `kernel.randomize_va_space = 2` (full ASLR)
2. **File permissions** — MEDIUM per item
   - World-writable files outside /tmp
   - SUID binaries that shouldn't have SUID
3. **Authentication** — varies
   - PAM password quality modules (MEDIUM)
   - Account lockout policies (MEDIUM)
4. **Logging** — LOW to MEDIUM
   - Ensure rsyslog or journald is running
   - Check log rotation is configured
5. **Unnecessary services** — LOW per item
   - Disable services not in use

### Applying sysctl hardening

```bash
# Add to /etc/sysctl.d/99-hardening.conf
cat <<EOF | sudo tee /etc/sysctl.d/99-hardening.conf
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
kernel.randomize_va_space = 2
EOF
sudo sysctl --system
```

---

## 7. Package Updates

### Severity by package type

- **CRITICAL**: Pending updates for `linux-image-*`, `openssl`, `libssl*`, `openssh-server`, `openvpn`
- **HIGH**: Pending updates for `nginx`, `apache2`, `sudo`, `systemd`, `glibc`/`libc6`
- **MEDIUM**: Other pending security updates
- **LOW**: Non-security updates

### Reboot required

If `/var/run/reboot-required` exists, the kernel or a core library was updated but the running
system is still using the old version. This is HIGH — the fix (a kernel exploit, say) isn't
active until reboot.

### Unattended upgrades

If not installed or not enabled, flag as MEDIUM with remediation:
```bash
sudo apt install unattended-upgrades -y
sudo dpkg-reconfigure -plow unattended-upgrades
```

---

## 8. Users & Auth

### Users with login shells

Only human users and root should have interactive shells (`/bin/bash`, `/bin/sh`, `/bin/zsh`).
Service accounts (www-data, mysql, nobody, etc.) should have `/usr/sbin/nologin` or `/bin/false`.

- Unexpected user with a login shell → HIGH (possible backdoor account)
- UID 0 user that isn't root → CRITICAL (hidden root account)

### Sudo group

Should be as small as possible. Each member effectively has root access.

- Unexpected user in sudo group → HIGH
- Service account in sudo group → CRITICAL

### Failed SSH logins

| Count (24h) | Interpretation |
|---|---|
| 0-50 | Low activity, normal |
| 50-500 | Normal internet noise |
| 500-5000 | Moderate scanning, fail2ban should be handling this |
| 5000+ | Heavy targeting, check fail2ban effectiveness and consider geo-blocking |

### Authorized keys

Count the keys in each user's `~/.ssh/authorized_keys`. Unexpected keys are a sign of
compromise or unauthorized access. Each key should be accounted for.

- Unknown key in root's authorized_keys → CRITICAL
- Unknown key in any user's authorized_keys → HIGH
