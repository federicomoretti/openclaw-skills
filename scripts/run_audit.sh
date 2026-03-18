#!/usr/bin/env bash
# =============================================================================
# VPS Security Audit — Data Collection Script
#
# This script MUST run as root (or via sudo) because the tools it invokes
# (lynis, rkhunter, fail2ban-client, iptables, ss -p, sshd -T) all require
# elevated privileges to inspect system state.
#
# USAGE:
#   sudo bash run_audit.sh              # run once, output to stdout + file
#   sudo bash run_audit.sh --cron       # run silently, output to file only
#   sudo bash run_audit.sh --install    # install systemd timer for weekly runs
#   sudo bash run_audit.sh --uninstall  # remove systemd timer
#
# OUTPUT:
#   /var/log/vps-audit/latest.log       — most recent audit (symlink)
#   /var/log/vps-audit/YYYYMMDD-HHMMSS.log — timestamped archive
#
# SECURITY MODEL:
#   The AI agent never needs sudo. It reads /var/log/vps-audit/latest.log.
#   Logs are owned by root with mode 600. To let a non-root user (or agent)
#   read them, either:
#     a) copy the file to a readable location, or
#     b) create a dedicated "audit" group and chmod 640 the log dir
#   See --setup-reader below.
#
#   sudo bash run_audit.sh --setup-reader USERNAME
#     Creates an "audit-reader" group, adds USERNAME to it, and sets
#     /var/log/vps-audit/ to group-readable (750/640). The user can then
#     read audit logs without sudo.
# =============================================================================

set -uo pipefail

# ---- Check root ----
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: This script must be run as root. Use: sudo bash $0" >&2
    exit 1
fi

AUDIT_SCRIPT_PATH="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
SYSTEMD_SERVICE="/etc/systemd/system/vps-audit.service"
SYSTEMD_TIMER="/etc/systemd/system/vps-audit.timer"
LOG_DIR="/var/log/vps-audit"

# ---- Handle flags ----

case "${1:-}" in
    --install)
        echo "Installing systemd timer for weekly VPS audit..."

        cat > "$SYSTEMD_SERVICE" <<SVCEOF
[Unit]
Description=VPS Security Audit Data Collection
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/bash $AUDIT_SCRIPT_PATH --cron
Nice=10
IOSchedulingClass=idle
SVCEOF

        cat > "$SYSTEMD_TIMER" <<TMREOF
[Unit]
Description=Run VPS Security Audit weekly

[Timer]
OnCalendar=Sun 03:00
RandomizedDelaySec=1800
Persistent=true

[Install]
WantedBy=timers.target
TMREOF

        systemctl daemon-reload
        systemctl enable --now vps-audit.timer
        echo ""
        echo "Done. Audit will run every Sunday at ~3:00 AM."
        echo ""
        echo "Useful commands:"
        echo "  Check timer:    systemctl list-timers vps-audit.timer"
        echo "  Run now:        sudo systemctl start vps-audit.service"
        echo "  View results:   cat /var/log/vps-audit/latest.log"
        exit 0
        ;;

    --uninstall)
        echo "Removing systemd timer..."
        systemctl disable --now vps-audit.timer 2>/dev/null || true
        rm -f "$SYSTEMD_SERVICE" "$SYSTEMD_TIMER"
        systemctl daemon-reload
        echo "Done. Timer removed. Logs in $LOG_DIR are preserved."
        exit 0
        ;;

    --setup-reader)
        TARGET_USER="${2:-}"
        if [ -z "$TARGET_USER" ]; then
            echo "Usage: sudo bash $0 --setup-reader USERNAME"
            exit 1
        fi
        if ! id "$TARGET_USER" &>/dev/null; then
            echo "ERROR: User '$TARGET_USER' does not exist."
            exit 1
        fi

        GROUP_NAME="audit-reader"
        if ! getent group "$GROUP_NAME" &>/dev/null; then
            groupadd "$GROUP_NAME"
            echo "Created group: $GROUP_NAME"
        fi

        usermod -aG "$GROUP_NAME" "$TARGET_USER"
        echo "Added $TARGET_USER to group $GROUP_NAME"

        mkdir -p "$LOG_DIR"
        chown root:"$GROUP_NAME" "$LOG_DIR"
        chmod 750 "$LOG_DIR"
        # Fix existing logs
        find "$LOG_DIR" -name "*.log" -exec chown root:"$GROUP_NAME" {} \;
        find "$LOG_DIR" -name "*.log" -exec chmod 640 {} \;

        echo ""
        echo "Done. $TARGET_USER can now read audit logs:"
        echo "  cat $LOG_DIR/latest.log"
        echo ""
        echo "Note: $TARGET_USER may need to log out and back in for the"
        echo "group membership to take effect."
        exit 0
        ;;
esac

# ---- Setup output ----
mkdir -p "$LOG_DIR"
TIMESTAMP=$(date -u +"%Y%m%d-%H%M%S")
TIMESTAMP_HUMAN=$(date -u +"%Y-%m-%d %H:%M:%S UTC")
ARCHIVE_LOG="$LOG_DIR/$TIMESTAMP.log"
LATEST_LOG="$LOG_DIR/latest.log"

# If --cron, only write to file. Otherwise tee to stdout as well.
if [ "${1:-}" = "--cron" ]; then
    exec > "$ARCHIVE_LOG" 2>&1
else
    exec > >(tee "$ARCHIVE_LOG") 2>&1
fi

DIVIDER="========================================================================"

echo "$DIVIDER"
echo "VPS SECURITY AUDIT — $TIMESTAMP_HUMAN"
echo "$DIVIDER"
echo ""

# ---------- Phase 1: System Snapshot ----------
echo "==== PHASE 1: SYSTEM SNAPSHOT ===="
echo "hostname: $(hostname)"
echo "kernel: $(uname -r)"
echo "os: $(cat /etc/os-release 2>/dev/null | grep -E '^(NAME|VERSION)=' | tr '\n' ' ')"
echo "uptime: $(uptime -p 2>/dev/null || uptime)"
echo "disk_root: $(df -h / | tail -1)"
echo "memory: $(free -h | grep Mem)"
echo ""
echo "-- Current logins --"
who 2>/dev/null || echo "(no users logged in)"
echo ""
echo "-- Last 10 logins --"
last -n 10 --time-format iso 2>/dev/null || last -n 10
echo ""

# ---------- Phase 2: Network Exposure ----------
echo "==== PHASE 2: NETWORK EXPOSURE ===="
echo "-- Listening TCP services --"
ss -tlnp 2>/dev/null || echo "ERROR: ss command failed"
echo ""
echo "-- Listening UDP services --"
ss -ulnp 2>/dev/null || echo "ERROR: ss command failed"
echo ""
echo "-- UFW status --"
if command -v ufw &>/dev/null; then
    ufw status verbose 2>/dev/null || echo "ERROR: ufw command failed"
else
    echo "UFW: not installed"
fi
echo ""
echo "-- iptables filter rules --"
iptables -L -n -v --line-numbers 2>/dev/null || echo "ERROR: iptables command failed"
echo ""
echo "-- iptables NAT rules --"
iptables -t nat -L -n -v --line-numbers 2>/dev/null || echo "(no NAT rules or iptables unavailable)"
echo ""

# ---------- Phase 3: SSH Configuration ----------
echo "==== PHASE 3: SSH HARDENING ===="
if command -v sshd &>/dev/null; then
    sshd -T 2>/dev/null | grep -E "^(permitrootlogin|passwordauthentication|pubkeyauthentication|port |allowusers|allowgroups|maxauthtries|x11forwarding|permitemptypasswords|logingracetime|clientaliveinterval|clientalivecountmax|addressfamily|listenaddress)" || echo "ERROR: sshd -T failed"
else
    echo "sshd: not found"
fi
echo ""

# ---------- Phase 4: Fail2ban ----------
echo "==== PHASE 4: FAIL2BAN ===="
if command -v fail2ban-client &>/dev/null; then
    echo "service_status: $(systemctl is-active fail2ban 2>/dev/null || echo 'unknown')"
    echo ""
    echo "-- Jail list --"
    fail2ban-client status 2>/dev/null || echo "ERROR: fail2ban-client status failed"
    echo ""

    for jail in $(fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*://;s/,/ /g' | xargs); do
        echo "-- Jail: $jail --"
        fail2ban-client status "$jail" 2>/dev/null || true
        echo "bantime: $(fail2ban-client get "$jail" bantime 2>/dev/null || echo 'N/A')"
        echo "findtime: $(fail2ban-client get "$jail" findtime 2>/dev/null || echo 'N/A')"
        echo "maxretry: $(fail2ban-client get "$jail" maxretry 2>/dev/null || echo 'N/A')"
        echo ""
    done
else
    echo "fail2ban: NOT INSTALLED"
fi
echo ""

# ---------- Phase 5: rkhunter ----------
echo "==== PHASE 5: RKHUNTER ===="
if command -v rkhunter &>/dev/null; then
    rkhunter --check --skip-keypress --report-warnings-only 2>&1 || true
    echo "RKHUNTER_EXIT_CODE: ${PIPESTATUS[0]:-$?}"
else
    echo "rkhunter: NOT INSTALLED"
fi
echo ""

# ---------- Phase 6: Lynis ----------
echo "==== PHASE 6: LYNIS ===="
if command -v lynis &>/dev/null; then
    lynis audit system --no-colors --quick 2>&1 || true
    echo ""
    echo "-- Lynis Summary --"
    if [ -f /var/log/lynis.log ]; then
        grep -E "Hardening index|Warnings? \(" /var/log/lynis.log 2>/dev/null | tail -5
    fi
    if [ -f /var/log/lynis-report.dat ]; then
        echo "warnings_count: $(grep -c '^warning\[\]' /var/log/lynis-report.dat 2>/dev/null || echo 0)"
        echo "suggestions_count: $(grep -c '^suggestion\[\]' /var/log/lynis-report.dat 2>/dev/null || echo 0)"
        echo ""
        echo "-- Lynis Warnings --"
        grep '^warning\[\]' /var/log/lynis-report.dat 2>/dev/null || echo "(none)"
        echo ""
        echo "-- Lynis Top Suggestions --"
        grep '^suggestion\[\]' /var/log/lynis-report.dat 2>/dev/null | head -20 || echo "(none)"
    fi
else
    echo "lynis: NOT INSTALLED"
fi
echo ""

# ---------- Phase 7: Package Updates ----------
echo "==== PHASE 7: UPDATES ===="
apt update -qq 2>/dev/null || true
echo "-- Upgradable packages --"
apt list --upgradable 2>/dev/null || true
echo ""
echo "running_kernel: $(uname -r)"
echo "reboot_required: $([ -f /var/run/reboot-required ] && echo 'YES' || echo 'no')"
echo ""
echo "-- Unattended upgrades --"
if dpkg -l 2>/dev/null | grep -q unattended-upgrades; then
    echo "unattended_upgrades: installed"
    echo "enabled: $(systemctl is-enabled unattended-upgrades 2>/dev/null || echo 'unknown')"
else
    echo "unattended_upgrades: NOT INSTALLED"
fi
echo ""

# ---------- Phase 8: Users & Auth ----------
echo "==== PHASE 8: USERS ===="
echo "-- Users with login shells --"
grep -v '/nologin\|/false' /etc/passwd | cut -d: -f1,3,7
echo ""
echo "-- Sudo group members --"
getent group sudo 2>/dev/null || getent group wheel 2>/dev/null || echo "(could not determine sudo group)"
echo ""
echo "-- Failed SSH logins (last 24h) --"
FAILED_COUNT=$(journalctl _SYSTEMD_UNIT=sshd.service --since "24 hours ago" 2>/dev/null | grep -c "Failed password" 2>/dev/null || grep -c "Failed password" /var/log/auth.log 2>/dev/null || echo "unknown")
echo "failed_ssh_logins_24h: $FAILED_COUNT"
echo ""
echo "-- Authorized keys --"
find /home /root -name "authorized_keys" -exec echo "--- {} ---" \; -exec wc -l {} \; 2>/dev/null || true
echo ""

# ---------- Finalize ----------
echo "$DIVIDER"
echo "AUDIT DATA COLLECTION COMPLETE — $TIMESTAMP_HUMAN"
echo "Results saved to: $ARCHIVE_LOG"
echo "$DIVIDER"

# Symlink latest
ln -sf "$ARCHIVE_LOG" "$LATEST_LOG"

# Apply correct permissions
chmod 700 "$LOG_DIR"
chmod 600 "$ARCHIVE_LOG"

# If audit-reader group exists, use group permissions instead
if getent group audit-reader &>/dev/null; then
    chown root:audit-reader "$LOG_DIR" "$ARCHIVE_LOG"
    chmod 750 "$LOG_DIR"
    chmod 640 "$ARCHIVE_LOG"
fi

# Prune logs older than 90 days
find "$LOG_DIR" -name "*.log" -not -name "latest.log" -mtime +90 -delete 2>/dev/null || true
