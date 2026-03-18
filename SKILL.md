---
name: vps-security-audit
description: >
  Run a comprehensive security audit on a Linux VPS. Use this skill whenever the user says things 
  like "check my server", "run a security scan", "audit my server". 
  This skill orchestrates multiple security tools (lynis, rkhunter, fail2ban,
  UFW/iptables, SSH config, package updates, open ports) into a single structured audit with
  interpreted results and prioritized recommendations.
metadata:
  {
    "openclaw":
      {
        "requires": { "bins": ["lynis", "rkhunter"] }
      },
  }
---

# VPS Security Audit Skill

Run a structured, multi-phase security audit on a Linux VPS and produce an interpreted report
with prioritized action items.

Designed for Ubuntu/Debian servers with these tools pre-installed: `lynis`, `rkhunter`, `fail2ban`.
If a tool is missing, log it as a finding and continue — never abort the audit because one tool
is unavailable.

## Privilege Separation Model

The audit tools (lynis, rkhunter, fail2ban-client, iptables, ss, sshd) all require root.
Rather than giving the AI agent sudo access, the architecture separates concerns:

1. **Data collection** runs as root (via the script, cron, or systemd timer)
2. **Interpretation** runs unprivileged — the agent just reads a log file

The agent never needs sudo. It reads `/var/log/vps-audit/latest.log`.

## First-Time Setup (run once on the VPS as root)

```bash
# 1. Copy the script to the server
scp scripts/run_audit.sh user@server:/usr/local/bin/vps-audit.sh

# 2. (Optional) Install a weekly systemd timer
sudo bash /usr/local/bin/vps-audit.sh --install

# 3. (Optional) Let a non-root user read results without sudo
sudo bash /usr/local/bin/vps-audit.sh --setup-reader USERNAME
```

## How to Execute an Audit

**Option A — Manual run (interactive):**
```bash
sudo bash /usr/local/bin/vps-audit.sh
```
Output goes to stdout AND `/var/log/vps-audit/YYYYMMDD-HHMMSS.log`.

**Option B — Automated (systemd timer runs weekly):**
Results accumulate in `/var/log/vps-audit/`. The symlink `latest.log` always
points to the most recent run. Logs older than 90 days are auto-pruned.

**Option C — Cron (silent, file-only output):**
```bash
sudo bash /usr/local/bin/vps-audit.sh --cron
```

## How the Agent Interprets Results

1. Read `/var/log/vps-audit/latest.log` (or have the user paste it)
2. Parse each `==== PHASE N: ... ====` section
3. Apply the interpretation rules from `references/interpretation_guide.md`
4. Produce the final report using `references/report_template.md`

---

## Interpreting Results

After collecting raw data, read `references/interpretation_guide.md` for detailed
interpretation rules for every phase, including severity classifications, common false
positives, and what-good-looks-like baselines.

## Producing the Report

Use `references/report_template.md` to format the final report. The report must include:

1. **Executive Summary** — Overall health, most critical finding, hardening score
2. **Findings Table** — Every finding with severity, category, description, remediation
3. **Prioritized Action Plan** — Grouped CRITICAL → LOW, with copy-pasteable commands
4. **Score Breakdown** — Per-category numeric score and weighted overall score

## Scoring System

Each category starts at 100, then deducts per finding:
- CRITICAL: −40 | HIGH: −20 | MEDIUM: −10 | LOW: −5 (floor: 0)

Overall = weighted average:
- Network Exposure: 25% | SSH: 20% | Firewall: 20% | Malware/Rootkit: 15% | Updates: 10% | Users: 10%

## Important

- Never include passwords, private keys, or sensitive tokens in the report.
- Always include exact remediation commands — the user should be able to copy-paste fixes.
- If overall score < 50, flag the server as **requiring immediate attention**.
- After the report, offer to help execute remediations interactively.
