# 🐧 Linux / Ubuntu Admin Script Bundle
**17 bash scripts for security auditing, user management, backup, and system monitoring**

---

## 📦 Scripts Overview

| # | Script | Purpose | Root Required |
|---|--------|---------|---------------|
| 01 | `01-sudo-access-auditor.sh` | Audit who has sudo/root and flag anomalies | ✅ |
| 02 | `02-last-login-reporter.sh` | Report inactive accounts and login history | ✅ |
| 03 | `03-ssh-key-auditor.sh` | Audit SSH authorized_keys across all users | ✅ |
| 04 | `04-failed-ssh-tracker.sh` | Track failed SSH logins with IP geolocation | ✅ |
| 05 | `05-bulk-lock-unlock.sh` | Lock/unlock user accounts in bulk | ✅ |
| 06 | `06-cis-benchmark.sh` | CIS Level 1 & 2 hardening benchmark checker | ✅ |
| 07 | `07-world-writable-finder.sh` | Find world-writable files and directories | ✅ |
| 08 | `08-firewall-reporter.sh` | Export and analyse UFW/iptables rules | ✅ |
| 09 | `09-auth-log-blocker.sh` | Parse auth logs and block brute-force IPs | ✅ |
| 10 | `10-rootkit-scanner.sh` | Wrapper for chkrootkit & rkhunter | ✅ |
| 11 | `11-rsync-backup.sh` | Incremental rsync backup with rotation | ✅ |
| 12 | `12-auto-update.sh` | Auto-update with pre/post package snapshots | ✅ |
| 13 | `13-outdated-packages.sh` | Outdated package report with CVE/USN links | ✅ |
| 14 | `14-package-inventory.sh` | Export full package inventory (apt/snap/pip) to CSV | — |
| 15 | `15-ssl-cert-checker.sh` | SSL certificate expiry checker with alerts | — |
| 16 | `16-cron-auditor.sh` | Audit all cron jobs, flag suspicious entries | ✅ |
| 17 | `17-systemd-reporter.sh` | Systemd failed unit reporter with journal logs | ✅ |

---

## 🚀 Quick Start

```bash
# Make all scripts executable
chmod +x *.sh

# Run any script as root
sudo bash 01-sudo-access-auditor.sh
sudo bash 06-cis-benchmark.sh
sudo bash 17-systemd-reporter.sh

# Run all scripts in sequence (generates all reports)
for s in *.sh; do sudo bash "$s"; done
```

---

## 📁 Output Locations

All HTML reports are saved under `/var/log/admin-reports/`:

| Script | Report Directory |
|--------|-----------------|
| Sudo audit | `/var/log/admin-reports/sudo-audit/` |
| Last login | `/var/log/admin-reports/last-login/` |
| SSH keys | `/var/log/admin-reports/ssh-audit/` |
| Failed SSH | `/var/log/admin-reports/ssh-failures/` |
| Account mgmt | `/var/log/admin-reports/account-mgmt/` |
| CIS benchmark | `/var/log/admin-reports/cis-benchmark/` |
| World-writable | `/var/log/admin-reports/world-writable/` |
| Firewall | `/var/log/admin-reports/firewall/` |
| Auth blocker | `/var/log/admin-reports/auth-blocker/` |
| Rootkit scan | `/var/log/admin-reports/rootkit-scan/` |
| Backups | `/var/log/admin-reports/backup/` |
| Updates | `/var/log/admin-reports/updates/` |
| Package audit | `/var/log/admin-reports/packages/` |
| SSL certs | `/var/log/admin-reports/ssl/` |
| Cron audit | `/var/log/admin-reports/cron-audit/` |
| Systemd | `/var/log/admin-reports/systemd/` |

---

## ⚙️ Configuration

Each script has a **CONFIGURATION** section at the top. Common options:

### Email Reports
Set `MAIL_TO` in any script to receive HTML reports by email:
```bash
MAIL_TO="admin@yourcompany.com"
```
Requires the `mail` command: `sudo apt install mailutils`

### Approved Sudo Users (Script 01)
```bash
APPROVED_SUDO_USERS=("ubuntu" "admin" "deploy")
```

### SSH Failure Blocking (Script 09)
```bash
BLOCK_METHOD="ufw"        # ufw | iptables | hosts.deny | dry-run
BLOCK_THRESHOLD=10        # failures before blocking
```

### SSL Domains (Script 15)
```bash
DOMAINS=(
    "yourdomain.com:443"
    "mail.yourdomain.com:465"
    "api.yourdomain.com:8443"
)
```

### Backup Sets (Script 11)
```bash
BACKUP_SETS=(
    "home:/home:/mnt/backup/home:30"
    "etc:/etc:/mnt/backup/etc:30"
    "www:/var/www:/mnt/backup/www:14"
)
# Format: "name:source:destination:keep_days"
```

---

## 📅 Recommended Cron Schedule

Add to `/etc/crontab` or `/etc/cron.d/admin-scripts`:

```cron
# Daily security reports (2am)
0 2 * * * root /opt/admin-scripts/01-sudo-access-auditor.sh
0 2 * * * root /opt/admin-scripts/04-failed-ssh-tracker.sh
0 2 * * * root /opt/admin-scripts/09-auth-log-blocker.sh

# Weekly audits (Sunday 3am)
0 3 * * 0 root /opt/admin-scripts/03-ssh-key-auditor.sh
0 3 * * 0 root /opt/admin-scripts/06-cis-benchmark.sh
0 3 * * 0 root /opt/admin-scripts/07-world-writable-finder.sh
0 3 * * 0 root /opt/admin-scripts/10-rootkit-scanner.sh
0 3 * * 0 root /opt/admin-scripts/16-cron-auditor.sh

# Daily backup (1am)
0 1 * * * root /opt/admin-scripts/11-rsync-backup.sh

# Daily updates (4am)
0 4 * * * root /opt/admin-scripts/12-auto-update.sh

# SSL check (daily, 6am)
0 6 * * * root /opt/admin-scripts/15-ssl-cert-checker.sh

# Systemd health (every 4 hours)
0 */4 * * * root /opt/admin-scripts/17-systemd-reporter.sh
```

---

## 📋 Requirements

### Standard (included in Ubuntu)
- `bash` 4.0+
- `awk`, `grep`, `sed`, `find`, `stat`
- `openssl` (for SSL checker)
- `systemctl`, `journalctl` (for systemd reporter)
- `dpkg`, `apt` (for package scripts)
- `rsync` (for backup)
- `ss` or `netstat` (for firewall reporter)

### Optional
- `curl` — required for IP geolocation (script 04) and CVE lookup (script 13)
- `ufw` — for firewall reporting and IP blocking
- `chkrootkit`, `rkhunter` — auto-installed by script 10 if missing
- `mail` (`mailutils`) — for email reports
- `snap`, `flatpak` — for package inventory
- `lastlog`, `chage` — usually pre-installed

### Install all optional tools:
```bash
sudo apt install curl ufw chkrootkit rkhunter mailutils rsync
```

---

## 🔒 Security Notes

- **All scripts require root** unless noted — run with `sudo`
- Scripts that block IPs (`09`) default to `dry-run` mode — review before enabling `ufw` blocking
- The world-writable finder (`07`) has `AUTO_FIX=false` by default — review findings before enabling
- Backup script (`11`) needs valid source/destination paths configured before first run
- The auto-updater (`12`) runs live changes — set `DRY_RUN=true` to preview first
- Approved sudo users (`01`) should be configured for your environment before running

---

## 📊 Report Format

All reports are:
- **HTML** — colour-coded, with severity badges and expandable sections
- **Saved locally** to `/var/log/admin-reports/[category]/`
- **Optionally emailed** as HTML attachments via `mail`
- Named with timestamps: `report-YYYYMMDD_HHMMSS.html`

---

*Generated for Ubuntu 20.04 / 22.04 / 24.04 LTS — compatible with most Debian-based systems*
