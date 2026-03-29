#!/usr/bin/env bash
# =============================================================
#  CIS BENCHMARK CHECKER (Ubuntu / Debian)
#  Runs key CIS Level 1 & 2 checks and scores your system
#  Run as: sudo bash 06-cis-benchmark.sh
# =============================================================

set -uo pipefail

# =============================================================
#  CONFIGURATION
# =============================================================
REPORT_DIR="/var/log/admin-reports/cis-benchmark"
HTML_FILE="${REPORT_DIR}/cis-$(date +%Y%m%d_%H%M%S).html"
MAIL_TO=""
MAIL_SUBJECT="CIS Benchmark Report - $(hostname) - $(date +%Y-%m-%d)"

# =============================================================
#  COLOURS
# =============================================================
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
PASS=0; FAIL=0; WARN=0; INFO_COUNT=0

section() { echo -e "\n${BOLD}━━━ $* ━━━${RESET}"; }

pass() {
    echo -e "  ${GREEN}[PASS]${RESET} $1"
    RESULTS+=("PASS|$1|$2")
    PASS=$((PASS+1))
}
fail() {
    echo -e "  ${RED}[FAIL]${RESET} $1"
    RESULTS+=("FAIL|$1|$2")
    FAIL=$((FAIL+1))
}
warn_check() {
    echo -e "  ${YELLOW}[WARN]${RESET} $1"
    RESULTS+=("WARN|$1|$2")
    WARN=$((WARN+1))
}
info_check() {
    echo -e "  ${CYAN}[INFO]${RESET} $1"
    RESULTS+=("INFO|$1|$2")
    INFO_COUNT=$((INFO_COUNT+1))
}

[[ $EUID -eq 0 ]] || { echo "Run as root: sudo $0"; exit 1; }
mkdir -p "$REPORT_DIR"
declare -a RESULTS

# =============================================================
#  1. FILESYSTEM CONFIGURATION
# =============================================================
section "1. Filesystem Configuration"

# 1.1 Separate partitions
for mp in /tmp /var /var/log /home; do
    if mount | grep -q " $mp "; then
        pass "Separate partition for $mp" "Dedicated partition exists for $mp"
    else
        warn_check "No separate partition for $mp" "CIS recommends a dedicated partition for $mp to prevent disk exhaustion"
    fi
done

# 1.2 /tmp options
tmp_opts=$(mount | grep ' /tmp ' | grep -oP 'noexec|nosuid|nodev' | tr '\n' ',' | sed 's/,$//')
for opt in noexec nosuid nodev; do
    if mount | grep ' /tmp ' | grep -q "$opt"; then
        pass "/tmp mounted with $opt" "Good: /tmp has $opt mount option"
    else
        fail "/tmp not mounted with $opt" "Add '$opt' to /tmp mount options in /etc/fstab"
    fi
done

# 1.3 Sticky bit on world-writable dirs
ww_no_sticky=$(df --local -P | awk '{print $6}' | tail -n +2 | \
    xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | head -5)
if [[ -z "$ww_no_sticky" ]]; then
    pass "Sticky bit set on all world-writable directories" "No world-writable dirs without sticky bit"
else
    fail "World-writable directories without sticky bit found" "Run: chmod +t <dir> for each: $ww_no_sticky"
fi

# =============================================================
#  2. SOFTWARE UPDATES
# =============================================================
section "2. Software Updates"

# 2.1 APT auto-updates configured
if dpkg -l unattended-upgrades 2>/dev/null | grep -q '^ii'; then
    pass "unattended-upgrades installed" "Automatic security updates are enabled"
else
    fail "unattended-upgrades not installed" "Run: apt install unattended-upgrades && dpkg-reconfigure -p low unattended-upgrades"
fi

# 2.2 Pending updates
pending=$(apt-get -s upgrade 2>/dev/null | grep -c '^Inst' || echo 0)
if [[ "$pending" -eq 0 ]]; then
    pass "No pending package updates" "System is up to date"
elif [[ "$pending" -le 5 ]]; then
    warn_check "$pending pending updates" "Run: apt upgrade"
else
    fail "$pending pending updates" "System has $pending packages requiring update. Run: apt upgrade"
fi

# 2.3 Security-specific pending
sec_pending=$(apt-get -s upgrade 2>/dev/null | grep -i security | wc -l || echo 0)
if [[ "$sec_pending" -gt 0 ]]; then
    fail "$sec_pending pending security updates" "Run: apt upgrade immediately"
else
    pass "No pending security updates" "All security patches applied"
fi

# =============================================================
#  3. NETWORK CONFIGURATION
# =============================================================
section "3. Network Configuration"

# 3.1 IPv6 disabled (if not needed)
if sysctl net.ipv6.conf.all.disable_ipv6 2>/dev/null | grep -q '= 1'; then
    info_check "IPv6 is disabled" "Note: disable if not needed"
else
    info_check "IPv6 is enabled" "Ensure IPv6 is properly configured if enabled"
fi

# 3.2 IP forwarding disabled
if sysctl net.ipv4.ip_forward 2>/dev/null | grep -q '= 0'; then
    pass "IP forwarding disabled" "net.ipv4.ip_forward = 0"
else
    fail "IP forwarding is ENABLED" "Set net.ipv4.ip_forward=0 in /etc/sysctl.conf unless this is a router"
fi

# 3.3 Packet redirect sending
for param in net.ipv4.conf.all.send_redirects net.ipv4.conf.default.send_redirects; do
    val=$(sysctl "$param" 2>/dev/null | awk '{print $3}' || echo "?")
    if [[ "$val" == "0" ]]; then
        pass "$param = 0" "Good"
    else
        fail "$param = $val (should be 0)" "Set $param=0 in /etc/sysctl.conf"
    fi
done

# 3.4 ICMP redirects ignored
for param in net.ipv4.conf.all.accept_redirects net.ipv4.conf.default.accept_redirects; do
    val=$(sysctl "$param" 2>/dev/null | awk '{print $3}' || echo "?")
    if [[ "$val" == "0" ]]; then
        pass "$param = 0" "Ignoring ICMP redirects"
    else
        fail "$param should be 0 (is $val)" "Set in /etc/sysctl.conf"
    fi
done

# 3.5 SYN cookies
val=$(sysctl net.ipv4.tcp_syncookies 2>/dev/null | awk '{print $3}' || echo "?")
if [[ "$val" == "1" ]]; then
    pass "TCP SYN cookies enabled" "Protection against SYN flood attacks"
else
    fail "TCP SYN cookies disabled" "Set net.ipv4.tcp_syncookies=1 in /etc/sysctl.conf"
fi

# 3.6 Bogus ICMP error responses
val=$(sysctl net.ipv4.icmp_ignore_bogus_error_responses 2>/dev/null | awk '{print $3}' || echo "?")
if [[ "$val" == "1" ]]; then
    pass "Bogus ICMP error responses ignored" ""
else
    warn_check "Bogus ICMP responses not ignored" "Set net.ipv4.icmp_ignore_bogus_error_responses=1"
fi

# =============================================================
#  4. FIREWALL
# =============================================================
section "4. Firewall"

# 4.1 UFW / iptables active
if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
    pass "UFW firewall is active" "$(ufw status | head -3)"
elif iptables -L INPUT 2>/dev/null | grep -qv "ACCEPT\s*all\s*--\s*anywhere\s*anywhere$"; then
    pass "iptables rules present" "Custom iptables rules found"
elif command -v firewalld &>/dev/null && systemctl is-active firewalld &>/dev/null; then
    pass "firewalld is active" ""
else
    fail "No active firewall detected" "Enable UFW: ufw enable, or configure iptables/firewalld"
fi

# 4.2 Default deny policy
if command -v ufw &>/dev/null; then
    if ufw status verbose 2>/dev/null | grep "Default" | grep -q "deny (incoming)"; then
        pass "UFW default incoming: deny" "Good default policy"
    else
        fail "UFW default incoming policy is not DENY" "Run: ufw default deny incoming"
    fi
fi

# =============================================================
#  5. SSH HARDENING
# =============================================================
section "5. SSH Configuration"

sshd="/etc/ssh/sshd_config"

check_sshd() {
    local param="$1" expected="$2" desc="$3" fix="$4"
    local val
    val=$(grep -i "^${param}" "$sshd" 2>/dev/null | awk '{print $2}' | head -1 || echo "")
    if [[ -z "$val" ]]; then
        warn_check "SSH $param not explicitly set (default may be insecure)" "Add '$param $expected' to $sshd"
    elif [[ "${val,,}" == "${expected,,}" ]]; then
        pass "SSH $param = $val" "$desc"
    else
        fail "SSH $param = $val (expected $expected)" "$fix"
    fi
}

check_sshd "Protocol"              "2"          "SSH Protocol 2 only"                      "Set Protocol 2 in $sshd"
check_sshd "PermitRootLogin"       "no"         "Root login via SSH disabled"              "Set PermitRootLogin no"
check_sshd "PasswordAuthentication" "no"        "Password auth disabled (keys only)"       "Set PasswordAuthentication no"
check_sshd "PermitEmptyPasswords"  "no"         "Empty passwords disallowed"               "Set PermitEmptyPasswords no"
check_sshd "X11Forwarding"         "no"         "X11 forwarding disabled"                  "Set X11Forwarding no"
check_sshd "MaxAuthTries"          "4"          "Max auth tries set to 4"                  "Set MaxAuthTries 4"
check_sshd "UsePAM"                "yes"        "PAM enabled"                              "Set UsePAM yes"
check_sshd "AllowAgentForwarding"  "no"         "Agent forwarding disabled"                "Set AllowAgentForwarding no"
check_sshd "ClientAliveInterval"   "300"        "SSH idle timeout set"                     "Set ClientAliveInterval 300"
check_sshd "LoginGraceTime"        "60"         "Login grace time restricted"              "Set LoginGraceTime 60"

# SSH banner
if grep -qi "^Banner" "$sshd" 2>/dev/null; then
    pass "SSH login banner configured" "Legal warning banner present"
else
    warn_check "No SSH login banner" "Add 'Banner /etc/issue.net' to $sshd and create banner file"
fi

# =============================================================
#  6. USER ACCOUNTS & PASSWORD POLICY
# =============================================================
section "6. User Accounts & Password Policy"

# 6.1 Password min days
min_days=$(grep "^PASS_MIN_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}' || echo 0)
if [[ "$min_days" -ge 7 ]]; then
    pass "PASS_MIN_DAYS = $min_days (≥7)" "Minimum password age set"
else
    fail "PASS_MIN_DAYS = $min_days (should be ≥7)" "Edit /etc/login.defs: PASS_MIN_DAYS 7"
fi

# 6.2 Password max days
max_days=$(grep "^PASS_MAX_DAYS" /etc/login.defs 2>/dev/null | awk '{print $2}' || echo 999)
if [[ "$max_days" -le 90 ]]; then
    pass "PASS_MAX_DAYS = $max_days (≤90)" "Password rotation enforced"
else
    fail "PASS_MAX_DAYS = $max_days (should be ≤90)" "Edit /etc/login.defs: PASS_MAX_DAYS 90"
fi

# 6.3 Password warn age
warn_age=$(grep "^PASS_WARN_AGE" /etc/login.defs 2>/dev/null | awk '{print $2}' || echo 0)
if [[ "$warn_age" -ge 7 ]]; then
    pass "PASS_WARN_AGE = $warn_age (≥7)" "Users warned 7+ days before expiry"
else
    fail "PASS_WARN_AGE = $warn_age (should be ≥7)" "Edit /etc/login.defs: PASS_WARN_AGE 7"
fi

# 6.4 Password complexity (libpam-pwquality or cracklib)
if dpkg -l libpam-pwquality 2>/dev/null | grep -q '^ii' || \
   dpkg -l libpam-cracklib 2>/dev/null | grep -q '^ii'; then
    pass "Password quality library installed" "Password complexity enforced"
else
    fail "No password quality library" "Run: apt install libpam-pwquality"
fi

# 6.5 UID 0 accounts (should only be root)
uid0_count=$(awk -F: '$3==0{print $1}' /etc/passwd | grep -v '^root$' | wc -l)
if [[ "$uid0_count" -eq 0 ]]; then
    pass "Only root has UID 0" "No shadow root accounts"
else
    fail "$uid0_count non-root account(s) with UID=0" "Investigate immediately — $(awk -F: '$3==0{print $1}' /etc/passwd | grep -v root | tr '\n' ' ')"
fi

# 6.6 No accounts without passwords
no_pw=$(awk -F: '($2 == "" ) { print $1 }' /etc/shadow 2>/dev/null | wc -l)
if [[ "$no_pw" -eq 0 ]]; then
    pass "All accounts have passwords" "No blank password accounts"
else
    fail "$no_pw account(s) with blank password" "Lock or set passwords for: $(awk -F: '$2==\"\"{print $1}' /etc/shadow | tr '\n' ' ')"
fi

# 6.7 Default umask
umask_val=$(grep "^UMASK" /etc/login.defs 2>/dev/null | awk '{print $2}' || echo "?")
if [[ "$umask_val" == "027" || "$umask_val" == "077" ]]; then
    pass "Default umask = $umask_val" "Restrictive default file permissions"
else
    warn_check "Default umask = $umask_val (recommend 027)" "Set UMASK 027 in /etc/login.defs"
fi

# =============================================================
#  7. AUDITING & LOGGING
# =============================================================
section "7. Auditing & Logging"

# 7.1 auditd
if systemctl is-active auditd &>/dev/null 2>&1 || service auditd status &>/dev/null 2>&1; then
    pass "auditd is running" "System audit daemon active"
elif dpkg -l auditd 2>/dev/null | grep -q '^ii'; then
    fail "auditd installed but not running" "Start it: systemctl enable --now auditd"
else
    fail "auditd not installed" "Run: apt install auditd audispd-plugins"
fi

# 7.2 rsyslog
if systemctl is-active rsyslog &>/dev/null 2>&1; then
    pass "rsyslog is running" "System logging active"
else
    warn_check "rsyslog not running" "Check logging: systemctl start rsyslog"
fi

# 7.3 Log files permissions
for lf in /var/log/syslog /var/log/auth.log /var/log/kern.log; do
    [[ -f "$lf" ]] || continue
    perms=$(stat -c "%a" "$lf" 2>/dev/null)
    if [[ "$perms" == "640" || "$perms" == "600" ]]; then
        pass "$lf permissions = $perms" "Appropriate log file permissions"
    else
        warn_check "$lf permissions = $perms (recommend 640)" "chmod 640 $lf"
    fi
done

# 7.4 journald persistent logging
if grep -q "^Storage=persistent" /etc/systemd/journald.conf 2>/dev/null; then
    pass "journald persistent storage enabled" "Logs survive reboots"
else
    warn_check "journald not set to persistent storage" "Add Storage=persistent to /etc/systemd/journald.conf"
fi

# =============================================================
#  8. CRON & AT
# =============================================================
section "8. Cron & AT Scheduling"

# 8.1 cron.allow / cron.deny
if [[ -f /etc/cron.allow ]]; then
    pass "/etc/cron.allow exists" "Only users in allow list can use cron"
else
    warn_check "/etc/cron.allow does not exist" "Create it to restrict cron access to specific users"
fi

# 8.2 Cron file permissions
for f in /etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
    [[ -e "$f" ]] || continue
    perms=$(stat -c "%a" "$f" 2>/dev/null)
    owner=$(stat -c "%U" "$f" 2>/dev/null)
    if [[ "$owner" == "root" ]]; then
        pass "$f owned by root" ""
    else
        fail "$f not owned by root (owner: $owner)" "chown root:root $f"
    fi
done

# =============================================================
#  9. SYSTEM MAINTENANCE
# =============================================================
section "9. System & Services"

# 9.1 Core dumps disabled
core_pattern=$(sysctl kernel.core_pattern 2>/dev/null | awk '{print $3}' || echo "?")
core_size=$(ulimit -c 2>/dev/null || echo "?")
if [[ "$core_size" == "0" ]] || grep -q "^hard core 0" /etc/security/limits.conf 2>/dev/null; then
    pass "Core dumps disabled" "Prevents sensitive data in core files"
else
    warn_check "Core dumps not explicitly disabled" "Add '* hard core 0' to /etc/security/limits.conf"
fi

# 9.2 ASLR enabled
aslr=$(sysctl kernel.randomize_va_space 2>/dev/null | awk '{print $3}' || echo "?")
if [[ "$aslr" == "2" ]]; then
    pass "ASLR enabled (kernel.randomize_va_space=2)" "Full address space randomization"
elif [[ "$aslr" == "1" ]]; then
    warn_check "ASLR partial (kernel.randomize_va_space=1)" "Set kernel.randomize_va_space=2 in /etc/sysctl.conf"
else
    fail "ASLR disabled (kernel.randomize_va_space=$aslr)" "Set kernel.randomize_va_space=2 in /etc/sysctl.conf"
fi

# 9.3 NTP/timesyncd
if systemctl is-active systemd-timesyncd &>/dev/null 2>&1 || \
   systemctl is-active ntp &>/dev/null 2>&1 || \
   systemctl is-active chrony &>/dev/null 2>&1; then
    pass "Time synchronization active" "NTP/timesyncd running"
else
    fail "No time synchronization service running" "Enable: systemctl enable --now systemd-timesyncd"
fi

# 9.4 Unnecessary services
for svc in avahi-daemon cups isc-dhcp-server ldap vsftpd apache2 nginx; do
    if systemctl is-active "$svc" &>/dev/null 2>&1; then
        warn_check "Service '$svc' is running" "Disable if not needed: systemctl disable --now $svc"
    fi
done

# 9.5 SUID/SGID binaries check
suid_count=$(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | wc -l)
if [[ "$suid_count" -le 30 ]]; then
    pass "$suid_count SUID/SGID binaries found (≤30)" "Reasonable number"
elif [[ "$suid_count" -le 60 ]]; then
    warn_check "$suid_count SUID/SGID binaries found" "Review: find / -xdev -perm -4000 -type f"
else
    fail "$suid_count SUID/SGID binaries found (>60)" "Review and remove unnecessary SUID bits"
fi

# =============================================================
#  SCORE CALCULATION
# =============================================================
total=$((PASS + FAIL + WARN + INFO_COUNT))
score=0
[[ $total -gt 0 ]] && score=$(( (PASS * 100) / total ))

section "RESULTS"
echo -e "  ${GREEN}PASS${RESET} : $PASS"
echo -e "  ${RED}FAIL${RESET} : $FAIL"
echo -e "  ${YELLOW}WARN${RESET} : $WARN"
echo -e "  ${CYAN}INFO${RESET} : $INFO_COUNT"
echo -e "  ${BOLD}Score: ${score}% (${PASS}/${total})${RESET}"

grade="F"
grade_color="#c0392b"
[[ $score -ge 50 ]] && grade="D" && grade_color="#e67e22"
[[ $score -ge 60 ]] && grade="C" && grade_color="#d4ac0d"
[[ $score -ge 70 ]] && grade="B" && grade_color="#2e86c1"
[[ $score -ge 80 ]] && grade="B+" && grade_color="#1e8449"
[[ $score -ge 90 ]] && grade="A" && grade_color="#1a5e20"
[[ $score -ge 95 ]] && grade="A+" && grade_color="#0d6e3b"

# =============================================================
#  GENERATE HTML REPORT
# =============================================================
result_rows=""
for entry in "${RESULTS[@]}"; do
    IFS='|' read -r status check fix <<< "$entry"
    case "$status" in
        PASS) badge="<span class='badge b-green'>✔ PASS</span>"; row_style="" ;;
        FAIL) badge="<span class='badge b-red'>✘ FAIL</span>";   row_style="border-left:4px solid #c0392b;" ;;
        WARN) badge="<span class='badge b-orange'>⚠ WARN</span>"; row_style="border-left:4px solid #e67e22;" ;;
        INFO) badge="<span class='badge b-blue'>ℹ INFO</span>";   row_style="" ;;
    esac
    result_rows+="<tr style='$row_style'><td>$badge</td><td>$check</td><td style='font-size:11px;color:#555'>$fix</td></tr>"
done

cat > "$HTML_FILE" <<HTML
<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>
body{font-family:Segoe UI,Arial,sans-serif;background:#f4f6f9;padding:20px}
.container{max-width:1100px;margin:auto;background:white;border-radius:10px;box-shadow:0 4px 15px rgba(0,0,0,.12);overflow:hidden}
.header{background:linear-gradient(135deg,${grade_color},#1a252f);color:white;padding:30px}
.header h1{margin:0;font-size:24px}.header p{margin:5px 0 0;opacity:.85;font-size:14px}
.grade-box{display:inline-block;background:rgba(255,255,255,.2);border-radius:12px;padding:10px 25px;margin-top:10px}
.grade{font-size:48px;font-weight:bold}.grade-sub{font-size:14px;opacity:.9}
.content{padding:25px}
.stats{display:flex;gap:15px;margin-bottom:25px;flex-wrap:wrap}
.stat{flex:1;min-width:100px;border-radius:8px;padding:14px;text-align:center}
.stat .num{font-size:28px;font-weight:bold}.stat .lbl{font-size:11px;margin-top:4px}
.s-red{background:#fdedec;border-top:4px solid #c0392b;color:#7b241c}
.s-orange{background:#fef5e7;border-top:4px solid #e67e22;color:#7d4e1a}
.s-green{background:#eafaf1;border-top:4px solid #1e8449;color:#1a5e20}
.s-blue{background:#eaf4fb;border-top:4px solid #2e86c1}
.progress-bar{background:#e0e0e0;border-radius:10px;height:20px;overflow:hidden;margin:10px 0}
.progress-fill{height:20px;border-radius:10px;background:${grade_color};transition:width .3s;display:flex;align-items:center;justify-content:center;color:white;font-size:12px;font-weight:bold}
h2{font-size:16px;color:#2c3e50;border-bottom:2px solid #eee;padding-bottom:8px;margin-top:28px}
table{width:100%;border-collapse:collapse;font-size:13px;margin-bottom:20px}
th{background:#2c3e50;color:white;padding:10px 12px;text-align:left}
td{padding:9px 12px;border-bottom:1px solid #f0f0f0;vertical-align:top}
tr:hover td{background:#f5f8ff}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:bold;color:white;white-space:nowrap}
.b-red{background:#c0392b}.b-orange{background:#e67e22}.b-green{background:#1e8449}.b-blue{background:#2e86c1}
.footer{background:#f4f6f9;padding:15px 25px;font-size:12px;color:#888;border-top:1px solid #e0e0e0}
</style></head><body>
<div class="container">
<div class="header">
  <h1>🛡️ CIS Benchmark Report</h1>
  <p>Host: <strong>$(hostname -f)</strong> &nbsp;|&nbsp; OS: $(lsb_release -ds 2>/dev/null || uname -a) &nbsp;|&nbsp; $(date)</p>
  <div class="grade-box">
    <div class="grade">${grade}</div>
    <div class="grade-sub">${score}% (${PASS}/${total} checks passed)</div>
  </div>
</div>
<div class="content">
<div class="progress-bar"><div class="progress-fill" style="width:${score}%">${score}%</div></div>
<div class="stats">
  <div class="stat s-green"><div class="num">$PASS</div><div class="lbl">Passed</div></div>
  <div class="stat s-red"><div class="num">$FAIL</div><div class="lbl">Failed</div></div>
  <div class="stat s-orange"><div class="num">$WARN</div><div class="lbl">Warnings</div></div>
  <div class="stat s-blue"><div class="num">$INFO_COUNT</div><div class="lbl">Info</div></div>
</div>

<h2>📋 All Check Results</h2>
<table>
  <tr><th style="width:80px">Result</th><th>Check</th><th>Remediation / Notes</th></tr>
  ${result_rows}
</table>
</div>
<div class="footer">CIS Ubuntu Benchmark Checker &nbsp;|&nbsp; $(date) &nbsp;|&nbsp; Not a complete CIS audit — key Level 1 & 2 controls only</div>
</div></body></html>
HTML

[[ -n "$MAIL_TO" ]] && command -v mail &>/dev/null && \
    mail -s "$MAIL_SUBJECT" -a "Content-Type: text/html" "$MAIL_TO" < "$HTML_FILE"

echo ""
echo "  HTML report: $HTML_FILE"
echo "  Grade: $grade ($score%)"
echo ""
