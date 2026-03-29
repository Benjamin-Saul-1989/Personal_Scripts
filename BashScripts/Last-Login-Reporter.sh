#!/usr/bin/env bash
# =============================================================
#  LAST LOGIN REPORTER
#  Flags inactive accounts and reports login history
#  Run as: sudo bash 02-last-login-reporter.sh
# =============================================================

set -euo pipefail

# =============================================================
#  CONFIGURATION
# =============================================================
REPORT_DIR="/var/log/admin-reports/last-login"
REPORT_FILE="${REPORT_DIR}/last-login-$(date +%Y%m%d_%H%M%S).html"

# Flag accounts inactive longer than this many days
INACTIVE_DAYS=90
# Flag accounts never logged in
FLAG_NEVER_LOGIN=true
# Minimum UID to check (skip system accounts)
MIN_UID=1000
# System accounts to always skip
SKIP_USERS=("nobody" "nologin" "sync" "halt" "shutdown")

MAIL_TO=""
MAIL_SUBJECT="Last Login Report - $(hostname) - $(date +%Y-%m-%d)"

# =============================================================
#  COLOUR CODES
# =============================================================
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
alert()   { echo -e "${RED}[ALERT]${RESET} $*"; }
ok()      { echo -e "${GREEN}[OK]${RESET}    $*"; }
section() { echo -e "\n${BOLD}=== $* ===${RESET}"; }

[[ $EUID -eq 0 ]] || { echo "Run as root: sudo $0"; exit 1; }
mkdir -p "$REPORT_DIR"

# =============================================================
#  COLLECT USER DATA
# =============================================================
section "Collecting user login data..."

declare -a INACTIVE_USERS
declare -a NEVER_LOGGED
declare -a ACTIVE_USERS
declare -a LOCKED_USERS

NOW_EPOCH=$(date +%s)

while IFS=: read -r username _ uid gid gecos home shell; do
    # Skip system accounts
    [[ "$uid" -lt "$MIN_UID" ]] && continue
    skip=false
    for s in "${SKIP_USERS[@]}"; do [[ "$username" == "$s" ]] && skip=true; done
    $skip && continue
    [[ "$shell" =~ nologin|false|sync|halt ]] && continue

    # Check if account is locked
    locked=false
    pw_status=$(passwd -S "$username" 2>/dev/null | awk '{print $2}' || echo "?")
    [[ "$pw_status" == "L" || "$pw_status" == "LK" ]] && locked=true

    # Get last login info
    last_entry=$(lastlog -u "$username" 2>/dev/null | tail -1)
    last_login_str=$(echo "$last_entry" | awk '{if ($4=="**Never") print "Never"; else print $4,$5,$6,$9}')

    days_inactive=0
    if [[ "$last_login_str" == "Never" || "$last_login_str" =~ \*\*Never ]]; then
        last_login_str="Never"
        days_inactive=99999
    else
        last_epoch=$(date -d "$last_login_str" +%s 2>/dev/null || echo 0)
        if [[ "$last_epoch" -gt 0 ]]; then
            days_inactive=$(( (NOW_EPOCH - last_epoch) / 86400 ))
        fi
    fi

    # Password expiry info
    pw_expires=$(chage -l "$username" 2>/dev/null | grep "Password expires" | cut -d: -f2 | xargs || echo "N/A")
    acct_expires=$(chage -l "$username" 2>/dev/null | grep "Account expires" | cut -d: -f2 | xargs || echo "N/A")

    entry="${username}|${uid}|${home}|${last_login_str}|${days_inactive}|${locked}|${pw_expires}|${acct_expires}"

    if $locked; then
        LOCKED_USERS+=("$entry")
        info "Locked account: $username"
    elif [[ "$last_login_str" == "Never" ]]; then
        NEVER_LOGGED+=("$entry")
        warn "Never logged in: $username"
    elif [[ "$days_inactive" -ge "$INACTIVE_DAYS" ]]; then
        INACTIVE_USERS+=("$entry")
        alert "Inactive ($days_inactive days): $username"
    else
        ACTIVE_USERS+=("$entry")
        ok "Active: $username (last: $last_login_str, $days_inactive days ago)"
    fi

done < /etc/passwd

# =============================================================
#  RECENT LOGINS (last 30 events)
# =============================================================
section "Recent login events..."
RECENT_LOGINS=$(last -n 30 -F 2>/dev/null | head -32 || last -n 30 | head -32)

# =============================================================
#  FAILED LOGINS TODAY
# =============================================================
FAILED_TODAY=$(grep "Failed password\|authentication failure" /var/log/auth.log 2>/dev/null | \
    grep "$(date '+%b %_d')" | wc -l || echo 0)

# =============================================================
#  BUILD HTML REPORT
# =============================================================
total_inactive=${#INACTIVE_USERS[@]}
total_never=${#NEVER_LOGGED[@]}
total_active=${#ACTIVE_USERS[@]}
total_locked=${#LOCKED_USERS[@]}

header_color="#1e8449"
[[ $total_inactive -gt 0 || $total_never -gt 0 ]] && header_color="#e67e22"

badge_days() {
    local d=$1
    if [[ "$d" -ge 99999 ]]; then echo "<span class='badge b-gray'>Never</span>"
    elif [[ "$d" -ge 180 ]]; then echo "<span class='badge b-red'>${d}d ago</span>"
    elif [[ "$d" -ge 90 ]];  then echo "<span class='badge b-orange'>${d}d ago</span>"
    elif [[ "$d" -ge 30 ]];  then echo "<span class='badge b-yellow'>${d}d ago</span>"
    else echo "<span class='badge b-green'>${d}d ago</span>"
    fi
}

build_user_rows() {
    local -n arr=$1
    local rows=""
    for entry in "${arr[@]}"; do
        IFS='|' read -r uname uid home last days locked pwexp acctexp <<< "$entry"
        local lock_badge=""
        [[ "$locked" == "true" ]] && lock_badge="<span class='badge b-red'>LOCKED</span>"
        local days_badge
        days_badge=$(badge_days "$days")
        rows+="<tr><td><strong>$uname</strong></td><td>$uid</td><td>$home</td><td>$last</td><td>$days_badge</td><td>$lock_badge</td><td>$pwexp</td></tr>"
    done
    echo "$rows"
}

recent_rows=""
while IFS= read -r line; do
    [[ "$line" =~ ^$ ]] && continue
    [[ "$line" =~ ^wtmp ]] && continue
    recent_rows+="<tr><td style='font-family:monospace;font-size:12px;'>$(echo "$line" | sed 's/&/\&amp;/g;s/</\&lt;/g')</td></tr>"
done <<< "$RECENT_LOGINS"

cat > "$REPORT_FILE" <<HTML
<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>
body{font-family:Segoe UI,Arial,sans-serif;background:#f4f6f9;padding:20px}
.container{max-width:1100px;margin:auto;background:white;border-radius:10px;box-shadow:0 4px 15px rgba(0,0,0,.12);overflow:hidden}
.header{background:linear-gradient(135deg,${header_color},#1a252f);color:white;padding:30px}
.header h1{margin:0;font-size:24px}.header p{margin:5px 0 0;opacity:.85;font-size:14px}
.content{padding:25px}
.stats{display:flex;gap:15px;margin-bottom:25px;flex-wrap:wrap}
.stat{flex:1;min-width:120px;border-radius:8px;padding:16px;text-align:center}
.stat .num{font-size:32px;font-weight:bold}.stat .lbl{font-size:12px;margin-top:4px}
.s-red{background:#fdedec;border-top:4px solid #c0392b;color:#7b241c}
.s-orange{background:#fef5e7;border-top:4px solid #e67e22;color:#7d4e1a}
.s-green{background:#eafaf1;border-top:4px solid #1e8449;color:#1a5e20}
.s-blue{background:#eaf4fb;border-top:4px solid #2e86c1}
.s-gray{background:#f2f3f4;border-top:4px solid #7f8c8d}
h2{font-size:16px;color:#2c3e50;border-bottom:2px solid #eee;padding-bottom:8px;margin-top:28px}
table{width:100%;border-collapse:collapse;font-size:13px;margin-bottom:20px}
th{background:#2c3e50;color:white;padding:10px 12px;text-align:left}
td{padding:9px 12px;border-bottom:1px solid #f0f0f0;vertical-align:middle}
tr:hover td{background:#f5f8ff}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:bold;color:white}
.b-red{background:#c0392b}.b-orange{background:#e67e22}.b-yellow{background:#d4ac0d;color:#333}
.b-green{background:#1e8449}.b-gray{background:#7f8c8d}
.alert-box{background:#fef9e7;border:1px solid #e67e22;border-radius:8px;padding:14px 18px;margin-bottom:20px;color:#7d6608}
.footer{background:#f4f6f9;padding:15px 25px;font-size:12px;color:#888;border-top:1px solid #e0e0e0}
</style></head><body>
<div class="container">
<div class="header">
  <h1>👤 Last Login Report</h1>
  <p>Host: <strong>$(hostname -f)</strong> &nbsp;|&nbsp; Inactive threshold: ${INACTIVE_DAYS} days &nbsp;|&nbsp; $(date)</p>
</div>
<div class="content">
$([ $((total_inactive + total_never)) -gt 0 ] && echo "<div class='alert-box'>⚠️ $total_inactive inactive account(s) and $total_never account(s) that have never logged in detected.</div>")
<div class="stats">
  <div class="stat s-blue"><div class="num">$((total_active+total_inactive+total_never+total_locked))</div><div class="lbl">Total Accounts</div></div>
  <div class="stat s-green"><div class="num">$total_active</div><div class="lbl">Active</div></div>
  <div class="stat s-orange"><div class="num">$total_inactive</div><div class="lbl">Inactive >${INACTIVE_DAYS}d</div></div>
  <div class="stat s-red"><div class="num">$total_never</div><div class="lbl">Never Logged In</div></div>
  <div class="stat s-gray"><div class="num">$total_locked</div><div class="lbl">Locked</div></div>
  <div class="stat s-red"><div class="num">$FAILED_TODAY</div><div class="lbl">Failed Logins Today</div></div>
</div>

<h2>⚠️ Inactive Accounts (>${INACTIVE_DAYS} days)</h2>
<table><tr><th>Username</th><th>UID</th><th>Home</th><th>Last Login</th><th>Inactive</th><th>Status</th><th>Password Expires</th></tr>
$(build_user_rows INACTIVE_USERS)
$([ $total_inactive -eq 0 ] && echo "<tr><td colspan='7' style='text-align:center;color:#1e8449;'>✅ No inactive accounts</td></tr>")
</table>

<h2>🚫 Never Logged In</h2>
<table><tr><th>Username</th><th>UID</th><th>Home</th><th>Last Login</th><th>Inactive</th><th>Status</th><th>Password Expires</th></tr>
$(build_user_rows NEVER_LOGGED)
$([ $total_never -eq 0 ] && echo "<tr><td colspan='7' style='text-align:center;color:#1e8449;'>✅ All accounts have logged in</td></tr>")
</table>

<h2>✅ Active Accounts</h2>
<table><tr><th>Username</th><th>UID</th><th>Home</th><th>Last Login</th><th>Inactive</th><th>Status</th><th>Password Expires</th></tr>
$(build_user_rows ACTIVE_USERS)
</table>

<h2>🔒 Locked Accounts</h2>
<table><tr><th>Username</th><th>UID</th><th>Home</th><th>Last Login</th><th>Inactive</th><th>Status</th><th>Password Expires</th></tr>
$(build_user_rows LOCKED_USERS)
$([ $total_locked -eq 0 ] && echo "<tr><td colspan='7' style='text-align:center;color:#888;'>No locked accounts</td></tr>")
</table>

<h2>📋 Recent Login Events (last 30)</h2>
<table><tr><th>Entry</th></tr>
${recent_rows}
</table>

</div>
<div class="footer">Generated by last-login-reporter.sh &nbsp;|&nbsp; $(date) &nbsp;|&nbsp; Inactive threshold: ${INACTIVE_DAYS} days</div>
</div></body></html>
HTML

# =============================================================
#  EMAIL
# =============================================================
if [[ -n "$MAIL_TO" ]] && command -v mail &>/dev/null; then
    mail -s "$MAIL_SUBJECT" -a "Content-Type: text/html" "$MAIL_TO" < "$REPORT_FILE"
fi

# =============================================================
#  SUMMARY
# =============================================================
section "COMPLETE"
echo "  Report : $REPORT_FILE"
echo ""
[[ $total_inactive -gt 0 ]] && warn "$total_inactive inactive account(s) found"
[[ $total_never -gt 0 ]]    && warn "$total_never account(s) never logged in"
[[ $total_inactive -eq 0 && $total_never -eq 0 ]] && ok "No inactive accounts detected"
echo ""
