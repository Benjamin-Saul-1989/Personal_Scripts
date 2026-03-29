#!/usr/bin/env bash
# =============================================================
#  FAILED SSH LOGIN TRACKER WITH GEO-LOOKUP
#  Parses auth.log for failed SSH attempts, geolocates IPs,
#  and generates an HTML threat report
#  Run as: sudo bash 04-failed-ssh-tracker.sh
# =============================================================

set -euo pipefail

# =============================================================
#  CONFIGURATION
# =============================================================
REPORT_DIR="/var/log/admin-reports/ssh-failures"
HTML_FILE="${REPORT_DIR}/ssh-failures-$(date +%Y%m%d_%H%M%S).html"
AUTH_LOG="/var/log/auth.log"
SYSLOG="/var/log/syslog"
HOURS_BACK=24            # How many hours of logs to analyse
TOP_N=20                 # Show top N attacking IPs
GEO_LOOKUP=true          # Use ip-api.com for geolocation (free, rate-limited)
GEO_BATCH_LIMIT=50       # Max IPs to geolocate (avoid rate limits)
AUTO_BLOCK=false         # Set true to auto-add top offenders to ufw deny
AUTO_BLOCK_THRESHOLD=20  # Block IPs with this many attempts or more
MAIL_TO=""
MAIL_SUBJECT="Failed SSH Report - $(hostname) - $(date +%Y-%m-%d)"

# =============================================================
#  COLOURS
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
#  FIND AUTH LOG
# =============================================================
LOG_FILE=""
for f in "$AUTH_LOG" "/var/log/secure" "/var/log/auth.log.1"; do
    [[ -f "$f" ]] && LOG_FILE="$f" && break
done

# Also check journalctl
USE_JOURNALCTL=false
if [[ -z "$LOG_FILE" ]] && command -v journalctl &>/dev/null; then
    USE_JOURNALCTL=true
    info "Using journalctl for log data"
fi

section "Parsing SSH failure logs..."

# =============================================================
#  EXTRACT FAILED ATTEMPTS
# =============================================================
TMP_FAILS=$(mktemp)

if $USE_JOURNALCTL; then
    journalctl -u ssh -u sshd --since "${HOURS_BACK} hours ago" 2>/dev/null | \
        grep -E "Failed password|Invalid user|Connection closed|authentication failure" > "$TMP_FAILS" || true
else
    # Calculate cutoff time for log parsing
    cutoff=$(date -d "${HOURS_BACK} hours ago" '+%b %_d %H' 2>/dev/null || date -v -${HOURS_BACK}H '+%b %_d %H')
    grep -E "Failed password|Invalid user|authentication failure|sshd.*error" "$LOG_FILE" 2>/dev/null > "$TMP_FAILS" || true
fi

total_attempts=$(wc -l < "$TMP_FAILS")
info "Found $total_attempts failed attempts in log"

# =============================================================
#  PARSE IPs AND USERNAMES
# =============================================================
TMP_IPS=$(mktemp)
TMP_USERS=$(mktemp)

# Extract IPs
grep -oP '(\d{1,3}\.){3}\d{1,3}' "$TMP_FAILS" | sort > "$TMP_IPS"
# Extract attempted usernames
grep -oP '(?<=Invalid user |Failed password for (invalid user )?)\w+' "$TMP_FAILS" | \
    sort | uniq -c | sort -rn > "$TMP_USERS" || true

# Count per IP
declare -A IP_COUNTS
while IFS= read -r ip; do
    IP_COUNTS["$ip"]=$(( ${IP_COUNTS["$ip"]:-0} + 1 ))
done < "$TMP_IPS"

# Sort IPs by count
declare -a SORTED_IPS
mapfile -t SORTED_IPS < <(
    for ip in "${!IP_COUNTS[@]}"; do
        echo "${IP_COUNTS[$ip]} $ip"
    done | sort -rn | head -"$TOP_N" | awk '{print $2}'
)

total_unique_ips=${#IP_COUNTS[@]}
info "Unique attacking IPs: $total_unique_ips"

# =============================================================
#  GEO-LOOKUP
# =============================================================
declare -A GEO_DATA  # ip -> "country|city|isp|lat|lon"

if $GEO_LOOKUP && [[ ${#SORTED_IPS[@]} -gt 0 ]]; then
    section "Geolocating IPs (up to $GEO_BATCH_LIMIT)..."

    # Build batch query for ip-api.com (free, max 100/min)
    count=0
    batch_ips="["
    for ip in "${SORTED_IPS[@]}"; do
        [[ $count -ge $GEO_BATCH_LIMIT ]] && break
        batch_ips+="{\"query\":\"$ip\"},"
        count+=1
    done
    batch_ips="${batch_ips%,}]"

    if command -v curl &>/dev/null; then
        geo_response=$(curl -s --max-time 15 \
            -H "Content-Type: application/json" \
            -d "$batch_ips" \
            "http://ip-api.com/batch?fields=status,query,country,city,isp,lat,lon,org" 2>/dev/null || echo "[]")

        # Parse JSON manually (no jq dependency)
        while IFS= read -r line; do
            ip=$(echo "$line"    | grep -oP '"query":"\K[^"]+' || echo "")
            country=$(echo "$line" | grep -oP '"country":"\K[^"]+' || echo "Unknown")
            city=$(echo "$line"    | grep -oP '"city":"\K[^"]+' || echo "Unknown")
            isp=$(echo "$line"     | grep -oP '"isp":"\K[^"]+' || echo "Unknown")
            [[ -n "$ip" ]] && GEO_DATA["$ip"]="${country}|${city}|${isp}"
            info "  $ip → $city, $country ($isp)"
        done < <(echo "$geo_response" | grep -oP '\{[^}]+\}' || true)
    else
        warn "curl not found — skipping geolocation"
    fi
fi

# =============================================================
#  AUTO-BLOCK (optional)
# =============================================================
declare -a BLOCKED_IPS
if $AUTO_BLOCK && command -v ufw &>/dev/null; then
    section "Auto-blocking top offenders..."
    for ip in "${SORTED_IPS[@]}"; do
        count=${IP_COUNTS[$ip]:-0}
        if [[ $count -ge $AUTO_BLOCK_THRESHOLD ]]; then
            if ufw deny from "$ip" to any 2>/dev/null; then
                BLOCKED_IPS+=("$ip")
                alert "Blocked: $ip ($count attempts)"
            fi
        fi
    done
fi

# =============================================================
#  TOP TARGETED USERNAMES
# =============================================================
declare -a TOP_USERS
while IFS= read -r line; do
    count=$(echo "$line" | awk '{print $1}')
    user=$(echo "$line"  | awk '{print $2}')
    TOP_USERS+=("$count|$user")
done < <(head -15 "$TMP_USERS" || true)

# =============================================================
#  HOURLY DISTRIBUTION
# =============================================================
declare -A HOURLY
if [[ -f "$LOG_FILE" ]]; then
    while IFS= read -r line; do
        hour=$(echo "$line" | grep -oP '(?<=T| )\d{2}(?=:\d{2}:\d{2})' | head -1 || echo "")
        [[ -z "$hour" ]] && continue
        HOURLY["$hour"]=$(( ${HOURLY["$hour"]:-0} + 1 ))
    done < "$TMP_FAILS"
fi

# =============================================================
#  BUILD HTML REPORT
# =============================================================
ip_rows=""
for ip in "${SORTED_IPS[@]}"; do
    count=${IP_COUNTS[$ip]:-0}
    geo="${GEO_DATA[$ip]:-Unknown|Unknown|Unknown}"
    IFS='|' read -r country city isp <<< "$geo"

    is_blocked=false
    for b in "${BLOCKED_IPS[@]}"; do [[ "$b" == "$ip" ]] && is_blocked=true && break; done

    severity_badge=""
    if [[ $count -ge 100 ]]; then
        severity_badge="<span class='badge b-red'>CRITICAL</span>"
    elif [[ $count -ge 50 ]]; then
        severity_badge="<span class='badge b-orange'>HIGH</span>"
    elif [[ $count -ge 20 ]]; then
        severity_badge="<span class='badge b-yellow'>MEDIUM</span>"
    else
        severity_badge="<span class='badge b-blue'>LOW</span>"
    fi

    block_badge=$($is_blocked && echo "<span class='badge b-red'>BLOCKED</span>" || echo "")

    # Threat bar (visual)
    max_count=${IP_COUNTS[${SORTED_IPS[0]}]:-1}
    pct=$(( count * 100 / max_count ))
    bar="<div style='background:#eee;border-radius:4px;height:8px;width:100%'><div style='background:#c0392b;height:8px;border-radius:4px;width:${pct}%'></div></div>"

    ip_rows+="<tr>
      <td><strong style='font-family:monospace'>$ip</strong> $block_badge</td>
      <td>$severity_badge</td>
      <td style='text-align:right'><strong>$count</strong></td>
      <td>$bar</td>
      <td>$country</td>
      <td>$city</td>
      <td style='font-size:11px;color:#555'>$isp</td>
    </tr>"
done

user_rows=""
for entry in "${TOP_USERS[@]}"; do
    IFS='|' read -r cnt uname <<< "$entry"
    pct_bar=""
    if [[ ${#TOP_USERS[@]} -gt 0 ]]; then
        first_count=$(echo "${TOP_USERS[0]}" | cut -d'|' -f1)
        p=$(( cnt * 100 / (first_count + 1) ))
        pct_bar="<div style='background:#eee;border-radius:4px;height:6px;width:100px;display:inline-block'><div style='background:#e67e22;height:6px;border-radius:4px;width:${p}%'></div></div>"
    fi
    user_rows+="<tr><td><strong>$uname</strong></td><td style='text-align:right'>$cnt</td><td>$pct_bar</td></tr>"
done

blocked_rows=""
for ip in "${BLOCKED_IPS[@]}"; do
    blocked_rows+="<tr><td style='font-family:monospace'>$ip</td><td>${IP_COUNTS[$ip]:-?} attempts</td></tr>"
done

max_att=${IP_COUNTS[${SORTED_IPS[0]:-x}]:-0}
hcolor="#1e8449"
[[ $total_unique_ips -gt 50 ]] && hcolor="#e67e22"
[[ $max_att -ge 100 ]] && hcolor="#c0392b"

cat > "$HTML_FILE" <<HTML
<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>
body{font-family:Segoe UI,Arial,sans-serif;background:#f4f6f9;padding:20px}
.container{max-width:1100px;margin:auto;background:white;border-radius:10px;box-shadow:0 4px 15px rgba(0,0,0,.12);overflow:hidden}
.header{background:linear-gradient(135deg,${hcolor},#1a252f);color:white;padding:30px}
.header h1{margin:0;font-size:24px}.header p{margin:5px 0 0;opacity:.85;font-size:14px}
.content{padding:25px}
.stats{display:flex;gap:15px;margin-bottom:25px;flex-wrap:wrap}
.stat{flex:1;min-width:120px;border-radius:8px;padding:16px;text-align:center}
.stat .num{font-size:32px;font-weight:bold}.stat .lbl{font-size:12px;margin-top:4px}
.s-red{background:#fdedec;border-top:4px solid #c0392b;color:#7b241c}
.s-orange{background:#fef5e7;border-top:4px solid #e67e22;color:#7d4e1a}
.s-green{background:#eafaf1;border-top:4px solid #1e8449;color:#1a5e20}
.s-blue{background:#eaf4fb;border-top:4px solid #2e86c1}
h2{font-size:16px;color:#2c3e50;border-bottom:2px solid #eee;padding-bottom:8px;margin-top:28px}
table{width:100%;border-collapse:collapse;font-size:13px;margin-bottom:20px}
th{background:#2c3e50;color:white;padding:10px 12px;text-align:left}
td{padding:9px 12px;border-bottom:1px solid #f0f0f0;vertical-align:middle}
tr:hover td{background:#f5f8ff}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:bold;color:white;margin:1px}
.b-red{background:#c0392b}.b-orange{background:#e67e22}.b-yellow{background:#d4ac0d;color:#333}
.b-green{background:#1e8449}.b-blue{background:#2e86c1}.b-gray{background:#7f8c8d}
.two-col{display:grid;grid-template-columns:3fr 2fr;gap:20px}
.footer{background:#f4f6f9;padding:15px 25px;font-size:12px;color:#888;border-top:1px solid #e0e0e0}
</style></head><body>
<div class="container">
<div class="header">
  <h1>🛡️ Failed SSH Login Report</h1>
  <p>Host: <strong>$(hostname -f)</strong> &nbsp;|&nbsp; Last ${HOURS_BACK} hours &nbsp;|&nbsp; $(date)</p>
</div>
<div class="content">
<div class="stats">
  <div class="stat s-red"><div class="num">$total_attempts</div><div class="lbl">Total Attempts</div></div>
  <div class="stat s-orange"><div class="num">$total_unique_ips</div><div class="lbl">Unique IPs</div></div>
  <div class="stat s-blue"><div class="num">$max_att</div><div class="lbl">Max from One IP</div></div>
  <div class="stat s-red"><div class="num">${#BLOCKED_IPS[@]}</div><div class="lbl">Auto-Blocked</div></div>
</div>

<div class="two-col">
<div>
<h2>🌐 Top ${TOP_N} Attacking IPs</h2>
<table>
  <tr><th>IP Address</th><th>Severity</th><th>Attempts</th><th>Volume</th><th>Country</th><th>City</th><th>ISP</th></tr>
  ${ip_rows:-<tr><td colspan='7' style='text-align:center;color:#1e8449;'>✅ No failed attempts found</td></tr>}
</table>
</div>
<div>
<h2>👤 Top Targeted Usernames</h2>
<table>
  <tr><th>Username</th><th>Attempts</th><th>Volume</th></tr>
  ${user_rows:-<tr><td colspan='3' style='text-align:center;color:#888;'>No data</td></tr>}
</table>
$([ ${#BLOCKED_IPS[@]} -gt 0 ] && echo "
<h2>🚫 Auto-Blocked IPs</h2>
<table><tr><th>IP</th><th>Reason</th></tr>
${blocked_rows}
</table>")
</div>
</div>

<h2>💡 Hardening Recommendations</h2>
<table><tr><th>Action</th><th>Command / Notes</th></tr>
<tr><td>Disable password auth</td><td><code>PasswordAuthentication no</code> in /etc/ssh/sshd_config</td></tr>
<tr><td>Change SSH port</td><td><code>Port 2222</code> in /etc/ssh/sshd_config (reduces noise)</td></tr>
<tr><td>Install fail2ban</td><td><code>apt install fail2ban</code> — auto-bans repeated failures</td></tr>
<tr><td>Allow only specific users</td><td><code>AllowUsers youruser</code> in /etc/ssh/sshd_config</td></tr>
<tr><td>Block country ranges</td><td>Use ipset + iptables or ufw deny from country ranges</td></tr>
<tr><td>Enable 2FA</td><td><code>apt install libpam-google-authenticator</code></td></tr>
</table>
</div>
<div class="footer">Generated by failed-ssh-tracker.sh &nbsp;|&nbsp; Log: $LOG_FILE &nbsp;|&nbsp; $(date)</div>
</div></body></html>
HTML

rm -f "$TMP_FAILS" "$TMP_IPS" "$TMP_USERS"

[[ -n "$MAIL_TO" ]] && command -v mail &>/dev/null && \
    mail -s "$MAIL_SUBJECT" -a "Content-Type: text/html" "$MAIL_TO" < "$HTML_FILE"

section "COMPLETE"
echo "  Report        : $HTML_FILE"
echo "  Total attempts: $total_attempts from $total_unique_ips unique IPs"
[[ ${#BLOCKED_IPS[@]} -gt 0 ]] && alert "Auto-blocked ${#BLOCKED_IPS[@]} IP(s)"
echo ""
