#!/usr/bin/env bash
# =============================================================
#  FAILED AUTH LOG PARSER & BRUTE-FORCE IP BLOCKER
#  Parses auth logs, identifies brute-force IPs, and optionally
#  blocks them via UFW or /etc/hosts.deny
#  Run as: sudo bash 09-auth-log-blocker.sh
# =============================================================

set -euo pipefail

# =============================================================
#  CONFIGURATION
# =============================================================
REPORT_DIR="/var/log/admin-reports/auth-blocker"
HTML_FILE="${REPORT_DIR}/auth-report-$(date +%Y%m%d_%H%M%S).html"
BLOCK_LOG="${REPORT_DIR}/blocked-ips.log"
WHITELIST_FILE="${REPORT_DIR}/whitelist.txt"

# Blocking settings
BLOCK_THRESHOLD=10       # Block IPs with this many failures
BLOCK_METHOD="ufw"       # "ufw", "hosts.deny", or "iptables", or "dry-run"
HOURS_BACK=24            # Hours of log history to analyse
UNBLOCK_AFTER_DAYS=7     # Auto-remove blocks older than this (0 = never)

# Whitelist — NEVER block these IPs (one per line in $WHITELIST_FILE)
STATIC_WHITELIST=("127.0.0.1" "::1")

# Log file locations
AUTH_LOGS=("/var/log/auth.log" "/var/log/auth.log.1" "/var/log/secure")

MAIL_TO=""
MAIL_SUBJECT="Auth Blocker Report - $(hostname) - $(date +%Y-%m-%d)"

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
touch "$BLOCK_LOG"
[[ ! -f "$WHITELIST_FILE" ]] && touch "$WHITELIST_FILE"

# =============================================================
#  LOAD WHITELIST
# =============================================================
declare -A WHITELIST
for ip in "${STATIC_WHITELIST[@]}"; do WHITELIST["$ip"]=1; done
while IFS= read -r ip; do
    [[ -z "$ip" || "$ip" =~ ^# ]] && continue
    WHITELIST["$ip"]=1
done < "$WHITELIST_FILE"
info "Loaded ${#WHITELIST[@]} whitelisted IPs"

# =============================================================
#  PARSE AUTH LOGS
# =============================================================
section "Parsing authentication logs (last ${HOURS_BACK}h)..."

TMP_COMBINED=$(mktemp)
cutoff_epoch=$( date -d "${HOURS_BACK} hours ago" +%s 2>/dev/null || date -v -${HOURS_BACK}H +%s )

for logfile in "${AUTH_LOGS[@]}"; do
    [[ -f "$logfile" ]] && cat "$logfile" >> "$TMP_COMBINED" && info "Reading: $logfile"
done

if command -v journalctl &>/dev/null && [[ ! -s "$TMP_COMBINED" ]]; then
    journalctl --since "${HOURS_BACK} hours ago" -u ssh -u sshd 2>/dev/null >> "$TMP_COMBINED" || true
fi

total_lines=$(wc -l < "$TMP_COMBINED")
info "Total log lines: $total_lines"

# =============================================================
#  COUNT FAILURES BY IP AND TYPE
# =============================================================
declare -A IP_FAIL_COUNT
declare -A IP_FAIL_TYPES
declare -A IP_USERNAMES

# Patterns to match
while IFS= read -r line; do
    ip=""
    fail_type=""
    username=""

    if [[ "$line" =~ "Failed password for" ]]; then
        ip=$(echo "$line" | grep -oP '(\d{1,3}\.){3}\d{1,3}' | tail -1)
        username=$(echo "$line" | grep -oP '(?<=Failed password for (invalid user )?)\w+' | head -1)
        fail_type="Failed-Password"
    elif [[ "$line" =~ "Invalid user" ]]; then
        ip=$(echo "$line" | grep -oP '(\d{1,3}\.){3}\d{1,3}' | tail -1)
        username=$(echo "$line" | grep -oP '(?<=Invalid user )\w+' | head -1)
        fail_type="Invalid-User"
    elif [[ "$line" =~ "authentication failure" ]]; then
        ip=$(echo "$line" | grep -oP 'rhost=(\d{1,3}\.){3}\d{1,3}' | grep -oP '(\d{1,3}\.){3}\d{1,3}' || echo "")
        fail_type="Auth-Failure"
    elif [[ "$line" =~ "Connection closed by invalid user" ]]; then
        ip=$(echo "$line" | grep -oP '(\d{1,3}\.){3}\d{1,3}' | head -1)
        fail_type="Invalid-User-Closed"
    elif [[ "$line" =~ "BREAK-IN ATTEMPT" ]]; then
        ip=$(echo "$line" | grep -oP '(\d{1,3}\.){3}\d{1,3}' | head -1)
        fail_type="BREAK-IN"
    fi

    [[ -z "$ip" ]] && continue
    [[ -v "WHITELIST[$ip]" ]] && continue

    IP_FAIL_COUNT["$ip"]=$(( ${IP_FAIL_COUNT["$ip"]:-0} + 1 ))
    IP_FAIL_TYPES["$ip"]+="${fail_type} "
    [[ -n "$username" ]] && IP_USERNAMES["$ip"]+="${username} "

done < "$TMP_COMBINED"

rm -f "$TMP_COMBINED"

total_unique_ips=${#IP_FAIL_COUNT[@]}
total_failures=0
for count in "${IP_FAIL_COUNT[@]}"; do total_failures=$((total_failures + count)); done

info "Total failures: $total_failures from $total_unique_ips unique IPs"

# =============================================================
#  SORT IPs BY FAILURE COUNT
# =============================================================
declare -a SORTED_IPS
mapfile -t SORTED_IPS < <(
    for ip in "${!IP_FAIL_COUNT[@]}"; do
        echo "${IP_FAIL_COUNT[$ip]} $ip"
    done | sort -rn | awk '{print $2}'
)

# =============================================================
#  CHECK ALREADY BLOCKED IPs
# =============================================================
is_blocked() {
    local ip="$1"
    case "$BLOCK_METHOD" in
        ufw)
            ufw status 2>/dev/null | grep -q "DENY.*$ip" && return 0
            ;;
        hosts.deny)
            grep -q "$ip" /etc/hosts.deny 2>/dev/null && return 0
            ;;
        iptables)
            iptables -L INPUT -n 2>/dev/null | grep -q "$ip" && return 0
            ;;
    esac
    return 1
}

# =============================================================
#  BLOCK IPs
# =============================================================
block_ip() {
    local ip="$1" count="$2"
    [[ -v "WHITELIST[$ip]" ]] && warn "Skipping whitelisted IP: $ip" && return 1
    is_blocked "$ip" && info "Already blocked: $ip" && return 0

    case "$BLOCK_METHOD" in
        ufw)
            if ufw deny from "$ip" to any comment "auto-blocked: $count failures $(date +%Y-%m-%d)" 2>/dev/null; then
                ok "UFW blocked: $ip ($count failures)"
                echo "$(date '+%Y-%m-%d %H:%M:%S') BLOCKED $ip ($count failures) via ufw" >> "$BLOCK_LOG"
                return 0
            fi
            ;;
        hosts.deny)
            echo "ALL: $ip  # auto-blocked $(date) - $count failures" >> /etc/hosts.deny
            ok "hosts.deny blocked: $ip"
            echo "$(date '+%Y-%m-%d %H:%M:%S') BLOCKED $ip ($count failures) via hosts.deny" >> "$BLOCK_LOG"
            return 0
            ;;
        iptables)
            if iptables -I INPUT -s "$ip" -j DROP 2>/dev/null; then
                ok "iptables blocked: $ip"
                echo "$(date '+%Y-%m-%d %H:%M:%S') BLOCKED $ip ($count failures) via iptables" >> "$BLOCK_LOG"
                return 0
            fi
            ;;
        dry-run)
            warn "[DRY-RUN] Would block: $ip ($count failures)"
            return 0
            ;;
    esac
    return 1
}

# =============================================================
#  PROCESS IPs
# =============================================================
section "Processing IPs (threshold: $BLOCK_THRESHOLD)..."

declare -a NEWLY_BLOCKED ALREADY_BLOCKED BELOW_THRESHOLD

for ip in "${SORTED_IPS[@]}"; do
    count=${IP_FAIL_COUNT[$ip]:-0}
    types="${IP_FAIL_TYPES[$ip]:-}"
    users="${IP_USERNAMES[$ip]:-}"

    if [[ $count -ge $BLOCK_THRESHOLD ]]; then
        if is_blocked "$ip"; then
            ALREADY_BLOCKED+=("$ip|$count|$types|$users|yes")
            info "Already blocked: $ip ($count failures)"
        else
            if block_ip "$ip" "$count"; then
                NEWLY_BLOCKED+=("$ip|$count|$types|$users|new")
            fi
        fi
    else
        BELOW_THRESHOLD+=("$ip|$count|$types|$users|no")
    fi
done

# =============================================================
#  AUTO-UNBLOCK OLD BLOCKS (optional)
# =============================================================
if [[ "$UNBLOCK_AFTER_DAYS" -gt 0 && "$BLOCK_METHOD" == "ufw" ]]; then
    section "Checking for expired blocks..."
    cutoff_block=$(date -d "${UNBLOCK_AFTER_DAYS} days ago" '+%Y-%m-%d')

    while IFS= read -r line; do
        if [[ "$line" =~ BLOCKED.*([0-9]{4}-[0-9]{2}-[0-9]{2}) ]]; then
            block_date="${BASH_REMATCH[1]}"
            block_ip_val=$(echo "$line" | grep -oP '(\d{1,3}\.){3}\d{1,3}' | head -1)
            if [[ "$block_date" < "$cutoff_block" && -n "$block_ip_val" ]]; then
                ufw delete deny from "$block_ip_val" to any 2>/dev/null && \
                    info "Auto-unblocked expired block: $block_ip_val (blocked $block_date)"
            fi
        fi
    done < "$BLOCK_LOG"
fi

# =============================================================
#  BUILD HTML REPORT
# =============================================================
build_ip_rows() {
    local -n arr=$1
    local rows=""
    for entry in "${arr[@]}"; do
        IFS='|' read -r ip count types users status <<< "$entry"
        # Unique type badges
        local type_badges=""
        for t in $(echo "$types" | tr ' ' '\n' | sort -u | head -5); do
            [[ -z "$t" ]] && continue
            case "$t" in
                *BREAK*) type_badges+="<span class='badge b-red'>$t</span> " ;;
                *Invalid*) type_badges+="<span class='badge b-orange'>$t</span> " ;;
                *) type_badges+="<span class='badge b-blue'>$t</span> " ;;
            esac
        done
        # Top usernames
        local top_users
        top_users=$(echo "$users" | tr ' ' '\n' | sort | uniq -c | sort -rn | head -3 | awk '{print $2"("$1")"}' | tr '\n' ' ')

        local status_badge
        case "$status" in
            new)  status_badge="<span class='badge b-red'>🚫 NEWLY BLOCKED</span>" ;;
            yes)  status_badge="<span class='badge b-orange'>Already Blocked</span>" ;;
            no)   status_badge="<span class='badge b-gray'>Below Threshold</span>" ;;
            *) status_badge="" ;;
        esac

        rows+="<tr><td><strong style='font-family:monospace'>$ip</strong></td><td style='text-align:right;font-weight:bold;color:#c0392b'>$count</td><td>$type_badges</td><td style='font-size:11px'>$top_users</td><td>$status_badge</td></tr>"
    done
    echo "$rows"
}

# Recent block log entries
log_rows=""
while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    log_rows+="<tr><td style='font-family:monospace;font-size:11px'>$(echo "$line" | sed 's/&/\&amp;/g')</td></tr>"
done < <(tail -20 "$BLOCK_LOG" 2>/dev/null | tac || true)

hcolor="#1e8449"
[[ ${#NEWLY_BLOCKED[@]} -gt 0 ]] && hcolor="#c0392b"
[[ ${#NEWLY_BLOCKED[@]} -eq 0 && ${#ALREADY_BLOCKED[@]} -gt 0 ]] && hcolor="#e67e22"

cat > "$HTML_FILE" <<HTML
<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>
body{font-family:Segoe UI,Arial,sans-serif;background:#f4f6f9;padding:20px}
.container{max-width:1050px;margin:auto;background:white;border-radius:10px;box-shadow:0 4px 15px rgba(0,0,0,.12);overflow:hidden}
.header{background:linear-gradient(135deg,${hcolor},#1a252f);color:white;padding:30px}
.header h1{margin:0;font-size:24px}.header p{margin:5px 0 0;opacity:.85;font-size:14px}
.content{padding:25px}
.stats{display:flex;gap:15px;margin-bottom:25px;flex-wrap:wrap}
.stat{flex:1;min-width:110px;border-radius:8px;padding:14px;text-align:center}
.stat .num{font-size:28px;font-weight:bold}.stat .lbl{font-size:11px;margin-top:4px}
.s-red{background:#fdedec;border-top:4px solid #c0392b;color:#7b241c}
.s-orange{background:#fef5e7;border-top:4px solid #e67e22;color:#7d4e1a}
.s-green{background:#eafaf1;border-top:4px solid #1e8449;color:#1a5e20}
.s-blue{background:#eaf4fb;border-top:4px solid #2e86c1}
h2{font-size:15px;color:#2c3e50;border-bottom:2px solid #eee;padding-bottom:7px;margin-top:24px}
table{width:100%;border-collapse:collapse;font-size:13px;margin-bottom:15px}
th{background:#2c3e50;color:white;padding:9px 12px;text-align:left}
td{padding:8px 12px;border-bottom:1px solid #f0f0f0;vertical-align:middle}
tr:hover td{background:#f5f8ff}
.badge{display:inline-block;padding:2px 7px;border-radius:10px;font-size:10px;font-weight:bold;color:white;margin:1px}
.b-red{background:#c0392b}.b-orange{background:#e67e22}.b-green{background:#1e8449}
.b-blue{background:#2e86c1}.b-gray{background:#7f8c8d}
.footer{background:#f4f6f9;padding:15px 25px;font-size:12px;color:#888;border-top:1px solid #e0e0e0}
</style></head><body>
<div class="container">
<div class="header">
  <h1>🚫 Auth Log Blocker Report</h1>
  <p>Host: <strong>$(hostname -f)</strong> &nbsp;|&nbsp; Block method: <strong>$BLOCK_METHOD</strong> &nbsp;|&nbsp; Threshold: <strong>$BLOCK_THRESHOLD</strong> failures &nbsp;|&nbsp; $(date)</p>
</div>
<div class="content">
<div class="stats">
  <div class="stat s-red"><div class="num">$total_failures</div><div class="lbl">Total Failures</div></div>
  <div class="stat s-orange"><div class="num">$total_unique_ips</div><div class="lbl">Unique IPs</div></div>
  <div class="stat s-red"><div class="num">${#NEWLY_BLOCKED[@]}</div><div class="lbl">Newly Blocked</div></div>
  <div class="stat s-orange"><div class="num">${#ALREADY_BLOCKED[@]}</div><div class="lbl">Already Blocked</div></div>
  <div class="stat s-blue"><div class="num">${#BELOW_THRESHOLD[@]}</div><div class="lbl">Below Threshold</div></div>
</div>

<h2>🚫 Newly Blocked IPs</h2>
<table><tr><th>IP Address</th><th>Failures</th><th>Attack Types</th><th>Top Usernames</th><th>Status</th></tr>
$(build_ip_rows NEWLY_BLOCKED)
$([ ${#NEWLY_BLOCKED[@]} -eq 0 ] && echo "<tr><td colspan='5' style='text-align:center;color:#1e8449;padding:15px'>✅ No new blocks this run</td></tr>")
</table>

<h2>⚠️ Already-Blocked IPs (Still Attacking)</h2>
<table><tr><th>IP Address</th><th>Failures</th><th>Attack Types</th><th>Top Usernames</th><th>Status</th></tr>
$(build_ip_rows ALREADY_BLOCKED)
$([ ${#ALREADY_BLOCKED[@]} -eq 0 ] && echo "<tr><td colspan='5' style='text-align:center;color:#888;padding:15px'>None</td></tr>")
</table>

<h2>📊 Below Threshold (Watching)</h2>
<table><tr><th>IP Address</th><th>Failures</th><th>Attack Types</th><th>Top Usernames</th><th>Status</th></tr>
$(build_ip_rows BELOW_THRESHOLD)
$([ ${#BELOW_THRESHOLD[@]} -eq 0 ] && echo "<tr><td colspan='5' style='text-align:center;color:#888;padding:15px'>None</td></tr>")
</table>

<h2>📋 Recent Block Log</h2>
<table><tr><th>Entry</th></tr>
${log_rows:-<tr><td style='text-align:center;color:#888'>No block log entries</td></tr>}
</table>
</div>
<div class="footer">Generated by auth-log-blocker.sh &nbsp;|&nbsp; Block log: $BLOCK_LOG &nbsp;|&nbsp; Whitelist: $WHITELIST_FILE &nbsp;|&nbsp; $(date)</div>
</div></body></html>
HTML

[[ -n "$MAIL_TO" ]] && command -v mail &>/dev/null && \
    mail -s "$MAIL_SUBJECT" -a "Content-Type: text/html" "$MAIL_TO" < "$HTML_FILE"

section "COMPLETE"
echo "  Report         : $HTML_FILE"
echo "  Total failures : $total_failures from $total_unique_ips IPs"
echo "  Newly blocked  : ${#NEWLY_BLOCKED[@]}"
echo "  Block method   : $BLOCK_METHOD (threshold: $BLOCK_THRESHOLD)"
echo ""
