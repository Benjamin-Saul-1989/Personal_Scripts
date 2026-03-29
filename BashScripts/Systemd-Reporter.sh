#!/usr/bin/env bash
# =============================================================
#  SYSTEMD FAILED UNIT REPORTER
#  Reports failed units, recent errors, restart counts, and
#  service health metrics
#  Run as: sudo bash 17-systemd-reporter.sh
# =============================================================

set -euo pipefail

# =============================================================
#  CONFIGURATION
# =============================================================
REPORT_DIR="/var/log/admin-reports/systemd"
HTML_FILE="${REPORT_DIR}/systemd-$(date +%Y%m%d_%H%M%S).html"
LOG_LINES=30        # Journal log lines to pull per failed unit
HOURS_BACK=24       # Hours of journal history for error analysis
TOP_RESTARTS=15     # Top N services by restart count

MAIL_TO=""
MAIL_SUBJECT="Systemd Health Report - $(hostname) - $(date +%Y-%m-%d)"

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
#  COLLECT FAILED UNITS
# =============================================================
section "Collecting failed systemd units..."

declare -a FAILED_UNITS
declare -a FAILED_DETAILS

while IFS= read -r line; do
    [[ -z "$line" || "$line" =~ ^UNIT || "$line" =~ ^● ]] && continue
    unit=$(echo "$line" | awk '{print $1}')
    load=$(echo "$line" | awk '{print $2}')
    active=$(echo "$line" | awk '{print $3}')
    sub=$(echo "$line" | awk '{print $4}')
    desc=$(echo "$line" | awk '{$1=$2=$3=$4=""; print $0}' | xargs)
    [[ -z "$unit" || "$unit" =~ ^$ ]] && continue

    FAILED_UNITS+=("$unit")
    info "Failed unit: $unit ($desc)"
done < <(systemctl --failed --no-legend --no-pager 2>/dev/null | grep -v "^$\|loaded units" || true)

FAILED_COUNT=${#FAILED_UNITS[@]}
[[ $FAILED_COUNT -eq 0 ]] && ok "No failed units found" || alert "$FAILED_COUNT failed unit(s) detected"

# =============================================================
#  GET JOURNAL LOGS FOR EACH FAILED UNIT
# =============================================================
declare -A UNIT_LOGS
declare -A UNIT_STATUS

for unit in "${FAILED_UNITS[@]}"; do
    info "Getting status for: $unit"
    status_out=$(systemctl status "$unit" --no-pager -l 2>/dev/null | head -30 || echo "Status unavailable")
    UNIT_STATUS["$unit"]="$status_out"

    journal_out=$(journalctl -u "$unit" --no-pager -n "$LOG_LINES" --since "${HOURS_BACK} hours ago" 2>/dev/null | \
        grep -v "^--" | tail -$LOG_LINES || echo "No journal entries")
    UNIT_LOGS["$unit"]="$journal_out"
done

# =============================================================
#  COLLECT ALL SERVICES AND THEIR STATUS
# =============================================================
section "Collecting all service states..."

declare -a ALL_SERVICES
declare -i active_count=0 inactive_count=0 failed_services=0

while IFS= read -r line; do
    [[ "$line" =~ ^UNIT ]] && continue
    [[ -z "$line" ]] && continue
    unit=$(echo "$line" | awk '{print $1}')
    load=$(echo "$line" | awk '{print $2}')
    active=$(echo "$line" | awk '{print $3}')
    sub=$(echo "$line" | awk '{print $4}')
    [[ -z "$unit" ]] && continue
    # Only .service units
    [[ "$unit" =~ \.service$ ]] || continue

    case "$active" in
        active)   active_count=$((active_count + 1)) ;;
        inactive) inactive_count=$((inactive_count + 1)) ;;
        failed)   failed_services=$((failed_services + 1)) ;;
    esac

    ALL_SERVICES+=("$unit|$load|$active|$sub")
done < <(systemctl list-units --type=service --all --no-legend --no-pager 2>/dev/null || true)

TOTAL_SERVICES=${#ALL_SERVICES[@]}
info "Total services: $TOTAL_SERVICES (active: $active_count, failed: $failed_services)"

# =============================================================
#  RESTART COUNTS
# =============================================================
section "Checking restart counts (last ${HOURS_BACK}h)..."

declare -a RESTART_DATA

while IFS= read -r line; do
    count=$(echo "$line" | awk '{print $1}')
    unit=$(echo "$line" | awk '{print $2}')
    [[ -z "$unit" || "$count" -lt 1 ]] && continue
    RESTART_DATA+=("$count|$unit")
done < <(
    journalctl --since "${HOURS_BACK} hours ago" --no-pager 2>/dev/null | \
        grep -oP '[a-zA-Z0-9_\-]+\.service(?=.*[Ss]tarted|.*start)' | \
        sort | uniq -c | sort -rn | head -$TOP_RESTARTS || true
)

# =============================================================
#  JOURNAL ERROR SUMMARY (last 24h)
# =============================================================
section "Analysing journal errors..."

declare -a JOURNAL_ERRORS
ERROR_COUNT=0
WARN_COUNT=0

while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    JOURNAL_ERRORS+=("$line")
done < <(
    journalctl --since "${HOURS_BACK} hours ago" --no-pager -p 0..3 2>/dev/null | \
        grep -v "^--\|Logs begin\|Logs end" | tail -50 || true
)
ERROR_COUNT=${#JOURNAL_ERRORS[@]}

# Warning count
WARN_COUNT=$(journalctl --since "${HOURS_BACK} hours ago" --no-pager -p 4 2>/dev/null | \
    grep -v "^--\|Logs begin" | wc -l || echo 0)

info "Critical/error events (${HOURS_BACK}h): $ERROR_COUNT"
info "Warning events (${HOURS_BACK}h)       : $WARN_COUNT"

# =============================================================
#  SYSTEM BOOT INFO
# =============================================================
section "Checking system boot info..."

BOOT_TIME=$(who -b 2>/dev/null | awk '{print $3,$4}' || systemctl show --property=KernelTimestamp 2>/dev/null | cut -d= -f2 || echo "?")
UPTIME=$(uptime -p 2>/dev/null || echo "?")
LAST_BOOT=$(last reboot -n 3 2>/dev/null | head -3 | awk '{print $1,$3,$4,$5,$6,$7}' | head -3 || echo "?")
KERNEL=$(uname -r)

# Check for persistent journal
JOURNAL_PERSISTENT=false
[[ -d /var/log/journal ]] && JOURNAL_PERSISTENT=true

# =============================================================
#  BUILD HTML REPORT
# =============================================================
hcolor="#1e8449"
[[ $FAILED_COUNT -gt 0 ]] && hcolor="#e67e22"
[[ $FAILED_COUNT -gt 3 || $ERROR_COUNT -gt 50 ]] && hcolor="#c0392b"

# Failed units table
failed_rows=""
for unit in "${FAILED_UNITS[@]}"; do
    status="${UNIT_STATUS[$unit]:-}"
    logs="${UNIT_LOGS[$unit]:-}"

    # Extract last error from status
    last_err=$(echo "$status" | grep -i "error\|failed\|exit code" | head -1 | xargs || echo "See logs below")
    main_pid=$(echo "$status" | grep -oP '(?<=Main PID: )\d+' | head -1 || echo "?")

    # Build log rows
    log_html=""
    while IFS= read -r log_line; do
        [[ -z "$log_line" ]] && continue
        style=""
        [[ "$log_line" =~ [Ee]rror|FAILED|failed ]] && style="color:#c0392b"
        [[ "$log_line" =~ [Ww]arning ]] && style="color:#e67e22"
        log_html+="<div style='$style;font-family:monospace;font-size:11px;padding:1px 0'>$(echo "$log_line" | sed 's/&/\&amp;/g;s/</\&lt;/g;s/>/\&gt;/g')</div>"
    done <<< "$logs"

    failed_rows+="
    <tr style='border-left:4px solid #c0392b;background:#fff5f5'>
      <td colspan='3'>
        <div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:6px'>
          <strong style='font-size:14px'>$unit</strong>
          <span class='badge b-red'>FAILED</span>
        </div>
        <div style='font-size:11px;color:#555;margin-bottom:4px'>Last error: $last_err</div>
        <details><summary style='cursor:pointer;color:#2e86c1;font-size:12px'>View last $LOG_LINES log lines</summary>
          <div style='background:#1e2a38;color:#e0e0e0;padding:10px;border-radius:4px;margin-top:4px;overflow-x:auto'>
            ${log_html:-<span style='color:#888'>No logs</span>}
          </div>
        </details>
      </td>
    </tr>"
done

# Service overview table
svc_rows=""
for entry in "${ALL_SERVICES[@]}"; do
    IFS='|' read -r unit load active sub <<< "$entry"
    case "$active" in
        active)   badge="<span class='badge b-green'>active</span>" ;;
        failed)   badge="<span class='badge b-red'>failed</span>" ;;
        inactive) badge="<span class='badge b-gray'>inactive</span>" ;;
        *)        badge="<span class='badge b-orange'>$active</span>" ;;
    esac
    sub_badge=""
    case "$sub" in
        running)  sub_badge="<span class='badge b-green'>running</span>" ;;
        dead)     sub_badge="<span class='badge b-gray'>dead</span>" ;;
        exited)   sub_badge="<span class='badge b-blue'>exited</span>" ;;
        failed)   sub_badge="<span class='badge b-red'>failed</span>" ;;
        *)        sub_badge="<span class='badge b-orange'>$sub</span>" ;;
    esac
    [[ "$active" == "inactive" || "$active" == "active" && "$sub" == "running" ]] || \
        svc_rows+="<tr><td><strong>$unit</strong></td><td>$badge</td><td>$sub_badge</td><td>$load</td></tr>"
done

restart_rows=""
for entry in "${RESTART_DATA[@]}"; do
    IFS='|' read -r count unit <<< "$entry"
    bar_width=$((count * 2 > 200 ? 200 : count * 2))
    restart_rows+="<tr><td><strong>$unit</strong></td><td style='text-align:right;font-weight:bold'>$count</td><td><div style='background:#e0e0e0;border-radius:4px;height:10px;width:200px'><div style='background:#e67e22;height:10px;border-radius:4px;width:${bar_width}px'></div></div></td></tr>"
done

error_rows=""
for line in "${JOURNAL_ERRORS[@]:0:30}"; do
    style=""
    [[ "$line" =~ [Ee]rror|FAIL ]] && style="color:#c0392b"
    error_rows+="<tr><td style='font-family:monospace;font-size:11px;${style}'>$(echo "$line" | sed 's/&/\&amp;/g;s/</\&lt;/g' | cut -c1-180)</td></tr>"
done

cat > "$HTML_FILE" <<HTML
<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>
body{font-family:Segoe UI,Arial,sans-serif;background:#f4f6f9;padding:20px}
.container{max-width:1100px;margin:auto;background:white;border-radius:10px;box-shadow:0 4px 15px rgba(0,0,0,.12);overflow:hidden}
.header{background:linear-gradient(135deg,${hcolor},#1a252f);color:white;padding:30px}
.header h1{margin:0;font-size:24px}.header p{margin:5px 0 0;opacity:.85;font-size:14px}
.content{padding:25px}
.stats{display:flex;gap:15px;margin-bottom:25px;flex-wrap:wrap}
.stat{flex:1;min-width:110px;border-radius:8px;padding:14px;text-align:center}
.stat .num{font-size:26px;font-weight:bold}.stat .lbl{font-size:11px;margin-top:4px}
.s-red{background:#fdedec;border-top:4px solid #c0392b;color:#7b241c}
.s-orange{background:#fef5e7;border-top:4px solid #e67e22;color:#7d4e1a}
.s-green{background:#eafaf1;border-top:4px solid #1e8449;color:#1a5e20}
.s-blue{background:#eaf4fb;border-top:4px solid #2e86c1}
.s-gray{background:#f2f3f4;border-top:4px solid #7f8c8d}
.sysinfo{background:#f4f6f9;border-radius:8px;padding:14px;margin-bottom:20px;font-size:13px}
.sysinfo span{margin-right:25px;color:#555}
.sysinfo strong{color:#2c3e50}
h2{font-size:16px;color:#2c3e50;border-bottom:2px solid #eee;padding-bottom:8px;margin-top:28px}
table{width:100%;border-collapse:collapse;font-size:12px;margin-bottom:20px}
th{background:#2c3e50;color:white;padding:9px 12px;text-align:left}
td{padding:8px 12px;border-bottom:1px solid #f0f0f0;vertical-align:top}
tr:hover td{background:#f5f8ff}
.badge{display:inline-block;padding:2px 7px;border-radius:10px;font-size:10px;font-weight:bold;color:white;margin:1px}
.b-red{background:#c0392b}.b-orange{background:#e67e22}.b-green{background:#1e8449}
.b-blue{background:#2e86c1}.b-gray{background:#7f8c8d}
details summary{user-select:none}
.footer{background:#f4f6f9;padding:15px 25px;font-size:12px;color:#888;border-top:1px solid #e0e0e0}
</style></head><body>
<div class="container">
<div class="header">
  <h1>⚙️ Systemd Health Report</h1>
  <p>Host: <strong>$(hostname -f)</strong> &nbsp;|&nbsp; Kernel: $KERNEL &nbsp;|&nbsp; $(date)</p>
</div>
<div class="content">
<div class="sysinfo">
  <span>🖥️ <strong>Uptime:</strong> $UPTIME</span>
  <span>🔄 <strong>Boot:</strong> $BOOT_TIME</span>
  <span>📦 <strong>Total services:</strong> $TOTAL_SERVICES</span>
  <span>📓 <strong>Persistent journal:</strong> $($JOURNAL_PERSISTENT && echo "Yes" || echo "No")</span>
</div>

<div class="stats">
  <div class="stat $([[ $FAILED_COUNT -gt 0 ]] && echo s-red || echo s-green)"><div class="num">$FAILED_COUNT</div><div class="lbl">Failed Units</div></div>
  <div class="stat s-green"><div class="num">$active_count</div><div class="lbl">Active Services</div></div>
  <div class="stat s-gray"><div class="num">$inactive_count</div><div class="lbl">Inactive Services</div></div>
  <div class="stat $([[ $ERROR_COUNT -gt 0 ]] && echo s-orange || echo s-green)"><div class="num">$ERROR_COUNT</div><div class="lbl">Errors (${HOURS_BACK}h)</div></div>
  <div class="stat $([[ $WARN_COUNT -gt 0 ]] && echo s-orange || echo s-green)"><div class="num">$WARN_COUNT</div><div class="lbl">Warnings (${HOURS_BACK}h)</div></div>
  <div class="stat s-blue"><div class="num">${#RESTART_DATA[@]}</div><div class="lbl">Restarting Svcs</div></div>
</div>

<h2>🚨 Failed Units ($FAILED_COUNT)</h2>
<table>
  ${failed_rows:-<tr><td style='text-align:center;color:#1e8449;padding:20px;font-size:15px'>✅ No failed systemd units</td></tr>}
</table>

<h2>🔄 Most Restarted Services (last ${HOURS_BACK}h)</h2>
<table><tr><th>Service</th><th>Restarts</th><th>Activity</th></tr>
${restart_rows:-<tr><td colspan='3' style='text-align:center;color:#888;padding:12px'>No restart data found</td></tr>}
</table>

<h2>📛 Journal Errors & Criticals (last ${HOURS_BACK}h, capped at 30)</h2>
<table><tr><th>Log Entry</th></tr>
${error_rows:-<tr><td style='text-align:center;color:#1e8449;padding:12px'>✅ No critical/error events in the last ${HOURS_BACK} hours</td></tr>}
</table>

<h2>⚙️ Non-Running Service States</h2>
<table><tr><th>Unit</th><th>Active</th><th>Sub-state</th><th>Load</th></tr>
${svc_rows:-<tr><td colspan='4' style='text-align:center;color:#1e8449;padding:12px'>✅ All loaded services in expected states</td></tr>}
</table>

<h2>💡 Useful Commands</h2>
<table><tr><th>Command</th><th>Purpose</th></tr>
<tr><td><code>systemctl --failed</code></td><td>Show all failed units</td></tr>
<tr><td><code>journalctl -p err -b</code></td><td>Show errors since last boot</td></tr>
<tr><td><code>journalctl -u unit.service -f</code></td><td>Follow a specific unit's logs</td></tr>
<tr><td><code>systemctl restart unit.service</code></td><td>Restart a failed unit</td></tr>
<tr><td><code>systemctl reset-failed</code></td><td>Clear failed state for all units</td></tr>
<tr><td><code>journalctl --disk-usage</code></td><td>Check journal disk usage</td></tr>
<tr><td><code>systemd-analyze blame</code></td><td>Show boot time per service</td></tr>
</table>
</div>
<div class="footer">Generated by systemd-reporter.sh &nbsp;|&nbsp; $(date) &nbsp;|&nbsp; $(hostname)</div>
</div></body></html>
HTML

[[ -n "$MAIL_TO" ]] && command -v mail &>/dev/null && \
    mail -s "$MAIL_SUBJECT" -a "Content-Type: text/html" "$MAIL_TO" < "$HTML_FILE"

section "COMPLETE"
echo "  Failed units     : $FAILED_COUNT"
echo "  Active services  : $active_count"
echo "  Journal errors   : $ERROR_COUNT (last ${HOURS_BACK}h)"
echo "  Report           : $HTML_FILE"
[[ $FAILED_COUNT -gt 0 ]] && alert "$FAILED_COUNT unit(s) failed — check report for details"
[[ $FAILED_COUNT -eq 0 ]] && ok "All systemd units are healthy"
echo ""
