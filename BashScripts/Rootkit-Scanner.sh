#!/usr/bin/env bash
# =============================================================
#  ROOTKIT SCANNER WRAPPER
#  Runs chkrootkit and/or rkhunter, consolidates results,
#  and emails an HTML report
#  Run as: sudo bash 10-rootkit-scanner.sh
# =============================================================

set -euo pipefail

# =============================================================
#  CONFIGURATION
# =============================================================
REPORT_DIR="/var/log/admin-reports/rootkit-scan"
HTML_FILE="${REPORT_DIR}/rootkit-$(date +%Y%m%d_%H%M%S).html"
HISTORY_FILE="${REPORT_DIR}/scan-history.log"

AUTO_INSTALL=true        # Auto-install scanners if missing
UPDATE_RKHUNTER=true     # Update rkhunter database before scan
MAIL_TO=""
MAIL_SUBJECT="Rootkit Scan Report - $(hostname) - $(date +%Y-%m-%d)"

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
#  INSTALL SCANNERS IF MISSING
# =============================================================
section "Checking scanner availability..."

install_if_missing() {
    local pkg="$1"
    if ! command -v "$pkg" &>/dev/null; then
        if $AUTO_INSTALL; then
            warn "$pkg not found — installing..."
            DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" -q 2>&1 | tail -3
            command -v "$pkg" &>/dev/null && ok "Installed: $pkg" || warn "Failed to install: $pkg"
        else
            warn "$pkg not installed. Set AUTO_INSTALL=true or: apt install $pkg"
        fi
    else
        ok "$pkg is available: $(command -v "$pkg")"
    fi
}

install_if_missing chkrootkit
install_if_missing rkhunter

CHKROOTKIT_AVAIL=false
RKHUNTER_AVAIL=false
command -v chkrootkit &>/dev/null && CHKROOTKIT_AVAIL=true
command -v rkhunter   &>/dev/null && RKHUNTER_AVAIL=true

# =============================================================
#  RUN CHKROOTKIT
# =============================================================
CHK_OUTPUT=""
CHK_INFECTED=0
CHK_WARNINGS=0
CHK_STATUS="not_run"

if $CHKROOTKIT_AVAIL; then
    section "Running chkrootkit..."
    TMP_CHK=$(mktemp)

    chkrootkit -q 2>&1 | tee "$TMP_CHK" || true
    CHK_OUTPUT=$(cat "$TMP_CHK")

    # Count infections and warnings
    CHK_INFECTED=$(grep -c "INFECTED"   "$TMP_CHK" 2>/dev/null || echo 0)
    CHK_WARNINGS=$(grep -c "Suspicious" "$TMP_CHK" 2>/dev/null || echo 0)
    CHK_WARNINGS=$((CHK_WARNINGS + $(grep -ci "warning" "$TMP_CHK" 2>/dev/null || echo 0)))

    if [[ $CHK_INFECTED -gt 0 ]]; then
        alert "chkrootkit: $CHK_INFECTED INFECTED items found!"
        CHK_STATUS="infected"
    elif [[ $CHK_WARNINGS -gt 0 ]]; then
        warn "chkrootkit: $CHK_WARNINGS warning(s) found"
        CHK_STATUS="warning"
    else
        ok "chkrootkit: Clean"
        CHK_STATUS="clean"
    fi

    rm -f "$TMP_CHK"
else
    warn "chkrootkit not available — skipping"
    CHK_STATUS="skipped"
fi

# =============================================================
#  UPDATE RKHUNTER DATABASE
# =============================================================
if $RKHUNTER_AVAIL && $UPDATE_RKHUNTER; then
    section "Updating rkhunter database..."
    rkhunter --update --nocolors 2>&1 | grep -E "Updated|unchanged|Checked|Error" | head -10 || true
    rkhunter --propupd --nocolors 2>&1 | grep -E "File|Updated|properties" | head -5 || true
    ok "rkhunter database updated"
fi

# =============================================================
#  RUN RKHUNTER
# =============================================================
RKH_OUTPUT=""
RKH_WARNINGS=0
RKH_STATUS="not_run"

if $RKHUNTER_AVAIL; then
    section "Running rkhunter..."
    TMP_RKH=$(mktemp)

    rkhunter --check --sk --nocolors --report-warnings-only 2>&1 | tee "$TMP_RKH" || true
    RKH_OUTPUT=$(cat "$TMP_RKH")

    RKH_WARNINGS=$(grep -c "Warning\|WARNING" "$TMP_RKH" 2>/dev/null || echo 0)
    RKH_ERRORS=$(grep -c "Error\|ERROR" "$TMP_RKH" 2>/dev/null || echo 0)

    if [[ $RKH_WARNINGS -gt 0 || $RKH_ERRORS -gt 0 ]]; then
        warn "rkhunter: $RKH_WARNINGS warning(s), $RKH_ERRORS error(s)"
        RKH_STATUS="warning"
    else
        ok "rkhunter: Clean"
        RKH_STATUS="clean"
    fi

    rm -f "$TMP_RKH"
else
    warn "rkhunter not available — skipping"
    RKH_STATUS="skipped"
fi

# =============================================================
#  ADDITIONAL MANUAL CHECKS
# =============================================================
section "Running additional checks..."

declare -a EXTRA_CHECKS

# Check for unusual SUID files
suid_unusual=$(find /bin /sbin /usr/bin /usr/sbin -perm -4000 -type f 2>/dev/null | \
    while IFS= read -r f; do
        # Common known SUID files
        known=false
        for kf in /usr/bin/passwd /usr/bin/sudo /bin/su /usr/bin/chsh /usr/bin/chfn \
                  /usr/bin/newgrp /bin/mount /bin/umount /usr/bin/pkexec; do
            [[ "$f" == "$kf" ]] && known=true && break
        done
        $known || echo "$f"
    done)

if [[ -n "$suid_unusual" ]]; then
    EXTRA_CHECKS+=("WARNING|Unusual SUID binaries found|$suid_unusual")
    warn "Unusual SUID files: $(echo "$suid_unusual" | tr '\n' ' ')"
else
    EXTRA_CHECKS+=("OK|No unusual SUID binaries|")
    ok "SUID check: Clean"
fi

# Check for hidden directories in common paths
hidden_dirs=$(find /tmp /var/tmp /dev/shm -maxdepth 2 -name ".*" -type d 2>/dev/null || true)
if [[ -n "$hidden_dirs" ]]; then
    EXTRA_CHECKS+=("WARNING|Hidden directories in temp locations|$(echo "$hidden_dirs" | tr '\n' ' ')")
    warn "Hidden dirs: $(echo "$hidden_dirs" | tr '\n' ' ')"
else
    EXTRA_CHECKS+=("OK|No hidden directories in temp locations|")
fi

# Check /etc/passwd for unusual entries
unusual_passwd=$(awk -F: '$7 != "/sbin/nologin" && $7 != "/bin/false" && $7 != "/usr/sbin/nologin" && $3 < 1000 && $1 != "root" && $1 != "sync" && $1 != "shutdown" && $1 != "halt" {print $1":"$7}' /etc/passwd 2>/dev/null || true)
if [[ -n "$unusual_passwd" ]]; then
    EXTRA_CHECKS+=("WARNING|System accounts with login shells|$unusual_passwd")
    warn "Unusual system accounts: $unusual_passwd"
else
    EXTRA_CHECKS+=("OK|No unusual system account shells|")
fi

# Check for world-writable files in /etc
ww_etc=$(find /etc -maxdepth 2 -perm -0002 -type f 2>/dev/null | head -5 || true)
if [[ -n "$ww_etc" ]]; then
    EXTRA_CHECKS+=("WARNING|World-writable files in /etc|$(echo "$ww_etc" | tr '\n' ' ')")
    alert "World-writable /etc files: $(echo "$ww_etc" | tr '\n' ' ')"
else
    EXTRA_CHECKS+=("OK|No world-writable files in /etc|")
fi

# Check listening ports for suspicious activity
suspicious_ports=$(ss -tlnp 2>/dev/null | awk 'NR>1 {print $4}' | grep -oP '(?<=:)\d+$' | \
    while IFS= read -r p; do
        [[ "$p" -gt 49151 && "$p" -lt 65536 ]] && echo "$p (high ephemeral)"
    done | head -5 || true)
if [[ -n "$suspicious_ports" ]]; then
    EXTRA_CHECKS+=("INFO|Unusual high ports listening|$suspicious_ports")
else
    EXTRA_CHECKS+=("OK|No unusual listening ports|")
fi

# Check crontabs for suspicious entries
sus_cron=$(for f in /etc/crontab /var/spool/cron/crontabs/* /etc/cron.d/*; do
    [[ -f "$f" ]] || continue
    grep -v '^#\|^$' "$f" | grep -i 'curl\|wget\|bash\|sh\s*-\|python\|perl\|nc\|ncat' 2>/dev/null | \
        sed "s|^|[$f]: |"
done 2>/dev/null | head -10 || true)
if [[ -n "$sus_cron" ]]; then
    EXTRA_CHECKS+=("WARNING|Suspicious cron entries|$sus_cron")
    warn "Suspicious cron entries found"
else
    EXTRA_CHECKS+=("OK|No suspicious cron entries|")
fi

# =============================================================
#  LOG HISTORY
# =============================================================
echo "$(date '+%Y-%m-%d %H:%M:%S') | chkrootkit=$CHK_STATUS infected=$CHK_INFECTED | rkhunter=$RKH_STATUS warnings=$RKH_WARNINGS" >> "$HISTORY_FILE"

# =============================================================
#  BUILD HTML REPORT
# =============================================================
overall_status="CLEAN"
hcolor="#1e8449"
[[ "$CHK_STATUS" == "warning" || "$RKH_STATUS" == "warning" ]] && overall_status="WARNING" && hcolor="#e67e22"
[[ "$CHK_STATUS" == "infected" ]] && overall_status="INFECTED" && hcolor="#c0392b"

chk_rows=""
while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    if [[ "$line" =~ INFECTED ]]; then
        chk_rows+="<tr style='border-left:4px solid #c0392b'><td style='font-family:monospace;font-size:11px;color:#c0392b'>$line</td></tr>"
    elif [[ "$line" =~ Suspicious|WARNING|warning ]]; then
        chk_rows+="<tr style='border-left:4px solid #e67e22'><td style='font-family:monospace;font-size:11px;color:#e67e22'>$line</td></tr>"
    else
        chk_rows+="<tr><td style='font-family:monospace;font-size:11px;color:#555'>$line</td></tr>"
    fi
done <<< "${CHK_OUTPUT:-No output}"

rkh_rows=""
while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    if [[ "$line" =~ Warning|WARNING ]]; then
        rkh_rows+="<tr style='border-left:4px solid #e67e22'><td style='font-family:monospace;font-size:11px;color:#e67e22'>$line</td></tr>"
    elif [[ "$line" =~ Error|ERROR ]]; then
        rkh_rows+="<tr style='border-left:4px solid #c0392b'><td style='font-family:monospace;font-size:11px;color:#c0392b'>$line</td></tr>"
    else
        rkh_rows+="<tr><td style='font-family:monospace;font-size:11px;color:#555'>$line</td></tr>"
    fi
done <<< "${RKH_OUTPUT:-No output}"

extra_rows=""
for entry in "${EXTRA_CHECKS[@]}"; do
    IFS='|' read -r status check detail <<< "$entry"
    case "$status" in
        OK)      badge="<span class='badge b-green'>✔ OK</span>" ; style="" ;;
        WARNING) badge="<span class='badge b-orange'>⚠ WARNING</span>"; style="border-left:4px solid #e67e22;" ;;
        INFO)    badge="<span class='badge b-blue'>ℹ INFO</span>";    style="" ;;
    esac
    extra_rows+="<tr style='$style'><td>$badge</td><td>$check</td><td style='font-size:11px;color:#555;word-break:break-all'>$detail</td></tr>"
done

hist_rows=""
while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    hist_rows+="<tr><td style='font-family:monospace;font-size:11px'>$line</td></tr>"
done < <(tail -10 "$HISTORY_FILE" 2>/dev/null | tac || true)

cat > "$HTML_FILE" <<HTML
<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>
body{font-family:Segoe UI,Arial,sans-serif;background:#f4f6f9;padding:20px}
.container{max-width:1100px;margin:auto;background:white;border-radius:10px;box-shadow:0 4px 15px rgba(0,0,0,.12);overflow:hidden}
.header{background:linear-gradient(135deg,${hcolor},#1a252f);color:white;padding:30px}
.header h1{margin:0;font-size:24px}.header p{margin:5px 0 0;opacity:.85;font-size:14px}
.overall{display:inline-block;background:rgba(255,255,255,.2);border-radius:8px;padding:6px 18px;margin-top:10px;font-size:18px;font-weight:bold}
.content{padding:25px}
.stats{display:flex;gap:15px;margin-bottom:25px;flex-wrap:wrap}
.stat{flex:1;min-width:120px;border-radius:8px;padding:16px;text-align:center}
.stat .num{font-size:28px;font-weight:bold}.stat .lbl{font-size:11px;margin-top:4px}
.s-red{background:#fdedec;border-top:4px solid #c0392b;color:#7b241c}
.s-orange{background:#fef5e7;border-top:4px solid #e67e22;color:#7d4e1a}
.s-green{background:#eafaf1;border-top:4px solid #1e8449;color:#1a5e20}
.s-blue{background:#eaf4fb;border-top:4px solid #2e86c1}
h2{font-size:16px;color:#2c3e50;border-bottom:2px solid #eee;padding-bottom:8px;margin-top:28px}
table{width:100%;border-collapse:collapse;font-size:13px;margin-bottom:20px}
th{background:#2c3e50;color:white;padding:10px 12px;text-align:left}
td{padding:8px 12px;border-bottom:1px solid #f0f0f0;vertical-align:top}
tr:hover td{background:#f5f8ff}
.badge{display:inline-block;padding:2px 7px;border-radius:10px;font-size:10px;font-weight:bold;color:white;margin:1px}
.b-red{background:#c0392b}.b-orange{background:#e67e22}.b-green{background:#1e8449}.b-blue{background:#2e86c1}
.footer{background:#f4f6f9;padding:15px 25px;font-size:12px;color:#888;border-top:1px solid #e0e0e0}
</style></head><body>
<div class="container">
<div class="header">
  <h1>🦠 Rootkit Scan Report</h1>
  <p>Host: <strong>$(hostname -f)</strong> &nbsp;|&nbsp; Kernel: $(uname -r) &nbsp;|&nbsp; $(date)</p>
  <div class="overall">Overall: $overall_status</div>
</div>
<div class="content">
<div class="stats">
  <div class="stat $( [[ $CHK_INFECTED -gt 0 ]] && echo s-red || echo s-green)"><div class="num">$CHK_INFECTED</div><div class="lbl">chkrootkit Infections</div></div>
  <div class="stat $( [[ $CHK_WARNINGS -gt 0 ]] && echo s-orange || echo s-green)"><div class="num">$CHK_WARNINGS</div><div class="lbl">chkrootkit Warnings</div></div>
  <div class="stat $( [[ $RKH_WARNINGS -gt 0 ]] && echo s-orange || echo s-green)"><div class="num">$RKH_WARNINGS</div><div class="lbl">rkhunter Warnings</div></div>
  <div class="stat s-blue"><div class="num">${#EXTRA_CHECKS[@]}</div><div class="lbl">Manual Checks</div></div>
</div>

<h2>🔍 Additional Manual Checks</h2>
<table><tr><th style="width:120px">Status</th><th>Check</th><th>Details</th></tr>
${extra_rows}
</table>

<h2>🔬 chkrootkit Results</h2>
$(if [[ "$CHK_STATUS" == "skipped" ]]; then echo "<p style='color:#888'>⚠ chkrootkit not installed or skipped.</p>"; else echo ""; fi)
<table><tr><th>Output</th></tr>
${chk_rows:-<tr><td style='color:#1e8449'>✅ No infections found</td></tr>}
</table>

<h2>🔬 rkhunter Results (warnings/errors only)</h2>
$(if [[ "$RKH_STATUS" == "skipped" ]]; then echo "<p style='color:#888'>⚠ rkhunter not installed or skipped.</p>"; else echo ""; fi)
<table><tr><th>Output</th></tr>
${rkh_rows:-<tr><td style='color:#1e8449'>✅ No warnings found</td></tr>}
</table>

<h2>📅 Scan History (last 10)</h2>
<table><tr><th>History</th></tr>
${hist_rows:-<tr><td style='color:#888'>No scan history yet</td></tr>}
</table>
</div>
<div class="footer">Generated by rootkit-scanner.sh &nbsp;|&nbsp; $(date) &nbsp;|&nbsp; History: $HISTORY_FILE</div>
</div></body></html>
HTML

[[ -n "$MAIL_TO" ]] && command -v mail &>/dev/null && \
    mail -s "$MAIL_SUBJECT" -a "Content-Type: text/html" "$MAIL_TO" < "$HTML_FILE"

section "SCAN COMPLETE"
echo "  Overall status  : $overall_status"
echo "  chkrootkit      : $CHK_STATUS (infected: $CHK_INFECTED, warnings: $CHK_WARNINGS)"
echo "  rkhunter        : $RKH_STATUS (warnings: $RKH_WARNINGS)"
echo "  HTML report     : $HTML_FILE"
echo ""
