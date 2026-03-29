#!/usr/bin/env bash
# =============================================================
#  SSL CERTIFICATE EXPIRY CHECKER
#  Checks SSL certificates for a list of domains/IPs and
#  generates a colour-coded expiry report
#  Run as: sudo bash 15-ssl-cert-checker.sh
#  Or:     bash 15-ssl-cert-checker.sh (no root needed)
# =============================================================

set -euo pipefail

# =============================================================
#  CONFIGURATION
# =============================================================
REPORT_DIR="/var/log/admin-reports/ssl"
HTML_FILE="${REPORT_DIR}/ssl-$(date +%Y%m%d_%H%M%S).html"

# Days-to-expiry thresholds
CRITICAL_DAYS=14
WARNING_DAYS=30
NOTICE_DAYS=60

# Timeout for each SSL connection (seconds)
CONNECT_TIMEOUT=10

# Domains/hosts to check — format: "host:port" or "host" (defaults to 443)
DOMAINS=(
    "google.com:443"
    "github.com:443"
    "$(hostname -f):443"
    # Add your domains:
    # "yourdomain.com:443"
    # "mail.yourdomain.com:465"
    # "vpn.yourdomain.com:8443"
    # "internal-server:443"
)

# Also scan local certificate files
CERT_PATHS=(
    "/etc/ssl/certs"
    "/etc/letsencrypt/live"
    "/etc/nginx/ssl"
    "/etc/apache2/ssl"
)

MAIL_TO=""
MAIL_SUBJECT="SSL Certificate Report - $(hostname) - $(date +%Y-%m-%d)"

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

mkdir -p "$REPORT_DIR"

declare -a RESULTS  # host|port|status|days|expiry|issued_by|subject_cn|error

# =============================================================
#  CHECK A SINGLE DOMAIN VIA NETWORK
# =============================================================
check_domain() {
    local host="$1"
    local port="${2:-443}"
    local status="" days=0 expiry="" issued_by="" cn="" error=""

    info "Checking $host:$port..."

    # Fetch certificate
    CERT_OUTPUT=$(echo "" | timeout "$CONNECT_TIMEOUT" openssl s_client \
        -connect "${host}:${port}" \
        -servername "$host" \
        -verify_quiet \
        2>/dev/null || echo "CONNECT_FAILED")

    if [[ "$CERT_OUTPUT" == "CONNECT_FAILED" || -z "$CERT_OUTPUT" ]]; then
        RESULTS+=("$host|$port|error|0|||Connection failed after ${CONNECT_TIMEOUT}s")
        alert "$host:$port — Connection failed"
        return
    fi

    # Extract cert info
    CERT_TEXT=$(echo "$CERT_OUTPUT" | openssl x509 -noout \
        -dates -subject -issuer -ext subjectAltName 2>/dev/null || echo "PARSE_FAILED")

    if [[ "$CERT_TEXT" == "PARSE_FAILED" || -z "$CERT_TEXT" ]]; then
        RESULTS+=("$host|$port|error|0|||Could not parse certificate")
        alert "$host:$port — Could not parse certificate"
        return
    fi

    # Parse dates
    not_after=$(echo "$CERT_TEXT" | grep "^notAfter=" | cut -d= -f2)
    not_before=$(echo "$CERT_TEXT" | grep "^notBefore=" | cut -d= -f2)
    cn=$(echo "$CERT_TEXT" | grep "^subject=" | grep -oP '(?<=CN\s*=\s*)[^,/]+' | head -1 || echo "?")
    issued_by=$(echo "$CERT_TEXT" | grep "^issuer=" | grep -oP '(?<=O\s*=\s*)[^,/]+' | head -1 || echo "?")
    san=$(echo "$CERT_TEXT" | grep "DNS:" | sed 's/DNS://g;s/,/\n/g' | tr -d ' ' | head -5 | tr '\n' ' ' || echo "")

    if [[ -z "$not_after" ]]; then
        RESULTS+=("$host|$port|error|0|||Could not read expiry date")
        return
    fi

    # Calculate days to expiry
    expiry_epoch=$(date -d "$not_after" +%s 2>/dev/null || date -jf "%b %e %H:%M:%S %Y %Z" "$not_after" +%s 2>/dev/null || echo 0)
    now_epoch=$(date +%s)
    days=$(( (expiry_epoch - now_epoch) / 86400 ))
    expiry=$(date -d "$not_after" '+%Y-%m-%d' 2>/dev/null || echo "$not_after")

    # Determine status
    if [[ $days -lt 0 ]]; then
        status="expired"
        alert "$host:$port — EXPIRED ($days days)"
    elif [[ $days -le $CRITICAL_DAYS ]]; then
        status="critical"
        alert "$host:$port — CRITICAL: $days days remaining"
    elif [[ $days -le $WARNING_DAYS ]]; then
        status="warning"
        warn "$host:$port — WARNING: $days days remaining"
    elif [[ $days -le $NOTICE_DAYS ]]; then
        status="notice"
        warn "$host:$port — Notice: $days days remaining"
    else
        status="ok"
        ok "$host:$port — OK: $days days remaining (expires $expiry)"
    fi

    RESULTS+=("$host|$port|$status|$days|$expiry|$issued_by|$cn|$san")
}

# =============================================================
#  CHECK LOCAL CERTIFICATE FILES
# =============================================================
check_cert_file() {
    local filepath="$1"
    local status="" days=0 expiry="" cn="" issued_by=""

    CERT_TEXT=$(openssl x509 -in "$filepath" -noout -dates -subject -issuer 2>/dev/null || echo "")
    [[ -z "$CERT_TEXT" ]] && return

    not_after=$(echo "$CERT_TEXT" | grep "^notAfter=" | cut -d= -f2)
    cn=$(echo "$CERT_TEXT" | grep "^subject=" | grep -oP '(?<=CN\s*=\s*)[^,/]+' | head -1 || echo "?")
    issued_by=$(echo "$CERT_TEXT" | grep "^issuer=" | grep -oP '(?<=O\s*=\s*)[^,/]+' | head -1 || echo "?")

    [[ -z "$not_after" ]] && return

    expiry_epoch=$(date -d "$not_after" +%s 2>/dev/null || echo 0)
    now_epoch=$(date +%s)
    days=$(( (expiry_epoch - now_epoch) / 86400 ))
    expiry=$(date -d "$not_after" '+%Y-%m-%d' 2>/dev/null || echo "$not_after")

    if [[ $days -lt 0 ]]; then status="expired"
    elif [[ $days -le $CRITICAL_DAYS ]]; then status="critical"
    elif [[ $days -le $WARNING_DAYS ]]; then  status="warning"
    elif [[ $days -le $NOTICE_DAYS ]]; then   status="notice"
    else status="ok"; fi

    RESULTS+=("$(basename "$filepath")|file|$status|$days|$expiry|$issued_by|$cn|$filepath")
    info "File $filepath: $status ($days days)"
}

# =============================================================
#  RUN CHECKS
# =============================================================
section "Checking remote certificates..."
for domain in "${DOMAINS[@]}"; do
    host=$(echo "$domain" | cut -d: -f1)
    port=$(echo "$domain" | grep -oP ':\K\d+$' || echo "443")
    check_domain "$host" "$port"
done

section "Checking local certificate files..."
for cert_path in "${CERT_PATHS[@]}"; do
    [[ -d "$cert_path" ]] || continue
    while IFS= read -r f; do
        check_cert_file "$f"
    done < <(find "$cert_path" -maxdepth 3 -name "*.pem" -o -name "*.crt" -o -name "fullchain.pem" 2>/dev/null | head -30)
done

# =============================================================
#  COUNTS
# =============================================================
EXPIRED_COUNT=$(printf '%s\n' "${RESULTS[@]}" | grep -c '|expired|' || echo 0)
CRITICAL_COUNT=$(printf '%s\n' "${RESULTS[@]}" | grep -c '|critical|' || echo 0)
WARNING_COUNT=$(printf '%s\n' "${RESULTS[@]}" | grep -c '|warning|' || echo 0)
NOTICE_COUNT=$(printf '%s\n' "${RESULTS[@]}" | grep -c '|notice|' || echo 0)
OK_COUNT=$(printf '%s\n' "${RESULTS[@]}" | grep -c '|ok|' || echo 0)
ERROR_COUNT=$(printf '%s\n' "${RESULTS[@]}" | grep -c '|error|' || echo 0)
TOTAL=${#RESULTS[@]}

# =============================================================
#  BUILD HTML REPORT
# =============================================================
hcolor="#1e8449"
[[ $NOTICE_COUNT -gt 0 ]] && hcolor="#2e86c1"
[[ $WARNING_COUNT -gt 0 ]] && hcolor="#e67e22"
[[ $CRITICAL_COUNT -gt 0 || $EXPIRED_COUNT -gt 0 ]] && hcolor="#c0392b"

# Sort results: expired/critical first
result_rows=""
for priority in expired critical warning notice ok error; do
    for entry in "${RESULTS[@]}"; do
        IFS='|' read -r host port status days expiry issuer cn extra <<< "$entry"
        [[ "$status" != "$priority" ]] && continue

        case "$status" in
            expired)  badge="<span class='badge b-black'>💀 EXPIRED</span>";  row_style="background:#fff5f5;border-left:4px solid #c0392b" ;;
            critical) badge="<span class='badge b-red'>🚨 CRITICAL</span>";   row_style="background:#fff5f5;border-left:4px solid #c0392b" ;;
            warning)  badge="<span class='badge b-orange'>⚠ WARNING</span>";  row_style="background:#fffdf0;border-left:4px solid #e67e22" ;;
            notice)   badge="<span class='badge b-blue'>ℹ NOTICE</span>";     row_style="background:#f0f7ff;border-left:4px solid #2e86c1" ;;
            ok)       badge="<span class='badge b-green'>✔ OK</span>";         row_style="" ;;
            error)    badge="<span class='badge b-gray'>⚡ ERROR</span>";      row_style="background:#f5f5f5" ;;
        esac

        # Days display
        days_display=""
        if [[ $days -lt 0 ]]; then
            days_display="<strong style='color:#c0392b'>Expired ${days#-}d ago</strong>"
        elif [[ $days -le $CRITICAL_DAYS ]]; then
            days_display="<strong style='color:#c0392b'>${days} days</strong>"
        elif [[ $days -le $WARNING_DAYS ]]; then
            days_display="<strong style='color:#e67e22'>${days} days</strong>"
        else
            days_display="<span style='color:#1e8449'>${days} days</span>"
        fi

        result_rows+="<tr style='$row_style'>
          <td><strong>$host</strong></td>
          <td>$port</td>
          <td>$badge</td>
          <td>$days_display</td>
          <td>$expiry</td>
          <td style='font-size:11px;color:#555'>$cn</td>
          <td style='font-size:11px;color:#555'>$issuer</td>
          <td style='font-size:11px;color:#888'>$extra</td>
        </tr>"
    done
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
.stat{flex:1;min-width:100px;border-radius:8px;padding:14px;text-align:center}
.stat .num{font-size:28px;font-weight:bold}.stat .lbl{font-size:11px;margin-top:4px}
.s-red{background:#fdedec;border-top:4px solid #c0392b;color:#7b241c}
.s-orange{background:#fef5e7;border-top:4px solid #e67e22;color:#7d4e1a}
.s-blue{background:#eaf4fb;border-top:4px solid #2e86c1}
.s-green{background:#eafaf1;border-top:4px solid #1e8449;color:#1a5e20}
.s-gray{background:#f2f3f4;border-top:4px solid #7f8c8d}
h2{font-size:16px;color:#2c3e50;border-bottom:2px solid #eee;padding-bottom:8px;margin-top:28px}
table{width:100%;border-collapse:collapse;font-size:12px;margin-bottom:20px}
th{background:#2c3e50;color:white;padding:9px 12px;text-align:left}
td{padding:8px 12px;border-bottom:1px solid #f0f0f0;vertical-align:middle}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:10px;font-weight:bold;color:white;white-space:nowrap}
.b-red{background:#c0392b}.b-orange{background:#e67e22}.b-green{background:#1e8449}
.b-blue{background:#2e86c1}.b-gray{background:#7f8c8d}.b-black{background:#1a252f}
.footer{background:#f4f6f9;padding:15px 25px;font-size:12px;color:#888;border-top:1px solid #e0e0e0}
</style></head><body>
<div class="container">
<div class="header">
  <h1>🔒 SSL Certificate Expiry Report</h1>
  <p>Host: <strong>$(hostname -f)</strong> &nbsp;|&nbsp; Critical: <${CRITICAL_DAYS}d &nbsp;| Warning: <${WARNING_DAYS}d &nbsp;|&nbsp; $(date)</p>
</div>
<div class="content">
<div class="stats">
  <div class="stat s-red"><div class="num">$EXPIRED_COUNT</div><div class="lbl">Expired</div></div>
  <div class="stat s-red"><div class="num">$CRITICAL_COUNT</div><div class="lbl">Critical &lt;${CRITICAL_DAYS}d</div></div>
  <div class="stat s-orange"><div class="num">$WARNING_COUNT</div><div class="lbl">Warning &lt;${WARNING_DAYS}d</div></div>
  <div class="stat s-blue"><div class="num">$NOTICE_COUNT</div><div class="lbl">Notice &lt;${NOTICE_DAYS}d</div></div>
  <div class="stat s-green"><div class="num">$OK_COUNT</div><div class="lbl">OK</div></div>
  <div class="stat s-gray"><div class="num">$ERROR_COUNT</div><div class="lbl">Errors</div></div>
</div>

<h2>📋 All Certificates ($TOTAL checked)</h2>
<table>
  <tr><th>Host / File</th><th>Port</th><th>Status</th><th>Days Left</th><th>Expiry</th><th>Common Name</th><th>Issued By</th><th>SANs / Path</th></tr>
  ${result_rows:-<tr><td colspan='8' style='text-align:center;color:#888'>No certificates checked</td></tr>}
</table>

<h2>💡 Certificate Renewal Tips</h2>
<table><tr><th>Action</th><th>Command</th></tr>
<tr><td>Renew Let's Encrypt (Certbot)</td><td><code>certbot renew --dry-run</code> then <code>certbot renew</code></td></tr>
<tr><td>Check cert expiry manually</td><td><code>echo | openssl s_client -connect host:443 2>/dev/null | openssl x509 -noout -dates</code></td></tr>
<tr><td>View local cert file</td><td><code>openssl x509 -in /path/cert.pem -noout -text</code></td></tr>
<tr><td>Set up auto-renewal</td><td><code>systemctl enable certbot.timer</code> or add to cron</td></tr>
</table>
</div>
<div class="footer">Generated by ssl-cert-checker.sh &nbsp;|&nbsp; $(date) &nbsp;|&nbsp; Critical threshold: ${CRITICAL_DAYS}d &nbsp;|&nbsp; Warning: ${WARNING_DAYS}d</div>
</div></body></html>
HTML

[[ -n "$MAIL_TO" ]] && command -v mail &>/dev/null && \
    mail -s "$MAIL_SUBJECT" -a "Content-Type: text/html" "$MAIL_TO" < "$HTML_FILE"

section "COMPLETE"
echo "  Checked    : $TOTAL"
echo "  Expired    : $EXPIRED_COUNT"
echo "  Critical   : $CRITICAL_COUNT"
echo "  Warning    : $WARNING_COUNT"
echo "  OK         : $OK_COUNT"
echo "  Report     : $HTML_FILE"
[[ $((EXPIRED_COUNT + CRITICAL_COUNT)) -gt 0 ]] && \
    alert "Action required: $((EXPIRED_COUNT + CRITICAL_COUNT)) expired or critically expiring cert(s)!"
echo ""
