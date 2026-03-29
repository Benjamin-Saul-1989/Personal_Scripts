#!/usr/bin/env bash
# =============================================================
#  FIREWALL RULE EXPORTER / REPORTER
#  Exports and analyses UFW and iptables rules
#  Run as: sudo bash 08-firewall-reporter.sh
# =============================================================

set -euo pipefail

# =============================================================
#  CONFIGURATION
# =============================================================
REPORT_DIR="/var/log/admin-reports/firewall"
HTML_FILE="${REPORT_DIR}/firewall-$(date +%Y%m%d_%H%M%S).html"
BACKUP_FILE="${REPORT_DIR}/rules-backup-$(date +%Y%m%d_%H%M%S).txt"
MAIL_TO=""
MAIL_SUBJECT="Firewall Report - $(hostname) - $(date +%Y-%m-%d)"

# Ports to flag as high-risk if open to ANY
HIGH_RISK_PORTS=(22 23 25 53 135 137 138 139 445 1433 1434 3306 3389 5432 5900 6379 27017)
declare -A PORT_NAMES=(
    [20]="FTP-data" [21]="FTP" [22]="SSH" [23]="Telnet" [25]="SMTP"
    [53]="DNS" [80]="HTTP" [110]="POP3" [135]="RPC" [139]="NetBIOS"
    [143]="IMAP" [389]="LDAP" [443]="HTTPS" [445]="SMB" [465]="SMTPS"
    [587]="Submission" [993]="IMAPS" [995]="POP3S" [1433]="MSSQL"
    [1434]="MSSQL-UDP" [3306]="MySQL" [3389]="RDP" [5432]="PostgreSQL"
    [5900]="VNC" [6379]="Redis" [8080]="HTTP-Alt" [8443]="HTTPS-Alt"
    [27017]="MongoDB"
)

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
#  DETECT FIREWALL TYPE
# =============================================================
UFW_ACTIVE=false
IPTABLES_PRESENT=false
NFT_PRESENT=false

command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active" && UFW_ACTIVE=true
command -v iptables &>/dev/null && IPTABLES_PRESENT=true
command -v nft &>/dev/null && NFT_PRESENT=true

section "Firewall Detection"
$UFW_ACTIVE        && ok  "UFW: Active"         || info "UFW: Not active"
$IPTABLES_PRESENT  && info "iptables: Available" || info "iptables: Not found"
$NFT_PRESENT       && info "nftables: Available" || info "nftables: Not found"

# =============================================================
#  BACKUP CURRENT RULES
# =============================================================
{
    echo "======================================================"
    echo "  FIREWALL RULES BACKUP"
    echo "  Host: $(hostname -f)"
    echo "  Date: $(date)"
    echo "======================================================"
    echo ""

    if $UFW_ACTIVE; then
        echo "=== UFW STATUS ==="
        ufw status verbose 2>/dev/null || true
        echo ""
    fi

    if $IPTABLES_PRESENT; then
        echo "=== IPTABLES (IPv4) ==="
        iptables -L -n -v --line-numbers 2>/dev/null || true
        echo ""
        echo "=== IPTABLES-SAVE ==="
        iptables-save 2>/dev/null || true
        echo ""
        echo "=== IP6TABLES ==="
        ip6tables -L -n -v 2>/dev/null || true
        echo ""
    fi

    if $NFT_PRESENT; then
        echo "=== NFTABLES ==="
        nft list ruleset 2>/dev/null || true
    fi
} > "$BACKUP_FILE"
ok "Rules backed up to: $BACKUP_FILE"

# =============================================================
#  PARSE UFW RULES
# =============================================================
declare -a UFW_RULES
declare -a FLAGGED_RULES

if $UFW_ACTIVE; then
    section "Parsing UFW rules..."
    while IFS= read -r line; do
        [[ -z "$line" || "$line" =~ ^-- || "$line" =~ ^Status || "$line" =~ ^Logging || \
           "$line" =~ ^Default || "$line" =~ ^New || "$line" =~ ^To ]] && continue

        # Parse UFW numbered output
        port=$(echo "$line" | awk '{print $1}' | sed 's/(v6)//')
        action=$(echo "$line" | awk '{print $2}')
        from=$(echo "$line" | awk '{print $3}')

        [[ -z "$port" || -z "$action" ]] && continue

        # Extract port number for risk check
        port_num=$(echo "$port" | grep -oP '^\d+' || echo "")
        port_name="${PORT_NAMES[$port_num]:-}"
        [[ -z "$port_name" && -n "$port_num" ]] && port_name="port $port_num"
        [[ -z "$port_name" ]] && port_name="$port"

        risk="low"
        risk_reason=""
        if [[ "$action" == "ALLOW" || "$action" == "ALLOW IN" ]]; then
            if [[ "$from" == "Anywhere" ]]; then
                risk="medium"
                for rp in "${HIGH_RISK_PORTS[@]}"; do
                    if [[ "$port_num" == "$rp" ]]; then
                        risk="high"
                        risk_reason="High-risk port open to ANY"
                        break
                    fi
                done
                [[ -z "$risk_reason" ]] && risk_reason="Open to any source"
            fi
        fi

        UFW_RULES+=("${port_name}|${action}|${from}|${risk}|${risk_reason}")
        [[ "$risk" != "low" ]] && FLAGGED_RULES+=("UFW|${port_name}|${action}|${from}|${risk}|${risk_reason}")

        info "Rule: $port_name → $action from $from [$risk]"
    done < <(ufw status 2>/dev/null | grep -v "^Status\|^Logging\|^Default\|^New\|^To\|^--\|^$" || true)
fi

# =============================================================
#  PARSE IPTABLES
# =============================================================
declare -a IPT_RULES

if $IPTABLES_PRESENT; then
    section "Parsing iptables rules..."

    for chain in INPUT OUTPUT FORWARD; do
        while IFS= read -r line; do
            [[ "$line" =~ ^Chain || "$line" =~ ^target || "$line" =~ ^pkts || -z "$line" ]] && continue

            target=$(echo "$line" | awk '{print $1}')
            prot=$(echo "$line" | awk '{print $2}')
            src=$(echo "$line" | awk '{print $4}')
            dst=$(echo "$line" | awk '{print $5}')
            rest=$(echo "$line" | cut -d' ' -f6-)

            # Extract port from 'dpt:' or 'multiport dports'
            dport=$(echo "$rest" | grep -oP '(?<=dpt:)\d+' | head -1 || echo "")
            [[ -z "$dport" ]] && dport=$(echo "$rest" | grep -oP '(?<=dports )\S+' | head -1 || echo "any")

            risk="low"
            [[ "$target" == "ACCEPT" && "$src" == "0.0.0.0/0" ]] && risk="medium"
            port_name="${PORT_NAMES[$dport]:-$dport}"

            IPT_RULES+=("${chain}|${target}|${prot}|${src}|${dst}|${dport}|${port_name}|${risk}")
        done < <(iptables -L "$chain" -n -v 2>/dev/null | tail -n +3 || true)
    done

    info "Parsed ${#IPT_RULES[@]} iptables rules"
fi

# =============================================================
#  OPEN PORTS CHECK (cross-reference with ss/netstat)
# =============================================================
section "Checking listening ports..."
declare -a LISTENING_PORTS

while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    proto=$(echo "$line" | awk '{print $1}')
    local_addr=$(echo "$line" | awk '{print $5}')
    process=$(echo "$line" | awk '{print $7}' | grep -oP '(?<=").*(?=")' | head -1 || echo "?")
    port=$(echo "$local_addr" | grep -oP '(?<=:)\d+$' || echo "")
    [[ -z "$port" ]] && continue

    port_name="${PORT_NAMES[$port]:-port $port}"
    is_high_risk=false
    for rp in "${HIGH_RISK_PORTS[@]}"; do [[ "$port" == "$rp" ]] && is_high_risk=true && break; done

    LISTENING_PORTS+=("${proto}|${port}|${port_name}|${local_addr}|${process}|${is_high_risk}")
done < <(ss -tlnup 2>/dev/null | tail -n +2 || netstat -tlnup 2>/dev/null | tail -n +3 || true)

# =============================================================
#  BUILD HTML REPORT
# =============================================================
fw_status="Unknown"
$UFW_ACTIVE && fw_status="UFW Active"
! $UFW_ACTIVE && $IPTABLES_PRESENT && fw_status="iptables (no UFW)"
! $UFW_ACTIVE && ! $IPTABLES_PRESENT && fw_status="No Firewall Detected"

hcolor="#1e8449"
[[ "${#FLAGGED_RULES[@]}" -gt 0 ]] && hcolor="#e67e22"
[[ "$fw_status" == "No Firewall Detected" ]] && hcolor="#c0392b"

ufw_rows=""
for entry in "${UFW_RULES[@]}"; do
    IFS='|' read -r port action from risk reason <<< "$entry"
    case "$risk" in
        high)   rb="<span class='badge b-red'>HIGH</span>" ;;
        medium) rb="<span class='badge b-orange'>MEDIUM</span>" ;;
        *)      rb="<span class='badge b-green'>LOW</span>" ;;
    esac
    case "$action" in
        *ALLOW*) ab="<span class='badge b-green'>$action</span>" ;;
        *DENY*|*REJECT*) ab="<span class='badge b-red'>$action</span>" ;;
        *) ab="<span class='badge b-gray'>$action</span>" ;;
    esac
    ufw_rows+="<tr><td>$port</td><td>$ab</td><td>$from</td><td>$rb</td><td style='font-size:11px;color:#555'>$reason</td></tr>"
done

ipt_rows=""
for entry in "${IPT_RULES[@]}"; do
    IFS='|' read -r chain target prot src dst dport pname risk <<< "$entry"
    case "$target" in
        ACCEPT) tb="<span class='badge b-green'>ACCEPT</span>" ;;
        DROP)   tb="<span class='badge b-red'>DROP</span>" ;;
        REJECT) tb="<span class='badge b-red'>REJECT</span>" ;;
        *)      tb="<span class='badge b-gray'>$target</span>" ;;
    esac
    ipt_rows+="<tr><td>$chain</td><td>$tb</td><td>$prot</td><td>$src</td><td>$dst</td><td>$pname</td></tr>"
done

listen_rows=""
for entry in "${LISTENING_PORTS[@]}"; do
    IFS='|' read -r proto port pname addr proc is_high <<< "$entry"
    risk_badge=$($is_high && echo "<span class='badge b-orange'>High-Risk Port</span>" || echo "")
    listen_rows+="<tr><td>$proto</td><td><strong>$port</strong></td><td>$pname</td><td style='font-family:monospace;font-size:11px'>$addr</td><td style='font-size:11px'>$proc</td><td>$risk_badge</td></tr>"
done

flagged_rows=""
for entry in "${FLAGGED_RULES[@]}"; do
    IFS='|' read -r src port action from risk reason <<< "$entry"
    flagged_rows+="<tr style='border-left:4px solid #e67e22'><td>$src</td><td><strong>$port</strong></td><td>$action</td><td>$from</td><td><span class='badge b-orange'>$risk</span></td><td style='font-size:11px'>$reason</td></tr>"
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
.stat{flex:1;min-width:120px;border-radius:8px;padding:16px;text-align:center}
.stat .num{font-size:28px;font-weight:bold}.stat .lbl{font-size:11px;margin-top:4px}
.s-red{background:#fdedec;border-top:4px solid #c0392b;color:#7b241c}
.s-orange{background:#fef5e7;border-top:4px solid #e67e22;color:#7d4e1a}
.s-green{background:#eafaf1;border-top:4px solid #1e8449;color:#1a5e20}
.s-blue{background:#eaf4fb;border-top:4px solid #2e86c1}
h2{font-size:15px;color:#2c3e50;border-bottom:2px solid #eee;padding-bottom:7px;margin-top:24px}
table{width:100%;border-collapse:collapse;font-size:12px;margin-bottom:15px}
th{background:#2c3e50;color:white;padding:9px 10px;text-align:left}
td{padding:8px 10px;border-bottom:1px solid #f0f0f0;vertical-align:middle}
tr:hover td{background:#f5f8ff}
.badge{display:inline-block;padding:2px 7px;border-radius:10px;font-size:10px;font-weight:bold;color:white;margin:1px}
.b-red{background:#c0392b}.b-orange{background:#e67e22}.b-green{background:#1e8449}
.b-blue{background:#2e86c1}.b-gray{background:#7f8c8d}
.footer{background:#f4f6f9;padding:15px 25px;font-size:12px;color:#888;border-top:1px solid #e0e0e0}
</style></head><body>
<div class="container">
<div class="header">
  <h1>🔥 Firewall Report</h1>
  <p>Host: <strong>$(hostname -f)</strong> &nbsp;|&nbsp; Status: <strong>$fw_status</strong> &nbsp;|&nbsp; $(date)</p>
</div>
<div class="content">
<div class="stats">
  <div class="stat s-blue"><div class="num">${#UFW_RULES[@]}</div><div class="lbl">UFW Rules</div></div>
  <div class="stat s-orange"><div class="num">${#FLAGGED_RULES[@]}</div><div class="lbl">Flagged Rules</div></div>
  <div class="stat s-blue"><div class="num">${#LISTENING_PORTS[@]}</div><div class="lbl">Listening Ports</div></div>
  <div class="stat s-red"><div class="num">$(printf '%s\n' "${LISTENING_PORTS[@]}" | grep -c '|true$' 2>/dev/null || echo 0)</div><div class="lbl">High-Risk Ports</div></div>
</div>

<h2>⚠️ Flagged Rules (Review Required)</h2>
<table><tr><th>Source</th><th>Port/Service</th><th>Action</th><th>From</th><th>Risk</th><th>Reason</th></tr>
${flagged_rows:-<tr><td colspan='6' style='text-align:center;color:#1e8449;padding:15px'>✅ No flagged rules</td></tr>}
</table>

<h2>🛡️ UFW Rules</h2>
<table><tr><th>Port/Service</th><th>Action</th><th>From</th><th>Risk</th><th>Notes</th></tr>
${ufw_rows:-<tr><td colspan='5' style='text-align:center;color:#888'>UFW not active or no rules</td></tr>}
</table>

<h2>⚙️ iptables Rules (INPUT/OUTPUT/FORWARD)</h2>
<table><tr><th>Chain</th><th>Target</th><th>Proto</th><th>Source</th><th>Dest</th><th>Port</th></tr>
${ipt_rows:-<tr><td colspan='6' style='text-align:center;color:#888'>No iptables rules or iptables not available</td></tr>}
</table>

<h2>🔌 Currently Listening Ports</h2>
<table><tr><th>Proto</th><th>Port</th><th>Service</th><th>Address</th><th>Process</th><th>Risk</th></tr>
${listen_rows:-<tr><td colspan='6' style='text-align:center;color:#888'>No listening ports found</td></tr>}
</table>
</div>
<div class="footer">Generated by firewall-reporter.sh &nbsp;|&nbsp; Backup: $BACKUP_FILE &nbsp;|&nbsp; $(date)</div>
</div></body></html>
HTML

[[ -n "$MAIL_TO" ]] && command -v mail &>/dev/null && \
    mail -s "$MAIL_SUBJECT" -a "Content-Type: text/html" "$MAIL_TO" < "$HTML_FILE"

ok "HTML report: $HTML_FILE"
ok "Rules backup: $BACKUP_FILE"
