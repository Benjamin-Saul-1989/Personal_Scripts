#!/usr/bin/env bash
# =============================================================
#  OUTDATED PACKAGE REPORTER WITH CVE LINKS
#  Lists all upgradable packages, fetches Ubuntu Security
#  Notices (USN) for known CVEs, and generates an HTML report
#  Run as: sudo bash 13-outdated-packages.sh
# =============================================================

set -euo pipefail

# =============================================================
#  CONFIGURATION
# =============================================================
REPORT_DIR="/var/log/admin-reports/packages"
HTML_FILE="${REPORT_DIR}/outdated-$(date +%Y%m%d_%H%M%S).html"

# Fetch USN/CVE data from Ubuntu security tracker
FETCH_CVE_DATA=true
USN_API="https://ubuntu.com/security/notices.json"
CVE_BASE_URL="https://ubuntu.com/security/CVE"
USN_BASE_URL="https://ubuntu.com/security/notices"
MAX_USN_FETCH=50    # Limit API calls

MAIL_TO=""
MAIL_SUBJECT="Outdated Package Report - $(hostname) - $(date +%Y-%m-%d)"

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
#  REFRESH PACKAGE LISTS
# =============================================================
section "Refreshing package lists..."
apt-get update -q 2>&1 | grep -E "Hit:|Get:|Err:|Ign:" | head -10 || true

# =============================================================
#  GET UPGRADABLE PACKAGES
# =============================================================
section "Collecting upgradable packages..."

declare -a ALL_PKGS
declare -a SECURITY_PKGS
declare -a REGULAR_PKGS

while IFS= read -r line; do
    [[ -z "$line" || "$line" =~ ^Listing ]] && continue

    pkg=$(echo "$line" | awk '{print $1}' | cut -d'/' -f1)
    new_ver=$(echo "$line" | awk '{print $2}')
    repo=$(echo "$line" | awk '{print $3}')
    old_ver=$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null || echo "?")

    is_security=$(echo "$repo" | grep -ci "security" || echo 0)
    [[ "$is_security" -gt 0 ]] && type="security" || type="regular"

    ALL_PKGS+=("$pkg|$old_ver|$new_ver|$repo|$type")
    [[ "$type" == "security" ]] && SECURITY_PKGS+=("$pkg|$old_ver|$new_ver|$repo") || \
        REGULAR_PKGS+=("$pkg|$old_ver|$new_ver|$repo")

    info "$pkg: $old_ver → $new_ver [$type]"
done < <(apt list --upgradable 2>/dev/null || true)

total_pkgs=${#ALL_PKGS[@]}
sec_count=${#SECURITY_PKGS[@]}
reg_count=${#REGULAR_PKGS[@]}

info "Total upgradable : $total_pkgs"
info "Security updates : $sec_count"
info "Regular updates  : $reg_count"

# =============================================================
#  FETCH USN DATA (Ubuntu Security Notices)
# =============================================================
declare -A PKG_CVE_MAP   # pkg -> "CVE1,CVE2"
declare -A PKG_USN_MAP   # pkg -> "USN-1234-1"
declare -A USN_SEVERITY  # USN -> severity

if $FETCH_CVE_DATA && command -v curl &>/dev/null && [[ $sec_count -gt 0 ]]; then
    section "Fetching USN security data..."

    # Detect Ubuntu codename for API query
    UBUNTU_CODENAME=$(lsb_release -cs 2>/dev/null || echo "noble")
    info "Ubuntu codename: $UBUNTU_CODENAME"

    # Fetch recent security notices
    USN_JSON=$(curl -s --max-time 20 \
        "${USN_API}?release=${UBUNTU_CODENAME}&limit=${MAX_USN_FETCH}" 2>/dev/null || echo "")

    if [[ -n "$USN_JSON" && "$USN_JSON" != "{}" ]]; then
        ok "Fetched USN data"

        # Parse USN JSON manually (no jq)
        # Extract USN IDs and their packages
        while IFS= read -r usn_block; do
            usn_id=$(echo "$usn_block" | grep -oP '"id":\s*"\K[^"]+' | head -1 || echo "")
            severity=$(echo "$usn_block" | grep -oP '"severity":\s*"\K[^"]+' | head -1 || echo "unknown")
            pkgs_in_usn=$(echo "$usn_block" | grep -oP '"package":\s*"\K[^"]+' | head -10 || echo "")
            cves_in_usn=$(echo "$usn_block" | grep -oP '"cve_id":\s*"\K[^"]+' | head -5 | tr '\n' ',' | sed 's/,$//' || echo "")

            [[ -z "$usn_id" ]] && continue
            USN_SEVERITY["$usn_id"]="$severity"

            while IFS= read -r pkg_name; do
                [[ -z "$pkg_name" ]] && continue
                PKG_USN_MAP["$pkg_name"]+="${usn_id},"
                [[ -n "$cves_in_usn" ]] && PKG_CVE_MAP["$pkg_name"]+="${cves_in_usn},"
            done <<< "$pkgs_in_usn"
        done < <(echo "$USN_JSON" | grep -oP '\{[^{}]*"id"[^{}]*\}' 2>/dev/null || true)

        info "Parsed $(echo "$USN_JSON" | grep -o '"id"' | wc -l) USN entries"
    else
        warn "Could not fetch USN data (offline or API unavailable)"
    fi
fi

# =============================================================
#  BUILD HTML REPORT
# =============================================================
hcolor="#1e8449"
[[ $total_pkgs -gt 0 ]] && hcolor="#e67e22"
[[ $sec_count -gt 0 ]] && hcolor="#c0392b"
[[ $total_pkgs -eq 0 ]] && hcolor="#1e8449"

build_pkg_table() {
    local -n arr=$1
    local show_type=$2
    local rows=""
    for entry in "${arr[@]}"; do
        IFS='|' read -r pkg old new repo type <<< "$entry"

        # Look up CVE/USN data
        usns="${PKG_USN_MAP[$pkg]:-}"
        cves="${PKG_CVE_MAP[$pkg]:-}"

        usn_links=""
        for usn in $(echo "$usns" | tr ',' '\n' | head -3); do
            [[ -z "$usn" ]] && continue
            sev="${USN_SEVERITY[$usn]:-unknown}"
            sev_color="b-orange"
            [[ "$sev" == "critical" || "$sev" == "high" ]] && sev_color="b-red"
            [[ "$sev" == "low" || "$sev" == "negligible" ]] && sev_color="b-green"
            usn_links+="<a href='${USN_BASE_URL}/${usn}' target='_blank' style='text-decoration:none'><span class='badge ${sev_color}'>$usn</span></a> "
        done

        cve_links=""
        for cve in $(echo "$cves" | tr ',' '\n' | sort -u | head -4); do
            [[ -z "$cve" || ! "$cve" =~ ^CVE ]] && continue
            cve_links+="<a href='${CVE_BASE_URL}/${cve}' target='_blank' style='color:#2e86c1;font-size:11px;text-decoration:none'>$cve</a> "
        done

        # Type badge (only if showing all)
        type_cell=""
        if [[ "$show_type" == "yes" ]]; then
            [[ "$type" == "security" ]] && \
                type_cell="<td><span class='badge b-red'>🔒 Security</span></td>" || \
                type_cell="<td><span class='badge b-blue'>Regular</span></td>"
        fi

        rows+="<tr>
          <td><strong>$pkg</strong></td>
          <td style='font-family:monospace;font-size:11px;color:#888'>$old</td>
          <td style='font-family:monospace;font-size:11px;color:#1e8449'>$new</td>
          <td style='font-size:11px;color:#555'>$(echo "$repo" | cut -c1-35)</td>
          ${type_cell}
          <td>$usn_links</td>
          <td>$cve_links</td>
        </tr>"
    done
    echo "$rows"
}

cat > "$HTML_FILE" <<HTML
<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>
body{font-family:Segoe UI,Arial,sans-serif;background:#f4f6f9;padding:20px}
.container{max-width:1200px;margin:auto;background:white;border-radius:10px;box-shadow:0 4px 15px rgba(0,0,0,.12);overflow:hidden}
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
table{width:100%;border-collapse:collapse;font-size:12px;margin-bottom:20px}
th{background:#2c3e50;color:white;padding:9px 12px;text-align:left}
td{padding:8px 12px;border-bottom:1px solid #f0f0f0;vertical-align:middle}
tr:hover td{background:#f5f8ff}
.badge{display:inline-block;padding:2px 7px;border-radius:10px;font-size:10px;font-weight:bold;color:white;margin:1px}
.b-red{background:#c0392b}.b-orange{background:#e67e22}.b-green{background:#1e8449}.b-blue{background:#2e86c1}
.fix-cmd{background:#1e2a38;color:#e0e0e0;padding:10px 15px;border-radius:6px;font-family:monospace;font-size:13px;margin:10px 0}
.footer{background:#f4f6f9;padding:15px 25px;font-size:12px;color:#888;border-top:1px solid #e0e0e0}
</style></head><body>
<div class="container">
<div class="header">
  <h1>📦 Outdated Package Report</h1>
  <p>Host: <strong>$(hostname -f)</strong> &nbsp;|&nbsp; OS: $(lsb_release -ds 2>/dev/null || echo "Unknown") &nbsp;|&nbsp; $(date)</p>
</div>
<div class="content">
<div class="stats">
  <div class="stat $([[ $total_pkgs -gt 0 ]] && echo s-orange || echo s-green)"><div class="num">$total_pkgs</div><div class="lbl">Total Upgradable</div></div>
  <div class="stat $([[ $sec_count -gt 0 ]] && echo s-red || echo s-green)"><div class="num">$sec_count</div><div class="lbl">Security Updates</div></div>
  <div class="stat s-blue"><div class="num">$reg_count</div><div class="lbl">Regular Updates</div></div>
  <div class="stat s-green"><div class="num">$(dpkg -l 2>/dev/null | grep -c '^ii' || echo '?')</div><div class="lbl">Total Installed</div></div>
</div>

$([[ $total_pkgs -eq 0 ]] && echo "<p style='text-align:center;color:#1e8449;font-size:18px;padding:20px'>✅ System is fully up to date!</p>")

$([[ $sec_count -gt 0 ]] && echo "
<h2>🔒 Security Updates ($sec_count)</h2>
<div class='fix-cmd'>sudo apt-get install $(printf '%s\n' \"${SECURITY_PKGS[@]}\" | cut -d'|' -f1 | tr '\n' ' ')</div>
<table>
  <tr><th>Package</th><th>Current</th><th>Available</th><th>Repository</th><th>USN</th><th>CVEs</th></tr>
  $(build_pkg_table SECURITY_PKGS no)
</table>")

$([[ $reg_count -gt 0 ]] && echo "
<h2>📋 Regular Updates ($reg_count)</h2>
<table>
  <tr><th>Package</th><th>Current</th><th>Available</th><th>Repository</th><th>USN</th><th>CVEs</th></tr>
  $(build_pkg_table REGULAR_PKGS no)
</table>")

<h2>🚀 Quick Fix Commands</h2>
<div class='fix-cmd'># Install all updates:<br>sudo apt-get update &amp;&amp; sudo apt-get upgrade -y</div>
<div class='fix-cmd'># Security updates only (Ubuntu):<br>sudo unattended-upgrade -d</div>
<div class='fix-cmd'># Clean up:<br>sudo apt-get autoremove -y &amp;&amp; sudo apt-get autoclean</div>

<h2>🔗 Resources</h2>
<table><tr><th>Resource</th><th>URL</th></tr>
<tr><td>Ubuntu Security Notices</td><td><a href='https://ubuntu.com/security/notices' target='_blank'>ubuntu.com/security/notices</a></td></tr>
<tr><td>Ubuntu CVE Tracker</td><td><a href='https://ubuntu.com/security/cves' target='_blank'>ubuntu.com/security/cves</a></td></tr>
<tr><td>Debian Security</td><td><a href='https://www.debian.org/security/' target='_blank'>debian.org/security</a></td></tr>
<tr><td>NVD CVE Database</td><td><a href='https://nvd.nist.gov/vuln/search' target='_blank'>nvd.nist.gov</a></td></tr>
</table>
</div>
<div class="footer">Generated by outdated-packages.sh &nbsp;|&nbsp; $(date) &nbsp;|&nbsp; $(hostname)</div>
</div></body></html>
HTML

[[ -n "$MAIL_TO" ]] && command -v mail &>/dev/null && \
    mail -s "$MAIL_SUBJECT" -a "Content-Type: text/html" "$MAIL_TO" < "$HTML_FILE"

section "COMPLETE"
echo "  Total upgradable : $total_pkgs"
echo "  Security updates : $sec_count"
echo "  Report           : $HTML_FILE"
[[ $sec_count -gt 0 ]] && alert "$sec_count security update(s) pending — run: sudo apt-get upgrade"
[[ $total_pkgs -eq 0 ]] && ok "System is up to date"
echo ""
