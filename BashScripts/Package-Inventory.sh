#!/usr/bin/env bash
# =============================================================
#  INSTALLED PACKAGE INVENTORY EXPORTER
#  Exports full inventory of apt, snap, flatpak, pip packages
#  to CSV and HTML with sizes, versions, and descriptions
#  Run as: sudo bash 14-package-inventory.sh
# =============================================================

set -euo pipefail

# =============================================================
#  CONFIGURATION
# =============================================================
REPORT_DIR="/var/log/admin-reports/inventory"
HTML_FILE="${REPORT_DIR}/inventory-$(date +%Y%m%d_%H%M%S).html"
CSV_FILE="${REPORT_DIR}/inventory-$(date +%Y%m%d_%H%M%S).csv"

INCLUDE_APT=true
INCLUDE_SNAP=true
INCLUDE_FLATPAK=true
INCLUDE_PIP=true
INCLUDE_NPM=false       # Can be slow; enable if needed
INCLUDE_GEM=false

MAIL_TO=""
MAIL_SUBJECT="Package Inventory - $(hostname) - $(date +%Y-%m-%d)"

# =============================================================
#  COLOURS
# =============================================================
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
ok()      { echo -e "${GREEN}[OK]${RESET}    $*"; }
section() { echo -e "\n${BOLD}=== $* ===${RESET}"; }

mkdir -p "$REPORT_DIR"

# =============================================================
#  COLLECT APT/DPKG PACKAGES
# =============================================================
declare -a APT_PKGS
APT_COUNT=0

if $INCLUDE_APT; then
    section "Collecting dpkg/apt packages..."

    while IFS=$'\t' read -r pkg ver arch size desc; do
        [[ -z "$pkg" ]] && continue
        # Convert size from KB to human-readable
        size_h=$(numfmt --to=iec --suffix=B $((size * 1024)) 2>/dev/null || echo "${size}KB")
        APT_PKGS+=("apt|$pkg|$ver|$arch|$size_h|$desc")
        APT_COUNT=$((APT_COUNT + 1))
    done < <(dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${Installed-Size}\t${binary:Summary}\n' 2>/dev/null | \
        awk -F'\t' '$1 != "" && $5 != "deinstall"' | head -2000 || true)

    ok "APT packages: $APT_COUNT"
fi

# =============================================================
#  COLLECT SNAP PACKAGES
# =============================================================
declare -a SNAP_PKGS
SNAP_COUNT=0

if $INCLUDE_SNAP && command -v snap &>/dev/null; then
    section "Collecting snap packages..."

    while IFS= read -r line; do
        [[ "$line" =~ ^Name || -z "$line" ]] && continue
        pkg=$(echo "$line" | awk '{print $1}')
        ver=$(echo "$line" | awk '{print $2}')
        rev=$(echo "$line" | awk '{print $3}')
        tracking=$(echo "$line" | awk '{print $4}')
        [[ -z "$pkg" ]] && continue
        SNAP_PKGS+=("snap|$pkg|$ver|rev:$rev|?|channel:$tracking")
        SNAP_COUNT=$((SNAP_COUNT + 1))
        info "Snap: $pkg $ver"
    done < <(snap list 2>/dev/null || true)

    ok "Snap packages: $SNAP_COUNT"
fi

# =============================================================
#  COLLECT FLATPAK PACKAGES
# =============================================================
declare -a FLATPAK_PKGS
FLATPAK_COUNT=0

if $INCLUDE_FLATPAK && command -v flatpak &>/dev/null; then
    section "Collecting flatpak packages..."

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        pkg=$(echo "$line" | awk '{print $1}')
        app_id=$(echo "$line" | awk '{print $2}')
        ver=$(echo "$line" | awk '{print $3}')
        branch=$(echo "$line" | awk '{print $4}')
        origin=$(echo "$line" | awk '{print $5}')
        [[ -z "$pkg" || "$pkg" == "Name" ]] && continue
        FLATPAK_PKGS+=("flatpak|$pkg|$ver|$branch|?|$app_id")
        FLATPAK_COUNT=$((FLATPAK_COUNT + 1))
        info "Flatpak: $pkg $ver"
    done < <(flatpak list --columns=name,application,version,branch,origin 2>/dev/null || true)

    ok "Flatpak packages: $FLATPAK_COUNT"
fi

# =============================================================
#  COLLECT PIP PACKAGES
# =============================================================
declare -a PIP_PKGS
PIP_COUNT=0

if $INCLUDE_PIP; then
    section "Collecting Python (pip) packages..."

    for pip_cmd in pip3 pip pip2; do
        command -v "$pip_cmd" &>/dev/null || continue
        while IFS= read -r line; do
            [[ "$line" =~ ^Package || "$line" =~ ^--- || -z "$line" ]] && continue
            pkg=$(echo "$line" | awk '{print $1}')
            ver=$(echo "$line" | awk '{print $2}')
            [[ -z "$pkg" ]] && continue
            PIP_PKGS+=("$pip_cmd|$pkg|$ver|-|?|-")
            PIP_COUNT=$((PIP_COUNT + 1))
        done < <("$pip_cmd" list 2>/dev/null || true)
        break   # Only use first found pip
    done

    ok "pip packages: $PIP_COUNT"
fi

# =============================================================
#  COLLECT NPM GLOBAL PACKAGES (optional)
# =============================================================
declare -a NPM_PKGS
NPM_COUNT=0

if $INCLUDE_NPM && command -v npm &>/dev/null; then
    section "Collecting npm global packages..."
    while IFS= read -r line; do
        [[ "$line" =~ ^npm || -z "$line" ]] && continue
        pkg=$(echo "$line" | grep -oP '(?<=── )\S+' | cut -d@ -f1 | head -1 || echo "")
        ver=$(echo "$line" | grep -oP '(?<=@)\S+' | head -1 || echo "?")
        [[ -z "$pkg" ]] && continue
        NPM_PKGS+=("npm|$pkg|$ver|-|?|-")
        NPM_COUNT=$((NPM_COUNT + 1))
    done < <(npm list -g --depth=0 2>/dev/null | tail -n +2 || true)
    ok "npm packages: $NPM_COUNT"
fi

# =============================================================
#  GENERATE CSV
# =============================================================
section "Writing CSV..."
{
    echo "Manager,Package,Version,Architecture,Size,Description"
    for entry in "${APT_PKGS[@]}" "${SNAP_PKGS[@]}" "${FLATPAK_PKGS[@]}" \
                  "${PIP_PKGS[@]}" "${NPM_PKGS[@]}"; do
        IFS='|' read -r mgr pkg ver arch size desc <<< "$entry"
        # Escape commas and quotes in description
        desc="${desc//,/;}"
        desc="${desc//\"/\'}"
        echo "$mgr,$pkg,$ver,$arch,$size,\"$desc\""
    done
} > "$CSV_FILE"
ok "CSV saved: $CSV_FILE"

# =============================================================
#  LARGE PACKAGES (top 20 by size)
# =============================================================
declare -a TOP_LARGE
while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    # dpkg-query for size
    pkg=$(echo "$line" | awk '{print $1}')
    size=$(echo "$line" | awk '{print $2}')
    size_h=$(numfmt --to=iec --suffix=B $((size * 1024)) 2>/dev/null || echo "${size}K")
    ver=$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null || echo "?")
    TOP_LARGE+=("$pkg|$size_h|$ver")
done < <(dpkg-query -W -f='${Package}\t${Installed-Size}\n' 2>/dev/null | \
    awk -F'\t' '$2 > 0' | sort -t$'\t' -k2 -rn | head -20 || true)

# Recently installed (last 7 days)
declare -a RECENT_PKGS
while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    date_str=$(echo "$line" | awk '{print $1}')
    pkg=$(echo "$line" | awk '{print $4}' | tr -d '()' || echo "")
    action=$(echo "$line" | awk '{print $3}')
    [[ "$action" =~ installed|upgraded && -n "$pkg" ]] && RECENT_PKGS+=("$date_str|$action|$pkg")
done < <(grep -E "install |upgrade " /var/log/dpkg.log 2>/dev/null | tail -50 | sort -r | head -20 || true)

# =============================================================
#  BUILD HTML REPORT
# =============================================================
TOTAL=$((APT_COUNT + SNAP_COUNT + FLATPAK_COUNT + PIP_COUNT + NPM_COUNT))

apt_rows=""
for entry in "${APT_PKGS[@]:0:500}"; do  # Cap at 500 for HTML performance
    IFS='|' read -r mgr pkg ver arch size desc <<< "$entry"
    apt_rows+="<tr><td><strong>$pkg</strong></td><td style='font-family:monospace;font-size:11px'>$ver</td><td>$arch</td><td>$size</td><td style='font-size:11px;color:#555;max-width:250px'>$desc</td></tr>"
done
[[ $APT_COUNT -gt 500 ]] && apt_rows+="<tr><td colspan='5' style='text-align:center;color:#888'>... and $((APT_COUNT-500)) more (see CSV export)</td></tr>"

large_rows=""
for entry in "${TOP_LARGE[@]}"; do
    IFS='|' read -r pkg size ver <<< "$entry"
    large_rows+="<tr><td><strong>$pkg</strong></td><td>$ver</td><td><strong>$size</strong></td></tr>"
done

snap_rows=""
for entry in "${SNAP_PKGS[@]}"; do
    IFS='|' read -r mgr pkg ver arch size desc <<< "$entry"
    snap_rows+="<tr><td><strong>$pkg</strong></td><td style='font-family:monospace;font-size:11px'>$ver</td><td style='font-size:11px;color:#555'>$desc</td></tr>"
done

pip_rows=""
for entry in "${PIP_PKGS[@]}"; do
    IFS='|' read -r mgr pkg ver arch size desc <<< "$entry"
    pip_rows+="<tr><td><strong>$pkg</strong></td><td style='font-family:monospace;font-size:11px'>$ver</td><td>$mgr</td></tr>"
done

recent_rows=""
for entry in "${RECENT_PKGS[@]}"; do
    IFS='|' read -r date action pkg <<< "$entry"
    badge=$([[ "$action" =~ install ]] && echo "<span class='badge b-green'>installed</span>" || echo "<span class='badge b-blue'>upgraded</span>")
    recent_rows+="<tr><td>$date</td><td>$badge</td><td><strong>$pkg</strong></td></tr>"
done

cat > "$HTML_FILE" <<HTML
<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>
body{font-family:Segoe UI,Arial,sans-serif;background:#f4f6f9;padding:20px}
.container{max-width:1100px;margin:auto;background:white;border-radius:10px;box-shadow:0 4px 15px rgba(0,0,0,.12);overflow:hidden}
.header{background:linear-gradient(135deg,#1a3a5c,#2e86c1);color:white;padding:30px}
.header h1{margin:0;font-size:24px}.header p{margin:5px 0 0;opacity:.85;font-size:14px}
.content{padding:25px}
.stats{display:flex;gap:15px;margin-bottom:25px;flex-wrap:wrap}
.stat{flex:1;min-width:110px;border-radius:8px;padding:14px;text-align:center}
.stat .num{font-size:28px;font-weight:bold}.stat .lbl{font-size:11px;margin-top:4px}
.s-blue{background:#eaf4fb;border-top:4px solid #2e86c1}
.s-green{background:#eafaf1;border-top:4px solid #1e8449;color:#1a5e20}
.s-orange{background:#fef5e7;border-top:4px solid #e67e22;color:#7d4e1a}
.s-gray{background:#f2f3f4;border-top:4px solid #7f8c8d}
h2{font-size:16px;color:#2c3e50;border-bottom:2px solid #eee;padding-bottom:8px;margin-top:28px}
table{width:100%;border-collapse:collapse;font-size:12px;margin-bottom:20px}
th{background:#2c3e50;color:white;padding:9px 12px;text-align:left}
td{padding:7px 12px;border-bottom:1px solid #f0f0f0;vertical-align:middle}
tr:hover td{background:#f5f8ff}
.badge{display:inline-block;padding:2px 7px;border-radius:10px;font-size:10px;font-weight:bold;color:white;margin:1px}
.b-green{background:#1e8449}.b-blue{background:#2e86c1}.b-orange{background:#e67e22}
.csv-link{display:inline-block;background:#2e86c1;color:white;padding:8px 18px;border-radius:6px;text-decoration:none;font-weight:bold;margin:10px 0}
.footer{background:#f4f6f9;padding:15px 25px;font-size:12px;color:#888;border-top:1px solid #e0e0e0}
</style></head><body>
<div class="container">
<div class="header">
  <h1>📋 Package Inventory Report</h1>
  <p>Host: <strong>$(hostname -f)</strong> &nbsp;|&nbsp; OS: $(lsb_release -ds 2>/dev/null || echo "Unknown") &nbsp;|&nbsp; $(date)</p>
</div>
<div class="content">
<p>📥 <a class='csv-link' href='file://${CSV_FILE}' target='_blank'>Download CSV Export</a> &nbsp; <code style='font-size:12px;color:#555'>${CSV_FILE}</code></p>

<div class="stats">
  <div class="stat s-blue"><div class="num">$TOTAL</div><div class="lbl">Total Packages</div></div>
  <div class="stat s-blue"><div class="num">$APT_COUNT</div><div class="lbl">apt/dpkg</div></div>
  <div class="stat s-orange"><div class="num">$SNAP_COUNT</div><div class="lbl">snap</div></div>
  <div class="stat s-green"><div class="num">$FLATPAK_COUNT</div><div class="lbl">flatpak</div></div>
  <div class="stat s-gray"><div class="num">$PIP_COUNT</div><div class="lbl">pip</div></div>
  <div class="stat s-gray"><div class="num">$NPM_COUNT</div><div class="lbl">npm</div></div>
</div>

<h2>📦 Top 20 Largest Packages</h2>
<table><tr><th>Package</th><th>Version</th><th>Installed Size</th></tr>
${large_rows:-<tr><td colspan='3' style='text-align:center;color:#888'>No data</td></tr>}
</table>

<h2>🕐 Recently Installed/Upgraded (dpkg.log)</h2>
<table><tr><th>Date</th><th>Action</th><th>Package</th></tr>
${recent_rows:-<tr><td colspan='3' style='text-align:center;color:#888'>No recent dpkg activity</td></tr>}
</table>

<h2>📦 apt/dpkg Packages ($APT_COUNT) — first 500 shown</h2>
<table><tr><th>Package</th><th>Version</th><th>Arch</th><th>Size</th><th>Description</th></tr>
${apt_rows:-<tr><td colspan='5' style='text-align:center;color:#888'>No dpkg packages found</td></tr>}
</table>

$([[ $SNAP_COUNT -gt 0 ]] && echo "
<h2>🔒 Snap Packages ($SNAP_COUNT)</h2>
<table><tr><th>Package</th><th>Version</th><th>Channel/Notes</th></tr>
${snap_rows}
</table>")

$([[ $PIP_COUNT -gt 0 ]] && echo "
<h2>🐍 Python (pip) Packages ($PIP_COUNT)</h2>
<table><tr><th>Package</th><th>Version</th><th>pip</th></tr>
${pip_rows}
</table>")
</div>
<div class="footer">Generated by package-inventory.sh &nbsp;|&nbsp; CSV: $CSV_FILE &nbsp;|&nbsp; $(date)</div>
</div></body></html>
HTML

[[ -n "$MAIL_TO" ]] && command -v mail &>/dev/null && \
    mail -s "$MAIL_SUBJECT" -a "Content-Type: text/html" "$MAIL_TO" < "$HTML_FILE"

section "COMPLETE"
echo "  Total packages : $TOTAL (apt:$APT_COUNT snap:$SNAP_COUNT flatpak:$FLATPAK_COUNT pip:$PIP_COUNT npm:$NPM_COUNT)"
echo "  HTML report    : $HTML_FILE"
echo "  CSV export     : $CSV_FILE"
echo ""
