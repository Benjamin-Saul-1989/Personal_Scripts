#!/usr/bin/env bash
# =============================================================
#  WORLD-WRITABLE FILE FINDER
#  Finds files/dirs writable by any user — a common security risk
#  Run as: sudo bash 07-world-writable-finder.sh
# =============================================================

set -euo pipefail

# =============================================================
#  CONFIGURATION
# =============================================================
REPORT_DIR="/var/log/admin-reports/world-writable"
HTML_FILE="${REPORT_DIR}/ww-$(date +%Y%m%d_%H%M%S).html"

# Paths to scan (space separated). Use "/" for entire filesystem.
SCAN_PATHS=("/" )
# Paths to exclude from scan
EXCLUDE_PATHS=(
    "/proc" "/sys" "/dev" "/run" "/snap"
    "/tmp"          # Expected to be world-writable
    "/var/tmp"      # Expected
    "/var/crash"
)

# Auto-fix: set to true to chmod o-w on found files (DANGEROUS — review first!)
AUTO_FIX=false
# Sticky-bit: add sticky bit to world-writable directories instead of removing write
ADD_STICKY_TO_DIRS=false

MAIL_TO=""
MAIL_SUBJECT="World-Writable File Report - $(hostname) - $(date +%Y-%m-%d)"

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

# Build exclusion args for find
EXCLUDE_ARGS=()
for ep in "${EXCLUDE_PATHS[@]}"; do
    EXCLUDE_ARGS+=(-path "$ep" -prune -o)
done

declare -a WW_FILES WW_DIRS WW_STICKY_DIRS WW_SUID WW_SGID
declare -a FIXED_FILES

section "Scanning for world-writable files..."

for SCAN_PATH in "${SCAN_PATHS[@]}"; do
    [[ -d "$SCAN_PATH" ]] || continue
    info "Scanning: $SCAN_PATH (this may take a while...)"

    # World-writable files (no sticky bit)
    while IFS= read -r f; do
        [[ -z "$f" ]] && continue
        perms=$(stat -c "%a %U %G %n" "$f" 2>/dev/null || echo "? ? ? $f")
        read -r perm owner group fname <<< "$perms"
        size=$(stat -c "%s" "$f" 2>/dev/null | numfmt --to=iec 2>/dev/null || echo "?")
        mtime=$(stat -c "%y" "$f" 2>/dev/null | cut -d. -f1 || echo "?")

        # Check for extra risks
        is_suid=false; is_sgid=false
        [[ "$perm" =~ ^[4-7] ]] && is_suid=true
        [[ "$perm" =~ ^[2-36-7] ]] && is_sgid=true

        entry="${fname}|${perm}|${owner}|${group}|${size}|${mtime}|${is_suid}|${is_sgid}"

        if [[ -d "$f" ]]; then
            WW_DIRS+=("$entry")
            warn "World-writable dir: $f (perms: $perm, owner: $owner)"
        else
            WW_FILES+=("$entry")
            alert "World-writable file: $f (perms: $perm, owner: $owner)"
            $is_suid && alert "  ↳ SUID bit set! High risk."
            $is_sgid && alert "  ↳ SGID bit set! High risk."
        fi

        # Auto-fix
        if $AUTO_FIX; then
            if [[ -d "$f" ]] && $ADD_STICKY_TO_DIRS; then
                chmod +t "$f" && FIXED_FILES+=("$f:sticky") && ok "  Set sticky bit: $f"
            else
                chmod o-w "$f" && FIXED_FILES+=("$f:o-w_removed") && ok "  Removed world-write: $f"
            fi
        fi

    done < <(
        find "$SCAN_PATH" "${EXCLUDE_ARGS[@]}" \
            -type f -perm -0002 -print 2>/dev/null
        find "$SCAN_PATH" "${EXCLUDE_ARGS[@]}" \
            -type d -perm -0002 ! -perm -1000 -print 2>/dev/null
    )

    # World-writable dirs WITH sticky bit (less risky, informational)
    while IFS= read -r f; do
        [[ -z "$f" ]] && continue
        perms=$(stat -c "%a %U %G" "$f" 2>/dev/null || echo "? ? ?")
        read -r perm owner group <<< "$perms"
        WW_STICKY_DIRS+=("${f}|${perm}|${owner}|${group}")
        info "World-writable+sticky dir: $f (OK - sticky bit set)"
    done < <(
        find "$SCAN_PATH" "${EXCLUDE_ARGS[@]}" \
            -type d -perm -1002 -print 2>/dev/null
    )

done

# =============================================================
#  SUMMARY STATS
# =============================================================
total_files=${#WW_FILES[@]}
total_dirs=${#WW_DIRS[@]}
total_sticky=${#WW_STICKY_DIRS[@]}
suid_ww=$(printf '%s\n' "${WW_FILES[@]}" | grep -c '|true|' 2>/dev/null || echo 0)
total_fixed=${#FIXED_FILES[@]}

section "Summary"
echo "  World-writable files : $total_files"
echo "  World-writable dirs  : $total_dirs"
echo "  SUID + world-writable: $suid_ww"
echo "  Sticky dirs (ok)     : $total_sticky"
$AUTO_FIX && echo "  Auto-fixed           : $total_fixed"

# =============================================================
#  BUILD HTML REPORT
# =============================================================
hcolor="#1e8449"
[[ $((total_files + total_dirs)) -gt 0 ]] && hcolor="#e67e22"
[[ $suid_ww -gt 0 ]] && hcolor="#c0392b"

build_rows() {
    local -n arr=$1
    local rows=""
    local is_dir=${2:-false}
    for entry in "${arr[@]}"; do
        IFS='|' read -r fname perm owner group size mtime suid sgid <<< "$entry"

        local risk_badges=""
        $suid && risk_badges+="<span class='badge b-red'>SUID</span> "
        $sgid && risk_badges+="<span class='badge b-red'>SGID</span> "
        [[ "$owner" == "root" ]] && risk_badges+="<span class='badge b-orange'>ROOT-OWNED</span> "
        [[ -z "$risk_badges" ]] && risk_badges="<span class='badge b-orange'>World-Writable</span>"

        if $is_dir; then
            rows+="<tr><td style='font-family:monospace;font-size:12px;word-break:break-all'>$fname</td><td>$perm</td><td>$owner</td><td>$group</td><td>$risk_badges</td></tr>"
        else
            rows+="<tr><td style='font-family:monospace;font-size:12px;word-break:break-all'>$fname</td><td>$perm</td><td>$owner</td><td>$group</td><td>$size</td><td>$mtime</td><td>$risk_badges</td></tr>"
        fi
    done
    echo "$rows"
}

sticky_rows=""
for entry in "${WW_STICKY_DIRS[@]}"; do
    IFS='|' read -r fname perm owner group <<< "$entry"
    sticky_rows+="<tr><td style='font-family:monospace;font-size:12px'>$fname</td><td>$perm</td><td>$owner</td><td>$group</td></tr>"
done

fixed_rows=""
for entry in "${FIXED_FILES[@]}"; do
    IFS=':' read -r fname action <<< "$entry"
    fixed_rows+="<tr><td style='font-family:monospace;font-size:12px'>$fname</td><td>$action</td></tr>"
done

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
.b-red{background:#c0392b}.b-orange{background:#e67e22}.b-green{background:#1e8449}.b-blue{background:#2e86c1}.b-gray{background:#7f8c8d}
.alert-box{background:#fdedec;border:1px solid #c0392b;border-radius:8px;padding:14px 18px;margin-bottom:20px;color:#7b241c;font-weight:bold}
.info-box{background:#eaf4fb;border:1px solid #2e86c1;border-radius:8px;padding:14px 18px;margin-bottom:20px;color:#1a3a5c}
.footer{background:#f4f6f9;padding:15px 25px;font-size:12px;color:#888;border-top:1px solid #e0e0e0}
</style></head><body>
<div class="container">
<div class="header">
  <h1>📂 World-Writable File Report</h1>
  <p>Host: <strong>$(hostname -f)</strong> &nbsp;|&nbsp; Scanned: ${SCAN_PATHS[*]} &nbsp;|&nbsp; $(date)</p>
</div>
<div class="content">
$([ $suid_ww -gt 0 ] && echo "<div class='alert-box'>🚨 $suid_ww SUID world-writable file(s) found — critical risk!</div>")
$([ $((total_files+total_dirs)) -eq 0 ] && echo "<div class='info-box'>✅ No world-writable files or directories found outside excluded paths.</div>")
<div class="stats">
  <div class="stat s-red"><div class="num">$total_files</div><div class="lbl">WW Files</div></div>
  <div class="stat s-orange"><div class="num">$total_dirs</div><div class="lbl">WW Directories</div></div>
  <div class="stat s-red"><div class="num">$suid_ww</div><div class="lbl">SUID+WW</div></div>
  <div class="stat s-green"><div class="num">$total_sticky</div><div class="lbl">Sticky Dirs (OK)</div></div>
</div>

<h2>🚨 World-Writable Files</h2>
<table><tr><th>Path</th><th>Perms</th><th>Owner</th><th>Group</th><th>Size</th><th>Modified</th><th>Risk</th></tr>
$(build_rows WW_FILES false)
$([ $total_files -eq 0 ] && echo "<tr><td colspan='7' style='text-align:center;color:#1e8449;padding:15px'>✅ No world-writable files found</td></tr>")
</table>

<h2>📁 World-Writable Directories (no sticky bit)</h2>
<table><tr><th>Path</th><th>Perms</th><th>Owner</th><th>Group</th><th>Risk</th></tr>
$(build_rows WW_DIRS true)
$([ $total_dirs -eq 0 ] && echo "<tr><td colspan='5' style='text-align:center;color:#1e8449;padding:15px'>✅ No unprotected world-writable dirs found</td></tr>")
</table>

<h2>ℹ️ World-Writable Directories WITH Sticky Bit (OK)</h2>
<table><tr><th>Path</th><th>Perms</th><th>Owner</th><th>Group</th></tr>
${sticky_rows:-<tr><td colspan='4' style='text-align:center;color:#888'>None</td></tr>}
</table>

$([ $total_fixed -gt 0 ] && echo "
<h2>🔧 Auto-Fixed</h2>
<table><tr><th>Path</th><th>Action</th></tr>
${fixed_rows}
</table>")

<h2>💡 Remediation</h2>
<table><tr><th>Action</th><th>Command</th></tr>
<tr><td>Remove world-write from file</td><td><code>chmod o-w /path/to/file</code></td></tr>
<tr><td>Add sticky bit to shared dir</td><td><code>chmod +t /path/to/dir</code></td></tr>
<tr><td>Remove SUID from file</td><td><code>chmod u-s /path/to/file</code></td></tr>
<tr><td>Find all WW files</td><td><code>find / -xdev -type f -perm -0002 2>/dev/null</code></td></tr>
<tr><td>Find WW dirs without sticky</td><td><code>find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null</code></td></tr>
</table>
</div>
<div class="footer">Generated by world-writable-finder.sh &nbsp;|&nbsp; $(date) &nbsp;|&nbsp; Excluded: ${EXCLUDE_PATHS[*]}</div>
</div></body></html>
HTML

[[ -n "$MAIL_TO" ]] && command -v mail &>/dev/null && \
    mail -s "$MAIL_SUBJECT" -a "Content-Type: text/html" "$MAIL_TO" < "$HTML_FILE"

ok "Report saved: $HTML_FILE"
