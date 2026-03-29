#!/usr/bin/env bash
# =============================================================
#  AUTO-UPDATE SCRIPT WITH PRE/POST SNAPSHOT
#  Takes a system snapshot, runs apt upgrade, compares results,
#  and generates an HTML change report
#  Run as: sudo bash 12-auto-update.sh
# =============================================================

set -euo pipefail

# =============================================================
#  CONFIGURATION
# =============================================================
REPORT_DIR="/var/log/admin-reports/updates"
HTML_FILE="${REPORT_DIR}/update-$(date +%Y%m%d_%H%M%S).html"
LOG_FILE="${REPORT_DIR}/update-$(date +%Y%m%d_%H%M%S).log"
SNAPSHOT_DIR="${REPORT_DIR}/snapshots"

DRY_RUN=false              # Set true to simulate only (no changes)
AUTO_REMOVE=true           # Run apt autoremove after upgrade
REBOOT_IF_REQUIRED=false   # Set true to auto-reboot if /var/run/reboot-required
SNAPSHOT_ENABLED=true      # Save pre/post package lists for diffing

MAIL_TO=""
MAIL_SUBJECT="System Update Report - $(hostname) - $(date +%Y-%m-%d)"

# =============================================================
#  COLOURS
# =============================================================
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
info()    { echo -e "${CYAN}[INFO]${RESET}  $*" | tee -a "$LOG_FILE"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*" | tee -a "$LOG_FILE"; }
alert()   { echo -e "${RED}[ALERT]${RESET} $*" | tee -a "$LOG_FILE"; }
ok()      { echo -e "${GREEN}[OK]${RESET}    $*" | tee -a "$LOG_FILE"; }
section() { echo -e "\n${BOLD}=== $* ===${RESET}" | tee -a "$LOG_FILE"; }

[[ $EUID -eq 0 ]] || { echo "Run as root: sudo $0"; exit 1; }
mkdir -p "$REPORT_DIR" "$SNAPSHOT_DIR"

START_TIME=$(date +%s)
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

section "System Auto-Update — $(date)"
$DRY_RUN && warn "DRY-RUN MODE — no changes will be made"

# =============================================================
#  PRE-SNAPSHOT
# =============================================================
PRE_SNAP="${SNAPSHOT_DIR}/pre-${TIMESTAMP}.txt"
POST_SNAP="${SNAPSHOT_DIR}/post-${TIMESTAMP}.txt"

if $SNAPSHOT_ENABLED; then
    section "Taking pre-update snapshot..."
    dpkg-query -W -f='${Package} ${Version}\n' 2>/dev/null | sort > "$PRE_SNAP"
    PRE_COUNT=$(wc -l < "$PRE_SNAP")
    info "Pre-snapshot: $PRE_COUNT packages → $PRE_SNAP"

    # Also save kernel info
    echo "KERNEL: $(uname -r)" >> "$PRE_SNAP"
    echo "OS: $(lsb_release -ds 2>/dev/null || cat /etc/os-release | grep PRETTY | cut -d= -f2 | tr -d '"')" >> "$PRE_SNAP"
fi

# =============================================================
#  APT UPDATE (refresh package lists)
# =============================================================
section "Running apt-get update..."
if $DRY_RUN; then
    info "[DRY-RUN] Would run: apt-get update"
else
    apt-get update -y 2>&1 | tee -a "$LOG_FILE" | grep -E "Hit:|Get:|Err:|Ign:|Reading" | head -20
    ok "Package lists updated"
fi

# =============================================================
#  LIST PENDING UPGRADES
# =============================================================
section "Checking pending upgrades..."
PENDING_LIST=$(apt-get -s upgrade 2>/dev/null | grep "^Inst" || true)
PENDING_COUNT=$(echo "$PENDING_LIST" | grep -c "^Inst" || echo 0)
SECURITY_COUNT=$(echo "$PENDING_LIST" | grep -ci "security" || echo 0)

info "Packages to upgrade : $PENDING_COUNT"
info "Security updates    : $SECURITY_COUNT"

# Build upgrade plan
declare -a PLANNED_UPGRADES
while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    pkg=$(echo "$line" | awk '{print $2}')
    new_ver=$(echo "$line" | grep -oP '(?<=\[)[^\]]+(?=\])' | head -1 || echo "?")
    old_ver=$(echo "$line" | grep -oP '(?<=\()[^)]+(?=\))' | head -1 || echo "?")
    is_security=$(echo "$line" | grep -ci "security" || echo 0)
    [[ "$is_security" -gt 0 ]] && type="security" || type="regular"
    PLANNED_UPGRADES+=("$pkg|$old_ver|$new_ver|$type")
done <<< "$PENDING_LIST"

for entry in "${PLANNED_UPGRADES[@]:0:20}"; do
    IFS='|' read -r pkg old new type <<< "$entry"
    [[ "$type" == "security" ]] && \
        alert "SECURITY: $pkg  $old → $new" || \
        info  "Upgrade : $pkg  $old → $new"
done
[[ ${#PLANNED_UPGRADES[@]} -gt 20 ]] && info "... and $((${#PLANNED_UPGRADES[@]} - 20)) more"

# =============================================================
#  RUN UPGRADE
# =============================================================
UPGRADE_STATUS="success"
UPGRADED_COUNT=0
ERRORS=""

if [[ $PENDING_COUNT -gt 0 ]]; then
    section "Running upgrade ($PENDING_COUNT packages)..."
    if $DRY_RUN; then
        info "[DRY-RUN] Would run: apt-get upgrade -y"
        UPGRADED_COUNT=$PENDING_COUNT
    else
        if DEBIAN_FRONTEND=noninteractive apt-get upgrade -y \
            -o Dpkg::Options::="--force-confdef" \
            -o Dpkg::Options::="--force-confold" \
            2>&1 | tee -a "$LOG_FILE"; then
            UPGRADED_COUNT=$PENDING_COUNT
            ok "Upgrade complete"
        else
            UPGRADE_STATUS="failed"
            ERRORS="apt-get upgrade returned non-zero exit code"
            alert "Upgrade FAILED — check log: $LOG_FILE"
        fi
    fi
else
    ok "System is already up to date — nothing to upgrade"
fi

# =============================================================
#  APT AUTOREMOVE
# =============================================================
AUTOREMOVE_COUNT=0
if $AUTO_REMOVE && ! $DRY_RUN; then
    section "Running autoremove..."
    AUTOREMOVE_OUT=$(apt-get autoremove -y 2>&1 | tee -a "$LOG_FILE" || true)
    AUTOREMOVE_COUNT=$(echo "$AUTOREMOVE_OUT" | grep -oP '\d+(?= packages? will be removed)' | head -1 || echo 0)
    [[ "$AUTOREMOVE_COUNT" -gt 0 ]] && ok "Autoremoved $AUTOREMOVE_COUNT package(s)" || info "No packages to autoremove"
fi

# =============================================================
#  POST-SNAPSHOT & DIFF
# =============================================================
declare -a ADDED_PKGS REMOVED_PKGS CHANGED_PKGS
DIFF_OUTPUT=""

if $SNAPSHOT_ENABLED && ! $DRY_RUN; then
    section "Taking post-update snapshot..."
    dpkg-query -W -f='${Package} ${Version}\n' 2>/dev/null | sort > "$POST_SNAP"
    echo "KERNEL: $(uname -r)" >> "$POST_SNAP"
    POST_COUNT=$(wc -l < "$POST_SNAP")
    info "Post-snapshot: $POST_COUNT packages → $POST_SNAP"

    # Diff pre vs post
    DIFF_OUTPUT=$(diff "$PRE_SNAP" "$POST_SNAP" 2>/dev/null || true)

    while IFS= read -r line; do
        [[ "$line" =~ ^[<>] ]] || continue
        pkg=$(echo "$line" | awk '{print $2}')
        ver=$(echo "$line" | awk '{print $3}')
        if [[ "$line" =~ ^'<' ]]; then
            # Line only in pre (removed or version changed)
            if grep -q "^> $pkg " "$POST_SNAP" 2>/dev/null; then
                new_ver=$(grep "^$pkg " "$POST_SNAP" | awk '{print $2}')
                CHANGED_PKGS+=("$pkg|$ver|$new_ver")
            else
                REMOVED_PKGS+=("$pkg|$ver")
            fi
        elif [[ "$line" =~ ^'>' ]]; then
            # Line only in post (added or version changed — already handled above)
            grep -q "^< $pkg " <(echo "$DIFF_OUTPUT") 2>/dev/null || \
                ADDED_PKGS+=("$pkg|$ver")
        fi
    done <<< "$DIFF_OUTPUT"
fi

# =============================================================
#  REBOOT CHECK
# =============================================================
REBOOT_REQUIRED=false
REBOOT_PKGS=""
[[ -f /var/run/reboot-required ]] && REBOOT_REQUIRED=true
[[ -f /var/run/reboot-required.pkgs ]] && REBOOT_PKGS=$(cat /var/run/reboot-required.pkgs)

if $REBOOT_REQUIRED; then
    warn "REBOOT REQUIRED — packages: $REBOOT_PKGS"
    if $REBOOT_IF_REQUIRED && ! $DRY_RUN; then
        warn "Scheduling reboot in 1 minute..."
        shutdown -r +1 "Auto-update requires reboot" || true
    fi
fi

# =============================================================
#  BUILD HTML REPORT
# =============================================================
DURATION=$(( $(date +%s) - START_TIME ))

hcolor="#1e8449"
[[ $SECURITY_COUNT -gt 0 ]] && hcolor="#e67e22"
[[ "$UPGRADE_STATUS" == "failed" ]] && hcolor="#c0392b"
$REBOOT_REQUIRED && hcolor="#9b59b6"

build_pkg_rows() {
    local -n arr=$1
    local cols=$2
    local rows=""
    for entry in "${arr[@]}"; do
        if [[ "$cols" == "3" ]]; then
            IFS='|' read -r pkg old new <<< "$entry"
            rows+="<tr><td><strong>$pkg</strong></td><td style='font-family:monospace;font-size:11px;color:#888'>$old</td><td style='font-family:monospace;font-size:11px;color:#1e8449'>$new</td></tr>"
        else
            IFS='|' read -r pkg ver <<< "$entry"
            rows+="<tr><td><strong>$pkg</strong></td><td style='font-family:monospace;font-size:11px'>$ver</td></tr>"
        fi
    done
    echo "$rows"
}

planned_rows=""
for entry in "${PLANNED_UPGRADES[@]}"; do
    IFS='|' read -r pkg old new type <<< "$entry"
    type_badge=$([[ "$type" == "security" ]] && echo "<span class='badge b-red'>🔒 Security</span>" || echo "<span class='badge b-blue'>Regular</span>")
    planned_rows+="<tr><td><strong>$pkg</strong></td><td style='font-family:monospace;font-size:11px;color:#888'>$old</td><td style='font-family:monospace;font-size:11px;color:#1e8449'>$new</td><td>$type_badge</td></tr>"
done

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
.s-purple{background:#f5eef8;border-top:4px solid #9b59b6;color:#6c3483}
h2{font-size:15px;color:#2c3e50;border-bottom:2px solid #eee;padding-bottom:7px;margin-top:24px}
table{width:100%;border-collapse:collapse;font-size:13px;margin-bottom:15px}
th{background:#2c3e50;color:white;padding:9px 12px;text-align:left}
td{padding:8px 12px;border-bottom:1px solid #f0f0f0;vertical-align:middle}
tr:hover td{background:#f5f8ff}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:bold;color:white;margin:1px}
.b-red{background:#c0392b}.b-green{background:#1e8449}.b-blue{background:#2e86c1}.b-purple{background:#9b59b6}
.alert-box{border-radius:8px;padding:14px 18px;margin-bottom:16px;font-weight:bold}
.reboot-box{background:#f5eef8;border:1px solid #9b59b6;color:#6c3483}
.footer{background:#f4f6f9;padding:15px 25px;font-size:12px;color:#888;border-top:1px solid #e0e0e0}
</style></head><body>
<div class="container">
<div class="header">
  <h1>🔄 Auto-Update Report</h1>
  <p>Host: <strong>$(hostname -f)</strong> &nbsp;|&nbsp; Mode: $($DRY_RUN && echo "DRY-RUN" || echo "LIVE") &nbsp;|&nbsp; $(date)</p>
</div>
<div class="content">
$($REBOOT_REQUIRED && echo "<div class='alert-box reboot-box'>⚡ Reboot required! Packages: $REBOOT_PKGS</div>")

<div class="stats">
  <div class="stat $([[ $UPGRADED_COUNT -gt 0 ]] && echo s-green || echo s-blue)"><div class="num">$UPGRADED_COUNT</div><div class="lbl">Upgraded</div></div>
  <div class="stat $([[ $SECURITY_COUNT -gt 0 ]] && echo s-orange || echo s-green)"><div class="num">$SECURITY_COUNT</div><div class="lbl">Security Updates</div></div>
  <div class="stat s-blue"><div class="num">$AUTOREMOVE_COUNT</div><div class="lbl">Autoremoved</div></div>
  <div class="stat $($REBOOT_REQUIRED && echo s-purple || echo s-green)"><div class="num">$($REBOOT_REQUIRED && echo "YES" || echo "NO")</div><div class="lbl">Reboot Needed</div></div>
  <div class="stat s-blue"><div class="num">${DURATION}s</div><div class="lbl">Duration</div></div>
</div>

<h2>📦 Packages Upgraded ($PENDING_COUNT)</h2>
<table><tr><th>Package</th><th>Old Version</th><th>New Version</th><th>Type</th></tr>
${planned_rows:-<tr><td colspan='4' style='text-align:center;color:#1e8449'>✅ System was already up to date</td></tr>}
</table>

$([ ${#CHANGED_PKGS[@]} -gt 0 ] && echo "
<h2>🔀 Changed Packages (Pre→Post Snapshot Diff)</h2>
<table><tr><th>Package</th><th>Before</th><th>After</th></tr>
$(build_pkg_rows CHANGED_PKGS 3)
</table>")

$([ ${#ADDED_PKGS[@]} -gt 0 ] && echo "
<h2>➕ New Packages Added</h2>
<table><tr><th>Package</th><th>Version</th></tr>
$(build_pkg_rows ADDED_PKGS 2)
</table>")

$([ ${#REMOVED_PKGS[@]} -gt 0 ] && echo "
<h2>➖ Packages Removed (Autoremoved)</h2>
<table><tr><th>Package</th><th>Version</th></tr>
$(build_pkg_rows REMOVED_PKGS 2)
</table>")

<h2>📋 Snapshot Files</h2>
<table><tr><th>File</th><th>Description</th></tr>
<tr><td style='font-family:monospace;font-size:12px'>$PRE_SNAP</td><td>Pre-update package list</td></tr>
$(! $DRY_RUN && echo "<tr><td style='font-family:monospace;font-size:12px'>$POST_SNAP</td><td>Post-update package list</td></tr>")
<tr><td style='font-family:monospace;font-size:12px'>$LOG_FILE</td><td>Full apt log output</td></tr>
</table>
</div>
<div class="footer">Generated by auto-update.sh &nbsp;|&nbsp; Status: $UPGRADE_STATUS &nbsp;|&nbsp; $(date)</div>
</div></body></html>
HTML

[[ -n "$MAIL_TO" ]] && command -v mail &>/dev/null && \
    mail -s "$MAIL_SUBJECT" -a "Content-Type: text/html" "$MAIL_TO" < "$HTML_FILE"

section "UPDATE COMPLETE"
echo "  Upgraded     : $UPGRADED_COUNT"
echo "  Security     : $SECURITY_COUNT"
echo "  Autoremoved  : $AUTOREMOVE_COUNT"
echo "  Status       : $UPGRADE_STATUS"
echo "  Reboot needed: $REBOOT_REQUIRED"
echo "  Report       : $HTML_FILE"
echo "  Log          : $LOG_FILE"
echo ""
