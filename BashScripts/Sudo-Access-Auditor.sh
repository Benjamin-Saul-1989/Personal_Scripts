#!/usr/bin/env bash
# =============================================================
#  SUDO ACCESS AUDITOR
#  Audits who has root/sudo access and flags suspicious grants
#  Run as: sudo bash 01-sudo-access-auditor.sh
# =============================================================

set -euo pipefail

# =============================================================
#  CONFIGURATION
# =============================================================
REPORT_DIR="/var/log/admin-reports/sudo-audit"
REPORT_FILE="${REPORT_DIR}/sudo-audit-$(date +%Y%m%d_%H%M%S).txt"
HTML_FILE="${REPORT_DIR}/sudo-audit-$(date +%Y%m%d_%H%M%S).html"

# Accounts that are EXPECTED to have sudo (won't be flagged)
APPROVED_SUDO_USERS=("ubuntu" "admin" "ansible")

# Min UID for human accounts (ignore system accounts below this)
MIN_UID=1000

# Email settings (leave MAIL_TO blank to skip email)
MAIL_TO=""
MAIL_FROM="alerts@$(hostname -f)"
MAIL_SUBJECT="Sudo Access Audit Report - $(hostname) - $(date +%Y-%m-%d)"

# =============================================================
#  COLOUR CODES
# =============================================================
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

# =============================================================
#  HELPERS
# =============================================================
info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
alert()   { echo -e "${RED}[ALERT]${RESET} $*"; }
ok()      { echo -e "${GREEN}[OK]${RESET}    $*"; }
section() { echo -e "\n${BOLD}=== $* ===${RESET}"; }

require_root() {
    [[ $EUID -eq 0 ]] || { echo "Run as root: sudo $0"; exit 1; }
}

mkdir -p "$REPORT_DIR"

# =============================================================
#  COLLECT DATA
# =============================================================
require_root

declare -A SUDO_USERS
declare -A FLAGS

section "Scanning sudo access..."

# ── 1. Members of sudo / wheel / admin groups ────────────────
for grp in sudo wheel admin root; do
    if getent group "$grp" &>/dev/null; then
        members=$(getent group "$grp" | cut -d: -f4)
        IFS=',' read -ra mlist <<< "$members"
        for u in "${mlist[@]}"; do
            [[ -z "$u" ]] && continue
            SUDO_USERS["$u"]+="group:$grp "
        done
        info "Group '$grp': ${members:-<empty>}"
    fi
done

# ── 2. Sudoers file ──────────────────────────────────────────
if [[ -f /etc/sudoers ]]; then
    while IFS= read -r line; do
        # Skip comments and empty lines
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${line// }" ]] && continue
        # Match user ALL= lines (not group %)
        if [[ "$line" =~ ^([A-Za-z0-9_-]+)[[:space:]]+ALL ]]; then
            u="${BASH_REMATCH[1]}"
            SUDO_USERS["$u"]+="sudoers "
            # Flag NOPASSWD
            [[ "$line" =~ NOPASSWD ]] && FLAGS["$u"]+="NOPASSWD "
        fi
    done < /etc/sudoers
fi

# ── 3. /etc/sudoers.d/* ──────────────────────────────────────
if [[ -d /etc/sudoers.d ]]; then
    for f in /etc/sudoers.d/*; do
        [[ -f "$f" ]] || continue
        while IFS= read -r line; do
            [[ "$line" =~ ^[[:space:]]*# ]] && continue
            [[ -z "${line// }" ]] && continue
            if [[ "$line" =~ ^([A-Za-z0-9_-]+)[[:space:]]+ALL ]]; then
                u="${BASH_REMATCH[1]}"
                SUDO_USERS["$u"]+="sudoers.d:$(basename "$f") "
                [[ "$line" =~ NOPASSWD ]] && FLAGS["$u"]+="NOPASSWD "
            fi
        done < "$f"
    done
fi

# ── 4. UID=0 accounts (shadow root) ──────────────────────────
while IFS=: read -r uname _ uid _; do
    if [[ "$uid" -eq 0 && "$uname" != "root" ]]; then
        SUDO_USERS["$uname"]+="UID=0 "
        FLAGS["$uname"]+="SHADOW_ROOT "
        alert "Shadow root account found: $uname (UID=0)"
    fi
done < /etc/passwd

# =============================================================
#  ANALYSE EACH USER
# =============================================================
section "Analysing users..."

declare -a FLAGGED_USERS
declare -a CLEAN_USERS
declare -a UNKNOWN_USERS

for u in "${!SUDO_USERS[@]}"; do
    sources="${SUDO_USERS[$u]}"
    flags="${FLAGS[$u]:-}"
    uid=$(id -u "$u" 2>/dev/null || echo "?")
    shell=$(getent passwd "$u" 2>/dev/null | cut -d: -f7 || echo "?")
    last=$(last -n1 "$u" 2>/dev/null | head -1 | awk '{print $4,$5,$6,$7}' || echo "never")

    # Check if approved
    approved=false
    for a in "${APPROVED_SUDO_USERS[@]}"; do
        [[ "$u" == "$a" ]] && approved=true && break
    done

    # Extra flags
    [[ "$shell" =~ nologin|false ]] && flags+="NO_SHELL "
    [[ "$uid" != "?" && "$uid" -lt "$MIN_UID" && "$uid" -ne 0 ]] && flags+="SYSTEM_ACCOUNT "
    ! id "$u" &>/dev/null && flags+="USER_NOT_FOUND "

    if [[ -n "$flags" ]]; then
        FLAGGED_USERS+=("$u|$uid|$shell|$sources|$flags|$last")
        alert "FLAGGED: $u (uid=$uid) — $flags"
    elif [[ "$approved" == false ]]; then
        UNKNOWN_USERS+=("$u|$uid|$shell|$sources||$last")
        warn "UNAPPROVED: $u (uid=$uid) — $sources"
    else
        CLEAN_USERS+=("$u|$uid|$shell|$sources||$last")
        ok "Approved: $u (uid=$uid)"
    fi
done

# =============================================================
#  GENERATE TEXT REPORT
# =============================================================
{
echo "======================================================"
echo "  SUDO ACCESS AUDIT REPORT"
echo "  Host    : $(hostname -f)"
echo "  Date    : $(date)"
echo "  Kernel  : $(uname -r)"
echo "======================================================"
echo ""
echo "SUMMARY"
echo "-------"
echo "  Total sudo users   : ${#SUDO_USERS[@]}"
echo "  Flagged (anomalies): ${#FLAGGED_USERS[@]}"
echo "  Unapproved (review): ${#UNKNOWN_USERS[@]}"
echo "  Approved/clean     : ${#CLEAN_USERS[@]}"
echo ""

echo "FLAGGED USERS (Requires Immediate Review)"
echo "-----------------------------------------"
if [[ ${#FLAGGED_USERS[@]} -eq 0 ]]; then
    echo "  None"
else
    for entry in "${FLAGGED_USERS[@]}"; do
        IFS='|' read -r u uid shell sources flags last <<< "$entry"
        printf "  %-20s uid=%-6s shell=%-20s\n" "$u" "$uid" "$shell"
        printf "  %-20s Sources : %s\n" "" "$sources"
        printf "  %-20s FLAGS   : %s\n" "" "$flags"
        printf "  %-20s Last    : %s\n" "" "$last"
        echo ""
    done
fi

echo "UNAPPROVED USERS (Not in approved list)"
echo "----------------------------------------"
if [[ ${#UNKNOWN_USERS[@]} -eq 0 ]]; then
    echo "  None"
else
    for entry in "${UNKNOWN_USERS[@]}"; do
        IFS='|' read -r u uid shell sources flags last <<< "$entry"
        printf "  %-20s uid=%-6s  Last: %s\n" "$u" "$uid" "$last"
        printf "  %-20s Sources : %s\n" "" "$sources"
        echo ""
    done
fi

echo "APPROVED USERS"
echo "--------------"
for entry in "${CLEAN_USERS[@]}"; do
    IFS='|' read -r u uid shell sources flags last <<< "$entry"
    printf "  %-20s uid=%-6s  Last: %s\n" "$u" "$uid" "$last"
done

echo ""
echo "ROOT (UID=0) ACCOUNTS"
echo "---------------------"
awk -F: '$3==0 {print "  "$1}' /etc/passwd

echo ""
echo "RAW SUDOERS ENTRIES"
echo "-------------------"
grep -v '^#' /etc/sudoers 2>/dev/null | grep -v '^$' || echo "  Could not read"

} | tee "$REPORT_FILE"

# =============================================================
#  GENERATE HTML REPORT
# =============================================================
flag_count=${#FLAGGED_USERS[@]}
unknown_count=${#UNKNOWN_USERS[@]}
clean_count=${#CLEAN_USERS[@]}
total_count=${#SUDO_USERS[@]}

header_color="#c0392b"
[[ $flag_count -eq 0 && $unknown_count -eq 0 ]] && header_color="#1e8449"
[[ $flag_count -eq 0 && $unknown_count -gt 0 ]]  && header_color="#e67e22"

build_rows() {
    local arr=("$@")
    local rows=""
    for entry in "${arr[@]}"; do
        IFS='|' read -r u uid shell sources flags last <<< "$entry"
        local flag_html=""
        for f in $flags; do
            flag_html+="<span class='badge badge-red'>$f</span> "
        done
        rows+="<tr><td><strong>$u</strong></td><td>$uid</td><td>$shell</td><td>$sources</td><td>$flag_html</td><td>$last</td></tr>"
    done
    echo "$rows"
}

cat > "$HTML_FILE" <<HTML
<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>
body{font-family:Segoe UI,Arial,sans-serif;background:#f4f6f9;padding:20px;margin:0}
.container{max-width:1100px;margin:auto;background:white;border-radius:10px;box-shadow:0 4px 15px rgba(0,0,0,.12);overflow:hidden}
.header{background:linear-gradient(135deg,${header_color},#1a252f);color:white;padding:30px}
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
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:bold;margin:1px;color:white}
.badge-red{background:#c0392b}.badge-orange{background:#e67e22}.badge-green{background:#1e8449}
.alert-box{background:#fdedec;border:1px solid #c0392b;border-radius:8px;padding:14px 18px;margin-bottom:20px;color:#7b241c;font-weight:bold}
.footer{background:#f4f6f9;padding:15px 25px;font-size:12px;color:#888;border-top:1px solid #e0e0e0}
</style></head><body>
<div class="container">
<div class="header">
  <h1>🔐 Sudo Access Audit Report</h1>
  <p>Host: <strong>$(hostname -f)</strong> &nbsp;|&nbsp; $(date)</p>
</div>
<div class="content">
$([ $flag_count -gt 0 ] && echo "<div class='alert-box'>🚨 $flag_count flagged account(s) require immediate review!</div>")
<div class="stats">
  <div class="stat s-blue"><div class="num">$total_count</div><div class="lbl">Total Sudo Users</div></div>
  <div class="stat s-red"><div class="num">$flag_count</div><div class="lbl">Flagged</div></div>
  <div class="stat s-orange"><div class="num">$unknown_count</div><div class="lbl">Unapproved</div></div>
  <div class="stat s-green"><div class="num">$clean_count</div><div class="lbl">Approved</div></div>
</div>

<h2>🚨 Flagged Users</h2>
<table><tr><th>User</th><th>UID</th><th>Shell</th><th>Source</th><th>Flags</th><th>Last Login</th></tr>
$(build_rows "${FLAGGED_USERS[@]}")
$([ ${#FLAGGED_USERS[@]} -eq 0 ] && echo "<tr><td colspan='6' style='text-align:center;color:#1e8449;'>✅ No flagged users</td></tr>")
</table>

<h2>⚠️ Unapproved Users (Review Required)</h2>
<table><tr><th>User</th><th>UID</th><th>Shell</th><th>Source</th><th>Flags</th><th>Last Login</th></tr>
$(build_rows "${UNKNOWN_USERS[@]}")
$([ ${#UNKNOWN_USERS[@]} -eq 0 ] && echo "<tr><td colspan='6' style='text-align:center;color:#1e8449;'>✅ No unapproved users</td></tr>")
</table>

<h2>✅ Approved Users</h2>
<table><tr><th>User</th><th>UID</th><th>Shell</th><th>Source</th><th>Flags</th><th>Last Login</th></tr>
$(build_rows "${CLEAN_USERS[@]}")
</table>

<h2>🔑 UID=0 Accounts</h2>
<table><tr><th>Username</th><th>Note</th></tr>
$(awk -F: '$3==0{print "<tr><td><strong>"$1"</strong></td><td>"($1=="root"?"Standard root":"⚠️ Shadow root account!")"</td></tr>"}' /etc/passwd)
</table>
</div>
<div class="footer">Generated by sudo-access-auditor.sh &nbsp;|&nbsp; $(date) &nbsp;|&nbsp; $(hostname)</div>
</div></body></html>
HTML

# =============================================================
#  EMAIL (optional)
# =============================================================
if [[ -n "$MAIL_TO" ]] && command -v mail &>/dev/null; then
    mail -s "$MAIL_SUBJECT" -a "Content-Type: text/html" "$MAIL_TO" < "$HTML_FILE"
    info "Report emailed to $MAIL_TO"
fi

# =============================================================
#  SUMMARY
# =============================================================
section "AUDIT COMPLETE"
echo -e "  Text report : $REPORT_FILE"
echo -e "  HTML report : $HTML_FILE"
echo ""
[[ $flag_count -gt 0 ]]    && alert "$flag_count flagged user(s) — immediate review required!"
[[ $unknown_count -gt 0 ]] && warn  "$unknown_count unapproved user(s) — review recommended"
[[ $flag_count -eq 0 && $unknown_count -eq 0 ]] && ok "No anomalies detected"
echo ""
