#!/usr/bin/env bash
# =============================================================
#  BULK USER ACCOUNT LOCK / UNLOCK
#  Lock or unlock multiple user accounts with full audit trail
#  Run as: sudo bash 05-bulk-lock-unlock.sh [lock|unlock|status] [user1 user2 ...]
#  Or run interactively with no args
# =============================================================

set -euo pipefail

# =============================================================
#  CONFIGURATION
# =============================================================
REPORT_DIR="/var/log/admin-reports/account-mgmt"
LOG_FILE="${REPORT_DIR}/account-changes.log"
MIN_UID=1000
PROTECTED_USERS=("root")  # Never touch these
MAIL_TO=""
MAIL_SUBJECT="Account Lock/Unlock Report - $(hostname) - $(date +%Y-%m-%d)"

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
touch "$LOG_FILE"

# =============================================================
#  HELPERS
# =============================================================
get_account_status() {
    local user="$1"
    local pw_status
    pw_status=$(passwd -S "$user" 2>/dev/null | awk '{print $2}' || echo "?")
    case "$pw_status" in
        P|PS)  echo "active" ;;
        L|LK)  echo "locked" ;;
        NP)    echo "no-password" ;;
        *)     echo "unknown" ;;
    esac
}

get_user_info() {
    local user="$1"
    local uid shell home last_login
    uid=$(id -u "$user" 2>/dev/null || echo "?")
    shell=$(getent passwd "$user" | cut -d: -f7 || echo "?")
    home=$(getent passwd "$user" | cut -d: -f6 || echo "?")
    last_login=$(lastlog -u "$user" 2>/dev/null | tail -1 | awk '{if($4=="**Never") print "Never"; else print $4,$5,$6,$9}' || echo "?")
    echo "${uid}|${shell}|${home}|${last_login}"
}

is_protected() {
    local user="$1"
    for p in "${PROTECTED_USERS[@]}"; do [[ "$user" == "$p" ]] && return 0; done
    return 1
}

audit_log() {
    local action="$1" user="$2" result="$3" reason="${4:-}"
    echo "$(date '+%Y-%m-%d %H:%M:%S') | ACTION=$action | USER=$user | RESULT=$result | BY=$(logname 2>/dev/null || echo root) | REASON=$reason" >> "$LOG_FILE"
}

# =============================================================
#  DISPLAY STATUS TABLE
# =============================================================
show_status() {
    section "Current Account Status"
    printf "%-20s %-8s %-10s %-25s %s\n" "USERNAME" "UID" "STATUS" "LAST LOGIN" "SHELL"
    printf "%s\n" "$(printf '%.0s-' {1..90})"

    while IFS=: read -r uname _ uid _ _ home shell; do
        [[ "$uid" -lt "$MIN_UID" ]] && continue
        [[ "$shell" =~ nologin|false|sync|halt ]] && continue

        status=$(get_account_status "$uname")
        last=$(lastlog -u "$uname" 2>/dev/null | tail -1 | awk '{if($4=="**Never") print "Never"; else print $4,$5,$6}' || echo "?")

        color="$GREEN"
        [[ "$status" == "locked" ]] && color="$RED"
        [[ "$status" == "no-password" ]] && color="$YELLOW"

        printf "${color}%-20s %-8s %-10s %-25s %s${RESET}\n" "$uname" "$uid" "$status" "$last" "$shell"
    done < /etc/passwd
    echo ""
}

# =============================================================
#  LOCK A USER
# =============================================================
lock_user() {
    local user="$1" reason="${2:-Manual lock}"
    local result=""

    if ! id "$user" &>/dev/null; then
        alert "User not found: $user"
        audit_log "LOCK" "$user" "FAILED:not_found" "$reason"
        return 1
    fi

    if is_protected "$user"; then
        alert "Protected user — refusing to lock: $user"
        audit_log "LOCK" "$user" "REFUSED:protected" "$reason"
        return 1
    fi

    local current_status
    current_status=$(get_account_status "$user")

    if [[ "$current_status" == "locked" ]]; then
        warn "Already locked: $user"
        return 0
    fi

    # Lock the password
    if passwd -l "$user" &>/dev/null; then
        # Also expire the account to prevent SSH key login too
        usermod --expiredate 1 "$user" &>/dev/null || true
        ok "Locked: $user"
        audit_log "LOCK" "$user" "SUCCESS" "$reason"
        echo "  $(date '+%Y-%m-%d %H:%M:%S') LOCKED $user" >> "$LOG_FILE"
        return 0
    else
        alert "Failed to lock: $user"
        audit_log "LOCK" "$user" "FAILED:passwd_error" "$reason"
        return 1
    fi
}

# =============================================================
#  UNLOCK A USER
# =============================================================
unlock_user() {
    local user="$1" reason="${2:-Manual unlock}"

    if ! id "$user" &>/dev/null; then
        alert "User not found: $user"
        audit_log "UNLOCK" "$user" "FAILED:not_found" "$reason"
        return 1
    fi

    if is_protected "$user"; then
        alert "Protected user — refusing to modify: $user"
        return 1
    fi

    local current_status
    current_status=$(get_account_status "$user")

    if [[ "$current_status" == "active" ]]; then
        warn "Already active: $user"
        return 0
    fi

    # Unlock password and restore account expiry
    if passwd -u "$user" &>/dev/null; then
        usermod --expiredate "" "$user" &>/dev/null || true
        ok "Unlocked: $user"
        audit_log "UNLOCK" "$user" "SUCCESS" "$reason"
        return 0
    else
        alert "Failed to unlock: $user"
        audit_log "UNLOCK" "$user" "FAILED:passwd_error" "$reason"
        return 1
    fi
}

# =============================================================
#  INTERACTIVE MODE
# =============================================================
interactive_mode() {
    section "Interactive Bulk Account Manager"
    show_status

    echo -e "${BOLD}Available actions:${RESET}"
    echo "  1) Lock specific users"
    echo "  2) Unlock specific users"
    echo "  3) Lock ALL inactive accounts (never logged in)"
    echo "  4) Lock accounts by inactivity (X days)"
    echo "  5) Show status only"
    echo "  6) View audit log"
    echo "  q) Quit"
    echo ""
    read -rp "Select action [1-6/q]: " choice

    case "$choice" in
        1)
            read -rp "Enter usernames to LOCK (space-separated): " -a users
            read -rp "Reason for locking: " reason
            echo ""
            section "Locking accounts..."
            for u in "${users[@]}"; do
                lock_user "$u" "$reason"
            done
            ;;
        2)
            read -rp "Enter usernames to UNLOCK (space-separated): " -a users
            read -rp "Reason for unlocking: " reason
            echo ""
            section "Unlocking accounts..."
            for u in "${users[@]}"; do
                unlock_user "$u" "$reason"
            done
            ;;
        3)
            echo ""
            warn "About to lock ALL accounts that have NEVER logged in."
            read -rp "Are you sure? (yes/no): " confirm
            [[ "$confirm" != "yes" ]] && echo "Cancelled." && return

            section "Locking never-logged-in accounts..."
            while IFS=: read -r uname _ uid _ _ _ shell; do
                [[ "$uid" -lt "$MIN_UID" ]] && continue
                [[ "$shell" =~ nologin|false ]] && continue
                last=$(lastlog -u "$uname" 2>/dev/null | tail -1)
                if [[ "$last" =~ \*\*Never ]]; then
                    lock_user "$uname" "Auto-lock: never logged in"
                fi
            done < /etc/passwd
            ;;
        4)
            read -rp "Lock accounts inactive for more than X days: " days
            echo ""
            warn "About to lock accounts inactive for more than ${days} days."
            read -rp "Are you sure? (yes/no): " confirm
            [[ "$confirm" != "yes" ]] && echo "Cancelled." && return

            now=$(date +%s)
            section "Locking inactive accounts..."
            while IFS=: read -r uname _ uid _ _ _ shell; do
                [[ "$uid" -lt "$MIN_UID" ]] && continue
                [[ "$shell" =~ nologin|false ]] && continue
                last_str=$(lastlog -u "$uname" 2>/dev/null | tail -1 | awk '{print $4,$5,$6,$9}')
                [[ "$last_str" =~ \*\*Never ]] && continue
                last_epoch=$(date -d "$last_str" +%s 2>/dev/null || echo 0)
                [[ "$last_epoch" -eq 0 ]] && continue
                inactive=$(( (now - last_epoch) / 86400 ))
                if [[ "$inactive" -ge "$days" ]]; then
                    lock_user "$uname" "Auto-lock: inactive ${inactive} days"
                fi
            done < /etc/passwd
            ;;
        5)
            show_status
            ;;
        6)
            echo ""
            section "Audit Log (last 50 entries)"
            tail -50 "$LOG_FILE" 2>/dev/null || echo "  Log is empty"
            ;;
        q|Q)
            echo "Bye."
            exit 0
            ;;
        *)
            echo "Invalid choice."
            ;;
    esac
}

# =============================================================
#  GENERATE HTML STATUS REPORT
# =============================================================
generate_report() {
    local html_file="${REPORT_DIR}/account-status-$(date +%Y%m%d_%H%M%S).html"

    declare -a locked_users active_users nologin_users

    while IFS=: read -r uname _ uid _ _ home shell; do
        [[ "$uid" -lt "$MIN_UID" ]] && continue
        status=$(get_account_status "$uname")
        info_data=$(get_user_info "$uname")
        IFS='|' read -r pu_uid pu_shell pu_home last_login <<< "$info_data"
        entry="${uname}|${pu_uid}|${status}|${last_login}|${pu_shell}"

        case "$status" in
            locked)     locked_users+=("$entry") ;;
            active)     active_users+=("$entry") ;;
            no-password) nologin_users+=("$entry") ;;
        esac
    done < /etc/passwd

    total=$((${#locked_users[@]} + ${#active_users[@]} + ${#nologin_users[@]}))

    build_rows() {
        local -n arr=$1
        for e in "${arr[@]}"; do
            IFS='|' read -r u uid st last shell <<< "$e"
            local sbadge
            case "$st" in
                locked)      sbadge="<span class='badge b-red'>LOCKED</span>" ;;
                active)      sbadge="<span class='badge b-green'>ACTIVE</span>" ;;
                no-password) sbadge="<span class='badge b-orange'>NO PASSWORD</span>" ;;
                *)           sbadge="<span class='badge b-gray'>$st</span>" ;;
            esac
            echo "<tr><td><strong>$u</strong></td><td>$uid</td><td>$sbadge</td><td>$last</td><td style='font-size:11px'>$shell</td></tr>"
        done
    }

    log_rows=""
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        log_rows+="<tr><td style='font-family:monospace;font-size:11px'>$(echo "$line" | sed 's/&/\&amp;/g')</td></tr>"
    done < <(tail -30 "$LOG_FILE" 2>/dev/null | tac || true)

    cat > "$html_file" <<HTML
<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>
body{font-family:Segoe UI,Arial,sans-serif;background:#f4f6f9;padding:20px}
.container{max-width:1000px;margin:auto;background:white;border-radius:10px;box-shadow:0 4px 15px rgba(0,0,0,.12);overflow:hidden}
.header{background:linear-gradient(135deg,#1a3a5c,#2e86c1);color:white;padding:30px}
.header h1{margin:0;font-size:24px}.header p{margin:5px 0 0;opacity:.85;font-size:14px}
.content{padding:25px}
.stats{display:flex;gap:15px;margin-bottom:25px;flex-wrap:wrap}
.stat{flex:1;min-width:100px;border-radius:8px;padding:14px;text-align:center}
.stat .num{font-size:28px;font-weight:bold}.stat .lbl{font-size:11px;margin-top:4px}
.s-red{background:#fdedec;border-top:4px solid #c0392b;color:#7b241c}
.s-green{background:#eafaf1;border-top:4px solid #1e8449;color:#1a5e20}
.s-orange{background:#fef5e7;border-top:4px solid #e67e22;color:#7d4e1a}
.s-blue{background:#eaf4fb;border-top:4px solid #2e86c1}
h2{font-size:15px;color:#2c3e50;border-bottom:2px solid #eee;padding-bottom:7px;margin-top:24px}
table{width:100%;border-collapse:collapse;font-size:13px;margin-bottom:15px}
th{background:#2c3e50;color:white;padding:9px 12px;text-align:left}
td{padding:8px 12px;border-bottom:1px solid #f0f0f0;vertical-align:middle}
tr:hover td{background:#f5f8ff}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:bold;color:white}
.b-red{background:#c0392b}.b-green{background:#1e8449}.b-orange{background:#e67e22}.b-gray{background:#7f8c8d}
.footer{background:#f4f6f9;padding:15px 25px;font-size:12px;color:#888;border-top:1px solid #e0e0e0}
</style></head><body>
<div class="container">
<div class="header">
  <h1>🔒 Account Status Report</h1>
  <p>Host: <strong>$(hostname -f)</strong> &nbsp;|&nbsp; $(date)</p>
</div>
<div class="content">
<div class="stats">
  <div class="stat s-blue"><div class="num">$total</div><div class="lbl">Total Accounts</div></div>
  <div class="stat s-green"><div class="num">${#active_users[@]}</div><div class="lbl">Active</div></div>
  <div class="stat s-red"><div class="num">${#locked_users[@]}</div><div class="lbl">Locked</div></div>
  <div class="stat s-orange"><div class="num">${#nologin_users[@]}</div><div class="lbl">No Password</div></div>
</div>

<h2>🔒 Locked Accounts</h2>
<table><tr><th>User</th><th>UID</th><th>Status</th><th>Last Login</th><th>Shell</th></tr>
$(build_rows locked_users)
$([ ${#locked_users[@]} -eq 0 ] && echo "<tr><td colspan='5' style='text-align:center;color:#888;'>No locked accounts</td></tr>")
</table>

<h2>✅ Active Accounts</h2>
<table><tr><th>User</th><th>UID</th><th>Status</th><th>Last Login</th><th>Shell</th></tr>
$(build_rows active_users)
</table>

<h2>📋 Recent Audit Log</h2>
<table><tr><th>Log Entry</th></tr>
${log_rows:-<tr><td style='text-align:center;color:#888;'>No audit entries yet</td></tr>}
</table>
</div>
<div class="footer">Generated by bulk-lock-unlock.sh &nbsp;|&nbsp; Audit log: $LOG_FILE &nbsp;|&nbsp; $(date)</div>
</div></body></html>
HTML

    echo ""
    ok "Status report saved: $html_file"
    [[ -n "$MAIL_TO" ]] && command -v mail &>/dev/null && \
        mail -s "$MAIL_SUBJECT" -a "Content-Type: text/html" "$MAIL_TO" < "$html_file"
}

# =============================================================
#  COMMAND-LINE MODE
# =============================================================
if [[ $# -ge 1 ]]; then
    ACTION="${1:-status}"
    shift
    USERS=("$@")

    case "$ACTION" in
        lock)
            [[ ${#USERS[@]} -eq 0 ]] && { echo "Usage: $0 lock user1 [user2 ...]"; exit 1; }
            section "Locking accounts: ${USERS[*]}"
            read -rp "Reason: " REASON
            for u in "${USERS[@]}"; do lock_user "$u" "$REASON"; done
            ;;
        unlock)
            [[ ${#USERS[@]} -eq 0 ]] && { echo "Usage: $0 unlock user1 [user2 ...]"; exit 1; }
            section "Unlocking accounts: ${USERS[*]}"
            read -rp "Reason: " REASON
            for u in "${USERS[@]}"; do unlock_user "$u" "$REASON"; done
            ;;
        status)
            show_status
            ;;
        report)
            generate_report
            ;;
        *)
            echo "Usage: $0 [lock|unlock|status|report] [users...]"
            echo "       $0              (interactive mode)"
            exit 1
            ;;
    esac
    generate_report
else
    interactive_mode
    generate_report
fi

section "Done. Audit log: $LOG_FILE"
