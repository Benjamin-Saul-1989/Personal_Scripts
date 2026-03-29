#!/usr/bin/env bash
# =============================================================
#  CRON JOB AUDITOR
#  Scans all user crontabs, system cron dirs, and anacron
#  entries — flags suspicious commands and world-writable scripts
#  Run as: sudo bash 16-cron-auditor.sh
# =============================================================

set -euo pipefail

# =============================================================
#  CONFIGURATION
# =============================================================
REPORT_DIR="/var/log/admin-reports/cron-audit"
HTML_FILE="${REPORT_DIR}/cron-audit-$(date +%Y%m%d_%H%M%S).html"
MIN_UID=0   # Include root (0) and all human users

# Suspicious command patterns (regex)
SUSPICIOUS_PATTERNS=(
    "curl\s.*\|.*sh"            # curl | sh (pipe to shell)
    "wget\s.*\|.*sh"            # wget | sh
    "curl\s.*-o.*&&"            # download and execute
    "wget\s.*-O.*&&"
    "/tmp/.*\.(sh|py|pl|rb)"    # scripts in /tmp
    "bash\s+-[ic]"              # bash -c or bash -i
    "python.*-c"                # python one-liners
    "perl.*-e"                  # perl one-liners
    "nc\s+-"                    # netcat
    "ncat\s"
    "/dev/tcp"                  # bash TCP redirect
    "base64\s+--decode"         # encoded payloads
    "base64\s+-d"
    "eval\s*\$\("               # eval obfuscation
    "chmod.*\+x.*&&"            # make executable then run
    "rm\s+-rf\s+/"              # dangerous deletion
    "mkfifo"                    # named pipe (reverse shell indicator)
    "xterm.*-display"           # X display hijack
)

MAIL_TO=""
MAIL_SUBJECT="Cron Audit Report - $(hostname) - $(date +%Y-%m-%d)"

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

declare -a ALL_ENTRIES      # All cron entries
declare -a FLAGGED_ENTRIES  # Suspicious entries
declare -i total_entries=0 flagged_count=0

# =============================================================
#  ANALYSIS FUNCTION
# =============================================================
analyse_entry() {
    local owner="$1"
    local source="$2"
    local schedule="$3"
    local command="$4"

    local flags=""

    # Check for suspicious patterns
    for pattern in "${SUSPICIOUS_PATTERNS[@]}"; do
        if echo "$command" | grep -qiP "$pattern" 2>/dev/null; then
            flags+="SUSPICIOUS:${pattern} "
            break
        fi
    done

    # Check if script file exists and permissions
    script_path=$(echo "$command" | grep -oP '(/[^|\s;]+\.(sh|py|pl|rb|bash))' | head -1 || echo "")
    if [[ -n "$script_path" && -f "$script_path" ]]; then
        perms=$(stat -c "%a" "$script_path" 2>/dev/null || echo "?")
        owner_f=$(stat -c "%U" "$script_path" 2>/dev/null || echo "?")
        [[ "$perms" =~ [2367] ]] && flags+="WORLD_WRITABLE_SCRIPT "
        [[ "$owner_f" != "$owner" && "$owner_f" != "root" ]] && flags+="SCRIPT_WRONG_OWNER($owner_f) "
    elif [[ -n "$script_path" && ! -f "$script_path" ]]; then
        flags+="SCRIPT_NOT_FOUND "
    fi

    # Check if binary in PATH for simple commands
    binary=$(echo "$command" | awk '{print $1}' | sed 's|.*/||')
    if [[ -n "$binary" && "$binary" != "/bin/" ]]; then
        full_path=$(echo "$command" | awk '{print $1}')
        if [[ "$full_path" =~ ^/ && ! -f "$full_path" ]]; then
            flags+="BINARY_NOT_FOUND "
        fi
    fi

    # Check for world-writable command
    cmd_binary=$(echo "$command" | awk '{print $1}')
    if [[ -f "$cmd_binary" ]]; then
        cmd_perms=$(stat -c "%a" "$cmd_binary" 2>/dev/null || echo "?")
        [[ "$cmd_perms" =~ [2367] ]] && flags+="WORLD_WRITABLE_BINARY "
    fi

    ALL_ENTRIES+=("${owner}|${source}|${schedule}|${command}|${flags}")
    total_entries=$((total_entries + 1))

    if [[ -n "$flags" ]]; then
        FLAGGED_ENTRIES+=("${owner}|${source}|${schedule}|${command}|${flags}")
        flagged_count=$((flagged_count + 1))
        alert "FLAGGED [$owner] $command — $flags"
    else
        info "OK [$owner] $command"
    fi
}

# =============================================================
#  PARSE A CRONTAB FILE
# =============================================================
parse_crontab() {
    local file="$1"
    local owner="${2:-unknown}"
    local source="${3:-$file}"

    [[ -f "$file" ]] || return

    while IFS= read -r line; do
        # Skip comments and empty lines
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
        # Skip env var lines (NAME=value)
        [[ "$line" =~ ^[[:space:]]*[A-Z_]+=.* ]] && continue
        # Skip @reboot/@hourly etc shorthand — still audit them
        local schedule command

        if [[ "$line" =~ ^@(reboot|hourly|daily|weekly|monthly|yearly|annually) ]]; then
            schedule=$(echo "$line" | awk '{print $1}')
            command=$(echo "$line" | cut -d' ' -f2-)
        elif [[ "$line" =~ ^[0-9*] || "$line" =~ ^[-*/] ]]; then
            # Standard 5-field crontab
            schedule=$(echo "$line" | awk '{print $1,$2,$3,$4,$5}')
            command=$(echo "$line" | awk '{$1=$2=$3=$4=$5=""; print $0}' | xargs)
        else
            continue
        fi

        [[ -z "$command" ]] && continue
        analyse_entry "$owner" "$source" "$schedule" "$command"
    done < "$file"
}

# =============================================================
#  SCAN USER CRONTABS
# =============================================================
section "Scanning user crontabs..."

# Root crontab
if crontab -l -u root &>/dev/null 2>&1; then
    TMP_ROOT=$(mktemp)
    crontab -l -u root 2>/dev/null > "$TMP_ROOT"
    parse_crontab "$TMP_ROOT" "root" "crontab (root)"
    rm -f "$TMP_ROOT"
fi

# All user crontabs from spool
for f in /var/spool/cron/crontabs/*; do
    [[ -f "$f" ]] || continue
    owner=$(basename "$f")
    parse_crontab "$f" "$owner" "crontab ($owner)"
done

# =============================================================
#  SCAN SYSTEM CRON FILES
# =============================================================
section "Scanning system cron files..."

# /etc/crontab
[[ -f /etc/crontab ]] && parse_crontab "/etc/crontab" "system" "/etc/crontab"

# /etc/cron.d/*
for f in /etc/cron.d/*; do
    [[ -f "$f" ]] || continue
    # System cron.d files have a username field after schedule
    while IFS= read -r line; do
        [[ -z "$line" || "$line" =~ ^# || "$line" =~ ^[A-Z_]+ ]] && continue
        if [[ "$line" =~ ^[0-9*@-] ]]; then
            sched=$(echo "$line" | awk '{print $1,$2,$3,$4,$5}')
            job_owner=$(echo "$line" | awk '{print $6}')
            cmd=$(echo "$line" | awk '{$1=$2=$3=$4=$5=$6=""; print $0}' | xargs)
            [[ -z "$cmd" ]] && continue
            analyse_entry "$job_owner" "$(basename "$f")" "$sched" "$cmd"
        fi
    done < "$f"
done

# /etc/cron.{hourly,daily,weekly,monthly}/*
for crondir in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
    [[ -d "$crondir" ]] || continue
    dir_name=$(basename "$crondir")
    for f in "$crondir"/*; do
        [[ -f "$f" && -x "$f" ]] || continue
        # Scan for suspicious content
        first_cmd=$(grep -v '^#\|^$' "$f" 2>/dev/null | head -3 | tr '\n' '; ')
        analyse_entry "root" "$dir_name" "@$dir_name" "$(basename "$f"): $first_cmd"
    done
done

# Anacron
if [[ -f /etc/anacrontab ]]; then
    section "Scanning anacrontab..."
    while IFS= read -r line; do
        [[ -z "$line" || "$line" =~ ^# || "$line" =~ ^[A-Z_]+ ]] && continue
        period=$(echo "$line" | awk '{print $1}')
        delay=$(echo "$line" | awk '{print $2}')
        job_id=$(echo "$line" | awk '{print $3}')
        command=$(echo "$line" | awk '{$1=$2=$3=""; print $0}' | xargs)
        [[ -z "$command" ]] && continue
        analyse_entry "root" "anacrontab" "period=$period delay=$delay" "$command"
    done < /etc/anacrontab
fi

# =============================================================
#  CHECK PERMISSIONS ON CRON DIRS
# =============================================================
section "Checking cron file permissions..."

declare -a PERM_ISSUES
for f in /etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.weekly /etc/cron.hourly /etc/cron.monthly; do
    [[ -e "$f" ]] || continue
    perms=$(stat -c "%a" "$f" 2>/dev/null || echo "?")
    owner=$(stat -c "%U" "$f" 2>/dev/null || echo "?")
    if [[ "$owner" != "root" ]]; then
        PERM_ISSUES+=("$f|$perms|$owner|Not owned by root!")
        alert "PERM: $f owned by $owner (should be root)"
    elif [[ "$perms" =~ [2367]$ ]]; then
        PERM_ISSUES+=("$f|$perms|$owner|World-writable!")
        warn "PERM: $f is world-writable ($perms)"
    else
        ok "PERM: $f — $perms, owner: $owner"
    fi
done

# =============================================================
#  CHECK CRON.ALLOW / CRON.DENY
# =============================================================
ALLOW_FILE_EXISTS=false
DENY_FILE_EXISTS=false
[[ -f /etc/cron.allow ]] && ALLOW_FILE_EXISTS=true
[[ -f /etc/cron.deny ]] && DENY_FILE_EXISTS=true

# =============================================================
#  BUILD HTML REPORT
# =============================================================
hcolor="#1e8449"
[[ $flagged_count -gt 0 ]] && hcolor="#e67e22"
[[ $flagged_count -gt 5 ]] && hcolor="#c0392b"

build_rows() {
    local -n arr=$1
    local rows=""
    for entry in "${arr[@]}"; do
        IFS='|' read -r owner source schedule command flags <<< "$entry"
        local flag_badges=""
        for f in $flags; do
            case "$f" in
                SUSPICIOUS*) flag_badges+="<span class='badge b-red'>SUSPICIOUS</span> " ;;
                WORLD_*) flag_badges+="<span class='badge b-red'>$f</span> " ;;
                *NOT_FOUND*) flag_badges+="<span class='badge b-orange'>$f</span> " ;;
                *WRONG_OWNER*) flag_badges+="<span class='badge b-orange'>$f</span> " ;;
                *) flag_badges+="<span class='badge b-gray'>$f</span> " ;;
            esac
        done
        [[ -z "$flag_badges" ]] && flag_badges="<span class='badge b-green'>✔ OK</span>"
        local short_cmd="${command:0:80}$([ ${#command} -gt 80 ] && echo '…' || true)"
        rows+="<tr>
          <td><strong>$owner</strong></td>
          <td style='font-size:11px;color:#555'>$source</td>
          <td style='font-family:monospace;font-size:11px'>$schedule</td>
          <td style='font-family:monospace;font-size:11px;word-break:break-all'>$short_cmd</td>
          <td>$flag_badges</td>
        </tr>"
    done
    echo "$rows"
}

perm_rows=""
for entry in "${PERM_ISSUES[@]}"; do
    IFS='|' read -r file perms owner issue <<< "$entry"
    perm_rows+="<tr><td style='font-family:monospace'>$file</td><td>$perms</td><td>$owner</td><td style='color:#c0392b;font-weight:bold'>$issue</td></tr>"
done

cat > "$HTML_FILE" <<HTML
<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>
body{font-family:Segoe UI,Arial,sans-serif;background:#f4f6f9;padding:20px}
.container{max-width:1150px;margin:auto;background:white;border-radius:10px;box-shadow:0 4px 15px rgba(0,0,0,.12);overflow:hidden}
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
h2{font-size:16px;color:#2c3e50;border-bottom:2px solid #eee;padding-bottom:8px;margin-top:28px}
table{width:100%;border-collapse:collapse;font-size:12px;margin-bottom:20px}
th{background:#2c3e50;color:white;padding:9px 12px;text-align:left}
td{padding:8px 12px;border-bottom:1px solid #f0f0f0;vertical-align:middle}
tr:hover td{background:#f5f8ff}
.badge{display:inline-block;padding:2px 7px;border-radius:10px;font-size:10px;font-weight:bold;color:white;margin:1px}
.b-red{background:#c0392b}.b-orange{background:#e67e22}.b-green{background:#1e8449}
.b-blue{background:#2e86c1}.b-gray{background:#7f8c8d}
.footer{background:#f4f6f9;padding:15px 25px;font-size:12px;color:#888;border-top:1px solid #e0e0e0}
</style></head><body>
<div class="container">
<div class="header">
  <h1>⏰ Cron Job Audit Report</h1>
  <p>Host: <strong>$(hostname -f)</strong> &nbsp;|&nbsp; $(date)</p>
</div>
<div class="content">
<div class="stats">
  <div class="stat s-blue"><div class="num">$total_entries</div><div class="lbl">Total Entries</div></div>
  <div class="stat $([[ $flagged_count -gt 0 ]] && echo s-orange || echo s-green)"><div class="num">$flagged_count</div><div class="lbl">Flagged</div></div>
  <div class="stat $([[ ${#PERM_ISSUES[@]} -gt 0 ]] && echo s-red || echo s-green)"><div class="num">${#PERM_ISSUES[@]}</div><div class="lbl">Permission Issues</div></div>
  <div class="stat $($ALLOW_FILE_EXISTS && echo s-green || echo s-orange)"><div class="num">$($ALLOW_FILE_EXISTS && echo "Yes" || echo "No")</div><div class="lbl">cron.allow exists</div></div>
</div>

<h2>⚠️ Flagged Entries ($flagged_count)</h2>
<table><tr><th>Owner</th><th>Source</th><th>Schedule</th><th>Command</th><th>Issues</th></tr>
$(build_rows FLAGGED_ENTRIES)
$([ $flagged_count -eq 0 ] && echo "<tr><td colspan='5' style='text-align:center;color:#1e8449;padding:15px'>✅ No suspicious cron entries found</td></tr>")
</table>

<h2>🔒 Cron File Permissions</h2>
<table><tr><th>File</th><th>Perms</th><th>Owner</th><th>Issue</th></tr>
${perm_rows:-<tr><td colspan='4' style='text-align:center;color:#1e8449;padding:15px'>✅ All permissions OK</td></tr>}
</table>

<h2>📋 All Cron Entries ($total_entries)</h2>
<table><tr><th>Owner</th><th>Source</th><th>Schedule</th><th>Command</th><th>Status</th></tr>
$(build_rows ALL_ENTRIES)
</table>
</div>
<div class="footer">Generated by cron-auditor.sh &nbsp;|&nbsp; $(date) &nbsp;|&nbsp; $(hostname)</div>
</div></body></html>
HTML

[[ -n "$MAIL_TO" ]] && command -v mail &>/dev/null && \
    mail -s "$MAIL_SUBJECT" -a "Content-Type: text/html" "$MAIL_TO" < "$HTML_FILE"

section "COMPLETE"
echo "  Total entries    : $total_entries"
echo "  Flagged          : $flagged_count"
echo "  Permission issues: ${#PERM_ISSUES[@]}"
echo "  Report           : $HTML_FILE"
[[ $flagged_count -gt 0 ]] && alert "$flagged_count suspicious cron entry/entries found!"
echo ""
