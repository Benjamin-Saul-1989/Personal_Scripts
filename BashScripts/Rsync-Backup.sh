#!/usr/bin/env bash
# =============================================================
#  INCREMENTAL RSYNC BACKUP WITH ROTATION
#  Hard-link based incremental backups, keeps N snapshots,
#  and emails an HTML report with sizes and status
#  Run as: sudo bash 11-rsync-backup.sh
# =============================================================

set -euo pipefail

# =============================================================
#  CONFIGURATION
# =============================================================

# Backup sets — each is an independent backup job
declare -a BACKUP_SETS=(
    "home:/home:/mnt/backup/home:30"
    # Format: "name:source_path:destination_path:keep_days"
    # Add more:
    # "etc:/etc:/mnt/backup/etc:30"
    # "var-www:/var/www:/mnt/backup/var-www:14"
    # "db-dumps:/var/backups/db:/mnt/backup/db:7"
)

# Rsync options
RSYNC_OPTS=(
    "-aH"           # Archive mode, preserve hard links
    "--delete"      # Remove files deleted from source
    "--delete-excluded"
    "--numeric-ids"
    "--stats"
    "--human-readable"
)

# Exclude patterns (applied to all backup sets)
EXCLUDES=(
    "--exclude=.cache"
    "--exclude=.thumbnails"
    "--exclude=*.tmp"
    "--exclude=*.log"
    "--exclude=/proc"
    "--exclude=/sys"
    "--exclude=/dev"
    "--exclude=/run"
    "--exclude=lost+found"
)

REPORT_DIR="/var/log/admin-reports/backup"
HTML_FILE="${REPORT_DIR}/backup-$(date +%Y%m%d_%H%M%S).html"
LOG_FILE="${REPORT_DIR}/backup-$(date +%Y%m%d_%H%M%S).log"
SNAPSHOT_FORMAT="%Y-%m-%d_%H%M%S"
PRE_BACKUP_HOOK=""   # Optional: path to script to run before backup
POST_BACKUP_HOOK=""  # Optional: path to script to run after backup
MAIL_TO=""
MAIL_SUBJECT="Backup Report - $(hostname) - $(date +%Y-%m-%d)"

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
mkdir -p "$REPORT_DIR"

declare -a RESULTS
START_TIME=$(date +%s)

# =============================================================
#  PRE-BACKUP HOOK
# =============================================================
if [[ -n "$PRE_BACKUP_HOOK" && -x "$PRE_BACKUP_HOOK" ]]; then
    section "Running pre-backup hook..."
    "$PRE_BACKUP_HOOK" && ok "Pre-hook succeeded" || warn "Pre-hook returned non-zero"
fi

# =============================================================
#  PROCESS EACH BACKUP SET
# =============================================================
for set_def in "${BACKUP_SETS[@]}"; do
    IFS=':' read -r SET_NAME SOURCE_PATH DEST_BASE KEEP_DAYS <<< "$set_def"

    section "Backup Set: $SET_NAME"
    info "Source : $SOURCE_PATH"
    info "Dest   : $DEST_BASE"
    info "Keep   : $KEEP_DAYS days"

    SET_START=$(date +%s)
    STATUS="success"
    ERROR_MSG=""
    TRANSFERRED=""
    TOTAL_SIZE=""
    SNAPSHOT_DIR=""

    # Validate source
    if [[ ! -e "$SOURCE_PATH" ]]; then
        STATUS="failed"
        ERROR_MSG="Source path does not exist: $SOURCE_PATH"
        alert "$ERROR_MSG"
        RESULTS+=("$SET_NAME|$SOURCE_PATH|$DEST_BASE|$STATUS|$ERROR_MSG|0|0|0|0")
        continue
    fi

    # Create destination directory
    mkdir -p "$DEST_BASE" 2>/dev/null || {
        STATUS="failed"
        ERROR_MSG="Cannot create destination: $DEST_BASE"
        alert "$ERROR_MSG"
        RESULTS+=("$SET_NAME|$SOURCE_PATH|$DEST_BASE|$STATUS|$ERROR_MSG|0|0|0|0")
        continue
    }

    # ==========================================================
    #  ROTATION SETUP
    # ==========================================================
    SNAPSHOT_NAME=$(date +"$SNAPSHOT_FORMAT")
    SNAPSHOT_DIR="${DEST_BASE}/${SNAPSHOT_NAME}"
    LATEST_LINK="${DEST_BASE}/latest"
    INCOMPLETE_DIR="${DEST_BASE}/incomplete"

    # Use the latest snapshot as the link-dest for hard-link dedup
    LINK_DEST_ARG=""
    if [[ -L "$LATEST_LINK" && -d "$(readlink -f "$LATEST_LINK")" ]]; then
        LINK_DEST_ARG="--link-dest=$(readlink -f "$LATEST_LINK")"
        info "Using link-dest: $(readlink -f "$LATEST_LINK")"
    else
        info "No previous snapshot found — performing full backup"
    fi

    # ==========================================================
    #  RUN RSYNC
    # ==========================================================
    info "Starting rsync..."
    TMP_RSYNC_OUT=$(mktemp)

    if rsync "${RSYNC_OPTS[@]}" "${EXCLUDES[@]}" \
        ${LINK_DEST_ARG} \
        --log-file="$LOG_FILE" \
        "$SOURCE_PATH/" \
        "${INCOMPLETE_DIR}/" \
        > "$TMP_RSYNC_OUT" 2>&1; then

        # Rename incomplete to final snapshot
        mv "$INCOMPLETE_DIR" "$SNAPSHOT_DIR"

        # Update 'latest' symlink
        rm -f "$LATEST_LINK"
        ln -s "$SNAPSHOT_DIR" "$LATEST_LINK"

        ok "Backup complete: $SNAPSHOT_DIR"

        # Extract stats from rsync output
        TRANSFERRED=$(grep "Number of regular files transferred" "$TMP_RSYNC_OUT" | grep -oP '[\d,]+' | tr -d ',' | head -1 || echo "?")
        TOTAL_SIZE=$(grep "Total file size" "$TMP_RSYNC_OUT" | grep -oP '[\d.]+ \w+' | head -1 || echo "?")
        SENT_SIZE=$(grep "Total transferred file size" "$TMP_RSYNC_OUT" | grep -oP '[\d.]+ \w+' | head -1 || echo "?")
        SPEED=$(grep "Transfer rate" "$TMP_RSYNC_OUT" | grep -oP '[\d.]+ \w+/s' | head -1 || echo "?")

        info "Files transferred : $TRANSFERRED"
        info "Total size        : $TOTAL_SIZE"
        info "Transferred size  : $SENT_SIZE"

    else
        EXIT_CODE=$?
        STATUS="failed"
        ERROR_MSG="rsync exited with code $EXIT_CODE"
        alert "$ERROR_MSG"
        # Keep incomplete dir for debugging
        SNAPSHOT_DIR="$INCOMPLETE_DIR (incomplete)"
        TRANSFERRED="0"
        TOTAL_SIZE="?"
        SENT_SIZE="?"
    fi

    rm -f "$TMP_RSYNC_OUT"

    # ==========================================================
    #  ROTATE OLD SNAPSHOTS
    # ==========================================================
    if [[ "$STATUS" == "success" ]]; then
        info "Rotating snapshots older than $KEEP_DAYS days..."
        DELETED_SNAPS=0
        while IFS= read -r old_snap; do
            [[ -d "$old_snap" ]] || continue
            snap_name=$(basename "$old_snap")
            # Parse snapshot date
            snap_date=$(echo "$snap_name" | grep -oP '^\d{4}-\d{2}-\d{2}' || echo "")
            [[ -z "$snap_date" ]] && continue
            snap_epoch=$(date -d "$snap_date" +%s 2>/dev/null || echo 0)
            now_epoch=$(date +%s)
            age_days=$(( (now_epoch - snap_epoch) / 86400 ))

            if [[ $age_days -gt $KEEP_DAYS ]]; then
                rm -rf "$old_snap"
                DELETED_SNAPS=$((DELETED_SNAPS + 1))
                info "Deleted old snapshot: $snap_name (${age_days}d old)"
            fi
        done < <(find "$DEST_BASE" -maxdepth 1 -type d -name "????-??-??_*" 2>/dev/null | sort || true)

        [[ $DELETED_SNAPS -gt 0 ]] && ok "Removed $DELETED_SNAPS old snapshot(s)"
    fi

    # ==========================================================
    #  COUNT SNAPSHOTS
    # ==========================================================
    SNAP_COUNT=$(find "$DEST_BASE" -maxdepth 1 -type d -name "????-??-??_*" 2>/dev/null | wc -l || echo 0)
    DEST_USAGE=$(du -sh "$DEST_BASE" 2>/dev/null | cut -f1 || echo "?")

    SET_DURATION=$(( $(date +%s) - SET_START ))

    RESULTS+=("$SET_NAME|$SOURCE_PATH|$DEST_BASE|$STATUS|${ERROR_MSG:-}|${TRANSFERRED:-?}|${TOTAL_SIZE:-?}|$SNAP_COUNT|$SET_DURATION|$DEST_USAGE")
    info "Duration: ${SET_DURATION}s | Snapshots: $SNAP_COUNT | Dest usage: $DEST_USAGE"
done

# =============================================================
#  POST-BACKUP HOOK
# =============================================================
if [[ -n "$POST_BACKUP_HOOK" && -x "$POST_BACKUP_HOOK" ]]; then
    section "Running post-backup hook..."
    "$POST_BACKUP_HOOK" && ok "Post-hook succeeded" || warn "Post-hook returned non-zero"
fi

# =============================================================
#  BUILD HTML REPORT
# =============================================================
TOTAL_DURATION=$(( $(date +%s) - START_TIME ))
SUCCESS_COUNT=$(printf '%s\n' "${RESULTS[@]}" | grep -c '|success|' || echo 0)
FAIL_COUNT=$(printf '%s\n' "${RESULTS[@]}" | grep -c '|failed|' || echo 0)

hcolor="#1e8449"
[[ $FAIL_COUNT -gt 0 ]] && hcolor="#c0392b"

result_rows=""
for entry in "${RESULTS[@]}"; do
    IFS='|' read -r name src dest status errmsg files size snaps dur usage <<< "$entry"
    case "$status" in
        success) badge="<span class='badge b-green'>✔ SUCCESS</span>" ;;
        failed)  badge="<span class='badge b-red'>✘ FAILED</span>" ;;
        *)       badge="<span class='badge b-gray'>$status</span>" ;;
    esac
    mins=$((dur / 60)); secs=$((dur % 60))
    duration_str="${mins}m ${secs}s"
    result_rows+="<tr>
      <td><strong>$name</strong></td>
      <td style='font-size:11px'>$src</td>
      <td style='font-size:11px'>$dest</td>
      <td>$badge</td>
      <td style='text-align:right'>$files</td>
      <td style='text-align:right'>$size</td>
      <td style='text-align:center'>$snaps</td>
      <td>$duration_str</td>
      <td>$usage</td>
      <td style='font-size:11px;color:#c0392b'>$errmsg</td>
    </tr>"
done

total_mins=$((TOTAL_DURATION / 60)); total_secs=$((TOTAL_DURATION % 60))

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
.stat .num{font-size:28px;font-weight:bold}.stat .lbl{font-size:11px;margin-top:4px}
.s-red{background:#fdedec;border-top:4px solid #c0392b;color:#7b241c}
.s-green{background:#eafaf1;border-top:4px solid #1e8449;color:#1a5e20}
.s-blue{background:#eaf4fb;border-top:4px solid #2e86c1}
.s-gray{background:#f2f3f4;border-top:4px solid #7f8c8d}
h2{font-size:16px;color:#2c3e50;border-bottom:2px solid #eee;padding-bottom:8px;margin-top:28px}
table{width:100%;border-collapse:collapse;font-size:12px;margin-bottom:20px}
th{background:#2c3e50;color:white;padding:9px 10px;text-align:left}
td{padding:8px 10px;border-bottom:1px solid #f0f0f0;vertical-align:middle}
tr:hover td{background:#f5f8ff}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:bold;color:white}
.b-red{background:#c0392b}.b-green{background:#1e8449}.b-gray{background:#7f8c8d}
.footer{background:#f4f6f9;padding:15px 25px;font-size:12px;color:#888;border-top:1px solid #e0e0e0}
</style></head><body>
<div class="container">
<div class="header">
  <h1>💾 Incremental Rsync Backup Report</h1>
  <p>Host: <strong>$(hostname -f)</strong> &nbsp;|&nbsp; Duration: ${total_mins}m ${total_secs}s &nbsp;|&nbsp; $(date)</p>
</div>
<div class="content">
<div class="stats">
  <div class="stat s-blue"><div class="num">${#RESULTS[@]}</div><div class="lbl">Backup Sets</div></div>
  <div class="stat s-green"><div class="num">$SUCCESS_COUNT</div><div class="lbl">Succeeded</div></div>
  <div class="stat s-red"><div class="num">$FAIL_COUNT</div><div class="lbl">Failed</div></div>
  <div class="stat s-gray"><div class="num">${total_mins}m</div><div class="lbl">Total Duration</div></div>
</div>

<h2>📦 Backup Results</h2>
<table>
  <tr><th>Set</th><th>Source</th><th>Destination</th><th>Status</th><th>Files</th><th>Size</th><th>Snapshots</th><th>Duration</th><th>Dest Usage</th><th>Error</th></tr>
  ${result_rows}
</table>

<h2>ℹ️ Backup Method: Hard-Link Incremental</h2>
<table><tr><th>Feature</th><th>Detail</th></tr>
<tr><td>Method</td><td>rsync with --link-dest (hard-link deduplication)</td></tr>
<tr><td>Storage efficiency</td><td>Unchanged files are hard-linked — only changed files use new space</td></tr>
<tr><td>Snapshot format</td><td>YYYY-MM-DD_HHMMSS directories under each destination</td></tr>
<tr><td>Rotation</td><td>Snapshots older than KEEP_DAYS days are automatically removed</td></tr>
<tr><td>Recovery</td><td>rsync /mnt/backup/home/latest/ /home/ (or any dated snapshot)</td></tr>
<tr><td>Log file</td><td>$LOG_FILE</td></tr>
</table>
</div>
<div class="footer">Generated by rsync-backup.sh &nbsp;|&nbsp; $(date)</div>
</div></body></html>
HTML

[[ -n "$MAIL_TO" ]] && command -v mail &>/dev/null && \
    mail -s "$MAIL_SUBJECT" -a "Content-Type: text/html" "$MAIL_TO" < "$HTML_FILE"

section "BACKUP COMPLETE"
echo "  Sets run   : ${#RESULTS[@]}"
echo "  Succeeded  : $SUCCESS_COUNT"
echo "  Failed     : $FAIL_COUNT"
echo "  Duration   : ${total_mins}m ${total_secs}s"
echo "  HTML report: $HTML_FILE"
echo "  Log file   : $LOG_FILE"
echo ""
[[ $FAIL_COUNT -gt 0 ]] && alert "One or more backup sets FAILED — check the report!"
