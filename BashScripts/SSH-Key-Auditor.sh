#!/usr/bin/env bash
# =============================================================
#  SSH KEY AUDITOR
#  Audits all authorized_keys files across users, checks key
#  types, sizes, duplicates, and flags weak/unknown keys
#  Run as: sudo bash 03-ssh-key-auditor.sh
# =============================================================

set -euo pipefail

# =============================================================
#  CONFIGURATION
# =============================================================
REPORT_DIR="/var/log/admin-reports/ssh-audit"
HTML_FILE="${REPORT_DIR}/ssh-audit-$(date +%Y%m%d_%H%M%S).html"
MIN_UID=1000
MIN_RSA_BITS=2048      # Flag RSA keys smaller than this
MAIL_TO=""
MAIL_SUBJECT="SSH Key Audit - $(hostname) - $(date +%Y-%m-%d)"

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
#  DATA STRUCTURES
# =============================================================
declare -a ALL_KEYS          # All discovered keys
declare -a FLAGGED_KEYS      # Keys with issues
declare -A KEY_FINGERPRINTS  # fp -> "user:file" for dup detection
declare -a DUPLICATE_KEYS    # Duplicate fingerprints
declare -i total_keys=0 flagged_count=0 dup_count=0

# =============================================================
#  SCAN GLOBAL AUTHORIZED_KEYS
# =============================================================
section "Scanning SSH configuration..."

sshd_config="/etc/ssh/sshd_config"
auth_keys_pattern="authorized_keys"
if [[ -f "$sshd_config" ]]; then
    ak=$(grep -i "^AuthorizedKeysFile" "$sshd_config" | awk '{print $2}' | head -1 || echo "")
    [[ -n "$ak" ]] && auth_keys_pattern="$ak"
fi
info "AuthorizedKeysFile pattern: $auth_keys_pattern"

# Global authorized_keys locations
GLOBAL_KEYS_FILES=("/etc/ssh/authorized_keys" "/root/.ssh/authorized_keys")

# =============================================================
#  ANALYSE A SINGLE KEY LINE
# =============================================================
analyse_key() {
    local user="$1" file="$2" line="$3"
    local flags="" type="" bits="" fingerprint="" comment=""

    # Extract key type
    type=$(echo "$line" | awk '{print $1}')
    keydata=$(echo "$line" | awk '{print $2}')
    comment=$(echo "$line" | awk '{print $3}')

    # Get fingerprint and bit size
    tmpkey=$(mktemp)
    echo "$line" > "$tmpkey"
    fp_output=$(ssh-keygen -l -f "$tmpkey" 2>/dev/null || echo "")
    rm -f "$tmpkey"

    bits=$(echo "$fp_output" | awk '{print $1}')
    fingerprint=$(echo "$fp_output" | awk '{print $2}')

    # Flag checks
    case "$type" in
        ssh-rsa)
            [[ -n "$bits" && "$bits" -lt "$MIN_RSA_BITS" ]] && flags+="WEAK_RSA(<${MIN_RSA_BITS}bit) "
            ;;
        ssh-dss|ssh-dsa)
            flags+="DSA_DEPRECATED "
            ;;
        ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521)
            flags+="ECDSA_NIST "  # Informational — NIST curves are ok but note them
            ;;
        ssh-ed25519)
            : # Best — no flag
            ;;
        *)
            flags+="UNKNOWN_TYPE "
            ;;
    esac

    [[ -z "$comment" ]] && flags+="NO_COMMENT "
    [[ "$line" =~ ^ssh-.*from= ]] && flags+="HAS_FROM_RESTRICTION "  # good, note it
    [[ "$line" =~ command= ]]     && flags+="HAS_COMMAND_RESTRICTION "

    # Duplicate detection
    if [[ -n "$fingerprint" ]]; then
        if [[ -v "KEY_FINGERPRINTS[$fingerprint]" ]]; then
            flags+="DUPLICATE_KEY "
            DUPLICATE_KEYS+=("$fingerprint|$user|$file|${KEY_FINGERPRINTS[$fingerprint]}")
            dup_count+=1
        else
            KEY_FINGERPRINTS["$fingerprint"]="${user}:${file}"
        fi
    fi

    ALL_KEYS+=("${user}|${file}|${type}|${bits}|${fingerprint}|${comment}|${flags}")
    [[ -n "$flags" && ! "$flags" =~ ^(HAS_FROM_RESTRICTION|HAS_COMMAND_RESTRICTION|ECDSA_NIST).*$ ]] && \
        FLAGGED_KEYS+=("${user}|${file}|${type}|${bits}|${fingerprint}|${comment}|${flags}") && flagged_count+=1
    total_keys+=1
}

# =============================================================
#  SCAN ALL USER HOME DIRECTORIES
# =============================================================
section "Scanning user SSH keys..."

# Root
root_ak="/root/.ssh/authorized_keys"
if [[ -f "$root_ak" ]]; then
    info "Scanning root: $root_ak"
    while IFS= read -r line; do
        [[ -z "$line" || "$line" =~ ^# ]] && continue
        analyse_key "root" "$root_ak" "$line"
    done < "$root_ak"
fi

# All human users
while IFS=: read -r uname _ uid _ _ homedir _; do
    [[ "$uid" -lt "$MIN_UID" ]] && continue
    [[ -z "$homedir" || ! -d "$homedir" ]] && continue

    ak_file="${homedir}/.ssh/authorized_keys"
    [[ ! -f "$ak_file" ]] && continue

    # Check permissions
    dir_perms=$(stat -c "%a" "${homedir}/.ssh" 2>/dev/null || echo "?")
    file_perms=$(stat -c "%a" "$ak_file" 2>/dev/null || echo "?")
    file_owner=$(stat -c "%U" "$ak_file" 2>/dev/null || echo "?")

    info "Scanning $uname: $ak_file (perms: $file_perms, owner: $file_owner)"

    # Permission warnings
    [[ "$dir_perms" != "700" && "$dir_perms" != "?" ]] && \
        warn "$uname: .ssh dir permissions are $dir_perms (should be 700)"
    [[ "$file_perms" != "600" && "$file_perms" != "?" ]] && \
        warn "$uname: authorized_keys permissions are $file_perms (should be 600)"
    [[ "$file_owner" != "$uname" && "$file_owner" != "?" ]] && \
        warn "$uname: authorized_keys owned by $file_owner (should be $uname)"

    key_count=0
    while IFS= read -r line; do
        [[ -z "$line" || "$line" =~ ^# ]] && continue
        analyse_key "$uname" "$ak_file" "$line"
        key_count+=1
    done < "$ak_file"

    [[ $key_count -eq 0 ]] && info "$uname: authorized_keys is empty"

done < /etc/passwd

# =============================================================
#  SCAN SYSTEM SSH HOST KEYS
# =============================================================
section "Checking SSH host key strengths..."
declare -a HOST_KEY_INFO
for f in /etc/ssh/ssh_host_*_key.pub; do
    [[ -f "$f" ]] || continue
    fp=$(ssh-keygen -l -f "$f" 2>/dev/null || echo "?")
    HOST_KEY_INFO+=("$f|$fp")
    info "Host key: $fp"
done

# =============================================================
#  BUILD HTML REPORT
# =============================================================
build_key_rows() {
    local -n arr=$1
    local rows=""
    for entry in "${arr[@]}"; do
        IFS='|' read -r user file type bits fp comment flags <<< "$entry"
        local badges=""
        for f in $flags; do
            case "$f" in
                WEAK*|DSA*|UNKNOWN*|DUPLICATE*) badges+="<span class='badge b-red'>$f</span> " ;;
                NO_COMMENT)                     badges+="<span class='badge b-orange'>$f</span> " ;;
                HAS_*|ECDSA*)                   badges+="<span class='badge b-green'>$f</span> " ;;
                *)                              badges+="<span class='badge b-gray'>$f</span> " ;;
            esac
        done
        [[ -z "$badges" ]] && badges="<span class='badge b-green'>✔ OK</span>"
        local type_badge=""
        case "$type" in
            ssh-ed25519)   type_badge="<span class='badge b-green'>ed25519</span>" ;;
            ssh-rsa)       type_badge="<span class='badge b-blue'>RSA</span>" ;;
            ecdsa-*)       type_badge="<span class='badge b-blue'>ECDSA</span>" ;;
            ssh-dss|ssh-dsa) type_badge="<span class='badge b-red'>DSA ⚠</span>" ;;
            *)             type_badge="<span class='badge b-gray'>$type</span>" ;;
        esac
        local short_fp="${fp:0:20}…"
        local short_file
        short_file=$(basename "$(dirname "$file")")/$(basename "$file")
        rows+="<tr><td><strong>$user</strong></td><td style='font-size:11px'>$short_file</td><td>$type_badge</td><td>$bits</td><td style='font-family:monospace;font-size:11px'>$short_fp</td><td style='font-size:11px;color:#555'>$comment</td><td>$badges</td></tr>"
    done
    echo "$rows"
}

dup_rows=""
for entry in "${DUPLICATE_KEYS[@]}"; do
    IFS='|' read -r fp user1 file1 orig <<< "$entry"
    dup_rows+="<tr><td style='font-family:monospace;font-size:11px'>${fp:0:30}…</td><td>$user1</td><td style='font-size:11px'>$file1</td><td>${orig%%:*}</td><td style='font-size:11px'>${orig##*:}</td></tr>"
done

host_rows=""
for entry in "${HOST_KEY_INFO[@]}"; do
    IFS='|' read -r file fp <<< "$entry"
    host_rows+="<tr><td>$(basename "$file")</td><td style='font-family:monospace;font-size:12px'>$fp</td></tr>"
done

hcolor="#1e8449"
[[ $flagged_count -gt 0 ]] && hcolor="#c0392b"

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
th{background:#2c3e50;color:white;padding:9px 10px;text-align:left}
td{padding:8px 10px;border-bottom:1px solid #f0f0f0;vertical-align:middle}
tr:hover td{background:#f5f8ff}
.badge{display:inline-block;padding:2px 7px;border-radius:10px;font-size:10px;font-weight:bold;color:white;margin:1px}
.b-red{background:#c0392b}.b-orange{background:#e67e22}.b-green{background:#1e8449}
.b-blue{background:#2e86c1}.b-gray{background:#7f8c8d}
.alert-box{background:#fdedec;border:1px solid #c0392b;border-radius:8px;padding:14px 18px;margin-bottom:20px;color:#7b241c;font-weight:bold}
.footer{background:#f4f6f9;padding:15px 25px;font-size:12px;color:#888;border-top:1px solid #e0e0e0}
</style></head><body>
<div class="container">
<div class="header">
  <h1>🔑 SSH Key Audit Report</h1>
  <p>Host: <strong>$(hostname -f)</strong> &nbsp;|&nbsp; $(date)</p>
</div>
<div class="content">
$([ $flagged_count -gt 0 ] && echo "<div class='alert-box'>🚨 $flagged_count key(s) have issues requiring review!</div>")
<div class="stats">
  <div class="stat s-blue"><div class="num">$total_keys</div><div class="lbl">Total Keys</div></div>
  <div class="stat s-red"><div class="num">$flagged_count</div><div class="lbl">Flagged</div></div>
  <div class="stat s-orange"><div class="num">$dup_count</div><div class="lbl">Duplicates</div></div>
  <div class="stat s-green"><div class="num">$((total_keys - flagged_count - dup_count))</div><div class="lbl">Clean</div></div>
</div>

<h2>⚠️ Flagged Keys</h2>
<table><tr><th>User</th><th>File</th><th>Type</th><th>Bits</th><th>Fingerprint</th><th>Comment</th><th>Issues</th></tr>
$(build_key_rows FLAGGED_KEYS)
$([ $flagged_count -eq 0 ] && echo "<tr><td colspan='7' style='text-align:center;color:#1e8449;padding:15px;'>✅ No flagged keys</td></tr>")
</table>

<h2>🔁 Duplicate Keys (same key on multiple accounts)</h2>
<table><tr><th>Fingerprint</th><th>Found In User</th><th>Found In File</th><th>Also In User</th><th>Also In File</th></tr>
${dup_rows:-<tr><td colspan='5' style='text-align:center;color:#1e8449;padding:15px;'>✅ No duplicate keys found</td></tr>}
</table>

<h2>📋 All Authorized Keys</h2>
<table><tr><th>User</th><th>File</th><th>Type</th><th>Bits</th><th>Fingerprint</th><th>Comment</th><th>Status</th></tr>
$(build_key_rows ALL_KEYS)
$([ $total_keys -eq 0 ] && echo "<tr><td colspan='7' style='text-align:center;color:#888;padding:15px;'>No authorized_keys files found</td></tr>")
</table>

<h2>🖥️ SSH Host Keys</h2>
<table><tr><th>Key File</th><th>Fingerprint</th></tr>
${host_rows:-<tr><td colspan='2' style='text-align:center;color:#888;'>None found</td></tr>}
</table>

<h2>ℹ️ Key Type Recommendations</h2>
<table><tr><th>Type</th><th>Recommendation</th></tr>
<tr><td><span class='badge b-green'>ed25519</span></td><td>✅ Best — use this for all new keys</td></tr>
<tr><td><span class='badge b-blue'>RSA ≥4096</span></td><td>✅ Good — acceptable for compatibility</td></tr>
<tr><td><span class='badge b-blue'>RSA 2048–4095</span></td><td>⚠️ Acceptable — consider upgrading</td></tr>
<tr><td><span class='badge b-orange'>RSA &lt;2048</span></td><td>❌ Weak — replace immediately</td></tr>
<tr><td><span class='badge b-red'>DSA</span></td><td>❌ Deprecated — replace immediately</td></tr>
<tr><td><span class='badge b-blue'>ECDSA (NIST)</span></td><td>⚠️ Acceptable but NIST curves are debated — prefer ed25519</td></tr>
</table>
</div>
<div class="footer">Generated by ssh-key-auditor.sh &nbsp;|&nbsp; $(date) &nbsp;|&nbsp; $(hostname)</div>
</div></body></html>
HTML

[[ -n "$MAIL_TO" ]] && command -v mail &>/dev/null && \
    mail -s "$MAIL_SUBJECT" -a "Content-Type: text/html" "$MAIL_TO" < "$HTML_FILE"

section "COMPLETE"
echo "  Report : $HTML_FILE"
echo "  Total keys : $total_keys | Flagged: $flagged_count | Duplicates: $dup_count"
