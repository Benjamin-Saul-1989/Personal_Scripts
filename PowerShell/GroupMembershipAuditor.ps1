#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Group Membership Auditor
.DESCRIPTION
    Audits Active Directory group memberships, identifies changes,
    flags high-privilege groups, and emails a full HTML report.
.NOTES
    - Requires AD PowerShell module (RSAT)
    - Run on a schedule to detect membership changes over time
    - Saves a baseline snapshot for change detection
#>

# ============================================================ #
#  CONFIGURATION - Edit these values                           #
# ============================================================ #
$Config = @{
    # Email Settings
    SMTPServer   = "smtp.office365.com"
    SMTPPort     = 587
    UseSSL       = $true
    FromAddress  = "alerts@yourdomain.com"
    ToAddress    = "admin@yourdomain.com"
    Username     = "alerts@yourdomain.com"
    Password     = "YourPasswordHere"

    # Audit Settings
    ReportTitle  = "Group Membership Audit Report"
    SnapshotPath = "C:\Reports\GroupAudit\snapshot.json"
    ReportDir    = "C:\Reports\GroupAudit"

    # High-privilege groups to flag (add your own)
    HighPrivGroups = @(
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Administrators",
        "Account Operators",
        "Backup Operators",
        "Print Operators",
        "Server Operators",
        "Group Policy Creator Owners"
    )

    # Specific groups to audit (leave empty to audit ALL groups)
    TargetGroups = @()
}

# ============================================================ #
#  SECURE PASSWORD                                             #
# ============================================================ #
$SecurePass = ConvertTo-SecureString $Config.Password -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential($Config.Username, $SecurePass)

# ============================================================ #
#  INITIALIZE                                                  #
# ============================================================ #
Write-Host "Loading Active Directory module..." -ForegroundColor Cyan
try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Error "Active Directory module not found. Install RSAT tools."
    exit 1
}

if (-not (Test-Path $Config.ReportDir)) {
    New-Item -ItemType Directory -Path $Config.ReportDir | Out-Null
}

$ReportTime  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$ServerName  = $env:COMPUTERNAME
$CurrentSnap = @{}
$Changes     = [System.Collections.Generic.List[PSObject]]::new()
$GroupData   = [System.Collections.Generic.List[PSObject]]::new()

# ============================================================ #
#  LOAD PREVIOUS SNAPSHOT                                      #
# ============================================================ #
$PreviousSnap = @{}
if (Test-Path $Config.SnapshotPath) {
    Write-Host "Loading previous snapshot for change detection..." -ForegroundColor Cyan
    try {
        $PreviousSnap = Get-Content $Config.SnapshotPath -Raw | ConvertFrom-Json -AsHashtable
    } catch {
        Write-Warning "Could not load previous snapshot: $_"
    }
}

# ============================================================ #
#  QUERY AD GROUPS                                             #
# ============================================================ #
Write-Host "Querying AD groups..." -ForegroundColor Cyan

if ($Config.TargetGroups.Count -gt 0) {
    $Groups = $Config.TargetGroups | ForEach-Object { Get-ADGroup -Identity $_ -Properties Description, ManagedBy, WhenCreated }
} else {
    $Groups = Get-ADGroup -Filter * -Properties Description, ManagedBy, WhenCreated | Sort-Object Name
}

Write-Host "Found $($Groups.Count) group(s) to audit." -ForegroundColor Green

# ============================================================ #
#  AUDIT EACH GROUP                                            #
# ============================================================ #
foreach ($Group in $Groups) {
    $Members = Get-ADGroupMember -Identity $Group -Recursive -ErrorAction SilentlyContinue |
               Select-Object Name, SamAccountName, ObjectClass

    $MemberNames   = ($Members | Select-Object -ExpandProperty SamAccountName | Sort-Object)
    $IsHighPriv    = $Config.HighPrivGroups -contains $Group.Name
    $MemberCount   = $Members.Count
    $UserCount     = ($Members | Where-Object { $_.ObjectClass -eq 'user' }).Count
    $GroupCount    = ($Members | Where-Object { $_.ObjectClass -eq 'group' }).Count
    $ComputerCount = ($Members | Where-Object { $_.ObjectClass -eq 'computer' }).Count

    # Store current snapshot
    $CurrentSnap[$Group.SamAccountName] = $MemberNames

    # Detect changes vs previous snapshot
    $Added   = @()
    $Removed = @()
    if ($PreviousSnap.ContainsKey($Group.SamAccountName)) {
        $Prev    = @($PreviousSnap[$Group.SamAccountName])
        $Added   = $MemberNames | Where-Object { $_ -notin $Prev }
        $Removed = $Prev | Where-Object { $_ -notin $MemberNames }

        foreach ($a in $Added) {
            $Changes.Add([PSCustomObject]@{
                Group      = $Group.Name
                Change     = "Added"
                Member     = $a
                HighPriv   = $IsHighPriv
                DetectedAt = $ReportTime
            })
        }
        foreach ($r in $Removed) {
            $Changes.Add([PSCustomObject]@{
                Group      = $Group.Name
                Change     = "Removed"
                Member     = $r
                HighPriv   = $IsHighPriv
                DetectedAt = $ReportTime
            })
        }
    }

    $GroupData.Add([PSCustomObject]@{
        Name          = $Group.Name
        SAM           = $Group.SamAccountName
        Description   = $Group.Description
        MemberCount   = $MemberCount
        UserCount     = $UserCount
        GroupCount    = $GroupCount
        ComputerCount = $ComputerCount
        IsHighPriv    = $IsHighPriv
        Added         = $Added.Count
        Removed       = $Removed.Count
        Members       = $Members
    })
}

# ============================================================ #
#  SAVE NEW SNAPSHOT                                           #
# ============================================================ #
$CurrentSnap | ConvertTo-Json -Depth 5 | Out-File $Config.SnapshotPath -Encoding UTF8
Write-Host "Snapshot saved to $($Config.SnapshotPath)" -ForegroundColor Green

# ============================================================ #
#  BUILD HTML REPORT                                           #
# ============================================================ #
$TotalGroups   = $GroupData.Count
$TotalChanges  = $Changes.Count
$HighPrivCount = ($GroupData | Where-Object { $_.IsHighPriv }).Count
$ChangedGroups = ($Changes | Select-Object -ExpandProperty Group -Unique).Count

# Group summary rows
$GroupRows = ""
$alt = $false
foreach ($g in ($GroupData | Sort-Object IsHighPriv -Descending)) {
    $rowClass  = if ($alt) { "background:#fafafa;" } else { "" }
    $privBadge = if ($g.IsHighPriv) { "<span style='background:#c0392b;color:white;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:bold;'>⚠ HIGH PRIV</span>" } else { "" }
    $changeBadge = ""
    if ($g.Added -gt 0)   { $changeBadge += "<span style='background:#1e8449;color:white;padding:2px 7px;border-radius:10px;font-size:11px;margin-right:3px;'>+$($g.Added)</span>" }
    if ($g.Removed -gt 0) { $changeBadge += "<span style='background:#c0392b;color:white;padding:2px 7px;border-radius:10px;font-size:11px;'>-$($g.Removed)</span>" }
    if ($changeBadge -eq "") { $changeBadge = "<span style='color:#888;font-size:11px;'>No changes</span>" }

    $GroupRows += "<tr style='$rowClass'>
        <td><strong>$($g.Name)</strong> $privBadge</td>
        <td>$($g.Description)</td>
        <td style='text-align:center;'>$($g.MemberCount)</td>
        <td style='text-align:center;'>$($g.UserCount)</td>
        <td style='text-align:center;'>$($g.GroupCount)</td>
        <td>$changeBadge</td>
    </tr>"
    $alt = !$alt
}

# Changes rows
$ChangeRows = ""
if ($Changes.Count -eq 0) {
    $ChangeRows = "<tr><td colspan='5' style='text-align:center;color:#888;padding:20px;'>No membership changes detected since last run.</td></tr>"
} else {
    $alt = $false
    foreach ($c in $Changes) {
        $rowClass   = if ($alt) { "background:#fafafa;" } else { "" }
        $changeBadge = if ($c.Change -eq "Added") {
            "<span style='background:#1e8449;color:white;padding:3px 10px;border-radius:10px;font-size:12px;font-weight:bold;'>+ ADDED</span>"
        } else {
            "<span style='background:#c0392b;color:white;padding:3px 10px;border-radius:10px;font-size:12px;font-weight:bold;'>− REMOVED</span>"
        }
        $privFlag = if ($c.HighPriv) { "⚠️" } else { "" }
        $ChangeRows += "<tr style='$rowClass'>
            <td>$privFlag <strong>$($c.Group)</strong></td>
            <td>$changeBadge</td>
            <td>$($c.Member)</td>
            <td>$($c.DetectedAt)</td>
        </tr>"
        $alt = !$alt
    }
}

$AlertBanner = ""
$HighPrivChanges = $Changes | Where-Object { $_.HighPriv }
if ($HighPrivChanges.Count -gt 0) {
    $AlertBanner = "<div style='background:#fdedec;border:1px solid #c0392b;border-radius:8px;padding:14px 18px;margin-bottom:20px;font-size:14px;font-weight:bold;color:#7b241c;'>
        🚨 <strong>ALERT:</strong> $($HighPrivChanges.Count) change(s) detected in HIGH PRIVILEGE groups! Immediate review recommended.
    </div>"
}

$HTMLBody = @"
<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>
  body { font-family:Segoe UI,Arial,sans-serif; background:#f4f6f9; margin:0; padding:20px; }
  .container { max-width:1100px; margin:auto; background:white; border-radius:10px; box-shadow:0 4px 15px rgba(0,0,0,.12); overflow:hidden; }
  .header { background:linear-gradient(135deg,#1a3a5c,#2e86c1); color:white; padding:30px; }
  .header h1 { margin:0; font-size:24px; }
  .header p { margin:5px 0 0; opacity:.85; font-size:14px; }
  .content { padding:25px; }
  .stats { display:flex; gap:15px; margin-bottom:25px; flex-wrap:wrap; }
  .stat-card { flex:1; min-width:130px; border-radius:8px; padding:18px; text-align:center; }
  .stat-card .num { font-size:32px; font-weight:bold; }
  .stat-card .lbl { font-size:12px; margin-top:5px; }
  .card-blue { background:#eaf4fb; border-top:4px solid #2e86c1; color:#1a3a5c; }
  .card-red  { background:#fdedec; border-top:4px solid #c0392b; color:#7b241c; }
  .card-orange { background:#fef5e7; border-top:4px solid #e67e22; color:#7d4e1a; }
  .card-green { background:#eafaf1; border-top:4px solid #1e8449; color:#1a5e20; }
  h2 { font-size:16px; color:#2c3e50; border-bottom:2px solid #eee; padding-bottom:8px; margin-top:28px; }
  table { width:100%; border-collapse:collapse; font-size:13px; margin-bottom:20px; }
  th { background:#2c3e50; color:white; padding:10px 12px; text-align:left; }
  td { padding:9px 12px; border-bottom:1px solid #f0f0f0; vertical-align:middle; }
  tr:hover td { background:#f5f8ff; }
  .footer { background:#f4f6f9; padding:15px 25px; font-size:12px; color:#888; border-top:1px solid #e0e0e0; }
</style></head><body>
<div class="container">
  <div class="header">
    <h1>👥 $($Config.ReportTitle)</h1>
    <p>Server: <strong>$ServerName</strong> &nbsp;|&nbsp; Generated: $ReportTime</p>
  </div>
  <div class="content">
    $AlertBanner
    <div class="stats">
      <div class="stat-card card-blue"><div class="num">$TotalGroups</div><div class="lbl">Total Groups</div></div>
      <div class="stat-card card-red"><div class="num">$HighPrivCount</div><div class="lbl">High-Privilege Groups</div></div>
      <div class="stat-card card-orange"><div class="num">$TotalChanges</div><div class="lbl">Total Changes</div></div>
      <div class="stat-card card-green"><div class="num">$ChangedGroups</div><div class="lbl">Groups Changed</div></div>
    </div>

    <h2>🔄 Membership Changes Since Last Run</h2>
    <table>
      <tr><th>Group</th><th>Change</th><th>Member</th><th>Detected At</th></tr>
      $ChangeRows
    </table>

    <h2>📋 All Groups Summary</h2>
    <table>
      <tr><th>Group Name</th><th>Description</th><th>Total Members</th><th>Users</th><th>Nested Groups</th><th>Changes</th></tr>
      $GroupRows
    </table>
  </div>
  <div class="footer">Auto-generated by PowerShell Group Membership Auditor &nbsp;|&nbsp; $ReportTime</div>
</div></body></html>
"@

# ============================================================ #
#  SEND EMAIL                                                  #
# ============================================================ #
$AlertTag = if ($HighPrivChanges.Count -gt 0) { "🚨 ALERT - " } else { "" }
$Subject  = "$($AlertTag)Group Membership Audit | $TotalChanges change(s) | $(Get-Date -Format 'yyyy-MM-dd')"

$MailParams = @{
    From       = $Config.FromAddress
    To         = $Config.ToAddress
    Subject    = $Subject
    Body       = $HTMLBody
    BodyAsHtml = $true
    SmtpServer = $Config.SMTPServer
    Port       = $Config.SMTPPort
    UseSsl     = $Config.UseSSL
    Credential = $Credential
}

try {
    Send-MailMessage @MailParams
    Write-Host "✅ Report emailed to $($Config.ToAddress)" -ForegroundColor Green
} catch {
    Write-Error "❌ Failed to send email: $_"
}

# ============================================================ #
#  SAVE LOCAL HTML REPORT                                      #
# ============================================================ #
$ReportPath = "$($Config.ReportDir)\GroupAudit_$(Get-Date -Format 'yyyyMMdd_HHmm').html"
$HTMLBody | Out-File -FilePath $ReportPath -Encoding UTF8
Write-Host "📄 Report saved to: $ReportPath" -ForegroundColor Cyan

# ============================================================ #
#  CONSOLE SUMMARY                                             #
# ============================================================ #
Write-Host "`n===== GROUP AUDIT SUMMARY =====" -ForegroundColor White
Write-Host "Total Groups    : $TotalGroups"
Write-Host "High-Priv Groups: $HighPrivCount" -ForegroundColor Yellow
Write-Host "Total Changes   : $TotalChanges"  -ForegroundColor $(if($TotalChanges -gt 0){'Red'}else{'Green'})
Write-Host "================================`n" -ForegroundColor White
