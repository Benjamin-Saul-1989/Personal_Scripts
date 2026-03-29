#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Change Log Tracker — Who Did What and When
.DESCRIPTION
    Monitors Windows Security Event Log for administrative changes:
    user account changes, group membership changes, GPO modifications,
    scheduled task creation, service installs, logon events, and more.
    Emails a consolidated HTML report of recent changes.
.NOTES
    - Requires administrator privileges
    - Security auditing must be enabled in Group Policy for full coverage
    - Recommended: run hourly or daily via Task Scheduler
    - Enable: Computer Config → Policies → Windows Settings → Security Settings → Advanced Audit Policy
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

    # Tracking Settings
    HoursBack    = 24                    # How far back to look
    ReportTitle  = "Change Log Tracker"
    ReportDir    = "C:\Reports\ChangeLog"
    LogPath      = "C:\Reports\ChangeLog\changelog.csv"  # Persistent change log

    # Accounts to EXCLUDE from reports (system/noise)
    ExcludeAccounts = @(
        "SYSTEM",
        "LOCAL SERVICE",
        "NETWORK SERVICE",
        "DWM-1","DWM-2","DWM-3",
        "UMFD-0","UMFD-1","UMFD-2"
    )

    # Alert on these specific event IDs (always email immediately)
    CriticalEventIDs = @(4728, 4732, 4756)   # Admin/privileged group member adds
}

# ============================================================ #
#  SECURE PASSWORD                                             #
# ============================================================ #
$SecurePass = ConvertTo-SecureString $Config.Password -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential($Config.Username, $SecurePass)

# ============================================================ #
#  INITIALIZE                                                  #
# ============================================================ #
if (-not (Test-Path $Config.ReportDir)) {
    New-Item -ItemType Directory -Path $Config.ReportDir | Out-Null
}

$ReportTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$StartTime  = (Get-Date).AddHours(-$Config.HoursBack)
$Changes    = [System.Collections.Generic.List[PSObject]]::new()

# ============================================================ #
#  EVENT ID CATALOG                                            #
# ============================================================ #
$EventCatalog = @{
    # Account Management
    4720 = @{ Category = "User Account"; Description = "User account created";         Severity = "High" }
    4722 = @{ Category = "User Account"; Description = "User account enabled";         Severity = "Medium" }
    4723 = @{ Category = "User Account"; Description = "Password change attempted";    Severity = "Low" }
    4724 = @{ Category = "User Account"; Description = "Password reset by admin";      Severity = "High" }
    4725 = @{ Category = "User Account"; Description = "User account disabled";        Severity = "Medium" }
    4726 = @{ Category = "User Account"; Description = "User account deleted";         Severity = "High" }
    4738 = @{ Category = "User Account"; Description = "User account changed";         Severity = "Medium" }
    4740 = @{ Category = "User Account"; Description = "User account locked out";      Severity = "Medium" }
    4767 = @{ Category = "User Account"; Description = "User account unlocked";        Severity = "Low" }
    4781 = @{ Category = "User Account"; Description = "Account name changed";         Severity = "High" }

    # Group Management
    4727 = @{ Category = "Group Change";  Description = "Security group created";       Severity = "High" }
    4728 = @{ Category = "Group Change";  Description = "Member added to global group"; Severity = "High" }
    4729 = @{ Category = "Group Change";  Description = "Member removed from global group"; Severity = "High" }
    4730 = @{ Category = "Group Change";  Description = "Security group deleted";       Severity = "High" }
    4732 = @{ Category = "Group Change";  Description = "Member added to local group";  Severity = "High" }
    4733 = @{ Category = "Group Change";  Description = "Member removed from local group"; Severity = "Medium" }
    4756 = @{ Category = "Group Change";  Description = "Member added to universal group"; Severity = "High" }
    4757 = @{ Category = "Group Change";  Description = "Member removed from universal group"; Severity = "Medium" }

    # Logon / Logoff
    4624 = @{ Category = "Logon";         Description = "Successful logon";             Severity = "Info" }
    4625 = @{ Category = "Logon";         Description = "Failed logon attempt";         Severity = "Medium" }
    4634 = @{ Category = "Logon";         Description = "Account logged off";           Severity = "Info" }
    4648 = @{ Category = "Logon";         Description = "Logon with explicit credentials"; Severity = "Medium" }
    4672 = @{ Category = "Logon";         Description = "Special privileges assigned";  Severity = "High" }

    # Policy Changes
    4713 = @{ Category = "Policy Change"; Description = "Kerberos policy changed";      Severity = "Critical" }
    4719 = @{ Category = "Policy Change"; Description = "System audit policy changed";  Severity = "Critical" }
    4739 = @{ Category = "Policy Change"; Description = "Domain policy changed";        Severity = "Critical" }
    4906 = @{ Category = "Policy Change"; Description = "CrashOnAuditFail changed";     Severity = "Critical" }

    # System Events
    4697 = @{ Category = "System";        Description = "Service installed on system";  Severity = "High" }
    7045 = @{ Category = "System";        Description = "New service installed";        Severity = "High" }
    4698 = @{ Category = "Scheduled Task";Description = "Scheduled task created";       Severity = "High" }
    4699 = @{ Category = "Scheduled Task";Description = "Scheduled task deleted";       Severity = "Medium" }
    4700 = @{ Category = "Scheduled Task";Description = "Scheduled task enabled";       Severity = "Medium" }
    4701 = @{ Category = "Scheduled Task";Description = "Scheduled task disabled";      Severity = "Low" }
    4702 = @{ Category = "Scheduled Task";Description = "Scheduled task updated";       Severity = "Medium" }

    # Object Access
    4670 = @{ Category = "Object Access"; Description = "Object permissions changed";   Severity = "Medium" }
    4907 = @{ Category = "Object Access"; Description = "Object audit settings changed";Severity = "Medium" }

    # Firewall
    4946 = @{ Category = "Firewall";      Description = "Firewall rule added";          Severity = "High" }
    4947 = @{ Category = "Firewall";      Description = "Firewall rule modified";       Severity = "Medium" }
    4948 = @{ Category = "Firewall";      Description = "Firewall rule deleted";        Severity = "Medium" }
    4950 = @{ Category = "Firewall";      Description = "Firewall setting changed";     Severity = "High" }

    # Process
    4688 = @{ Category = "Process";       Description = "New process created";          Severity = "Info" }
    4689 = @{ Category = "Process";       Description = "Process terminated";           Severity = "Info" }
}

# ============================================================ #
#  HELPER: EXTRACT FIELD FROM EVENT MESSAGE                   #
# ============================================================ #
function Get-EventField {
    param([string]$Message, [string]$FieldName)
    if ($Message -match "$FieldName\s*:\s*(.+?)(\r?\n|$)") {
        return $Matches[1].Trim()
    }
    return ""
}

# ============================================================ #
#  QUERY SECURITY EVENT LOG                                    #
# ============================================================ #
Write-Host "Querying Security event log for the last $($Config.HoursBack) hours..." -ForegroundColor Cyan

$EventIDs = $EventCatalog.Keys
$LogsToCheck = @(
    @{ Log = "Security";    IDs = ($EventIDs | Where-Object { $_ -ge 4000 }) }
    @{ Log = "System";      IDs = @(7045) }
    @{ Log = "Microsoft-Windows-TaskScheduler/Operational"; IDs = @(106, 140, 141, 200, 201) }
)

foreach ($LogSpec in $LogsToCheck) {
    $AvailableIDs = $LogSpec.IDs | Where-Object { $EventCatalog.ContainsKey([int]$_) }
    if ($AvailableIDs.Count -eq 0) { continue }

    try {
        $Events = Get-WinEvent -FilterHashtable @{
            LogName   = $LogSpec.Log
            Id        = $AvailableIDs
            StartTime = $StartTime
        } -ErrorAction Stop

        foreach ($Event in $Events) {
            # Skip system/noise accounts
            $Msg     = $Event.Message
            $Subject = Get-EventField -Message $Msg -FieldName "Subject:\s+\r?\n\s+Security ID"
            $ActorAccount = Get-EventField -Message $Msg -FieldName "Account Name"
            if (-not $ActorAccount) { $ActorAccount = $Event.Properties[1].Value 2>$null }

            if ($ActorAccount -in $Config.ExcludeAccounts) { continue }
            if ($ActorAccount -match "^\$$") { continue }  # Skip machine accounts

            $CatalogEntry = $EventCatalog[[int]$Event.Id]
            if (-not $CatalogEntry) { continue }

            # Extract target account if present
            $TargetAccount = ""
            if ($Msg -match "Target Account:\s*\r?\n\s+.*?Account Name:\s+(.+?)(\r|\n)") {
                $TargetAccount = $Matches[1].Trim()
            } elseif ($Msg -match "Account Name:\s+(.+?)(\r|\n).*?Account Name:\s+(.+?)(\r|\n)") {
                $TargetAccount = $Matches[3].Trim()
            }

            # Extract workstation/IP
            $WorkStation = Get-EventField -Message $Msg -FieldName "Workstation Name"
            $SourceIP    = Get-EventField -Message $Msg -FieldName "Source Network Address"
            $LogonType   = Get-EventField -Message $Msg -FieldName "Logon Type"

            $IsCritical  = $Event.Id -in $Config.CriticalEventIDs

            $Changes.Add([PSCustomObject]@{
                Timestamp    = $Event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                EventID      = $Event.Id
                Category     = $CatalogEntry.Category
                Description  = $CatalogEntry.Description
                Severity     = $CatalogEntry.Severity
                Actor        = $ActorAccount
                Target       = $TargetAccount
                WorkStation  = $WorkStation
                SourceIP     = $SourceIP
                LogonType    = $LogonType
                IsCritical   = $IsCritical
                Computer     = $Event.MachineName
            })
        }

    } catch {
        if ($_.Exception.Message -notlike "*No events*") {
            Write-Warning "Could not query '$($LogSpec.Log)': $_"
        }
    }
}

# Filter out logon noise for summary (keep only non-Info events unless specified)
$SignificantChanges = $Changes | Where-Object { $_.Severity -ne "Info" }
Write-Host "Found $($Changes.Count) total events ($($SignificantChanges.Count) significant)" -ForegroundColor Green

# ============================================================ #
#  APPEND TO PERSISTENT LOG                                    #
# ============================================================ #
if ($SignificantChanges.Count -gt 0) {
    $LogExists = Test-Path $Config.LogPath
    $SignificantChanges |
        Select-Object Timestamp,EventID,Category,Description,Severity,Actor,Target,WorkStation,SourceIP,Computer |
        Export-Csv -Path $Config.LogPath -NoTypeInformation -Append:$LogExists
}

# ============================================================ #
#  BUILD HTML REPORT                                           #
# ============================================================ #
$TotalChanges    = $SignificantChanges.Count
$CriticalChanges = ($SignificantChanges | Where-Object { $_.Severity -eq 'Critical' -or $_.IsCritical }).Count
$HighChanges     = ($SignificantChanges | Where-Object { $_.Severity -eq 'High' }).Count
$UniqueActors    = ($SignificantChanges | Select-Object -ExpandProperty Actor -Unique).Count

# Group by category
$CategoryGroups = $SignificantChanges | Group-Object Category | Sort-Object Count -Descending

$CategoryRows = ""
foreach ($grp in $CategoryGroups) {
    $critCount = ($grp.Group | Where-Object { $_.Severity -in @('Critical','High') -or $_.IsCritical }).Count
    $critColor = if ($critCount -gt 0) { "color:#c0392b;font-weight:bold;" } else { "" }
    $CategoryRows += "<tr>
        <td><strong>$($grp.Name)</strong></td>
        <td style='text-align:center;'>$($grp.Count)</td>
        <td style='text-align:center;$critColor'>$critCount</td>
    </tr>"
}

function Get-SeverityBadge {
    param([string]$Sev, [bool]$IsCrit = $false)
    if ($IsCrit) { $Sev = "Critical" }
    $color = switch ($Sev) {
        "Critical" { "#7b241c" }
        "High"     { "#c0392b" }
        "Medium"   { "#e67e22" }
        "Low"      { "#2e86c1" }
        "Info"     { "#7f8c8d" }
        default    { "#7f8c8d" }
    }
    return "<span style='background:$color;color:white;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:bold;'>$Sev</span>"
}

$ChangeRows = ""
$alt = $false
foreach ($c in ($SignificantChanges | Sort-Object Timestamp -Descending | Select-Object -First 500)) {
    $rowClass  = if ($alt) { "background:#fafafa;" } else { "" }
    $critStyle = if ($c.IsCritical -or $c.Severity -eq 'Critical') { "border-left:4px solid #7b241c;" } elseif ($c.Severity -eq 'High') { "border-left:4px solid #c0392b;" } else { "" }
    $badge     = Get-SeverityBadge -Sev $c.Severity -IsCrit $c.IsCritical
    $target    = if ($c.Target -and $c.Target -ne $c.Actor) { $c.Target } else { "-" }
    $ws        = if ($c.WorkStation) { $c.WorkStation } elseif ($c.SourceIP -and $c.SourceIP -ne "-") { $c.SourceIP } else { "-" }

    $ChangeRows += "<tr style='$rowClass$critStyle'>
        <td style='font-size:12px;white-space:nowrap;'>$($c.Timestamp)</td>
        <td>$($c.EventID)</td>
        <td>$($c.Category)</td>
        <td>$($c.Description)</td>
        <td>$badge</td>
        <td><strong>$($c.Actor)</strong></td>
        <td>$target</td>
        <td style='font-size:12px;color:#555;'>$ws</td>
    </tr>"
    $alt = !$alt
}

if ($ChangeRows -eq "") {
    $ChangeRows = "<tr><td colspan='8' style='text-align:center;color:#1e8449;padding:20px;font-weight:bold;'>✅ No significant changes detected in the last $($Config.HoursBack) hours.</td></tr>"
}

$AlertBanner = ""
if ($CriticalChanges -gt 0) {
    $AlertBanner = "<div style='background:#fdedec;border:1px solid #c0392b;border-radius:8px;padding:14px 18px;margin-bottom:20px;color:#7b241c;font-weight:bold;'>
        🚨 $CriticalChanges critical/high-severity change(s) detected! Immediate review recommended.</div>"
}

$HeaderColor = if ($CriticalChanges -gt 0) { "linear-gradient(135deg,#7b241c,#c0392b)" }
              elseif ($HighChanges -gt 0)   { "linear-gradient(135deg,#1a3a5c,#2e86c1)" }
              else                          { "linear-gradient(135deg,#1a5e20,#1e8449)" }

$HTMLBody = @"
<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>
  body { font-family:Segoe UI,Arial,sans-serif; background:#f4f6f9; padding:20px; }
  .container { max-width:1200px; margin:auto; background:white; border-radius:10px; box-shadow:0 4px 15px rgba(0,0,0,.12); overflow:hidden; }
  .header { background:$HeaderColor; color:white; padding:30px; }
  .header h1 { margin:0; font-size:24px; }
  .header p { margin:5px 0 0; opacity:.85; font-size:14px; }
  .content { padding:25px; }
  .stats { display:flex; gap:15px; margin-bottom:25px; flex-wrap:wrap; }
  .stat-card { flex:1; min-width:130px; border-radius:8px; padding:16px; text-align:center; }
  .stat-card .num { font-size:32px; font-weight:bold; }
  .stat-card .lbl { font-size:12px; margin-top:4px; }
  .card-blue   { background:#eaf4fb; border-top:4px solid #2e86c1; }
  .card-red    { background:#fdedec; border-top:4px solid #c0392b; color:#7b241c; }
  .card-orange { background:#fef5e7; border-top:4px solid #e67e22; color:#7d4e1a; }
  .card-purple { background:#f4ecf7; border-top:4px solid #8e44ad; color:#5b2c6f; }
  h2 { font-size:16px; color:#2c3e50; border-bottom:2px solid #eee; padding-bottom:8px; margin-top:28px; }
  .two-col { display:grid; grid-template-columns:2fr 1fr; gap:20px; }
  table { width:100%; border-collapse:collapse; font-size:12px; margin-bottom:20px; }
  th { background:#2c3e50; color:white; padding:9px 10px; text-align:left; }
  td { padding:8px 10px; border-bottom:1px solid #f0f0f0; vertical-align:middle; }
  tr:hover td { background:#f5f8ff; }
  .footer { background:#f4f6f9; padding:15px 25px; font-size:12px; color:#888; border-top:1px solid #e0e0e0; }
</style></head><body>
<div class="container">
  <div class="header">
    <h1>📋 $($Config.ReportTitle)</h1>
    <p>Server: <strong>$env:COMPUTERNAME</strong> &nbsp;|&nbsp; Period: Last $($Config.HoursBack) hours &nbsp;|&nbsp; Generated: $ReportTime</p>
  </div>
  <div class="content">
    $AlertBanner
    <div class="stats">
      <div class="stat-card card-blue"><div class="num">$TotalChanges</div><div class="lbl">Total Changes</div></div>
      <div class="stat-card card-red"><div class="num">$CriticalChanges</div><div class="lbl">Critical / High</div></div>
      <div class="stat-card card-orange"><div class="num">$HighChanges</div><div class="lbl">High Severity</div></div>
      <div class="stat-card card-purple"><div class="num">$UniqueActors</div><div class="lbl">Unique Actors</div></div>
    </div>

    <h2>📊 Changes by Category</h2>
    <table style="max-width:450px;">
      <tr><th>Category</th><th>Total Events</th><th>Critical/High</th></tr>
      $CategoryRows
    </table>

    <h2>🕵️ Change Log (Most Recent First — max 500)</h2>
    <table>
      <tr><th>Timestamp</th><th>Event ID</th><th>Category</th><th>Description</th><th>Severity</th><th>Actor</th><th>Target</th><th>Workstation/IP</th></tr>
      $ChangeRows
    </table>
  </div>
  <div class="footer">
    Auto-generated by PowerShell Change Log Tracker &nbsp;|&nbsp; $ReportTime &nbsp;|&nbsp;
    Persistent log: $($Config.LogPath)
  </div>
</div></body></html>
"@

# ============================================================ #
#  SEND EMAIL                                                  #
# ============================================================ #
$AlertTag = if ($CriticalChanges -gt 0) { "🚨 " } elseif ($HighChanges -gt 0) { "⚠️ " } else { "✅ " }
$Subject  = "$($AlertTag)Change Log | $TotalChanges changes, $CriticalChanges critical | $(Get-Date -Format 'yyyy-MM-dd HH:mm')"

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
    Write-Error "❌ Email failed: $_"
}

# ============================================================ #
#  SAVE LOCAL REPORT                                           #
# ============================================================ #
$ReportPath = "$($Config.ReportDir)\ChangeLog_$(Get-Date -Format 'yyyyMMdd_HHmm').html"
$HTMLBody | Out-File -FilePath $ReportPath -Encoding UTF8
Write-Host "📄 Report saved: $ReportPath" -ForegroundColor Cyan
Write-Host "📊 Persistent CSV log: $($Config.LogPath)" -ForegroundColor Cyan

# ============================================================ #
#  CONSOLE SUMMARY                                             #
# ============================================================ #
Write-Host "`n===== CHANGE LOG SUMMARY =====" -ForegroundColor White
Write-Host "Total Changes : $TotalChanges"
Write-Host "Critical/High : $CriticalChanges" -ForegroundColor $(if($CriticalChanges -gt 0){'Red'}else{'Green'})
Write-Host "Unique Actors : $UniqueActors"
Write-Host "Period        : Last $($Config.HoursBack) hours"
Write-Host "==============================`n" -ForegroundColor White
