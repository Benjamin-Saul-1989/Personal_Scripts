#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Failed Login Attempt Reporter
.DESCRIPTION
    Scans Windows Security Event Log for failed login attempts (Event ID 4625)
    and sends a formatted HTML email report.
.NOTES
    - Requires administrator privileges!
    - Schedule via Task Scheduler for automated reporting!
#>

# ============================================================
#  CONFIGURATION For Email                                   #
# ============================================================
$Config = @{
    # Email Settings
    SMTPServer    = "smtp.office365.com"        
    SMTPPort      = 587
    UseSSL        = $true
    FromAddress   = ""     # Please submit a ticket, the team: Benjamin, Jason, or Nic, to have an email configured 
    ToAddress     = ""     # If your team, has destrobtion list for alerts send it here. 
    Username      = ""     # Enter from address
    Password      = ""     # See secure password note below

    # Report Settings
    HoursBack     = 24                          # This value determens how far back in the logs to look increase the value to to go back futer
    FailThreshold = 5                           # Highlight users with a high faluer rate.
    ReportTitle   = "Failed Login Attempt Report"
}

$SecurePass = ConvertTo-SecureString $Config.Password -AsPlainText -Force

# ============================================================
#  COLLECT FAILED LOGIN EVENTS                               #
# ============================================================
Write-Host "Scanning event log for the last $($Config.HoursBack) hours..." -ForegroundColor Cyan

$StartTime = (Get-Date).AddHours(-$Config.HoursBack)

try {
    $FailedLogins = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = 4625
        StartTime = $StartTime
    } -ErrorAction Stop
} catch {
    if ($_.Exception.Message -like "*No events*") {
        Write-Host "No failed login events found in the specified time range." -ForegroundColor Yellow
        $FailedLogins = @()
    } else {
        Write-Error "Failed to query event log: $_"
        exit 1
    }
}

Write-Host "Found $($FailedLogins.Count) failed login event(s)." -ForegroundColor Green

# ============================================================
#  PARSE EVENT DATA                                          #
# ============================================================
$ParsedEvents = foreach ($Event in $FailedLogins) {
    $XML = [xml]$Event.ToXml()
    $EventData = $XML.Event.EventData.Data

    # Extract fields from XML
    $GetField = { param($name) ($EventData | Where-Object { $_.Name -eq $name }).'#text' }

    [PSCustomObject]@{
        TimeStamp        = $Event.TimeCreated
        TargetUsername   = & $GetField 'TargetUserName'
        TargetDomain     = & $GetField 'TargetDomainName'
        SourceIP         = & $GetField 'IpAddress'
        SourcePort       = & $GetField 'IpPort'
        SourceWorkstation= & $GetField 'WorkstationName'
        LogonType        = & $GetField 'LogonType'
        FailureReason    = switch (& $GetField 'SubStatus') {
            '0xC000006A' { 'Wrong Password' }
            '0xC0000064' { 'Unknown Username' }
            '0xC000006D' { 'Bad Username or Password' }
            '0xC000006F' { 'Account Logon Outside Allowed Hours' }
            '0xC0000070' { 'Account Logon from Unauthorized Workstation' }
            '0xC0000071' { 'Password Expired' }
            '0xC0000072' { 'Account Disabled' }
            '0xC0000193' { 'Account Expired' }
            '0xC0000224' { 'Password Must Change' }
            '0xC0000234' { 'Account Locked Out' }
            default       { "Code: $(& $GetField 'SubStatus')" }
        }
        LogonTypeName    = switch (& $GetField 'LogonType') {
            '2'  { 'Interactive' }
            '3'  { 'Network' }
            '4'  { 'Batch' }
            '5'  { 'Service' }
            '7'  { 'Unlock' }
            '8'  { 'NetworkCleartext' }
            '10' { 'RemoteInteractive (RDP)' }
            '11' { 'CachedInteractive' }
            default { "Type $(& $GetField 'LogonType')" }
        }
    }
}

# ============================================================
#  SUMMARY STATISTICS                                        #
# ============================================================
$TotalFailures     = $ParsedEvents.Count
$UniqueUsers       = ($ParsedEvents | Select-Object -Unique TargetUsername).Count
$UniqueIPs         = ($ParsedEvents | Where-Object { $_.SourceIP -ne '-' -and $_.SourceIP -ne $null } | Select-Object -Unique SourceIP).Count
$TopOffenders      = $ParsedEvents | Group-Object TargetUsername | Sort-Object Count -Descending | Select-Object -First 10
$TopSourceIPs      = $ParsedEvents | Where-Object { $_.SourceIP -ne '-' -and $_.SourceIP -ne $null } | Group-Object SourceIP | Sort-Object Count -Descending | Select-Object -First 10
$HighRiskUsers     = $TopOffenders | Where-Object { $_.Count -ge $Config.FailThreshold }

# ============================================================
#  BUILD HTML REPORT                                         #
# ============================================================
# I used AI to build the report, as it was far easier to do it like that than by AI! This saved so much time. 

$ReportTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$ServerName = $env:COMPUTERNAME

# Helper to build HTML table rows
function Build-TableRows {
    param($Data, $Properties)
    $rows = ""
    $alt = $false
    foreach ($item in $Data) {
        $rowClass = if ($alt) { 'alt' } else { '' }
        $rows += "<tr class='$rowClass'>"
        foreach ($prop in $Properties) {
            $val = $item.$prop
            if ($null -eq $val -or $val -eq '') { $val = '-' }
            $rows += "<td>$([System.Web.HttpUtility]::HtmlEncode($val.ToString()))</td>"
        }
        $rows += "</tr>"
        $alt = !$alt
    }
    return $rows
}

# Top offenders rows
$TopOffenderRows = ""
$alt = $false
foreach ($o in $TopOffenders) {
    $rowClass = if ($alt) { 'alt' } else { '' }
    $highlight = if ($o.Count -ge $Config.FailThreshold) { 'style="background:#fff0f0; font-weight:bold;"' } else { '' }
    $TopOffenderRows += "<tr class='$rowClass' $highlight><td>$($o.Name)</td><td>$($o.Count)</td></tr>"
    $alt = !$alt
}

# Top IPs rows
$TopIPRows = ""
$alt = $false
foreach ($ip in $TopSourceIPs) {
    $rowClass = if ($alt) { 'alt' } else { '' }
    $TopIPRows += "<tr class='$rowClass'><td>$($ip.Name)</td><td>$($ip.Count)</td></tr>"
    $alt = !$alt
}

# Recent events rows (last 50)
$RecentRows = ""
$alt = $false
foreach ($e in ($ParsedEvents | Sort-Object TimeStamp -Descending | Select-Object -First 50)) {
    $rowClass = if ($alt) { 'alt' } else { '' }
    $RecentRows += "<tr class='$rowClass'>
        <td>$($e.TimeStamp.ToString('yyyy-MM-dd HH:mm:ss'))</td>
        <td>$($e.TargetUsername)</td>
        <td>$($e.TargetDomain)</td>
        <td>$($e.SourceIP)</td>
        <td>$($e.SourceWorkstation)</td>
        <td>$($e.LogonTypeName)</td>
        <td>$($e.FailureReason)</td>
    </tr>"
    $alt = !$alt
}

$HTMLBody = @"
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<style>
    body        { font-family: Segoe UI, Arial, sans-serif; background: #f4f6f9; color: #333; margin: 0; padding: 20px; }
    .container  { max-width: 1100px; margin: auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); overflow: hidden; }
    .header     { background: linear-gradient(135deg, #c0392b, #922b21); color: white; padding: 30px; }
    .header h1  { margin: 0; font-size: 24px; }
    .header p   { margin: 5px 0 0; opacity: 0.85; font-size: 14px; }
    .content    { padding: 25px; }
    .stats      { display: flex; gap: 15px; margin-bottom: 25px; flex-wrap: wrap; }
    .stat-card  { flex: 1; min-width: 140px; background: #f8f9fa; border-left: 4px solid #c0392b; border-radius: 6px; padding: 15px; }
    .stat-card .num  { font-size: 32px; font-weight: bold; color: #c0392b; }
    .stat-card .lbl  { font-size: 12px; color: #666; margin-top: 4px; }
    .alert      { background: #fff3cd; border: 1px solid #ffc107; border-radius: 6px; padding: 12px 16px; margin-bottom: 20px; font-size: 14px; }
    .alert.danger { background: #f8d7da; border-color: #dc3545; }
    h2          { font-size: 16px; color: #c0392b; border-bottom: 2px solid #f0f0f0; padding-bottom: 8px; margin-top: 25px; }
    table       { width: 100%; border-collapse: collapse; font-size: 13px; margin-bottom: 20px; }
    th          { background: #c0392b; color: white; padding: 10px 12px; text-align: left; }
    td          { padding: 8px 12px; border-bottom: 1px solid #f0f0f0; }
    tr.alt td   { background: #fafafa; }
    tr:hover td { background: #fff5f5; }
    .footer     { background: #f4f6f9; padding: 15px 25px; font-size: 12px; color: #888; border-top: 1px solid #e0e0e0; }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1> $($Config.ReportTitle)</h1>
    <p>Server: <strong>$ServerName</strong> &nbsp;|&nbsp; Period: Last $($Config.HoursBack) hours &nbsp;|&nbsp; Generated: $ReportTime</p>
  </div>
  <div class="content">

    $(if ($HighRiskUsers.Count -gt 0) {
      "<div class='alert danger'> <strong>High Risk Alert:</strong> $($HighRiskUsers.Count) account(s) have $($Config.FailThreshold)+ failed attempts — possible brute force attack.</div>"
    })
    $(if ($TotalFailures -eq 0) {
      "<div class='alert'> No failed login attempts detected in the last $($Config.HoursBack) hours.</div>"
    })

    <div class="stats">
      <div class="stat-card"><div class="num">$TotalFailures</div><div class="lbl">Total Failed Attempts</div></div>
      <div class="stat-card"><div class="num">$UniqueUsers</div><div class="lbl">Unique Usernames</div></div>
      <div class="stat-card"><div class="num">$UniqueIPs</div><div class="lbl">Unique Source IPs</div></div>
      <div class="stat-card"><div class="num">$($Config.HoursBack)h</div><div class="lbl">Reporting Window</div></div>
    </div>

    <h2> Top Offending Accounts</h2>
    <table>
      <tr><th>Username</th><th>Failed Attempts</th></tr>
      $TopOffenderRows
    </table>

    <h2> Top Source IP Addresses</h2>
    <table>
      <tr><th>IP Address</th><th>Failed Attempts</th></tr>
      $TopIPRows
    </table>

    <h2> Recent Failed Attempts (Last 50)</h2>
    <table>
      <tr><th>Time</th><th>Username</th><th>Domain</th><th>Source IP</th><th>Workstation</th><th>Logon Type</th><th>Reason</th></tr>
      $RecentRows
    </table>

  </div>
  <div class="footer">
    Auto-generated by PowerShell Failed Login Reporter &nbsp;|&nbsp; $ReportTime &nbsp;|&nbsp; $ServerName
  </div>
</div>
</body>
</html>
"@

# ============================================================
#  SEND EMAIL                                                #
# ============================================================
$AlertTag = if ($HighRiskUsers.Count -gt 0) { "🚨 ALERT - " } else { "" }
$Subject = "$AlertTag$($Config.ReportTitle) | $ServerName | $TotalFailures failures | $(Get-Date -Format 'yyyy-MM-dd')"

$Credential = New-Object System.Management.Automation.PSCredential($Config.Username, $SecurePass)

$MailParams = @{
    From        = $Config.FromAddress
    To          = $Config.ToAddress
    Subject     = $Subject
    Body        = $HTMLBody
    BodyAsHtml  = $true
    SmtpServer  = $Config.SMTPServer
    Port        = $Config.SMTPPort
    UseSsl      = $Config.UseSSL
    Credential  = $Credential
}

try {
    Send-MailMessage @MailParams
    Write-Host "✅ Report emailed to $($Config.ToAddress)" -ForegroundColor Green
} catch {
    Write-Error "❌ Failed to send email: $_"
}

# ============================================================
#  Save HTML report locally as well                          #
# ============================================================
$ReportPath = "C:\Reports\FailedLogins_$(Get-Date -Format 'yyyyMMdd_HHmm').html"
if (-not (Test-Path "C:\Reports")) { New-Item -ItemType Directory -Path "C:\Reports" | Out-Null }
$HTMLBody | Out-File -FilePath $ReportPath -Encoding UTF8
Write-Host "📄 Report saved to: $ReportPath" -ForegroundColor Cyan