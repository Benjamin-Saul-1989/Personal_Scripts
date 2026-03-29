#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Port Scanner for a List of Servers
.DESCRIPTION
    Scans specified TCP ports on a list of servers using multi-threading,
    identifies open/closed ports, flags unexpected open ports, and emails report.
.NOTES
    - Uses RunspacePool for high-speed parallel scanning
    - No external tools required — uses .NET TCP sockets
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

    # Scan Settings
    Servers      = @("server01", "server02", "192.168.1.1")

    # Ports to scan (add/remove as needed)
    Ports        = @(21,22,23,25,53,80,110,135,139,143,443,445,
                     1433,1434,3306,3389,5985,5986,8080,8443,9090)

    TimeoutMS    = 1000         # Connection timeout per port
    MaxThreads   = 200          # Parallel threads

    ReportTitle  = "Port Scan Report"
    ReportDir    = "C:\Reports\PortScan"

    # Ports that should NOT be open (flag as unexpected)
    UnexpectedPorts = @(21,23,135,139,1434)

    # Known port names
    PortNames    = @{
        21   = "FTP"
        22   = "SSH"
        23   = "Telnet"
        25   = "SMTP"
        53   = "DNS"
        80   = "HTTP"
        110  = "POP3"
        135  = "RPC"
        139  = "NetBIOS"
        143  = "IMAP"
        443  = "HTTPS"
        445  = "SMB"
        1433 = "SQL Server"
        1434 = "SQL Browser"
        3306 = "MySQL"
        3389 = "RDP"
        5985 = "WinRM HTTP"
        5986 = "WinRM HTTPS"
        8080 = "HTTP Alt"
        8443 = "HTTPS Alt"
        9090 = "Web Admin"
    }
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

$AllResults  = [System.Collections.Generic.List[PSObject]]::new()
$ReportTime  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$ScanStart   = Get-Date

Write-Host "Starting port scan on $($Config.Servers.Count) server(s), $($Config.Ports.Count) port(s) each..." -ForegroundColor Cyan

# ============================================================ #
#  MULTI-THREADED PORT SCAN                                    #
# ============================================================ #
$RunspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $Config.MaxThreads)
$RunspacePool.Open()

$ScanScript = {
    param($Server, $Port, $TimeoutMS)
    $Result = [PSCustomObject]@{
        Server = $Server
        Port   = $Port
        Status = "Closed"
        Error  = $null
    }
    try {
        $TCP = New-Object System.Net.Sockets.TcpClient
        $Connect = $TCP.BeginConnect($Server, $Port, $null, $null)
        $Wait    = $Connect.AsyncWaitHandle.WaitOne($TimeoutMS, $false)
        if ($Wait -and !$TCP.Client.Connected) { $Wait = $false }
        if ($Wait) {
            $TCP.EndConnect($Connect) | Out-Null
            $Result.Status = "Open"
        }
        $TCP.Close()
    } catch {
        $Result.Error = $_.ToString()
    }
    return $Result
}

$Jobs = @()
foreach ($Server in $Config.Servers) {
    foreach ($Port in $Config.Ports) {
        $PS = [System.Management.Automation.PowerShell]::Create()
        $PS.RunspacePool = $RunspacePool
        $PS.AddScript($ScanScript).AddArgument($Server).AddArgument($Port).AddArgument($Config.TimeoutMS) | Out-Null
        $Jobs += [PSCustomObject]@{ PS = $PS; Handle = $PS.BeginInvoke() }
    }
}

$Total     = $Jobs.Count
$Done      = 0
foreach ($Job in $Jobs) {
    $Result = $Job.PS.EndInvoke($Job.Handle)
    $Job.PS.Dispose()
    if ($Result) { $AllResults.Add($Result) }
    $Done++
    if ($Done % 50 -eq 0) {
        Write-Progress -Activity "Scanning ports" -Status "$Done/$Total" -PercentComplete ([math]::Round($Done/$Total*100))
    }
}
Write-Progress -Activity "Scanning ports" -Completed

$RunspacePool.Close()
$RunspacePool.Dispose()

$ScanDuration = [math]::Round(((Get-Date) - $ScanStart).TotalSeconds, 1)
Write-Host "Scan completed in ${ScanDuration}s" -ForegroundColor Green

# ============================================================ #
#  PROCESS RESULTS                                             #
# ============================================================ #
$OpenPorts        = $AllResults | Where-Object { $_.Status -eq 'Open' }
$UnexpectedOpen   = $OpenPorts  | Where-Object { $_.Port -in $Config.UnexpectedPorts }
$TotalOpen        = $OpenPorts.Count
$TotalUnexpected  = $UnexpectedOpen.Count

# Per-server stats
$ServerStats = $Config.Servers | ForEach-Object {
    $s = $_
    $sOpen = ($OpenPorts | Where-Object { $_.Server -eq $s }).Count
    $sUnex = ($UnexpectedOpen | Where-Object { $_.Server -eq $s }).Count
    [PSCustomObject]@{ Server = $s; OpenPorts = $sOpen; Unexpected = $sUnex }
}

# ============================================================ #
#  BUILD HTML REPORT                                           #
# ============================================================ #
# Server summary rows
$ServerRows = ""
foreach ($s in $ServerStats) {
    $uCol = if ($s.Unexpected -gt 0) { "color:#c0392b;font-weight:bold;" } else { "color:#1e8449;" }
    $ServerRows += "<tr>
        <td><strong>$($s.Server)</strong></td>
        <td style='text-align:center;font-weight:bold;'>$($s.OpenPorts)</td>
        <td style='text-align:center;$uCol'>$($s.Unexpected)</td>
    </tr>"
}

# Open ports table
$OpenRows = ""
$alt = $false
foreach ($r in ($OpenPorts | Sort-Object Server, Port)) {
    $rowClass  = if ($alt) { "background:#fafafa;" } else { "" }
    $portName  = if ($Config.PortNames.ContainsKey($r.Port)) { $Config.PortNames[$r.Port] } else { "Unknown" }
    $isUnexpected = $r.Port -in $Config.UnexpectedPorts
    $unexpBadge   = if ($isUnexpected) { "<span style='background:#c0392b;color:white;padding:1px 6px;border-radius:8px;font-size:10px;margin-left:4px;'>⚠ UNEXPECTED</span>" } else { "" }
    $rowBorder    = if ($isUnexpected) { "border-left:4px solid #c0392b;" } else { "" }
    $OpenRows += "<tr style='$rowClass$rowBorder'>
        <td><strong>$($r.Server)</strong></td>
        <td><strong>$($r.Port)</strong> $unexpBadge</td>
        <td>$portName</td>
        <td><span style='background:#1e8449;color:white;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:bold;'>OPEN</span></td>
    </tr>"
    $alt = !$alt
}

if ($OpenRows -eq "") {
    $OpenRows = "<tr><td colspan='4' style='text-align:center;color:#888;padding:20px;'>No open ports found.</td></tr>"
}

$UnexpRows = ""
foreach ($r in $UnexpectedOpen) {
    $portName = if ($Config.PortNames.ContainsKey($r.Port)) { $Config.PortNames[$r.Port] } else { "Unknown" }
    $UnexpRows += "<tr>
        <td><strong>$($r.Server)</strong></td>
        <td><strong>$($r.Port)</strong></td>
        <td>$portName</td>
        <td style='color:#c0392b;font-weight:bold;'>Review / Close</td>
    </tr>"
}
if ($UnexpRows -eq "") {
    $UnexpRows = "<tr><td colspan='4' style='text-align:center;color:#1e8449;padding:15px;'>✅ No unexpected ports open.</td></tr>"
}

$AlertBanner = ""
if ($TotalUnexpected -gt 0) {
    $AlertBanner = "<div style='background:#fdedec;border:1px solid #c0392b;border-radius:8px;padding:14px 18px;margin-bottom:20px;color:#7b241c;font-weight:bold;'>
        🚨 $TotalUnexpected unexpected port(s) are open — immediate review recommended!</div>"
}

$HTMLBody = @"
<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>
  body { font-family:Segoe UI,Arial,sans-serif; background:#f4f6f9; padding:20px; }
  .container { max-width:950px; margin:auto; background:white; border-radius:10px; box-shadow:0 4px 15px rgba(0,0,0,.12); overflow:hidden; }
  .header { background:linear-gradient(135deg,#212f3d,#2e4057); color:white; padding:30px; }
  .header h1 { margin:0; font-size:24px; }
  .header p { margin:5px 0 0; opacity:.85; font-size:14px; }
  .content { padding:25px; }
  .stats { display:flex; gap:15px; margin-bottom:25px; flex-wrap:wrap; }
  .stat-card { flex:1; min-width:130px; border-radius:8px; padding:16px; text-align:center; }
  .stat-card .num { font-size:32px; font-weight:bold; }
  .stat-card .lbl { font-size:12px; margin-top:4px; }
  .card-blue   { background:#eaf4fb; border-top:4px solid #2e86c1; }
  .card-green  { background:#eafaf1; border-top:4px solid #1e8449; color:#1a5e20; }
  .card-red    { background:#fdedec; border-top:4px solid #c0392b; color:#7b241c; }
  .card-gray   { background:#f2f3f4; border-top:4px solid #7f8c8d; }
  h2 { font-size:16px; color:#2c3e50; border-bottom:2px solid #eee; padding-bottom:8px; margin-top:28px; }
  table { width:100%; border-collapse:collapse; font-size:13px; margin-bottom:20px; }
  th { background:#2c3e50; color:white; padding:10px 12px; text-align:left; }
  td { padding:9px 12px; border-bottom:1px solid #f0f0f0; vertical-align:middle; }
  tr:hover td { background:#f5f8ff; }
  .footer { background:#f4f6f9; padding:15px 25px; font-size:12px; color:#888; border-top:1px solid #e0e0e0; }
</style></head><body>
<div class="container">
  <div class="header">
    <h1>🔍 $($Config.ReportTitle)</h1>
    <p>Servers: <strong>$($Config.Servers -join ', ')</strong> &nbsp;|&nbsp; Ports: $($Config.Ports.Count) &nbsp;|&nbsp; Duration: ${ScanDuration}s &nbsp;|&nbsp; $ReportTime</p>
  </div>
  <div class="content">
    $AlertBanner
    <div class="stats">
      <div class="stat-card card-blue"><div class="num">$($Config.Servers.Count)</div><div class="lbl">Servers Scanned</div></div>
      <div class="stat-card card-green"><div class="num">$TotalOpen</div><div class="lbl">Open Ports</div></div>
      <div class="stat-card card-red"><div class="num">$TotalUnexpected</div><div class="lbl">Unexpected Open</div></div>
      <div class="stat-card card-gray"><div class="num">${ScanDuration}s</div><div class="lbl">Scan Duration</div></div>
    </div>

    <h2>🖥️ Per-Server Summary</h2>
    <table style="max-width:500px;">
      <tr><th>Server</th><th>Open Ports</th><th>Unexpected</th></tr>
      $ServerRows
    </table>

    <h2>⚠️ Unexpected Open Ports</h2>
    <table>
      <tr><th>Server</th><th>Port</th><th>Service</th><th>Action</th></tr>
      $UnexpRows
    </table>

    <h2>✅ All Open Ports</h2>
    <table>
      <tr><th>Server</th><th>Port</th><th>Service</th><th>Status</th></tr>
      $OpenRows
    </table>
  </div>
  <div class="footer">Auto-generated by PowerShell Port Scanner &nbsp;|&nbsp; $ReportTime</div>
</div></body></html>
"@

# ============================================================ #
#  SEND EMAIL                                                  #
# ============================================================ #
$AlertTag = if ($TotalUnexpected -gt 0) { "🚨 " } else { "✅ " }
$Subject  = "$($AlertTag)Port Scan | $TotalOpen open ports, $TotalUnexpected unexpected | $(Get-Date -Format 'yyyy-MM-dd')"

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
$ReportPath = "$($Config.ReportDir)\PortScan_$(Get-Date -Format 'yyyyMMdd_HHmm').html"
$HTMLBody | Out-File -FilePath $ReportPath -Encoding UTF8
Write-Host "📄 Report saved: $ReportPath" -ForegroundColor Cyan

# ============================================================ #
#  CONSOLE SUMMARY                                             #
# ============================================================ #
Write-Host "`n===== PORT SCAN SUMMARY =====" -ForegroundColor White
Write-Host "Scanned     : $($Config.Servers.Count) server(s), $($Config.Ports.Count) port(s) each"
Write-Host "Open Ports  : $TotalOpen"        -ForegroundColor $(if($TotalOpen -gt 0){'Yellow'}else{'Green'})
Write-Host "Unexpected  : $TotalUnexpected"  -ForegroundColor $(if($TotalUnexpected -gt 0){'Red'}else{'Green'})
Write-Host "Duration    : ${ScanDuration}s"
Write-Host "=============================`n" -ForegroundColor White
