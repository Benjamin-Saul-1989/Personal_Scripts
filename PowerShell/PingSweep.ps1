#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Ping Sweep Across a Subnet
.DESCRIPTION
    Performs a fast multi-threaded ping sweep of one or more subnets,
    resolves hostnames, identifies new/missing hosts, and emails a report.
.NOTES
    - Uses RunspacePool for speed (scans /24 in ~10 seconds)
    - Compares to previous snapshot to detect new or lost hosts
    - No admin required for ping itself, admin needed for email/saving
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
    Subnets      = @("192.168.1")      # Add subnets: @("192.168.1","192.168.2","10.0.0")
    StartHost    = 1                    # Start of host range (usually 1)
    EndHost      = 254                  # End of host range (usually 254)
    TimeoutMS    = 500                  # Ping timeout in milliseconds
    MaxThreads   = 100                  # Concurrent threads (higher = faster, more CPU)
    ResolveNames = $true                # Resolve hostnames via DNS

    ReportTitle  = "Network Ping Sweep Report"
    ReportDir    = "C:\Reports\PingSweep"
    SnapshotPath = "C:\Reports\PingSweep\snapshot.json"
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

$ReportTime  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$ScanStart   = Get-Date
$AllResults  = [System.Collections.Generic.List[PSObject]]::new()

# ============================================================ #
#  LOAD PREVIOUS SNAPSHOT                                      #
# ============================================================ #
$PreviousHosts = @()
if (Test-Path $Config.SnapshotPath) {
    try {
        $PreviousHosts = Get-Content $Config.SnapshotPath -Raw | ConvertFrom-Json
        Write-Host "Loaded previous snapshot: $($PreviousHosts.Count) hosts" -ForegroundColor Cyan
    } catch {
        Write-Warning "Could not load snapshot: $_"
    }
}

# ============================================================ #
#  THREADED PING SWEEP                                         #
# ============================================================ #
foreach ($Subnet in $Config.Subnets) {
    Write-Host "Sweeping subnet: $Subnet.0/24 ..." -ForegroundColor Cyan

    # Build IP list
    $IPList = $Config.StartHost..$Config.EndHost | ForEach-Object { "$Subnet.$_" }
    $TotalIPs = $IPList.Count

    # Create runspace pool
    $RunspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $Config.MaxThreads)
    $RunspacePool.Open()

    $PingScript = {
        param($IP, $Timeout, $ResolveNames)
        $Result = [PSCustomObject]@{
            IP       = $IP
            Status   = "Offline"
            Hostname = ""
            RTT_ms   = $null
            MAC      = ""
        }
        try {
            $Ping     = New-Object System.Net.NetworkInformation.Ping
            $PingReply = $Ping.Send($IP, $Timeout)
            if ($PingReply.Status -eq "Success") {
                $Result.Status = "Online"
                $Result.RTT_ms = $PingReply.RoundtripTime
                if ($ResolveNames) {
                    try {
                        $Result.Hostname = [System.Net.Dns]::GetHostEntry($IP).HostName
                    } catch { $Result.Hostname = "" }
                }
            }
        } catch { }
        return $Result
    }

    $Jobs = @()
    foreach ($IP in $IPList) {
        $PS = [System.Management.Automation.PowerShell]::Create()
        $PS.RunspacePool = $RunspacePool
        $PS.AddScript($PingScript).AddArgument($IP).AddArgument($Config.TimeoutMS).AddArgument($Config.ResolveNames) | Out-Null
        $Jobs += [PSCustomObject]@{ PS = $PS; Handle = $PS.BeginInvoke(); IP = $IP }
    }

    # Collect results with progress
    $Completed = 0
    foreach ($Job in $Jobs) {
        $Result = $Job.PS.EndInvoke($Job.Handle)
        $Job.PS.Dispose()
        if ($Result) {
            $Result | ForEach-Object {
                $_.PSObject.Properties.Add([System.Management.Automation.PSNoteProperty]::new("Subnet", $Subnet))
                $AllResults.Add($_)
            }
        }
        $Completed++
        if ($Completed % 20 -eq 0) {
            $pct = [math]::Round($Completed / $TotalIPs * 100)
            Write-Progress -Activity "Pinging $Subnet.x" -Status "$Completed/$TotalIPs" -PercentComplete $pct
        }
    }
    Write-Progress -Activity "Pinging $Subnet.x" -Completed

    $RunspacePool.Close()
    $RunspacePool.Dispose()

    $OnlineCount = ($AllResults | Where-Object { $_.Subnet -eq $Subnet -and $_.Status -eq 'Online' }).Count
    Write-Host "  $OnlineCount online hosts found in $Subnet.0/24" -ForegroundColor Green
}

$ScanDuration = [math]::Round(((Get-Date) - $ScanStart).TotalSeconds, 1)

# ============================================================ #
#  CHANGE DETECTION                                            #
# ============================================================ #
$OnlineHosts  = $AllResults | Where-Object { $_.Status -eq 'Online' }
$OnlineIPs    = $OnlineHosts | Select-Object -ExpandProperty IP
$PreviousIPs  = $PreviousHosts | Where-Object { $_.Status -eq 'Online' } | Select-Object -ExpandProperty IP

$NewHosts     = $OnlineIPs | Where-Object { $_ -notin $PreviousIPs }
$LostHosts    = $PreviousIPs | Where-Object { $_ -notin $OnlineIPs }

# ============================================================ #
#  SAVE SNAPSHOT                                               #
# ============================================================ #
$AllResults | ConvertTo-Json | Out-File $Config.SnapshotPath -Encoding UTF8

# ============================================================ #
#  STATISTICS                                                  #
# ============================================================ #
$TotalScanned = $AllResults.Count
$TotalOnline  = ($AllResults | Where-Object { $_.Status -eq 'Online' }).Count
$TotalOffline = $TotalScanned - $TotalOnline

# ============================================================ #
#  BUILD HTML REPORT                                           #
# ============================================================ #
$OnlineRows = ""
$alt = $false
foreach ($h in ($OnlineHosts | Sort-Object { [Version]$_.IP })) {
    $rowClass  = if ($alt) { "background:#fafafa;" } else { "" }
    $isNew     = $h.IP -in $NewHosts
    $newBadge  = if ($isNew) { "<span style='background:#1e8449;color:white;padding:1px 6px;border-radius:8px;font-size:11px;margin-left:5px;'>NEW</span>" } else { "" }
    $rtt       = if ($h.RTT_ms -ne $null) { "$($h.RTT_ms) ms" } else { "-" }
    $host_     = if ($h.Hostname) { $h.Hostname } else { "-" }
    $rowBorder = if ($isNew) { "border-left:4px solid #1e8449;" } else { "" }
    $OnlineRows += "<tr style='$rowClass$rowBorder'>
        <td><strong>$($h.IP)</strong>$newBadge</td>
        <td>$($h.Subnet).0/24</td>
        <td><span style='background:#1e8449;color:white;padding:2px 8px;border-radius:10px;font-size:11px;'>Online</span></td>
        <td>$host_</td>
        <td style='text-align:right;'>$rtt</td>
    </tr>"
    $alt = !$alt
}

$NewRows  = ""
foreach ($ip in $NewHosts) {
    $h = $OnlineHosts | Where-Object { $_.IP -eq $ip }
    $NewRows += "<tr><td><strong>$ip</strong></td><td>$($h.Hostname)</td><td><span style='background:#1e8449;color:white;padding:2px 8px;border-radius:10px;font-size:11px;'>Appeared</span></td></tr>"
}
if ($NewRows -eq "")  { $NewRows  = "<tr><td colspan='3' style='text-align:center;color:#888;'>No new hosts since last scan</td></tr>" }

$LostRows = ""
foreach ($ip in $LostHosts) {
    $LostRows += "<tr><td><strong>$ip</strong></td><td>-</td><td><span style='background:#c0392b;color:white;padding:2px 8px;border-radius:10px;font-size:11px;'>Disappeared</span></td></tr>"
}
if ($LostRows -eq "") { $LostRows = "<tr><td colspan='3' style='text-align:center;color:#888;'>No hosts disappeared since last scan</td></tr>" }

$AlertBanner = ""
if ($NewHosts.Count -gt 0 -or $LostHosts.Count -gt 0) {
    $alerts = @()
    if ($NewHosts.Count  -gt 0) { $alerts += "$($NewHosts.Count) new host(s) detected on the network" }
    if ($LostHosts.Count -gt 0) { $alerts += "$($LostHosts.Count) host(s) have gone offline since last scan" }
    $AlertBanner = "<div style='background:#fef9e7;border:1px solid #f39c12;border-radius:8px;padding:14px 18px;margin-bottom:20px;color:#7d6608;'>
        ⚠️ " + ($alerts -join " | ") + "</div>"
}

$HTMLBody = @"
<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>
  body { font-family:Segoe UI,Arial,sans-serif; background:#f4f6f9; padding:20px; }
  .container { max-width:950px; margin:auto; background:white; border-radius:10px; box-shadow:0 4px 15px rgba(0,0,0,.12); overflow:hidden; }
  .header { background:linear-gradient(135deg,#1c2833,#1a5276); color:white; padding:30px; }
  .header h1 { margin:0; font-size:24px; }
  .header p { margin:5px 0 0; opacity:.85; font-size:14px; }
  .content { padding:25px; }
  .stats { display:flex; gap:15px; margin-bottom:25px; flex-wrap:wrap; }
  .stat-card { flex:1; min-width:130px; border-radius:8px; padding:16px; text-align:center; }
  .stat-card .num { font-size:32px; font-weight:bold; }
  .stat-card .lbl { font-size:12px; margin-top:4px; }
  .card-blue   { background:#eaf4fb; border-top:4px solid #2e86c1; }
  .card-green  { background:#eafaf1; border-top:4px solid #1e8449; color:#1a5e20; }
  .card-gray   { background:#f2f3f4; border-top:4px solid #7f8c8d; }
  .card-orange { background:#fef5e7; border-top:4px solid #e67e22; color:#7d4e1a; }
  h2 { font-size:16px; color:#2c3e50; border-bottom:2px solid #eee; padding-bottom:8px; margin-top:28px; }
  .two-col { display:grid; grid-template-columns:1fr 1fr; gap:20px; }
  table { width:100%; border-collapse:collapse; font-size:13px; margin-bottom:20px; }
  th { background:#2c3e50; color:white; padding:10px 12px; text-align:left; }
  td { padding:9px 12px; border-bottom:1px solid #f0f0f0; vertical-align:middle; }
  tr:hover td { background:#f5f8ff; }
  .footer { background:#f4f6f9; padding:15px 25px; font-size:12px; color:#888; border-top:1px solid #e0e0e0; }
</style></head><body>
<div class="container">
  <div class="header">
    <h1>🌐 $($Config.ReportTitle)</h1>
    <p>Subnets: <strong>$($Config.Subnets | ForEach-Object { "$_.0/24" } | Join-String -Separator ', ')</strong> &nbsp;|&nbsp; Scan time: ${ScanDuration}s &nbsp;|&nbsp; $ReportTime</p>
  </div>
  <div class="content">
    $AlertBanner
    <div class="stats">
      <div class="stat-card card-blue"><div class="num">$TotalScanned</div><div class="lbl">IPs Scanned</div></div>
      <div class="stat-card card-green"><div class="num">$TotalOnline</div><div class="lbl">Online Hosts</div></div>
      <div class="stat-card card-gray"><div class="num">$TotalOffline</div><div class="lbl">Offline</div></div>
      <div class="stat-card card-orange"><div class="num">$($NewHosts.Count)</div><div class="lbl">New Hosts</div></div>
    </div>

    <div class="two-col">
      <div>
        <h2>🆕 New Hosts (Since Last Scan)</h2>
        <table><tr><th>IP</th><th>Hostname</th><th>Change</th></tr>$NewRows</table>
      </div>
      <div>
        <h2>❌ Lost Hosts (Since Last Scan)</h2>
        <table><tr><th>IP</th><th>Last Known Hostname</th><th>Change</th></tr>$LostRows</table>
      </div>
    </div>

    <h2>✅ All Online Hosts</h2>
    <table>
      <tr><th>IP Address</th><th>Subnet</th><th>Status</th><th>Hostname</th><th>RTT</th></tr>
      $OnlineRows
    </table>
  </div>
  <div class="footer">Auto-generated by PowerShell Ping Sweep &nbsp;|&nbsp; Scanned $TotalScanned IPs in ${ScanDuration}s &nbsp;|&nbsp; $ReportTime</div>
</div></body></html>
"@

# ============================================================ #
#  SEND EMAIL                                                  #
# ============================================================ #
$AlertTag = if ($NewHosts.Count -gt 0 -or $LostHosts.Count -gt 0) { "⚠️ " } else { "✅ " }
$Subject  = "$($AlertTag)Ping Sweep | $TotalOnline online, $($NewHosts.Count) new | $(Get-Date -Format 'yyyy-MM-dd')"

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
$ReportPath = "$($Config.ReportDir)\PingSweep_$(Get-Date -Format 'yyyyMMdd_HHmm').html"
$HTMLBody | Out-File -FilePath $ReportPath -Encoding UTF8
$OnlineHosts | Export-Csv -Path ($ReportPath -replace '\.html$','.csv') -NoTypeInformation
Write-Host "📄 Report saved: $ReportPath" -ForegroundColor Cyan

# ============================================================ #
#  CONSOLE SUMMARY                                             #
# ============================================================ #
Write-Host "`n===== PING SWEEP SUMMARY =====" -ForegroundColor White
Write-Host "Scanned  : $TotalScanned IPs in ${ScanDuration}s"
Write-Host "Online   : $TotalOnline"   -ForegroundColor Green
Write-Host "Offline  : $TotalOffline"  -ForegroundColor Gray
Write-Host "New      : $($NewHosts.Count)"  -ForegroundColor Yellow
Write-Host "Lost     : $($LostHosts.Count)" -ForegroundColor Red
Write-Host "==============================`n" -ForegroundColor White
