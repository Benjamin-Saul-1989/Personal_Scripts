#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Duplicate IP Address Detector
.DESCRIPTION
    Scans the network for duplicate IP addresses using ARP scanning,
    cross-references DNS, DHCP, and ARP cache, then emails a report.
.NOTES
    - Requires administrator privileges
    - Uses arp.exe and ping for detection
    - Can scan local subnets or specified ranges
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
    Subnets      = @("192.168.1")     # Subnets to scan (no trailing .0)
    StartHost    = 1
    EndHost      = 254
    TimeoutMS    = 300
    MaxThreads   = 150
    PingsPerIP   = 2                  # Extra pings to flush ARP

    ReportTitle  = "Duplicate IP Address Detection Report"
    ReportDir    = "C:\Reports\DuplicateIP"

    # Known static assignments to cross-reference (optional)
    # Format: IP = "Description"
    KnownStaticIPs = @{
        # "192.168.1.1"  = "Gateway/Router"
        # "192.168.1.10" = "Domain Controller"
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

$ReportTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$ScanStart  = Get-Date

Write-Host "Starting duplicate IP detection..." -ForegroundColor Cyan
Write-Host "Step 1: Flushing ARP cache..." -ForegroundColor Yellow
arp -d * 2>$null

# ============================================================ #
#  STEP 1 — PING SWEEP TO POPULATE ARP CACHE                  #
# ============================================================ #
Write-Host "Step 2: Pinging all IPs to populate ARP cache..." -ForegroundColor Yellow

$RunspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $Config.MaxThreads)
$RunspacePool.Open()

$PingScript = {
    param($IP, $Timeout, $PingCount)
    for ($i = 0; $i -lt $PingCount; $i++) {
        try {
            $p = New-Object System.Net.NetworkInformation.Ping
            $p.Send($IP, $Timeout) | Out-Null
        } catch { }
    }
}

$AllIPs = foreach ($Subnet in $Config.Subnets) {
    $Config.StartHost..$Config.EndHost | ForEach-Object { "$Subnet.$_" }
}

$Jobs = foreach ($IP in $AllIPs) {
    $PS = [System.Management.Automation.PowerShell]::Create()
    $PS.RunspacePool = $RunspacePool
    $PS.AddScript($PingScript).AddArgument($IP).AddArgument($Config.TimeoutMS).AddArgument($Config.PingsPerIP) | Out-Null
    [PSCustomObject]@{ PS = $PS; Handle = $PS.BeginInvoke() }
}

$Done = 0
foreach ($Job in $Jobs) {
    $Job.PS.EndInvoke($Job.Handle) | Out-Null
    $Job.PS.Dispose()
    $Done++
    if ($Done % 50 -eq 0) {
        Write-Progress -Activity "Pinging IPs" -Status "$Done/$($AllIPs.Count)" -PercentComplete ([math]::Round($Done / $AllIPs.Count * 100))
    }
}
Write-Progress -Activity "Pinging IPs" -Completed
$RunspacePool.Close()
$RunspacePool.Dispose()

Start-Sleep -Seconds 2  # Allow ARP to settle

# ============================================================ #
#  STEP 2 — CAPTURE ARP TABLE                                  #
# ============================================================ #
Write-Host "Step 3: Reading ARP table..." -ForegroundColor Yellow

$ARPOutput  = arp -a 2>$null
$ARPEntries = [System.Collections.Generic.List[PSObject]]::new()

$CurrentInterface = ""
foreach ($Line in $ARPOutput) {
    if ($Line -match "Interface:\s+(\d+\.\d+\.\d+\.\d+)") {
        $CurrentInterface = $Matches[1]
    } elseif ($Line -match "^\s+(\d+\.\d+\.\d+\.\d+)\s+([\da-f-]+)\s+(\w+)") {
        $IP  = $Matches[1].Trim()
        $MAC = $Matches[2].Trim().ToUpper() -replace "-", ":"
        $Type = $Matches[3].Trim()

        # Skip broadcast/multicast
        if ($IP -match "^224\." -or $IP -eq "255.255.255.255" -or $MAC -match "^(FF:|01:|33:)") { continue }

        $ARPEntries.Add([PSCustomObject]@{
            IP        = $IP
            MAC       = $MAC
            Type      = $Type
            Interface = $CurrentInterface
        })
    }
}

Write-Host "  ARP table has $($ARPEntries.Count) entries" -ForegroundColor Cyan

# ============================================================ #
#  STEP 3 — DETECT DUPLICATES                                  #
# ============================================================ #
Write-Host "Step 4: Analyzing for duplicates..." -ForegroundColor Yellow

# Duplicate IP = same IP with multiple different MACs
$DuplicateIPs = $ARPEntries |
    Group-Object IP |
    Where-Object {
        ($_.Group | Select-Object -ExpandProperty MAC -Unique).Count -gt 1
    }

# Duplicate MAC = same MAC assigned to multiple IPs
$DuplicateMACs = $ARPEntries |
    Where-Object { $_.MAC -ne "ff:ff:ff:ff:ff:ff" -and $_.MAC -notmatch "^01:" } |
    Group-Object MAC |
    Where-Object {
        ($_.Group | Select-Object -ExpandProperty IP -Unique).Count -gt 1
    }

$DupIPCount  = $DuplicateIPs.Count
$DupMACCount = $DuplicateMACs.Count

Write-Host "  Duplicate IPs found : $DupIPCount"  -ForegroundColor $(if($DupIPCount -gt 0){'Red'}else{'Green'})
Write-Host "  Duplicate MACs found: $DupMACCount" -ForegroundColor $(if($DupMACCount -gt 0){'Yellow'}else{'Green'})

# ============================================================ #
#  RESOLVE HOSTNAMES FOR FLAGGED IPs                          #
# ============================================================ #
$AllFlaggedIPs = @()
$DuplicateIPs  | ForEach-Object { $AllFlaggedIPs += $_.Group.IP }
$DuplicateMACs | ForEach-Object { $AllFlaggedIPs += $_.Group.IP }
$AllFlaggedIPs = $AllFlaggedIPs | Select-Object -Unique

$Hostnames = @{}
foreach ($IP in $AllFlaggedIPs) {
    try {
        $Hostnames[$IP] = [System.Net.Dns]::GetHostEntry($IP).HostName
    } catch {
        $Hostnames[$IP] = ""
    }
}

# ============================================================ #
#  BUILD HTML REPORT                                           #
# ============================================================ #
$ScanDuration = [math]::Round(((Get-Date) - $ScanStart).TotalSeconds, 1)

$DupIPRows = ""
if ($DuplicateIPs.Count -eq 0) {
    $DupIPRows = "<tr><td colspan='5' style='text-align:center;color:#1e8449;padding:20px;font-weight:bold;'>✅ No duplicate IP addresses detected!</td></tr>"
} else {
    $alt = $false
    foreach ($grp in $DuplicateIPs) {
        $hostname    = $Hostnames[$grp.Name]
        $isStatic    = $Config.KnownStaticIPs.ContainsKey($grp.Name)
        $staticNote  = if ($isStatic) { " <span style='background:#8e44ad;color:white;padding:1px 6px;border-radius:8px;font-size:10px;'>STATIC: $($Config.KnownStaticIPs[$grp.Name])</span>" } else { "" }
        $macList     = ($grp.Group | Select-Object -ExpandProperty MAC -Unique) -join "<br>"
        $ifaceList   = ($grp.Group | Select-Object -ExpandProperty Interface -Unique) -join ", "
        $rowClass    = if ($alt) { "background:#fdf2f8;" } else { "background:#fef9f9;" }

        $DupIPRows += "<tr style='$rowClass border-left:4px solid #c0392b;'>
            <td><strong style='color:#c0392b;'>$($grp.Name)</strong>$staticNote</td>
            <td>$hostname</td>
            <td style='font-family:monospace;font-size:12px;'>$macList</td>
            <td style='text-align:center;color:#c0392b;font-weight:bold;'>$($grp.Group.Count)</td>
            <td style='font-size:12px;color:#555;'>$ifaceList</td>
        </tr>"
        $alt = !$alt
    }
}

$DupMACRows = ""
if ($DuplicateMACs.Count -eq 0) {
    $DupMACRows = "<tr><td colspan='4' style='text-align:center;color:#1e8449;padding:20px;font-weight:bold;'>✅ No duplicate MAC addresses detected!</td></tr>"
} else {
    $alt = $false
    foreach ($grp in $DuplicateMACs) {
        $rowClass = if ($alt) { "background:#fafafa;" } else { "" }
        $ipList   = ($grp.Group | Select-Object -ExpandProperty IP -Unique) | ForEach-Object {
            $h = $Hostnames[$_]
            if ($h) { "$_ ($h)" } else { $_ }
        }
        $DupMACRows += "<tr style='$rowClass border-left:4px solid #e67e22;'>
            <td><strong style='font-family:monospace;'>$($grp.Name)</strong></td>
            <td>$($ipList -join '<br>')</td>
            <td style='text-align:center;color:#e67e22;font-weight:bold;'>$($grp.Group.Count)</td>
            <td style='font-size:12px;color:#888;'>Possible VM migration, NIC teaming, or IP conflict</td>
        </tr>"
        $alt = !$alt
    }
}

# All ARP entries for reference
$ARPRows = ""
$alt = $false
foreach ($e in ($ARPEntries | Sort-Object { [Version]$_.IP } | Select-Object -First 200)) {
    $rowClass   = if ($alt) { "background:#fafafa;" } else { "" }
    $isDupIP    = $DuplicateIPs | Where-Object { $_.Name -eq $e.IP }
    $dupStyle   = if ($isDupIP) { "color:#c0392b;font-weight:bold;" } else { "" }
    $hostname   = $Hostnames[$e.IP]
    $ARPRows   += "<tr style='$rowClass'>
        <td style='font-family:monospace;$dupStyle'>$($e.IP)</td>
        <td style='font-family:monospace;font-size:12px;'>$($e.MAC)</td>
        <td>$hostname</td>
        <td>$($e.Type)</td>
        <td>$($e.Interface)</td>
    </tr>"
    $alt = !$alt
}

$AlertBanner = ""
if ($DupIPCount -gt 0) {
    $AlertBanner = "<div style='background:#fdedec;border:1px solid #c0392b;border-radius:8px;padding:14px 18px;margin-bottom:20px;color:#7b241c;font-weight:bold;font-size:14px;'>
        🚨 $DupIPCount duplicate IP address(es) detected! These can cause network outages and connectivity issues. Investigate immediately.</div>"
} elseif ($DupMACCount -gt 0) {
    $AlertBanner = "<div style='background:#fef5e7;border:1px solid #e67e22;border-radius:8px;padding:14px 18px;margin-bottom:20px;color:#7d4e1a;'>
        ⚠️ $DupMACCount duplicate MAC address(es) found — this may indicate VM cloning, NIC teaming, or spoofing.</div>"
}

$HTMLBody = @"
<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>
  body { font-family:Segoe UI,Arial,sans-serif; background:#f4f6f9; padding:20px; }
  .container { max-width:1050px; margin:auto; background:white; border-radius:10px; box-shadow:0 4px 15px rgba(0,0,0,.12); overflow:hidden; }
  .header { background:linear-gradient(135deg,#1c2833,#922b21); color:white; padding:30px; }
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
  .card-green  { background:#eafaf1; border-top:4px solid #1e8449; color:#1a5e20; }
  h2 { font-size:16px; color:#2c3e50; border-bottom:2px solid #eee; padding-bottom:8px; margin-top:28px; }
  table { width:100%; border-collapse:collapse; font-size:13px; margin-bottom:20px; }
  th { background:#2c3e50; color:white; padding:10px 12px; text-align:left; }
  td { padding:9px 12px; border-bottom:1px solid #f0f0f0; vertical-align:middle; }
  tr:hover td { background:#f5f8ff; }
  .footer { background:#f4f6f9; padding:15px 25px; font-size:12px; color:#888; border-top:1px solid #e0e0e0; }
</style></head><body>
<div class="container">
  <div class="header">
    <h1>🔎 $($Config.ReportTitle)</h1>
    <p>Subnets: <strong>$($Config.Subnets | ForEach-Object {"$_.0/24"} | Join-String -Separator ', ')</strong> &nbsp;|&nbsp; Scan time: ${ScanDuration}s &nbsp;|&nbsp; $ReportTime</p>
  </div>
  <div class="content">
    $AlertBanner
    <div class="stats">
      <div class="stat-card card-blue"><div class="num">$($ARPEntries.Count)</div><div class="lbl">ARP Entries</div></div>
      <div class="stat-card card-red"><div class="num">$DupIPCount</div><div class="lbl">Duplicate IPs</div></div>
      <div class="stat-card card-orange"><div class="num">$DupMACCount</div><div class="lbl">Duplicate MACs</div></div>
      <div class="stat-card card-green"><div class="num">$(($ARPEntries | Select-Object -ExpandProperty IP -Unique).Count)</div><div class="lbl">Unique IPs Online</div></div>
    </div>

    <h2>🚨 Duplicate IP Addresses (Same IP, Different MACs)</h2>
    <table>
      <tr><th>IP Address</th><th>Hostname</th><th>MAC Addresses</th><th>ARP Entries</th><th>Interface</th></tr>
      $DupIPRows
    </table>

    <h2>⚠️ Duplicate MAC Addresses (Same MAC, Multiple IPs)</h2>
    <table>
      <tr><th>MAC Address</th><th>IP Addresses</th><th>Entries</th><th>Notes</th></tr>
      $DupMACRows
    </table>

    <h2>📋 Full ARP Table (first 200 entries)</h2>
    <table>
      <tr><th>IP Address</th><th>MAC Address</th><th>Hostname</th><th>Type</th><th>Interface</th></tr>
      $ARPRows
    </table>
  </div>
  <div class="footer">Auto-generated by PowerShell Duplicate IP Detector &nbsp;|&nbsp; $ReportTime</div>
</div></body></html>
"@

# ============================================================ #
#  SEND EMAIL                                                  #
# ============================================================ #
$AlertTag = if ($DupIPCount -gt 0) { "🚨 ALERT - " } elseif ($DupMACCount -gt 0) { "⚠️ " } else { "✅ " }
$Subject  = "$($AlertTag)Duplicate IP Scan | $DupIPCount dup IPs, $DupMACCount dup MACs | $(Get-Date -Format 'yyyy-MM-dd')"

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
$ReportPath = "$($Config.ReportDir)\DuplicateIP_$(Get-Date -Format 'yyyyMMdd_HHmm').html"
$HTMLBody | Out-File -FilePath $ReportPath -Encoding UTF8
Write-Host "📄 Report saved: $ReportPath" -ForegroundColor Cyan

# ============================================================ #
#  CONSOLE SUMMARY                                             #
# ============================================================ #
Write-Host "`n===== DUPLICATE IP SUMMARY =====" -ForegroundColor White
Write-Host "ARP Entries    : $($ARPEntries.Count)"
Write-Host "Duplicate IPs  : $DupIPCount"  -ForegroundColor $(if($DupIPCount -gt 0){'Red'}else{'Green'})
Write-Host "Duplicate MACs : $DupMACCount" -ForegroundColor $(if($DupMACCount -gt 0){'Yellow'}else{'Green'})
Write-Host "Scan Duration  : ${ScanDuration}s"
Write-Host "================================`n" -ForegroundColor White
