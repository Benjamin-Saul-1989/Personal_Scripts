#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Open Firewall Rule Scanner
.DESCRIPTION
    Scans Windows Firewall rules across local or remote servers,
    flags risky/overly permissive rules, and emails an HTML report.
.NOTES
    - Requires administrator privileges
    - For remote servers, ensure WinRM/PSRemoting is enabled
    - Schedule via Task Scheduler for regular audits
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
    ReportTitle  = "Firewall Rule Audit Report"
    ReportDir    = "C:\Reports\Firewall"

    # Target servers (leave as just localhost for local only)
    Servers      = @("localhost")
    # To scan remote servers add them: @("localhost","server01","server02")

    # Risk Detection
    RiskyPorts   = @(21,22,23,25,53,135,137,138,139,445,1433,1434,3306,3389,5985,5986,8080,8443)
    RiskyPortNames = @{
        21   = "FTP"
        22   = "SSH"
        23   = "Telnet"
        25   = "SMTP"
        53   = "DNS"
        135  = "RPC"
        137  = "NetBIOS-NS"
        138  = "NetBIOS-DGM"
        139  = "NetBIOS-SSN"
        445  = "SMB"
        1433 = "SQL Server"
        1434 = "SQL Browser"
        3306 = "MySQL"
        3389 = "RDP"
        5985 = "WinRM HTTP"
        5986 = "WinRM HTTPS"
        8080 = "HTTP Alt"
        8443 = "HTTPS Alt"
    }
}

# ============================================================ #
#  SECURE PASSWORD                                             #
# ============================================================ #
$SecurePass = ConvertTo-SecureString $Config.Password -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential($Config.Username, $SecurePass)

# ============================================================ #
#  HELPER FUNCTIONS                                            #
# ============================================================ #
function Get-RiskLevel {
    param($Rule)

    # Any rule = critical risk factors
    if ($Rule.RemoteAddress -eq "Any" -and $Rule.Direction -eq "Inbound" -and $Rule.Action -eq "Allow") {
        $ports = $Rule.LocalPort -split ","
        foreach ($p in $ports) {
            $p = $p.Trim()
            if ($p -eq "Any") { return "Critical" }
            if ([int]::TryParse($p, [ref]$null) -and [int]$p -in $Config.RiskyPorts) { return "High" }
        }
        return "Medium"
    }
    if ($Rule.RemoteAddress -eq "Any" -and $Rule.Direction -eq "Inbound") { return "Low" }
    return "Info"
}

function Get-PortDescription {
    param([string]$Port)
    if ($Port -eq "Any") { return "ALL PORTS ⚠️" }
    $ports = $Port -split ","
    $descs = foreach ($p in $ports) {
        $p = $p.Trim()
        if ($Config.RiskyPortNames.ContainsKey([int]$p)) { "$p ($($Config.RiskyPortNames[[int]$p]))" }
        else { $p }
    }
    return $descs -join ", "
}

# ============================================================ #
#  SCAN FIREWALL RULES                                         #
# ============================================================ #
if (-not (Test-Path $Config.ReportDir)) {
    New-Item -ItemType Directory -Path $Config.ReportDir | Out-Null
}

$AllRules    = [System.Collections.Generic.List[PSObject]]::new()
$ServerStats = [System.Collections.Generic.List[PSObject]]::new()

foreach ($Server in $Config.Servers) {
    Write-Host "Scanning firewall rules on: $Server" -ForegroundColor Cyan

    try {
        $ScriptBlock = {
            Get-NetFirewallRule -All | Where-Object { $_.Enabled -eq $true } | ForEach-Object {
                $rule    = $_
                $portFilt = $rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
                $addrFilt = $rule | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
                $appFilt  = $rule | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue

                [PSCustomObject]@{
                    Name          = $rule.DisplayName
                    Direction     = $rule.Direction.ToString()
                    Action        = $rule.Action.ToString()
                    Protocol      = if ($portFilt.Protocol) { $portFilt.Protocol } else { "Any" }
                    LocalPort     = if ($portFilt.LocalPort) { $portFilt.LocalPort -join "," } else { "Any" }
                    RemotePort    = if ($portFilt.RemotePort) { $portFilt.RemotePort -join "," } else { "Any" }
                    RemoteAddress = if ($addrFilt.RemoteAddress) { $addrFilt.RemoteAddress -join "," } else { "Any" }
                    LocalAddress  = if ($addrFilt.LocalAddress) { $addrFilt.LocalAddress -join "," } else { "Any" }
                    Program       = if ($appFilt.Program) { $appFilt.Program } else { "Any" }
                    Profile       = $rule.Profile.ToString()
                    Group         = $rule.Group
                    Description   = $rule.Description
                }
            }
        }

        $Rules = if ($Server -eq "localhost" -or $Server -eq $env:COMPUTERNAME) {
            Invoke-Command -ScriptBlock $ScriptBlock
        } else {
            Invoke-Command -ComputerName $Server -ScriptBlock $ScriptBlock -ErrorAction Stop
        }

        $CritCount = 0; $HighCount = 0; $MedCount = 0

        foreach ($Rule in $Rules) {
            $Risk = Get-RiskLevel -Rule $Rule
            if ($Risk -eq "Critical") { $CritCount++ }
            if ($Risk -eq "High")     { $HighCount++ }
            if ($Risk -eq "Medium")   { $MedCount++ }

            $AllRules.Add([PSCustomObject]@{
                Server        = $Server
                Name          = $Rule.Name
                Direction     = $Rule.Direction
                Action        = $Rule.Action
                Protocol      = $Rule.Protocol
                LocalPort     = $Rule.LocalPort
                RemoteAddress = $Rule.RemoteAddress
                Program       = $Rule.Program
                Profile       = $Rule.Profile
                Group         = $Rule.Group
                Risk          = $Risk
            })
        }

        $ServerStats.Add([PSCustomObject]@{
            Server    = $Server
            Total     = $Rules.Count
            Critical  = $CritCount
            High      = $HighCount
            Medium    = $MedCount
            Status    = "Scanned"
        })

        Write-Host "  Found $($Rules.Count) enabled rules ($CritCount critical, $HighCount high)" -ForegroundColor $(if($CritCount -gt 0){'Red'}else{'Green'})

    } catch {
        Write-Warning "  Failed to scan $Server : $_"
        $ServerStats.Add([PSCustomObject]@{
            Server   = $Server
            Total    = 0
            Critical = 0
            High     = 0
            Medium   = 0
            Status   = "Failed: $_"
        })
    }
}

# ============================================================ #
#  COMPUTE TOTALS                                              #
# ============================================================ #
$TotalRules    = $AllRules.Count
$CriticalRules = ($AllRules | Where-Object { $_.Risk -eq 'Critical' })
$HighRules     = ($AllRules | Where-Object { $_.Risk -eq 'High' })
$MediumRules   = ($AllRules | Where-Object { $_.Risk -eq 'Medium' })
$InboundAllow  = ($AllRules | Where-Object { $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow' }).Count

# ============================================================ #
#  BUILD HTML REPORT                                           #
# ============================================================ #
$ReportTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

function Get-RiskBadge {
    param([string]$Risk)
    $color = switch ($Risk) {
        "Critical" { "#7b241c" }
        "High"     { "#c0392b" }
        "Medium"   { "#e67e22" }
        "Low"      { "#2e86c1" }
        "Info"     { "#7f8c8d" }
        default    { "#7f8c8d" }
    }
    return "<span style='background:$color;color:white;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:bold;'>$Risk</span>"
}

$RiskyRows = ""
$alt = $false
foreach ($r in (($CriticalRules + $HighRules + $MediumRules) | Sort-Object Risk)) {
    $rowClass = if ($alt) { "background:#fafafa;" } else { "" }
    $portDesc = Get-PortDescription -Port $r.LocalPort
    $progText = if ($r.Program -ne "Any") { $r.Program.Split("\")[-1] } else { "Any" }
    $RiskyRows += "<tr style='$rowClass'>
        <td><strong>$($r.Server)</strong></td>
        <td style='max-width:200px;word-break:break-word;'>$($r.Name)</td>
        <td>$(Get-RiskBadge -Risk $r.Risk)</td>
        <td>$($r.Direction)</td>
        <td>$($r.Action)</td>
        <td>$($r.Protocol)</td>
        <td>$portDesc</td>
        <td>$($r.RemoteAddress)</td>
        <td style='font-size:11px;color:#555;'>$progText</td>
    </tr>"
    $alt = !$alt
}

if ($RiskyRows -eq "") {
    $RiskyRows = "<tr><td colspan='9' style='text-align:center;color:#1e8449;padding:20px;font-weight:bold;'>✅ No risky rules detected!</td></tr>"
}

$ServerRows = ""
foreach ($s in $ServerStats) {
    $statusBadge = if ($s.Status -eq "Scanned") {
        "<span style='background:#1e8449;color:white;padding:2px 8px;border-radius:10px;font-size:11px;'>✔ Scanned</span>"
    } else {
        "<span style='background:#c0392b;color:white;padding:2px 8px;border-radius:10px;font-size:11px;'>✘ Failed</span>"
    }
    $ServerRows += "<tr>
        <td><strong>$($s.Server)</strong></td>
        <td style='text-align:center;'>$($s.Total)</td>
        <td style='text-align:center;color:#7b241c;font-weight:bold;'>$($s.Critical)</td>
        <td style='text-align:center;color:#c0392b;font-weight:bold;'>$($s.High)</td>
        <td style='text-align:center;color:#e67e22;font-weight:bold;'>$($s.Medium)</td>
        <td>$statusBadge</td>
    </tr>"
}

$AlertBanner = ""
if ($CriticalRules.Count -gt 0) {
    $AlertBanner = "<div style='background:#fdedec;border:1px solid #c0392b;border-radius:8px;padding:14px 18px;margin-bottom:20px;font-weight:bold;color:#7b241c;'>
        🚨 $($CriticalRules.Count) CRITICAL rule(s) found — inbound rules open to ANY source with risky ports. Immediate review required!</div>"
}

$HTMLBody = @"
<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>
  body { font-family:Segoe UI,Arial,sans-serif; background:#f4f6f9; padding:20px; }
  .container { max-width:1200px; margin:auto; background:white; border-radius:10px; box-shadow:0 4px 15px rgba(0,0,0,.12); overflow:hidden; }
  .header { background:linear-gradient(135deg,#1c2833,#2e4057); color:white; padding:30px; }
  .header h1 { margin:0; font-size:24px; }
  .header p { margin:5px 0 0; opacity:.85; font-size:14px; }
  .content { padding:25px; }
  .stats { display:flex; gap:15px; margin-bottom:25px; flex-wrap:wrap; }
  .stat-card { flex:1; min-width:130px; border-radius:8px; padding:16px; text-align:center; }
  .stat-card .num { font-size:32px; font-weight:bold; }
  .stat-card .lbl { font-size:12px; margin-top:4px; }
  .card-total   { background:#eaf0fb; border-top:4px solid #2e86c1; }
  .card-crit    { background:#f9ebea; border-top:4px solid #7b241c; color:#7b241c; }
  .card-high    { background:#fdedec; border-top:4px solid #c0392b; color:#c0392b; }
  .card-inbound { background:#fef5e7; border-top:4px solid #e67e22; color:#7d4e1a; }
  h2 { font-size:16px; color:#2c3e50; border-bottom:2px solid #eee; padding-bottom:8px; margin-top:28px; }
  table { width:100%; border-collapse:collapse; font-size:12px; margin-bottom:20px; }
  th { background:#2c3e50; color:white; padding:9px 10px; text-align:left; }
  td { padding:8px 10px; border-bottom:1px solid #f0f0f0; vertical-align:middle; }
  tr:hover td { background:#f5f8ff; }
  .footer { background:#f4f6f9; padding:15px 25px; font-size:12px; color:#888; border-top:1px solid #e0e0e0; }
</style></head><body>
<div class="container">
  <div class="header">
    <h1>🛡️ $($Config.ReportTitle)</h1>
    <p>Servers Scanned: <strong>$($Config.Servers -join ', ')</strong> &nbsp;|&nbsp; Generated: $ReportTime</p>
  </div>
  <div class="content">
    $AlertBanner
    <div class="stats">
      <div class="stat-card card-total"><div class="num">$TotalRules</div><div class="lbl">Total Enabled Rules</div></div>
      <div class="stat-card card-crit"><div class="num">$($CriticalRules.Count)</div><div class="lbl">Critical Risk</div></div>
      <div class="stat-card card-high"><div class="num">$($HighRules.Count)</div><div class="lbl">High Risk</div></div>
      <div class="stat-card card-inbound"><div class="num">$InboundAllow</div><div class="lbl">Inbound Allow Rules</div></div>
    </div>

    <h2>🖥️ Per-Server Summary</h2>
    <table>
      <tr><th>Server</th><th>Total Rules</th><th>Critical</th><th>High</th><th>Medium</th><th>Scan Status</th></tr>
      $ServerRows
    </table>

    <h2>⚠️ Risky Rules (Critical / High / Medium)</h2>
    <table>
      <tr><th>Server</th><th>Rule Name</th><th>Risk</th><th>Direction</th><th>Action</th><th>Protocol</th><th>Port(s)</th><th>Remote Address</th><th>Program</th></tr>
      $RiskyRows
    </table>
  </div>
  <div class="footer">Auto-generated by PowerShell Firewall Rule Scanner &nbsp;|&nbsp; $ReportTime</div>
</div></body></html>
"@

# ============================================================ #
#  SEND EMAIL                                                  #
# ============================================================ #
$AlertTag = if ($CriticalRules.Count -gt 0) { "🚨 CRITICAL - " } elseif ($HighRules.Count -gt 0) { "⚠️ " } else { "✅ " }
$Subject  = "$($AlertTag)Firewall Audit | $($CriticalRules.Count) Critical, $($HighRules.Count) High | $(Get-Date -Format 'yyyy-MM-dd')"

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
$ReportPath = "$($Config.ReportDir)\FirewallAudit_$(Get-Date -Format 'yyyyMMdd_HHmm').html"
$HTMLBody | Out-File -FilePath $ReportPath -Encoding UTF8
Write-Host "📄 Report saved: $ReportPath" -ForegroundColor Cyan

# ============================================================ #
#  CONSOLE SUMMARY                                             #
# ============================================================ #
Write-Host "`n===== FIREWALL SCAN SUMMARY =====" -ForegroundColor White
Write-Host "Total Rules : $TotalRules"
Write-Host "Critical    : $($CriticalRules.Count)" -ForegroundColor Red
Write-Host "High        : $($HighRules.Count)"     -ForegroundColor DarkRed
Write-Host "Medium      : $($MediumRules.Count)"   -ForegroundColor Yellow
Write-Host "=================================`n"    -ForegroundColor White
