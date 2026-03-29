#Requires -RunAsAdministrator
<#
.SYNOPSIS
    RDP Access Auditor
.DESCRIPTION
    Audits who has Remote Desktop access on local and remote servers
    by checking the Remote Desktop Users group and admin rights,
    then emails a full HTML report.
.NOTES
    - Requires administrator privileges
    - For remote servers, WinRM/PSRemoting must be enabled
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
    Servers      = @("localhost")
    # Add remote servers: @("localhost","server01","server02","server03")

    ReportTitle  = "RDP Access Audit Report"
    ReportDir    = "C:\Reports\RDPAudit"

    # Accounts that are expected/approved to have RDP (won't be flagged)
    ApprovedUsers = @("Administrator", "Domain Admins")

    # Alert if more than this many users have RDP access on a single server
    MaxRDPUsers  = 10
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
$ServerStats = [System.Collections.Generic.List[PSObject]]::new()
$ReportTime  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# ============================================================ #
#  AUDIT EACH SERVER                                           #
# ============================================================ #
$AuditScript = {
    $Results = @()

    # ── RDP Enabled Check ──────────────────────────────────────
    $RDPEnabled = $false
    try {
        $RDPReg = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction Stop
        $RDPEnabled = ($RDPReg.fDenyTSConnections -eq 0)
    } catch { }

    # ── Remote Desktop Users Group ─────────────────────────────
    $RDPGroupMembers = @()
    try {
        $Group = [ADSI]"WinNT://./Remote Desktop Users,group"
        $Members = @($Group.Invoke("Members"))
        foreach ($Member in $Members) {
            $obj = New-Object System.DirectoryServices.DirectoryEntry($Member)
            $RDPGroupMembers += [PSCustomObject]@{
                Name    = $obj.Name
                Type    = "Remote Desktop Users"
                Source  = "Local Group"
            }
        }
    } catch { }

    # ── Local Administrators Group ─────────────────────────────
    $LocalAdmins = @()
    try {
        $Group = [ADSI]"WinNT://./Administrators,group"
        $Members = @($Group.Invoke("Members"))
        foreach ($Member in $Members) {
            $obj = New-Object System.DirectoryServices.DirectoryEntry($Member)
            $LocalAdmins += [PSCustomObject]@{
                Name    = $obj.Name
                Type    = "Local Administrator"
                Source  = "Administrators Group"
            }
        }
    } catch { }

    # ── Network Level Authentication ──────────────────────────
    $NLAEnabled = $false
    try {
        $NLAReg = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -ErrorAction Stop
        $NLAEnabled = ($NLAReg.UserAuthentication -eq 1)
    } catch { }

    # ── RDP Port ──────────────────────────────────────────────
    $RDPPort = 3389
    try {
        $PortReg = Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "PortNumber" -ErrorAction Stop
        $RDPPort = $PortReg.PortNumber
    } catch { }

    # ── Active RDP Sessions ───────────────────────────────────
    $ActiveSessions = @()
    try {
        $QwinstaOutput = qwinsta 2>$null
        foreach ($line in ($QwinstaOutput | Select-Object -Skip 1)) {
            if ($line -match "^\s+(\S+)\s+(\S+)\s+(\d+)\s+(\S+)") {
                $ActiveSessions += [PSCustomObject]@{
                    SessionName = $Matches[1]
                    Username    = $Matches[2]
                    SessionID   = $Matches[3]
                    State       = $Matches[4]
                }
            }
        }
    } catch { }

    return [PSCustomObject]@{
        RDPEnabled     = $RDPEnabled
        RDPPort        = $RDPPort
        NLAEnabled     = $NLAEnabled
        RDPGroupMembers = $RDPGroupMembers
        LocalAdmins    = $LocalAdmins
        ActiveSessions = $ActiveSessions
    }
}

foreach ($Server in $Config.Servers) {
    Write-Host "Auditing RDP access on: $Server" -ForegroundColor Cyan

    try {
        $AuditData = if ($Server -eq "localhost" -or $Server -eq $env:COMPUTERNAME) {
            Invoke-Command -ScriptBlock $AuditScript
        } else {
            Invoke-Command -ComputerName $Server -ScriptBlock $AuditScript -ErrorAction Stop
        }

        $AllMembers = @($AuditData.RDPGroupMembers) + @($AuditData.LocalAdmins)
        $UniqueUsers = $AllMembers | Select-Object -ExpandProperty Name -Unique
        $Unapproved  = $UniqueUsers | Where-Object { $_ -notin $Config.ApprovedUsers }

        foreach ($m in $AllMembers) {
            $IsApproved = $m.Name -in $Config.ApprovedUsers
            $AllResults.Add([PSCustomObject]@{
                Server     = $Server
                Account    = $m.Name
                AccessType = $m.Type
                Source     = $m.Source
                Approved   = $IsApproved
                RDPEnabled = $AuditData.RDPEnabled
                NLA        = $AuditData.NLAEnabled
            })
        }

        $ServerStats.Add([PSCustomObject]@{
            Server         = $Server
            RDPEnabled     = $AuditData.RDPEnabled
            RDPPort        = $AuditData.RDPPort
            NLAEnabled     = $AuditData.NLAEnabled
            TotalAccess    = $UniqueUsers.Count
            UnapprovedCount= $Unapproved.Count
            ActiveSessions = $AuditData.ActiveSessions.Count
            Status         = "Scanned"
        })

        Write-Host "  RDP Enabled: $($AuditData.RDPEnabled) | Port: $($AuditData.RDPPort) | NLA: $($AuditData.NLAEnabled) | Users with access: $($UniqueUsers.Count)" -ForegroundColor $(if($AuditData.RDPEnabled){'Yellow'}else{'Green'})

    } catch {
        Write-Warning "  Failed to audit $Server : $_"
        $ServerStats.Add([PSCustomObject]@{
            Server         = $Server
            RDPEnabled     = "Unknown"
            RDPPort        = "Unknown"
            NLAEnabled     = "Unknown"
            TotalAccess    = 0
            UnapprovedCount= 0
            ActiveSessions = 0
            Status         = "Failed"
        })
    }
}

# ============================================================ #
#  COMPUTE TOTALS                                              #
# ============================================================ #
$TotalServers      = $Config.Servers.Count
$RDPEnabledCount   = ($ServerStats | Where-Object { $_.RDPEnabled -eq $true }).Count
$NLADisabledCount  = ($ServerStats | Where-Object { $_.NLAEnabled -eq $false -and $_.RDPEnabled -eq $true }).Count
$TotalUnapproved   = ($AllResults | Where-Object { -not $_.Approved }).Count
$OverExposedServers= ($ServerStats | Where-Object { $_.TotalAccess -gt $Config.MaxRDPUsers }).Count

# ============================================================ #
#  BUILD HTML REPORT                                           #
# ============================================================ #
$ServerRows = ""
foreach ($s in $ServerStats) {
    $rdpBadge = if ($s.RDPEnabled -eq $true)  { "<span style='background:#c0392b;color:white;padding:2px 8px;border-radius:10px;font-size:11px;'>ENABLED</span>" }
                elseif ($s.RDPEnabled -eq $false) { "<span style='background:#1e8449;color:white;padding:2px 8px;border-radius:10px;font-size:11px;'>DISABLED</span>" }
                else { "<span style='background:#7f8c8d;color:white;padding:2px 8px;border-radius:10px;font-size:11px;'>UNKNOWN</span>" }
    $nlaBadge = if ($s.NLAEnabled -eq $true)  { "<span style='background:#1e8449;color:white;padding:2px 8px;border-radius:10px;font-size:11px;'>✔ NLA On</span>" }
                elseif ($s.NLAEnabled -eq $false) { "<span style='background:#e67e22;color:white;padding:2px 8px;border-radius:10px;font-size:11px;'>⚠ NLA Off</span>" }
                else { "-" }
    $portText = if ($s.RDPPort -ne 3389 -and $s.RDPPort -ne "Unknown") { "<strong style='color:#e67e22;'>$($s.RDPPort) ⚠</strong>" } else { $s.RDPPort }
    $unapprText = if ($s.UnapprovedCount -gt 0) { "<strong style='color:#c0392b;'>$($s.UnapprovedCount)</strong>" } else { "<span style='color:#1e8449;'>0</span>" }

    $ServerRows += "<tr>
        <td><strong>$($s.Server)</strong></td>
        <td>$rdpBadge</td>
        <td>$portText</td>
        <td>$nlaBadge</td>
        <td style='text-align:center;'>$($s.TotalAccess)</td>
        <td style='text-align:center;'>$unapprText</td>
        <td style='text-align:center;'>$($s.ActiveSessions)</td>
    </tr>"
}

$AccessRows = ""
$alt = $false
foreach ($r in ($AllResults | Sort-Object Server, AccessType)) {
    $rowClass    = if ($alt) { "background:#fafafa;" } else { "" }
    $approvedBadge = if ($r.Approved) {
        "<span style='background:#1e8449;color:white;padding:2px 7px;border-radius:10px;font-size:11px;'>✔ Approved</span>"
    } else {
        "<span style='background:#e67e22;color:white;padding:2px 7px;border-radius:10px;font-size:11px;'>Review</span>"
    }
    $typeBadge = if ($r.AccessType -eq "Local Administrator") {
        "<span style='background:#8e44ad;color:white;padding:2px 7px;border-radius:10px;font-size:11px;'>Admin</span>"
    } else {
        "<span style='background:#2e86c1;color:white;padding:2px 7px;border-radius:10px;font-size:11px;'>RDP User</span>"
    }
    $AccessRows += "<tr style='$rowClass'>
        <td><strong>$($r.Server)</strong></td>
        <td>$($r.Account)</td>
        <td>$typeBadge</td>
        <td>$($r.Source)</td>
        <td>$approvedBadge</td>
    </tr>"
    $alt = !$alt
}

$AlertBanner = ""
if ($NLADisabledCount -gt 0 -or $TotalUnapproved -gt 0) {
    $alerts = @()
    if ($NLADisabledCount -gt 0) { $alerts += "$NLADisabledCount server(s) have RDP enabled WITHOUT Network Level Authentication" }
    if ($TotalUnapproved -gt 0)  { $alerts += "$TotalUnapproved unapproved account(s) have RDP access — review required" }
    $AlertBanner = "<div style='background:#fef9e7;border:1px solid #f39c12;border-radius:8px;padding:14px 18px;margin-bottom:20px;color:#7d6608;font-size:14px;'>
        ⚠️ <strong>Attention:</strong> " + ($alerts -join " | ") + "</div>"
}

$HTMLBody = @"
<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>
  body { font-family:Segoe UI,Arial,sans-serif; background:#f4f6f9; padding:20px; }
  .container { max-width:1050px; margin:auto; background:white; border-radius:10px; box-shadow:0 4px 15px rgba(0,0,0,.12); overflow:hidden; }
  .header { background:linear-gradient(135deg,#154360,#1a5276); color:white; padding:30px; }
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
  table { width:100%; border-collapse:collapse; font-size:13px; margin-bottom:20px; }
  th { background:#2c3e50; color:white; padding:10px 12px; text-align:left; }
  td { padding:9px 12px; border-bottom:1px solid #f0f0f0; vertical-align:middle; }
  tr:hover td { background:#f5f8ff; }
  .footer { background:#f4f6f9; padding:15px 25px; font-size:12px; color:#888; border-top:1px solid #e0e0e0; }
</style></head><body>
<div class="container">
  <div class="header">
    <h1>🖥️ $($Config.ReportTitle)</h1>
    <p>Servers: <strong>$($Config.Servers -join ', ')</strong> &nbsp;|&nbsp; Generated: $ReportTime</p>
  </div>
  <div class="content">
    $AlertBanner
    <div class="stats">
      <div class="stat-card card-blue"><div class="num">$TotalServers</div><div class="lbl">Servers Scanned</div></div>
      <div class="stat-card card-red"><div class="num">$RDPEnabledCount</div><div class="lbl">RDP Enabled</div></div>
      <div class="stat-card card-orange"><div class="num">$NLADisabledCount</div><div class="lbl">NLA Disabled</div></div>
      <div class="stat-card card-purple"><div class="num">$TotalUnapproved</div><div class="lbl">Unapproved Accounts</div></div>
    </div>

    <h2>🖥️ Server RDP Configuration</h2>
    <table>
      <tr><th>Server</th><th>RDP Status</th><th>Port</th><th>NLA</th><th>Users w/ Access</th><th>Unapproved</th><th>Active Sessions</th></tr>
      $ServerRows
    </table>

    <h2>👤 All Accounts with RDP Access</h2>
    <table>
      <tr><th>Server</th><th>Account</th><th>Access Type</th><th>Source Group</th><th>Status</th></tr>
      $AccessRows
    </table>
  </div>
  <div class="footer">Auto-generated by PowerShell RDP Access Auditor &nbsp;|&nbsp; $ReportTime</div>
</div></body></html>
"@

# ============================================================ #
#  SEND EMAIL                                                  #
# ============================================================ #
$AlertTag = if ($NLADisabledCount -gt 0 -or $TotalUnapproved -gt 0) { "⚠️ " } else { "✅ " }
$Subject  = "$($AlertTag)RDP Access Audit | $RDPEnabledCount servers with RDP | $(Get-Date -Format 'yyyy-MM-dd')"

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
$ReportPath = "$($Config.ReportDir)\RDPAudit_$(Get-Date -Format 'yyyyMMdd_HHmm').html"
$HTMLBody | Out-File -FilePath $ReportPath -Encoding UTF8
Write-Host "📄 Report saved: $ReportPath" -ForegroundColor Cyan

# ============================================================ #
#  CONSOLE SUMMARY                                             #
# ============================================================ #
Write-Host "`n===== RDP AUDIT SUMMARY =====" -ForegroundColor White
Write-Host "Servers Scanned  : $TotalServers"
Write-Host "RDP Enabled      : $RDPEnabledCount"   -ForegroundColor $(if($RDPEnabledCount -gt 0){'Yellow'}else{'Green'})
Write-Host "NLA Disabled     : $NLADisabledCount"  -ForegroundColor $(if($NLADisabledCount -gt 0){'Red'}else{'Green'})
Write-Host "Unapproved Users : $TotalUnapproved"   -ForegroundColor $(if($TotalUnapproved -gt 0){'Yellow'}else{'Green'})
Write-Host "=============================`n"        -ForegroundColor White
