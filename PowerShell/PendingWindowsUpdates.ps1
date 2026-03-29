#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Pending Windows Update Checker
.DESCRIPTION
    Checks for pending Windows Updates on local and remote servers,
    categorizes by severity, and emails a prioritized HTML report.
.NOTES
    - Requires PSWindowsUpdate module (auto-installs if missing)
    - Remote servers need WinRM/PSRemoting enabled
    - Run as local/domain admin
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
    # Add remote servers: @("localhost","server01","server02")

    ReportTitle  = "Pending Windows Updates Report"
    ReportDir    = "C:\Reports\WindowsUpdates"

    # Alert thresholds
    CriticalAlertCount = 1      # Alert if ANY critical updates pending
    TotalAlertCount    = 20     # Alert if total pending exceeds this
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

$AllUpdates  = [System.Collections.Generic.List[PSObject]]::new()
$ServerStats = [System.Collections.Generic.List[PSObject]]::new()
$ReportTime  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# ============================================================ #
#  UPDATE COLLECTION SCRIPT                                    #
# ============================================================ #
$CollectScript = {
    # Try PSWindowsUpdate first, fall back to COM object
    $Updates = @()

    try {
        if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope AllUsers | Out-Null
            Install-Module PSWindowsUpdate -Force -Scope AllUsers -AllowClobber | Out-Null
        }
        Import-Module PSWindowsUpdate -Force -ErrorAction Stop
        $Updates = Get-WUList -ErrorAction Stop | ForEach-Object {
            [PSCustomObject]@{
                Title       = $_.Title
                KB          = $_.KBArticleIDs -join ","
                Severity    = if ($_.MsrcSeverity) { $_.MsrcSeverity } else { "Unknown" }
                Size_MB     = if ($_.MaxDownloadSize) { [math]::Round($_.MaxDownloadSize / 1MB, 1) } else { 0 }
                IsDownloaded= $_.IsDownloaded
                Category    = ($_.Categories | Select-Object -First 1 -ExpandProperty Name)
                RebootRequired = $_.RebootRequired
            }
        }
    } catch {
        # Fallback: Windows Update COM object
        try {
            $Session  = New-Object -ComObject Microsoft.Update.Session
            $Searcher = $Session.CreateUpdateSearcher()
            $Result   = $Searcher.Search("IsInstalled=0 AND IsHidden=0")
            $Updates  = $Result.Updates | ForEach-Object {
                $upd = $_
                [PSCustomObject]@{
                    Title        = $upd.Title
                    KB           = ($upd.KBArticleIDs | ForEach-Object { $_ }) -join ","
                    Severity     = if ($upd.MsrcSeverity) { $upd.MsrcSeverity } else { "Unknown" }
                    Size_MB      = [math]::Round($upd.MaxDownloadSize / 1MB, 1)
                    IsDownloaded = $upd.IsDownloaded
                    Category     = $upd.Categories.Item(0).Name
                    RebootRequired = $upd.RebootRequired
                }
            }
        } catch {
            return @{ Error = $_.ToString(); Updates = @() }
        }
    }

    # Check last update install date
    $LastInstall = $null
    try {
        $Searcher2 = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
        $HistCount = $Searcher2.GetTotalHistoryCount()
        if ($HistCount -gt 0) {
            $LastEntry = $Searcher2.QueryHistory(0,1) | Select-Object -First 1
            $LastInstall = $LastEntry.Date
        }
    } catch { }

    # Check if reboot is pending
    $RebootPending = $false
    try {
        $RebootPending = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -ErrorAction SilentlyContinue) -ne $null
    } catch { }

    return @{
        Updates        = $Updates
        LastInstall    = $LastInstall
        RebootPending  = $RebootPending
        Error          = $null
    }
}

# ============================================================ #
#  SCAN EACH SERVER                                            #
# ============================================================ #
foreach ($Server in $Config.Servers) {
    Write-Host "Checking updates on: $Server" -ForegroundColor Cyan

    try {
        $Data = if ($Server -eq "localhost" -or $Server -eq $env:COMPUTERNAME) {
            Invoke-Command -ScriptBlock $CollectScript
        } else {
            Invoke-Command -ComputerName $Server -ScriptBlock $CollectScript -ErrorAction Stop
        }

        if ($Data.Error) {
            Write-Warning "  Error on $Server : $($Data.Error)"
            $ServerStats.Add([PSCustomObject]@{
                Server        = $Server
                Total         = 0
                Critical      = 0
                Important     = 0
                Moderate      = 0
                RebootPending = $false
                LastInstall   = "Unknown"
                Status        = "Error: $($Data.Error)"
            })
            continue
        }

        $CritCount  = ($Data.Updates | Where-Object { $_.Severity -eq 'Critical' }).Count
        $ImpCount   = ($Data.Updates | Where-Object { $_.Severity -eq 'Important' }).Count
        $ModCount   = ($Data.Updates | Where-Object { $_.Severity -like 'Moderate*' -or $_.Severity -eq 'Low' }).Count

        foreach ($upd in $Data.Updates) {
            $AllUpdates.Add([PSCustomObject]@{
                Server         = $Server
                Title          = $upd.Title
                KB             = if ($upd.KB) { "KB$($upd.KB)" } else { "-" }
                Severity       = $upd.Severity
                Category       = $upd.Category
                Size_MB        = $upd.Size_MB
                IsDownloaded   = $upd.IsDownloaded
                RebootRequired = $upd.RebootRequired
            })
        }

        $ServerStats.Add([PSCustomObject]@{
            Server        = $Server
            Total         = $Data.Updates.Count
            Critical      = $CritCount
            Important     = $ImpCount
            Moderate      = $ModCount
            RebootPending = $Data.RebootPending
            LastInstall   = if ($Data.LastInstall) { $Data.LastInstall.ToString("yyyy-MM-dd") } else { "Unknown" }
            Status        = "Scanned"
        })

        Write-Host "  $($Data.Updates.Count) pending ($CritCount critical, $ImpCount important) | Reboot: $($Data.RebootPending)" -ForegroundColor $(if($CritCount -gt 0){'Red'}elseif($Data.Updates.Count -gt 0){'Yellow'}else{'Green'})

    } catch {
        Write-Warning "  Failed to scan $Server : $_"
        $ServerStats.Add([PSCustomObject]@{
            Server        = $Server
            Total         = 0
            Critical      = 0
            Important     = 0
            Moderate      = 0
            RebootPending = $false
            LastInstall   = "Unknown"
            Status        = "Failed: $_"
        })
    }
}

# ============================================================ #
#  TOTALS                                                      #
# ============================================================ #
$TotalPending    = $AllUpdates.Count
$TotalCritical   = ($AllUpdates | Where-Object { $_.Severity -eq 'Critical' }).Count
$TotalImportant  = ($AllUpdates | Where-Object { $_.Severity -eq 'Important' }).Count
$TotalReboots    = ($ServerStats | Where-Object { $_.RebootPending }).Count

$OverallStatus = if ($TotalCritical -gt 0) { "CRITICAL" }
                 elseif ($TotalPending -gt $Config.TotalAlertCount) { "WARNING" }
                 elseif ($TotalPending -gt 0) { "UPDATES AVAILABLE" }
                 else { "UP TO DATE" }

# ============================================================ #
#  BUILD HTML REPORT                                           #
# ============================================================ #
function Get-SeverityBadge {
    param([string]$Sev)
    $color = switch ($Sev) {
        "Critical"  { "#7b241c" }
        "Important" { "#c0392b" }
        "Moderate"  { "#e67e22" }
        "Low"       { "#2e86c1" }
        default     { "#7f8c8d" }
    }
    return "<span style='background:$color;color:white;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:bold;'>$Sev</span>"
}

$ServerRows = ""
foreach ($s in $ServerStats) {
    $rebootBadge = if ($s.RebootPending) {
        "<span style='background:#e67e22;color:white;padding:2px 7px;border-radius:10px;font-size:11px;'>⚠ Pending</span>"
    } else {
        "<span style='background:#1e8449;color:white;padding:2px 7px;border-radius:10px;font-size:11px;'>✔ No</span>"
    }
    $statusBadge = if ($s.Status -eq "Scanned") {
        "<span style='background:#1e8449;color:white;padding:2px 7px;border-radius:10px;font-size:11px;'>✔ OK</span>"
    } else {
        "<span style='background:#c0392b;color:white;padding:2px 7px;border-radius:10px;font-size:11px;'>✘ Error</span>"
    }
    $ServerRows += "<tr>
        <td><strong>$($s.Server)</strong></td>
        <td style='text-align:center;font-weight:bold;'>$($s.Total)</td>
        <td style='text-align:center;color:#7b241c;font-weight:bold;'>$($s.Critical)</td>
        <td style='text-align:center;color:#c0392b;font-weight:bold;'>$($s.Important)</td>
        <td style='text-align:center;color:#e67e22;'>$($s.Moderate)</td>
        <td>$rebootBadge</td>
        <td>$($s.LastInstall)</td>
        <td>$statusBadge</td>
    </tr>"
}

$UpdateRows = ""
$alt = $false
foreach ($u in ($AllUpdates | Sort-Object Severity, Server)) {
    $rowClass = if ($alt) { "background:#fafafa;" } else { "" }
    $sev = Get-SeverityBadge -Sev $u.Severity
    $dlBadge = if ($u.IsDownloaded) { "✔" } else { "—" }
    $rbBadge = if ($u.RebootRequired) { "<span style='color:#e67e22;font-weight:bold;'>Yes</span>" } else { "No" }
    $UpdateRows += "<tr style='$rowClass'>
        <td><strong>$($u.Server)</strong></td>
        <td style='max-width:300px;word-break:break-word;'>$($u.Title)</td>
        <td>$($u.KB)</td>
        <td>$sev</td>
        <td style='font-size:11px;color:#555;'>$($u.Category)</td>
        <td style='text-align:right;'>$($u.Size_MB) MB</td>
        <td style='text-align:center;'>$dlBadge</td>
        <td style='text-align:center;'>$rbBadge</td>
    </tr>"
    $alt = !$alt
}
if ($UpdateRows -eq "") {
    $UpdateRows = "<tr><td colspan='8' style='text-align:center;color:#1e8449;padding:20px;font-weight:bold;'>✅ All servers are up to date!</td></tr>"
}

$HeaderColor = switch ($OverallStatus) {
    "CRITICAL"          { "linear-gradient(135deg,#7b241c,#c0392b)" }
    "WARNING"           { "linear-gradient(135deg,#7d6608,#d4ac0d)" }
    "UPDATES AVAILABLE" { "linear-gradient(135deg,#1a3a5c,#2e86c1)" }
    default             { "linear-gradient(135deg,#1a5e20,#1e8449)" }
}

$AlertBanner = ""
if ($TotalCritical -gt 0) {
    $AlertBanner = "<div style='background:#fdedec;border:1px solid #c0392b;border-radius:8px;padding:14px 18px;margin-bottom:20px;color:#7b241c;font-weight:bold;'>
        🚨 $TotalCritical CRITICAL update(s) pending across your servers — install immediately!</div>"
} elseif ($TotalReboots -gt 0) {
    $AlertBanner = "<div style='background:#fef5e7;border:1px solid #e67e22;border-radius:8px;padding:14px 18px;margin-bottom:20px;color:#7d4e1a;'>
        ⚠️ $TotalReboots server(s) are awaiting a reboot to complete pending updates.</div>"
}

$HTMLBody = @"
<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>
  body { font-family:Segoe UI,Arial,sans-serif; background:#f4f6f9; padding:20px; }
  .container { max-width:1100px; margin:auto; background:white; border-radius:10px; box-shadow:0 4px 15px rgba(0,0,0,.12); overflow:hidden; }
  .header { background:$HeaderColor; color:white; padding:30px; }
  .header h1 { margin:0; font-size:24px; }
  .header p { margin:5px 0 0; opacity:.85; font-size:14px; }
  .header .status { font-size:18px; font-weight:bold; margin-top:8px; }
  .content { padding:25px; }
  .stats { display:flex; gap:15px; margin-bottom:25px; flex-wrap:wrap; }
  .stat-card { flex:1; min-width:130px; border-radius:8px; padding:16px; text-align:center; }
  .stat-card .num { font-size:32px; font-weight:bold; }
  .stat-card .lbl { font-size:12px; margin-top:4px; }
  .card-total  { background:#eaf0fb; border-top:4px solid #2e86c1; }
  .card-crit   { background:#f9ebea; border-top:4px solid #7b241c; color:#7b241c; }
  .card-imp    { background:#fdedec; border-top:4px solid #c0392b; color:#c0392b; }
  .card-reboot { background:#fef5e7; border-top:4px solid #e67e22; color:#7d4e1a; }
  h2 { font-size:16px; color:#2c3e50; border-bottom:2px solid #eee; padding-bottom:8px; margin-top:28px; }
  table { width:100%; border-collapse:collapse; font-size:12px; margin-bottom:20px; }
  th { background:#2c3e50; color:white; padding:9px 10px; text-align:left; }
  td { padding:8px 10px; border-bottom:1px solid #f0f0f0; vertical-align:middle; }
  tr:hover td { background:#f5f8ff; }
  .footer { background:#f4f6f9; padding:15px 25px; font-size:12px; color:#888; border-top:1px solid #e0e0e0; }
</style></head><body>
<div class="container">
  <div class="header">
    <h1>🔄 $($Config.ReportTitle)</h1>
    <p>Servers: <strong>$($Config.Servers -join ', ')</strong> &nbsp;|&nbsp; Generated: $ReportTime</p>
    <div class="status">Status: $OverallStatus</div>
  </div>
  <div class="content">
    $AlertBanner
    <div class="stats">
      <div class="stat-card card-total"><div class="num">$TotalPending</div><div class="lbl">Total Pending</div></div>
      <div class="stat-card card-crit"><div class="num">$TotalCritical</div><div class="lbl">Critical</div></div>
      <div class="stat-card card-imp"><div class="num">$TotalImportant</div><div class="lbl">Important</div></div>
      <div class="stat-card card-reboot"><div class="num">$TotalReboots</div><div class="lbl">Awaiting Reboot</div></div>
    </div>

    <h2>🖥️ Per-Server Summary</h2>
    <table>
      <tr><th>Server</th><th>Total</th><th>Critical</th><th>Important</th><th>Moderate/Low</th><th>Reboot Pending</th><th>Last Installed</th><th>Status</th></tr>
      $ServerRows
    </table>

    <h2>📋 All Pending Updates</h2>
    <table>
      <tr><th>Server</th><th>Update Title</th><th>KB</th><th>Severity</th><th>Category</th><th>Size</th><th>Downloaded</th><th>Reboot</th></tr>
      $UpdateRows
    </table>
  </div>
  <div class="footer">Auto-generated by PowerShell Windows Update Checker &nbsp;|&nbsp; $ReportTime</div>
</div></body></html>
"@

# ============================================================ #
#  SEND EMAIL                                                  #
# ============================================================ #
$Icon    = if ($TotalCritical -gt 0) { "🚨" } elseif ($TotalPending -gt 0) { "⚠️" } else { "✅" }
$Subject = "$Icon Windows Updates | $TotalPending pending ($TotalCritical critical) | $(Get-Date -Format 'yyyy-MM-dd')"

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
$ReportPath = "$($Config.ReportDir)\WindowsUpdates_$(Get-Date -Format 'yyyyMMdd_HHmm').html"
$HTMLBody | Out-File -FilePath $ReportPath -Encoding UTF8
Write-Host "📄 Report saved: $ReportPath" -ForegroundColor Cyan

# ============================================================ #
#  CONSOLE SUMMARY                                             #
# ============================================================ #
Write-Host "`n===== WINDOWS UPDATE SUMMARY =====" -ForegroundColor White
Write-Host "Overall Status : $OverallStatus" -ForegroundColor $(if($TotalCritical -gt 0){'Red'}elseif($TotalPending -gt 0){'Yellow'}else{'Green'})
Write-Host "Total Pending  : $TotalPending"
Write-Host "Critical       : $TotalCritical" -ForegroundColor $(if($TotalCritical -gt 0){'Red'}else{'Green'})
Write-Host "Important      : $TotalImportant"
Write-Host "Reboot Pending : $TotalReboots"  -ForegroundColor $(if($TotalReboots -gt 0){'Yellow'}else{'Green'})
Write-Host "==================================`n" -ForegroundColor White
