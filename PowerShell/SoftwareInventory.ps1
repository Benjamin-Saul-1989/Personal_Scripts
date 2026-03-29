#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installed Software Inventory Across Servers
.DESCRIPTION
    Collects installed software from local and remote servers via registry
    and WMI, then emails a consolidated HTML report with CSV export.
.NOTES
    - Requires administrator privileges
    - Remote servers need WinRM/PSRemoting enabled
    - Checks both 32-bit and 64-bit registry hives
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

    ReportTitle  = "Installed Software Inventory"
    ReportDir    = "C:\Reports\SoftwareInventory"

    # Filter Options
    ExcludePatterns = @("Microsoft Visual C++", "Microsoft .NET", "Windows SDK")  # Omit noise
    HighlightSoftware = @("TeamViewer","AnyDesk","Chrome","Firefox","7-Zip","Notepad++","VLC")
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

$AllSoftware = [System.Collections.Generic.List[PSObject]]::new()
$ReportTime  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# ============================================================ #
#  SOFTWARE COLLECTION SCRIPT                                  #
# ============================================================ #
$CollectScript = {
    $RegPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    $Software = foreach ($path in $RegPaths) {
        try {
            Get-ItemProperty $path -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -ne $null -and $_.DisplayName -ne "" } |
            Select-Object `
                @{N='Name';       E={ $_.DisplayName }},
                @{N='Version';    E={ $_.DisplayVersion }},
                @{N='Publisher';  E={ $_.Publisher }},
                @{N='InstallDate';E={ $_.InstallDate }},
                @{N='InstallLocation'; E={ $_.InstallLocation }},
                @{N='Size_MB';    E={ if($_.EstimatedSize){ [math]::Round($_.EstimatedSize/1024,1) } else { $null } }},
                @{N='Arch';       E={ if($path -like "*Wow6432*"){'32-bit'}else{'64-bit'} }}
        } catch { }
    }

    return $Software | Sort-Object Name -Unique
}

# ============================================================ #
#  SCAN EACH SERVER                                            #
# ============================================================ #
foreach ($Server in $Config.Servers) {
    Write-Host "Collecting software inventory from: $Server" -ForegroundColor Cyan

    try {
        $Software = if ($Server -eq "localhost" -or $Server -eq $env:COMPUTERNAME) {
            Invoke-Command -ScriptBlock $CollectScript
        } else {
            Invoke-Command -ComputerName $Server -ScriptBlock $CollectScript -ErrorAction Stop
        }

        $Filtered = $Software | Where-Object {
            $name = $_.Name
            -not ($Config.ExcludePatterns | Where-Object { $name -like "*$_*" })
        }

        foreach ($app in $Filtered) {
            $AllSoftware.Add([PSCustomObject]@{
                Server       = $Server
                Name         = $app.Name
                Version      = $app.Version
                Publisher    = $app.Publisher
                InstallDate  = $app.InstallDate
                Size_MB      = $app.Size_MB
                Arch         = $app.Arch
                Highlighted  = ($Config.HighlightSoftware | Where-Object { $app.Name -like "*$_*" }).Count -gt 0
            })
        }

        Write-Host "  Found $($Filtered.Count) applications" -ForegroundColor Green

    } catch {
        Write-Warning "  Failed to collect from $Server : $_"
        $AllSoftware.Add([PSCustomObject]@{
            Server      = $Server
            Name        = "ERROR: Could not connect"
            Version     = ""
            Publisher   = ""
            InstallDate = ""
            Size_MB     = $null
            Arch        = ""
            Highlighted = $false
        })
    }
}

# ============================================================ #
#  STATISTICS                                                  #
# ============================================================ #
$TotalApps       = $AllSoftware.Count
$UniqueApps      = ($AllSoftware | Select-Object -ExpandProperty Name -Unique).Count
$UniquePublishers= ($AllSoftware | Where-Object { $_.Publisher } | Select-Object -ExpandProperty Publisher -Unique).Count
$HighlightedApps = ($AllSoftware | Where-Object { $_.Highlighted })

# Top publishers
$TopPublishers = $AllSoftware | Where-Object { $_.Publisher } |
    Group-Object Publisher | Sort-Object Count -Descending | Select-Object -First 10

# ============================================================ #
#  BUILD HTML REPORT                                           #
# ============================================================ #
$SoftwareRows = ""
$alt = $false
foreach ($app in ($AllSoftware | Sort-Object Server, Name)) {
    $rowClass   = if ($alt) { "background:#fafafa;" } else { "" }
    $hlStyle    = if ($app.Highlighted) { "border-left:4px solid #2e86c1;" } else { "" }
    $sizeText   = if ($app.Size_MB) { "$($app.Size_MB) MB" } else { "-" }
    $dateText   = if ($app.InstallDate) { $app.InstallDate } else { "-" }
    $archBadge  = if ($app.Arch -eq "32-bit") {
        "<span style='background:#7f8c8d;color:white;padding:1px 6px;border-radius:8px;font-size:10px;'>32</span>"
    } else {
        "<span style='background:#2e86c1;color:white;padding:1px 6px;border-radius:8px;font-size:10px;'>64</span>"
    }

    $SoftwareRows += "<tr style='$rowClass$hlStyle'>
        <td><strong>$($app.Server)</strong></td>
        <td>$($app.Name)</td>
        <td style='font-size:12px;color:#555;'>$($app.Version)</td>
        <td style='font-size:12px;color:#555;'>$($app.Publisher)</td>
        <td style='text-align:center;'>$archBadge</td>
        <td style='text-align:right;font-size:12px;'>$sizeText</td>
        <td style='font-size:12px;color:#888;'>$dateText</td>
    </tr>"
    $alt = !$alt
}

$PublisherRows = ""
foreach ($p in $TopPublishers) {
    $PublisherRows += "<tr><td>$($p.Name)</td><td style='text-align:center;font-weight:bold;'>$($p.Count)</td></tr>"
}

$HighlightRows = ""
if ($HighlightedApps.Count -gt 0) {
    foreach ($h in $HighlightedApps) {
        $HighlightRows += "<tr><td><strong>$($h.Server)</strong></td><td>$($h.Name)</td><td>$($h.Version)</td><td>$($h.Publisher)</td></tr>"
    }
} else {
    $HighlightRows = "<tr><td colspan='4' style='text-align:center;color:#888;'>None of the highlighted apps were found.</td></tr>"
}

$HTMLBody = @"
<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>
  body { font-family:Segoe UI,Arial,sans-serif; background:#f4f6f9; padding:20px; }
  .container { max-width:1150px; margin:auto; background:white; border-radius:10px; box-shadow:0 4px 15px rgba(0,0,0,.12); overflow:hidden; }
  .header { background:linear-gradient(135deg,#1a3a5c,#1e5f8a); color:white; padding:30px; }
  .header h1 { margin:0; font-size:24px; }
  .header p { margin:5px 0 0; opacity:.85; font-size:14px; }
  .content { padding:25px; }
  .stats { display:flex; gap:15px; margin-bottom:25px; flex-wrap:wrap; }
  .stat-card { flex:1; min-width:130px; border-radius:8px; padding:16px; text-align:center; }
  .stat-card .num { font-size:32px; font-weight:bold; }
  .stat-card .lbl { font-size:12px; margin-top:4px; }
  .card-blue   { background:#eaf4fb; border-top:4px solid #2e86c1; }
  .card-green  { background:#eafaf1; border-top:4px solid #1e8449; color:#1a5e20; }
  .card-purple { background:#f4ecf7; border-top:4px solid #8e44ad; color:#5b2c6f; }
  .card-orange { background:#fef5e7; border-top:4px solid #e67e22; color:#7d4e1a; }
  h2 { font-size:16px; color:#2c3e50; border-bottom:2px solid #eee; padding-bottom:8px; margin-top:28px; }
  table { width:100%; border-collapse:collapse; font-size:12px; margin-bottom:20px; }
  th { background:#2c3e50; color:white; padding:9px 10px; text-align:left; }
  td { padding:8px 10px; border-bottom:1px solid #f0f0f0; vertical-align:middle; }
  tr:hover td { background:#f5f8ff; }
  .two-col { display:grid; grid-template-columns:2fr 1fr; gap:20px; }
  .footer { background:#f4f6f9; padding:15px 25px; font-size:12px; color:#888; border-top:1px solid #e0e0e0; }
</style></head><body>
<div class="container">
  <div class="header">
    <h1>📦 $($Config.ReportTitle)</h1>
    <p>Servers: <strong>$($Config.Servers -join ', ')</strong> &nbsp;|&nbsp; Generated: $ReportTime</p>
  </div>
  <div class="content">
    <div class="stats">
      <div class="stat-card card-blue"><div class="num">$TotalApps</div><div class="lbl">Total Installations</div></div>
      <div class="stat-card card-green"><div class="num">$UniqueApps</div><div class="lbl">Unique Applications</div></div>
      <div class="stat-card card-purple"><div class="num">$UniquePublishers</div><div class="lbl">Publishers</div></div>
      <div class="stat-card card-orange"><div class="num">$($HighlightedApps.Count)</div><div class="lbl">Highlighted Apps</div></div>
    </div>

    <h2>⭐ Highlighted Applications</h2>
    <table>
      <tr><th>Server</th><th>Application</th><th>Version</th><th>Publisher</th></tr>
      $HighlightRows
    </table>

    <h2>🏢 Top Publishers by App Count</h2>
    <table style="max-width:400px;">
      <tr><th>Publisher</th><th>Apps</th></tr>
      $PublisherRows
    </table>

    <h2>📋 Full Software Inventory</h2>
    <table>
      <tr><th>Server</th><th>Application</th><th>Version</th><th>Publisher</th><th>Arch</th><th>Size</th><th>Install Date</th></tr>
      $SoftwareRows
    </table>
  </div>
  <div class="footer">Auto-generated by PowerShell Software Inventory &nbsp;|&nbsp; $ReportTime</div>
</div></body></html>
"@

# ============================================================ #
#  EXPORT CSV                                                  #
# ============================================================ #
$CSVPath = "$($Config.ReportDir)\SoftwareInventory_$(Get-Date -Format 'yyyyMMdd_HHmm').csv"
$AllSoftware | Select-Object Server,Name,Version,Publisher,Arch,Size_MB,InstallDate |
    Export-Csv -Path $CSVPath -NoTypeInformation
Write-Host "📊 CSV exported: $CSVPath" -ForegroundColor Cyan

# ============================================================ #
#  SEND EMAIL                                                  #
# ============================================================ #
$Subject = "Software Inventory | $TotalApps apps across $($Config.Servers.Count) server(s) | $(Get-Date -Format 'yyyy-MM-dd')"

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
    Attachments = $CSVPath
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
$ReportPath = "$($Config.ReportDir)\SoftwareInventory_$(Get-Date -Format 'yyyyMMdd_HHmm').html"
$HTMLBody | Out-File -FilePath $ReportPath -Encoding UTF8
Write-Host "📄 Report saved: $ReportPath" -ForegroundColor Cyan

# ============================================================ #
#  CONSOLE SUMMARY                                             #
# ============================================================ #
Write-Host "`n===== SOFTWARE INVENTORY SUMMARY =====" -ForegroundColor White
Write-Host "Total Installations : $TotalApps"
Write-Host "Unique Applications : $UniqueApps"
Write-Host "Publishers          : $UniquePublishers"
Write-Host "Highlighted Apps    : $($HighlightedApps.Count)" -ForegroundColor Yellow
Write-Host "======================================`n"         -ForegroundColor White
