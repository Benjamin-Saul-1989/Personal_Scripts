#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Uninstall Application from Multiple Machines
.DESCRIPTION
    Remotely uninstalls a specified application from multiple computers
    via PSRemoting, supports MSI GUID and display name matching,
    and emails a full results report.
.NOTES
    - Requires administrator privileges
    - Remote machines need WinRM/PSRemoting enabled
#>

# ============================================================ #
#  CONFIGURATION - Edit these values                           #
# ============================================================ #
$Config = @{
    # Email Settings
    SMTPServer   = "smtp.office365.com"
    SMTPPort     = 587
    UseSSL       = $true
    FromAddress  = "it@yourdomain.com"
    ToAddress    = "admin@yourdomain.com"
    Username     = "it@yourdomain.com"
    Password     = "YourPasswordHere"

    # Uninstall Settings
    ReportTitle  = "Remote Application Uninstall Report"
    ReportDir    = "C:\Reports\Uninstall"

    # Target computers
    TargetComputers = @("server01", "server02", "workstation01")
    # Or load from file: $TargetComputers = Get-Content "C:\scripts\computers.txt"

    # Application to uninstall — use ONE of these methods:
    # Option A: Match by display name (partial match supported)
    AppNamePattern   = "TeamViewer"       # e.g. "Adobe Reader", "7-Zip", "Chrome"

    # Option B: Uninstall by MSI Product GUID (more precise, comment out AppNamePattern)
    # AppGUID        = "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}"

    # Uninstall arguments
    MsiUninstallArgs = "/qn /norestart"   # Silent MSI uninstall
    ExeUninstallArgs = "/S"               # Common silent EXE uninstall flag

    # If $true — only report what WOULD be uninstalled, don't actually uninstall
    WhatIf           = $false
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

$Results    = [System.Collections.Generic.List[PSObject]]::new()
$ReportTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

if ($Config.WhatIf) {
    Write-Host "⚠️  WHATIF MODE — No uninstalls will be performed" -ForegroundColor Yellow
}

# ============================================================ #
#  UNINSTALL SCRIPT BLOCK                                      #
# ============================================================ #
$UninstallScript = {
    param($AppPattern, $AppGUID, $MsiArgs, $ExeArgs, $WhatIf)

    $RegPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    # Find matching apps
    $MatchingApps = foreach ($path in $RegPaths) {
        Get-ItemProperty $path -ErrorAction SilentlyContinue |
        Where-Object {
            $_.DisplayName -ne $null -and (
                ($AppPattern -and $_.DisplayName -like "*$AppPattern*") -or
                ($AppGUID    -and $_.PSChildName -eq $AppGUID)
            )
        } | Select-Object DisplayName, DisplayVersion, Publisher,
                          UninstallString, PSChildName,
                          @{N='Is64Bit';E={ $path -notlike "*Wow6432*" }}
    }

    if ($MatchingApps.Count -eq 0) {
        return @{ Found = $false; Apps = @(); Results = @() }
    }

    $UninstallResults = foreach ($app in $MatchingApps) {
        if ($WhatIf) {
            [PSCustomObject]@{
                AppName    = $app.DisplayName
                Version    = $app.DisplayVersion
                ExitCode   = "WHATIF"
                Status     = "WhatIf"
                Message    = "Would uninstall: $($app.UninstallString)"
            }
            continue
        }

        try {
            $UninstallStr = $app.UninstallString
            $ExitCode     = $null

            # Determine MSI vs EXE
            if ($UninstallStr -match "msiexec" -or $app.PSChildName -match "^\{") {
                # MSI uninstall
                $GUID = if ($app.PSChildName -match "^\{") { $app.PSChildName }
                        else { ($UninstallStr -replace ".*(\{[^}]+\}).*", '$1') }
                $proc = Start-Process "msiexec.exe" -ArgumentList "/x `"$GUID`" $MsiArgs" -Wait -PassThru -NoNewWindow
                $ExitCode = $proc.ExitCode
            } elseif ($UninstallStr -ne $null -and $UninstallStr -ne "") {
                # EXE uninstall
                $ExePath = ($UninstallStr -replace '"', '').Split(' ')[0]
                $ExtraArgs = ($UninstallStr -split ' ', 2)[1]
                $AllArgs   = "$ExtraArgs $ExeArgs".Trim()
                $proc = Start-Process -FilePath $ExePath -ArgumentList $AllArgs -Wait -PassThru -NoNewWindow
                $ExitCode = $proc.ExitCode
            } else {
                throw "No uninstall string found"
            }

            $Success = $ExitCode -in @(0, 3010, 1605)
            $Msg     = if ($ExitCode -eq 0)    { "Uninstalled successfully" }
                       elseif ($ExitCode -eq 3010) { "Uninstalled — reboot required" }
                       elseif ($ExitCode -eq 1605) { "Product not installed (already removed)" }
                       else { "Exit code: $ExitCode" }

            [PSCustomObject]@{
                AppName  = $app.DisplayName
                Version  = $app.DisplayVersion
                ExitCode = $ExitCode
                Status   = if ($Success) { "Success" } else { "Failed" }
                Message  = $Msg
            }

        } catch {
            [PSCustomObject]@{
                AppName  = $app.DisplayName
                Version  = $app.DisplayVersion
                ExitCode = "ERROR"
                Status   = "Failed"
                Message  = $_.ToString()
            }
        }
    }

    return @{ Found = $true; Apps = $MatchingApps; Results = $UninstallResults }
}

# ============================================================ #
#  PROCESS EACH COMPUTER                                       #
# ============================================================ #
foreach ($Computer in $Config.TargetComputers) {
    Write-Host "`n🖥️  Processing: $Computer" -ForegroundColor Cyan

    if (-not (Test-Connection -ComputerName $Computer -Count 1 -Quiet)) {
        Write-Warning "  $Computer is unreachable"
        $Results.Add([PSCustomObject]@{
            Computer = $Computer
            AppName  = "N/A"
            Version  = "N/A"
            Status   = "Unreachable"
            ExitCode = "N/A"
            Message  = "Computer offline or unreachable"
        })
        continue
    }

    try {
        $Output = Invoke-Command `
            -ComputerName $Computer `
            -ScriptBlock $UninstallScript `
            -ArgumentList $Config.AppNamePattern, $Config.AppGUID, $Config.MsiUninstallArgs, $Config.ExeUninstallArgs, $Config.WhatIf `
            -ErrorAction Stop

        if (-not $Output.Found) {
            Write-Host "  ℹ️  Application not found on $Computer" -ForegroundColor Yellow
            $Results.Add([PSCustomObject]@{
                Computer = $Computer
                AppName  = $Config.AppNamePattern ?? $Config.AppGUID
                Version  = "N/A"
                Status   = "Not Found"
                ExitCode = "N/A"
                Message  = "Application not installed on this machine"
            })
        } else {
            foreach ($r in $Output.Results) {
                $color = if ($r.Status -eq 'Success') { "Green" } elseif ($r.Status -eq 'WhatIf') { "Cyan" } else { "Red" }
                Write-Host "  [$($r.Status)] $($r.AppName) v$($r.Version) — $($r.Message)" -ForegroundColor $color

                $Results.Add([PSCustomObject]@{
                    Computer = $Computer
                    AppName  = $r.AppName
                    Version  = $r.Version
                    Status   = $r.Status
                    ExitCode = $r.ExitCode
                    Message  = $r.Message
                })
            }
        }

    } catch {
        Write-Warning "  Failed to connect to $Computer : $_"
        $Results.Add([PSCustomObject]@{
            Computer = $Computer
            AppName  = "N/A"
            Version  = "N/A"
            Status   = "Connection Failed"
            ExitCode = "ERROR"
            Message  = $_.ToString()
        })
    }
}

# ============================================================ #
#  STATISTICS                                                  #
# ============================================================ #
$TotalAttempts = $Results.Count
$Successes     = ($Results | Where-Object { $_.Status -eq 'Success' }).Count
$Failures      = ($Results | Where-Object { $_.Status -eq 'Failed'  }).Count
$NotFound      = ($Results | Where-Object { $_.Status -eq 'Not Found' }).Count
$WhatIfCount   = ($Results | Where-Object { $_.Status -eq 'WhatIf' }).Count

# ============================================================ #
#  BUILD HTML REPORT                                           #
# ============================================================ #
$ResultRows = ""
$alt = $false
foreach ($r in $Results) {
    $rowClass = if ($alt) { "background:#fafafa;" } else { "" }
    $badge = switch ($r.Status) {
        "Success"          { "<span style='background:#1e8449;color:white;padding:2px 9px;border-radius:10px;font-size:12px;font-weight:bold;'>✔ SUCCESS</span>" }
        "Failed"           { "<span style='background:#c0392b;color:white;padding:2px 9px;border-radius:10px;font-size:12px;font-weight:bold;'>✘ FAILED</span>" }
        "Not Found"        { "<span style='background:#7f8c8d;color:white;padding:2px 9px;border-radius:10px;font-size:12px;'>NOT FOUND</span>" }
        "Unreachable"      { "<span style='background:#e67e22;color:white;padding:2px 9px;border-radius:10px;font-size:12px;'>OFFLINE</span>" }
        "WhatIf"           { "<span style='background:#2e86c1;color:white;padding:2px 9px;border-radius:10px;font-size:12px;'>WHATIF</span>" }
        "Connection Failed"{ "<span style='background:#c0392b;color:white;padding:2px 9px;border-radius:10px;font-size:12px;'>CONN FAIL</span>" }
        default            { "<span style='background:#7f8c8d;color:white;padding:2px 9px;border-radius:10px;font-size:12px;'>$($r.Status)</span>" }
    }
    $ResultRows += "<tr style='$rowClass'>
        <td><strong>$($r.Computer)</strong></td>
        <td>$($r.AppName)</td>
        <td>$($r.Version)</td>
        <td>$badge</td>
        <td style='text-align:center;'>$($r.ExitCode)</td>
        <td style='font-size:12px;color:#555;'>$($r.Message)</td>
    </tr>"
    $alt = !$alt
}

$WhatIfBanner = if ($Config.WhatIf) {
    "<div style='background:#eaf4fb;border:1px solid #2e86c1;border-radius:8px;padding:14px 18px;margin-bottom:20px;color:#1a3a5c;font-weight:bold;'>
        ℹ️ WHATIF MODE — This is a preview only. No software was actually uninstalled.</div>"
} else { "" }

$HTMLBody = @"
<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>
  body { font-family:Segoe UI,Arial,sans-serif; background:#f4f6f9; padding:20px; }
  .container { max-width:950px; margin:auto; background:white; border-radius:10px; box-shadow:0 4px 15px rgba(0,0,0,.12); overflow:hidden; }
  .header { background:linear-gradient(135deg,#4a1942,#7d3c98); color:white; padding:30px; }
  .header h1 { margin:0; font-size:24px; }
  .header p { margin:5px 0 0; opacity:.85; font-size:14px; }
  .content { padding:25px; }
  .stats { display:flex; gap:15px; margin-bottom:25px; flex-wrap:wrap; }
  .stat-card { flex:1; min-width:130px; border-radius:8px; padding:16px; text-align:center; }
  .stat-card .num { font-size:32px; font-weight:bold; }
  .stat-card .lbl { font-size:12px; margin-top:4px; }
  .card-blue  { background:#eaf0fb; border-top:4px solid #2e86c1; }
  .card-green { background:#eafaf1; border-top:4px solid #1e8449; color:#1a5e20; }
  .card-red   { background:#fdedec; border-top:4px solid #c0392b; color:#7b241c; }
  .card-gray  { background:#f2f3f4; border-top:4px solid #7f8c8d; }
  h2 { font-size:16px; color:#2c3e50; border-bottom:2px solid #eee; padding-bottom:8px; margin-top:28px; }
  table { width:100%; border-collapse:collapse; font-size:13px; margin-bottom:20px; }
  th { background:#2c3e50; color:white; padding:10px 12px; text-align:left; }
  td { padding:9px 12px; border-bottom:1px solid #f0f0f0; vertical-align:middle; }
  tr:hover td { background:#f5f8ff; }
  .footer { background:#f4f6f9; padding:15px 25px; font-size:12px; color:#888; border-top:1px solid #e0e0e0; }
</style></head><body>
<div class="container">
  <div class="header">
    <h1>🗑️ $($Config.ReportTitle)</h1>
    <p>App: <strong>$($Config.AppNamePattern ?? $Config.AppGUID)</strong> &nbsp;|&nbsp; Targets: $($Config.TargetComputers.Count) computer(s) &nbsp;|&nbsp; $ReportTime</p>
  </div>
  <div class="content">
    $WhatIfBanner
    <div class="stats">
      <div class="stat-card card-blue"><div class="num">$TotalAttempts</div><div class="lbl">Total</div></div>
      <div class="stat-card card-green"><div class="num">$Successes</div><div class="lbl">Uninstalled</div></div>
      <div class="stat-card card-red"><div class="num">$Failures</div><div class="lbl">Failed</div></div>
      <div class="stat-card card-gray"><div class="num">$NotFound</div><div class="lbl">Not Found</div></div>
    </div>

    <h2>📋 Results</h2>
    <table>
      <tr><th>Computer</th><th>Application</th><th>Version</th><th>Status</th><th>Exit Code</th><th>Message</th></tr>
      $ResultRows
    </table>
  </div>
  <div class="footer">Auto-generated by PowerShell Remote Uninstaller &nbsp;|&nbsp; $ReportTime</div>
</div></body></html>
"@

# ============================================================ #
#  SEND EMAIL                                                  #
# ============================================================ #
$Mode    = if ($Config.WhatIf) { "[WHATIF] " } else { "" }
$Icon    = if ($Failures -gt 0) { "⚠️" } else { "✅" }
$AppName = $Config.AppNamePattern ?? $Config.AppGUID
$Subject = "$Icon $($Mode)Uninstall Report: $AppName | $Successes/$TotalAttempts succeeded | $(Get-Date -Format 'yyyy-MM-dd')"

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
$ReportPath = "$($Config.ReportDir)\Uninstall_$(Get-Date -Format 'yyyyMMdd_HHmm').html"
$HTMLBody | Out-File -FilePath $ReportPath -Encoding UTF8
$Results | Export-Csv -Path ($ReportPath -replace '\.html$','.csv') -NoTypeInformation
Write-Host "📄 Report saved: $ReportPath" -ForegroundColor Cyan

# ============================================================ #
#  CONSOLE SUMMARY                                             #
# ============================================================ #
Write-Host "`n===== UNINSTALL SUMMARY =====" -ForegroundColor White
Write-Host "App        : $AppName"
Write-Host "Succeeded  : $Successes" -ForegroundColor Green
Write-Host "Failed     : $Failures"  -ForegroundColor Red
Write-Host "Not Found  : $NotFound"  -ForegroundColor Yellow
Write-Host "============================`n"  -ForegroundColor White
