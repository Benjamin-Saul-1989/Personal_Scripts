#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Remote Software Installation via PowerShell Remoting
.DESCRIPTION
    Deploys software installers (MSI/EXE) to remote servers or workstations
    via PSRemoting, tracks results, and emails a full deployment report.
.NOTES
    - Requires administrator privileges
    - Remote machines need WinRM/PSRemoting enabled
    - Place installers in the SourcePath or use a network share
    - Supports MSI and EXE installers with configurable arguments
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

    # Deployment Settings
    ReportTitle  = "Remote Software Deployment Report"
    ReportDir    = "C:\Reports\Deployment"

    # Source path for installers (UNC share accessible by all targets, or local path)
    SourcePath   = "\\fileserver\software\deploy"

    # Temp folder on remote machines during install
    RemoteTempDir = "C:\Windows\Temp\PSInstall"

    # Target computers (comma separated or load from file)
    TargetComputers = @("server01", "server02")
    # To load from file: Get-Content "C:\deploy\computers.txt"

    # Software to deploy (array of hashtables)
    Software = @(
        @{
            Name        = "7-Zip 23.01"
            Installer   = "7z2301-x64.msi"
            Type        = "MSI"       # MSI or EXE
            Arguments   = "/qn /norestart"
            ExpectedExitCodes = @(0, 3010)   # 3010 = success, reboot required
        }
        # Add more:
        # @{
        #     Name      = "Notepad++ 8.6"
        #     Installer = "npp.8.6.Installer.x64.exe"
        #     Type      = "EXE"
        #     Arguments = "/S"
        #     ExpectedExitCodes = @(0)
        # }
    )
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
$StartTime  = Get-Date

# ============================================================ #
#  VALIDATE SOURCE FILES                                       #
# ============================================================ #
Write-Host "Validating source installers..." -ForegroundColor Cyan
foreach ($sw in $Config.Software) {
    $InstallerPath = Join-Path $Config.SourcePath $sw.Installer
    if (-not (Test-Path $InstallerPath)) {
        Write-Warning "Installer not found: $InstallerPath"
    } else {
        Write-Host "  ✅ Found: $($sw.Installer)" -ForegroundColor Green
    }
}

# ============================================================ #
#  DEPLOY TO EACH COMPUTER                                     #
# ============================================================ #
foreach ($Computer in $Config.TargetComputers) {
    Write-Host "`n🖥️  Deploying to: $Computer" -ForegroundColor Cyan

    # Test connectivity
    if (-not (Test-Connection -ComputerName $Computer -Count 1 -Quiet)) {
        Write-Warning "  $Computer is unreachable — skipping"
        $Results.Add([PSCustomObject]@{
            Computer  = $Computer
            Software  = "N/A"
            Status    = "Failed"
            ExitCode  = "N/A"
            Duration  = "N/A"
            Message   = "Computer unreachable (ping failed)"
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        })
        continue
    }

    foreach ($sw in $Config.Software) {
        $InstallerSource = Join-Path $Config.SourcePath $sw.Installer
        $SwStart         = Get-Date

        Write-Host "  Installing: $($sw.Name)..." -ForegroundColor Yellow

        try {
            $DeployScript = {
                param($SwConfig, $SourceFile, $TempDir)

                # Create temp dir
                if (-not (Test-Path $TempDir)) {
                    New-Item -ItemType Directory -Path $TempDir -Force | Out-Null
                }

                # Copy installer to remote temp dir
                $LocalInstaller = Join-Path $TempDir (Split-Path $SourceFile -Leaf)

                try {
                    Copy-Item -Path $SourceFile -Destination $LocalInstaller -Force -ErrorAction Stop
                } catch {
                    return @{ ExitCode = -1; Message = "Copy failed: $_"; Success = $false }
                }

                # Run installer
                try {
                    if ($SwConfig.Type -eq "MSI") {
                        $Process = Start-Process -FilePath "msiexec.exe" `
                            -ArgumentList "/i `"$LocalInstaller`" $($SwConfig.Arguments)" `
                            -Wait -PassThru -NoNewWindow
                    } else {
                        $Process = Start-Process -FilePath $LocalInstaller `
                            -ArgumentList $SwConfig.Arguments `
                            -Wait -PassThru -NoNewWindow
                    }

                    $ExitCode = $Process.ExitCode
                    $Success  = $ExitCode -in $SwConfig.ExpectedExitCodes

                    $Message = if ($ExitCode -eq 0) { "Installation successful" }
                               elseif ($ExitCode -eq 3010) { "Installation successful — reboot required" }
                               elseif ($ExitCode -eq 1602) { "Installation cancelled by user" }
                               elseif ($ExitCode -eq 1603) { "Fatal error during installation" }
                               elseif ($ExitCode -eq 1618) { "Another installation already in progress" }
                               else { "Completed with exit code: $ExitCode" }

                    return @{ ExitCode = $ExitCode; Message = $Message; Success = $Success }

                } catch {
                    return @{ ExitCode = -2; Message = "Launch failed: $_"; Success = $false }
                } finally {
                    # Cleanup temp file
                    Remove-Item $LocalInstaller -Force -ErrorAction SilentlyContinue
                }
            }

            $DeployResult = Invoke-Command `
                -ComputerName $Computer `
                -ScriptBlock $DeployScript `
                -ArgumentList $sw, $InstallerSource, $Config.RemoteTempDir `
                -ErrorAction Stop

            $Duration = [math]::Round(((Get-Date) - $SwStart).TotalSeconds, 1)
            $Status   = if ($DeployResult.Success) { "Success" } else { "Failed" }
            $ExitCode = $DeployResult.ExitCode
            $Message  = $DeployResult.Message

            $color = if ($Status -eq "Success") { "Green" } else { "Red" }
            Write-Host "  [$Status] $($sw.Name) — Exit: $ExitCode — $Message ($Duration s)" -ForegroundColor $color

        } catch {
            $Duration = [math]::Round(((Get-Date) - $SwStart).TotalSeconds, 1)
            $Status   = "Failed"
            $ExitCode = "ERROR"
            $Message  = $_.ToString()
            Write-Warning "  [Failed] $($sw.Name) — $Message"
        }

        $Results.Add([PSCustomObject]@{
            Computer  = $Computer
            Software  = $sw.Name
            Status    = $Status
            ExitCode  = $ExitCode
            Duration  = "$Duration s"
            Message   = $Message
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        })
    }
}

# ============================================================ #
#  STATISTICS                                                  #
# ============================================================ #
$TotalDeployments = $Results.Count
$Successes        = ($Results | Where-Object { $_.Status -eq 'Success' }).Count
$Failures         = ($Results | Where-Object { $_.Status -eq 'Failed'  }).Count
$TotalDuration    = [math]::Round(((Get-Date) - $StartTime).TotalMinutes, 1)

# ============================================================ #
#  BUILD HTML REPORT                                           #
# ============================================================ #
$ResultRows = ""
$alt = $false
foreach ($r in $Results) {
    $rowClass   = if ($alt) { "background:#fafafa;" } else { "" }
    $badge = if ($r.Status -eq 'Success') {
        "<span style='background:#1e8449;color:white;padding:2px 9px;border-radius:10px;font-size:12px;font-weight:bold;'>✔ SUCCESS</span>"
    } else {
        "<span style='background:#c0392b;color:white;padding:2px 9px;border-radius:10px;font-size:12px;font-weight:bold;'>✘ FAILED</span>"
    }
    $ResultRows += "<tr style='$rowClass'>
        <td><strong>$($r.Computer)</strong></td>
        <td>$($r.Software)</td>
        <td>$badge</td>
        <td style='text-align:center;'>$($r.ExitCode)</td>
        <td style='text-align:center;'>$($r.Duration)</td>
        <td style='font-size:12px;color:#555;'>$($r.Message)</td>
        <td style='font-size:11px;color:#888;'>$($r.Timestamp)</td>
    </tr>"
    $alt = !$alt
}

# Summary by computer
$ComputerRows = ""
$Results | Group-Object Computer | ForEach-Object {
    $cOK   = ($_.Group | Where-Object { $_.Status -eq 'Success' }).Count
    $cFail = ($_.Group | Where-Object { $_.Status -eq 'Failed'  }).Count
    $cStatus = if ($cFail -gt 0) { "#c0392b" } else { "#1e8449" }
    $ComputerRows += "<tr>
        <td><strong>$($_.Name)</strong></td>
        <td style='text-align:center;color:#1e8449;font-weight:bold;'>$cOK</td>
        <td style='text-align:center;color:#c0392b;font-weight:bold;'>$cFail</td>
    </tr>"
}

$HeaderColor = if ($Failures -gt 0) { "linear-gradient(135deg,#7b241c,#c0392b)" } else { "linear-gradient(135deg,#1a5e20,#1e8449)" }

$HTMLBody = @"
<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>
  body { font-family:Segoe UI,Arial,sans-serif; background:#f4f6f9; padding:20px; }
  .container { max-width:1050px; margin:auto; background:white; border-radius:10px; box-shadow:0 4px 15px rgba(0,0,0,.12); overflow:hidden; }
  .header { background:$HeaderColor; color:white; padding:30px; }
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
    <h1>🚀 $($Config.ReportTitle)</h1>
    <p>Targets: <strong>$($Config.TargetComputers -join ', ')</strong> &nbsp;|&nbsp; Duration: $TotalDuration min &nbsp;|&nbsp; $ReportTime</p>
  </div>
  <div class="content">
    <div class="stats">
      <div class="stat-card card-blue"><div class="num">$TotalDeployments</div><div class="lbl">Total Deployments</div></div>
      <div class="stat-card card-green"><div class="num">$Successes</div><div class="lbl">Successful</div></div>
      <div class="stat-card card-red"><div class="num">$Failures</div><div class="lbl">Failed</div></div>
      <div class="stat-card card-gray"><div class="num">$TotalDuration m</div><div class="lbl">Total Duration</div></div>
    </div>

    <h2>🖥️ Results by Computer</h2>
    <table style="max-width:400px;">
      <tr><th>Computer</th><th>Succeeded</th><th>Failed</th></tr>
      $ComputerRows
    </table>

    <h2>📋 Full Deployment Results</h2>
    <table>
      <tr><th>Computer</th><th>Software</th><th>Status</th><th>Exit Code</th><th>Duration</th><th>Message</th><th>Time</th></tr>
      $ResultRows
    </table>
  </div>
  <div class="footer">Auto-generated by PowerShell Remote Software Installer &nbsp;|&nbsp; $ReportTime</div>
</div></body></html>
"@

# ============================================================ #
#  SEND EMAIL                                                  #
# ============================================================ #
$Icon    = if ($Failures -gt 0) { "❌" } else { "✅" }
$Subject = "$Icon Deployment Report | $Successes/$TotalDeployments succeeded | $(Get-Date -Format 'yyyy-MM-dd')"

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
#  SAVE LOCAL REPORT + CSV                                     #
# ============================================================ #
$ReportPath = "$($Config.ReportDir)\Deployment_$(Get-Date -Format 'yyyyMMdd_HHmm').html"
$CSVPath    = "$($Config.ReportDir)\Deployment_$(Get-Date -Format 'yyyyMMdd_HHmm').csv"
$HTMLBody | Out-File -FilePath $ReportPath -Encoding UTF8
$Results | Export-Csv -Path $CSVPath -NoTypeInformation
Write-Host "📄 Report saved: $ReportPath" -ForegroundColor Cyan

# ============================================================ #
#  CONSOLE SUMMARY                                             #
# ============================================================ #
Write-Host "`n===== DEPLOYMENT SUMMARY =====" -ForegroundColor White
Write-Host "Total : $TotalDeployments"
Write-Host "OK    : $Successes" -ForegroundColor Green
Write-Host "Failed: $Failures"  -ForegroundColor Red
Write-Host "Time  : $TotalDuration minutes"
Write-Host "==============================`n" -ForegroundColor White
