#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Log File Archiver and Compressor
.DESCRIPTION
    Scans configured log directories, archives logs older than a threshold
    into date-stamped ZIP files, optionally deletes originals, and emails a report.
.NOTES
    - Requires administrator privileges
    - Uses System.IO.Compression for ZIP (no 7-zip required)
    - Supports multiple directories with individual retention policies
    - Safe: never deletes originals unless archival succeeds
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

    # Archive Settings
    ReportTitle  = "Log File Archiver Report"
    ReportDir    = "C:\Reports\LogArchive"
    ArchiveRoot  = "C:\LogArchives"     # Root folder for all archives
    DeleteAfterArchive = $true          # Delete original files after successful archive
    WhatIf       = $false               # $true = preview only, no changes made

    # Log Sources — each entry is a directory to archive
    LogSources   = @(
        @{
            Name          = "IIS Logs"
            Path          = "C:\inetpub\logs\LogFiles"
            Pattern       = "*.log"
            OlderThanDays = 7
            Recurse       = $true
            ArchiveSubDir = "IIS"
        },
        @{
            Name          = "Windows Event Logs (Archived)"
            Path          = "C:\Windows\System32\winevt\Logs"
            Pattern       = "*.evtx"
            OlderThanDays = 30
            Recurse       = $false
            ArchiveSubDir = "EventLogs"
        },
        @{
            Name          = "Application Logs"
            Path          = "C:\AppLogs"
            Pattern       = "*.log"
            OlderThanDays = 14
            Recurse       = $true
            ArchiveSubDir = "AppLogs"
        }
        # Add more sources as needed:
        # @{
        #     Name          = "SQL Server Logs"
        #     Path          = "C:\Program Files\Microsoft SQL Server\MSSQL\Log"
        #     Pattern       = "*.txt"
        #     OlderThanDays = 30
        #     Recurse       = $false
        #     ArchiveSubDir = "SQLLogs"
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
Add-Type -AssemblyName System.IO.Compression.FileSystem

if (-not (Test-Path $Config.ReportDir)) {
    New-Item -ItemType Directory -Path $Config.ReportDir | Out-Null
}
if (-not (Test-Path $Config.ArchiveRoot)) {
    New-Item -ItemType Directory -Path $Config.ArchiveRoot | Out-Null
}

$ReportTime  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$DateStamp   = Get-Date -Format "yyyyMMdd"
$AllResults  = [System.Collections.Generic.List[PSObject]]::new()
$TotalArchived = 0
$TotalDeleted  = 0
$TotalErrors   = 0
$TotalSavedMB  = 0

if ($Config.WhatIf) {
    Write-Host "⚠️  WHATIF MODE — No files will be moved or deleted" -ForegroundColor Yellow
}

# ============================================================ #
#  HELPER: HUMAN READABLE SIZE                                 #
# ============================================================ #
function Format-FileSize {
    param([long]$Bytes)
    if ($Bytes -ge 1GB) { return "$([math]::Round($Bytes/1GB, 2)) GB" }
    if ($Bytes -ge 1MB) { return "$([math]::Round($Bytes/1MB, 2)) MB" }
    if ($Bytes -ge 1KB) { return "$([math]::Round($Bytes/1KB, 1)) KB" }
    return "$Bytes B"
}

# ============================================================ #
#  PROCESS EACH LOG SOURCE                                     #
# ============================================================ #
foreach ($Source in $Config.LogSources) {
    Write-Host "`n📁 Processing: $($Source.Name)" -ForegroundColor Cyan
    Write-Host "   Path: $($Source.Path) | Pattern: $($Source.Pattern) | Older than: $($Source.OlderThanDays) days"

    if (-not (Test-Path $Source.Path)) {
        Write-Warning "   Path not found, skipping: $($Source.Path)"
        $AllResults.Add([PSCustomObject]@{
            Source       = $Source.Name
            ArchivePath  = "N/A"
            FilesFound   = 0
            FilesArchived= 0
            FilesDeleted = 0
            OriginalSize = "N/A"
            ArchiveSize  = "N/A"
            Savings      = "N/A"
            Status       = "Path Not Found"
            Errors       = "Directory does not exist: $($Source.Path)"
        })
        $TotalErrors++
        continue
    }

    # Find eligible files
    $CutoffDate = (Get-Date).AddDays(-$Source.OlderThanDays)
    $GCIParams  = @{
        Path    = $Source.Path
        Filter  = $Source.Pattern
        File    = $true
        Recurse = $Source.Recurse
        ErrorAction = "SilentlyContinue"
    }
    $EligibleFiles = Get-ChildItem @GCIParams | Where-Object { $_.LastWriteTime -lt $CutoffDate }

    if ($EligibleFiles.Count -eq 0) {
        Write-Host "   No eligible files found" -ForegroundColor Gray
        $AllResults.Add([PSCustomObject]@{
            Source        = $Source.Name
            ArchivePath   = "N/A"
            FilesFound    = 0
            FilesArchived = 0
            FilesDeleted  = 0
            OriginalSize  = "0 B"
            ArchiveSize   = "0 B"
            Savings       = "0%"
            Status        = "No Files"
            Errors        = ""
        })
        continue
    }

    $OriginalBytes = ($EligibleFiles | Measure-Object -Property Length -Sum).Sum
    Write-Host "   Found $($EligibleFiles.Count) files ($(Format-FileSize $OriginalBytes))" -ForegroundColor Yellow

    if ($Config.WhatIf) {
        Write-Host "   [WHATIF] Would archive $($EligibleFiles.Count) files" -ForegroundColor Cyan
        $AllResults.Add([PSCustomObject]@{
            Source        = $Source.Name
            ArchivePath   = "WHATIF"
            FilesFound    = $EligibleFiles.Count
            FilesArchived = $EligibleFiles.Count
            FilesDeleted  = if ($Config.DeleteAfterArchive) { $EligibleFiles.Count } else { 0 }
            OriginalSize  = Format-FileSize $OriginalBytes
            ArchiveSize   = "WHATIF"
            Savings       = "WHATIF"
            Status        = "WhatIf"
            Errors        = ""
        })
        continue
    }

    # ── Create Archive ─────────────────────────────────────────
    $ArchiveDir  = Join-Path $Config.ArchiveRoot $Source.ArchiveSubDir
    if (-not (Test-Path $ArchiveDir)) { New-Item -ItemType Directory -Path $ArchiveDir | Out-Null }

    $ArchiveName = "$($Source.ArchiveSubDir)_$DateStamp.zip"
    $ArchivePath = Join-Path $ArchiveDir $ArchiveName
    $Counter     = 1
    while (Test-Path $ArchivePath) {
        $ArchiveName = "$($Source.ArchiveSubDir)_${DateStamp}_$Counter.zip"
        $ArchivePath = Join-Path $ArchiveDir $ArchiveName
        $Counter++
    }

    $FilesArchived = 0
    $FilesDeleted  = 0
    $Errors        = @()

    try {
        $ZipStream = [System.IO.File]::Open($ArchivePath, [System.IO.FileMode]::Create)
        $Archive   = New-Object System.IO.Compression.ZipArchive($ZipStream, [System.IO.Compression.ZipArchiveMode]::Create)

        foreach ($File in $EligibleFiles) {
            try {
                $EntryName = $File.FullName.Substring($Source.Path.Length).TrimStart('\','/')
                $Entry     = $Archive.CreateEntry($EntryName, [System.IO.Compression.CompressionLevel]::Optimal)
                $EntStream = $Entry.Open()
                $FileStream = [System.IO.File]::OpenRead($File.FullName)
                $FileStream.CopyTo($EntStream)
                $FileStream.Close()
                $EntStream.Close()
                $FilesArchived++
            } catch {
                $Errors += "Archive error: $($File.Name): $_"
            }
        }

        $Archive.Dispose()
        $ZipStream.Close()

        $ArchiveBytes = (Get-Item $ArchivePath).Length
        $Savings      = if ($OriginalBytes -gt 0) { "$([math]::Round((1 - $ArchiveBytes/$OriginalBytes)*100, 1))%" } else { "0%" }

        Write-Host "   ✅ Archived $FilesArchived files → $ArchiveName ($(Format-FileSize $ArchiveBytes), saved $Savings)" -ForegroundColor Green
        $TotalArchived += $FilesArchived
        $TotalSavedMB  += [math]::Round(($OriginalBytes - $ArchiveBytes) / 1MB, 2)

        # ── Delete Originals ───────────────────────────────────
        if ($Config.DeleteAfterArchive -and $FilesArchived -gt 0) {
            foreach ($File in $EligibleFiles) {
                try {
                    Remove-Item $File.FullName -Force -ErrorAction Stop
                    $FilesDeleted++
                } catch {
                    $Errors += "Delete error: $($File.Name): $_"
                }
            }
            Write-Host "   🗑️  Deleted $FilesDeleted original files" -ForegroundColor Green
            $TotalDeleted += $FilesDeleted
        }

        $AllResults.Add([PSCustomObject]@{
            Source        = $Source.Name
            ArchivePath   = $ArchivePath
            FilesFound    = $EligibleFiles.Count
            FilesArchived = $FilesArchived
            FilesDeleted  = $FilesDeleted
            OriginalSize  = Format-FileSize $OriginalBytes
            ArchiveSize   = Format-FileSize $ArchiveBytes
            Savings       = $Savings
            Status        = if ($Errors.Count -eq 0) { "Success" } else { "Partial" }
            Errors        = $Errors -join "; "
        })

    } catch {
        $TotalErrors++
        Write-Warning "   ❌ Archive failed: $_"
        $AllResults.Add([PSCustomObject]@{
            Source        = $Source.Name
            ArchivePath   = "FAILED"
            FilesFound    = $EligibleFiles.Count
            FilesArchived = 0
            FilesDeleted  = 0
            OriginalSize  = Format-FileSize $OriginalBytes
            ArchiveSize   = "N/A"
            Savings       = "N/A"
            Status        = "Failed"
            Errors        = $_.ToString()
        })
    }
}

# ============================================================ #
#  BUILD HTML REPORT                                           #
# ============================================================ #
$SuccessCount = ($AllResults | Where-Object { $_.Status -eq 'Success' }).Count
$FailCount    = ($AllResults | Where-Object { $_.Status -eq 'Failed'  }).Count

$ResultRows = ""
$alt = $false
foreach ($r in $AllResults) {
    $rowClass = if ($alt) { "background:#fafafa;" } else { "" }
    $badge = switch ($r.Status) {
        "Success"  { "<span style='background:#1e8449;color:white;padding:2px 9px;border-radius:10px;font-size:12px;font-weight:bold;'>✔ Success</span>" }
        "Partial"  { "<span style='background:#e67e22;color:white;padding:2px 9px;border-radius:10px;font-size:12px;font-weight:bold;'>⚠ Partial</span>" }
        "Failed"   { "<span style='background:#c0392b;color:white;padding:2px 9px;border-radius:10px;font-size:12px;font-weight:bold;'>✘ Failed</span>" }
        "WhatIf"   { "<span style='background:#2e86c1;color:white;padding:2px 9px;border-radius:10px;font-size:12px;'>Preview</span>" }
        "No Files" { "<span style='background:#7f8c8d;color:white;padding:2px 9px;border-radius:10px;font-size:12px;'>No Files</span>" }
        default    { "<span style='background:#7f8c8d;color:white;padding:2px 9px;border-radius:10px;font-size:12px;'>$($r.Status)</span>" }
    }
    $archiveDisplay = if ($r.ArchivePath -ne "N/A" -and $r.ArchivePath -ne "FAILED" -and $r.ArchivePath -ne "WHATIF") {
        "<span style='font-size:11px;color:#555;'>$(Split-Path $r.ArchivePath -Leaf)</span>"
    } else { $r.ArchivePath }

    $ResultRows += "<tr style='$rowClass'>
        <td><strong>$($r.Source)</strong></td>
        <td style='text-align:center;'>$($r.FilesFound)</td>
        <td style='text-align:center;'>$($r.FilesArchived)</td>
        <td style='text-align:center;'>$($r.FilesDeleted)</td>
        <td>$($r.OriginalSize)</td>
        <td>$($r.ArchiveSize)</td>
        <td><strong style='color:#1e8449;'>$($r.Savings)</strong></td>
        <td>$badge</td>
        <td>$archiveDisplay</td>
    </tr>"
    $alt = !$alt
}

$WhatIfBanner = if ($Config.WhatIf) {
    "<div style='background:#eaf4fb;border:1px solid #2e86c1;border-radius:8px;padding:14px 18px;margin-bottom:20px;color:#1a3a5c;font-weight:bold;'>
        ℹ️ WHATIF MODE — This is a preview only. No files were archived or deleted.</div>"
} else { "" }

$HTMLBody = @"
<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>
  body { font-family:Segoe UI,Arial,sans-serif; background:#f4f6f9; padding:20px; }
  .container { max-width:1100px; margin:auto; background:white; border-radius:10px; box-shadow:0 4px 15px rgba(0,0,0,.12); overflow:hidden; }
  .header { background:linear-gradient(135deg,#1c3a4a,#1e6091); color:white; padding:30px; }
  .header h1 { margin:0; font-size:24px; }
  .header p { margin:5px 0 0; opacity:.85; font-size:14px; }
  .content { padding:25px; }
  .stats { display:flex; gap:15px; margin-bottom:25px; flex-wrap:wrap; }
  .stat-card { flex:1; min-width:130px; border-radius:8px; padding:16px; text-align:center; }
  .stat-card .num { font-size:32px; font-weight:bold; }
  .stat-card .lbl { font-size:12px; margin-top:4px; }
  .card-blue   { background:#eaf4fb; border-top:4px solid #2e86c1; }
  .card-green  { background:#eafaf1; border-top:4px solid #1e8449; color:#1a5e20; }
  .card-orange { background:#fef5e7; border-top:4px solid #e67e22; color:#7d4e1a; }
  .card-purple { background:#f4ecf7; border-top:4px solid #8e44ad; color:#5b2c6f; }
  h2 { font-size:16px; color:#2c3e50; border-bottom:2px solid #eee; padding-bottom:8px; margin-top:28px; }
  table { width:100%; border-collapse:collapse; font-size:12px; }
  th { background:#2c3e50; color:white; padding:10px 12px; text-align:left; }
  td { padding:9px 12px; border-bottom:1px solid #f0f0f0; vertical-align:middle; }
  tr:hover td { background:#f5f8ff; }
  .footer { background:#f4f6f9; padding:15px 25px; font-size:12px; color:#888; border-top:1px solid #e0e0e0; }
</style></head><body>
<div class="container">
  <div class="header">
    <h1>🗜️ $($Config.ReportTitle)</h1>
    <p>Server: <strong>$env:COMPUTERNAME</strong> &nbsp;|&nbsp; Archive Root: $($Config.ArchiveRoot) &nbsp;|&nbsp; $ReportTime</p>
  </div>
  <div class="content">
    $WhatIfBanner
    <div class="stats">
      <div class="stat-card card-blue"><div class="num">$($AllResults.Count)</div><div class="lbl">Sources Processed</div></div>
      <div class="stat-card card-green"><div class="num">$TotalArchived</div><div class="lbl">Files Archived</div></div>
      <div class="stat-card card-orange"><div class="num">$TotalDeleted</div><div class="lbl">Files Deleted</div></div>
      <div class="stat-card card-purple"><div class="num">$TotalSavedMB MB</div><div class="lbl">Space Saved</div></div>
    </div>

    <h2>📦 Archive Results</h2>
    <table>
      <tr><th>Source</th><th>Found</th><th>Archived</th><th>Deleted</th><th>Original Size</th><th>Archive Size</th><th>Savings</th><th>Status</th><th>Archive File</th></tr>
      $ResultRows
    </table>
  </div>
  <div class="footer">Auto-generated by PowerShell Log Archiver &nbsp;|&nbsp; $ReportTime</div>
</div></body></html>
"@

# ============================================================ #
#  SEND EMAIL                                                  #
# ============================================================ #
$Icon    = if ($FailCount -gt 0) { "⚠️" } else { "✅" }
$Mode    = if ($Config.WhatIf) { "[WHATIF] " } else { "" }
$Subject = "$Icon $($Mode)Log Archive | $TotalArchived files archived, $TotalSavedMB MB saved | $(Get-Date -Format 'yyyy-MM-dd')"

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
$ReportPath = "$($Config.ReportDir)\LogArchive_$(Get-Date -Format 'yyyyMMdd_HHmm').html"
$HTMLBody | Out-File -FilePath $ReportPath -Encoding UTF8
Write-Host "📄 Report saved: $ReportPath" -ForegroundColor Cyan

# ============================================================ #
#  CONSOLE SUMMARY                                             #
# ============================================================ #
Write-Host "`n===== LOG ARCHIVE SUMMARY =====" -ForegroundColor White
Write-Host "Sources Processed : $($AllResults.Count)"
Write-Host "Files Archived    : $TotalArchived"  -ForegroundColor Green
Write-Host "Files Deleted     : $TotalDeleted"   -ForegroundColor Yellow
Write-Host "Space Saved       : $TotalSavedMB MB" -ForegroundColor Cyan
Write-Host "Errors            : $TotalErrors"    -ForegroundColor $(if($TotalErrors -gt 0){'Red'}else{'Green'})
Write-Host "==============================`n"     -ForegroundColor White
