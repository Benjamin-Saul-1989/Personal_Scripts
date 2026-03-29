#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Backup Job Verification Reporter
.DESCRIPTION
    Scans Windows Event Logs for backup job results from multiple backup solutions
    (Windows Server Backup, Veeam, Backup Exec, Azure Backup, DPM) and sends
    a formatted HTML email report.
.NOTES
    - Requires administrator privileges
    - Schedule via Task Scheduler for automated daily reporting
    - Covers: Windows Server Backup, Veeam, Veritas Backup Exec, Azure Backup, DPM
#>

# ============================================================ #
#  CONFIGURATION - Edit these values                           #
# ============================================================ #
$Config = @{
    # Email Settings
    SMTPServer    = "smtp.office365.com"        
    SMTPPort      = 587
    UseSSL        = $true
    FromAddress   = ""     # Please submit a ticket, the team: Benjamin, Jason, or Nic, to have an email configured 
    ToAddress     = ""     # If your team, has destrobtion list for alerts send it here. 
    Username      = ""     # Enter from address
    Password      = ""     # See secure password note below

    # Report Settings
    HoursBack    = 24
    ReportTitle  = "Backup Job Verification Report"

    # Backup Solutions to Check (set to $false to skip)
    CheckWSB        = $true
    CheckVeeam      = $true
    CheckBackupExec = $true
    CheckAzure      = $true
    CheckDPM        = $true
}

# ============================================================ #
#  SECURE PASSWORD                                             #
# ============================================================ #
$SecurePass = ConvertTo-SecureString $Config.Password -AsPlainText -Force

# ============================================================ #
#  HELPER FUNCTIONS                                            #
# ============================================================ #
function Get-EventsFromLog {
    param(
        [string]$LogName,
        [int[]]$EventIds,
        [datetime]$StartTime,
        [string]$ProviderName = $null
    )
    try {
        $filter = @{
            LogName   = $LogName
            Id        = $EventIds
            StartTime = $StartTime
        }
        if ($ProviderName) { $filter['ProviderName'] = $ProviderName }

        Get-WinEvent -FilterHashtable $filter -ErrorAction Stop
    } catch {
        if ($_.Exception.Message -notlike "*No events*") {
            Write-Warning "Could not query '$LogName': $_"
        }
        return @()
    }
}

function Test-LogExists {
    param([string]$LogName)
    try {
        Get-WinEvent -ListLog $LogName -ErrorAction Stop | Out-Null
        return $true
    } catch {
        return $false
    }
}

function Get-StatusBadge {
    param([string]$Status)
    switch ($Status) {
        'Success' { return "<span style='background:#1e8449;color:white;padding:3px 10px;border-radius:12px;font-size:12px;font-weight:bold;'>✔ SUCCESS</span>" }
        'Warning' { return "<span style='background:#d68910;color:white;padding:3px 10px;border-radius:12px;font-size:12px;font-weight:bold;'>⚠ WARNING</span>" }
        'Failed'  { return "<span style='background:#c0392b;color:white;padding:3px 10px;border-radius:12px;font-size:12px;font-weight:bold;'>✘ FAILED</span>" }
        'Unknown' { return "<span style='background:#7f8c8d;color:white;padding:3px 10px;border-radius:12px;font-size:12px;font-weight:bold;'>? UNKNOWN</span>" }
        default   { return "<span style='background:#7f8c8d;color:white;padding:3px 10px;border-radius:12px;font-size:12px;font-weight:bold;'>$Status</span>" }
    }
}

# ============================================================ #
#  INITIALIZE RESULTS                                          #
# ============================================================ #
$AllResults = [System.Collections.Generic.List[PSObject]]::new()
$StartTime  = (Get-Date).AddHours(-$Config.HoursBack)
$ServerName = $env:COMPUTERNAME

# ============================================================ #
#  1. WINDOWS SERVER BACKUP (WSB)                              #
# ============================================================ #
if ($Config.CheckWSB) {
    Write-Host "Checking Windows Server Backup..." -ForegroundColor Cyan

    $WSBSuccess = @(4, 14, 520)
    $WSBFailed  = @(5, 19, 521, 546, 561)
    $WSBWarning = @(8, 518)
    $WSBLog     = "Microsoft-Windows-Backup"

    if (Test-LogExists $WSBLog) {
        $WSBEvents = Get-EventsFromLog -LogName $WSBLog -EventIds ($WSBSuccess + $WSBFailed + $WSBWarning) -StartTime $StartTime

        if ($WSBEvents.Count -eq 0) {
            $AllResults.Add([PSCustomObject]@{
                Solution = "Windows Server Backup"
                JobName  = "System Backup"
                Status   = "Unknown"
                Time     = "No events in last $($Config.HoursBack)h"
                Duration = "-"
                Message  = "No backup events found. Backup may not have run."