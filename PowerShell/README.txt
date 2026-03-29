# Windows Server PowerShell Admin Scripts
# ==========================================
# 15-script bundle for Windows Server administration
# All scripts require PowerShell 5.1+ and administrator privileges

## SCRIPTS INCLUDED

| # | Script | Purpose |
|---|--------|---------|
| 01 | PasswordExpiryNotifier    | Emails users before their AD password expires |
| 02 | GroupMembershipAuditor    | Audits AD group changes, flags high-privilege groups |
| 03 | NewEmployeeOnboarding     | Creates AD account, assigns groups, sets up home drive |
| 04 | EmployeeOffboarding       | Disables account, moves OU, removes groups, revokes licenses |
| 05 | OpenFirewallRuleScanner   | Scans for risky/overly permissive firewall rules |
| 06 | RDPAccessAuditor          | Audits who has RDP access on each server |
| 07 | SoftwareInventory         | Collects installed software across servers |
| 08 | PendingWindowsUpdates     | Checks pending updates and severity across servers |
| 09 | RemoteSoftwareInstall     | Deploys MSI/EXE installers via PSRemoting |
| 10 | RemoteUninstall           | Uninstalls an app from multiple machines |
| 11 | PingSweep                 | Multi-threaded ping sweep with change detection |
| 12 | PortScanner               | TCP port scanner with unexpected port flagging |
| 13 | DuplicateIPDetector       | Finds duplicate IPs/MACs via ARP scanning |
| 14 | LogFileArchiver           | Archives and compresses old log files to ZIP |
| 15 | ChangeLogTracker          | Tracks admin changes via Windows Security Event Log |

## QUICK SETUP

1. Open each script in PowerShell ISE or VS Code
2. Edit the $Config block at the top of each script
3. Set your SMTP server, email addresses, and any paths
4. Run as Administrator

## COMMON REQUIREMENTS

- PowerShell 5.1 or higher
- Run as Administrator (most scripts)
- RSAT / Active Directory module (scripts 01-04)
- WinRM/PSRemoting enabled on remote targets (scripts 05-10)
- SMTP relay or Office 365 credentials for email reports

## HEADER STYLE

All scripts use the standard section header format:

    # ============================================================ #
    #  SECTION TITLE HERE                                          #
    # ============================================================ #

## SCHEDULING (Task Scheduler)

Recommended schedules:
- 01 PasswordExpiry   : Daily at 7:00 AM
- 02 GroupAudit       : Daily at 6:00 AM
- 05 FirewallScan     : Weekly
- 06 RDPAudit         : Weekly
- 07 SoftwareInventory: Weekly
- 08 WindowsUpdates   : Daily at 6:00 AM
- 11 PingSweep        : Hourly or Daily
- 12 PortScanner      : Weekly
- 13 DuplicateIP      : Daily
- 14 LogArchiver      : Weekly
- 15 ChangeLog        : Hourly or Daily

## NOTES

- All scripts save local HTML reports to C:\Reports\[Category]\ by default
- Change $Config.ReportDir in each script to customize report location
- Scripts with WhatIf mode ($Config.WhatIf = $true) preview without making changes
- Scripts 11-13 use RunspacePool threading for high performance
