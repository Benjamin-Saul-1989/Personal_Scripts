#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Employee Offboarding Automation
.DESCRIPTION
    Automates employee offboarding: disables AD account, resets password,
    removes group memberships, moves to disabled OU, revokes O365 licenses,
    and sends confirmation report.
.NOTES
    - Requires AD PowerShell module (RSAT)
    - Optional: MSOnline or AzureAD module for O365 license revocation
    - Run as Domain Admin or delegated account
#>

# ============================================================ #
#  CONFIGURATION - Edit these values                           #
# ============================================================ #
$Config = @{
    # Email Settings
    SMTPServer     = "smtp.office365.com"
    SMTPPort       = 587
    UseSSL         = $true
    FromAddress    = "it@yourdomain.com"
    Username       = "it@yourdomain.com"
    Password       = "YourPasswordHere"
    AdminEmail     = "admin@yourdomain.com"
    HREmail        = "hr@yourdomain.com"

    # AD Settings
    DisabledOU     = "OU=Disabled Users,DC=yourdomain,DC=com"
    ArchiveOU      = "OU=Archived,OU=Disabled Users,DC=yourdomain,DC=com"

    # Offboarding Actions (set $false to skip)
    DisableAccount      = $true
    ResetPassword       = $true
    RemoveGroups        = $true
    MoveToDisabledOU    = $true
    HideFromGAL         = $true
    RevokeO365License   = $false   # Requires MSOnline module
    DisableO365Account  = $false   # Requires MSOnline module
    ClearManager        = $true
    SetDescription      = $true    # Stamps disable date and reason in description

    # Report
    ReportDir      = "C:\Reports\Offboarding"

    # Groups to NEVER remove (e.g. required for mail flow)
    PreserveGroups = @("Domain Users")
}

# ============================================================ #
#  SECURE PASSWORD                                             #
# ============================================================ #
$SecurePass = ConvertTo-SecureString $Config.Password -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential($Config.Username, $SecurePass)

# ============================================================ #
#  HELPER FUNCTIONS                                            #
# ============================================================ #
function New-RandomPassword {
    $chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$%".ToCharArray()
    return -join ($chars | Get-Random -Count 20)
}

# ============================================================ #
#  LOAD AD MODULE                                              #
# ============================================================ #
try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Error "Active Directory module not found."
    exit 1
}

if (-not (Test-Path $Config.ReportDir)) {
    New-Item -ItemType Directory -Path $Config.ReportDir | Out-Null
}

# ============================================================ #
#  GET TARGET USERNAME                                         #
# ============================================================ #
$TargetUsername = Read-Host "Enter username (SamAccountName) to offboard"
$OffboardReason = Read-Host "Reason for offboarding (e.g. Resigned, Terminated, Retired)"
$RequestedBy    = Read-Host "Requested by (your name)"

try {
    $User = Get-ADUser -Identity $TargetUsername `
        -Properties DisplayName, EmailAddress, Department, Title, Manager,
                    MemberOf, DistinguishedName, Description, Enabled `
        -ErrorAction Stop
} catch {
    Write-Error "User '$TargetUsername' not found in Active Directory."
    exit 1
}

Write-Host "`nOffboarding: $($User.DisplayName) ($($User.SamAccountName))" -ForegroundColor Yellow
Write-Host "Reason     : $OffboardReason" -ForegroundColor Yellow
$Confirm = Read-Host "Confirm offboarding? (yes/no)"
if ($Confirm -ne "yes") {
    Write-Host "Offboarding cancelled." -ForegroundColor Red
    exit 0
}

# ============================================================ #
#  CAPTURE PRE-OFFBOARD STATE                                  #
# ============================================================ #
$OffboardTime  = Get-Date
$PreState = [PSCustomObject]@{
    DisplayName  = $User.DisplayName
    Username     = $User.SamAccountName
    Email        = $User.EmailAddress
    Department   = $User.Department
    Title        = $User.Title
    Manager      = if ($User.Manager) { (Get-ADUser $User.Manager).SamAccountName } else { "None" }
    Groups       = ($User.MemberOf | ForEach-Object { (Get-ADGroup $_).Name }) -join ", "
    DN           = $User.DistinguishedName
    WasEnabled   = $User.Enabled
}

$Actions = [System.Collections.Generic.List[PSObject]]::new()

function Add-Action {
    param([string]$Step, [string]$Status, [string]$Detail = "")
    $Actions.Add([PSCustomObject]@{ Step = $Step; Status = $Status; Detail = $Detail })
    $color = if ($Status -eq "Success") { "Green" } elseif ($Status -eq "Skipped") { "Yellow" } else { "Red" }
    Write-Host "  [$Status] $Step $(if($Detail){" - $Detail"})" -ForegroundColor $color
}

# ============================================================ #
#  1. DISABLE ACCOUNT                                          #
# ============================================================ #
if ($Config.DisableAccount) {
    try {
        Disable-ADAccount -Identity $TargetUsername -ErrorAction Stop
        Add-Action "Disable AD Account" "Success" "Account disabled"
    } catch {
        Add-Action "Disable AD Account" "Failed" $_.ToString()
    }
} else { Add-Action "Disable AD Account" "Skipped" }

# ============================================================ #
#  2. RESET PASSWORD                                           #
# ============================================================ #
if ($Config.ResetPassword) {
    try {
        $NewPwd = New-RandomPassword
        Set-ADAccountPassword -Identity $TargetUsername -NewPassword (ConvertTo-SecureString $NewPwd -AsPlainText -Force) -Reset -ErrorAction Stop
        Set-ADUser -Identity $TargetUsername -ChangePasswordAtLogon $false -ErrorAction Stop
        Add-Action "Reset Password" "Success" "Password randomized"
    } catch {
        Add-Action "Reset Password" "Failed" $_.ToString()
    }
} else { Add-Action "Reset Password" "Skipped" }

# ============================================================ #
#  3. REMOVE GROUP MEMBERSHIPS                                 #
# ============================================================ #
if ($Config.RemoveGroups) {
    $GroupsRemoved = 0
    $User.MemberOf | ForEach-Object {
        $GroupName = (Get-ADGroup $_).Name
        if ($GroupName -in $Config.PreserveGroups) { return }
        try {
            Remove-ADGroupMember -Identity $_ -Members $TargetUsername -Confirm:$false -ErrorAction Stop
            $GroupsRemoved++
        } catch {
            Add-Action "Remove Group" "Failed" "$GroupName - $($_.ToString())"
        }
    }
    Add-Action "Remove Group Memberships" "Success" "$GroupsRemoved group(s) removed"
} else { Add-Action "Remove Group Memberships" "Skipped" }

# ============================================================ #
#  4. CLEAR MANAGER                                            #
# ============================================================ #
if ($Config.ClearManager) {
    try {
        Set-ADUser -Identity $TargetUsername -Clear Manager -ErrorAction Stop
        Add-Action "Clear Manager" "Success"
    } catch {
        Add-Action "Clear Manager" "Failed" $_.ToString()
    }
} else { Add-Action "Clear Manager" "Skipped" }

# ============================================================ #
#  5. HIDE FROM GAL                                            #
# ============================================================ #
if ($Config.HideFromGAL) {
    try {
        Set-ADUser -Identity $TargetUsername -Replace @{msExchHideFromAddressLists = $true} -ErrorAction Stop
        Add-Action "Hide from GAL" "Success"
    } catch {
        Add-Action "Hide from GAL" "Failed" $_.ToString()
    }
} else { Add-Action "Hide from GAL" "Skipped" }

# ============================================================ #
#  6. UPDATE DESCRIPTION                                       #
# ============================================================ #
if ($Config.SetDescription) {
    try {
        $Desc = "DISABLED: $($OffboardTime.ToString('yyyy-MM-dd')) | Reason: $OffboardReason | By: $RequestedBy"
        Set-ADUser -Identity $TargetUsername -Description $Desc -ErrorAction Stop
        Add-Action "Update Description" "Success" $Desc
    } catch {
        Add-Action "Update Description" "Failed" $_.ToString()
    }
} else { Add-Action "Update Description" "Skipped" }

# ============================================================ #
#  7. MOVE TO DISABLED OU                                      #
# ============================================================ #
if ($Config.MoveToDisabledOU) {
    try {
        Move-ADObject -Identity $User.DistinguishedName -TargetPath $Config.DisabledOU -ErrorAction Stop
        Add-Action "Move to Disabled OU" "Success" $Config.DisabledOU
    } catch {
        Add-Action "Move to Disabled OU" "Failed" $_.ToString()
    }
} else { Add-Action "Move to Disabled OU" "Skipped" }

# ============================================================ #
#  8. REVOKE O365 LICENSE (optional)                           #
# ============================================================ #
if ($Config.RevokeO365License) {
    try {
        Import-Module MSOnline -ErrorAction Stop
        Connect-MsolService -ErrorAction Stop
        $MsolUser = Get-MsolUser -UserPrincipalName $User.UserPrincipalName -ErrorAction Stop
        $MsolUser.Licenses | ForEach-Object {
            Set-MsolUserLicense -UserPrincipalName $User.UserPrincipalName -RemoveLicenses $_.AccountSkuId -ErrorAction Stop
        }
        Add-Action "Revoke O365 Licenses" "Success" "$($MsolUser.Licenses.Count) license(s) removed"
    } catch {
        Add-Action "Revoke O365 Licenses" "Failed" $_.ToString()
    }
} else { Add-Action "Revoke O365 Licenses" "Skipped" "Set RevokeO365License=`$true to enable" }

# ============================================================ #
#  BUILD HTML REPORT                                           #
# ============================================================ #
$ActionRows = ""
foreach ($a in $Actions) {
    $badgeColor = switch ($a.Status) {
        "Success" { "#1e8449" }
        "Failed"  { "#c0392b" }
        "Skipped" { "#7f8c8d" }
        default   { "#7f8c8d" }
    }
    $ActionRows += "<tr>
        <td>$($a.Step)</td>
        <td><span style='background:$badgeColor;color:white;padding:2px 9px;border-radius:10px;font-size:12px;font-weight:bold;'>$($a.Status)</span></td>
        <td style='font-size:12px;color:#555;'>$($a.Detail)</td>
    </tr>"
}

$SuccessCount = ($Actions | Where-Object { $_.Status -eq 'Success' }).Count
$FailCount    = ($Actions | Where-Object { $_.Status -eq 'Failed'  }).Count

$HTMLBody = @"
<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>
  body { font-family:Segoe UI,Arial,sans-serif; background:#f4f6f9; padding:20px; }
  .container { max-width:800px; margin:auto; background:white; border-radius:10px; box-shadow:0 4px 15px rgba(0,0,0,.12); overflow:hidden; }
  .header { background:linear-gradient(135deg,#4a235a,#7d3c98); color:white; padding:30px; }
  .header h1 { margin:0; font-size:24px; }
  .header p { margin:5px 0 0; opacity:.85; font-size:14px; }
  .content { padding:25px; }
  .info-grid { display:grid; grid-template-columns:1fr 1fr; gap:10px; background:#f8f9fa; border-radius:8px; padding:20px; margin-bottom:20px; font-size:13px; }
  .info-grid .label { color:#888; font-size:11px; }
  .info-grid .value { font-weight:bold; color:#2c3e50; }
  h2 { font-size:16px; color:#2c3e50; border-bottom:2px solid #eee; padding-bottom:8px; margin-top:25px; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th { background:#2c3e50; color:white; padding:10px 12px; text-align:left; }
  td { padding:9px 12px; border-bottom:1px solid #f0f0f0; vertical-align:middle; }
  .footer { background:#f4f6f9; padding:15px; font-size:12px; color:#888; text-align:center; border-top:1px solid #e0e0e0; }
</style></head><body>
<div class="container">
  <div class="header">
    <h1>🔒 Employee Offboarding Report</h1>
    <p>Completed: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') &nbsp;|&nbsp; $SuccessCount actions succeeded, $FailCount failed</p>
  </div>
  <div class="content">
    <h2>👤 Employee Details</h2>
    <div class="info-grid">
      <div><div class="label">FULL NAME</div><div class="value">$($PreState.DisplayName)</div></div>
      <div><div class="label">USERNAME</div><div class="value">$($PreState.Username)</div></div>
      <div><div class="label">EMAIL</div><div class="value">$($PreState.Email)</div></div>
      <div><div class="label">DEPARTMENT</div><div class="value">$($PreState.Department)</div></div>
      <div><div class="label">TITLE</div><div class="value">$($PreState.Title)</div></div>
      <div><div class="label">MANAGER</div><div class="value">$($PreState.Manager)</div></div>
      <div><div class="label">REASON</div><div class="value">$OffboardReason</div></div>
      <div><div class="label">PROCESSED BY</div><div class="value">$RequestedBy</div></div>
    </div>
    <h2>📋 Previous Group Memberships</h2>
    <p style="font-size:13px;color:#555;">$($PreState.Groups)</p>
    <h2>⚙️ Actions Taken</h2>
    <table>
      <tr><th>Step</th><th>Status</th><th>Details</th></tr>
      $ActionRows
    </table>
  </div>
  <div class="footer">Auto-generated by PowerShell Offboarding Script &nbsp;|&nbsp; $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</div>
</div></body></html>
"@

# ============================================================ #
#  SEND EMAIL REPORT                                           #
# ============================================================ #
$Subject = "Offboarding Complete: $($User.DisplayName) ($TargetUsername) | $(Get-Date -Format 'yyyy-MM-dd')"
$MailParams = @{
    From       = $Config.FromAddress
    To         = @($Config.AdminEmail, $Config.HREmail)
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
    Write-Host "✅ Report sent to admin and HR." -ForegroundColor Green
} catch {
    Write-Warning "❌ Email failed: $_"
}

# ============================================================ #
#  SAVE LOCAL REPORT                                           #
# ============================================================ #
$ReportPath = "$($Config.ReportDir)\Offboarding_${TargetUsername}_$(Get-Date -Format 'yyyyMMdd_HHmm').html"
$HTMLBody | Out-File -FilePath $ReportPath -Encoding UTF8
Write-Host "📄 Report saved: $ReportPath" -ForegroundColor Cyan

# ============================================================ #
#  CONSOLE SUMMARY                                             #
# ============================================================ #
Write-Host "`n===== OFFBOARDING COMPLETE =====" -ForegroundColor White
Write-Host "User       : $($User.DisplayName) ($TargetUsername)" -ForegroundColor Cyan
Write-Host "Succeeded  : $SuccessCount actions" -ForegroundColor Green
Write-Host "Failed     : $FailCount actions"    -ForegroundColor Red
Write-Host "================================`n"  -ForegroundColor White
