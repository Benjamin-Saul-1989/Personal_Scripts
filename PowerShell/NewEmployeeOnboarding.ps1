#Requires -RunAsAdministrator
<#
.SYNOPSIS
    New Employee Onboarding Automation
.DESCRIPTION
    Automates new employee setup: creates AD account, assigns groups,
    sets up home drive, and sends welcome email with credentials.
.NOTES
    - Requires AD PowerShell module (RSAT)
    - Run as Domain Admin or delegated account
    - Input via CSV file or interactive prompt
    - CSV columns: FirstName,LastName,Title,Department,Manager,Email,OU,Groups,HomeDrive
#>

# ============================================================ #
#  CONFIGURATION - Edit these values                           #
# ============================================================ #
$Config = @{
    # Email Settings
    SMTPServer    = "smtp.office365.com"
    SMTPPort      = 587
    UseSSL        = $true
    FromAddress   = "it@yourdomain.com"
    FromName      = "IT Department"
    Username      = "it@yourdomain.com"
    Password      = "YourPasswordHere"

    # AD Settings
    Domain        = "yourdomain.com"
    DomainDN      = "DC=yourdomain,DC=com"
    DefaultOU     = "OU=Users,DC=yourdomain,DC=com"
    DefaultGroups = @("Domain Users", "VPN Users", "Office365")
    HomeDriveRoot = "\\fileserver\homes"
    HomeDriveLetter = "H"
    UPNSuffix     = "@yourdomain.com"

    # Password Policy
    TempPassword  = "Welcome@2024!"   # User must change on first login
    PasswordChangeAtLogon = $true

    # Company Info
    CompanyName   = "Your Company"
    HelpDeskEmail = "helpdesk@yourdomain.com"
    HelpDeskPhone = "555-1234"

    # CSV Input (set to $null to use interactive mode)
    CSVPath       = $null             # e.g. "C:\Onboarding\new_employees.csv"

    # Report
    ReportDir     = "C:\Reports\Onboarding"
    AdminEmail    = "admin@yourdomain.com"
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
    $upper   = "ABCDEFGHJKLMNPQRSTUVWXYZ".ToCharArray()
    $lower   = "abcdefghjkmnpqrstuvwxyz".ToCharArray()
    $digits  = "23456789".ToCharArray()
    $special = "!@#$%^&*".ToCharArray()
    $all     = $upper + $lower + $digits + $special
    $pwd     = ($upper | Get-Random) + ($lower | Get-Random) + ($digits | Get-Random) + ($special | Get-Random)
    $pwd    += -join ($all | Get-Random -Count 6)
    return -join ($pwd.ToCharArray() | Get-Random -Count $pwd.Length)
}

function Get-UniqueUsername {
    param([string]$First, [string]$Last)
    $base = ($First.Substring(0,1) + $Last).ToLower() -replace '[^a-z0-9]', ''
    $uname = $base
    $i = 1
    while (Get-ADUser -Filter "SamAccountName -eq '$uname'" -ErrorAction SilentlyContinue) {
        $uname = "$base$i"
        $i++
    }
    return $uname
}

# ============================================================ #
#  LOAD AD MODULE                                              #
# ============================================================ #
try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Error "Active Directory module not found. Install RSAT tools."
    exit 1
}

if (-not (Test-Path $Config.ReportDir)) {
    New-Item -ItemType Directory -Path $Config.ReportDir | Out-Null
}

# ============================================================ #
#  LOAD EMPLOYEE DATA                                          #
# ============================================================ #
$Employees = @()

if ($Config.CSVPath -and (Test-Path $Config.CSVPath)) {
    Write-Host "Loading employees from CSV: $($Config.CSVPath)" -ForegroundColor Cyan
    $Employees = Import-Csv $Config.CSVPath
} else {
    Write-Host "Interactive mode - enter employee details" -ForegroundColor Cyan
    $emp = [PSCustomObject]@{
        FirstName  = Read-Host "First Name"
        LastName   = Read-Host "Last Name"
        Title      = Read-Host "Job Title"
        Department = Read-Host "Department"
        Manager    = Read-Host "Manager username (SamAccountName)"
        Email      = Read-Host "Personal email (for welcome email)"
        OU         = ""   # Will use default
        Groups     = ""   # Will use defaults
    }
    $Employees = @($emp)
}

# ============================================================ #
#  PROCESS EACH EMPLOYEE                                       #
# ============================================================ #
$Results = [System.Collections.Generic.List[PSObject]]::new()

foreach ($Emp in $Employees) {
    Write-Host "`nProcessing: $($Emp.FirstName) $($Emp.LastName)..." -ForegroundColor Cyan

    $Status  = "Success"
    $Notes   = @()
    $Actions = @()

    # Generate username and display name
    $Username    = Get-UniqueUsername -First $Emp.FirstName -Last $Emp.LastName
    $DisplayName = "$($Emp.FirstName) $($Emp.LastName)"
    $UPN         = "$Username$($Config.UPNSuffix)"
    $OU          = if ($Emp.OU -and $Emp.OU -ne "") { $Emp.OU } else { $Config.DefaultOU }
    $TempPwd     = if ($Config.TempPassword) { $Config.TempPassword } else { New-RandomPassword }
    $SecureTmpPwd = ConvertTo-SecureString $TempPwd -AsPlainText -Force
    $HomePath    = "$($Config.HomeDriveRoot)\$Username"

    # ── Create AD Account ──────────────────────────────────────
    try {
        $ADParams = @{
            Name                  = $DisplayName
            GivenName             = $Emp.FirstName
            Surname               = $Emp.LastName
            SamAccountName        = $Username
            UserPrincipalName     = $UPN
            DisplayName           = $DisplayName
            Title                 = $Emp.Title
            Department            = $Emp.Department
            EmailAddress          = $UPN
            AccountPassword       = $SecureTmpPwd
            ChangePasswordAtLogon = $Config.PasswordChangeAtLogon
            Enabled               = $true
            Path                  = $OU
            HomeDirectory         = $HomePath
            HomeDrive             = $Config.HomeDriveLetter
        }

        if ($Emp.Manager -and $Emp.Manager -ne "") {
            $ManagerObj = Get-ADUser -Identity $Emp.Manager -ErrorAction SilentlyContinue
            if ($ManagerObj) { $ADParams["Manager"] = $ManagerObj.DistinguishedName }
        }

        New-ADUser @ADParams -ErrorAction Stop
        $Actions += "✅ AD account created: $Username"
        Write-Host "  ✅ AD account created: $Username" -ForegroundColor Green
    } catch {
        $Status = "Failed"
        $Notes += "AD creation failed: $_"
        Write-Warning "  ❌ AD creation failed: $_"
        $Results.Add([PSCustomObject]@{
            Name     = $DisplayName
            Username = $Username
            Status   = "Failed"
            Actions  = "AD account creation failed"
            Notes    = $_.ToString()
        })
        continue
    }

    # ── Assign Groups ──────────────────────────────────────────
    $GroupsToAdd = $Config.DefaultGroups
    if ($Emp.Groups -and $Emp.Groups -ne "") {
        $GroupsToAdd += $Emp.Groups -split ";"
    }

    foreach ($Group in $GroupsToAdd) {
        $Group = $Group.Trim()
        if ($Group -eq "") { continue }
        try {
            Add-ADGroupMember -Identity $Group -Members $Username -ErrorAction Stop
            $Actions += "✅ Added to group: $Group"
            Write-Host "  ✅ Added to group: $Group" -ForegroundColor Green
        } catch {
            $Notes += "Group '$Group' failed: $_"
            Write-Warning "  ⚠️  Could not add to '$Group': $_"
        }
    }

    # ── Create Home Drive Folder ──────────────────────────────
    try {
        if (-not (Test-Path $HomePath)) {
            New-Item -ItemType Directory -Path $HomePath -ErrorAction Stop | Out-Null
            # Set permissions: Full Control for the user, no inheritance issues
            $ACL = Get-Acl $HomePath
            $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $Username, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
            )
            $ACL.SetAccessRule($Rule)
            Set-Acl -Path $HomePath -AclObject $ACL
            $Actions += "✅ Home drive created: $HomePath"
            Write-Host "  ✅ Home drive created: $HomePath" -ForegroundColor Green
        } else {
            $Actions += "ℹ️ Home drive already exists: $HomePath"
        }
    } catch {
        $Notes += "Home drive failed: $_"
        Write-Warning "  ⚠️  Home drive creation failed: $_"
    }

    # ── Send Welcome Email ─────────────────────────────────────
    $WelcomeEmail = if ($Emp.Email -and $Emp.Email -ne "") { $Emp.Email } else { $UPN }

    $WelcomeHTML = @"
<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>
  body { font-family:Segoe UI,Arial,sans-serif; background:#f4f6f9; margin:0; padding:20px; }
  .container { max-width:600px; margin:auto; background:white; border-radius:10px; box-shadow:0 2px 10px rgba(0,0,0,.1); overflow:hidden; }
  .header { background:linear-gradient(135deg,#1a5e20,#1e8449); color:white; padding:30px; text-align:center; }
  .header h1 { margin:0; font-size:24px; }
  .content { padding:30px; }
  .creds { background:#f8f9fa; border:2px dashed #2e86c1; border-radius:8px; padding:20px; margin:20px 0; font-family:monospace; }
  .creds .label { color:#888; font-size:12px; margin-bottom:2px; }
  .creds .value { font-size:16px; font-weight:bold; color:#2c3e50; margin-bottom:12px; }
  .warning { background:#fef9e7; border-left:4px solid #f39c12; padding:12px 16px; border-radius:4px; font-size:13px; margin:15px 0; }
  .footer { background:#f4f6f9; padding:15px; text-align:center; font-size:12px; color:#888; }
</style></head><body>
<div class="container">
  <div class="header"><h1>🎉 Welcome to $($Config.CompanyName)!</h1></div>
  <div class="content">
    <p>Hi <strong>$($Emp.FirstName)</strong>, welcome aboard! Your IT account has been set up and is ready to use.</p>
    <div class="creds">
      <div class="label">USERNAME</div><div class="value">$Username</div>
      <div class="label">TEMPORARY PASSWORD</div><div class="value">$TempPwd</div>
      <div class="label">EMAIL ADDRESS</div><div class="value">$UPN</div>
      <div class="label">HOME DRIVE</div><div class="value">$($Config.HomeDriveLetter): → $HomePath</div>
    </div>
    <div class="warning">⚠️ <strong>Important:</strong> You will be required to change your password on first login. Please keep your new password secure and do not share it.</div>
    <p><strong>Getting Started:</strong></p>
    <ul>
      <li>Log in with the credentials above</li>
      <li>Change your password immediately when prompted</li>
      <li>Your home drive ($($Config.HomeDriveLetter):) is mapped automatically</li>
    </ul>
    <p>Need help? Contact IT:<br>
    📧 <a href="mailto:$($Config.HelpDeskEmail)">$($Config.HelpDeskEmail)</a> &nbsp;|&nbsp; 📞 $($Config.HelpDeskPhone)</p>
  </div>
  <div class="footer">$($Config.CompanyName) IT Department</div>
</div></body></html>
"@

    try {
        Send-MailMessage `
            -From "$($Config.FromName) <$($Config.FromAddress)>" `
            -To $WelcomeEmail `
            -Subject "Welcome to $($Config.CompanyName) — Your IT Account Details" `
            -Body $WelcomeHTML `
            -BodyAsHtml `
            -SmtpServer $Config.SMTPServer `
            -Port $Config.SMTPPort `
            -UseSsl:$Config.UseSSL `
            -Credential $Credential
        $Actions += "✅ Welcome email sent to: $WelcomeEmail"
        Write-Host "  ✅ Welcome email sent to: $WelcomeEmail" -ForegroundColor Green
    } catch {
        $Notes += "Welcome email failed: $_"
        Write-Warning "  ⚠️  Welcome email failed: $_"
    }

    $Results.Add([PSCustomObject]@{
        Name     = $DisplayName
        Username = $Username
        UPN      = $UPN
        Status   = $Status
        Actions  = ($Actions -join "`n")
        Notes    = ($Notes -join "; ")
    })
}

# ============================================================ #
#  BUILD ADMIN SUMMARY EMAIL                                   #
# ============================================================ #
$SuccessCount = ($Results | Where-Object { $_.Status -eq 'Success' }).Count
$FailCount    = ($Results | Where-Object { $_.Status -eq 'Failed'  }).Count

$SummaryRows = ""
foreach ($r in $Results) {
    $badgeColor = if ($r.Status -eq 'Success') { "#1e8449" } else { "#c0392b" }
    $SummaryRows += "<tr>
        <td><strong>$($r.Name)</strong></td>
        <td>$($r.Username)</td>
        <td>$($r.UPN)</td>
        <td><span style='background:$badgeColor;color:white;padding:2px 9px;border-radius:10px;font-size:12px;'>$($r.Status)</span></td>
        <td style='font-size:12px;'>$($r.Notes)</td>
    </tr>"
}

$AdminHTML = @"
<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>
  body { font-family:Segoe UI,Arial,sans-serif; background:#f4f6f9; padding:20px; }
  .container { max-width:900px; margin:auto; background:white; border-radius:10px; box-shadow:0 2px 10px rgba(0,0,0,.1); overflow:hidden; }
  .header { background:linear-gradient(135deg,#1a3a5c,#2e86c1); color:white; padding:25px; }
  .content { padding:25px; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th { background:#2c3e50; color:white; padding:10px 12px; text-align:left; }
  td { padding:9px 12px; border-bottom:1px solid #f0f0f0; }
  .footer { background:#f4f6f9; padding:15px; font-size:12px; color:#888; text-align:center; }
</style></head><body>
<div class="container">
  <div class="header"><h1>👤 Onboarding Summary</h1>
  <p style="margin:5px 0 0;opacity:.8;">$(Get-Date -Format 'yyyy-MM-dd HH:mm') — $SuccessCount succeeded, $FailCount failed</p></div>
  <div class="content">
    <table><tr><th>Name</th><th>Username</th><th>UPN/Email</th><th>Status</th><th>Notes</th></tr>
    $SummaryRows</table>
  </div>
  <div class="footer">Auto-generated by PowerShell Onboarding Automation</div>
</div></body></html>
"@

try {
    Send-MailMessage `
        -From $Config.FromAddress `
        -To $Config.AdminEmail `
        -Subject "Onboarding Complete | $SuccessCount created | $(Get-Date -Format 'yyyy-MM-dd')" `
        -Body $AdminHTML -BodyAsHtml `
        -SmtpServer $Config.SMTPServer -Port $Config.SMTPPort `
        -UseSsl:$Config.UseSSL -Credential $Credential
    Write-Host "✅ Admin summary sent." -ForegroundColor Green
} catch {
    Write-Warning "❌ Admin summary email failed: $_"
}

# ============================================================ #
#  SAVE REPORT                                                 #
# ============================================================ #
$ReportPath = "$($Config.ReportDir)\Onboarding_$(Get-Date -Format 'yyyyMMdd_HHmm').csv"
$Results | Export-Csv -Path $ReportPath -NoTypeInformation
Write-Host "📄 Report saved: $ReportPath" -ForegroundColor Cyan

# ============================================================ #
#  CONSOLE SUMMARY                                             #
# ============================================================ #
Write-Host "`n===== ONBOARDING SUMMARY =====" -ForegroundColor White
Write-Host "Successful : $SuccessCount" -ForegroundColor Green
Write-Host "Failed     : $FailCount"    -ForegroundColor Red
Write-Host "==============================`n" -ForegroundColor White
