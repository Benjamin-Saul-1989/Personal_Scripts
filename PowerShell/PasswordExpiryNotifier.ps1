#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Password Expiry Notifier
.DESCRIPTION
    Scans Active Directory for users whose passwords are expiring soon
    and sends them a personalized email reminder.
.NOTES
    - Requires AD PowerShell module (RSAT)
    - Requires administrator privileges
    - Schedule via Task Scheduler to run daily
#>

# ============================================================ #
#  CONFIGURATION - Edit these values                           #
# ============================================================ #
$Config = @{
    # Email Settings
    SMTPServer    = "smtp.office365.com"
    SMTPPort      = 587
    UseSSL        = $true
    FromAddress   = "noreply@yourdomain.com"
    FromName      = "IT Support"
    Username      = "noreply@yourdomain.com"
    Password      = "YourPasswordHere"

    # Notification Settings
    WarnDays      = @(14, 7, 3, 1)       # Days before expiry to send alerts
    AdminEmail    = "admin@yourdomain.com"
    CompanyName   = "Your Company"
    HelpDeskEmail = "helpdesk@yourdomain.com"
    HelpDeskPhone = "555-1234"
    PasswordURL   = "https://account.activedirectory.windowsazure.com/ChangePassword.aspx"

    # AD Settings
    SearchBase    = ""                    # Leave blank for entire domain, or specify OU
                                          # e.g. "OU=Users,DC=yourdomain,DC=com"
}

# ============================================================ #
#  SECURE PASSWORD                                             #
# ============================================================ #
$SecurePass = ConvertTo-SecureString $Config.Password -AsPlainText -Force
$Credential = New-Object System.Management.Automation.PSCredential($Config.Username, $SecurePass)

# ============================================================ #
#  HELPER FUNCTIONS                                            #
# ============================================================ #
function Get-PasswordExpiryDate {
    param($User, $DefaultMaxPasswordAge)
    try {
        $policy = Get-ADUserResultantPasswordPolicy -Identity $User -ErrorAction SilentlyContinue
        $maxAge = if ($policy) { $policy.MaxPasswordAge } else { $DefaultMaxPasswordAge }
        if ($maxAge -eq [TimeSpan]::Zero) { return $null }  # Password never expires
        return $User.PasswordLastSet + $maxAge
    } catch {
        if ($DefaultMaxPasswordAge -eq [TimeSpan]::Zero) { return $null }
        return $User.PasswordLastSet + $DefaultMaxPasswordAge
    }
}

# ============================================================ #
#  GET DEFAULT DOMAIN PASSWORD POLICY                          #
# ============================================================ #
Write-Host "Loading domain password policy..." -ForegroundColor Cyan

try {
    Import-Module ActiveDirectory -ErrorAction Stop
} catch {
    Write-Error "Active Directory module not found. Install RSAT tools."
    exit 1
}

$DomainPolicy       = Get-ADDefaultDomainPasswordPolicy
$DefaultMaxPwdAge   = $DomainPolicy.MaxPasswordAge
$Today              = Get-Date
$NotifiedCount      = 0
$SkippedCount       = 0
$SummaryList        = [System.Collections.Generic.List[PSObject]]::new()

# ============================================================ #
#  GET ALL ENABLED AD USERS WITH EMAIL                         #
# ============================================================ #
Write-Host "Querying Active Directory users..." -ForegroundColor Cyan

$ADParams = @{
    Filter     = { Enabled -eq $true -and PasswordNeverExpires -eq $false -and PasswordLastSet -gt 0 }
    Properties = @("EmailAddress","PasswordLastSet","PasswordNeverExpires","DisplayName","GivenName","msDS-ResultantPSO")
}
if ($Config.SearchBase -ne "") { $ADParams["SearchBase"] = $Config.SearchBase }

$Users = Get-ADUser @ADParams | Where-Object { $_.EmailAddress -ne $null -and $_.EmailAddress -ne "" }
Write-Host "Found $($Users.Count) users to check." -ForegroundColor Green

# ============================================================ #
#  CHECK EACH USER AND SEND NOTIFICATIONS                      #
# ============================================================ #
foreach ($User in $Users) {
    $ExpiryDate = Get-PasswordExpiryDate -User $User -DefaultMaxPasswordAge $DefaultMaxPwdAge

    if ($null -eq $ExpiryDate) {
        $SkippedCount++
        continue
    }

    $DaysLeft = [math]::Round(($ExpiryDate - $Today).TotalDays)

    # Only notify if within warning days
    if ($DaysLeft -notin $Config.WarnDays -or $DaysLeft -lt 0) {
        $SkippedCount++
        continue
    }

    $SummaryList.Add([PSCustomObject]@{
        Name       = $User.DisplayName
        Username   = $User.SamAccountName
        Email      = $User.EmailAddress
        ExpiryDate = $ExpiryDate.ToString("yyyy-MM-dd")
        DaysLeft   = $DaysLeft
    })

    # Urgency color
    $UrgencyColor = if ($DaysLeft -le 1) { "#c0392b" } elseif ($DaysLeft -le 3) { "#e67e22" } else { "#2e86c1" }
    $UrgencyText  = if ($DaysLeft -eq 1) { "TODAY - URGENT" } elseif ($DaysLeft -le 3) { "Very Soon" } else { "Coming Up" }

    $UserHTMLBody = @"
<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>
  body { font-family: Segoe UI, Arial, sans-serif; background:#f4f6f9; margin:0; padding:20px; }
  .container { max-width:600px; margin:auto; background:white; border-radius:10px; box-shadow:0 2px 10px rgba(0,0,0,0.1); overflow:hidden; }
  .header { background:linear-gradient(135deg,$UrgencyColor, #1a252f); color:white; padding:30px; text-align:center; }
  .header h1 { margin:0; font-size:22px; }
  .content { padding:30px; }
  .days-box { background:$UrgencyColor; color:white; border-radius:10px; padding:20px; text-align:center; margin:20px 0; }
  .days-box .num { font-size:48px; font-weight:bold; }
  .days-box .lbl { font-size:14px; opacity:.9; }
  .btn { display:inline-block; background:$UrgencyColor; color:white; padding:12px 30px; border-radius:6px; text-decoration:none; font-weight:bold; margin:20px 0; }
  .info { background:#f8f9fa; border-left:4px solid $UrgencyColor; padding:12px 16px; border-radius:4px; font-size:13px; margin:15px 0; }
  .footer { background:#f4f6f9; padding:15px; text-align:center; font-size:12px; color:#888; }
</style></head><body>
<div class="container">
  <div class="header"><h1>🔐 Password Expiry Notice</h1><p>$($Config.CompanyName) IT Security</p></div>
  <div class="content">
    <p>Hi <strong>$($User.GivenName)</strong>,</p>
    <p>Your network password is expiring soon. Please change it before it expires to avoid being locked out.</p>
    <div class="days-box">
      <div class="num">$DaysLeft</div>
      <div class="lbl">Day(s) Remaining — $UrgencyText</div>
    </div>
    <div class="info">
      <strong>Account:</strong> $($User.SamAccountName)<br>
      <strong>Expires:</strong> $($ExpiryDate.ToString("dddd, MMMM dd, yyyy 'at' hh:mm tt"))
    </div>
    <p><strong>How to change your password:</strong></p>
    <ul>
      <li><strong>On your work PC:</strong> Press <kbd>Ctrl+Alt+Del</kbd> → Change a password</li>
      <li><strong>Self-service portal:</strong> <a href="$($Config.PasswordURL)">Click here to change online</a></li>
    </ul>
    <a href="$($Config.PasswordURL)" class="btn">Change Password Now</a>
    <p>If you need help, contact the IT Help Desk:<br>
    📧 <a href="mailto:$($Config.HelpDeskEmail)">$($Config.HelpDeskEmail)</a> &nbsp;|&nbsp; 📞 $($Config.HelpDeskPhone)</p>
  </div>
  <div class="footer">This is an automated message from $($Config.CompanyName) IT. Please do not reply to this email.</div>
</div></body></html>
"@

    $DayWord = if ($DaysLeft -eq 1) { "1 day" } else { "$DaysLeft days" }
    $Subject = "⚠️ Action Required: Your password expires in $DayWord"

    try {
        Send-MailMessage `
            -From "$($Config.FromName) <$($Config.FromAddress)>" `
            -To $User.EmailAddress `
            -Subject $Subject `
            -Body $UserHTMLBody `
            -BodyAsHtml `
            -SmtpServer $Config.SMTPServer `
            -Port $Config.SMTPPort `
            -UseSsl:$Config.UseSSL `
            -Credential $Credential

        Write-Host "  ✅ Notified: $($User.DisplayName) ($($User.EmailAddress)) — $DaysLeft day(s)" -ForegroundColor Green
        $NotifiedCount++
    } catch {
        Write-Warning "  ❌ Failed to email $($User.EmailAddress): $_"
    }
}

# ============================================================ #
#  SEND ADMIN SUMMARY REPORT                                   #
# ============================================================ #
Write-Host "`nSending admin summary..." -ForegroundColor Cyan

$SummaryRows = ""
$alt = $false
foreach ($s in ($SummaryList | Sort-Object DaysLeft)) {
    $rowClass = if ($alt) { "background:#fafafa;" } else { "" }
    $color    = if ($s.DaysLeft -le 1) { "#c0392b" } elseif ($s.DaysLeft -le 3) { "#e67e22" } else { "#2e86c1" }
    $SummaryRows += "<tr style='$rowClass'>
        <td>$($s.Name)</td>
        <td>$($s.Username)</td>
        <td>$($s.Email)</td>
        <td>$($s.ExpiryDate)</td>
        <td><strong style='color:$color;'>$($s.DaysLeft) day(s)</strong></td>
    </tr>"
    $alt = !$alt
}

if ($SummaryList.Count -eq 0) { $SummaryRows = "<tr><td colspan='5' style='text-align:center;color:#888;'>No expiring passwords today.</td></tr>" }

$AdminHTML = @"
<!DOCTYPE html><html><head><meta charset="UTF-8">
<style>
  body { font-family:Segoe UI,Arial,sans-serif; background:#f4f6f9; padding:20px; }
  .container { max-width:900px; margin:auto; background:white; border-radius:10px; box-shadow:0 2px 10px rgba(0,0,0,.1); overflow:hidden; }
  .header { background:linear-gradient(135deg,#1a252f,#2c3e50); color:white; padding:25px; }
  .header h1 { margin:0; font-size:22px; }
  .content { padding:25px; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th { background:#2c3e50; color:white; padding:10px 12px; text-align:left; }
  td { padding:9px 12px; border-bottom:1px solid #f0f0f0; }
  .footer { background:#f4f6f9; padding:15px; font-size:12px; color:#888; text-align:center; }
</style></head><body>
<div class="container">
  <div class="header"><h1>🔐 Password Expiry Admin Summary</h1>
  <p style="margin:5px 0 0;opacity:.8;">$(Get-Date -Format 'yyyy-MM-dd HH:mm') | $($Config.CompanyName)</p></div>
  <div class="content">
    <p><strong>$NotifiedCount</strong> user(s) notified today. <strong>$SkippedCount</strong> skipped (not in warning window or no email).</p>
    <table>
      <tr><th>Display Name</th><th>Username</th><th>Email</th><th>Expiry Date</th><th>Days Left</th></tr>
      $SummaryRows
    </table>
  </div>
  <div class="footer">Auto-generated by PowerShell Password Expiry Notifier</div>
</div></body></html>
"@

try {
    Send-MailMessage `
        -From "$($Config.FromName) <$($Config.FromAddress)>" `
        -To $Config.AdminEmail `
        -Subject "Password Expiry Summary | $NotifiedCount notified | $(Get-Date -Format 'yyyy-MM-dd')" `
        -Body $AdminHTML `
        -BodyAsHtml `
        -SmtpServer $Config.SMTPServer `
        -Port $Config.SMTPPort `
        -UseSsl:$Config.UseSSL `
        -Credential $Credential
    Write-Host "✅ Admin summary sent to $($Config.AdminEmail)" -ForegroundColor Green
} catch {
    Write-Warning "❌ Failed to send admin summary: $_"
}

# ============================================================ #
#  CONSOLE SUMMARY                                             #
# ============================================================ #
Write-Host "`n===== PASSWORD EXPIRY SUMMARY =====" -ForegroundColor White
Write-Host "Users Notified : $NotifiedCount" -ForegroundColor Green
Write-Host "Users Skipped  : $SkippedCount"  -ForegroundColor Yellow
Write-Host "==================================`n" -ForegroundColor White
