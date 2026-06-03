<#
# =============================================================
# Author  : 0xPrashanthSec
# GitHub  : https://github.com/0xPrashanthSec
# Purpose : SOC Incident Response Toolkit
# License : For authorized, safe, and educational use only.
#           Do NOT run against systems you do not own or have
#           explicit written permission to investigate.
# =============================================================
.SYNOPSIS
    SOC - Windows User Account Investigation
    Audits all local and domain user accounts, sessions, and privileges.
    What to look for: unexpected admin accounts, accounts created recently,
    accounts with no password policy, accounts never logged in, stale accounts.
    Required: Run as Administrator.
#>

$ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
Write-Host "`n=====================================================" -ForegroundColor Yellow
Write-Host "  SOC USER ACCOUNT INVESTIGATION  |  $ts UTC"           -ForegroundColor Yellow
Write-Host "=====================================================`n" -ForegroundColor Yellow

# ----------------------------------------------------------
Write-Host "[1] ALL LOCAL USER ACCOUNTS" -ForegroundColor Cyan
# ----------------------------------------------------------
Get-LocalUser |
    Select-Object Name, Enabled, LastLogon, PasswordLastSet,
        PasswordExpires, PasswordRequired, UserMayChangePassword,
        Description, SID |
    Format-Table -AutoSize

# ----------------------------------------------------------
Write-Host "[2] LOCAL ADMINISTRATORS GROUP" -ForegroundColor Cyan
# ----------------------------------------------------------
# Unexpected members here = privilege escalation
Get-LocalGroupMember -Group "Administrators" |
    Select-Object Name, PrincipalSource, ObjectClass | Format-Table -AutoSize

# ----------------------------------------------------------
Write-Host "[3] ALL LOCAL GROUPS AND MEMBERS" -ForegroundColor Cyan
# ----------------------------------------------------------
Get-LocalGroup | ForEach-Object {
    $group = $_
    Get-LocalGroupMember -Group $group.Name -EA SilentlyContinue |
        ForEach-Object {
            [PSCustomObject]@{Group=$group.Name; Member=$_.Name; Source=$_.PrincipalSource}
        }
} | Format-Table -AutoSize

# ----------------------------------------------------------
Write-Host "[4] ACCOUNTS CREATED IN LAST 30 DAYS" -ForegroundColor Cyan
# ----------------------------------------------------------
$cutoff = (Get-Date).AddDays(-30)
try {
    Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4720} -MaxEvents 100 -EA Stop |
        Select-Object TimeCreated,
            @{N="NewAccount";  E={$_.Properties[0].Value}},
            @{N="CreatedBy";   E={$_.Properties[4].Value}},
            @{N="Domain";      E={$_.Properties[1].Value}} |
        Format-Table -AutoSize
} catch {
    Write-Host "  Cannot read Security log." -ForegroundColor DarkYellow
}

# ----------------------------------------------------------
Write-Host "[5] ACTIVE LOGON SESSIONS" -ForegroundColor Cyan
# ----------------------------------------------------------
Get-CimInstance -ClassName Win32_LogonSession |
    ForEach-Object {
        $session = $_
        $user = Get-CimInstance -Query "ASSOCIATORS OF {Win32_LogonSession.LogonId='$($session.LogonId)'} WHERE AssocClass=Win32_LoggedOnUser" -EA SilentlyContinue
        [PSCustomObject]@{
            LogonId      = $session.LogonId
            LogonType    = $session.LogonType
            AuthPackage  = $session.AuthenticationPackage
            StartTime    = $session.StartTime
            User         = $user.Name
        }
    } | Format-Table -AutoSize

# ----------------------------------------------------------
Write-Host "[6] PASSWORD POLICY" -ForegroundColor Cyan
# ----------------------------------------------------------
net accounts 2>$null

# ----------------------------------------------------------
Write-Host "[7] RECENT FAILED AND SUCCESSFUL LOGINS PER ACCOUNT" -ForegroundColor Cyan
# ----------------------------------------------------------
# Repeated failures from one account = brute force or locked user
try {
    $failed = Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4625} -MaxEvents 200 -EA Stop
    $failed |
        Group-Object { $_.Properties[5].Value } |
        Sort-Object Count -Descending | Select-Object -First 15 |
        Select-Object @{N="Account";E={$_.Name}}, Count |
        Format-Table -AutoSize
} catch { Write-Host "  Cannot read Security log." -ForegroundColor DarkYellow }

# ----------------------------------------------------------
Write-Host "[8] DOMAIN ACCOUNTS (if domain-joined)" -ForegroundColor Cyan
# ----------------------------------------------------------
try {
    Import-Module ActiveDirectory -EA Stop
    Write-Host "  Recently enabled/created domain accounts (last 30 days):" -ForegroundColor DarkCyan
    $cutoff = (Get-Date).AddDays(-30)
    Get-ADUser -Filter {WhenCreated -ge $cutoff} -Properties WhenCreated, LastLogonDate, Enabled |
        Select-Object Name, SamAccountName, Enabled, WhenCreated, LastLogonDate |
        Format-Table -AutoSize

    Write-Host "  Domain Admin members:" -ForegroundColor DarkCyan
    Get-ADGroupMember -Identity "Domain Admins" |
        Select-Object Name, SamAccountName, ObjectClass | Format-Table -AutoSize
} catch {
    Write-Host "  Not domain-joined or ActiveDirectory module unavailable." -ForegroundColor DarkYellow
}

# ----------------------------------------------------------
Write-Host "[9] REMOTE DESKTOP USERS GROUP" -ForegroundColor Cyan
# ----------------------------------------------------------
Get-LocalGroupMember -Group "Remote Desktop Users" -EA SilentlyContinue |
    Select-Object Name, PrincipalSource | Format-Table -AutoSize

Write-Host "`n[USER ACCOUNTS DONE] => Run 08_Remediation.ps1 if action needed`n" -ForegroundColor Green
