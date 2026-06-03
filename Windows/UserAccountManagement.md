# Windows User Account Management

> **SOC Use Case:** Create a temporary local account for investigation access, perform the work, then fully clean up when done.
> All commands require **PowerShell as Administrator**.

---

## Create a Local User Account

```powershell
# Define credentials
$Username = "soc_temp"
$Password = ConvertTo-SecureString "TempP@ss123!" -AsPlainText -Force

# Create the account
New-LocalUser -Name $Username -Password $Password -FullName "SOC Temp" -Description "Temporary SOC account" -PasswordNeverExpires $false -UserMayNotChangePassword $true

# Confirm it was created
Get-LocalUser -Name $Username
```

---

## Add User to a Group

```powershell
# Add to standard Users group (default, limited access)
Add-LocalGroupMember -Group "Users" -Member "soc_temp"

# Add to Administrators group (only if elevated access is required for investigation)
Add-LocalGroupMember -Group "Administrators" -Member "soc_temp"

# Verify group membership
Get-LocalGroupMember -Group "Administrators"
Get-LocalGroupMember -Group "Users"
```

---

## Create a Domain Account (if machine is domain-joined)

```powershell
Import-Module ActiveDirectory

# Create domain user
New-ADUser -Name "soc_temp" -SamAccountName "soc_temp" -UserPrincipalName "soc_temp@domain.com" `
    -AccountPassword (ConvertTo-SecureString "TempP@ss123!" -AsPlainText -Force) `
    -Enabled $true -PasswordNeverExpires $false -ChangePasswordAtLogon $true

# Add to a domain group
Add-ADGroupMember -Identity "Domain Users" -Members "soc_temp"

# Verify
Get-ADUser -Identity "soc_temp"
```

---

## Unlock or Reset Password

```powershell
# Reset a local account password
$NewPass = ConvertTo-SecureString "NewP@ss456!" -AsPlainText -Force
Set-LocalUser -Name "soc_temp" -Password $NewPass

# Reset domain account password and force change at next logon
Set-ADAccountPassword -Identity "soc_temp" -NewPassword (ConvertTo-SecureString "NewP@ss456!" -AsPlainText -Force) -Reset
Set-ADUser -Identity "soc_temp" -ChangePasswordAtLogon $true

# Unlock a domain account that got locked out
Unlock-ADAccount -Identity "soc_temp"

# Check if account is locked
Get-ADUser -Identity "soc_temp" -Properties LockedOut | Select-Object Name, LockedOut
```

---

## List All Local Users and Sessions

```powershell
# List all local accounts
Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, Description

# List current active sessions
query user

# List all local groups
Get-LocalGroup

# Members of Administrators group
Get-LocalGroupMember -Group "Administrators"
```

---

## Disable an Account (Temporary Suspend Without Deleting)

```powershell
# Disable local account
Disable-LocalUser -Name "soc_temp"

# Disable domain account
Disable-ADAccount -Identity "soc_temp"

# Re-enable if needed
Enable-LocalUser -Name "soc_temp"
Enable-ADAccount -Identity "soc_temp"
```

---

## Cleanup — Full Account Removal

```powershell
# ---- LOCAL ACCOUNT CLEANUP ----

# Force log off any active sessions first
# Get session ID, then log it off
$session = query user 2>&1 | Select-String "soc_temp"
# Note session ID from output, then:
# logoff <SessionID>

# Remove from any groups
Remove-LocalGroupMember -Group "Administrators" -Member "soc_temp" -ErrorAction SilentlyContinue
Remove-LocalGroupMember -Group "Users" -Member "soc_temp" -ErrorAction SilentlyContinue

# Delete the local account
Remove-LocalUser -Name "soc_temp"

# Verify it's gone
Get-LocalUser -Name "soc_temp" -ErrorAction SilentlyContinue


# ---- DOMAIN ACCOUNT CLEANUP ----

# Remove from all groups first
Get-ADUser -Identity "soc_temp" -Properties MemberOf |
    Select-Object -ExpandProperty MemberOf |
    ForEach-Object { Remove-ADGroupMember -Identity $_ -Members "soc_temp" -Confirm:$false }

# Delete the domain account
Remove-ADUser -Identity "soc_temp" -Confirm:$false

# Verify it's gone
Get-ADUser -Identity "soc_temp" -ErrorAction SilentlyContinue
```

---

## Cleanup — Remove Leftover Profile Data

```powershell
# Remove the user's local profile folder after account deletion
$profilePath = "C:\Users\soc_temp"
if (Test-Path $profilePath) {
    Remove-Item -Path $profilePath -Recurse -Force
    Write-Host "Profile folder removed: $profilePath"
}

# Remove profile registry entry (prevents orphaned profile warnings)
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
Get-ChildItem $regPath | ForEach-Object {
    $data = Get-ItemProperty $_.PSPath
    if ($data.ProfileImagePath -like "*soc_temp*") {
        Remove-Item $_.PSPath -Recurse -Force
        Write-Host "Registry profile entry removed."
    }
}
```

---

## Quick Reference

| Task | Command |
| ---- | ------- |
| Create local user | `New-LocalUser -Name "user" -Password $pass` |
| Add to Admins | `Add-LocalGroupMember -Group "Administrators" -Member "user"` |
| Disable account | `Disable-LocalUser -Name "user"` |
| Reset password | `Set-LocalUser -Name "user" -Password $pass` |
| Remove account | `Remove-LocalUser -Name "user"` |
| Remove profile | `Remove-Item "C:\Users\user" -Recurse -Force` |
| List sessions | `query user` |
