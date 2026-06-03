# macOS User Account Management

> **SOC Use Case:** Create a temporary account for investigation access on a remote Mac, perform the work, then fully clean up when done.
> All commands require **root** or **sudo**. macOS uses `dscl` (Directory Service Command Line) to manage local accounts.

---

## Create a Local User Account

```bash
# Step 1: Create the user record
sudo dscl . -create /Users/soc_temp

# Step 2: Set the login shell
sudo dscl . -create /Users/soc_temp UserShell /bin/bash

# Step 3: Set full name (display name)
sudo dscl . -create /Users/soc_temp RealName "SOC Temp"

# Step 4: Assign a unique UID (check existing UIDs first: dscl . -list /Users UniqueID)
sudo dscl . -create /Users/soc_temp UniqueID 510
sudo dscl . -create /Users/soc_temp PrimaryGroupID 20   # 20 = staff group (standard user)

# Step 5: Set the home directory path
sudo dscl . -create /Users/soc_temp NFSHomeDirectory /Users/soc_temp

# Step 6: Set the password
sudo dscl . -passwd /Users/soc_temp "TempP@ss123!"

# Step 7: Create and populate the home directory
sudo createhomedir -c -u soc_temp

# Verify account exists
dscl . read /Users/soc_temp
id soc_temp
```

---

## Create Account Using sysadminctl (macOS 10.10+, Simpler)

```bash
# Create a standard user
sudo sysadminctl -addUser soc_temp -fullName "SOC Temp" -password "TempP@ss123!"

# Create an administrator account
sudo sysadminctl -addUser soc_temp -fullName "SOC Temp" -password "TempP@ss123!" -admin

# Verify
dscl . read /Users/soc_temp UniqueID UserShell
```

---

## Add User to the Admin Group

```bash
# Grant admin rights (allows sudo and system preferences changes)
sudo dscl . -append /Groups/admin GroupMembership soc_temp

# Verify admin group members
dscl . read /Groups/admin GroupMembership

# Remove from admin group without deleting the account
sudo dscl . -delete /Groups/admin GroupMembership soc_temp
```

---

## Grant Specific Sudo Privileges

```bash
# Create a sudoers file scoped to this account only
sudo visudo -f /etc/sudoers.d/soc_temp

# Inside the file, paste one of these:
# Full sudo with password:
#   soc_temp ALL=(ALL) ALL
# Full sudo without password:
#   soc_temp ALL=(ALL) NOPASSWD: ALL
# Specific tools only (recommended for SOC work):
#   soc_temp ALL=(root) NOPASSWD: /usr/sbin/tcpdump, /usr/bin/lsof, /bin/ps

# Verify syntax is valid
sudo visudo -c -f /etc/sudoers.d/soc_temp
```

---

## Reset a User Password

```bash
# Method 1: dscl (works while logged in as another admin)
sudo dscl . -passwd /Users/soc_temp "NewP@ss456!"

# Method 2: sysadminctl
sudo sysadminctl -resetPasswordFor soc_temp -newPassword "NewP@ss456!"

# Method 3: passwd (if you can run as the user or as root)
sudo passwd soc_temp

# Force password change at next login
sudo pwpolicy -u soc_temp -setpolicy "isDisabled=0 newPasswordRequired=1"
```

---

## List All Users and Active Sessions

```bash
# List all non-system user accounts
dscl . list /Users | grep -v "^_"

# Full details of a specific user
dscl . read /Users/soc_temp

# List all accounts with UIDs (UID >= 500 are regular users)
dscl . -list /Users UniqueID | awk '$2 >= 500' | sort -k2 -n

# Currently logged-in users
who
w

# Login history (last 30)
last -n 30

# All users and their admin status
dscl . -list /Groups GroupMembership | grep admin
```

---

## Disable (Lock) an Account Without Deleting It

```bash
# Method 1: Change shell to /usr/bin/false (blocks interactive login)
sudo dscl . -change /Users/soc_temp UserShell /bin/bash /usr/bin/false

# Method 2: Remove authentication authority (disables all auth methods)
sudo dscl . -delete /Users/soc_temp AuthenticationAuthority

# Method 3: sysadminctl (macOS 10.10+)
sudo sysadminctl -disableUser soc_temp

# Kill any active sessions
sudo pkill -KILL -u soc_temp

# Re-enable by restoring the shell
sudo dscl . -change /Users/soc_temp UserShell /usr/bin/false /bin/bash
sudo sysadminctl -enableUser soc_temp
```

---

## Cleanup — Full Account Removal

```bash
# Step 1: Kill all active processes for this user
sudo pkill -KILL -u soc_temp

# Step 2: Verify no processes remain
ps -u soc_temp 2>/dev/null

# Step 3: Remove user from admin group (if added)
sudo dscl . -delete /Groups/admin GroupMembership soc_temp 2>/dev/null

# Step 4: Delete the user record from Directory Services
sudo dscl . -delete /Users/soc_temp

# Step 5: Remove the home directory
sudo rm -rf /Users/soc_temp

# Step 6: Remove any sudoers file created for this account
sudo rm -f /etc/sudoers.d/soc_temp

# Step 7: Verify the account is gone
dscl . list /Users | grep soc_temp
id soc_temp 2>&1
```

---

## Cleanup — Remove Leftover Data

```bash
# Remove any cron jobs left by the user
sudo crontab -r -u soc_temp 2>/dev/null

# Remove LaunchAgents placed by the user
sudo rm -rf /Users/soc_temp/Library/LaunchAgents 2>/dev/null

# Remove SSH authorized keys
sudo rm -rf /Users/soc_temp/.ssh 2>/dev/null

# Remove any files still owned by that UID on the system
# First get the UID that was assigned
UID_NUM=$(dscl . read /Users/soc_temp UniqueID 2>/dev/null | awk '{print $2}')
# After account deletion, find orphaned files by UID number
sudo find /Users /tmp /private/var -uid "$UID_NUM" 2>/dev/null | head -20
# Review and remove if confirmed:
# sudo find / -uid "$UID_NUM" -delete 2>/dev/null

# Remove from Finder/login window (clear cached user icon)
sudo defaults delete /Library/Preferences/com.apple.loginwindow "lastUser" 2>/dev/null
```

---

## Quick Reference

| Task | Command |
| ---- | ------- |
| Create user (simple) | `sysadminctl -addUser soc_temp -password "pass"` |
| Create user (full) | `dscl . -create /Users/soc_temp` + steps above |
| Set password | `dscl . -passwd /Users/soc_temp "pass"` |
| Add to admin group | `dscl . -append /Groups/admin GroupMembership soc_temp` |
| Disable login | `dscl . -delete /Users/soc_temp AuthenticationAuthority` |
| Kill user sessions | `pkill -KILL -u soc_temp` |
| Delete user record | `dscl . -delete /Users/soc_temp` |
| Remove home dir | `rm -rf /Users/soc_temp` |
| Remove sudoers file | `rm /etc/sudoers.d/soc_temp` |
| Verify removal | `dscl . list /Users | grep soc_temp` |
