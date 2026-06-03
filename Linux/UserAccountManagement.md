# Linux User Account Management

> **SOC Use Case:** Create a temporary account for investigation access on a remote Linux machine, perform the work, then fully clean up when done.
> All commands require **root** or **sudo**.

---

## Create a Local User Account

```bash
# Create account with home directory and bash shell
sudo useradd -m -s /bin/bash soc_temp

# Set the password (interactive prompt)
sudo passwd soc_temp

# OR set password non-interactively (useful in scripts)
echo "soc_temp:TempP@ss123!" | sudo chpasswd

# Verify account was created
id soc_temp
getent passwd soc_temp
```

---

## Create Account with Specific UID or Home Directory

```bash
# Create with a specific UID (useful to avoid conflicts)
sudo useradd -m -u 9001 -s /bin/bash -c "SOC Temp Account" soc_temp

# Create with a custom home directory path
sudo useradd -m -d /home/soc_temp -s /bin/bash soc_temp

# Create a system account (no home dir, no login shell — for service investigation only)
sudo useradd -r -s /usr/sbin/nologin soc_service
```

---

## Add User to Groups

```bash
# Add to the sudo group (gives full sudo access — only if required)
sudo usermod -aG sudo soc_temp      # Debian/Ubuntu
sudo usermod -aG wheel soc_temp     # RHEL/CentOS/Fedora

# Add to a specific group (e.g., adm gives read access to most logs)
sudo usermod -aG adm soc_temp

# Add to multiple groups at once
sudo usermod -aG sudo,adm,docker soc_temp

# Verify group membership
groups soc_temp
id soc_temp
```

---

## Grant Specific Sudo Privileges (Without Full Admin)

```bash
# Create a sudoers file scoped to this account only
sudo visudo -f /etc/sudoers.d/soc_temp

# Inside the file, add one of these:
# Full sudo access:
#   soc_temp ALL=(ALL:ALL) ALL
# No-password sudo:
#   soc_temp ALL=(ALL) NOPASSWD: ALL
# Specific commands only:
#   soc_temp ALL=(root) NOPASSWD: /usr/bin/tcpdump, /bin/netstat, /usr/bin/ss

# Verify sudoers syntax before saving
sudo visudo -c -f /etc/sudoers.d/soc_temp
```

---

## Unlock or Reset Password

```bash
# Reset password (interactive)
sudo passwd soc_temp

# Reset password non-interactively
echo "soc_temp:NewP@ss456!" | sudo chpasswd

# Unlock a locked account (locked with -L flag)
sudo usermod -U soc_temp

# Force password change at next login
sudo chage -d 0 soc_temp

# Check account expiry and password info
sudo chage -l soc_temp
```

---

## List All Users and Active Sessions

```bash
# All accounts with login shells
grep -E "/bin/bash|/bin/sh|/bin/zsh" /etc/passwd

# All accounts (UID >= 1000 are regular users on most distros)
awk -F: '$3 >= 1000 && $3 < 65534 {print $1, $3, $7}' /etc/passwd

# Currently logged-in users
who
w

# Login history (last 30)
last -n 30

# Failed login attempts
lastb -n 20 2>/dev/null || grep "Failed password" /var/log/auth.log | tail -20
```

---

## Lock an Account (Temporary Suspend Without Deleting)

```bash
# Lock the account (prepends ! to password hash in /etc/shadow)
sudo usermod -L soc_temp

# Also expire the account so it cannot log in
sudo usermod -e 1 soc_temp      # Set expiry to Jan 1, 1970 (effectively expired)

# Kill all active sessions for that user
sudo pkill -KILL -u soc_temp

# Unlock when needed
sudo usermod -U soc_temp
sudo usermod -e "" soc_temp     # Remove expiry
```

---

## Cleanup — Full Account Removal

```bash
# Step 1: Kill all active processes for this user
sudo pkill -KILL -u soc_temp

# Step 2: Verify no processes remain
ps -u soc_temp

# Step 3: Remove user AND home directory
sudo userdel -r soc_temp

# If userdel -r fails because home dir is on a separate mount:
sudo userdel soc_temp
sudo rm -rf /home/soc_temp

# Step 4: Remove any sudoers entry
sudo rm -f /etc/sudoers.d/soc_temp

# Step 5: Remove from any additional groups
# (userdel handles this automatically, but double-check)
grep "soc_temp" /etc/group

# Step 6: Verify account is gone
id soc_temp 2>&1
getent passwd soc_temp
```

---

## Cleanup — Remove Leftover Files and Cron Jobs

```bash
# Remove any cron jobs left by the user
sudo crontab -r -u soc_temp 2>/dev/null

# Remove any mail spool
sudo rm -f /var/mail/soc_temp /var/spool/mail/soc_temp

# Remove any SSH authorized keys (in case home dir already removed)
sudo rm -rf /home/soc_temp/.ssh 2>/dev/null

# Check for any files owned by the user that remain on the system
sudo find / -user soc_temp -type f 2>/dev/null | head -20
# If any found, review and remove:
# sudo find / -user soc_temp -type f -delete 2>/dev/null
```

---

## Quick Reference

| Task | Command |
| ---- | ------- |
| Create user with home | `useradd -m -s /bin/bash soc_temp` |
| Set password | `passwd soc_temp` |
| Add to sudo group | `usermod -aG sudo soc_temp` |
| Lock account | `usermod -L soc_temp` |
| Kill user sessions | `pkill -KILL -u soc_temp` |
| Delete account + home | `userdel -r soc_temp` |
| Remove sudoers file | `rm /etc/sudoers.d/soc_temp` |
| Verify removal | `id soc_temp` |
