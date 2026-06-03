#!/bin/bash
# SOC - Linux User Account Investigation
# Audits all user accounts, sudo access, SSH keys, and login history.
# What to look for: accounts with UID 0 (other than root), unexpected sudo access,
# accounts with no password, recently added accounts, unauthorized SSH keys.
# Required: Run as root or with sudo.

TS=$(date -u "+%Y-%m-%d %H:%M:%S")
echo ""
echo "====================================================="
echo "  SOC LINUX USER ACCOUNT INVESTIGATION  |  $TS UTC"
echo "====================================================="
echo ""

# ----------------------------------------------------------
echo "[1] ALL USER ACCOUNTS"
# ----------------------------------------------------------
# Accounts with UID 0 other than root = backdoor account
echo "  --- /etc/passwd (format: user:x:uid:gid:comment:home:shell) ---"
cat /etc/passwd
echo ""
echo "  --- Accounts with UID 0 (should ONLY be root) ---"
awk -F: '$3 == 0 {print "  ALERT: " $1 " has UID 0!"}' /etc/passwd
echo ""

# ----------------------------------------------------------
echo "[2] ACCOUNTS WITH LOGIN SHELLS"
# ----------------------------------------------------------
# Accounts with /bin/bash or /bin/sh can be used for remote login
echo "  --- Accounts with interactive shells ---"
grep -E "/bin/bash|/bin/sh|/bin/zsh|/usr/bin/zsh" /etc/passwd
echo ""

# ----------------------------------------------------------
echo "[3] LOCKED AND DISABLED ACCOUNTS"
# ----------------------------------------------------------
echo "  --- Locked accounts (! or * in shadow) ---"
awk -F: '$2 ~ /^!|^\*/ {print "  LOCKED: " $1}' /etc/shadow 2>/dev/null || \
    echo "  Cannot read /etc/shadow (need root)"
echo ""
echo "  --- Accounts with no password (DANGEROUS) ---"
awk -F: '$2 == "" {print "  NO PASSWORD: " $1}' /etc/shadow 2>/dev/null
echo ""

# ----------------------------------------------------------
echo "[4] SUDO ACCESS"
# ----------------------------------------------------------
# Unexpected sudoers = privilege escalation backdoor
echo "  --- /etc/sudoers ---"
cat /etc/sudoers 2>/dev/null | grep -v "^#" | grep -v "^$"
echo ""
echo "  --- /etc/sudoers.d/ entries ---"
for f in /etc/sudoers.d/*; do
    if [ -f "$f" ]; then
        echo "  --- $f ---"
        cat "$f" | grep -v "^#" | grep -v "^$"
        echo ""
    fi
done
echo "  --- Members of sudo/wheel group ---"
getent group sudo wheel 2>/dev/null
echo ""

# ----------------------------------------------------------
echo "[5] LOGIN HISTORY"
# ----------------------------------------------------------
echo "  --- Last 30 successful logins ---"
last -n 30 -i 2>/dev/null || last -n 30
echo ""
echo "  --- Last 20 failed logins ---"
lastb -n 20 -i 2>/dev/null || \
    grep "Failed password" /var/log/auth.log 2>/dev/null | tail -20 || \
    grep "Failed password" /var/log/secure 2>/dev/null | tail -20
echo ""

# ----------------------------------------------------------
echo "[6] CURRENTLY LOGGED-IN USERS"
# ----------------------------------------------------------
who
echo ""
w
echo ""

# ----------------------------------------------------------
echo "[7] RECENTLY CREATED OR MODIFIED ACCOUNTS"
# ----------------------------------------------------------
# Compare /etc/passwd modification time against known good baseline
echo "  --- /etc/passwd modification time ---"
stat /etc/passwd /etc/shadow /etc/group 2>/dev/null | grep -E "File:|Modify:"
echo ""
echo "  --- Accounts created in last 7 days (from passwd mtime heuristic) ---"
find /home -maxdepth 1 -type d -newer /etc/cron.daily -mtime -7 2>/dev/null
echo ""

# ----------------------------------------------------------
echo "[8] SSH AUTHORIZED KEYS"
# ----------------------------------------------------------
# Each key here = persistent remote access channel
echo "  --- Authorized SSH keys (all users) ---"
for homedir in /root /home/*; do
    keyfile="$homedir/.ssh/authorized_keys"
    if [ -f "$keyfile" ]; then
        echo "  === $keyfile ==="
        while IFS= read -r line; do
            echo "  $line"
            keycomment=$(echo "$line" | awk '{print $NF}')
            echo "  Comment/Source: $keycomment"
        done < "$keyfile"
        echo ""
    fi
done

# ----------------------------------------------------------
echo "[9] SSH CONFIGURATION"
# ----------------------------------------------------------
echo "  --- Key SSH config options ---"
grep -E "PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|AllowUsers|DenyUsers|Port" \
    /etc/ssh/sshd_config 2>/dev/null
echo ""

# ----------------------------------------------------------
echo "[10] GROUPS AND MEMBERSHIPS"
# ----------------------------------------------------------
cat /etc/group | grep -v "^#"
echo ""

echo "====================================================="
echo "  USER ACCOUNTS DONE => Run 08_Remediation.sh if action needed"
echo "====================================================="
