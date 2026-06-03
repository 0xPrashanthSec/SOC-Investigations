#!/bin/bash
# SOC - macOS User Account Investigation
# Audits all local user accounts, admin privileges, and login history.
# What to look for: unexpected admin accounts, hidden accounts (UID < 500),
# accounts with UID 0, unauthorized SSH keys, accounts with no password.
# Required: Run as root or with sudo.

TS=$(date -u "+%Y-%m-%d %H:%M:%S")
echo ""
echo "====================================================="
echo "  SOC macOS USER ACCOUNT INVESTIGATION  |  $TS UTC"
echo "====================================================="
echo ""

# ----------------------------------------------------------
echo "[1] ALL USER ACCOUNTS"
# ----------------------------------------------------------
# UID 0 = root equivalent. Accounts with UID < 500 are system accounts.
echo "  --- All accounts via dscl ---"
dscl . list /Users | grep -v "^_"
echo ""

echo "  --- Account details (UID, shell, home) ---"
for user in $(dscl . list /Users | grep -v "^_"); do
    uid=$(dscl . read /Users/$user UniqueID 2>/dev/null | awk '{print $2}')
    shell=$(dscl . read /Users/$user UserShell 2>/dev/null | awk '{print $2}')
    home=$(dscl . read /Users/$user NFSHomeDirectory 2>/dev/null | awk '{print $2}')
    realname=$(dscl . read /Users/$user RealName 2>/dev/null | sed 's/RealName: //' | tr -d '\n')
    if [ -n "$uid" ] && [ "$uid" -ge 500 ] 2>/dev/null; then
        echo "  User=$user UID=$uid Shell=$shell Home=$home Name=$realname"
    fi
done
echo ""

# ----------------------------------------------------------
echo "[2] ACCOUNTS WITH UID 0 (root equivalent - should ONLY be root)"
# ----------------------------------------------------------
dscl . list /Users UniqueID 2>/dev/null | awk '$2 == "0" {print "  ALERT: " $1 " has UID 0!"}'
echo ""

# ----------------------------------------------------------
echo "[3] ADMIN (WHEEL) GROUP MEMBERS"
# ----------------------------------------------------------
# Every admin user can use sudo - unexpected member = privilege escalation
echo "  --- Members of 'admin' group ---"
dscl . read /Groups/admin GroupMembership 2>/dev/null
echo ""
echo "  --- Members of 'wheel' group ---"
dscl . read /Groups/wheel GroupMembership 2>/dev/null
echo ""

# ----------------------------------------------------------
echo "[4] SUDO ACCESS"
# ----------------------------------------------------------
echo "  --- /etc/sudoers ---"
cat /etc/sudoers 2>/dev/null | grep -v "^#" | grep -v "^$"
echo ""
echo "  --- /etc/sudoers.d/ ---"
for f in /etc/sudoers.d/*; do
    if [ -f "$f" ]; then
        echo "  --- $f ---"
        cat "$f" | grep -v "^#" | grep -v "^$"
        echo ""
    fi
done

# ----------------------------------------------------------
echo "[5] LOGIN HISTORY"
# ----------------------------------------------------------
echo "  --- Last 30 successful logins ---"
last -n 30 2>/dev/null
echo ""
echo "  --- Failed logins ---"
lastb -n 20 2>/dev/null || \
    log show --predicate 'process == "SecurityAgent" AND eventMessage contains "failed"' \
        --last 24h --style syslog 2>/dev/null | tail -20
echo ""

# ----------------------------------------------------------
echo "[6] CURRENTLY LOGGED-IN USERS"
# ----------------------------------------------------------
who
echo ""
w 2>/dev/null
echo ""

# ----------------------------------------------------------
echo "[7] PASSWORD POLICY"
# ----------------------------------------------------------
pwpolicy -getaccountpolicies 2>/dev/null || \
    echo "  pwpolicy not available (pre-Catalina: use 'passwd' policy defaults)"
echo ""
echo "  --- Password hints status ---"
defaults read /Library/Preferences/com.apple.loginwindow RetriesUntilHint 2>/dev/null
echo ""

# ----------------------------------------------------------
echo "[8] ACCOUNT CREATION DATES (from home directory)"
# ----------------------------------------------------------
echo "  --- Home directory creation times ---"
for homedir in /Users/*; do
    username=$(basename "$homedir")
    if [ -d "$homedir" ]; then
        created=$(GetFileInfo -d "$homedir" 2>/dev/null || stat -f '%SB' "$homedir" 2>/dev/null)
        echo "  $username: created $created"
    fi
done
echo ""

# ----------------------------------------------------------
echo "[9] AUTHORIZED SSH KEYS"
# ----------------------------------------------------------
# Each key here is a persistent backdoor access channel
for homedir in /root /Users/*; do
    keyfile="$homedir/.ssh/authorized_keys"
    if [ -f "$keyfile" ]; then
        echo "  === $keyfile ==="
        while IFS= read -r line; do
            comment=$(echo "$line" | awk '{print $NF}')
            echo "  Key comment: $comment"
            echo "  $line"
        done < "$keyfile"
        echo ""
    fi
done

# ----------------------------------------------------------
echo "[10] SSH CONFIGURATION"
# ----------------------------------------------------------
echo "  --- Key sshd_config settings ---"
grep -E "PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|AllowUsers|DenyUsers|Port" \
    /etc/ssh/sshd_config 2>/dev/null
echo ""

echo "====================================================="
echo "  USER ACCOUNTS DONE => Run 08_Remediation.sh if action needed"
echo "====================================================="
