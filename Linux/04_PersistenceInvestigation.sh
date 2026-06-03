#!/bin/bash
# =============================================================
# Author  : 0xPrashanthSec
# GitHub  : https://github.com/0xPrashanthSec
# Purpose : SOC Incident Response Toolkit
# License : For authorized, safe, and educational use only.
#           Do NOT run against systems you do not own or have
#           explicit written permission to investigate.
# =============================================================
# SOC - Linux Persistence Investigation
# Enumerates all persistence mechanisms on Linux.
# What to look for: cron entries to /tmp, unexpected systemd services,
# modified shell profiles, LD_PRELOAD rootkits, unauthorized SSH keys.
# Required: Run as root or with sudo.

TS=$(date -u "+%Y-%m-%d %H:%M:%S")
echo ""
echo "====================================================="
echo "  SOC LINUX PERSISTENCE INVESTIGATION  |  $TS UTC"
echo "====================================================="
echo ""

# ----------------------------------------------------------
echo "[1] ROOT CRONTAB"
# ----------------------------------------------------------
echo "  --- /var/spool/cron/crontabs/root ---"
crontab -l 2>/dev/null || cat /var/spool/cron/crontabs/root 2>/dev/null || echo "  No root crontab"
echo ""

# ----------------------------------------------------------
echo "[2] ALL USER CRONTABS"
# ----------------------------------------------------------
for user in $(cut -f1 -d: /etc/passwd); do
    tab=$(crontab -l -u "$user" 2>/dev/null)
    if [ -n "$tab" ]; then
        echo "  --- User: $user ---"
        echo "$tab"
        echo ""
    fi
done

# ----------------------------------------------------------
echo "[3] SYSTEM CRON DIRECTORIES"
# ----------------------------------------------------------
for crondir in /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /etc/crontab; do
    if [ -e "$crondir" ]; then
        echo "  --- $crondir ---"
        if [ -f "$crondir" ]; then
            cat "$crondir"
        else
            ls -la "$crondir"
            for f in "$crondir"/*; do
                [ -f "$f" ] && echo "  File: $f" && cat "$f" && echo ""
            done
        fi
        echo ""
    fi
done

# ----------------------------------------------------------
echo "[4] SYSTEMD SERVICES - ENABLED"
# ----------------------------------------------------------
# Unknown enabled services, especially with binaries in /tmp or /home = persistence
systemctl list-units --type=service --state=running --no-pager 2>/dev/null | head -40
echo ""
echo "  --- Non-standard service unit files ---"
systemctl list-unit-files --type=service --state=enabled --no-pager 2>/dev/null | \
    grep -v "^lib\|^proc\|^sys\|snap\|NetworkManager\|ssh\|cron\|rsyslog\|systemd\|dbus\|getty\|autologin\|polkit\|udev\|plymouth\|apparmor\|snapd\|cups\|avahi\|ModemManager\|wpa_supplicant\|bluetooth\|thermald\|multipathd\|irq\|kdump" | \
    head -40
echo ""

# ----------------------------------------------------------
echo "[5] SYSTEMD SERVICE FILES IN SUSPICIOUS PATHS"
# ----------------------------------------------------------
# Legitimate services live in /lib/systemd or /usr/lib/systemd, not /tmp or home dirs
find /etc/systemd /home /tmp /var/tmp -name "*.service" 2>/dev/null | while read f; do
    echo "  FOUND: $f"
    cat "$f"
    echo ""
done

# ----------------------------------------------------------
echo "[6] SHELL PROFILE MODIFICATIONS"
# ----------------------------------------------------------
# Malware appends to shell profiles to execute on login
for profile in /etc/profile /etc/bashrc /etc/bash.bashrc /etc/environment; do
    if [ -f "$profile" ]; then
        echo "  --- $profile (last 20 lines) ---"
        tail -20 "$profile"
        echo ""
    fi
done

echo "  --- Per-user shell profiles ---"
for homedir in /home/* /root; do
    for profile in .bashrc .bash_profile .profile .zshrc .bash_logout; do
        f="$homedir/$profile"
        if [ -f "$f" ]; then
            echo "  --- $f ---"
            cat "$f"
            echo ""
        fi
    done
done

# ----------------------------------------------------------
echo "[7] LD_PRELOAD - LIBRARY HIJACKING"
# ----------------------------------------------------------
# Any entry here = a library loaded before everything else (rootkit technique)
echo "  --- /etc/ld.so.preload ---"
cat /etc/ld.so.preload 2>/dev/null || echo "  File does not exist (good)"
echo "  --- LD_PRELOAD env var in running processes ---"
for pid in $(ls /proc | grep -E '^[0-9]+$'); do
    env=$(cat /proc/$pid/environ 2>/dev/null | tr '\0' '\n' | grep "^LD_PRELOAD=")
    if [ -n "$env" ]; then
        comm=$(cat /proc/$pid/comm 2>/dev/null)
        echo "  PID=$pid ($comm): $env"
    fi
done
echo ""

# ----------------------------------------------------------
echo "[8] AUTHORIZED SSH KEYS"
# ----------------------------------------------------------
# Unexpected public keys = attacker backdoor
for homedir in /root /home/*; do
    keyfile="$homedir/.ssh/authorized_keys"
    if [ -f "$keyfile" ]; then
        echo "  --- $keyfile ---"
        cat "$keyfile"
        echo ""
    fi
done

# ----------------------------------------------------------
echo "[9] /ETC/RC.LOCAL AND INIT.D"
# ----------------------------------------------------------
cat /etc/rc.local 2>/dev/null && echo ""
ls -la /etc/init.d/ 2>/dev/null | head -20

# ----------------------------------------------------------
echo "[10] RECENTLY MODIFIED SYSTEM FILES (last 48 hours)"
# ----------------------------------------------------------
# Focus on critical directories where persistence lives
find /etc /usr/bin /usr/sbin /bin /sbin -newer /tmp/.soc_ref -type f 2>/dev/null | head -30 || \
find /etc /usr/bin /usr/sbin -mtime -2 -type f 2>/dev/null | head -30
echo ""

echo "====================================================="
echo "  PERSISTENCE DONE => Run 05_FileInvestigation.sh next"
echo "====================================================="
