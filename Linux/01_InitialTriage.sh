#!/bin/bash
# =============================================================
# Author  : 0xPrashanthSec
# GitHub  : https://github.com/0xPrashanthSec
# Purpose : SOC Incident Response Toolkit
# License : For authorized, safe, and educational use only.
#           Do NOT run against systems you do not own or have
#           explicit written permission to investigate.
# =============================================================
# SOC - Linux Initial Triage
# Run FIRST on any suspected compromised Linux machine.
# Captures identity, timing, active users, and system state.
# Required: Run as root or with sudo.

TS=$(date -u "+%Y-%m-%d %H:%M:%S")
echo ""
echo "====================================================="
echo "  SOC LINUX INITIAL TRIAGE  |  $TS UTC"
echo "====================================================="
echo ""

# ----------------------------------------------------------
echo "[1] SYSTEM IDENTITY"
# ----------------------------------------------------------
echo "  Hostname  : $(hostname -f)"
echo "  Kernel    : $(uname -r)"
echo "  OS        : $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')"
echo "  Arch      : $(uname -m)"
echo "  Date(UTC) : $(date -u)"
echo ""

# ----------------------------------------------------------
echo "[2] UPTIME AND LAST BOOT"
# ----------------------------------------------------------
uptime
who -b 2>/dev/null || last reboot | head -3
echo ""

# ----------------------------------------------------------
echo "[3] NETWORK INTERFACES"
# ----------------------------------------------------------
# Multiple IPs or unexpected interfaces can indicate tunneling
ip -4 addr show 2>/dev/null || ifconfig 2>/dev/null
echo ""

# ----------------------------------------------------------
echo "[4] WHO IS LOGGED ON RIGHT NOW"
# ----------------------------------------------------------
# Multiple root sessions or unknown users = red flag
who
echo ""
echo "  --- Active sessions (w) ---"
w
echo ""

# ----------------------------------------------------------
echo "[5] LAST 20 LOGINS"
# ----------------------------------------------------------
# Look for: logins from unexpected IPs, unusual hours, unknown usernames
last -n 20 -i 2>/dev/null || last -n 20
echo ""

# ----------------------------------------------------------
echo "[6] FAILED LOGIN ATTEMPTS"
# ----------------------------------------------------------
# Brute force indicator
echo "  --- Last 20 failed logins ---"
lastb -n 20 -i 2>/dev/null || lastb -n 20 2>/dev/null || \
    grep "Failed password" /var/log/auth.log 2>/dev/null | tail -20 || \
    grep "Failed password" /var/log/secure 2>/dev/null | tail -20
echo ""

# ----------------------------------------------------------
echo "[7] TOP 15 PROCESSES BY CPU"
# ----------------------------------------------------------
# Unknown process names, processes in /tmp or /dev/shm = red flag
ps auxf --sort=-%cpu | head -20
echo ""

# ----------------------------------------------------------
echo "[8] DISK USAGE OVERVIEW"
# ----------------------------------------------------------
df -h
echo ""

echo "====================================================="
echo "  TRIAGE DONE => Run 02_NetworkInvestigation.sh next"
echo "====================================================="
