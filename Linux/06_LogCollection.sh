#!/bin/bash
# =============================================================
# Author  : 0xPrashanthSec
# GitHub  : https://github.com/0xPrashanthSec
# Purpose : SOC Incident Response Toolkit
# License : For authorized, safe, and educational use only.
#           Do NOT run against systems you do not own or have
#           explicit written permission to investigate.
# =============================================================
# SOC - Linux Log Collection
# Collects and analyzes key security logs.
# Output is saved to /tmp/soc_logs_<timestamp>/ for export.
# Key log files:
#   /var/log/auth.log or /var/log/secure  - SSH, sudo, authentication
#   /var/log/syslog or /var/log/messages  - General system events
#   /var/log/kern.log                     - Kernel events
#   journalctl                            - systemd journal (modern systems)
# Required: Run as root or with sudo.

TS=$(date -u "+%Y-%m-%d %H:%M:%S")
OUTDIR="/tmp/soc_logs_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"

echo ""
echo "====================================================="
echo "  SOC LINUX LOG COLLECTION  |  $TS UTC"
echo "  Output: $OUTDIR"
echo "====================================================="
echo ""

# ----------------------------------------------------------
echo "[1] AUTHENTICATION LOG - RECENT 100 LINES"
# ----------------------------------------------------------
# SSH brute force, sudo abuse, PAM failures
AUTHLOG=""
for log in /var/log/auth.log /var/log/secure; do
    if [ -f "$log" ]; then
        AUTHLOG="$log"
        break
    fi
done

if [ -n "$AUTHLOG" ]; then
    echo "  Source: $AUTHLOG"
    echo ""
    echo "  --- Failed SSH logins ---"
    grep -E "Failed password|Invalid user|authentication failure" "$AUTHLOG" | tail -30 | tee "$OUTDIR/failed_ssh.txt"
    echo ""
    echo "  --- Successful SSH logins ---"
    grep -E "Accepted password|Accepted publickey" "$AUTHLOG" | tail -30 | tee "$OUTDIR/successful_ssh.txt"
    echo ""
    echo "  --- Sudo usage ---"
    grep "sudo:" "$AUTHLOG" | tail -30 | tee "$OUTDIR/sudo_usage.txt"
    echo ""
    echo "  --- New users / group changes ---"
    grep -E "useradd|usermod|groupadd|passwd" "$AUTHLOG" | tail -20 | tee "$OUTDIR/user_changes.txt"
    echo ""
    cp "$AUTHLOG" "$OUTDIR/auth.log.bak" 2>/dev/null
else
    echo "  auth.log/secure not found. Trying journalctl..."
    journalctl -u ssh -u sshd --since "24 hours ago" --no-pager 2>/dev/null | tail -50 | tee "$OUTDIR/ssh_journal.txt"
fi

# ----------------------------------------------------------
echo "[2] SYSLOG / MESSAGES"
# ----------------------------------------------------------
SYSLOG=""
for log in /var/log/syslog /var/log/messages; do
    if [ -f "$log" ]; then
        SYSLOG="$log"
        break
    fi
done

if [ -n "$SYSLOG" ]; then
    echo "  Source: $SYSLOG"
    tail -100 "$SYSLOG" | tee "$OUTDIR/syslog.txt"
    echo ""
else
    journalctl --since "24 hours ago" --no-pager 2>/dev/null | tail -100 | tee "$OUTDIR/journal.txt"
fi

# ----------------------------------------------------------
echo "[3] KERNEL LOG"
# ----------------------------------------------------------
# Module loads, segfaults, OOM kills can indicate exploitation
echo "  --- Recent kernel messages ---"
dmesg | tail -50 | tee "$OUTDIR/dmesg.txt"
echo ""
echo "  --- Module loads ---"
dmesg | grep -E "module|insmod|rmmod|loaded" | tail -20
echo ""

# ----------------------------------------------------------
echo "[4] LAST LOGINS"
# ----------------------------------------------------------
echo "  --- last (successful logins) ---"
last -n 50 -i 2>/dev/null | tee "$OUTDIR/last.txt"
echo ""
echo "  --- lastb (failed logins) ---"
lastb -n 50 -i 2>/dev/null | tee "$OUTDIR/lastb.txt" || \
    echo "  lastb requires /var/log/btmp and root access"
echo ""

# ----------------------------------------------------------
echo "[5] SYSTEMD JOURNAL - LAST 200 ENTRIES"
# ----------------------------------------------------------
journalctl -n 200 --no-pager 2>/dev/null | tee "$OUTDIR/journal_recent.txt"
echo ""

# ----------------------------------------------------------
echo "[6] CRON LOGS"
# ----------------------------------------------------------
echo "  --- Cron execution log ---"
grep -E "CRON|cron" "${SYSLOG:-/var/log/syslog}" 2>/dev/null | tail -30 | tee "$OUTDIR/cron_log.txt" || \
    journalctl -u cron --since "7 days ago" --no-pager 2>/dev/null | tail -30 | tee "$OUTDIR/cron_log.txt"
echo ""

# ----------------------------------------------------------
echo "[7] AUDIT LOG (if auditd running)"
# ----------------------------------------------------------
if command -v ausearch &>/dev/null; then
    echo "  --- Recent login failures ---"
    ausearch -m USER_LOGIN -sv no 2>/dev/null | tail -30 | tee "$OUTDIR/audit_failed_login.txt"
    echo ""
    echo "  --- Privilege escalation events ---"
    ausearch -m USER_ROLE_CHANGE,ROLE_ASSIGN 2>/dev/null | tail -20 | tee "$OUTDIR/audit_priv_esc.txt"
    echo ""
    echo "  --- File execution events ---"
    ausearch -m EXECVE --start recent 2>/dev/null | tail -30 | tee "$OUTDIR/audit_exec.txt"
fi

# ----------------------------------------------------------
echo "[8] WTMP AND BTMP (binary login records)"
# ----------------------------------------------------------
if [ -f /var/log/wtmp ]; then
    echo "  --- wtmp (all logins, reboots) ---"
    last -f /var/log/wtmp -n 50 2>/dev/null | tee "$OUTDIR/wtmp.txt"
fi
echo ""

# ----------------------------------------------------------
echo "[9] SUSPICIOUS LOG PATTERNS (cross-log search)"
# ----------------------------------------------------------
echo "  --- Base64-encoded commands in any log ---"
grep -rE "[A-Za-z0-9+/]{50,}={0,2}" /var/log/auth.log /var/log/syslog 2>/dev/null | head -10
echo ""
echo "  --- Wget/curl in logs ---"
grep -rE "wget|curl" /var/log/ 2>/dev/null | grep -v "Binary" | head -20
echo ""

echo "====================================================="
echo "  LOGS SAVED TO: $OUTDIR"
echo "  LOGS DONE => Run 07_UserAccountInvestigation.sh next"
echo "====================================================="
