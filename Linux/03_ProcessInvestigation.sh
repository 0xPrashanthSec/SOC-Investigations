#!/bin/bash
# SOC - Linux Process Investigation
# Enumerates running processes and flags suspicious behavior.
# What to look for: processes in /tmp or /dev/shm, processes with deleted
# executables, processes masquerading with spaces in names, unusual parents.
# Required: Run as root or with sudo.

TS=$(date -u "+%Y-%m-%d %H:%M:%S")
echo ""
echo "====================================================="
echo "  SOC LINUX PROCESS INVESTIGATION  |  $TS UTC"
echo "====================================================="
echo ""

# ----------------------------------------------------------
echo "[1] FULL PROCESS TREE"
# ----------------------------------------------------------
# Look for: unusual parent-child relationships (e.g., apache spawning bash)
ps auxf 2>/dev/null || ps -ef
echo ""

# ----------------------------------------------------------
echo "[2] PROCESSES RUNNING FROM SUSPICIOUS PATHS"
# ----------------------------------------------------------
# Executables in /tmp, /dev/shm, /var/tmp should never be there
echo "  --- Processes from /tmp, /dev/shm, /var/tmp ---"
for pid in $(ls /proc | grep -E '^[0-9]+$'); do
    exe=$(readlink /proc/$pid/exe 2>/dev/null)
    if echo "$exe" | grep -qE "^/tmp/|^/dev/shm/|^/var/tmp/|^/run/"; then
        cmdline=$(cat /proc/$pid/cmdline 2>/dev/null | tr '\0' ' ')
        user=$(stat -c '%U' /proc/$pid 2>/dev/null)
        echo "  PID=$pid USER=$user EXE=$exe CMD=$cmdline"
    fi
done
echo ""

# ----------------------------------------------------------
echo "[3] PROCESSES WITH DELETED EXECUTABLES (fileless malware indicator)"
# ----------------------------------------------------------
# A process whose binary has been deleted = fileless or cleanup attempt
ls -la /proc/*/exe 2>/dev/null | grep "(deleted)"
echo ""

# ----------------------------------------------------------
echo "[4] PROCESSES WITH UNUSUAL NAMES (spaces, dots, common names spoofed)"
# ----------------------------------------------------------
# Malware often uses names like 'kworker ' (trailing space) or '.systemd'
ps aux 2>/dev/null | awk '{print $11}' | grep -E '^\.|^ | $| {2}' | head -20
echo ""

# ----------------------------------------------------------
echo "[5] PROCESSES RUNNING AS ROOT (non-system)"
# ----------------------------------------------------------
# Any unexpected process running as root is a privilege escalation indicator
ps aux | awk '$1=="root" {print}' | grep -v -E "^root +1 |kthread|migration|watchdog|ksoftirq|kworker|rcu_|sched|cpuhp|netns|khungtaskd|oom_|writeback|kblockd|kcompactd|kswapd|jbd2|ext4|systemd|sshd|cron|rsyslog|auditd|dbus|polkit|NetworkManager|dhclient|bash|login|getty|agetty|init|kernel" | head -30
echo ""

# ----------------------------------------------------------
echo "[6] OPEN FILES BY PROCESS (lsof highlights)"
# ----------------------------------------------------------
# Look for processes with open files in /tmp or unusual locations
lsof 2>/dev/null | grep -E "^.*(tmp|shm|run|proc|deleted).*" | head -30
echo ""

# ----------------------------------------------------------
echo "[7] PROCESSES INJECTED INTO (via ptrace or /proc/mem access)"
# ----------------------------------------------------------
# Check for active ptrace attachments - debugger or injection
for pid in $(ls /proc | grep -E '^[0-9]+$'); do
    tracer=$(grep -m1 "TracerPid" /proc/$pid/status 2>/dev/null | awk '{print $2}')
    if [ -n "$tracer" ] && [ "$tracer" != "0" ]; then
        pname=$(cat /proc/$pid/comm 2>/dev/null)
        tname=$(cat /proc/$tracer/comm 2>/dev/null)
        echo "  TRACED: PID=$pid ($pname) by PID=$tracer ($tname)"
    fi
done
echo ""

# ----------------------------------------------------------
echo "[8] SHA256 HASHES OF PROCESSES IN SUSPICIOUS PATHS"
# ----------------------------------------------------------
# Submit to VirusTotal: https://www.virustotal.com/gui/file/<hash>
for pid in $(ls /proc | grep -E '^[0-9]+$'); do
    exe=$(readlink /proc/$pid/exe 2>/dev/null)
    if echo "$exe" | grep -qE "^/tmp/|^/dev/shm/|^/var/tmp/" && [ -f "$exe" ]; then
        hash=$(sha256sum "$exe" 2>/dev/null | awk '{print $1}')
        echo "  PID=$pid SHA256=$hash PATH=$exe"
    fi
done
echo ""

# ----------------------------------------------------------
echo "[9] RECENTLY STARTED PROCESSES (via /proc stat)"
# ----------------------------------------------------------
# Processes that started recently after the incident timestamp
BOOT_TIME=$(grep btime /proc/stat | awk '{print $2}')
for pid in $(ls /proc | grep -E '^[0-9]+$'); do
    starttime=$(awk '{print $22}' /proc/$pid/stat 2>/dev/null)
    if [ -n "$starttime" ]; then
        CLK_TCK=$(getconf CLK_TCK 2>/dev/null || echo 100)
        start_epoch=$((BOOT_TIME + starttime / CLK_TCK))
        now=$(date +%s)
        age=$((now - start_epoch))
        if [ $age -lt 3600 ]; then  # started in last 1 hour
            comm=$(cat /proc/$pid/comm 2>/dev/null)
            exe=$(readlink /proc/$pid/exe 2>/dev/null)
            echo "  PID=$pid COMM=$comm AGE=${age}s EXE=$exe"
        fi
    fi
done 2>/dev/null | head -30
echo ""

echo "====================================================="
echo "  PROCESS DONE => Run 04_PersistenceInvestigation.sh next"
echo "====================================================="
