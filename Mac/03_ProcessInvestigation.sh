#!/bin/bash
# SOC - macOS Process Investigation
# Enumerates all running processes and flags suspicious behavior.
# What to look for: processes from /tmp, unsigned binaries, processes
# with invalid or missing code signatures, unusual parent-child chains.
# Required: Run as root or with sudo.

TS=$(date -u "+%Y-%m-%d %H:%M:%S")
echo ""
echo "====================================================="
echo "  SOC macOS PROCESS INVESTIGATION  |  $TS UTC"
echo "====================================================="
echo ""

# ----------------------------------------------------------
echo "[1] FULL PROCESS LIST WITH PATHS"
# ----------------------------------------------------------
ps auxf 2>/dev/null || ps aux
echo ""

# ----------------------------------------------------------
echo "[2] PROCESSES RUNNING FROM SUSPICIOUS PATHS"
# ----------------------------------------------------------
# Malware on Mac commonly runs from /tmp, /var/tmp, /private/tmp, or user Downloads/Desktop
echo "  --- Suspicious path processes ---"
ps aux 2>/dev/null | awk 'NR>1{print $2, $11, $0}' | while read pid cmd line; do
    path=$(lsof -p "$pid" -a -d txt 2>/dev/null | awk 'NR>1{print $9}' | head -1)
    if echo "$path" | grep -qE "^/tmp/|^/private/tmp/|^/var/tmp/|Downloads|Desktop|/var/folders"; then
        echo "  PID=$pid PATH=$path CMD=$cmd"
    fi
done
echo ""

# ----------------------------------------------------------
echo "[3] CODE SIGNATURE VERIFICATION OF RUNNING PROCESSES"
# ----------------------------------------------------------
# Invalid or missing signatures = unsigned/tampered binary
echo "  --- Checking signatures of running processes ---"
ps aux 2>/dev/null | awk 'NR>1{print $2}' | sort -u | while read pid; do
    path=$(lsof -p "$pid" -a -d txt 2>/dev/null | awk 'NR>1{print $9}' | head -1)
    if [ -n "$path" ] && [ -f "$path" ]; then
        result=$(codesign -v "$path" 2>&1)
        if echo "$result" | grep -qE "not signed|invalid|CSSMERR"; then
            comm=$(ps -p $pid -o comm= 2>/dev/null)
            echo "  UNSIGNED/INVALID: PID=$pid Name=$comm Path=$path"
            echo "    $result"
        fi
    fi
done
echo ""

# ----------------------------------------------------------
echo "[4] PROCESSES WITH EXTERNAL NETWORK CONNECTIONS"
# ----------------------------------------------------------
lsof -i -n -P 2>/dev/null | grep ESTABLISHED | \
    grep -v "127\.0\.0\.1\|192\.168\.\|10\.\|::1"
echo ""

# ----------------------------------------------------------
echo "[5] PROCESSES STARTED IN LAST HOUR"
# ----------------------------------------------------------
# Use ps -o lstart for precise start time
echo "  --- Processes started in last 60 minutes ---"
ps -ax -o pid,lstart,comm,args 2>/dev/null | awk -v now="$(date +%s)" '
NR>1 {
    cmd="date -j -f \"%a %b %d %T %Y\" \"" $2" "$3" "$4" "$5" "$6"\" +%s 2>/dev/null"
    cmd | getline pstart
    close(cmd)
    if (now - pstart + 0 < 3600) print
}' | head -30
echo ""

# ----------------------------------------------------------
echo "[6] DYLIB INJECTION - DYLD_INSERT_LIBRARIES"
# ----------------------------------------------------------
# Mac equivalent of LD_PRELOAD - used for dylib injection attacks
echo "  --- Processes with DYLD_INSERT_LIBRARIES env var ---"
ps aux 2>/dev/null | awk 'NR>1{print $2}' | while read pid; do
    env_info=$(ps eww -p "$pid" 2>/dev/null | grep "DYLD_INSERT_LIBRARIES")
    if [ -n "$env_info" ]; then
        echo "  PID=$pid: $env_info"
    fi
done
echo ""

# ----------------------------------------------------------
echo "[7] HASHES OF PROCESSES FROM SUSPICIOUS PATHS"
# ----------------------------------------------------------
# Use SHA256 for VirusTotal submission
ps aux 2>/dev/null | awk 'NR>1{print $2}' | while read pid; do
    path=$(lsof -p "$pid" -a -d txt 2>/dev/null | awk 'NR>1{print $9}' | head -1)
    if echo "$path" | grep -qE "^/tmp/|^/private/tmp/|Downloads|Desktop" && [ -f "$path" ]; then
        hash=$(shasum -a 256 "$path" 2>/dev/null | awk '{print $1}')
        echo "  PID=$pid SHA256=$hash PATH=$path"
    fi
done
echo ""

# ----------------------------------------------------------
echo "[8] KERNEL EXTENSIONS (kexts)"
# ----------------------------------------------------------
# Unexpected kexts = rootkit or unauthorized driver
echo "  --- Loaded kernel extensions ---"
kextstat 2>/dev/null | grep -v "com.apple" | head -20
echo ""
echo "  --- All kexts (non-Apple) ---"
kextstat 2>/dev/null | awk 'NR>1{print $6}' | grep -v "com.apple" | sort
echo ""

echo "====================================================="
echo "  PROCESS DONE => Run 04_PersistenceInvestigation.sh next"
echo "====================================================="
