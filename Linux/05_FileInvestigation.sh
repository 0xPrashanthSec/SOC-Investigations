#!/bin/bash
# SOC - Linux File Investigation
# Hunts for malicious or suspicious files on the file system.
# Usage: sudo ./05_FileInvestigation.sh [/path/to/specific/file]
# What to look for: executables in /tmp, SUID binaries not in baseline,
# world-writable files in system paths, recently modified binaries.
# Required: Run as root or with sudo.

TARGET_FILE="${1:-}"
TS=$(date -u "+%Y-%m-%d %H:%M:%S")
echo ""
echo "====================================================="
echo "  SOC LINUX FILE INVESTIGATION  |  $TS UTC"
echo "====================================================="
echo ""

# ----------------------------------------------------------
echo "[1] FILES IN SUSPICIOUS DIRECTORIES"
# ----------------------------------------------------------
# No legitimate service should run binaries from these paths
for suspdir in /tmp /dev/shm /var/tmp /run/shm; do
    if [ -d "$suspdir" ]; then
        echo "  --- $suspdir ---"
        ls -laR "$suspdir" 2>/dev/null
        echo ""
    fi
done

# ----------------------------------------------------------
echo "[2] RECENTLY MODIFIED FILES IN KEY SYSTEM DIRECTORIES (last 7 days)"
# ----------------------------------------------------------
# Any binary modified after package install is suspicious
for dir in /bin /sbin /usr/bin /usr/sbin /lib /usr/lib /etc; do
    echo "  --- $dir (modified in last 7 days) ---"
    find "$dir" -mtime -7 -type f 2>/dev/null | head -20
    echo ""
done

# ----------------------------------------------------------
echo "[3] SUID AND SGID BINARIES"
# ----------------------------------------------------------
# Compare against known baseline. New SUID binaries = privilege escalation
echo "  --- All SUID binaries ---"
find / -perm -4000 -type f 2>/dev/null | sort
echo ""
echo "  --- All SGID binaries ---"
find / -perm -2000 -type f 2>/dev/null | sort
echo ""

# ----------------------------------------------------------
echo "[4] WORLD-WRITABLE FILES IN SYSTEM PATHS"
# ----------------------------------------------------------
# An attacker can modify these to persist or escalate privileges
find /etc /usr/bin /usr/sbin /bin /sbin -perm -o+w -type f 2>/dev/null
echo ""

# ----------------------------------------------------------
echo "[5] HIDDEN FILES AND DIRECTORIES (dot files outside home dirs)"
# ----------------------------------------------------------
# Rootkits and droppers hide in unexpected dot directories
find /tmp /var /run /dev -name ".*" -not -name ".." 2>/dev/null | head -30
echo ""

# ----------------------------------------------------------
echo "[6] RECENTLY CREATED EXECUTABLES (last 7 days, anywhere)"
# ----------------------------------------------------------
find / -perm /111 -newer /tmp/.soc_7d_ref -type f 2>/dev/null | \
    grep -v -E "^/proc/|^/sys/|^/dev/" | head -40 || \
find /home /tmp /var /srv /opt -mtime -7 -perm /111 -type f 2>/dev/null | head -40
echo ""

# ----------------------------------------------------------
echo "[7] STRINGS OUTPUT FOR SUSPICIOUS FILES IN /tmp"
# ----------------------------------------------------------
# Look for: IPs, URLs, base64 strings, common C2 indicators
for f in $(find /tmp /dev/shm /var/tmp -type f 2>/dev/null); do
    filetype=$(file "$f" 2>/dev/null)
    echo "  --- $f: $filetype ---"
    if echo "$filetype" | grep -qE "ELF|script|executable"; then
        strings "$f" 2>/dev/null | grep -E "(http|https|ftp|/bin/bash|/bin/sh|chmod|wget|curl|nc |ncat|socat|\.[0-9]+\.[0-9]+\.[0-9]+)" | head -20
    fi
    echo ""
done

# ----------------------------------------------------------
echo "[8] INVESTIGATE SPECIFIC FILE"
# ----------------------------------------------------------
if [ -n "$TARGET_FILE" ] && [ -f "$TARGET_FILE" ]; then
    echo "  File       : $TARGET_FILE"
    echo "  Type       : $(file "$TARGET_FILE")"
    echo "  SHA256     : $(sha256sum "$TARGET_FILE" | awk '{print $1}')"
    echo "  MD5        : $(md5sum "$TARGET_FILE" 2>/dev/null | awk '{print $1}')"
    echo "  Size       : $(stat -c '%s bytes, modified %y' "$TARGET_FILE")"
    echo "  Owner      : $(stat -c '%U:%G perms=%a' "$TARGET_FILE")"
    echo ""
    echo "  --- Strings (first 40 interesting lines) ---"
    strings "$TARGET_FILE" 2>/dev/null | grep -E "http|ip|pass|key|token|exec|bash|sh|curl|wget" | head -40
    echo ""
    echo "  --- Linked libraries ---"
    ldd "$TARGET_FILE" 2>/dev/null
    echo ""
    SHA=$(sha256sum "$TARGET_FILE" | awk '{print $1}')
    echo "  VirusTotal lookup: https://www.virustotal.com/gui/file/$SHA"
else
    echo "  No target file specified. Run as: sudo ./05_FileInvestigation.sh /path/to/file"
fi

echo ""
echo "====================================================="
echo "  FILE DONE => Run 06_LogCollection.sh next"
echo "====================================================="
