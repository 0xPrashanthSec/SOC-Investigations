#!/bin/bash
# =============================================================
# Author  : 0xPrashanthSec
# GitHub  : https://github.com/0xPrashanthSec
# Purpose : SOC Incident Response Toolkit
# License : For authorized, safe, and educational use only.
#           Do NOT run against systems you do not own or have
#           explicit written permission to investigate.
# =============================================================
# SOC - macOS File Investigation
# Hunts for malicious or suspicious files on macOS.
# Usage: sudo ./05_FileInvestigation.sh [/path/to/specific/file]
# What to look for: unsigned binaries, files in /tmp, quarantine metadata,
# extended attributes, recently dropped executables in user paths.
# Required: Run as root or with sudo.

TARGET_FILE="${1:-}"
TS=$(date -u "+%Y-%m-%d %H:%M:%S")
echo ""
echo "====================================================="
echo "  SOC macOS FILE INVESTIGATION  |  $TS UTC"
echo "====================================================="
echo ""

# ----------------------------------------------------------
echo "[1] FILES IN SUSPICIOUS DIRECTORIES"
# ----------------------------------------------------------
for suspdir in /tmp /private/tmp /var/tmp; do
    if [ -d "$suspdir" ]; then
        echo "  --- $suspdir ---"
        ls -laR "$suspdir" 2>/dev/null
        echo ""
    fi
done

# ----------------------------------------------------------
echo "[2] RECENTLY CREATED/MODIFIED EXECUTABLES (last 7 days)"
# ----------------------------------------------------------
# Check user-writable and common drop locations
for dir in /Users /tmp /private/tmp /Library/Application\ Support; do
    echo "  --- $dir (last 7 days, executable) ---"
    find "$dir" -mtime -7 -perm +111 -type f 2>/dev/null | \
        grep -v ".app/Contents/MacOS" | head -20
    echo ""
done

# ----------------------------------------------------------
echo "[3] QUARANTINE DATABASE (files downloaded from internet)"
# ----------------------------------------------------------
# Every file downloaded in macOS gets a quarantine xattr entry in this SQLite DB
echo "  --- Recently quarantined files (last 14 days) ---"
for homedir in /Users/*; do
    qdb="$homedir/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"
    if [ -f "$qdb" ]; then
        echo "  DB: $qdb"
        sqlite3 "$qdb" \
            "SELECT datetime(LSQuarantineTimeStamp+978307200,'unixepoch'), LSQuarantineAgentName, LSQuarantineDataURLString, LSQuarantineOriginURLString FROM LSQuarantineEvent ORDER BY LSQuarantineTimeStamp DESC LIMIT 30;" 2>/dev/null
        echo ""
    fi
done

# ----------------------------------------------------------
echo "[4] EXTENDED ATTRIBUTES (xattr) ON SUSPICIOUS FILES"
# ----------------------------------------------------------
# com.apple.quarantine is normal; com.apple.metadata:kMDItemDownloadedDate is ok
# Unknown xattrs or com.apple.security.exception entries = suspicious
for dir in /tmp /private/tmp /Users/*/Downloads /Users/*/Desktop; do
    find "$dir" -type f 2>/dev/null | while read f; do
        attrs=$(xattr "$f" 2>/dev/null)
        if [ -n "$attrs" ]; then
            echo "  $f:"
            echo "    xattrs: $attrs"
        fi
    done
done | head -60
echo ""

# ----------------------------------------------------------
echo "[5] CODE SIGNATURE CHECK ON SPECIFIC FILES"
# ----------------------------------------------------------
# Check all executables in /tmp and Downloads
for dir in /tmp /private/tmp /Users/*/Downloads /Users/*/Desktop; do
    find "$dir" -type f -perm +111 2>/dev/null | while read f; do
        result=$(codesign -v --deep "$f" 2>&1)
        if echo "$result" | grep -qE "not signed|invalid|CSSMERR|code object"; then
            echo "  UNSIGNED/INVALID: $f"
            echo "    $result"
        fi
    done
done
echo ""

# ----------------------------------------------------------
echo "[6] RECENTLY MODIFIED SYSTEM BINARIES (last 7 days)"
# ----------------------------------------------------------
# Any modification to Apple system binaries after initial install = tampering
find /usr/bin /usr/sbin /bin /sbin -mtime -7 -type f 2>/dev/null | while read f; do
    echo "  MODIFIED: $f ($(stat -f '%Sm' "$f"))"
done
echo ""

# ----------------------------------------------------------
echo "[7] BASH/ZSH HISTORY FILES"
# ----------------------------------------------------------
# Look for: base64 decode + exec, curl | sh, download stagers
for homedir in /Users/* /root; do
    for histfile in .bash_history .zsh_history; do
        f="$homedir/$histfile"
        if [ -f "$f" ]; then
            echo "  --- $f (last 30 commands) ---"
            tail -30 "$f" | while read line; do
                if echo "$line" | grep -qE "base64|curl.*sh|wget.*sh|python.*exec|chmod.*\+x|mktemp|/dev/tcp/|nc -e|ncat|socat"; then
                    echo "  [SUSPICIOUS] $line"
                else
                    echo "  $line"
                fi
            done
            echo ""
        fi
    done
done

# ----------------------------------------------------------
echo "[8] INVESTIGATE SPECIFIC FILE"
# ----------------------------------------------------------
if [ -n "$TARGET_FILE" ] && [ -f "$TARGET_FILE" ]; then
    echo "  File      : $TARGET_FILE"
    echo "  Type      : $(file "$TARGET_FILE")"
    echo "  SHA256    : $(shasum -a 256 "$TARGET_FILE" | awk '{print $1}')"
    echo "  MD5       : $(md5 -q "$TARGET_FILE" 2>/dev/null)"
    echo "  Size      : $(stat -f '%z bytes, modified %Sm' "$TARGET_FILE")"
    echo "  Owner     : $(stat -f '%Su:%Sg perms=%Sp' "$TARGET_FILE")"
    echo ""
    echo "  --- Code Signature ---"
    codesign -dv --verbose=4 "$TARGET_FILE" 2>&1 | head -20
    echo ""
    echo "  --- Gatekeeper Assessment ---"
    spctl --assess --type exec -v "$TARGET_FILE" 2>&1
    echo ""
    echo "  --- Extended Attributes ---"
    xattr -l "$TARGET_FILE" 2>/dev/null
    echo ""
    echo "  --- Strings (security-relevant) ---"
    strings "$TARGET_FILE" 2>/dev/null | grep -E "http|ip|pass|key|token|exec|bash|sh |curl|wget|openssl|base64" | head -30
    echo ""
    SHA=$(shasum -a 256 "$TARGET_FILE" | awk '{print $1}')
    echo "  VirusTotal: https://www.virustotal.com/gui/file/$SHA"
else
    echo "  No target file specified. Run as: sudo ./05_FileInvestigation.sh /path/to/file"
fi

echo ""
echo "====================================================="
echo "  FILE DONE => Run 06_LogCollection.sh next"
echo "====================================================="
