#!/bin/bash
# =============================================================
# Author  : 0xPrashanthSec
# GitHub  : https://github.com/0xPrashanthSec
# Purpose : SOC Incident Response Toolkit
# License : For authorized, safe, and educational use only.
#           Do NOT run against systems you do not own or have
#           explicit written permission to investigate.
# =============================================================
# SOC - macOS Persistence Investigation
# Enumerates all known macOS persistence mechanisms.
# What to look for: LaunchAgents/Daemons pointing to /tmp or Downloads,
# unsigned or recently modified launch plists, login hooks, cron jobs.
# Required: Run as root or with sudo.

TS=$(date -u "+%Y-%m-%d %H:%M:%S")
echo ""
echo "====================================================="
echo "  SOC macOS PERSISTENCE INVESTIGATION  |  $TS UTC"
echo "====================================================="
echo ""

# ----------------------------------------------------------
echo "[1] LAUNCH AGENTS (per-user, runs as user)"
# ----------------------------------------------------------
# Most common persistence on macOS - check for unsigned or unusual programs
for dir in /Library/LaunchAgents /System/Library/LaunchAgents; do
    if [ -d "$dir" ]; then
        echo "  --- $dir ---"
        for plist in "$dir"/*.plist; do
            [ -f "$plist" ] || continue
            echo ""
            echo "  File: $plist (Modified: $(stat -f '%Sm' "$plist" 2>/dev/null))"
            # Extract Program or ProgramArguments key
            /usr/libexec/PlistBuddy -c "Print :Label" "$plist" 2>/dev/null | xargs -I{} echo "    Label: {}"
            /usr/libexec/PlistBuddy -c "Print :Program" "$plist" 2>/dev/null | xargs -I{} echo "    Program: {}"
            /usr/libexec/PlistBuddy -c "Print :ProgramArguments" "$plist" 2>/dev/null | head -5
        done
        echo ""
    fi
done

# Per-user launch agents
for homedir in /Users/*; do
    userdir="$homedir/Library/LaunchAgents"
    if [ -d "$userdir" ]; then
        echo "  --- $userdir ---"
        for plist in "$userdir"/*.plist; do
            [ -f "$plist" ] || continue
            echo "  File: $plist"
            /usr/libexec/PlistBuddy -c "Print :Program" "$plist" 2>/dev/null | xargs -I{} echo "    Program: {}"
            /usr/libexec/PlistBuddy -c "Print :ProgramArguments" "$plist" 2>/dev/null | head -5
        done
        echo ""
    fi
done

# ----------------------------------------------------------
echo "[2] LAUNCH DAEMONS (system-wide, runs as root)"
# ----------------------------------------------------------
# Unexpected daemons running as root = high priority finding
for dir in /Library/LaunchDaemons /System/Library/LaunchDaemons; do
    if [ -d "$dir" ]; then
        echo "  --- $dir (non-Apple only) ---"
        for plist in "$dir"/*.plist; do
            [ -f "$plist" ] || continue
            label=$(/usr/libexec/PlistBuddy -c "Print :Label" "$plist" 2>/dev/null)
            # Skip known Apple items
            if echo "$label" | grep -qE "^com.apple\.|^com.openssh"; then continue; fi
            echo ""
            echo "  File: $plist"
            echo "    Label: $label"
            /usr/libexec/PlistBuddy -c "Print :Program" "$plist" 2>/dev/null | xargs -I{} echo "    Program: {}"
            /usr/libexec/PlistBuddy -c "Print :ProgramArguments" "$plist" 2>/dev/null | head -5
        done
        echo ""
    fi
done

# ----------------------------------------------------------
echo "[3] CURRENTLY LOADED LAUNCHD ITEMS"
# ----------------------------------------------------------
# Anything loaded and running that isn't Apple is worth reviewing
launchctl list 2>/dev/null | grep -v "^-\|com.apple\." | head -40
echo ""

# ----------------------------------------------------------
echo "[4] LOGIN ITEMS (per-user apps that start at login)"
# ----------------------------------------------------------
# Uses osascript to query the login items list
for homedir in /Users/*; do
    username=$(basename "$homedir")
    echo "  --- Login Items for $username ---"
    osascript -e 'tell application "System Events" to get the name of every login item' 2>/dev/null
    echo ""
done

# ----------------------------------------------------------
echo "[5] CRON JOBS"
# ----------------------------------------------------------
echo "  --- Root crontab ---"
crontab -l 2>/dev/null || echo "  No root crontab"
echo ""
echo "  --- All user crontabs ---"
for user in $(dscl . list /Users | grep -v "^_"); do
    tab=$(crontab -l -u "$user" 2>/dev/null)
    if [ -n "$tab" ]; then
        echo "  User: $user"
        echo "$tab"
        echo ""
    fi
done
echo "  --- /etc/cron.d ---"
ls -la /etc/cron.d/ 2>/dev/null
echo ""
echo "  --- /etc/periodic ---"
ls -laR /etc/periodic/ 2>/dev/null

# ----------------------------------------------------------
echo "[6] SHELL PROFILE MODIFICATIONS"
# ----------------------------------------------------------
# Malware appends reverse shell or download stager to shell profiles
for profile in /etc/profile /etc/bashrc /etc/zshrc /etc/zshenv; do
    if [ -f "$profile" ]; then
        echo "  --- $profile ---"
        cat "$profile"
        echo ""
    fi
done
for homedir in /Users/* /root; do
    for f in .bashrc .bash_profile .zshrc .zshenv .profile; do
        if [ -f "$homedir/$f" ]; then
            echo "  --- $homedir/$f ---"
            cat "$homedir/$f"
            echo ""
        fi
    done
done

# ----------------------------------------------------------
echo "[7] LOGIN AND LOGOUT HOOKS"
# ----------------------------------------------------------
# Legacy macOS persistence - runs script at login/logout
echo "  --- LoginHook ---"
defaults read com.apple.loginwindow LoginHook 2>/dev/null || echo "  None"
echo "  --- LogoutHook ---"
defaults read com.apple.loginwindow LogoutHook 2>/dev/null || echo "  None"
echo ""

# ----------------------------------------------------------
echo "[8] RECENTLY MODIFIED PLIST FILES (last 7 days)"
# ----------------------------------------------------------
find /Library/LaunchAgents /Library/LaunchDaemons /Users/*/Library/LaunchAgents \
    -name "*.plist" -mtime -7 2>/dev/null | while read f; do
    echo "  MODIFIED: $f ($(stat -f '%Sm' "$f"))"
done
echo ""

# ----------------------------------------------------------
echo "[9] AUTHORIZED SSH KEYS"
# ----------------------------------------------------------
for homedir in /root /Users/*; do
    keyfile="$homedir/.ssh/authorized_keys"
    if [ -f "$keyfile" ]; then
        echo "  --- $keyfile ---"
        cat "$keyfile"
        echo ""
    fi
done

echo "====================================================="
echo "  PERSISTENCE DONE => Run 05_FileInvestigation.sh next"
echo "====================================================="
