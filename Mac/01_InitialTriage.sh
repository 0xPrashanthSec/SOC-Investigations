#!/bin/bash
# SOC - macOS Initial Triage
# Run FIRST on any suspected compromised Mac.
# Captures identity, timing, active users, and system state.
# Required: Run as root or with sudo. Some commands need SIP disabled for full output.

TS=$(date -u "+%Y-%m-%d %H:%M:%S")
echo ""
echo "====================================================="
echo "  SOC macOS INITIAL TRIAGE  |  $TS UTC"
echo "====================================================="
echo ""

# ----------------------------------------------------------
echo "[1] SYSTEM IDENTITY"
# ----------------------------------------------------------
echo "  Hostname      : $(hostname)"
echo "  macOS Version : $(sw_vers -productName) $(sw_vers -productVersion) (Build: $(sw_vers -buildVersion))"
echo "  Kernel        : $(uname -r)"
echo "  Architecture  : $(uname -m)"
echo "  Serial Number : $(system_profiler SPHardwareDataType 2>/dev/null | grep 'Serial Number' | awk -F': ' '{print $2}')"
echo "  Hardware Model: $(system_profiler SPHardwareDataType 2>/dev/null | grep 'Model Identifier' | awk -F': ' '{print $2}')"
echo "  Date (UTC)    : $(date -u)"
echo ""

# ----------------------------------------------------------
echo "[2] UPTIME AND LAST BOOT"
# ----------------------------------------------------------
uptime
sysctl -n kern.boottime 2>/dev/null
echo ""

# ----------------------------------------------------------
echo "[3] NETWORK INTERFACES"
# ----------------------------------------------------------
# Multiple IPs, VPN interfaces, or unexpected adapters = tunneling
ifconfig | grep -E "^[a-z]|inet " | grep -v "inet6" | grep -v "127.0.0.1"
echo ""

# ----------------------------------------------------------
echo "[4] WHO IS LOGGED ON RIGHT NOW"
# ----------------------------------------------------------
who
echo ""
echo "  --- w command ---"
w
echo ""

# ----------------------------------------------------------
echo "[5] LAST 20 LOGINS"
# ----------------------------------------------------------
# Logins at odd hours, from unexpected IPs, or as root = red flag
last -n 20 2>/dev/null
echo ""

# ----------------------------------------------------------
echo "[6] FAILED LOGIN ATTEMPTS"
# ----------------------------------------------------------
echo "  --- Last 20 failed logins ---"
lastb -n 20 2>/dev/null || \
    log show --predicate 'process == "loginwindow" && eventMessage contains "failed"' \
        --last 24h --style syslog 2>/dev/null | tail -20 || \
    grep "Failed password" /var/log/system.log 2>/dev/null | tail -20
echo ""

# ----------------------------------------------------------
echo "[7] TOP 15 PROCESSES BY CPU"
# ----------------------------------------------------------
# Look for: unknown process names, processes in /tmp, /Users/*/Downloads
ps aux -r | head -20
echo ""

# ----------------------------------------------------------
echo "[8] GATEKEEPER AND SIP STATUS"
# ----------------------------------------------------------
# Disabled Gatekeeper = unsigned apps can run freely
echo "  --- Gatekeeper status ---"
spctl --status 2>/dev/null
echo ""
echo "  --- System Integrity Protection (SIP) ---"
csrutil status 2>/dev/null
echo ""
echo "  --- Notarization check ---"
spctl --assess --type exec /Applications 2>/dev/null | head -5

# ----------------------------------------------------------
echo "[9] DISK USAGE"
# ----------------------------------------------------------
df -H | grep -v tmpfs
echo ""

echo "====================================================="
echo "  TRIAGE DONE => Run 02_NetworkInvestigation.sh next"
echo "====================================================="
