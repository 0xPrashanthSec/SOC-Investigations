#!/bin/bash
# SOC - macOS Log Collection
# Collects key security-relevant logs from macOS.
# Output is saved to /tmp/soc_logs_<timestamp>/ for export.
# Key log sources:
#   unified log (log show)        - Modern macOS primary log source
#   /var/log/system.log           - Legacy system log
#   /var/log/secure.log           - Authentication (older macOS)
#   last / lastb                  - Login history
#   /Library/Logs/DiagnosticReports/ - Crash reports (post-exploitation)
# Required: Run as root or with sudo.

TS=$(date -u "+%Y-%m-%d %H:%M:%S")
OUTDIR="/tmp/soc_logs_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"

echo ""
echo "====================================================="
echo "  SOC macOS LOG COLLECTION  |  $TS UTC"
echo "  Output: $OUTDIR"
echo "====================================================="
echo ""

# ----------------------------------------------------------
echo "[1] UNIFIED LOG - AUTHENTICATION EVENTS (last 24h)"
# ----------------------------------------------------------
# Modern macOS uses unified logging - this is the authoritative source
echo "  --- SSH authentication events ---"
log show --predicate 'process == "sshd"' --last 24h --style syslog 2>/dev/null | \
    grep -E "Accepted|Failed|Invalid|error" | tail -50 | tee "$OUTDIR/ssh_auth.txt"
echo ""

echo "  --- sudo events ---"
log show --predicate 'process == "sudo"' --last 24h --style syslog 2>/dev/null | \
    tail -50 | tee "$OUTDIR/sudo_events.txt"
echo ""

echo "  --- Login window events ---"
log show --predicate 'process == "loginwindow" OR process == "SecurityAgent"' \
    --last 24h --style syslog 2>/dev/null | tail -50 | tee "$OUTDIR/login_window.txt"
echo ""

# ----------------------------------------------------------
echo "[2] UNIFIED LOG - SECURITY EVENTS (last 24h)"
# ----------------------------------------------------------
echo "  --- Gatekeeper / code signing events ---"
log show --predicate 'subsystem == "com.apple.security"' \
    --last 24h --style syslog 2>/dev/null | tail -50 | tee "$OUTDIR/security_events.txt"
echo ""

echo "  --- TCC (privacy/permissions) events ---"
log show --predicate 'subsystem == "com.apple.TCC"' \
    --last 24h --style syslog 2>/dev/null | tail -50 | tee "$OUTDIR/tcc_events.txt"
echo ""

echo "  --- Firewall events ---"
log show --predicate 'process == "socketfilterfw" OR process == "pfctl"' \
    --last 24h --style syslog 2>/dev/null | tail -30 | tee "$OUTDIR/firewall_events.txt"
echo ""

# ----------------------------------------------------------
echo "[3] SYSTEM LOG"
# ----------------------------------------------------------
if [ -f /var/log/system.log ]; then
    tail -100 /var/log/system.log | tee "$OUTDIR/system.log.txt"
else
    echo "  /var/log/system.log not found - using unified log"
    log show --last 1h --style syslog 2>/dev/null | tail -100 | tee "$OUTDIR/unified_recent.txt"
fi
echo ""

# ----------------------------------------------------------
echo "[4] LOGIN HISTORY"
# ----------------------------------------------------------
echo "  --- last (successful logins, last 50) ---"
last -n 50 2>/dev/null | tee "$OUTDIR/last.txt"
echo ""
echo "  --- lastb (failed logins) ---"
lastb -n 30 2>/dev/null | tee "$OUTDIR/lastb.txt" || \
    echo "  lastb requires /var/log/btmp"
echo ""

# ----------------------------------------------------------
echo "[5] LAUNCHD LOGS"
# ----------------------------------------------------------
echo "  --- launchd events (service starts/stops) ---"
log show --predicate 'process == "launchd"' --last 24h --style syslog 2>/dev/null | \
    tail -50 | tee "$OUTDIR/launchd.txt"
echo ""

# ----------------------------------------------------------
echo "[6] CRASH REPORTS"
# ----------------------------------------------------------
# Crash reports can indicate exploit attempts (heap sprays, buffer overflows)
echo "  --- Recent crash reports ---"
ls -lt /Library/Logs/DiagnosticReports/ 2>/dev/null | head -20 | tee "$OUTDIR/crash_reports.txt"
echo ""
echo "  --- User crash reports ---"
for homedir in /Users/*; do
    ls -lt "$homedir/Library/Logs/DiagnosticReports/" 2>/dev/null | head -10
done
echo ""

# ----------------------------------------------------------
echo "[7] FULL SECURITY LOG EXPORT (last 48h)"
# ----------------------------------------------------------
echo "  Exporting full security-relevant unified log (this may take a moment)..."
log show --last 48h --style syslog \
    --predicate 'eventType == logEvent AND (process == "sshd" OR process == "sudo" OR process == "loginwindow" OR process == "SecurityAgent" OR subsystem == "com.apple.security")' \
    2>/dev/null | tee "$OUTDIR/full_security_export.txt" | wc -l | xargs -I{} echo "  {} log lines exported"
echo ""

# ----------------------------------------------------------
echo "[8] NETWORK EXTENSION AND VPN LOGS"
# ----------------------------------------------------------
log show --predicate 'subsystem == "com.apple.networkextension"' \
    --last 24h --style syslog 2>/dev/null | tail -30 | tee "$OUTDIR/network_ext.txt"
echo ""

# ----------------------------------------------------------
echo "[9] AIRDROP AND SHARING EVENTS"
# ----------------------------------------------------------
log show --predicate 'process == "AirDropUIAgent" OR process == "sharingd"' \
    --last 24h --style syslog 2>/dev/null | tail -20 | tee "$OUTDIR/airdrop.txt"
echo ""

echo "====================================================="
echo "  LOGS SAVED TO: $OUTDIR"
echo "  LOGS DONE => Run 07_UserAccountInvestigation.sh next"
echo "====================================================="
