#!/bin/bash
# =============================================================
# Author  : 0xPrashanthSec
# GitHub  : https://github.com/0xPrashanthSec
# Purpose : SOC Incident Response Toolkit
# License : For authorized, safe, and educational use only.
#           Do NOT run against systems you do not own or have
#           explicit written permission to investigate.
# =============================================================
# SOC - macOS Network Investigation
# Maps all active and listening network activity on Mac.
# What to look for: unexpected external connections, backdoor listeners,
# processes from /tmp or Downloads with network activity.
# Required: Run as root or with sudo.

TS=$(date -u "+%Y-%m-%d %H:%M:%S")
echo ""
echo "====================================================="
echo "  SOC macOS NETWORK INVESTIGATION  |  $TS UTC"
echo "====================================================="
echo ""

# ----------------------------------------------------------
echo "[1] ESTABLISHED EXTERNAL CONNECTIONS"
# ----------------------------------------------------------
# Non-RFC1918 destinations are the priority - anything unknown here is suspicious
echo "  --- External TCP Established ---"
netstat -anv -p tcp 2>/dev/null | grep ESTABLISHED | \
    grep -v "127\.0\.0\.1\|192\.168\.\|10\.\|::1"
echo ""
echo "  --- lsof version (shows process name) ---"
lsof -i -n -P 2>/dev/null | grep ESTABLISHED | \
    grep -v "127\.0\.0\.1\|192\.168\.\|10\.\|::1"
echo ""

# ----------------------------------------------------------
echo "[2] ALL LISTENING PORTS"
# ----------------------------------------------------------
# Unexpected listeners = backdoor or C2 implant waiting for connection
netstat -anv -p tcp 2>/dev/null | grep LISTEN
echo ""
echo "  --- UDP listeners ---"
netstat -anv -p udp 2>/dev/null | grep -v "^$"
echo ""

# ----------------------------------------------------------
echo "[3] ALL OPEN NETWORK CONNECTIONS WITH PROCESS NAMES"
# ----------------------------------------------------------
lsof -i -n -P 2>/dev/null
echo ""

# ----------------------------------------------------------
echo "[4] PROCESSES WITH EXTERNAL CONNECTIONS FROM SUSPICIOUS PATHS"
# ----------------------------------------------------------
# Any process in /tmp, /var/tmp, or Downloads with a live connection
lsof -i -n -P 2>/dev/null | awk 'NR>1{print $1,$2,$9}' | sort -u | while read name pid addr; do
    if [ -n "$pid" ]; then
        exe=$(ps -p $pid -o comm= 2>/dev/null)
        path=$(lsof -p $pid -a -d txt 2>/dev/null | awk 'NR>1{print $9}' | head -1)
        if echo "$path" | grep -qE "/tmp/|/var/tmp/|Downloads/|Desktop/"; then
            echo "  SUSPICIOUS: $name (PID=$pid) FROM=$path CONN=$addr"
        fi
    fi
done
echo ""

# ----------------------------------------------------------
echo "[5] ARP TABLE"
# ----------------------------------------------------------
# Duplicate MACs = ARP poisoning / MITM attack
arp -a 2>/dev/null
echo ""

# ----------------------------------------------------------
echo "[6] ROUTING TABLE"
# ----------------------------------------------------------
netstat -rn 2>/dev/null
echo ""

# ----------------------------------------------------------
echo "[7] DNS CONFIGURATION AND CACHE"
# ----------------------------------------------------------
echo "  --- DNS servers in use ---"
scutil --dns 2>/dev/null | grep "nameserver\|domain" | head -20
echo ""
echo "  --- /etc/hosts (look for redirects of legit domains) ---"
cat /etc/hosts
echo ""
echo "  --- DNS cache (mdnsresponder) ---"
dscacheutil -cachedump -entries Host 2>/dev/null | head -40 || \
    sudo killall -INFO mDNSResponder 2>/dev/null && echo "  (Check Console.app for DNS cache dump)"
echo ""

# ----------------------------------------------------------
echo "[8] FIREWALL STATUS"
# ----------------------------------------------------------
echo "  --- Application Firewall ---"
/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null
/usr/libexec/ApplicationFirewall/socketfilterfw --listapps 2>/dev/null | head -20
echo ""
echo "  --- Packet Filter (pf) rules ---"
pfctl -sr 2>/dev/null || echo "  pf not running"
echo ""

# ----------------------------------------------------------
echo "[9] GEOLOCATION OF EXTERNAL IPs"
# ----------------------------------------------------------
EXTERNAL_IPS=$(lsof -i -n -P 2>/dev/null | grep ESTABLISHED | \
    grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | \
    grep -v "^127\.\|^192\.168\.\|^10\." | sort -u)

for ip in $EXTERNAL_IPS; do
    result=$(curl -s --max-time 5 "http://ip-api.com/json/$ip" 2>/dev/null)
    country=$(echo "$result" | grep -o '"country":"[^"]*"' | cut -d: -f2 | tr -d '"')
    org=$(echo "$result" | grep -o '"org":"[^"]*"' | cut -d: -f2 | tr -d '"')
    echo "  $ip => $country | $org"
done
echo ""

echo "====================================================="
echo "  NETWORK DONE => Run 03_ProcessInvestigation.sh next"
echo "====================================================="
