#!/bin/bash
# =============================================================
# Author  : 0xPrashanthSec
# GitHub  : https://github.com/0xPrashanthSec
# Purpose : SOC Incident Response Toolkit
# License : For authorized, safe, and educational use only.
#           Do NOT run against systems you do not own or have
#           explicit written permission to investigate.
# =============================================================
# SOC - Linux Network Investigation
# Maps all active and listening network activity.
# What to look for: unexpected external connections, unknown listeners,
# unusual ports, processes connecting out from /tmp or /dev/shm.
# Required: Run as root or with sudo.

TS=$(date -u "+%Y-%m-%d %H:%M:%S")
echo ""
echo "====================================================="
echo "  SOC LINUX NETWORK INVESTIGATION  |  $TS UTC"
echo "====================================================="
echo ""

# ----------------------------------------------------------
echo "[1] ESTABLISHED EXTERNAL CONNECTIONS"
# ----------------------------------------------------------
# Focus on connections to non-RFC1918 IPs - these are the ones that matter first
echo "  --- TCP Established (ss) ---"
ss -tnp state established 2>/dev/null | grep -v "127\.\|192\.168\.\|10\.\|::1"
echo ""
echo "  --- Fallback: netstat ---"
netstat -tnp 2>/dev/null | grep ESTABLISHED | grep -v "127\.\|192\.168\.\|10\." || true
echo ""

# ----------------------------------------------------------
echo "[2] ALL LISTENING PORTS"
# ----------------------------------------------------------
# Unexpected listeners - especially on 0.0.0.0 - indicate backdoors
ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null
echo ""

# ----------------------------------------------------------
echo "[3] ALL OPEN NETWORK FILES BY PROCESS"
# ----------------------------------------------------------
# Shows which process owns which network connection
lsof -i -n -P 2>/dev/null | head -60
echo ""

# ----------------------------------------------------------
echo "[4] PROCESSES CONNECTING OUT FROM SUSPICIOUS PATHS"
# ----------------------------------------------------------
# A process in /tmp, /dev/shm, or /var/tmp with a network connection = malware
echo "  --- Processes in suspicious paths with network connections ---"
lsof -i -n -P 2>/dev/null | awk 'NR>1 {print $2}' | sort -u | while read pid; do
    exe=$(readlink -f /proc/$pid/exe 2>/dev/null)
    if echo "$exe" | grep -qE "^/tmp/|^/dev/shm/|^/var/tmp/"; then
        echo "  PID=$pid EXE=$exe"
        ss -tnp 2>/dev/null | grep "pid=$pid,"
    fi
done
echo ""

# ----------------------------------------------------------
echo "[5] ARP / NEIGHBOR TABLE"
# ----------------------------------------------------------
# Duplicate MACs for different IPs = ARP poisoning
ip neigh show 2>/dev/null || arp -a 2>/dev/null
echo ""

# ----------------------------------------------------------
echo "[6] ROUTING TABLE"
# ----------------------------------------------------------
ip route show 2>/dev/null || route -n 2>/dev/null
echo ""

# ----------------------------------------------------------
echo "[7] DNS RESOLVER CONFIGURATION"
# ----------------------------------------------------------
# Unexpected DNS servers = DNS hijacking
cat /etc/resolv.conf 2>/dev/null
echo ""
echo "  --- /etc/hosts (look for redirects of legit domains) ---"
cat /etc/hosts 2>/dev/null
echo ""

# ----------------------------------------------------------
echo "[8] FIREWALL RULES"
# ----------------------------------------------------------
echo "  --- iptables ---"
iptables -L -n -v 2>/dev/null || echo "  iptables not available or no rules"
echo ""
echo "  --- nftables ---"
nft list ruleset 2>/dev/null || true
echo ""

# ----------------------------------------------------------
echo "[9] ACTIVE CONNECTIONS WITH GEOLOCATION (requires curl)"
# ----------------------------------------------------------
# Quick enrichment - look for connections to known-bad countries or unusual orgs
EXTERNAL_IPS=$(ss -tnp state established 2>/dev/null | awk 'NR>1{print $5}' | \
    cut -d: -f1 | grep -vE "^127\.|^192\.168\.|^10\.|^172\.(1[6-9]|2[0-9]|3[01])\.|^$" | sort -u)

for ip in $EXTERNAL_IPS; do
    if command -v curl &>/dev/null; then
        result=$(curl -s --max-time 5 "http://ip-api.com/json/$ip" 2>/dev/null)
        country=$(echo $result | grep -o '"country":"[^"]*"' | cut -d: -f2 | tr -d '"')
        org=$(echo $result | grep -o '"org":"[^"]*"' | cut -d: -f2 | tr -d '"')
        echo "  $ip => $country | $org"
    else
        echo "  $ip => curl not available for geolookup"
    fi
done
echo ""

echo "====================================================="
echo "  NETWORK DONE => Run 03_ProcessInvestigation.sh next"
echo "====================================================="
