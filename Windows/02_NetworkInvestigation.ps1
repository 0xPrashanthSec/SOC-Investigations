<#
# =============================================================
# Author  : 0xPrashanthSec
# GitHub  : https://github.com/0xPrashanthSec
# Purpose : SOC Incident Response Toolkit
# License : For authorized, safe, and educational use only.
#           Do NOT run against systems you do not own or have
#           explicit written permission to investigate.
# =============================================================
.SYNOPSIS
    SOC - Windows Network Investigation
    Maps all active and listening network activity.
    What to look for: unexpected external IPs, uncommon ports, unknown processes,
    SMB to external hosts, DNS to DGA-style domains.
    Required: Run as Administrator.
#>

$ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
Write-Host "`n=====================================================" -ForegroundColor Yellow
Write-Host "  SOC NETWORK INVESTIGATION  |  $ts UTC"               -ForegroundColor Yellow
Write-Host "=====================================================`n" -ForegroundColor Yellow

# ----------------------------------------------------------
Write-Host "[1] ESTABLISHED EXTERNAL CONNECTIONS" -ForegroundColor Cyan
# ----------------------------------------------------------
# Non-RFC1918 destinations. Any unknown process here is an immediate red flag.
Get-NetTCPConnection -State Established |
    Where-Object {
        $_.RemoteAddress -notmatch "^127\." -and
        $_.RemoteAddress -notmatch "^192\.168\." -and
        $_.RemoteAddress -notmatch "^10\." -and
        $_.RemoteAddress -notmatch "^172\.(1[6-9]|2[0-9]|3[01])\." -and
        $_.RemoteAddress -ne "::1" -and
        $_.RemoteAddress -ne "0.0.0.0"
    } |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort,
        @{N="PID";     E={$_.OwningProcess}},
        @{N="Process"; E={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).Name}},
        @{N="Path";    E={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).Path}} |
    Format-Table -AutoSize

# ----------------------------------------------------------
Write-Host "[2] ALL LISTENING PORTS (TCP)" -ForegroundColor Cyan
# ----------------------------------------------------------
# Unexpected listeners - especially on high ports or bound to 0.0.0.0 - indicate backdoors
Get-NetTCPConnection -State Listen |
    Select-Object LocalAddress, LocalPort,
        @{N="PID";     E={$_.OwningProcess}},
        @{N="Process"; E={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).Name}},
        @{N="Path";    E={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).Path}} |
    Sort-Object LocalPort | Format-Table -AutoSize

# ----------------------------------------------------------
Write-Host "[3] LISTENING UDP ENDPOINTS" -ForegroundColor Cyan
# ----------------------------------------------------------
Get-NetUDPEndpoint |
    Select-Object LocalAddress, LocalPort,
        @{N="PID";     E={$_.OwningProcess}},
        @{N="Process"; E={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).Name}} |
    Sort-Object LocalPort | Format-Table -AutoSize

# ----------------------------------------------------------
Write-Host "[4] DNS CACHE" -ForegroundColor Cyan
# ----------------------------------------------------------
# Look for: DGA domains (random-looking names), unexpected TLDs, known malicious domains
Get-DnsClientCache |
    Select-Object Entry, Data, TimeToLive |
    Sort-Object Entry | Format-Table -AutoSize

# ----------------------------------------------------------
Write-Host "[5] ARP TABLE" -ForegroundColor Cyan
# ----------------------------------------------------------
# Duplicate MACs for different IPs = ARP poisoning / MITM
Get-NetNeighbor | Where-Object { $_.State -ne 'Unreachable' } |
    Select-Object InterfaceAlias, IPAddress, LinkLayerAddress, State |
    Format-Table -AutoSize

# ----------------------------------------------------------
Write-Host "[6] SMB ACTIVITY (port 445)" -ForegroundColor Cyan
# ----------------------------------------------------------
# External SMB connections = lateral movement or data exfiltration
Get-NetTCPConnection |
    Where-Object { $_.RemotePort -eq 445 -or $_.LocalPort -eq 445 } |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State,
        @{N="Process"; E={(Get-Process -Id $_.OwningProcess -EA SilentlyContinue).Name}} |
    Format-Table -AutoSize

Write-Host "[6b] ACTIVE SMB SESSIONS" -ForegroundColor Cyan
try { Get-SmbSession | Format-Table -AutoSize } catch { Write-Host "  No SMB sessions or insufficient permissions" }

Write-Host "[6c] SMB SHARES" -ForegroundColor Cyan
Get-SmbShare | Select-Object Name, Path, Description | Format-Table -AutoSize

# ----------------------------------------------------------
Write-Host "[7] FIREWALL INBOUND ALLOW RULES" -ForegroundColor Cyan
# ----------------------------------------------------------
# Attacker-added rules commonly have no description or allow 'Any' application
Get-NetFirewallRule |
    Where-Object { $_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow' } |
    Select-Object DisplayName, Profile, Protocol,
        @{N="LocalPort"; E={(Get-NetFirewallPortFilter -AssociatedNetFirewallRule $_ -EA SilentlyContinue).LocalPort}} |
    Format-Table -AutoSize

# ----------------------------------------------------------
Write-Host "[8] ROUTING TABLE" -ForegroundColor Cyan
# ----------------------------------------------------------
Get-NetRoute | Where-Object { $_.RouteMetric -lt 256 } |
    Select-Object DestinationPrefix, NextHop, InterfaceAlias, RouteMetric |
    Format-Table -AutoSize

# ----------------------------------------------------------
Write-Host "[9] GEOLOCATION OF EXTERNAL IPs (requires internet)" -ForegroundColor Cyan
# ----------------------------------------------------------
$extIPs = Get-NetTCPConnection -State Established |
    Where-Object {
        $_.RemoteAddress -notmatch "^127\." -and $_.RemoteAddress -notmatch "^192\.168\." -and
        $_.RemoteAddress -notmatch "^10\." -and $_.RemoteAddress -notmatch "^172\.(1[6-9]|2[0-9]|3[01])\." -and
        $_.RemoteAddress -ne "::1" -and $_.RemoteAddress -ne "0.0.0.0"
    } | Select-Object -ExpandProperty RemoteAddress -Unique

foreach ($ip in $extIPs) {
    try {
        $geo = Invoke-RestMethod -Uri "http://ip-api.com/json/$ip" -TimeoutSec 5
        [PSCustomObject]@{IP=$ip; Country=$geo.country; City=$geo.city; ISP=$geo.isp; Org=$geo.org}
    } catch {
        [PSCustomObject]@{IP=$ip; Country="Lookup failed"; City=""; ISP=""; Org=""}
    }
} | Format-Table -AutoSize

Write-Host "`n[NETWORK DONE] => Run 03_ProcessInvestigation.ps1 next`n" -ForegroundColor Green
