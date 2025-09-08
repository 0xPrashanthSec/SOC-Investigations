<#
.SYNOPSIS
    Network Investigation Toolkit - PowerShell Module

.DESCRIPTION
    This module provides functions to inspect established TCP connections,
    filter for SMB port 445, resolve hostnames, geolocate IPs, inspect SMB sessions and shares,
    and check server/workstation services.
    
    This module includes the following functions:
    Get-ExternalTCPConnections: Lists established TCP connections excluding internal IPs.
    Get-SMBConnections: Filters for SMB (port 445) connections excluding internal IPs.
    Get-SMBGeoInfo: Geolocates remote IPs connected via SMB.
    Get-SMBHostnames: Resolves hostnames and shows process info for SMB connections.
    Get-SmbSessionInfo: Retrieves current SMB sessions.
    Get-SmbShareInfo: Lists SMB shares on the system.
    Get-ServerWorkstationServices: Checks status of Server and Workstation services.

.AUTHOR
    SaiPrashanth pulisetti
  
#>

function Get-ExternalTCPConnections {
    <#
    .SYNOPSIS
        Lists established TCP connections excluding internal IP ranges.

    .INSTRUCTIONS
        Use this to identify external connections that may be suspicious or unauthorized.

    .OUTPUTS
        PSCustomObject with LocalAddress, LocalPort, RemoteAddress, RemotePort, and Process path.
    #>
    Get-NetTCPConnection -State Established |
    Where-Object {
        $_.RemoteAddress -notlike "127.*" -and
        $_.RemoteAddress -notlike "192.168.*" -and
        $_.RemoteAddress -notlike "10.*"
    } |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort,
    @{Name="Process"; Expression={(Get-Process -Id $_.OwningProcess).Path}}
}

function Get-SMBConnections {
    <#
    .SYNOPSIS
        Filters established TCP connections for SMB port 445 excluding internal IPs.

    .INSTRUCTIONS
        Use this to detect SMB-based lateral movement or external access attempts.

    .OUTPUTS
        PSCustomObject with LocalAddress, LocalPort, RemoteAddress, RemotePort, and Process path.
    #>
    Get-NetTCPConnection -State Established |
    Where-Object {
        $_.RemotePort -eq 445 -and
        $_.RemoteAddress -notlike "127.*" -and
        $_.RemoteAddress -notlike "192.168.*" -and
        $_.RemoteAddress -notlike "10.*"
    } |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort,
    @{Name="Process"; Expression={(Get-Process -Id $_.OwningProcess).Path}}
}

function Get-SMBGeoInfo {
    <#
    .SYNOPSIS
        Geolocates remote IPs connected via SMB port 445.

    .INSTRUCTIONS
        Use this to enrich threat intelligence with geolocation data.

    .OUTPUTS
        PSCustomObject with RemoteIP, Country, City, and ISP.
    #>
    Get-NetTCPConnection -State Established |
    Where-Object {
        $_.RemotePort -eq 445 -and
        $_.RemoteAddress -notlike "127.*" -and
        $_.RemoteAddress -notlike "192.168.*" -and
        $_.RemoteAddress -notlike "10.*"
    } |
    ForEach-Object {
        $ip = $_.RemoteAddress
        $geo = Invoke-RestMethod -Uri "http://ip-api.com/json/$ip"
        [PSCustomObject]@{
            RemoteIP = $ip
            Country  = $geo.country
            City     = $geo.city
            ISP      = $geo.isp
        }
    }
}

function Get-SMBHostnames {
    <#
    .SYNOPSIS
        Resolves hostnames for SMB connections and shows process info.

    .INSTRUCTIONS
        Use this to correlate IPs with DNS names and identify responsible processes.

    .OUTPUTS
        Formatted table with connection and process details.
    #>
    Get-NetTCPConnection -State Established |
    Where-Object { $_.RemotePort -eq 445 } |
    Select-Object -Property LocalAddress, LocalPort,
    @{Name='RemoteHostName'; Expression={ (Resolve-DnsName $_.RemoteAddress -ErrorAction SilentlyContinue).NameHost }},
    RemoteAddress, RemotePort, State,
    @{Name='ProcessName'; Expression={ (Get-Process -Id $_.OwningProcess).Path }} |
    Format-Table -AutoSize
}

function Get-SmbSessionInfo {
    <#
    .SYNOPSIS
        Retrieves current SMB sessions.

    .INSTRUCTIONS
        Use this to monitor active SMB sessions for auditing or incident response.
    #>
    Get-SmbSession
}

function Get-SmbShareInfo {
    <#
    .SYNOPSIS
        Lists SMB shares available on the system.

    .INSTRUCTIONS
        Use this to review exposed shares and validate access control.
    #>
    Get-SmbShare
}

function Get-ServerWorkstationServices {
    <#
    .SYNOPSIS
        Checks status of Server and Workstation services.

    .INSTRUCTIONS
        Use this to verify that core services are running or to detect anomalies.
    #>
    Get-Service |
    Where-Object { $_.DisplayName -match "Server" -or $_.DisplayName -match "Workstation" }
}
