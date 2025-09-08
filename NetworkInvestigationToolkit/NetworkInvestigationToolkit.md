# NetworkInvestigationToolkit

## 🧭 Overview
**NetworkInvestigationToolkit** is a PowerShell module designed for security analysts and IT professionals to investigate network activity. It focuses on TCP connections, SMB traffic, and system services, providing reusable functions to:

- Identify suspicious external connections
- Filter SMB port 445 traffic
- Resolve hostnames
- Geolocate remote IPs
- Inspect SMB sessions and shares
- Check server and workstation service status

---

## 📦 Installation

1. Save the module file as `NetworkInvestigationToolkit.psm1`.
2. Place it in a directory, for example:
   ```powershell
   C:\PowerShellModules\NetworkInvestigationToolkit\
   ```
3. Import the module in PowerShell:
   ```powershell
   Import-Module "C:\PowerShellModules\NetworkInvestigationToolkit\NetworkInvestigationToolkit.psm1"
   ```

```
This module includes the following functions:
- Get-ExternalTCPConnections: Lists established TCP connections excluding internal IPs.
- Get-SMBConnections: Filters for SMB (port 445) connections excluding internal IPs.
- Get-SMBGeoInfo: Geolocates remote IPs connected via SMB.
- Get-SMBHostnames: Resolves hostnames and shows process info for SMB connections.
- Get-SmbSessionInfo: Retrieves current SMB sessions.
- Get-SmbShareInfo: Lists SMB shares on the system.
- Get-ServerWorkstationServices: Checks status of Server and Workstation services.
```
