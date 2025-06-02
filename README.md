# SOC Investigations: PowerShell Commands

Welcome to the **SOC Investigations** repository. This collection of PowerShell scripts is designed to support **Security Operations Center (SOC)** investigations. Each script performs a specific task related to system and network security, providing actionable insights for analysts. Explore the scripts below to enhance your security operations.

## Table of Contents
- [AutoRuns](#autoruns)
- [DomainAccountSearch](#domainaccountsearch)
- [FirewallChanges](#firewallchanges)
- [LastLoginUsers](#lastloginusers)
- [NetworkTraffic](#networktraffic)
- [NetworkTrafficDetails](#networktrafficdetails)
- [OpenPorts](#openports)
- [ScheduledTasks](#scheduledtasks)
- [InstalledPrograms](#installedprograms)
- [ApplicationEvents](#applicationevents)
- [RegistryChanges](#registrychanges)
- [RunningServices](#runningservices)
- [SuspiciousFiles](#suspiciousfiles)
- [LogonSessions](#logonsessions)
- [DNSQueries](#dnsqueries)
- [SecurityEventLogs](#securityeventlogs)
- [ProcessInjection](#processinjection)
- [ExternalConnections](#externalconnections)
- [PowerShellHistory](#powershellhistory)
- [GeoIPTracking](#geoiptracking)
- [Contribute](#contribute)

## Scripts

### AutoRuns
**Purpose**: Retrieves details about programs configured to run at system startup.  
```powershell
Get-CimInstance -ClassName Win32_StartupCommand | Select-Object Name, Command, Location, User
```
### DomainAccountSearch
Purpose: Searches for domain accounts. Replace DOMAIN and USERNAME with actual values.  
```powershell
Get-ADUser -Filter 'Name -like "*USERNAME*"' -Server 'DOMAIN'
```
### FirewallChanges
Purpose: Monitors active firewall rules for changes.  
```powershell
Get-NetFirewallRule | Where-Object { $_.Enabled -eq 'True' }
```
### LastLoginUsers
Purpose: Retrieves the last login details of users.  
```powershell
Get-WmiObject -Class Win32_ComputerSystem | Select-Object UserName, LastLogin
```

### NetworkTraffic
Purpose: Monitors network traffic with established connections to remote hosts.  
```powershell
Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' }
```
### NetworkTrafficDetails
Purpose: Provides detailed information about established TCP connections, including addresses, ports, and owning processes.  
```powershell
Get-NetTCPConnection -State Established | Select-Object -Property LocalAddress, LocalPort, @{Name='RemoteHostName'; Expression={(Resolve-DnsName $_.RemoteAddress).NameHost}}, RemoteAddress, RemotePort, State, @{Name='ProcessName'; Expression={(Get-Process -Id $_.OwningProcess).Path}} | Format-Table
```

### OpenPorts
Purpose: Checks for open ports. Replace PORT with the target port number.  
```powershell
Test-NetConnection -Port 'PORT'
```
### ScheduledTasks
Purpose: Lists scheduled tasks in a ready state.  
```powershell
Get-ScheduledTask | Where-Object { $_.State -eq 'Ready' }
```

### InstalledPrograms
Purpose: Retrieves installed programs, sorted by install date in descending order.  
```powershell
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, InstallDate | Sort-Object InstallDate -Descending
```

### ApplicationEvents
Purpose: Extracts application events from MsiInstaller (Event ID 1034) with timestamps and messages.  
```powershell
Get-WinEvent -FilterHashtable @{LogName="Application"; ProviderName="MsiInstaller"; Id=1034} | Format-Table -Property TimeCreated, Message -AutoSize -Wrap
```

### RegistryChanges
Purpose: Monitors critical registry keys for unauthorized modifications.  
```powershell
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" | Select-Object Name, Path
```

### RunningServices
Purpose: Lists all running services and their details.  
```powershell
Get-Service | Where-Object { $_.Status -eq 'Running' } | Select-Object Name, DisplayName, ServiceType, StartType
```

### SuspiciousFiles
Purpose: Identifies recently created files with suspicious extensions in common directories.  
```powershell
Get-ChildItem -Path "C:\Users", "C:\ProgramData" -Recurse -Include *.exe,*.bat,*.ps1 | Where-Object { $_.CreationTime -gt (Get-Date).AddDays(-7) } | Select-Object FullName, CreationTime, LastWriteTime
```

### LogonSessions
Purpose: Retrieves details about active logon sessions.  
```powershell
Get-CimInstance -ClassName Win32_LogonSession | Select-Object LogonId, LogonType, AuthenticationPackage, StartTime
```

### DNSQueries
Purpose: Monitors recent DNS queries to detect suspicious domain resolutions.  
```powershell
Get-DnsClientCache | Select-Object Entry, Name, Data, TimeToLive
```
### SecurityEventLogs
Purpose: Retrieves recent failed login attempts (Event ID 4625) from security event logs.  
```powershell
Get-WinEvent -FilterHashtable @{LogName="Security"; Id=4625} -MaxEvents 50 | Select-Object TimeCreated, @{Name="Account"; Expression={$_.Properties[5].Value}}, @{Name="SourceIP"; Expression={$_.Properties[19].Value}}
```

### ProcessInjection
Purpose: Detects processes with potential DLL injection by listing non-standard modules.  
```powershell
Get-Process | ForEach-Object { Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $($_.Id)" | Select-Object ProcessName, @{Name="Modules"; Expression={(Get-Process -Id $_.ProcessId | Select-Object -ExpandProperty Modules | Where-Object { $_.FileName -notlike "C:\Windows\*" -and $_.FileName -notlike "C:\Program Files*"}).FileName}} } | Where-Object { $_.Modules }
```

### ExternalConnections
Purpose: Lists processes with active external network connections.  
```powershell
Get-NetTCPConnection -State Established | Where-Object { $_.RemoteAddress -notlike "127.*" -and $_.RemoteAddress -notlike "192.168.*" } | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, @{Name="Process"; Expression={(Get-Process -Id $_.OwningProcess).Path}}
```

### PowerShellHistory
Purpose: Retrieves recent PowerShell command history to detect unauthorized scripts.  
```powershell
Get-Content -Path "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" | Select-Object -Last 50
```

### GeoIPTracking
Purpose: Resolves geolocation data for remote IPs in established connections.  
```powershell
Get-NetTCPConnection -State Established | Where-Object { $_.RemoteAddress -notlike "127.*" -and $_.RemoteAddress -notlike "192.168.*" } | ForEach-Object { $ip = $_.RemoteAddress; $geo = (Invoke-RestMethod -Uri "http://ip-api.com/json/$ip"); [PSCustomObject]@{ RemoteIP=$ip; Country=$geo.country; City=$geo.city; ISP=$geo.isp }}
```

### Contribute
 - This repository is a growing resource for SOC analysts. To contribute new scripts, suggest improvements, or report issues:
- Fork the repository.
- Create a new branch for your changes.
- Submit a pull request with a clear description of your updates.
- Thank you for joining the mission to strengthen cybersecurity defenses. New tools will be added regularly to keep this toolkit sharp.

