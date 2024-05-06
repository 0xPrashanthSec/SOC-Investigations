# SOC Investigations

## Introduction

This repository contains a collection of PowerShell scripts for Security Operations Center (SOC) investigations. Each script is designed to perform a specific task related to system and network security.

### AutoRuns
##### Fetches details about programs that run automatically on system startup
`Get-CimInstance -ClassName Win32_StartupCommand | Select-Object Name, Command, Location, User`

### DomainAccountSearch
#### Searches for domain accounts
##### Replace 'DOMAIN' and 'USERNAME' with actual values
`Get-ADUser -Filter 'Name -like "*USERNAME*"' -Server 'DOMAIN'`

### FirewallChanges
#### Monitors changes in firewall rules
`Get-NetFirewallRule | Where-Object { $_.Enabled -eq 'True' }`

### LastLoginUsers
#### Fetches the last login details of users
`Get-WmiObject -Class Win32_ComputerSystem | Select-Object UserName, LastLogin`

### NetworkTraffic
#### Monitors network traffic details with remote hosts
`Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' }`

### NetworkTrafficDetails
#### This script fetches details about established TCP connections on your system, including local and remote addresses and ports, the remote host name, the state of the connection, and the process that owns the connection.

`Get-NetTCPConnection -State Established | Select-Object -Property LocalAddress, LocalPort, @{Name='RemoteHostName'; Expression={(Resolve-DnsName $_.RemoteAddress).NameHost}}, RemoteAddress, RemotePort, State, @{Name='ProcessName'; Expression={(Get-Process -Id $_.OwningProcess).Path}} | Format-Table`

### OpenPorts
#### Checks for open ports on a system
##### Replace 'PORT' with actual value
`Test-NetConnection -Port 'PORT'`

### ScheduledTasks
#### Fetches details about scheduled tasks
`Get-ScheduledTask | Where-Object { $_.State -eq 'Ready' }`
