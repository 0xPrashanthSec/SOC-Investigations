# 🛡️ SOC Investigations: Your Cybersecurity Toolkit 🛠️

Welcome to the SOC Investigations repository! This is your one-stop-shop for PowerShell scripts designed to bolster your Security Operations Center (SOC) investigations. Each script in this collection is a powerful tool, honed to perform a specific task related to system and network security. Let's dive in!

## 🚀 AutoRuns
**Mission:** Fetch details about programs that run automatically on system startup.
```powershell
Get-CimInstance -ClassName Win32_StartupCommand | Select-Object Name, Command, Location, User
```

## 🔍 DomainAccountSearch
**Mission:** Search for domain accounts. Don't forget to replace 'DOMAIN' and 'USERNAME' with actual values.
```powershell
Get-ADUser -Filter 'Name -like "*USERNAME*"' -Server 'DOMAIN'
```

## 🚧 FirewallChanges
**Mission:** Keep an eye on changes in firewall rules.
```powershell
Get-NetFirewallRule | Where-Object { $_.Enabled -eq 'True' }
```

## 🕵️ LastLoginUsers
**Mission:** Fetch the last login details of users.
```powershell
Get-WmiObject -Class Win32_ComputerSystem | Select-Object UserName, LastLogin
```

## 🌐 NetworkTraffic
**Mission:** Monitor network traffic details with remote hosts.
```powershell
Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' }
```

## 📊 NetworkTrafficDetails
**Mission:** This script fetches details about established TCP connections on your system, including local and remote addresses and ports, the remote host name, the state of the connection, and the process that owns the connection.
```powershell
Get-NetTCPConnection -State Established | Select-Object -Property LocalAddress, LocalPort, @{Name='RemoteHostName'; Expression={(Resolve-DnsName $_.RemoteAddress).NameHost}}, RemoteAddress, RemotePort, State, @{Name='ProcessName'; Expression={(Get-Process -Id $_.OwningProcess).Path}} | Format-Table
```

## 🚪 OpenPorts
**Mission:** Checks for open ports on a system.  Replace 'PORT' with actual value
```powershell
Test-NetConnection -Port 'PORT'
```

## 📅 ScheduledTasks
**Mission:** Fetch details about scheduled tasks.
```powershell
Get-ScheduledTask | Where-Object { $_.State -eq 'Ready' }
```

Welcome aboard, cyber sentinel! Your mission, should you choose to accept it, involves utilizing these scripts to safeguard your network. This README will self-update as we continue to add more tools to your arsenal. Good luck! 🍀
