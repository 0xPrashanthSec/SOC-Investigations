# Fetches the last login details of users
Get-WmiObject -Class Win32_ComputerSystem | Select-Object UserName, LastLogin

