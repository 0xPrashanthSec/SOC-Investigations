# Fetches details about programs that run automatically on system startup
Get-CimInstance -ClassName Win32_StartupCommand | Select-Object Name, Command, Location, User
