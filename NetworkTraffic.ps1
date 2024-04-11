# Monitors network traffic details with remote hosts
Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' }
