# Fetches details about scheduled tasks
Get-ScheduledTask | Where-Object { $_.State -eq 'Ready' }
