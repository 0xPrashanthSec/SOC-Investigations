# Monitors changes in firewall rules
Get-NetFirewallRule | Where-Object { $_.Enabled -eq 'True' }
