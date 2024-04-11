# Searches for domain accounts
# Replace 'DOMAIN' and 'USERNAME' with actual values
Get-ADUser -Filter 'Name -like "*USERNAME*"' -Server 'DOMAIN'
