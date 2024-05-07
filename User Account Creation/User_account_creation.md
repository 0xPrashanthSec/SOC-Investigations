
## **Create local user account on host using Remote shell ( Mac/iOS)**

**Create the user Account**

    bash-3.2$ sudo dscl . -create /Users/temp
    bash-3.2$ sudo dscl . -create /Users/temp UserShell /bin/bash
    bash-3.2$ sudo dscl . -create /Users/temp RealName "temp"
    bash-3.2$ sudo dscl . -create /Users/temp NFSHomeDirectory /Local/Users/temp
    bash-3.2$ sudo dscl . -passwd /Users/temp ************

**Once Completed : test if the user exist or not:**

    bash-3.2$ dscl . list /Users | grep -v "^_"
**Delete the user account :**

    sudo /usr/bin/dscl . -delete /Users/dylan
    

## **Reset local account passwords from Shell**

Type the following command to list all the available accounts and press Enter:

    Get-LocalUser
    $Password = Read-Host "Enter the new password" -AsSecureString
    $UserAccount = Get-LocalUser -Name "UserName"  
    $UserAccount | Set-LocalUser -Password $Password
    

## **Reset local account passwords from Shell next logon attempt**

    $Username = "username" # Replace "username" with the actual username of the user

**Generate a secure password**

    $Password = Read-Host "Enter the new password" -AsSecureString

**Set the user's password**

    Set-ADAccountPassword -Identity $Username -NewPassword $Password -Reset

**Require the user to change their password on next logon**

    Set-ADUser -Identity $Username -ChangePasswordAtLogon $true
