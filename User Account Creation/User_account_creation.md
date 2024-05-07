**Create local user account on host using Remote shell ( Mac/iOS)**

**Create the user Account**

    bash-3.2$ sudo dscl . -create /Users/temp
    bash-3.2$ sudo dscl . -create /Users/temp UserShell /bin/bash
    bash-3.2$ sudo dscl . -create /Users/temp RealName "temp"
    bash-3.2$ sudo dscl . -create /Users/temp NFSHomeDirectory /Local/Users/temp
    bash-3.2$ sudo dscl . -passwd /Users/temp ************

Once Completed : test if the user exist or not:

    bash-3.2$ dscl . list /Users | grep -v "^_"
