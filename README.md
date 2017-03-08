# Avorix-Domain-Controller
A Raspberry Pi based domain controller developed for business and education.


## Installation
### 1. Configuring the Raspberry Pi
1. Install a clean version of Raspbian Lite on a Raspberry Pi.
1. Plug in an EXT4 USB-flashdrive.
1. Execute the following command: curl https://raw.githubusercontent.com/RHeijmann/Avorix-Domain-Controller/master/scripts/Install-DC.sh
1. Configure the first section of the script using: nano Install-DC.sh, save it using [Ctrl] + [x] followed by pressing on [Y].
1. Execute: sudo chmod +x Install-DC.sh
1. Execute: sudo bash Install-DC.sh

### 2. Adding a Windows computer
1. Boot up a Windows Vista/Win7/8/8.1/10 or Windows Server 2008/2008 R2/2012/2012 R2 client computer.
1. Search on the client computer for: SystemPropertiesComputerName.exe
1. Click on "Change...".
1. Select "Domain" under "Member of".
1. Enter your domain name.
1. Click on "OK".
1. Log on using the Active Directory administrator account.
1. Reboot.
   
### 3. Settings the right permissions on the "users"-share
1. Log on the client computer in as the Active Directory Administrator account.
1. Give the "users"-share the following share permissions:

    Principal | Access
    ----------|-------
    Authenticated Users | Read & execute
    Domain Admins | Full control
    
1. Give the "users"-share the following filesystempermissions:

    Principal | Access | Applies to
    ----------|--------|-----------
    Authenticated Users | Read & execute | This folder only
    CREATOR OWNER | Full control | Subfolders and files only
    Domain Admins | Full control | This folder, subfolders and files
    
1. Disable the permission"Inheritance".
