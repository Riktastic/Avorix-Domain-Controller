# Avorix-Domain-Controller
A Raspberry Pi based domain controller developed for business and education.


# Installation
1. Install a clean version of Raspbian Lite on a Raspberry Pi.
2. Plug in an EXT4 USB-flashdrive.
3. Execute the following command: curl https://raw.githubusercontent.com/RHeijmann/Avorix-Domain-Controller/master/scripts/Install-DC.sh
4. Configure the first section of the script using: nano Install-DC.sh, save it using [Ctrl] + [x] followed by pressing on [Y].
5. Execute: sudo chmod +x Install-DC.sh
6. Execute: sudo bash Install-DC.sh
7. Join the domain using the Active Directory administrator account.
   7.1. Boot up a Windows Vista/Win7/8/8.1/10 or Windows Server 2008/2008 R2/2012/2012 R2 client computer.
   7.1. Search on the client computer for: SystemPropertiesComputerName.exe
   7.2. Click on "Change...".
   7.3. Select "Domain" under "Member of".
   7.4. Enter your domain name.
   7.5. Click on "OK".
   7.6. Log on using the Active Directory administrator account.
   7.7. Reboot.
8. Log on the client computer in as the Active Directory Administrator account.
9. Give the "users"-share the following share permissions:
    Principal 	            Access
    Authenticated Users:    Read & execute
    Domain Admins:	        Full control 
10. Give the "users"-share the following filesystempermissions:
    Principal 	            Access      	Applies to
    Authenticated Users 	Read & execute 	This folder only
    CREATOR OWNER       	Full control 	Subfolders and files only
    Domain Admins 	        Full control 	This folder, subfolders and files
11. Disable the permission"Inheritance".
