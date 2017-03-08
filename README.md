# Avorix-Domain-Controller
A Raspberry Pi based domain controller developed for business and education.

The project is currently mainly focused on installing a Raspberry Pi Domain Controller.
While keeping the configuration files on an external USB-storage device. 


In the future the project will span to differenct Linux operating systems but we will first expand it's current functions including:
- Integrate a GUI for configuration.
- Integrate checks.
- Find a way to make AUDITD to work.
- Use PXE to deploy Windows.
- Set the permissions on the "users"-share automaticly.
- Adding the option to join a Active Directory domain.


## Installation
### Knowledge requirements
1. Basic knowledge of the Linux command shell. Most of the process is automated but it is required to be able to solve problems.
1. Basic networking knowledge, you will need to know what: 
   1. The difference between a switch and a router is
   1. The difference between a static and a DHCP IP-address is
   1. What a domainname actually is, a domainname is a nickname for an IP-address.
   1. How a computer is able communicate with the Internet.
1. Basic knowledge of creating shares in Windows.
1. Basic knowledge of maintaining an Active Directory Domain, YouTube has lots of free tutorials about this subject.

### Hardware requirements
1. A Raspberry Pi with Raspbian Lite, other computers with a Debian Jessie based operating system might work but these installations are not supported by the developers of this project.
1. A client computer with Windows Vista/Win7/8/8.1/10 or Windows Server 2008/2008 R2/2012/2012 R2.
1. A decent network with Internet access.


### 1. Configuring the Raspberry Pi
1. Install a clean version of Raspbian Lite on a Raspberry Pi.
1. Plug in an EXT4 USB-flashdrive.
1. Execute the following command: curl https://raw.githubusercontent.com/RHeijmann/Avorix-Domain-Controller/master/Install-DC.sh
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
