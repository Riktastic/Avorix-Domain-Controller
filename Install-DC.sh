#!/bin/bash
###########################################################
#                Avorix Domain Controller                 #
###########################################################
#
# This is currently in development!
# I recommend to execute this script per command in
# a CLEAN RASPBIAN installation!
#
# The Avorix Domain Controller uses SAMBA, NTP, DHCPD to
# mimic Microsoft Active Directory Domain Services
# (MS ADDS) on Raspberry Pi's running Raspbian while
# keeping it's configuration on a USB-memory device.
#
# This allows us to manage computers, users, shares,
# and policies using the RSAT-tools.
#
# This script was built upon best practices and experiences.
# ~ Rik Heijmann

###########################################################
#                       Versions                          #
###########################################################
DC_SCRIPT_VERSION="1.0-RC6"
DC_RELEASE_DATE="8-6-2017"
# Major update: Can break your current installation.
# Minor update: Will not break your current installation.
#
# 0.5: First release: Installs a SAMBA, NTP, DHCP server in
#                     a Secure environment.
# 0.5.1: Major update: Added checks for all services, made 
#                      changes to the settings.
# 0.5.2: Minor update: Added a summary and tutorial for
#                      at the end of the installation.
# 0.5.3: Minor update: Added a summary and tutorial for
#                      at the end of the installation.
# 0.6: Significant update: Added SELinux.
#
# 0.7: Significant update: Added Antivirus.
#
# 0.8: Significant update: Added PXE
#
# 0.9: Significant update: Extended to support UEFI PXE
#
# 1.0-RC2: Major update: Is more extensible.


###########################################################
#                         To Do                           #
###########################################################
# - Make this script work with CentOS, ArchLinux and Ubuntu.
# - Integrate a GUI for configuration.
# - Integrate checks: Partly Done, need more checks.
# - Find a way to make AUDITD to work.
# - PXE: Set the permissions on the "users"-share automaticly.

###########################################################
#                       Summary                           #
###########################################################
# 1. The configuration fase.
# 1.1. Settings.
# 1.2. System Specific Variables.
# 1.3. Check the configuration.
# 1.4. Show a summary of the settings.

# 2. The fase of compatibility.
# 2.1. Test the internet connection.
# 2.2. Update the complete system.
# 2.3. (Optional) Configure USBmount.
# 2.4. Build the Location-Of-Important-Files directorystructure.

# 3. The fase of installation
# 3.1. (Optional) Install & Temporarely disable SELinux  
# 3.2. Install the main components.
# 3.3. Configure the timezone  
# 3.4. Configure the hosts file.
# 3.5. Change the hostname.
# 3.6. Configure a static IP-address.
# 3.7. Configure the NTP-server.
# 3.8. Configure the Domain Controller.

# 4. The fase of adaption
# 4.1. (Optional) Configure SSH.
# 4.2. (Optional) Configure the DHCP-server.
# 4.3. (Optional) Configure the PXE-server.
# 4.4. (Optional) Configure SELinux.
# 4.5. (Optional) Configure automatic security updates.
# 4.6. (Optional) Test & Enable the Firewall.
# 4.7. Configure log in/out messages and EULA.

# 5. The fase of finishing up.
# 5.1. Log the current installation.
# 5.2. Display a summary of the installation.


###########################################################
#                                                         #
# 1.             The configuration fase                   #
#                                                         #
###########################################################

###########################################################
# 1.1.                 Settings                           #
###########################################################
# All these settings are important!
# Make sure that everything is setup correctly.

#Operating system:
OS=RASPBIAN
#1: RASPBIAN: 	Raspbian: Debian Jessie
#2: CENTOS7: 	CentOS 7 (Not working)

#Script settings: Set to 1 to enable.
SKIP_OS_WARNING=0 #Set this to 1 to disable the Raspbian Jessie warning.
SKIP_BEGINNING_SUMMARY=1 #Set this to 1 to fully automate the script.
SKIP_END_SUMMARY=1 #Set this to 1 to fully automate the script.
BRANDING=1 #RECOMMENDED! Configures log-in/out messages with an EULA.

#Storage Settings
STORE_FILES_ON_USB=0 #Set this to 0 to fully automate the script.
LOCATION_OF_IMPORTANT_FILES=/media/usb1 #Will only work if AUTO_CHECK_USB is set to 0.
BACKUP_LOIP=0 #Set this to 1 to automaticly backup the users and groups.
	BACKUP_LOIP_TIMING="0 2 * * *" #Enter here using the CRON-format at which time a backup should be made. 
					#Quick CRON tutorial:
					# Every day at 2AM: 0 2 * * *
					# Every first day of the month at 2AM: 0 2 1 * *
	BACKUP_LOIP_DESTINATION="$LOCATION_OF_IMPORTANT_FILES/Backup/"
AUTO_CHECK_USB=0  #Is not working.

#Network Settings
IP_ADDRESS=192.168.0.1
SUBNETMASKBITS=24
GATEWAY=192.168.0.2
DNSSERVER1=127.0.0.1
DNSSERVER2=

#Time Settings
REGION=Europe
TIMEZONE=Amsterdam
NTPSERVER1=0.pool.ntp.org
NTPSERVER2=1.pool.ntp.org
NTPSERVER3=2.pool.ntp.org

#Domain Controller Settings
JOIN_A_DOMAIN=0 #Set this to 1 to join a domain. Installing replication for DHCP, PXE, the GPO's and other functions will be done using a different script, that is still in development.

#Before you begin, please take a look at: https://wiki.samba.org/index.php/Active_Directory_Naming_FAQ
FQDN=avorix.local #This is your domain name.
EXTENSION=.local
NBIOS=AVORIX #This is the second level domain name capitalized.
DCNAME=DC1
BACKUP_DC=0 #Set this to 1 to automaticly backup the users and groups.
	BACKUP_DC_TIMING="0 2 * * *" #Enter here using the CRON-format at which time a backup should be made. 
					#Quick CRON tutorial:
					# Every day at 2AM: 0 2 * * *
					# Every first day of the month at 2AM: 0 2 1 * *
	BACKUP_DC_DESTINATION="$LOCATION_OF_IMPORTANT_FILES/SAMBA/Backup/"

#Note please only use Alpha-Numeric passwords. Special characters will cause problems.
ADMINPWD='P4ssw0rd' #This is the password of the Active Directory "Administrator"-account.

#Security Functions: Set to 1 to enable.
FIREWALL=1 #RECOMMENDED! Enables the built-in firewall and adds support for the selected functions.
ANTIVIRUS=1 #RECOMMENDED! Installs ClamAV antivirus to scan through your shares.
SELINUX=1 #RECOMMENDED! Enables SELINUX (Will first start permissive and collect data. The next day that data will be used to create a policy)
AUTOMATIC_SECURITY_UPDATES=1 #RECOMMENDED! Will daily check for security updates.

#Additional Modules: Set to 1 to enable.
WEBMIN=0
DHCP_SERVER=0 #Enable this only if you know that this is needed.
	DHCP_SUBNET=192.168.0.0
	DHCP_SUBNETMASK=255.255.255.0
	DHCP_BROADCASTADDRESS=192.168.0.255
	DHCP_GATEWAY=$GATEWAY
	DHCP_DNSSERVER1=$DNSSERVER1
	DHCP_DNSSERVER2=$DNSSERVER2
	DHCP_NETBIOSSERVER=$IP_ADDRESS
	DHCP_NTPSERVER1=$IP_ADDRESS
	DHCP_NTPSERVER2=0.pool.ntp.org
	DHCP_MAX_LEASE_TIME=1800
	DHCP_FIRST_IP_ADDRESS=192.168.0.10
	DHCP_LAST_IP_ADDRESS=192.168.0.200
	
	PXE_SERVER=0 #Requires DHCP! #Enable PXE to deliver minimal network environments such as WinPE to computers.
		PXE_TFTP_ROOT=$LOCATION_OF_IMPORTANT_FILES/PXE/TFTP #This location is for the WinPE .WIM-file.
		PXE_HTTP_ROOT=$LOCATION_OF_IMPORTANT_FILES/PXE/HTTP #This location is for the Windows Installer.
	
SSH_SERVER=0 #Enable this to add a user and allow it to be used to mange the server remotely.
	SSH_PORT=22
	SSH_USER=Avorix #Future users have to be added to the "ssh"-group to use "ssh".
	SSH_USER_PASSWORD='P4ssw0rd'
	SSH_USER_SUDO=1 #Set to 1 to give this user permission to run administrator commands using "sudo".
	SSH_PORTKNOCKING=0 #Enable this to only provide the SSH service when a sequence of numbers is knocked.						#IMPLEMENTED NOT TESTED.
		SSH_PORTKNOCKING_OPEN_SEQ1=7999 #Sequence number 1 for opening the openssh Portknock.
		SSH_PORTKNOCKING_OPEN_SEQ2=8181
		SSH_PORTKNOCKING_OPEN_SEQ3=1821
		SSH_PORTKNOCKING_CLOSE_SEQ1=7997 #Sequence number 1 for closing the openssh Portknock.
		SSH_PORTKNOCKING_CLOSE_SEQ2=8121
		SSH_PORTKNOCKING_CLOSE_SEQ3=5821
		
	SSH_FAIL2BAN=0 #Enable this to block an IP-address when a configurable amount of failed attempts has been reached.			#IMPLEMENTED NOT TESTED.
		SSH_FAIL2BAN_MAXRETRY=3 #How many attempts can be made to access the server from a single IP before a ban is imposed.
		SSH_FAIL2BAN_FINDTIME=900 #The length of time between login attempts before a ban is set. For example, if Fail2Ban is set to ban an IP after three failed log-in attempts, those three attempts must occur within the set findtime limit. The findtime value should be a set number of seconds.
		SSH_FAIL2BAN_BANTIME=900 #The length of time in seconds that the IP Address will be banned for. In my example I used ‘900’ seconds which would be 15 minutes. If you want to ban an IP Address permanently then you will set the bantime to ‘-1’.
		
	SSH_2FA=0 #Enable this to login usign Two-Factor-Authentication using Google-Authenticator. After installation run 'google-authenticator' as the user which will be using 2FA. During prompts choose 'y'. Afterwards restart SSH.													#IMPLEMENTED NOT TESTED!																											#Work in progress!


###########################################################
# 1.2.         System  Specific Variables                 #
###########################################################
# These variables ensure compatibility over multiple systems.
# Please do not change these!

if [ "$OS" == "RASPBIAN" ] ; then
# For Raspbian Jessie
# Tools
PM_UPDATE='apt-get update'
PM_UPGRADE='apt-get upgrade -y'
PM_SYSUPGRADE='apt-get dist-upgrade -y'
PM_INSTALL='apt-get install'
PM_INSTALL_ENDING_VARIABLES='-y'

# Packages:
PACKAGE_SAMBA='samba samba-vfs-modules'
PACKAGE_NTP='ntp'
PACKAGE_FIREWALLD='firewalld'
PACKAGE_SELINUX='selinux-basics selinux-policy-default'
PACKAGE_DHCPD='isc-dhcp-server'
PACKAGE_CLAMAV='clamav clamav-freshclam'
PACKAGE_OPENSSHD='openssh-server'
PACKAGE_TFTPD='tftpd-hpa'
PACKAGE_APACHE='apache2'
PACKAGE_USBMOUNT='usbmount'
PACKAGE_KNOCKD='knockd'
PACKAGE_FAIL2BAN='fail2ban'
PACKAGE_LIBPAM_GOOGLE_AUTHENTICATOR='libpam-google-authenticator' #Not Tested!

# Paths to folders:
PATH_FOLDER_CRON_DAILY='/etc/cron.daily'
PATH_FOLDER_CRON_HOURLY='/etc/cron.hourly'
PATH_FOLDER_APACHE_SITES_ENABLED='/etc/apache2/sites-enabled'
PATH_FOLDER_SSH_KEYS='/etc/ssh'
PATH_FOLDER_SAMBA_VAR_LIB='/var/lib/samba'
PATH_FOLDER_SAMBA_SETUP='/usr/share/samba/setup'
PATH_FOLDER_SAMBA_CACHE='/var/cache/samba'
PATH_FOLDER_SAMBA_LOG='/var/log/samba'


# Paths to files:
PATH_FILE_AUDIT_LOG='/var/log/audit/audit.log'
PATH_FILE_SELINUX_CONF='/etc/selinux/conf'
PATH_FILE_SELINUX_CONF_REPLACER='/etc/selinux/config.replacer'
PATH_FILE_DHCPD_CONF='/etc/dhcp/dhcpd.conf'
PATH_FILE_DHCPCD_CONF='/etc/dhcpcd.conf'
PATH_FILE_KRB5_CONF_EXAMPLE='/var/lib/samba/private/krb5.conf'
PATH_FILE_KRB5_CONF='/etc/krb5.conf'
PATH_FILE_SAMBA_CONF='/etc/samba/smb.conf'
PATH_FILE_NTP_CONF='/etc/ntp.conf'
PATH_FILE_SSH_CONF='/etc/ssh/sshd_config'
PATH_FILE_SUDO_CONF='/etc/sudoers'
PATH_FILE_HOSTNAME_CONF='/etc/hostname'
PATH_FILE_HOSTS_CONF='/etc/hosts'
PATH_FILE_TFTPD_CONF='/etc/default/tftpd-hpa'
PATH_FILE_USBMOUNT_CONF='/etc/usbmount/usbmount.conf'
PATH_FILE_KNOCKD_DEFAULT='/etc/default/knockd'
PATH_FILE_KNOCKD_CONF='/etc/knockd.conf'
PATH_FILE_FAIL2BAN_JAIL='/etc/fail2ban/jail.local'
PATH_FILE_PAMD_SSHD='/etc/pam.d/sshd'
PATH_FILE_ISSUE='/etc/issue'
PATH_FILE_ISSUENET='/etc/issue.net'
PATH_FILE_MOTD='/etc/motd'


#Daemons
DAEMON_SSH='ssh'
DAEMON_FIREWALD='firewalld'
DAEMON_TFTPD='tftpd-hpa'
DAEMON_APACHE='apache2'
DAEMON_DHCPCD='dhcpcd'
DAEMON_KNOCKD='knockd'
DAEMON_FAIL2BAN='fail2ban'
DAEMON_NTP='ntp'
DAEMON_SMBD='smbd'
DAEMON_NMBD='nmbd'
DAEMON_SAMBA_AD_DC='samba-ad-dc'
DAEMON_DHCPD='isc-dhcp-server'
fi

if [ "$OS" == "CENTOS7" ] ; then
# For CentOS 7
# Tools
PM_UPDATE=''
PM_UPGRADE=''
PM_SYSUPGRADE='yum update -y'							#Correct
PM_INSTALL='yum install'								#Correct
PM_INSTALL_ENDING_VARIABLES='-y'						#Correct

# Packages:
PACKAGE_SAMBA=''
PACKAGE_NTP=''
PACKAGE_FIREWALLD=''
PACKAGE_SELINUX=''
PACKAGE_DHCPD=''
PACKAGE_CLAMAV=''
PACKAGE_OPENSSHD=''
PACKAGE_TFTPD=''
PACKAGE_APACHE=''
PACKAGE_USBMOUNT=''
PACKAGE_KNOCKD=''
PACKAGE_FAIL2BAN=''
PACKAGE_LIBPAM_GOOGLE_AUTHENTICATOR=''

# Paths to folders:
PATH_FOLDER_CRON_DAILY=''
PATH_FOLDER_CRON_HOURLY=''
PATH_FOLDER_APACHE_SITES_ENABLED=''
PATH_FOLDER_SSH_KEYS=''

# Paths to files:
PATH_FILE_AUDIT_LOG=''
PATH_FILE_SELINUX_CONF=''
PATH_FILE_SELINUX_CONF_REPLACER=''
PATH_FILE_DHCPD_CONF=''
PATH_FILE_DHCPCD_CONF=''
PATH_FILE_KRB5_CONF_EXAMPLE=''
PATH_FILE_KRB5_CONF=''
PATH_FILE_SAMBA_CONF=''
PATH_FILE_NTP_CONF=''
PATH_FILE_SSH_CONF=''
PATH_FILE_SUDO_CONF=''
PATH_FILE_HOSTNAME_CONF=''
PATH_FILE_HOSTS_CONF=''
PATH_FILE_TFTPD_CONF=''
PATH_FILE_USBMOUNT_CONF=''
PATH_FILE_KNOCKD_DEFAULT=''
PATH_FILE_KNOCKD_CONF=''
PATH_FILE_FAIL2BAN_JAIL=''
PATH_FILE_PAMD_SSHD=''

#Daemons
DAEMON_SSH=''
DAEMON_FIREWALD=''
DAEMON_TFTPD=''
DAEMON_APACHE=''
DAEMON_DHCPCD=''
DAEMON_KNOCKD=''
DAEMON_FAIL2BAN=''
DAEMON_NTP=''
DAEMON_SMBD=''
DAEMON_NMBD=''
DAEMON_SAMBA_AD_DC=''
DAEMON_DHCPD=''
fi


###########################################################
# 1.3.               Check the configuration              #
###########################################################

if [ "$DHCP_SERVER" -eq "1" ] && [ "$PXE_SERVER" -eq "1" ] ; then
	PXE_SERVER=2
else
	PXE_SERVER=0
	setterm -term linux -back red -fore white
	echo "###########################################################"
	echo "# Warning: To use PXE Server enable the DHCP Server       #"
	echo "#           in the settings section of this script!       #"
	echo "###########################################################"
	pause_with_msg
	setterm -default
	exit
fi


###########################################################
# 1.4.        Show a summary of the settings              #
###########################################################

pause(){
	read fackEnterKey
}

pause_with_msg(){
	read -p "Press [Enter] to continue..." fackEnterKey
}


clear

if [ "$SKIP_BEGINNING_SUMMARY" -eq "0" ] ; then
	echo "###########################################################";
	echo "#       A quick summary of the installed settings         #";
	echo "###########################################################";
	echo "# You can change these settings"
	echo "# by opening this script in a texteditor"
	echo "# and change the variables that start from line 78."
	echo ""
	echo "Will be installed: $(if [ "$DHCP_SERVER" -eq "1" ] ; then echo "DHCP" ; fi);$(if [ "$PXE_SERVER" -eq "2" ] ; then echo "(with PXE)" ; fi)$(if [ "$SSH_SERVER" -eq "1" ]; then echo "SSH" ; fi);$(if [ "$SSH_2FA" -eq "1" ] || [ "$SSH_PORTKNOCKING" -eq "1" ] || [ "$SSH_FAIL2BAN" -eq "1" ]; then echo " (with $(if [ "$SSH_2FA" -eq "1" ] ; then echo "2-Factor-Authentication"; fi)$(if [ "$SSH_PORTKNOCKING" -eq "1" ] ; then echo "Portknocking"; fi)$(if [ "$SSH_FAIL2BAN" -eq "1" ] ; then echo "Fail2Ban"; fi)" ; fi)"
	echo "";
	echo "Will be configured: $(if [ "$AUTOMATIC_SECURITY_UPDATES" -eq "1" ]; then echo "Automatic_Security_Updates"; else echo ""; fi) $(if [ "$FIREWALL" -eq "1" ]; then echo "Firewall"; else echo ""; fi) $(if [ "$SELINUX" -eq "1" ]; then echo "SELinux"; else echo ""; fi)"
	
	pause_with_msg;
	echo "";
	echo "Storage Settings:";
	echo "1. Files will be stored in: $LOCATION_OF_IMPORTANT_FILES";
	echo "2. Files will be stored on removable USB storage: $(if [ "$STORE_FILES_ON_USB" -eq "1" ]; then echo "Yes"; else echo "No"; fi)";
	
	pause_with_msg;
	echo "";
	echo "Network settings:";
	echo "1. IP address: $IP_ADDRESS";
	echo "2. Subnetmaskbits: $SUBNETMASKBITS";
	echo "3. Gateway: $GATEWAY";
	echo "4. Preferred DNS-server: $DNSSERVER1";
	echo "5. Alternate DNS-server: $DNSSERVER2";
	
	pause_with_msg;
	echo "";
	echo "Domain Controller Settings:";
	echo "1. Fully Qualified Domain Name: $FQDN";
	echo "2. NetBIOS name: $NBIOS";
	echo "3. Name of the Domain Controller: $DCNAME";
	echo "4. Administrator User: Administrator (can not be changed)";
	echo "5. Administrator Password: $(if [ "$ADMINPWD" = 'P455w0RD' ]; then echo 'P455w0RD'; else echo "Hidden! "; fi)";
	
	pause_with_msg;
	echo "";
	echo "Time settings:";
	echo "1. Region: $REGION";
	echo "2. Timezone: $TIMEZONE";
	echo "3. NTP-Server 1: $NTPSERVER1";
	echo "4. NTP-Server 2: $NTPSERVER2";
	echo "5. NTP-Server 3: $NTPSERVER3";

	if [ "$DHCP_SERVER" -eq "1" ] ; then
		pause_with_msg;
		echo "";
		echo "DHCP Settings:";
		echo "1. Subnet: $DHCP_SUBNET";
		echo "2. Subnetmask: $DHCP_SUBNETMASK";
		echo "3. Broadcastaddress: $DHCP_BROADCASTADDRESS";
		echo "4. Gateway: $DHCP_GATEWAY";
		echo "5. Preferred DNS-Server: $DHCP_DNSSERVER1";
		echo "6. Alternate DNS-Server: $DHCP_DNSSERVER2";
		
		pause_with_msg;
		echo "7. NetBIOS-Server: $DHCP_NETBIOSSERVER";
		echo "8. NTP-Server 1: $DHCP_NTPSERVER1";
		echo "9. NTP-Server 2: $DHCP_NTPSERVER2";
		echo "10. Max Lease Time: $DHCP_MAX_LEASE_TIME";
		echo "11. First IP Address: $DHCP_FIRST_IP_ADDRESS";
		echo "12. Last IP Address: $DHCP_LAST_IP_ADDRESS";
		if [ "$PXE_SERVER" -eq "2" ] ; then
			pause_with_msg
			echo "";
			echo "PXE Settings:";
			echo "1. HTTP Folder: $PXE_HTTP_ROOT (This location is for the Windows Installer files)";
			echo "2. TFTP Folder: $PXE_TFTP_ROOT (This location is for the Windows PE .WIM-file.)";
		fi
	fi

	if [ "$SSH_SERVER" -eq "1" ] ; then
		pause_with_msg;
		echo "";
		echo "SSH Settings:";
		echo "SSH Port: $SSH_PORT";
		echo "SSH User: $SSH_USER";
		echo "SSH Password: $(if [ "$SSH_USER_PASSWORD" = 'P455w0RD' ]; then echo 'P455w0RD'; else echo "Hidden! "; fi)";
		echo "SSH User has Admin rights: $(if [ "$SSH_USER_SUDO" -eq "1" ]; then echo "Yes"; else echo "No"; fi)";
		if [ "$SSH_2FA" -eq "1" ] ; then
		echo "Two-Factor-Authentication: $(if [ "$SSH_2FA" -eq "1" ]; then echo "Yes"; else echo "No"; fi)";
		fi
		if [ "$SSH_PORTKNOCKING" -eq "1" ] ; then
		echo "Portknocking: $(if [ "$SSH_PORTKNOCKING" -eq "1" ]; then echo "Yes"; else echo "No"; fi)";
		echo "Portknocking Opening sequence: $SSH_PORTKNOCKING_OPEN_SEQ1, $SSH_PORTKNOCKING_OPEN_SEQ2, $SSH_PORTKNOCKING_OPEN_SEQ3";
		echo "Portknocking Closing sequence: $SSH_PORTKNOCKING_CLOSE_SEQ1, $SSH_PORTKNOCKING_CLOSE_SEQ2, $SSH_PORTKNOCKING_CLOSE_SEQ3";
		fi
		if [ "$SSH_FAIL2BAN" -eq "1" ] ; then
		echo "Fail2Ban: $(if [ "$SSH_FAIL2BAN" -eq "1" ]; then echo "Yes"; else echo "No"; fi)";
		echo "Fail2Ban Bantime: $SSH_FAIL2BAN_BANTIME";
		echo "Fail2Ban Time between login attempts: $SSH_FAIL2BAN_FINDTIME";
		echo "Fail2Ban Max login retries: $SSH_FAIL2BAN_MAXRETRY";
		fi
	fi
	
	clear
	
	setterm -term linux -back black -fore green
	echo "###########################################################"
	echo "#                 Confirm these settings                  #"
	echo "###########################################################"
	echo "Are these settings correct?"
	echo ""
	echo "Note: You can bypass this in the future by setting"
	echo "'SKIP_BEGINNING_SUMMARY' to 1"
	echo ""
	pause_with_msg
	setterm -default
	
	clear
fi


###########################################################
#                                                         #
# 2.            The fase of compatibility                 #
#                                                         #
###########################################################

###########################################################
# 2.1.         Test the internet connection               #
###########################################################

echo -e "GET http://google.com HTTP/1.0\n\n" | nc google.com 80 > /dev/null 2>&1

if [ $? -eq 0 ]; then
	echo "Your device is connected to the internet."
else
    setterm -term linux -back red -fore white
	echo "###########################################################"
	echo "# Warning: This script requires an internet connection!   #"
	echo "###########################################################"
	pause
	exit
	setterm -default
fi


###########################################################
# 2.2.          Update the complete system                #
###########################################################

if [ "$OS" == "RASPBIAN" ] ; then
sudo $PM_UPDATE
sudo $PM_UPGRADE
fi

sudo $PM_SYSUPGRADE


###########################################################
# 2.3.           (Optional) Configure USBmount            #
###########################################################

if [ "$STORE_FILES_ON_USB" -eq "1" ] ; then
	sudo $PM_INSTALL $PACKAGE_USBMOUNT $PM_INSTALL_ENDING_VARIABLES
	#if [ "$(dpkg -s usbmount 2>/dev/null >/dev/null)" -eq "0" ] ; then
	#	echo "USBMount is succesfully installed!"
	#else
	#	setterm -term linux -back red -fore white
	#	echo "###########################################################"
	#	echo "# Error: Installation stopped!                            #"
	#	echo "###########################################################"
	#	echo "Reason:"
	#	echo " - USBMount could not be installed."
	#	echo ""
	#	echo "Solution:"
	#	echo " - Make sure that:"
	#	echo "	- You have a stable internet connection!"
	#	echo "	- Install it manually."
	#	echo "	- Skip this part."
	#	echo "###########################################################"
	#	pause_with_msg
	#	setterm -default
	#	exit
	#fi

	#USBMount: Configuring.
	sudo mv $PATH_FILE_USBMOUNT_CONF $PATH_FILE_USBMOUNT_CONF.original
	sudo touch $PATH_FILE_USBMOUNT_CONF

	sudo cat <<EOT >> $PATH_FILE_USBMOUNT_CONF
#Generated by the Avorix Domain Controller install script.
ENABLED=1
MOUNTPOINTS="/media/usb1 /media/usb2 /media/usb3
             /media/usb4 /media/usb5 /media/usb6 /media/usb7 /media/usb8"
			 
FILESYSTEMS="vfat ext2 ext3 ext4 hfsplus"
MOUNTOPTIONS="sync,noexec,nodev,noatime,nodiratime"
FS_MOUNTOPTIONS=""
VERBOSE=no
EOT

	clear

	#Inform the user to insert their USB-device.
	setterm -term linux -back red -fore white
	read -p "Insert your USB-drive and press [Enter] to continue..." fackEnterKey
	setterm -default

	#USBMount: Make sure that the USB-drive is mounted else copy the files to a temporary folder.
	#It would be better if we listed the drives using mountusb.
	if [ "$AUTO_CHECK_USB" -eq "1" ] ; then
		#I'm lazy.
		if mount | grep /media/usb1 > /dev/null; then
			LOCATION_OF_IMPORTANT_FILES=/media/usb1
			setterm -term linux -back green -fore white
			echo "###########################################################"
			echo "#           Your USB-device has been found!               #"
			echo "###########################################################"
			setterm -default
		else
			setterm -term linux -back red -fore white
			echo "###########################################################"
			echo "# Error: Installation stopped!                            #"
			echo "###########################################################"
			echo "Reason:"
			echo " - Your USB-storage device could not be mounted."
			echo ""
			echo "Solution:"
			echo " - Prepare your USB-storage device:"
			echo "	- Find your USB-device by executing the command: lsblk"
			echo "	- Format your device by executing: mkfs.ext4 /dev/Your_Device"
			echo "	  As an example: mkfs.ext4 /dev/sda"
			echo "###########################################################"
			pause_with_msg
			setterm -default
			exit
		fi
	fi
fi


###########################################################
# 2.4.       Build the LOIF directory structure           #
###########################################################

#Creating folders for the $LOCATION_OF_IMPORTANT_FILES
sudo mkdir -p $LOCATION_OF_IMPORTANT_FILES/General/Configuration $LOCATION_OF_IMPORTANT_FILES/General/Logs $LOCATION_OF_IMPORTANT_FILES/Kerberos/Configuration $LOCATION_OF_IMPORTANT_FILES/SAMBA/Configuration $LOCATION_OF_IMPORTANT_FILES/SAMBA/State $LOCATION_OF_IMPORTANT_FILES/SAMBA/Setup $LOCATION_OF_IMPORTANT_FILES/SAMBA/Cache $LOCATION_OF_IMPORTANT_FILES/SAMBA/Logs $LOCATION_OF_IMPORTANT_FILES/SAMBA/Sockets/ntp_signd $LOCATION_OF_IMPORTANT_FILES/NTPD/Configuration $LOCATION_OF_IMPORTANT_FILES/NTPD/Logs $LOCATION_OF_IMPORTANT_FILES/NTPD/Data $LOCATION_OF_IMPORTANT_FILES/SAMBA/Shares/Users
#Linking folder to folders on the USB, as we want to capture all these files!
sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/SAMBA/State $PATH_FOLDER_SAMBA_VAR_LIB
sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/SAMBA/Setup $PATH_FOLDER_SAMBA_SETUP
sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/SAMBA/Cache $PATH_FOLDER_SAMBA_CACHE
sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/SAMBA/Logs $PATH_FOLDER_SAMBA_LOG

if [ "$SELINUX" -eq "0" ]; then
	sudo mkdir -p $LOCATION_OF_IMPORTANT_FILES/SELinux/Rules 
fi

if [ "$DHCP_SERVER" -eq "1" ]; then
	sudo mkdir -p $LOCATION_OF_IMPORTANT_FILES/DHCP/Configuration/
	#PXE has to be 2, unlike the others.
	if [ "$PXE_SERVER" -eq "2" ]; then
		sudo mkdir -p $LOCATION_OF_IMPORTANT_FILES/PXE/Configuration $LOCATION_OF_IMPORTANT_FILES/PXE/TFTP $LOCATION_OF_IMPORTANT_FILES/PXE/HTTP $LOCATION_OF_IMPORTANT_FILES/PXE/SAMBA/ $LOCATION_OF_IMPORTANT_FILES/PXE/Logs
	fi
fi

if [ "$SSH_SERVER" -eq "1" ]; then
	sudo mkdir -p $LOCATION_OF_IMPORTANT_FILES/SSH/Configuration/Keys
	if [ "$SSH_PORTKNOCKING" -eq "1" ] ; then
		sudo mkdir -p $LOCATION_OF_IMPORTANT_FILES/KNOCKD/Logs $LOCATION_OF_IMPORTANT_FILES/KNOCKD/Configuration/default
	fi
	if [ "$SSH_FAIL2BAN" -eq "1" ] ; then
		sudo mkdir -p $LOCATION_OF_IMPORTANT_FILES/FAIL2BAN/Logs $LOCATION_OF_IMPORTANT_FILES/FAIL2BAN/Configuration
	fi
fi


###########################################################
#                                                         #
# 3.            The fase of installation                  #
#                                                         #
###########################################################

###########################################################
# 3.1. (Optional) Install & Temporarely disable SELinux   #
###########################################################
#Temporary disable SELinux, will be enabled the next day with exclusions for DNS, SAMBA, DHCP and DHCP.
if [ "$SELINUX" -eq "1" ]; then
	sudo $PM_INSTALL $PACKAGE_SELINUX $PM_INSTALL_ENDING_VARIABLES
	
	#if [ "$(dpkg -s selinux-basics 2>/dev/null >/dev/null)" -eq "0" ] ; then
		#	echo "SELinux-Basics is succesfully installed!"
		#	else
		#	setterm -term linux -back red -fore white
		#	echo "###########################################################"
		#	echo "# Error: Installation stopped!                            #"
		#	echo "###########################################################"
		#	echo "Reason:"
		#	echo " - SELinux-Basics could not be installed."
		#	echo ""
		#	echo "Solution:"
		#	echo " - Make sure that:"
		#	echo "	- You have a stable internet connection!"
		#	echo "	- Install it manually."
		#	echo "	- Skip this part."
		#	echo "###########################################################"
		#	pause_with_msg
		#	setterm -default
		#	exit
	#fi

	#if [ "$(dpkg -s selinux-policy-default 2>/dev/null >/dev/null)" -eq "0" ] ; then
		#	echo "The SELinux-Policy-Default is succesfully installed!"
		#	else
		#	setterm -term linux -back red -fore white
		#	echo "###########################################################"
		#	echo "# Error: Installation stopped!                            #"
		#	echo "###########################################################"
		#	echo "Reason:"
		#	echo " - The SELinux-Policy-Default could not be installed."
		#	echo ""
		#	echo "Solution:"
		#	echo " - Make sure that:"
		#	echo "	- You have a stable internet connection!"
		#	echo "	- Install it manually."
		#	echo "	- Skip this part."
		#	echo "###########################################################"
		#	pause_with_msg
		#	setterm -default
		#	exit
	#fi

	sudo selinux-activate
	sudo mv $PATH_FILE_SELINUX_CONF $PATH_FILE_SELINUX_CONF.original
	sudo touch $PATH_FILE_SELINUX_CONF
	
	sudo cat <<EOT >> $PATH_FILE_SELINUX_CONF
# Generated by the Avorix Domain Controller install script $DC_SCRIPT_VERSION
# Generated on $(date)
#
# This file controls the state of SELinux on the system.
# SELINUX= can take one of these three values:
#       enforcing - SELinux security policy is enforced.
#       permissive - SELinux prints warnings instead of enforcing.
#       disabled - SELinux is fully disabled.
SELINUX=permissive
# SELINUXTYPE= type of policy in use. Possible values are:
#       targeted - Only targeted network daemons are protected.
#       strict - Full SELinux protection.
SELINUXTYPE=strict

# SETLOCALDEFS= Check local definition changes
SETLOCALDEFS=0
EOT
fi


###########################################################
# 3.2.             Install the main components            #
###########################################################

if [ "$DHCP_SERVER" -eq "1" ]; then
   sudo $PM_INSTALL $PACKAGE_DHCPD $PM_INSTALL_ENDING_VARIABLES
   
	#   if [ "$(dpkg -s isc-dhcp-server 2>/dev/null >/dev/null)" -eq "1" ] ; then
	#		echo "ISC-DHCP-Server is succesfully installed!"
	#		else
	#		setterm -term linux -back red -fore white
	#		echo "###########################################################"
	#		echo "# Error: Installation stopped!                            #"
	#		echo "###########################################################"
	#		echo "Reason:"
	#		echo " - ISC-DHCP-Server could not be installed."
	#		echo ""
	#		echo "Solution:"
	#		echo " - Make sure that:"
	#		echo "	- You have a stable internet connection!"
	#		echo "	- Install it manually."
	#		echo "	- Skip this part."
	#		echo "###########################################################"
	#		pause_with_msg
	#		setterm -default
	#		exit
	#	fi
fi

if [ "$ANTIVIRUS" -eq "1" ]; then
	sudo $PM_INSTALL $PACKAGE_CLAMAV $PM_INSTALL_ENDING_VARIABLES
	sudo touch $PATH_FOLDER_CRON_HOURLY/ClamAV
	sudo cat <<'EOT' >> $PATH_FOLDER_CRON_HOURLY/ClamAV
#!/bin/bash
# Generated by the Avorix Domain Controller install script $DC_SCRIPT_VERSION
# Generated on $(date)
#
# email subject
SUBJECT="VIRUS DETECTED ON `hostname`!!!"
# Email To ?
EMAIL="root@localhost"
# Log location
LOG=/var/log/clamav/scan.log
 
check_scan () {
 
    # Check the last set of results. If there are any "Infected" counts that aren't zero, we have a problem.
    if [ `tail -n 12 ${LOG}  | grep Infected | grep -v 0 | wc -l` != 0 ]
    then
        EMAILMESSAGE=`mktemp /tmp/virus-alert.XXXXX`
        echo "To: ${EMAIL}" >>  ${EMAILMESSAGE}
        echo "From: antivirus@$DCNAME.$FQDN" >>  ${EMAILMESSAGE}
        echo "Subject: ${SUBJECT}" >>  ${EMAILMESSAGE}
        echo "Importance: High" >> ${EMAILMESSAGE}
        echo "X-Priority: 1" >> ${EMAILMESSAGE}
        echo "`tail -n 50 ${LOG}`" >> ${EMAILMESSAGE}
        sendmail -t < ${EMAILMESSAGE}
    fi
 
}
 
find / -not -wholename '/sys/*' -and -not -wholename '/proc/*' -mmin -61 -type f -print0 | xargs -0 -r clamscan --exclude-dir=/proc/ --exclude-dir=/sys/ --quiet --infected --log=${LOG}
check_scan
 
find / -not -wholename '/sys/*' -and -not -wholename '/proc/*' -cmin -61 -type f -print0 | xargs -0 -r clamscan --exclude-dir=/proc/ --exclude-dir=/sys/ --quiet --infected --log=${LOG}
check_scan
EOT
	
	#if [ "$(dpkg -s clamav 2>/dev/null >/dev/null)" -eq "0" ] ; then
	#		echo "ClamAV is succesfully installed!"
	#else
	#	setterm -term linux -back red -fore white
	#	echo "###########################################################"
	#	echo "# Error: Installation stopped!                            #"
	#	echo "###########################################################"
	#	echo "Reason:"
	#	echo " - ClamAV could not be installed."
	#	echo ""
	#	echo "Solution:"
	#	echo " - Make sure that:"
	#	echo "	- You have a stable internet connection!"
	#	echo "	- Install it manually."
	#	echo "	- Skip this part."
	#	echo "###########################################################"
	#	pause_with_msg
	#	setterm -default
	#	exit
	#fi

	#if [ "$(dpkg -s clamav-freshclam 2>/dev/null >/dev/null)" -eq "0" ] ; then
	#	echo "ClamAV-FreshClam is succesfully installed!"
	#	else
	#	setterm -term linux -back red -fore white
	#	echo "###########################################################"
	#	echo "# Error: Installation stopped!                            #"
	#	echo "###########################################################"
	#	echo "Reason:"
	#	echo " - ClamAV-FreshClam could not be installed."
	#	echo ""
	#	echo "Solution:"
	#	echo " - Make sure that:"
	#	echo "	- You have a stable internet connection!"
	#	echo "	- Install it manually."
	#	echo "	- Skip this part."
	#	echo "###########################################################"
	#	pause_with_msg
	#	setterm -default
	#	exit
	#fi
fi

if [ "$FIREWALL" -eq "1" ]; then
    sudo $PM_INSTALL $PACKAGE_FIREWALLD $PM_INSTALL_ENDING_VARIABLES
	
	#if [ "$(dpkg -s firewalld 2>/dev/null >/dev/null)" -eq "0" ] ; then
	#	echo "FirewallD is succesfully installed!"
	#	sudo systemctl start $DAEMON_FIREWALD
	#else
	#	setterm -term linux -back red -fore white
	#	echo "###########################################################"
	#	echo "# Error: Installation stopped!                            #"
	#	echo "###########################################################"
	#	echo "Reason:"
	#	echo " - FirewallD could not be installed."
	#	echo ""
	#	echo "Solution:"
	#	echo " - Make sure that:"
	#	echo "	- You have a stable internet connection!"
	#	echo "	- Install it manually."
	#	echo "	- Skip this part."
	#	echo "###########################################################"
	#	pause_with_msg
	#	setterm -default
	#	exit
	#fi
fi

if [ "$SSH_SERVER" -eq "1" ] ; then
    sudo $PM_INSTALL $PACKAGE_OPENSSHD $PM_INSTALL_ENDING_VARIABLES
#    if [ "$(dpkg -s openssh-server 2>/dev/null >/dev/null)" -eq "0" ] ; then
#		echo "OpenSSH-Server is succesfully installed!"
#		else
#		setterm -term linux -back red -fore white
#		echo "###########################################################"
#		echo "# Error: Installation stopped!                            #"
#		echo "###########################################################"
#		echo "Reason:"
#		echo " - OpenSSH-Server could not be installed."
#		echo ""
#		echo "Solution:"
#		echo " - Make sure that:"
#		echo "	- You have a stable internet connection!"
#		echo "	- Install it manually."
#		echo "	- Skip this part."
#		echo "###########################################################"
#		pause_with_msg
#		setterm -default
#		exit
#	fi
	if [ "$SSH_PORTKNOCKING" -eq "1" ] ; then
		sudo $PM_INSTALL $PACKAGE_KNOCKD $PM_INSTALL_ENDING_VARIABLES
	fi
	if [ "$SSH_FAIL2BAN" -eq "1" ] ; then
		sudo $PM_INSTALL $PACKAGE_FAIL2BAN $PM_INSTALL_ENDING_VARIABLES
	fi
fi

if [ "$PXE_SERVER" -eq "2" ]; then

    sudo $PM_INSTALL $PACKAGE_TFTPD $PACKAGE_APACHE $PM_INSTALL_ENDING_VARIABLES
#		else
#		setterm -term linux -back red -fore white
#		echo "###########################################################"
#		echo "# Error: Installation stopped!                            #"
#		echo "###########################################################"
#		echo "Reason:"
#		echo " - TFTPd-HPA could not be installed."
#		echo ""
#		echo "Solution:"
#		echo " - Make sure that:"
#		echo "	- You have a stable internet connection!"
#		echo "	- Install it manually."
#		echo "	- Skip this part."
#		echo "###########################################################"
#		pause_with_msg
#		setterm -default
#		exit
#	fi
fi

sudo $PM_INSTALL $PACKAGE_SAMBA $PACKAGE_NTP $PM_INSTALL_ENDING_VARIABLES
#if [ "$(dpkg -s samba 2>/dev/null >/dev/null)" -eq "0" ] ; then
#	echo "SAMBA is succesfully installed!"
#	else
#	setterm -term linux -back red -fore white
#	echo "###########################################################"
#	echo "# Error: Installation stopped!                            #"
#	echo "###########################################################"
#	echo "Reason:"
#	echo " - SAMBA could not be installed."
#	echo ""
#	echo "Solution:"
#	echo " - Make sure that:"
#	echo "	- You have a stable internet connection!"
#	echo "	- Install it manually."
#	echo "	- Skip this part."
#	echo "###########################################################"
#	pause_with_msg
#	setterm -default
#	exit
#fi

#if [ "$(dpkg -s samba-vfs-modules 2>/dev/null >/dev/null)" -eq "0" ] ; then
#	echo "The SAMBA-VFS-Modules are succesfully installed!"
#	else
#	setterm -term linux -back red -fore white
#	echo "###########################################################"
#	echo "# Error: Installation stopped!                            #"
#	echo "###########################################################"
#	echo "Reason:"
#	echo " - The SAMBA-VFS-Modules could not be installed."
#	echo ""
#	echo "Solution:"
#	echo " - Make sure that:"
#	echo "	- You have a stable internet connection!"
#	echo "	- Install it manually."
#	echo "	- Skip this part."
#	echo "###########################################################"
#	pause_with_msg
#	setterm -default
#	exit
#fi

#if [ "$(dpkg -s ntp 2>/dev/null >/dev/null)" -eq "0" ] ; then
#	echo "NTP is succesfully installed!"
#	else
#	setterm -term linux -back red -fore white
#	echo "###########################################################"
#	echo "# Error: Installation stopped!                            #"
#	echo "###########################################################"
#	echo "Reason:"
#	echo " - NTP could not be installed."
#	echo ""
#	echo "Solution:"
#	echo " - Make sure that:"
#	echo "	- You have a stable internet connection!"
#	echo "	- Install it manually."
#	echo "	- Skip this part."
#	echo "###########################################################"
#	pause_with_msg
#	setterm -default
#	exit
#fi


if [ "$WEBMIN" -eq "1" ]; then

sudo apt-get install perl libnet-ssleay-perl openssl libauthen-pam-perl libpam-runtime libio-pty-perl apt-show-versions python
cd /root
sudo wget http://prdownloads.sourceforge.net/webadmin/webmin_1.840_all.deb
sudo dpkg --install webmin_1.840_all.deb
sudo rm webmin_1.840_all.deb
sudo wget http://www.webmin.com/jcameron-key.asc
sudo apt-key add jcameron-key.asc
sudo sh -c "echo 'deb http://download.webmin.com/download/repository sarge contrib' >> /etc/apt/sources.list"
fi

###########################################################
# 3.3.                Configure the timezone                #
###########################################################

sudo timedatectl set-timezone $REGION/$TIMEZONE
sudo timedatectl


###########################################################
# 3.4.            Configure the hosts file                 #
###########################################################

sudo mv $PATH_FILE_HOSTS_CONF $PATH_FILE_HOSTS_CONF.original
sudo touch $LOCATION_OF_IMPORTANT_FILES/General/Configuration/hosts
sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/General/Configuration/hosts $PATH_FILE_HOSTS_CONF

sudo cat <<EOT >> $LOCATION_OF_IMPORTANT_FILES/General/Configuration/hosts
#Generated by the Avorix Domain Controller install script $DC_SCRIPT_VERSION..
#Localhost
127.0.0.1     localhost localhost $DCNAME.$FQDN $DCNAME
::1           localhost ip6-localhost ip6-loopback ip6-$DCNAME.$FQDN ip6-$DCNAME

#Might not be needed.
ff02::1       ip6-allnodes
ff02::2       ip6-allrouters
EOT


###########################################################
# 3.5.                 Change the hostname                #
###########################################################

#Change the hostname and backup the original.
sudo mv $PATH_FILE_HOSTNAME_CONF $PATH_FILE_HOSTNAME_CONF.original
sudo touch $LOCATION_OF_IMPORTANT_FILES/General/Configuration/hostname
sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/General/Configuration/hostname $PATH_FILE_HOSTNAME_CONF

sudo cat <<EOT >> $LOCATION_OF_IMPORTANT_FILES/General/Configuration/hostname
$DCNAME.$FQDN
EOT

#Make the hostname for the current session active.
sudo hostname $DCNAME.$FQDN


###########################################################
# 3.6.         Configure a static IP-address              #
###########################################################

#Change the IP-address to static.
#First create a backup.
sudo mv $PATH_FILE_DHCPCD_CONF $PATH_FILE_DHCPCD_CONF.original
#Create an empty file.
sudo touch $LOCATION_OF_IMPORTANT_FILES/General/Configuration/dhcpcd.conf
#Link that file to the file that wil be used by DHCPCD.
sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/General/Configuration/dhcpcd.conf $PATH_FILE_DHCPCD_CONF
#Fill that file with the text that starts at "#Generated" till "$DNSSERVER2". 
sudo cat <<EOT >> $LOCATION_OF_IMPORTANT_FILES/General/Configuration/dhcpcd.conf
# Generated by the Avorix Domain Controller install script $DC_SCRIPT_VERSION.
# Generated on $(date)
#
# A sample configuration for dhcpcd.
# See dhcpcd.conf(5) for details.

# Allow users of this group to interact with dhcpcd via the control socket.
#controlgroup wheel

# Inform the DHCP server of our hostname for DDNS.
hostname

# Use the hardware address of the interface for the Client ID.
clientid
# or
# Use the same DUID + IAID as set in DHCPv6 for DHCPv4 ClientID as per RFC4361.
#duid

# Persist interface configuration when dhcpcd exits.
persistent

# Rapid commit support.
# Safe to enable by default because it requires the equivalent option set
# on the server to actually work.
option rapid_commit

# A list of options to request from the DHCP server.
option domain_name_servers, domain_name, domain_search, host_name
option classless_static_routes
# Most distributions have NTP support.
option ntp_servers
# Respect the network MTU.
# Some interface drivers reset when changing the MTU so disabled by default.
#option interface_mtu

# A ServerID is required by RFC2131.
require dhcp_server_identifier

# Generate Stable Private IPv6 Addresses instead of hardware based ones
slaac private

# A hook script is provided to lookup the hostname if not set by the DHCP
# server, but it should not be run by default.
nohook lookup-hostname

interface eth0
static ip_address=$IP_ADDRESS/$SUBNETMASK_BITS
static routers=$GATEWAY
static domain_name_servers=$DNSSERVER1, $DNSSERVER2
EOT

sudo ifconfig eth0 $IP_ADDRESS/$SUBNETMASKBITS
sudo systemctl stop $DAEMON_DHCPCD
sleep 5s
sudo systemctl start $DAEMON_DHCPCD

#Check if the DHCPCD configuration passes DHCPCD's test.
if [ $(systemctl is-active $DAEMON_DHCPCD) = "active" ]; then
	DHCPCD_STATUS=1
	sudo systemctl enable $DAEMON_DHCPCD
else
	DHCPCD_STATUS=0
	setterm -term linux -back red -fore white
	echo "###########################################################"
	echo "# Error: Installation stopped!                            #"
	echo "###########################################################"
	echo "Reason:"
	echo " - Your Network (DHCPCD) settings are incorrect."
	echo ""
	echo "Solution:"
	echo " - Make sure that the settings abide to:"
	echo "	- Not containing any illegal characters!"
	echo "	- Correct IP-addresses."
	echo "	- Correct Subnetmaskbits: Calculate one at: http://jodies.de/ipcalc"
	echo "  - Check: systemctl $DAEMON_DHCPCD status -l, for more details."
	echo "###########################################################"
	pause_with_msg
	setterm -default
	exit
fi


###########################################################
# 3.7.          Configure the NTP-server                   #
###########################################################
#If function FIREWALL is enabled then allow NTP to send and recieve over the network.
if [ "$FIREWALL" -eq "1" ]; then
	sudo firewall-cmd --permanent --zone=public --add-port=123/udp
fi

sudo mv $PATH_FILE_NTP_CONF $PATH_FILE_NTP_CONF.original
sudo touch $LOCATION_OF_IMPORTANT_FILES/NTPD/Configuration/ntp.conf
sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/NTPD/Configuration/ntp.conf $PATH_FILE_NTP_CONF
sudo cat <<EOT >> $LOCATION_OF_IMPORTANT_FILES/NTPD/Configuration/ntp.conf
# Generated by the Avorix Domain Controller install script $DC_SCRIPT_VERSION
# Generated on $(date)
#
# Local clock. Note that is not the "localhost" address!
server 127.127.1.0
fudge  127.127.1.0 stratum 10

# Where to retrieve the time from
server $NTPSERVER1     iburst prefer
server $NTPSERVER2     iburst prefer
server $NTPSERVER3     iburst prefer

driftfile       $LOCATION_OF_IMPORTANT_FILES/NTPD/Data/ntp.drift
logfile         $LOCATION_OF_IMPORTANT_FILES/NTPD/Logs
ntpsigndsocket  $LOCATION_OF_IMPORTANT_FILES/SAMBA/Sockets/ntp_signd/

# Access control
# Default restriction: Allow clients only to query the time
restrict default kod nomodify notrap nopeer mssntp

# No restrictions for "localhost"
restrict 127.0.0.1

# Enable the time sources to only provide time to this host
restrict $NTPSERVER1   mask 255.255.255.255    nomodify notrap nopeer noquery
restrict $NTPSERVER2   mask 255.255.255.255    nomodify notrap nopeer noquery
restrict $NTPSERVER3   mask 255.255.255.255    nomodify notrap nopeer noquery
EOT
sudo systemctl stop $DAEMON_NTP
sleep 5s
sudo systemctl start $DAEMON_NTP

#Check if the NTP configuration passes NTP's test.
if [ $(systemctl is-active $DAEMON_NTP) = "active" ]; then
	NTP_STATUS=1
	sudo systemctl enable $DAEMON_NTP
else
	NTP_STATUS=0
	setterm -term linux -back red -fore white
	echo "###########################################################"
	echo "# Error: Installation stopped!                            #"
	echo "###########################################################"
	echo "Reason:"
	echo " - Your Time (NTP) settings are incorrect."
	echo ""
	echo "Solution:"
	echo " - Make sure that the settings abide to:"
	echo "	- Not containing any illegal characters!"
	echo "	- Containing a correct Timezone/Region:"
	echo "	  Display all Timezones using: ls /usr/share/zoneinfo"
	echo "	  Display all Regions within a timezone using:"
	echo "	  ls /usr/share/zoneinfo/Your_timezone/"
	echo ""
	echo "  - Check: systemctl $DAEMON_NTP status -l, for more details."
	echo "###########################################################"
	pause_with_msg
	setterm -default
	exit
fi


###########################################################
# 3.8.       Configure the Domain Controller               #
###########################################################
if [ "$FIREWALL" -eq "1" ] ; then
	#SAMBA: DNS
	sudo firewall-cmd --permanent --zone=public --add-port=53/tcp
	sudo firewall-cmd --permanent --zone=public --add-port=53/udp
	
	#SAMBA: Kerberos
	sudo firewall-cmd --permanent --zone=public --add-port=88/tcp
	sudo firewall-cmd --permanent --zone=public --add-port=88/udp
	
	#SAMBA: End Point Mapper (DCE\RPC Locator Service)
	sudo firewall-cmd --permanent --zone=public --add-port=135/tcp
	
	#SAMBA: NetBIOS Name Service
	sudo firewall-cmd --permanent --zone=public --add-port=137/udp
	
	#SAMBA: NetBIOS Datagram
	sudo firewall-cmd --permanent --zone=public --add-port=138/udp
	
	#SAMBA: NetBIOS Session
	sudo firewall-cmd --permanent --zone=public --add-port=139/udp
	
	#SAMBA: LDAP
	sudo firewall-cmd --permanent --zone=public --add-port=389/tcp
	sudo firewall-cmd --permanent --zone=public --add-port=389/udp
	#sudo firewall-cmd --permanent --zone=public --add-port=636/tcp #For TLS-encryption
	
	#SAMBA: SMB over TCP
	sudo firewall-cmd --permanent --zone=public --add-port=445/tcp
	
	#SAMBA: Kerberos kpasswd
	sudo firewall-cmd --permanent --zone=public --add-port=464/tcp
	sudo firewall-cmd --permanent --zone=public --add-port=464/udp

	#SAMBA: Global Catalog
	sudo firewall-cmd --permanent --zone=public --add-port=3268/tcp
	#firewall-cmd --permanent --zone=public --add-port=3269/tcp #For TLS-encryption

	#SAMBA: Dynamic RPC Ports
	sudo firewall-cmd --permanent --add-port=1024-5000/tcp
	sudo firewall-cmd --permanent --add-port=1024-5000/udp
	
fi

#Linking the configs to the USB and creating the DC.
sudo mv $PATH_FILE_SAMBA_CONF $PATH_FILE_SAMBA_CONF.original

if [ "JOIN_A_DOMAIN" -eq "1" ] ; then

	sudo cp $PATH_FILE_KRB5_CONF_EXAMPLE $LOCATION_OF_IMPORTANT_FILES/Kerberos/Configuration/krb5.conf
	sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/Kerberos/Configuration/krb5.conf $PATH_FILE_KRB5_CONF
	sudo cat <<EOT >> $LOCATION_OF_IMPORTANT_FILES/Kerberos/Configuration/krb5.conf
[libdefaults]
    dns_lookup_realm = false
    dns_lookup_kdc = true
    default_realm = $FQDN
	
EOT
	
	sudo samba-tool domain join $FQDN DC -U "$NBIOS\administrator" --dns-backend=SAMBA_INTERNAL
	sudo cp $PATH_FILE_SAMBA_CONF $PATH_FILE_SAMBA_CONF.after_provision
	sudo mv $PATH_FILE_SAMBA_CONF $LOCATION_OF_IMPORTANT_FILES/SAMBA/Configuration/smb.conf
	sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/SAMBA/Configuration/smb.conf $PATH_FILE_SAMBA_CONF

else
	sudo samba-tool domain provision --server-role=dc --use-rfc2307 --dns-backend=SAMBA_INTERNAL --realm=$FQDN --domain=$NBIOS --host-name=$DCNAME --adminpass="$ADMINPWD" --host-ip=$IP_ADDRESS
	sudo cp $PATH_FILE_SAMBA_CONF $PATH_FILE_SAMBA_CONF.after_provision
	sudo mv $PATH_FILE_SAMBA_CONF $LOCATION_OF_IMPORTANT_FILES/SAMBA/Configuration/smb.conf
	sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/SAMBA/Configuration/smb.conf $PATH_FILE_SAMBA_CONF

	sudo cp $PATH_FILE_KRB5_CONF_EXAMPLE $LOCATION_OF_IMPORTANT_FILES/Kerberos/Configuration/krb5.conf
	sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/Kerberos/Configuration/krb5.conf $PATH_FILE_KRB5_CONF

	sudo cat <<EOT >> $LOCATION_OF_IMPORTANT_FILES/SAMBA/Configuration/smb.conf

[users]
       path = $LOCATION_OF_IMPORTANT_FILES/SAMBA/Shares/Users
	   
       read only = no
EOT
fi

if [ "$PXE_SERVER" -eq "2" ] ; then
	sudo cat <<EOT >> $LOCATION_OF_IMPORTANT_FILES/SAMBA/Configuration/smb.conf

[wininstall]
	comment = Windows Installers
    path = $LOCATION_OF_IMPORTANT_FILES/PXE/SAMBA
	guest ok = yes
	writable = no
	browsable = yes
EOT
fi

sudo systemctl stop $DAEMON_SMBD
sleep 5s
sudo systemctl start $DAEMON_SMBD
sleep 1s
sudo systemctl stop $DAEMON_NMBD
sleep 5s
sudo systemctl start $DAEMON_NMBD
sleep 1s
sudo systemctl stop $DAEMON_SAMBA_AD_DC
sleep 5s
sudo systemctl start $DAEMON_SAMBA_AD_DC

#Check if the SAMBA configuration passes SAMBA's test.
if [ $(systemctl is-active $DAEMON_NMBD) = "active" ] && [ $(systemctl is-active $DAEMON_NMBD) = "active" ] && [ $(systemctl is-active $DAEMON_SAMBA_AD_DC) = "active" ] ; then
	SAMBA_STATUS=1
	sudo systemctl enable $DAEMON_SMBD
	sudo systemctl enable $DAEMON_NMBD
	sudo systemctl enable $DAEMON_SAMBA_AD_DC
else
	SAMBA_STATUS=0
	setterm -term linux -back red -fore white
	echo "###########################################################"
	echo "# Error: Installation stopped!                            #"
	echo "###########################################################"
	echo "Reason:"
	echo " - Your SAMBA settings are incorrect."
	echo ""
	echo "Solution:"
	echo " - Make sure that the settings abide to:"
	echo "	- Not containing any illegal characters!"
	echo "	- Containing a correct FQDN, NetBiosname and DCName."
	echo "  - Check: systemctl $DAEMON_SMBD status -l, for more details."
	echo "  - Check: systemctl $DAEMON_NMBD status -l, for more details."
	echo "  - Check: systemctl $DAEMON_SAMBA_AD_DC status -l, for more details."
	echo "###########################################################"
	pause_with_msg
	setterm -default
	exit
fi


###########################################################
#                                                         #
# 4.                The fase of adaption                  #
#                                                         #
###########################################################

###########################################################
# 4.1. (Optional)          Configure SSH                    #
###########################################################
#SSH allows us to remotely open a terminal shell.
#Within a terminal shell we are able to completely modify the system.
#But if you are only in to modifying Active Directory just install the RSAT-tools, you won't need SSH.

if [ "$SSH_SERVER" -eq "1" ] ; then
	#If the SSH user needs SSH access, create the SSH group and the SSH user.
	if [ "$SSH_USER_SUDO" -eq "1" ] ; then
		sudo groupadd ssh
		sudo echo '%ssh  ALL=(ALL:ALL) ALL' >> $PATH_FILE_SUDO_CONF
		sudo useradd $SSH_USER -p "$SSH_USER_PASSWORD" -d /home/$SSH_USER -g ssh -g sudo -m
	else
		sudo groupadd ssh
		sudo mkdir /home/$SSH_USER
		sudo useradd $SSH_USER -p "$SSH_USER_PASSWORD" -d /home/$SSH_USER -g ssh -m
	fi
	
	if [ "$FIREWALL" -eq "1" ] ; then
		if [ "SSH_PORTKNOCKING" -eq "1" ] ; then
			#sudo cp $PATH_FILE_KNOCKD_CONF $LOCATION_OF_IMPORTANT_FILES/KNOCKD/Configuration
			sudo cp $PATH_FILE_KNOCKD_DEFAULT $LOCATION_OF_IMPORTANT_FILES/KNOCKD/Configuration/default/
			
			sudo mv $PATH_FILE_KNOCKD_CONF $PATH_FILE_KNOCKD_CONF.original
			sudo mv $PATH_FILE_KNOCKD_DEFAULT $PATH_FILE_KNOCKD_DEFAULT.original

			sudo touch $PATH_FILE_KNOCKD_CONF
			sudo touch $PATH_FILE_KNOCKD_DEFAULT

			sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/KNOCKD/Configuration/knockd.conf $PATH_FILE_KNOCKD_CONF
			sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/KNOCKD/Configuration/default/knockd $PATH_FILE_KNOCKD_DEFAULT

			cat <<EOT >> $LOCATION_OF_IMPORTANT_FILES/KNOCKD/Configuration/knockd.conf
[options]
    logfile = $LOCATION_OF_IMPORTANT_FILES/KNOCKD/Logs/knockd.log

[openSSH]
	sequence    = $SSH_PORTKNOCKING_OPEN_SEQ1,$SSH_PORTKNOCKING_OPEN_SEQ2,$SSH_PORTKNOCKING_OPEN_SEQ3
	seq_timeout = 10
	command 	= /usr/sbin/firewall-cmd --permanent --zone=public --add-rich-rule='rule family="ipv4" source address="%IP%" port protocol="tcp" port="$SSH_PORT" accept'
	tcpflags    = syn

[closeSSH]
	sequence    = $SSH_PORTKNOCKING_CLOSE_SEQ1,$SSH_PORTKNOCKING_CLOSE_SEQ1,$SSH_PORTKNOCKING_CLOSE_SEQ1
	seq_timeout = 10
	command     = /usr/sbin/firewall-cmd --permanent --zone=public --remove-rich-rule='rule family="ipv4" source address="%IP%" port protocol="tcp" port="$SSH_PORT" accept'
	tcpflags    = syn
EOT
			sed -i -e 's/START_KNOCKD=0/START_KNOCKD=1/g' $PATH_FILE_KNOCKD
			
			sudo systemctl start $DAEMON_KNOCKD
			sudo systemctl enable $DAEMON_KNOCKD
		else
			sudo firewall-cmd --permanent --zone=public --add-port=$SSH_PORT/tcp
		fi
		if [ "SSH_FAIL2BAN" -eq "1" ] ; then
			sudo cp $PATH_FILE_FAIL2BAN_JAIL $LOCATION_OF_IMPORTANT_FILES/FAIL2BAN/Configuration/jail.local
			sudo mv $PATH_FILE_FAIL2BAN_JAIL $PATH_FILE_FAIL2BAN_JAIL.original
			sudo touch $PATH_FILE_TFTPD_CONF
			sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/FAIL2BAN/Configuration/jail.local $PATH_FILE_FAIL2BAN_JAIL
			sudo cat <<'EOT' >> $LOCATION_OF_IMPORTANT_FILES/FAIL2BAN/Configuration/jail.local
[ssh]
 
enabled = true
port = $SSH_PORT
filter = sshd
logpath = $LOCATION_OF_IMPORTANT_FILES/FAIL2BAN/Logs/auth.log
bantime = $SSH_FAIL2BAN_BANTIME
banaction = iptables-allports
findtime = $SSH_FAIL2BAN_FINDTIME
maxretry = $SSH_FAIL2BAN_MAXRETRY
EOT

			sudo systemctl start $DAEMON_FAIL2BAN
			sudo systemctl enable $DAEMON_FAIL2BAN
		fi
	fi
	
    sudo mv $PATH_FOLDER_SSH_KEYS/ssh_host_* $LOCATION_OF_IMPORTANT_FILES/SSH/Configuration/Keys/ 
    sudo mv $PATH_FILE_SSH_CONF $PATH_FILE_SSH_CONF.original
    sudo touch $PATH_FILE_SSH_CONF
    sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/SSH/Configuration/sshd_config $PATH_FILE_SSH_CONF
   
    sudo cat <<EOT >> $LOCATION_OF_IMPORTANT_FILES/SSH/Configuration/sshd_config
# Generated by the Avorix Domain Controller install script $DC_SCRIPT_VERSION
# Generated on $(date)
# See the sshd_config(5) manpage for details

# What ports, IPs and protocols we listen for
Port 22
# Use these options to restrict which interfaces/protocols sshd will bind to
#ListenAddress ::
#ListenAddress 0.0.0.0
Protocol 2
# HostKeys for protocol version 2
HostKey $LOCATION_OF_IMPORTANT_FILES/SSH/Configuration/Keys/ssh_host_rsa_key
HostKey $LOCATION_OF_IMPORTANT_FILES/SSH/Configuration/Keys/ssh_host_dsa_key
HostKey $LOCATION_OF_IMPORTANT_FILES/SSH/Configuration/Keys/ssh_host_ecdsa_key
HostKey $LOCATION_OF_IMPORTANT_FILES/SSH/Configuration/Keys/ssh_host_ed25519_key
#Privilege Separation is turned on for security
UsePrivilegeSeparation yes

# Lifetime and size of ephemeral version 1 server key
KeyRegenerationInterval 3600
ServerKeyBits 1024

# Logging
SyslogFacility AUTH
LogLevel INFO

# Authentication:
LoginGraceTime 120
PermitRootLogin yes
StrictModes yes

RSAAuthentication yes
PubkeyAuthentication yes
#AuthorizedKeysFile     %h/.ssh/authorized_keys

# Don't read the user's ~/.rhosts and ~/.shosts files
IgnoreRhosts yes
# For this to work you will also need host keys in /etc/ssh_known_hosts
RhostsRSAAuthentication no
# similar for protocol version 2
HostbasedAuthentication no
# Uncomment if you don't trust ~/.ssh/known_hosts for RhostsRSAAuthentication
#IgnoreUserKnownHosts yes

# To enable empty passwords, change to yes (NOT RECOMMENDED)
PermitEmptyPasswords no

# Change to yes to enable challenge-response passwords (beware issues with
# some PAM modules and threads)
EOT

	if [ "$SSH_2FA" -eq "1" ] ; then
	sudo sed -i '1s/^/auth required pam_google_authenticator.so\n/' $PATH_FILE_PAMD_SSHD
    sudo cat <<EOT >> $LOCATION_OF_IMPORTANT_FILES/SSH/Configuration/sshd_config
ChallengeResponseAuthentication yes
EOT
	else
	sudo cat <<EOT >> $LOCATION_OF_IMPORTANT_FILES/SSH/Configuration/sshd_config
ChallengeResponseAuthentication no
EOT
	fi
sudo cat <<EOT >> $LOCATION_OF_IMPORTANT_FILES/SSH/Configuration/sshd_config

# Change to no to disable tunnelled clear text passwords
PasswordAuthentication yes

# Kerberos options
#KerberosAuthentication no
#KerberosGetAFSToken no
#KerberosOrLocalPasswd yes
#KerberosTicketCleanup yes

# GSSAPI options
#GSSAPIAuthentication no
#GSSAPICleanupCredentials yes

X11Forwarding yes
X11DisplayOffset 10
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
#UseLogin no

#MaxStartups 10:30:60
Banner /etc/issue.net

# Allow client to pass locale environment variables
AcceptEnv LANG LC_*

Subsystem sftp /usr/lib/openssh/sftp-server

# Set this to 'yes' to enable PAM authentication, account processing,
# and session processing. If this is enabled, PAM authentication will
# be allowed through the ChallengeResponseAuthentication and
# PasswordAuthentication.  Depending on your PAM configuration,
# PAM authentication via ChallengeResponseAuthentication may bypass
# the setting of "PermitRootLogin without-password".
# If you just want the PAM account and session checks to run without
# PAM authentication, then enable this but set PasswordAuthentication
# and ChallengeResponseAuthentication to 'no'.
UsePAM yes

# Automaticly kick the user after 5 minutes of inactivity.
# ClientAliveInterval 300
# ClientAliveCountMax 0

# Only allow users that are in the SSH-group.
# AllowGroups ssh
EOT

sudo systemctl stop $DAEMON_SSH
sleep 5s
sudo systemctl start $DAEMON_SSH

#Check if the SSH configuration passes SSH's test.
	if [ $(systemctl is-active $DAEMON_SSH) = "active" ]; then
		SSH_STATUS=1
		sudo systemctl enable $DAEMON_SSH
	else
		SSH_STATUS=0
		setterm -term linux -back red -fore white
		echo "###########################################################"
		echo "# Error: Installation stopped!                            #"
		echo "###########################################################"
		echo "Reason:"
		echo " - Your SSH settings are incorrect."
		echo ""
		echo "Solution:"
		echo " - Make sure that the settings abide to:"
		echo "	- Not containing any illegal characters!"
		echo "	- Containing a correct portnumber."
		echo "  - Check: systemctl $DAEMON_SSH status -l, for more details."
		echo "###########################################################"
		pause_with_msg
		setterm -default
		exit
	fi
fi


###########################################################
# 4.2.     (Optional) Configure the DHCP server           #
###########################################################
#In some situations and environments you do not want to have an additional DHCP-server.
#As there can only be 1 DHCP-server in a network. Having multiple will cause network failure.
#But to make the Domain Controller reachable you will need to let the DHCP-server instruct the devices on the network
#to use the DNS, NTP and the NetBIOS server of the Domain Controller.
if [ "$DHCP_SERVER" -eq "1" ] && [ "$FIREWALL" -eq "1" ] ; then
	sudo firewall-cmd --permanent --zone=public --add-port=67/udp
fi

if [ "$DHCP_SERVER" -eq "1" ] ; then
	sudo mv $PATH_FILE_DHCPD_CONF $PATH_FILE_DHCPD_CONF.original
	sudo touch $LOCATION_OF_IMPORTANT_FILES/DHCP/Configuration/dhcpd.conf
	sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/DHCP/Configuration/dhcpd.conf $PATH_FILE_DHCPD_CONF

	sudo cat <<EOT >> $LOCATION_OF_IMPORTANT_FILES/DHCP/Configuration/dhcpd.conf
# Generated by the Avorix Domain Controller install script $DC_SCRIPT_VERSION
# Generated on $(date)

EOT
	if [ "$PXE_SERVER" -eq "2" ] ; then
	sudo cat <<EOT >> $LOCATION_OF_IMPORTANT_FILES/DHCP/Configuration/dhcpd.conf
  option space ipxe;
  option ipxe-encap-opts code 175 = encapsulate ipxe;
  option ipxe.priority code 1 = signed integer 8;
  option ipxe.keep-san code 8 = unsigned integer 8;
  option ipxe.skip-san-boot code 9 = unsigned integer 8;
  option ipxe.syslogs code 85 = string;
  option ipxe.cert code 91 = string;
  option ipxe.privkey code 92 = string;
  option ipxe.crosscert code 93 = string;
  option ipxe.no-pxedhcp code 176 = unsigned integer 8;
  option ipxe.bus-id code 177 = string;
  option ipxe.bios-drive code 189 = unsigned integer 8;
  option ipxe.username code 190 = string;
  option ipxe.password code 191 = string;
  option ipxe.reverse-username code 192 = string;
  option ipxe.reverse-password code 193 = string;
  option ipxe.version code 235 = string;
  option iscsi-initiator-iqn code 203 = string;
  
  # Feature indicators
  option ipxe.pxeext code 16 = unsigned integer 8;
  option ipxe.iscsi code 17 = unsigned integer 8;
  option ipxe.aoe code 18 = unsigned integer 8;
  option ipxe.http code 19 = unsigned integer 8;
  option ipxe.https code 20 = unsigned integer 8;
  option ipxe.tftp code 21 = unsigned integer 8;
  option ipxe.ftp code 22 = unsigned integer 8;
  option ipxe.dns code 23 = unsigned integer 8;
  option ipxe.bzimage code 24 = unsigned integer 8;
  option ipxe.multiboot code 25 = unsigned integer 8;
  option ipxe.slam code 26 = unsigned integer 8;
  option ipxe.srp code 27 = unsigned integer 8;
  option ipxe.nbi code 32 = unsigned integer 8;
  option ipxe.pxe code 33 = unsigned integer 8;
  option ipxe.elf code 34 = unsigned integer 8;
  option ipxe.comboot code 35 = unsigned integer 8;
  option ipxe.efi code 36 = unsigned integer 8;
  option ipxe.fcoe code 37 = unsigned integer 8;
  option ipxe.vlan code 38 = unsigned integer 8;
  option ipxe.menu code 39 = unsigned integer 8;
  option ipxe.sdi code 40 = unsigned integer 8;
  option ipxe.nfs code 41 = unsigned integer 8;
  option ipxe.no-pxedhcp 1;
  
EOT
	fi

	sudo cat <<EOT >> $LOCATION_OF_IMPORTANT_FILES/DHCP/Configuration/dhcpd.conf
autorative;

subnet $DHCP_SUBNET netmask $DHCP_SUBNETMASK {
  max-lease-time $DHCP_MAX_LEASE_TIME; # 30 minutes
  range $DHCP_FIRST_IP_ADDRESS $DHCP_LAST_IP_ADDRESS;
  option subnet-mask $DHCP_SUBNETMASK;
  option broadcast-address $BROADCASTADDRESS;
  option time-offset 0;
  option routers $DHCP_GATEWAY;
  option domain-name "$FQDN";
  option domain-name-servers $DHCP_DNSSERVER1, $DHCP_DNSSERVER2;
  option netbios-name-servers $DHCP_NETBIOSSERVER;
  option ntp-servers $DHCP_NTPSERVER1, $DHCP_NTPSERVER2;
EOT

	if [ "$PXE_SERVER" -eq "2" ] ; then
		#Had to split these up as Cat doesn't like some characters.
		sudo cat <<EOT >> $LOCATION_OF_IMPORTANT_FILES/DHCP/Configuration/dhcpd.conf
  next-server $IP_ADDRESS;
EOT
		sudo cat <<'EOT' >> $LOCATION_OF_IMPORTANT_FILES/DHCP/Configuration/dhcpd.conf
  option client-arch code 93 = unsigned integer 16;
  if option client-arch != 0 {
     filename "ipxe.efi";
  } else {
     filename "undionly.kpxe";
  }
  
  if exists user-class and option user-class = "iPXE" {
EOT

		sudo cat <<EOT >> $LOCATION_OF_IMPORTANT_FILES/DHCP/Configuration/dhcpd.conf
    filename = "http://$IP_ADDRESS/boot.ipxe";
EOT
		sudo cat <<'EOT' >> $LOCATION_OF_IMPORTANT_FILES/DHCP/Configuration/dhcpd.conf
  } else {
	filename = "undionly.kpxe";
  }
EOT

		sudo cat <<EOT >> $LOCATION_OF_IMPORTANT_FILES/DHCP/Configuration/dhcpd.conf
}
EOT
		sudo cat <<'EOT' >> $PXE_TFTP_ROOT/boot.ipxe
  #!ipxe
  
  cpuid --ext 29 && set arch amd64 || set arch x86
  kernel wimboot
  initrd ${arch}/media/Boot/BCD                     BCD
  initrd ${arch}/media/Boot/boot.sdi                boot.sdi
  initrd ${arch}/media/sources/boot.wim             boot.wim
  boot
EOT

	fi

	sudo systemctl stop $DAEMON_DHCPD
	sleep 5s
	sudo systemctl start $DAEMON_DHCPD

#Check if the ISC-DHCP-Server configuration passes ISC-DHCP-Server's test.
	if [ $(systemctl is-active $DAEMON_DHCPD) = "active" ] ; then
		DHCPD_STATUS=1
		sudo systemctl enable $DAEMON_DHCPD
	else
		DHCPD_STATUS=0
		setterm -term linux -back red -fore white
		echo "###########################################################"
		echo "# Error: Installation stopped!                            #"
		echo "###########################################################"
		echo "Reason:"
		echo " - Your DHCP settings are incorrect."
		echo ""
		echo "Solution:"
		echo " - Make sure that the settings abide to:"
		echo "	- Not containing any illegal characters!"
		echo "	- Containing a correct FQDN, NetBiosname and DCName."
		echo "  - Check: systemctl $DAEMON_DHCPD status -l, for more details."
		echo "###########################################################"
		pause_with_msg
		setterm -default
		exit
	fi

fi


###########################################################
# 4.3.       (Optional) Configure the PXE-server          #
###########################################################

if [ "$PXE_SERVER" -eq "1" ] ; then

		if [ "$FIREWALL" -eq "1" ]; then
		sudo firewall-cmd --permanent --zone=public --add-port=69/udp
		sudo firewall-cmd --permanent --zone=public --add-port=80/udp
		fi

#    if [ "$(dpkg -s tftpd-hpa 2>/dev/null >/dev/null)" -eq "0" ] ; then
#		echo "OTFTPd-HPA is succesfully installed!"
		sudo curl http://boot.ipxe.org/undionly.kpxe -o $PXE_TFTP_ROOT/undionly.kpxe
		sudo curl http://boot.ipxe.org/ipxe.efi -o $PXE_TFTP_ROOT/ipxe.efi
		sudo mkdir /avorix_temp/dc -f
		sudo curl http://git.ipxe.org/releases/wimboot/wimboot-latest.tar.gz /avorix-temp/dc/wimboot-latest.tar.gz
		sudo tar xvf wimboot-latest.tar.gz -C /avorix-temp/dc/wimboot
		sudo find /avorix-temp/dc/wimboot -name 'wimboot' -exec cp {} $PXE_HTTP_ROOT/  \;
		sudo rm -Rf /avorix-temp

		sudo touch $PXE_TFTP_ROOT/boot.ipxe
		
		sudo systemctl start $DAEMON_TFTPD
		sleep 5s
		sudo systemctl stop $DAEMON_TFTPD

		sudo cp $PATH_FILE_TFTPD_CONF $LOCATION_OF_IMPORTANT_FILES/PXE/Configuration/tftpd-hpa.conf
		sudo mv $PATH_FILE_TFTPD_CONF $PATH_FILE_TFTPD_CONF.original
		sudo touch $PATH_FILE_TFTPD_CONF
		sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/PXE/Configuration/tftpd-hpa.conf $PATH_FILE_TFTPD_CONF
		sed -i -e 's/TFTP_DIRECTORY="/srv/tftp"/TFTP_DIRECTORY="$PXE_TFTP_ROOT"/g' $PATH_FILE_TFTPD_CONF
		sudo systemctl start $DAEMON_TFTPD
		sudo systemctl enable $DAEMON_TFTPD
		
		sudo touch $PATH_FOLDER_APACHE_SITES_ENABLED/Apache_iPXE.conf
		sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/PXE/Configuration/Apache_PXE.conf $PATH_FOLDER_APACHE_SITES_ENABLED/Apache_iPXE.conf
		
		sudo cat <<EOT >> $LOCATION_OF_IMPORTANT_FILES/PXE/Configuration/Apache_iPXE.conf
# Generated by the Avorix Domain Controller install script $DC_SCRIPT_VERSION.
# Generated on $(date)

	<VirtualHost *:80>
	# The ServerName directive sets the request scheme, hostname and port that
	# the server uses to identify itself. This is used when creating
	# redirection URLs. In the context of virtual hosts, the ServerName
	# specifies what hostname must appear in the request's Host: header to
	# match this virtual host. For the default virtual host (this file) this
	# value is not decisive as it is used as a last resort host regardless.
	# However, you must set it for any further virtual host explicitly.
	#ServerName www.example.com
	
	ServerSignature Off
	ServerTokens Prod
	FileETag None
	
	<Directory />
	Options None
	Order allow,deny
	Allow from all
	</Directory>

	ServerAdmin webmaster@localhost
	DocumentRoot $LOCATION_OF_IMPORTANT_FILES/PXE/HTTP

	# Available loglevels: trace8, ..., trace1, debug, info, notice, warn,
	# error, crit, alert, emerg.
	# It is also possible to configure the loglevel for particular
	# modules, e.g.
	#LogLevel info ssl:warn

	#ErrorLog ${APACHE_LOG_DIR}/error.log
	#CustomLog ${APACHE_LOG_DIR}/access.log combined

	# For most configuration files from conf-available/, which are
	# enabled or disabled at a global level, it is possible to
	# include a line for only one particular virtual host. For example the
	# following line enables the CGI configuration for this host only
	# after it has been globally disabled with "a2disconf".
	#Include conf-available/serve-cgi-bin.conf
	</VirtualHost>
	# vim: syntax=apache ts=4 sw=4 sts=4 sr noet
EOT
		
		sudo systemctl start $DAEMON_APACHE
		systemctl enable $DAEMON_APACHE
fi


###########################################################
# 4.4.          (Optional) Configure SELinux              #
###########################################################
#SELinux is a security module for the Linux kernel.
#It allows us to create security policy for each process.
#The policies include: Allowing files to be accessed, Allowing services to be run.

if [ "$SELINUX" -eq "1" ] ; then

	#Creates a script that wil check the next day which permissions NTP, SAMBA and DHCP need.
	sudo touch $PATH_FOLDER_CRON_DAILY/Configure-SELinux

	sudo cat <<EOT >> $PATH_FOLDER_CRON_DAILY/Configure-SELinux
#!/bin/bash
# Generated by the Avorix Domain Controller install script $DC_SCRIPT_VERSION
# Generated on $(date)
#
sudo grep smb $PATH_FILE_AUDIT_LOG | sudo audit2allow -M $LOCATION_OF_IMPORTANT_FILES/Kerberos/Configuration/smb
sudo grep ntp $PATH_FILE_AUDIT_LOG | sudo audit2allow -M $LOCATION_OF_IMPORTANT_FILES/Kerberos/Configuration/ntp
sudo grep dhcp $PATH_FILE_AUDIT_LOG | sudo audit2allow -M $LOCATION_OF_IMPORTANT_FILES/Kerberos/Configuration/dhcp
sudo semodule -i $LOCATION_OF_IMPORTANT_FILES/Kerberos/Configuration/smb
sudo semodule -i $LOCATION_OF_IMPORTANT_FILES/Kerberos/Configuration/ntp 
sudo semodule -i $LOCATION_OF_IMPORTANT_FILES/Kerberos/Configuration/dhcp
sudo mv -Rf $PATH_FILE_SELINUX_CONF_REPLACER $PATH_FILE_SELINUX_CONF
sudo rm -Rf $PATH_FOLDER_CRON_DAILY/Configure-SELinux
EOT

	#This file will be replaced with the original /etc/selinux/config once the above script is ran.
	sudo touch 	$PATH_FILE_SELINUX_CONF_REPLACER

	sudo cat <<EOT >> $PATH_FILE_SELINUX_CONF_REPLACER
# Generated by the Avorix Domain Controller install script $DC_SCRIPT_VERSION
# Generated on $(date)
#
# This file controls the state of SELinux on the system.
# SELINUX= can take one of these three values:
#       enforcing - SELinux security policy is enforced.
#       permissive - SELinux prints warnings instead of enforcing.
#       disabled - SELinux is fully disabled.
SELINUX=enforced
# SELINUXTYPE= type of policy in use. Possible values are:
#       targeted - Only targeted network daemons are protected.
#       strict - Full SELinux protection.
SELINUXTYPE=strict

# SETLOCALDEFS= Check local definition changes
SETLOCALDEFS=0
EOT
fi


###########################################################
# 4.5.  (Optional) Configure automatic security updates    #
###########################################################

if [ "$AUTOMATIC_SECURITY_UPDATES" -eq "1" ]; then
	#Check daily for updates and install the security updates.
	sudo cat <<EOT >> $PATH_FOLDER_CRON_DAILY/Install-Security-Updates
#!/bin/bash
# Generated by the Avorix Domain Controller install script $DC_SCRIPT_VERSION
# Generated on $(date)
#
echo "**************" >> $LOCATION_OF_IMPORTANT_FILES/General/Logs/Security-Updates.log
date >> $LOCATION_OF_IMPORTANT_FILES/General/Logs/Security-Updates.log
aptitude update >> $LOCATION_OF_IMPORTANT_FILES/General/Logs/Security-Updates.log
aptitude safe-upgrade -o Aptitude::Delete-Unused=false --assume-yes --target-release `lsb_release -cs`-security >> $LOCATION_OF_IMPORTANT_FILES/General/Logs/Security-Updates.log
echo "Security updates (if any) installed"
EOT

fi


###########################################################
# 4.6.      (Optional) Test & Enable the Firewall         #
###########################################################

if [ "$FIREWALL" -eq "1" ]; then

	sudo systemctl stop $DAEMON_FIREWALD
	sleep 5s
	sudo systemctl start $DAEMON_FIREWALD

	if [ $(systemctl is-active $DAEMON_FIREWALD) = "active" ] ; then
		FIREWALL_STATUS=1
		sudo systemctl enable $DAEMON_FIREWALD
	else
		FIREWALL_STATUS=0
		setterm -term linux -back red -fore white
		echo "###########################################################"
		echo "# Error: Installation stopped!                            #"
		echo "###########################################################"
		echo "Reason:"
		echo " - Your port settings are incorrect."
		echo ""
		echo "Solution:"
		echo " - Make sure that the port numbers abide to:"
		echo "	- Not containing any illegal characters!"
		echo "	- Containing a port number between 1 - 65535."
		echo "	- Containing a port number that is not reserved."
		echo "  - Check: systemctl $DAEMON_FIREWALD status -l, for more details."
		echo "###########################################################"
		pause_with_msg
		setterm -default
		exit
	fi
fi

###########################################################
# 4.7.               Configure a the backups              #
###########################################################

if [ "$BACKUP_DC" -eq "1" } ; then
	sudo crontab -l | { cat; echo "$BACKUP_DC_TIMING /usr/sbin/samba_backup /usr/local/samba $BACKUP_DC_DESTINATION"; } | crontab -
fi

if [ "$BACKUP_LOIP" -eq "1" } ; then
	sudo crontab -l | { cat; echo "$BACKUP_LOIP_TIMING tar cjf $LOCATION_OF_IMPORTANT_FILES/* $BACKUP_LOIP_DESTINATION/loip_$(date +%d%m%y).tar.bz2 --exclude $BACKUP_LOIP_DESTINATION/*"; } | crontab -
fi

###########################################################
# 4.8.        Configure log in/out messages and EULA      #
###########################################################

if [ "$BRANDING" -eq "1" ] ; then
	#Will be displayed after a SSH user had logged in.
	sudo mv /etc/issue /etc/issue.original
	sudo touch /etc/issue
	sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/General/Configuration/issue $PATH_FILE_ISSUE
	sudo cat <<EOT >> $LOCATION_OF_IMPORTANT_FILES/General/Configuration/issue
                           _      _____   _____   __   ___  
       /\                 (_)    |  __ \ / ____| /_ | / _ \ 
      /  \__   _____  _ __ ___  _| |  | | |       | || | | |
     / /\ \ \ / / _ \| '__| \ \/ / |  | | |       | || | | |
    / ____ \ V / (_) | |  | |>  <| |__| | |____   | || |_| |
   /_/    \_\_/ \___/|_|  |_/_/\_\_____/ \_____|  |_(_)___/ 
   
	For more: Github.com/RHeijmann/Avorix-Domain-Controller
                                                          
                                                          
 _____________________________________________________________
|                                                             
| ####          Version: $DC_SCRIPT_VERSION 
| ####      Released at: $DC_RELEASE_DATE
|_____________________________________________________________
 _____________________________________________________________
|                                                             
| ####           Domain: $FQDN 
| ####      Server name: $NBIOS
|_____________________________________________________________
 _____________________________________________________________
|                                                             
|  Current date: \t , \d                                      
|_____________________________________________________________
 _____________________________________________________________
|#############################################################
| This private computer system is only for the use 
| of authorized users. If you are not authorized by its owners
| you must log out immediately.                            
|#############################################################
|_____________________________________________________________
EOT
	
	#Will be displayed after a login using the interface.
	sudo mv /etc/motd /etc/motd.original
	sudo touch /etc/motd
	sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/General/Configuration/motd $PATH_FILE_MOTD
	sudo cat <<EOT >> $LOCATION_OF_IMPORTANT_FILES/General/Configuration/motd
                           _      _____   _____   __   ___  
       /\                 (_)    |  __ \ / ____| /_ | / _ \ 
      /  \__   _____  _ __ ___  _| |  | | |       | || | | |
     / /\ \ \ / / _ \| '__| \ \/ / |  | | |       | || | | |
    / ____ \ V / (_) | |  | |>  <| |__| | |____   | || |_| |
   /_/    \_\_/ \___/|_|  |_/_/\_\_____/ \_____|  |_(_)___/ 
   
	For more: Github.com/RHeijmann/Avorix-Domain-Controller
                                                          
                                                          
 _____________________________________________________________
|                                                             
| ####          Version: $DC_SCRIPT_VERSION 
| ####      Released at: $DC_RELEASE_DATE
|_____________________________________________________________
 _____________________________________________________________
|                                                             
| ####           Domain: $FQDN 
| ####      Server name: $NBIOS
|_____________________________________________________________
 _____________________________________________________________
|                                                             
|  Current date: \t , \d                                      
|_____________________________________________________________
 _____________________________________________________________
|#############################################################
| This private computer system is only for the use 
| of authorized users. If you are not authorized by its owners
| you must log out immediately.                            
|#############################################################
|_____________________________________________________________
EOT

	#Will be displayed after a SSH-authenticator has entered its loginname but still has to enter its password.
	sudo mv /etc/issue.net /etc/issue.net.original
	sudo touch /etc/issue.net
	sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/General/Configuration/issue.net $PATH_FILE_ISSUENET
	sudo cat <<EOT >> $LOCATION_OF_IMPORTANT_FILES/General/Configuration/issue.net
                           _      _____   _____   __   ___  
       /\                 (_)    |  __ \ / ____| /_ | / _ \ 
      /  \__   _____  _ __ ___  _| |  | | |       | || | | |
     / /\ \ \ / / _ \| '__| \ \/ / |  | | |       | || | | |
    / ____ \ V / (_) | |  | |>  <| |__| | |____   | || |_| |
   /_/    \_\_/ \___/|_|  |_/_/\_\_____/ \_____|  |_(_)___/ 
   
	For more: Github.com/RHeijmann/Avorix-Domain-Controller
 _____________________________________________________________
|                                                             |
|                           -EULA-                            |
|_____________________________________________________________|
 _____________________________________________________________ 
|                            -EN-                             |
|_____________________________________________________________|
|                                                             |
|                                                             |
|     This private computer system is for the use             |
|     of authorized users only. Individuals using             |
|     this computer system without authority,                 |
|     or in excess of their authority,                        |
|     are subject to having all of their activities           |
|     on this system monitored and recorded                   |
|     by system personnel.                                    |
|                                                             |
|     Authority can be obtained only with a written           |
|     authorization of the owners or administrators           |
|     of this system.                                         |
|     Owning a login name does not give authority to          |
|     use this system.                                        |
|     The use of potential exploits in order                  |
|     to gain access to this system does not provide          |
|     authorization to the use of this system.                |
|                                                             |
|     In the course of monitoring individuals                 |
|     improperly using this system, or in the                 |
|     course of system maintenance, the activities            |
|     of authorized users may also be monitored.              |
|                                                             |
|     Anyone using this system expressly consents             |
|     to such monitoring and is advised that if               |
|     such monitoring reveals possible evidence               |
|     of criminal activity, system personnel                  |
|     may provide the evidence of such                        |
|     monitoring to law enforcement officials.                |
|                                                             |
|_____________________________________________________________|
































                           _      _____   _____   __   ___  
       /\                 (_)    |  __ \ / ____| /_ | / _ \ 
      /  \__   _____  _ __ ___  _| |  | | |       | || | | |
     / /\ \ \ / / _ \| '__| \ \/ / |  | | |       | || | | |
    / ____ \ V / (_) | |  | |>  <| |__| | |____   | || |_| |
   /_/    \_\_/ \___/|_|  |_/_/\_\_____/ \_____|  |_(_)___/ 
   
	For more: Github.com/RHeijmann/Avorix-Domain-Controller
 _____________________________________________________________
|                                                             | 
| ####      BEFORE YOU AUTHENTICATE READ OUR EULA!       #### |
| ###                                                     ### |
| ####         Scroll upwards to read our EULA.          #### |
|_____________________________________________________________|
EOT

fi


###########################################################
#                                                         #
# 5.           The fase of finisching up                  #
#                                                         #
###########################################################

###########################################################
# 5.1.          Log the current installation               #
###########################################################

sudo cat <<EOT >> $LOCATION_OF_IMPORTANT_FILES/info.avdc
#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!#
#!!!!!!!!!!!!!!! Do not Remove This File !!!!!!!!!!!!!!!!!#
#!!!!! By deleting this file, the developers will not !!!!#
#!!!!!!!!!!!!!! be able to provide support! !!!!!!!!!!!!!!#
#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!#

###########################################################
# 1.                      General                         #
###########################################################
1. Script version: $DC_SCRIPT_VERSION ($DC_RELEASE_DATE)
2. Installation date: $(date)
3. Operating System: $(cat /etc/*-release)
4. Location of the important files: $LOCATION_OF_IMPORTANT_FILES
5. Timezone and Region: $TIMEZONE / $REGION
6. Correct Network settings: $(if [ "$DHCPCD_STATUS" -eq "1" ]; then echo "Yes"; else echo "No"; fi)


###########################################################
# 2.                      Modules                         #
###########################################################
1. DHCP: $(if [ "$DHCP_SERVER" -eq "1" ]; then echo "Yes"; else echo "No"; fi)
    - With: $(if [ "$PXE_SERVER" -eq "2" ]; then echo "PXE"; fi)
2. SSH: $(if [ "$SSH_SERVER" -eq "1" ]; then echo "Yes"; else echo "No"; fi)
	- With: $(if [ "$SSH_PORTKNOCKING" -eq "1" ]; then echo "Portknocking,"; fi) $(if [ "$SSH_FAIL2BAN" -eq "1" ]; then echo "Fail2Ban,"; fi) $(if [ "$SSH_2FA" -eq "1" ]; then echo "2-Factor-Authentication"; fi)


###########################################################
# 3.                Security Functions                    #
###########################################################
1. Automatic Security Updates: $(if [ "$AUTOMATIC_SECURITY_UPDATES" -eq "1" ]; then echo "Yes"; else echo "No"; fi)
2. Firewall: $(if [ "$FIREWALL" -eq "1" ]; then echo "Yes"; else echo "No"; fi)
3. SELinux: $(if [ "$SELINUX" -eq "1" ]; then echo "Yes"; else echo "No"; fi)


###########################################################
# 4.                  Network Settings                    #
###########################################################
1. IP-Address: $IP_ADDRESS
2. Subnetmaskbits: $SUBNETMASK_BITS
3. Gateway: $GATEWAY


###########################################################
# 3.                 Installed packages                   #
###########################################################

#############
### SAMBA ###
#############

Installed correctly: $(if [ "$SAMBA_STATUS" -eq "1" ]; then echo "Yes"; else echo "No"; fi)

### Installation Settings ###
1. Fully Qualified Domain Name: $FQDN
2. NetBIOS name: $NBIOS
3. Name of the Domain Controller: $DCNAME

### Packages ###

SAMBA:
	$(dpkg -p samba)

SAMBA-Winbind:
	$(dpkg -p samba-winbind)
	
SAMBA-VFS-Modules:
	$(dpkg -p samba-vfs-modules)


#############
###  NTP  ###
#############

Installed correctly: $(if [ "$NTP_STATUS" -eq "1" ]; then echo "Yes"; else echo "No"; fi)

### Installation Settings ###
1. First External NTP-Server: $NTPSERVER1
2. Second External NTP-Server: $NTPSERVER2
3. Third External NTP-Server: $NTPSERVER3

### Packages ###
NTP:
	$(dpkg -p ntp)


#########################
### Security Functions ##
#########################

$(if [ "$FIREWALL" -eq "1" ] ; then
	echo "##############"
	echo "###Firewall###"
	echo "##############"
	echo "";
	echo "Installed correctly: $(if [ "$FIREWALL_STATUS" -eq "1" ]; then echo "Yes"; else echo "No"; fi)"
	echo "";
	echo "### Packages ###"
	echo "FirewallD:"
	echo "	$(dpkg -p firewalld)"
fi)

$(if [ "$SELINUX" -eq "1" ] ; then
	echo "##############"
	echo "###SELinux ###"
	echo "##############"
	echo "";
	echo "### Packages ###"
	echo "SELinux-Basics"
	echo "	$(dpkg -p seliux-basics)"
	echo "";
	echo "SELinux-Policy-Default"
	echo "	$(dpkg -p seliux-policy-default)"
fi)

#########################
######## Modules ########
#########################

$(if [ "$DHCP_SERVER" -eq "1" ] ; then
	echo "##############"
	echo "###  DHCP  ###"
	echo "##############"
	echo ""
	echo "Installed correctly: $(if [ "$DHCPD_STATUS" -eq "1" ]; then echo "Yes"; else echo "No"; fi)"
	echo ""
	echo "### Installation Settings ###"
	echo "DHCP Subnet ID: $DHCP_SUBNET"
	echo "DHCP Subnetmask: $DHCP_SUBNETMASK"
	echo "DHCP Broadcastaddress: $DHCP_BROADCASTADDRESS"
	echo "DHCP Gateway: $DHCP_GATEWAY"
	echo "DHCP First DNS-Server: $DHCP_DNSSERVER1"
	echo "DHCP Second DNS-Server: $DHCP_DNSSERVER2"
	echo "DHCP NetBIOS-Server: $DHCP_NETBIOSSERVER"
	echo "DHCP First NTP-Server: $DHCP_NTPSERVER1"
	echo "DHCP Second NTP-Server: $DHCP_NTPSERVER2"
	echo "DHCP Maximum Lease Time: $DHCP_MAX_LEASE_TIME"
	echo "DHCP First IP-adres: $DHCP_FIRST_IP_ADDRESS"
	echo "DHCP Last IP-adres: $DHCP_LAST_IP_ADDRESS"
	echo ""
	echo "### Packages ###"
	echo "ISC-DHCP-Server"
	dpkg -p isc-dhcp-server
fi)

$(if [ "$PXE_SERVER" -eq "2" ] ; then
	echo "##############"
	echo "###  PXE   ###"
	echo "##############"
	echo "";
	echo "Installed correctly: $(if [ "$PXE_STATUS" -eq "1" ]; then echo "Yes"; else echo "No"; fi)"
	echo ""
	echo "### Installation Settings ###"
	echo "HTTP Folder: $PXE_HTTP"
	echo "TFTP Folder: $PXE_TFTP"
	echo ""
	echo "### Packages ###"
	echo "iPXE:"
	echo "	$(dpkg -p ipxe)"
	echo ""
	echo "Apache:"
	echo "	$(dpkg -p apache2)"
fi)

EOT


###########################################################
# 5.2.       Display a summary of the installatioon       #
###########################################################

if [ "$SKIP_END_SUMMARY" -eq "0" ] ; then

	if [ "$DHCP_SERVER" -eq "0" ] ; then
		clear
		echo "To connect a computer follow these steps:"
		echo "1. Search and open as admin 'control.exe'"
		echo "   on a Windows client PC that is on the same network."
		pause_with_msg
		echo "2. Within this control panel click on 'Network and internet'."
		pause
		echo "3. Click on 'Networkcenter'."
		pause
		echo "4. Click on the blue text next to 'Connections:'."
		pause
		echo "5. Click on in the opened popup on the 'Properties'-button."
		pause
		echo "6. Click on the text 'Internet Protocol version 4 (TCP/IPv4)'."
		pause
		echo	 "7. Click on the 'Properties'-button.."
		pause
		echo "8. Click on the text 'Use the following IP address:'."
		pause
		echo "9. Use the following data to fill this form:'."
		echo "  - IP address: $IP_ADDRESS"
		echo "  - Subnet mask: $SUBNETMASK"
		echo "  - Default gateway: $GATEWAY"
		pause
		echo "10. Click on the text 'Use the following DNS server addresses:'"
		pause
		echo "11. Use the following data to fill the next part of the form:"
		echo "  - Preferred DNS server: $DNSSERVER1"
		echo "  - Preferred DNS server: $DNSSERVER2"
		pause
		echo " If you followed these steps correctly you are now able to"
		echo " connect to this server and if you have entered a correct"
		echo " gateway address you are now able to reach the Internet."
	fi
	
	echo ""
	echo "To connect a computer follow these steps:"
	echo "1. Search and open as admin 'SystemPropertiesComputerName.exe'"
	pause_with_msg
	echo "   on a Windows client PC that is on the same network."
	pause
	echo "2. Select 'Domain'."
	pause
	echo "3. Enter '$FQDN' as your domain name."
	pause
	echo "4. Click on 'OK'."
	pause
	echo "5. Log in using these credentials:"
	echo "  - Username: $NBIOS\Administrator"
	
	if [ "$ADMINPWD" = 'P455w0RD' ] ; then
		echo '  - Password: P455w0RD (Make sure to change this!).'
		else
		echo "  - Password: Your password!"
	fi
	
	pause_with_msg
	setterm -term linux -back black -fore green
	echo "###########################################################"
	echo " Congratulations! If you followed these steps correctly"
	echo " you now have correctly configured this domain controller! "
	echo " The next step is configuring users, computers and policies!"
	echo ""
	echo " We recommend this video tutorial: https://youtu.be/lFwek_OuYZ8"
	echo " Although the video is mainly foccused on Windows Server,"
	echo " ours does exactly the same thing."
	echo " But to manage ours follow this tutorial on the client:"
	echo " https://youtu.be/eBdEoczETDY"
	echo "###########################################################"
	pause_with_msg
	setterm -default

fi

###########################################################
# 5.2.              Generate the modulesfile              #
###########################################################
sudo cat <<'EOT' >> $LOCATION_OF_IMPORTANT_FILES/modules.avdc
$(if [ "$SSH_SERVER" -eq "1" ]; then echo "SSH_SERVER" ; fi)
$(if [ "$SSH_PORTKNOCKING" -eq "1" ]; then echo "SSH_PORTKNOCKING" ; fi)
	- Test if there is knockd and its depends.
$(if [ "$SSH_FAIL2BAN" -eq "1" ]; then echo "SSH_FAIL2BAN" ; fi)
	- Test if there is fail2ban and its depends.
$(if [ "$DHCP_SERVER" -eq "1" ]; then echo "DHCP_SERVER" ; fi)
	- Test if there is ISC-DHCP-Server.
$(if [ "$PXE_SERVER" -eq "1" ]; then echo "PXE_SERVER" ; fi)
	- Test if there is Apache.
EOT


###########################################################
# 5.2.             Generate the locationscript            #
###########################################################
1. Disable all services if this function is enabled.

if [ "$MOBILE" -eq "1" ] ; then
sudo systemctl disable $DAEMON_DHCPCD
sudo systemctl disable $DAEMON_NTP
sudo systemctl disable $DAEMON_SMBD
sudo systemctl disable $DAEMON_NMBD
sudo systemctl disable $DAEMON_SAMBA_AD_DC
sudo systemctl disable $DAEMON_KNOCKD
sudo systemctl disable $DAEMON_FAIL2BAN
sudo systemctl disable $DAEMON_SSH
sudo systemctl disable $DAEMON_DHCPD
sudo systemctl disable $DAEMON_TFTPD
# sudo systemctl disable $DAEMON_FIREWALD

#Script starts here.
2. Check if the last LOIF still works.

sudo read -r LAST_LOIF < /etc/avorix/avdc_loip

if ! [ -f $LAST_LOIF ]; then
   LOCATION_OF_IMPORTANT_FILES="$(find . -type f -iname 'info.avdc' -print -quit)"
	if [ "$LOCATION_OF_IMPORTANT_FILES" == "" ] ; then
		echo "Your device could not be found."
		X + 1;
		Y + 2;
		sleep 60
	fi
else

LAST_LOIF=LOCATION_OF_IMPORTANT_FILES
sudo mkdir /etc/avorix
sudo touch /etc/avorix/loip.avdc
sudo sed -i '1s/^/$LOCATION_OF_IMPORTANT_FILES\n/' /etc/avorix/avdc_loip
LOCATION_OF_IMPORTANT_FILES=${LOCATION_OF_IMPORTANT_FILES%"info.avdc"}; #Remove suffix

fi

#4. Test using the info.avdc-file if this is the right system.
#	- If not, display an error.

#if grep -xq "1. Script version: $DC_SCRIPT_VERSION ($DC_RELEASE_DATE)" $LOCATION_OF_IMPORTANT_FILES/info.avdc ; then
#	SSH_FAIL2BAN=1
#else
#	SSH_FAIL2BAN=0
#fi


5. Test using the modules.avdc-file if this system has the correct dependencies (PXE, SSH...)
	- If not, display error ask and the user to fix this by automaticly installing the dependencies for them. 


if grep -xq "SSH_SERVER" $LOCATION_OF_IMPORTANT_FILES/modules.avdc ; then
	SSH_SERVER=1
else
	SSH_SERVER=0
fi

if grep -xq "SSH_PORTKNOCKING" $LOCATION_OF_IMPORTANT_FILES/modules.avdc ; then
	SSH_PORTKNOCKING=1
else
	SSH_PORTKNOCKING=0
fi

if grep -xq "SSH_FAIL2BAN" $LOCATION_OF_IMPORTANT_FILES/modules.avdc ; then
	SSH_FAIL2BAN=1
else
	SSH_FAIL2BAN=0
fi

if grep -xq "DHCP_SERVER" $LOCATION_OF_IMPORTANT_FILES/modules.avdc ; then
	DHCP_SERVER=1
else
	DHCP_SERVER=0
fi


if grep -xq "PXE_SERVER" $LOCATION_OF_IMPORTANT_FILES/modules.avdc ; then
	PXE_SERVER=1
else
	PXE_SERVER=0
fi

	
	6. Link the files.
	- If an error occurs warn the user.

sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/General/Configuration/dhcpcd.conf $PATH_FILE_DHCPCD_CONF
sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/General/Configuration/hosts $PATH_FILE_HOSTS_CONF
sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/General/Configuration/hostname $PATH_FILE_HOSTNAME_CONF
sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/NTPD/Configuration/ntp.conf $PATH_FILE_NTP_CONF
sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/Kerberos/Configuration/krb5.conf $PATH_FILE_KRB5_CONF
sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/SAMBA/State $PATH_FOLDER_SAMBA_VAR_LIB
sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/SAMBA/Setup $PATH_FOLDER_SAMBA_SETUP
sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/SAMBA/Cache $PATH_FOLDER_SAMBA_CACHE
sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/SAMBA/Logs $PATH_FOLDER_SAMBA_LOG
sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/SAMBA/Configuration/smb.conf $PATH_FILE_SAMBA_CONF
sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/Kerberos/Configuration/krb5.conf $PATH_FILE_KRB5_CONF	

if [ "$SSH_SERVER" -eq "1" ] ; then
sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/SSH/Configuration/sshd_config $PATH_FILE_SSH_CONF

	if [ "$SSH_PORTKNOCKING" -eq "1" ] ; then
		sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/KNOCKD/Configuration/knockd.conf $PATH_FILE_KNOCKD_CONF
		sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/KNOCKD/Configuration/default/knockd $PATH_FILE_KNOCKD_DEFAULT
	fi

	if [ "$SSH_FAIL2BAN" -eq "1" ] ; then
		sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/FAIL2BAN/Configuration/jail.local $PATH_FILE_FAIL2BAN_JAIL
	fi
fi

if [ "$DHCP_SERVER" -eq "1" ] ; then
	sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/DHCP/Configuration/dhcpd.conf $PATH_FILE_DHCPD_CONF

	if [ "$PXE_SERVER" -eq "1" ] ; then
		sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/PXE/Configuration/Apache_PXE.conf $PATH_FOLDER_APACHE_SITES_ENABLED/Apache_iPXE.conf
		sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/PXE/Configuration/tftpd-hpa.conf $PATH_FILE_TFTPD_CONF
	fi
fi
if [ "$BRANDING" -eq "1" ] ; then
	sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/General/Configuration/issue $PATH_FILE_ISSUE
	sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/General/Configuration/motd $PATH_FILE_MOTD
	sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/General/Configuration/issue.net $PATH_FILE_ISSUENET
fi
EOT
7. Start the services.
sudo systemctl start $DAEMON_NTP
sudo systemctl start $DAEMON_SMBD
sudo systemctl start $DAEMON_NMBD
sudo systemctl start $DAEMON_SAMBA_AD_DC
sudo systemctl start $DAEMON_KNOCKD
sudo systemctl start $DAEMON_FAIL2BAN
sudo systemctl start $DAEMON_SSH
sudo systemctl start $DAEMON_DHCPD
sudo systemctl start $DAEMON_TFTPD
sudo systemctl start $DAEMON_FIREWALD
EOT
fi
sudo reboot

#NOTES: 

#Useful Windows commands:
# Active Windows using: slmgr -ipk $PRODUCT_KEY, followed by: slmgr -ato
# Join Active Directory domain: netdom.exe join %computername% /domain:%FQDN /UserD:$NBIOS\Administrator /Password:$ADMINPWD
