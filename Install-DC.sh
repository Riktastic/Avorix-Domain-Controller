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
VERSION=0.5.1
# 0.5: First release: Installs a SAMBA, NTP, DHCP server in
#                     a Secure environment.
# 0.5.1: Major update: Added checks for all services, made 
#                      changes to the settings.
#                      Added a Installation log.

###########################################################
#                         To Do                           #
###########################################################
# - Make this script work with CentOS, ArchLinux and Ubuntu.
# - Integrate a GUI for configuration.
# - Integrate checks: Partly Done, need more checks.
# - Find a way to make AUDITD to work.
# - Use PXE to deploy Windows.
# - Set the permissions on the "users"-share automaticly.


###########################################################
#                       Summary                           #
###########################################################
# 1. Settings.
# 2. Update the complete system.
# 3. Configure the USB to save important files.
# 4. (Optional) Install & Temporarely disable SELinux  
# 5. Install the main components.
# 6. Configure the timezone  
# 7. Configure the hosts file.
# 8. Change the hostname.
# 9. Configure a static IP-address.
# 10. (Optional) Configure SSH.
# 11. Configure the NTP-server.
# 12. Configure SAMBA.
# 13. (Optional) Configure the DHCP-server.
# 14. (Optional) Configure SELinux.
# 15. (Optional) Configure automatic security updates.
# 16. (Optional) Test & Enable the Firewall  
# 16. Log the current installation.


###########################################################
# 1.                   Settings                           #
###########################################################
# All these settings are important!
# Make sure that everything is setup correctly.

#Additional Modules
export DHCP_SERVER=0 #Enable this only if you know that this is needed.
export SSH_SERVER=0

#Security Functions
export FIREWALL=1 #RECOMMENDED! Enables the built-in firewall and adds support for the selected functions.
export SELINUX=1 #RECOMMENDED! Enables SELINUX (Will first start permissive and collect data. The next day that data will be used to create a policy)
export AUTOMATIC_SECURITY_UPDATES=1 #RECOMMENDED! Will daily check for security updates.

#Storage Settings
export LOCATION_OF_IMPORTANT_FILES=/media/usb1 #Will only work if AUTO_CHECK_USB is set to 0.
export STORE_FILES_ON_USB=1
export AUTO_CHECK_USB=1 

#Network Settings
export IP_ADDRESS=192.168.0.2
export SUBNETMASK_BITS=24
export GATEWAY=192.168.0.1
export DNSSERVER1=$IP_ADDRESS
export DNSSERVER2=8.8.8.8

#SAMBA Settings
export FQDN=avorix.local #This is your domain name.
export NBIOS=AVORIX #This is the second level domain name capitalized.
export DCNAME=DC1
ADMINPWD=P@$$w0RD! #This is the password of the "Administrator"-account.

#Time Settings
export REGION=Europe
export TIMEZONE=Amsterdam
export NTPSERVER1=0.pool.ntp.org
export NTPSERVER2=1.pool.ntp.org
export NTPSERVER3=2.pool.ntp.org

#(Optional) DHCP Settings
export DHCP_SUBNET=192.168.0.0
export DHCP_SUBNETMASK=255.255.255.0
export DHCP_BROADCASTADDRESS=192.168.0.255
export DHCP_GATEWAY=$GATEWAY
export DHCP_DNSSERVER1=$DNSSERVER1
export DHCP_DNSSERVER2=$DNSSERVER2
export DHCP_NETBIOSSERVER=$IP_ADDRESS
export DHCP_NTPSERVER1=$IP_ADDRESS
export DHCP_NTPSERVER2=0.pool.ntp.org
export DHCP_MAX_LEASE_TIME=1800
export DHCP_FIRST_IP_ADDRESS=192.168.0.10
export DHCP_LAST_IP_ADDRESS=192.168.0.200

#(Optional) SSH Settings
SSH_PORT=22
SSH_USER=Avorix #Future users have to be added to the "ssh"-group to use "ssh".
SSH_USER_PASSWORD=P@$$w0rd!
SSH_USER_SUDO=1 #Set to 1 to give this user permission to run administrator commands using "sudo".


###########################################################
# 2.          Update the complete system                  #
###########################################################
sudo apt-get update
sudo apt-get upgrade -y
sudo apt-get dist-upgrade -y


###########################################################
# 3.    Configure the USB to save important files         #
###########################################################
if [ "$STORE_FILES_ON_USB" -eq "1" ] ; then
sudo apt-get install usbmount -y

#USBMount: Configuring.
sudo mv /etc/usbmount/usbmount.conf /etc/usbmount/usbmount.conf.original
sudo touch /etc/usbmount/usbmount.conf
sudo cat <<EOT >> /etc/usbmount/usbmount.conf
#Generated by the Avorix Domain Controller install script.
ENABLED=1
MOUNTPOINTS="/media/usb1 /media/usb2 /media/usb3
             /media/usb4 /media/usb5 /media/usb6 /media/usb7 /media/usb8"
			 
FILESYSTEMS="vfat ext2 ext3 ext4 hfsplus"
MOUNTOPTIONS="sync,noexec,nodev,noatime,nodiratime"
FS_MOUNTOPTIONS=""
VERBOSE=no
EOT

#USBMount: Make sure that the USB-drive is mounted else copy the files to a temporary folder.
#It would be better if we listed the drives using mountusb.
if [ "$AUTO_CHECK_USB" -eq "1" ] && mount | grep /media/usb1 > /dev/null ; then
    export LOCATION_OF_IMPORTANT_FILES=/media/usb1
else
    export LOCATION_OF_IMPORTANT_FILES=/media/temp
fi
fi

#Creating folders for the $LOCATION_OF_IMPORTANT_FILES
sudo mkdir -p $LOCATION_OF_IMPORTANT_FILES/General/Configuration $LOCATION_OF_IMPORTANT_FILES/General/Logs $LOCATION_OF_IMPORTANT_FILES/Kerberos/Configuration $LOCATION_OF_IMPORTANT_FILES/SAMBA/Configuration $LOCATION_OF_IMPORTANT_FILES/SAMBA/State $LOCATION_OF_IMPORTANT_FILES/SAMBA/Setup $LOCATION_OF_IMPORTANT_FILES/SAMBA/Cache $LOCATION_OF_IMPORTANT_FILES/SAMBA/Logs $LOCATION_OF_IMPORTANT_FILES/SAMBA/Sockets/ntp_signd $LOCATION_OF_IMPORTANT_FILES/NTPD/Configuration $LOCATION_OF_IMPORTANT_FILES/NTPD/Logs $LOCATION_OF_IMPORTANT_FILES/NTPD/Data

#Linking folder to folders on the USB.
sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/SAMBA/State/ /var/lib/samba/
sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/SAMBA/Setup/ /usr/share/samba/setup
sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/SAMBA/Cache/ /var/cache/samba
sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/SAMBA/Logs/ /var/log/samba


###########################################################
# 4.(Optional)   Install & Temporarely disable SELinux    #
###########################################################
#Temporary disable SELinux, will be enabled the next day with exclusions for DNS, SAMBA, DHCP and DHCP.
if [ "$SELINUX" -eq "1" ]; then
sudo apt-get install selinux-basics selinux-policy-default -y
sudo selinux-activate
sudo mv /etc/selinux/config /etc/selinux/config.original
sudo touch /etc/selinux/config
sudo cat <<EOT >> /etc/selinux/config
# Generated by the Avorix Domain Controller install script $VERSION
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
# 5.             Install the main components              #
###########################################################
if [ "$DHCP_SERVER" -eq "1" ]; then
   sudo apt-get install isc-dhcp-server -y
fi

if [ "$FIREWALL" -eq "1" ]; then
   sudo apt-get firewalld -y
fi

if [ "$SSH_SERVER" -eq "1" ]; then
   sudo apt-get openssh-server -y
fi

sudo apt-get install samba samba-windbind samba-vfs-modules ntp -y


###########################################################
# 6.                Configure the timezone                #
###########################################################
sudo timedatectl set-timezone $REGION/$TIMEZONE
sudo timedatectl


###########################################################
# 7.            Configure the hosts file                  #
###########################################################
sudo mv /etc/hosts /etc/hosts.original
sudo touch $LOCATION_OF_IMPORTANT_FILES/General/Configuration/hosts
sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/General/Configuration/hosts /etc/hosts
sudo cat <<EOT >> $LOCATION_OF_IMPORTANT_FILES/General/Configuration/hosts
#Generated by the Avorix Domain Controller install script.
#Localhost
127.0.0.1     localhost localhost
::1           localhost ip6-localhost ip6-loopback

#Domain name
$IP_ADDRESS     $DCNAME.$FQDN     $DCNAME

#Might not be needed.
ff02::1       ip6-allnodes
ff02::2       ip6-allrouters
EOT


###########################################################
# 8.                 Change the hostname                  #
###########################################################
#Change the hostname and backup the original.
sudo mv /etc/hostname /etc/hostname.original
sudo touch $LOCATION_OF_IMPORTANT_FILES/General/Configuration/hostname
sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/General/Configuration/hostname /etc/hostname
sudo cat <<EOT >> $LOCATION_OF_IMPORTANT_FILES/General/Configuration/hostname
$DCNAME.$FQDN
EOT

#Make the hostname for the current session active.
sudo hostname $DCNAME.$FQDN


###########################################################
# 9.         Configure a static IP-address                #
###########################################################
#Change the IP-address to static.
#First create a backup.
sudo mv /etc/dhcpcd.conf /etc/dhcpcd.conf.original
#Create an empty file.
sudo touch $LOCATION_OF_IMPORTANT_FILES/General/Configuration/dhcpcd.conf
#Link that file to the file that wil be used by DHCPCD.
sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/General/Configuration/dhcpcd.conf /etc/dhcpcd.conf
#Fill that file with the text that starts at "#Generated" till "$DNSSERVER2". 
sudo cat <<EOT >> $LOCATION_OF_IMPORTANT_FILES/General/Configuration/dhcpcd.conf
# Generated by the Avorix Domain Controller install script $VERSION.
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
sudo systemctl stop dhcpcd
sudo systemctl start dhcpcd

#Check if the DHCPCD configuration passes DHCPCD's test.
if [ $(systemctl is-active dhcpcd) -eq "0" ]; then
	DHCPCD_STATUS=1
	sudo systemctl enable dhcpcd
else
	DHCPCD_STATUS=0
	setterm -term linux -back red -fore white
	echo "###########################################################"
	echo "# Error: Installation stopped!                            #"
	echo "###########################################################"
	echo "Reason:"
	echo "- Your Network (DHCPCD) settings are incorrect."
	echo ""
	echo "Solution:"
	echo "- Make sure that the settings abide to:"
	echo "	- Not containing any illegal characters!"
	echo "	- Correct IP-addresses."
	echo "	- Correct Subnetmaskbits: Calculate one at: http://jodies.de/ipcalc"
	echo "  - Check: systemctl dhcpcd status -l, for more details."
	echo "###########################################################"
	setterm -default
	exit
fi


###########################################################
# 10.(Optional)          Configure SSH                    #
###########################################################
#SSH allows us to remotely open a terminal shell.
#Within a terminal shell we are able to completely modify the system.
#But if you are only in to modifying Active Directory just install the RSAT-tools, you won't need SSH.
if [ "$SSH_SERVER" -eq "1" && "$FIREWALL" -eq "1" ]; then
sudo firewall-cmd --permanent --zone=public --add-port=$SSH_PORT/tcp
fi

#If the SSH user needs SSH access, create the SSH group and the SSH user.
if [ "$SSH_SERVER" -eq "1" && "$SSH_USER_SUDO" -eq "1" ]; then
sudo groupadd ssh
sudo useradd $SSH_USER -d /home/$SSH_USER -g ssh -g sudo -m -p $SSH_USER_PASSWORD
else
sudo groupadd ssh
sudo useradd $SSH_USER -d /home/$SSH_USER -g ssh -m -p $SSH_USER_PASSWORD
fi

if [ "$SSH_SERVER" -eq "1" ]; then
   sudo mkdir -p $LOCATION_OF_IMPORTANT_FILES/SSH/Configuration
   sudo mv /etc/ssh/sshd_config /etc/ssh/sshd_config.orginal
   sudo touch /etc/ssh/sshd_config
   sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/SSH/Configuration/sshd_config /etc/ssh/sshd_config
   sudo cat <<EOT >> $LOCATION_OF_IMPORTANT_FILES/SSH/Configuration/sshd_config
# Generated by the Avorix Domain Controller install script $VERSION
# Generated on $(date)
#
# This is the sshd server system-wide configuration file.  See
# sshd_config(5) for more information.

# This sshd was compiled with PATH=/usr/bin:/bin:/usr/sbin:/sbin

# The strategy used for options in the default sshd_config shipped with
# OpenSSH is to specify options with their default value where
# possible, but leave them commented.  Uncommented options override the
# default value.

Port $SSH_PORT
#AddressFamily any
#ListenAddress 0.0.0.0
#ListenAddress ::

# The default requires explicit activation of protocol 1
Protocol 2

# HostKey for protocol version 1
#HostKey /etc/ssh/ssh_host_key
# HostKeys for protocol version 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_dsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Lifetime and size of ephemeral version 1 server key
#KeyRegenerationInterval 1h
#ServerKeyBits 1024

# Ciphers and keying
#RekeyLimit default none
Ciphers aes256-ctr,blowfish-cbc,aes256-cbc
MACs hmac-sha2-256,hmac-sha2-512,hmac-sha1

# Logging
# obsoletes QuietMode and FascistLogging
SyslogFacility AUTH
LogLevel VERBOSE

# Authentication:

LoginGraceTime 2m
PermitRootLogin no
StrictModes yes
MaxAuthTries 2
#MaxSessions 10

#RSAAuthentication yes
#PubkeyAuthentication yes

# The default is to check both .ssh/authorized_keys and .ssh/authorized_keys2
# but this is overridden so installations will only check .ssh/authorized_keys
AuthorizedKeysFile	.ssh/authorized_keys

#AuthorizedPrincipalsFile none

#AuthorizedKeysCommand none
#AuthorizedKeysCommandUser nobody

# For this to work you will also need host keys in /etc/ssh/ssh_known_hosts
RhostsRSAAuthentication no
# similar for protocol version 2
HostbasedAuthentication no
# Change to yes if you don't trust ~/.ssh/known_hosts for
# RhostsRSAAuthentication and HostbasedAuthentication
#IgnoreUserKnownHosts no
# Don't read the user's ~/.rhosts and ~/.shosts files
IgnoreRhosts yes

# To disable tunneled clear text passwords, change to no here!
#PasswordAuthentication yes
PermitEmptyPasswords yes

# Change to no to disable s/key passwords
ChallengeResponseAuthentication no

# Kerberos options
#KerberosAuthentication no
#KerberosOrLocalPasswd yes
#KerberosTicketCleanup yes
#KerberosGetAFSToken no

# GSSAPI options
#GSSAPIAuthentication no
#GSSAPICleanupCredentials yes

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

#AllowAgentForwarding yes
AllowTcpForwarding no
GatewayPorts no
X11Forwarding no
#X11DisplayOffset 10
#X11UseLocalhost yes
#PermitTTY yes
PrintMotd no # pam does that
#PrintLastLog yes
TCPKeepAlive yes
#UseLogin no
UsePrivilegeSeparation yes		# Default for new installations.
#PermitUserEnvironment no
#Compression delayed
#ClientAliveInterval 0
#ClientAliveCountMax 3
#UseDNS no
#PidFile /run/sshd.pid
#MaxStartups 10:30:100
#PermitTunnel no
#ChrootDirectory none
#VersionAddendum none

# no default banner path
Banner /etc/issue.net

# override default of no subsystems
Subsystem	sftp	/usr/lib/ssh/sftp-server

# Example of overriding settings on a per-user basis
#Match User anoncvs
#	X11Forwarding no
#	AllowTcpForwarding no
#	PermitTTY no
#	ForceCommand cvs server

AllowGroups ssh
EOT

sudo systemctl stop ssh
sudo systemctl start ssh

#Check if the SSH configuration passes SSH's test.
if [ $(systemctl is-active ssh) -eq "0" ]; then
	SSH_STATUS=1
	sudo systemctl enable ssh
else
	SSH_STATUS=0
	setterm -term linux -back red -fore white
	echo "###########################################################"
	echo "# Error: Installation stopped!                            #"
	echo "###########################################################"
	echo "Reason:"
	echo "- Your SSH settings are incorrect."
	echo ""
	echo "Solution:"
	echo "- Make sure that the settings abide to:"
	echo "	- Not containing any illegal characters!"
	echo "	- Containing a correct portnumber."
	echo "  - Check: systemctl ssh status -l, for more details."
	echo "###########################################################"
	setterm -default
	exit
fi
fi


###########################################################
# 11.          Configure the NTP-server                   #
###########################################################
#If function FIREWALL is enabled then allow NTP to send and recieve over the network.
if [ "$FIREWALL" -eq "1" ]; then
sudo firewall-cmd --permanent --zone=public --add-port=123/udp
fi

sudo mv /etc/ntp.conf /etc/ntp.conf.original
sudo touch $LOCATION_OF_IMPORTANT_FILES/NTPD/Configuration/ntp.conf
sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/NTPD/Configuration/ntp.conf /etc/ntp.conf
sudo cat <<EOT >> $LOCATION_OF_IMPORTANT_FILES/NTPD/Configuration/ntp.conf
# Generated by the Avorix Domain Controller install script $VERSION
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
sudo systemctl stop ntp
sudo systemctl start ntp

#Check if the NTP configuration passes NTP's test.
if [ $(systemctl is-active ntp) -eq "0" ]; then
	NTP_STATUS=1
	sudo systemctl enable ntp
else
	NTP_STATUS=0
	setterm -term linux -back red -fore white
	echo "###########################################################"
	echo "# Error: Installation stopped!                            #"
	echo "###########################################################"
	echo "Reason:"
	echo "- Your Time (NTP) settings are incorrect."
	echo ""
	echo "Solution:"
	echo "- Make sure that the settings abide to:"
	echo "	- Not containing any illegal characters!"
	echo "	- Containing a correct Timezone/Region:"
	echo "	  Display all Timezones using: ls /usr/share/zoneinfo"
	echo "	  Display all Regions within a timezone using:"
	echo "	  ls /usr/share/zoneinfo/Your_timezone/"
	echo ""
	echo "  - Check: systemctl ntp status -l, for more details."
	echo "###########################################################"
	setterm -default
	exit
fi



###########################################################
# 12.                Configure Samba                      #
###########################################################
if [ "$FIREWALL" -eq "1" ]; then
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
sudo mv /etc/samba/smb.conf /etc/samba/smb.conf.original
sudo samba-tool domain provision --server-role=dc --use-rfc2307 --dns-backend=SAMBA_INTERNAL --realm=$FQDN --domain=$NBIOS --host-name=$DCNAME --adminpass=$ADMINPWD --host-ip=$IP_ADDRESS

sudo cp /etc/samba/smb.conf /etc/samba/smb.conf.after_provision
sudo mv /etc/samba/smb.conf $LOCATION_OF_IMPORTANT_FILES/SAMBA/Configuration/smb.conf
sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/SAMBA/Configuration/smb.conf /etc/samba/smb.conf

sudo cp /var/lib/samba/private/krb5.conf $LOCATION_OF_IMPORTANT_FILES/Kerberos/Configuration/krb5.conf
sudo ln -sf $LOCATION_OF_IMPORTANT_FILES/Kerberos/krb5.conf /etc/krb5.conf

sudo mkdir -p &USB/SAMBA/Shares/Users
sudo cat <<EOT >> $LOCATION_OF_IMPORTANT_FILES/SAMBA/Configuration/smb.conf

[users]
       path = $LOCATION_OF_IMPORTANT_FILES/SAMBA/Shares/Users
       read only = no
EOT

sudo systemctl stop smbd
sudo systemctl start smbd

sudo systemctl stop nmbd
sudo systemctl start nmbd

sudo systemctl stop samba-ad-dc
sudo systemctl start samba-ad-dc

#Check if the SAMBA configuration passes SAMBA's test.
if [ $(systemctl is-active smbd) -eq "0" ] && [ $(systemctl is-active nmbd) -eq "0" ] && [ $(systemctl is-active samba-ad-dc) -eq "0" ] ; then
	SAMBA_STATUS=1
	sudo systemctl enable smbd
	sudo systemctl enable nmbd
	sudo systemctl enable samba-ad-dc
else
	SAMBA_STATUS=0
	setterm -term linux -back red -fore white
	echo "###########################################################"
	echo "# Error: Installation stopped!                            #"
	echo "###########################################################"
	echo "Reason:"
	echo "- Your SAMBA settings are incorrect."
	echo ""
	echo "Solution:"
	echo "- Make sure that the settings abide to:"
	echo "	- Not containing any illegal characters!"
	echo "	- Containing a correct FQDN, NetBiosname and DCName."
	echo "  - Check: systemctl smbd status -l, for more details."
	echo "  - Check: systemctl nmbd status -l, for more details."
	echo "  - Check: systemctl samba-ad-dc status -l, for more details."
	echo "###########################################################"
	setterm -default
	exit
fi


###########################################################
# 13.(Optional)    Configure the DHCP server              #
###########################################################
#In some situations and environments you do not want to have an additional DHCP-server.
#As there can only be 1 DHCP-server in a network. Having multiple will cause network failure.
#But to make the Domain Controller reachable you will need to let the DHCP-server instruct the devices on the network
#to use the DNS, NTP and the NetBIOS server of the Domain Controller.
if [ "$DHCP_SERVER" -eq "1" && "$FIREWALL" -eq "1"]; then
sudo firewall-cmd --permanent --zone=public --add-port=67/udp
fi

if [ "$DHCP_SERVER" -eq "1" ]; then
sudo cat <<EOT >> /etc/dhcpd.conf
subnet $DHCP_SUBNET netmask $DHCP_SUBNETMASK {
  option subnet-mask $DHCP_SUBNETMASK;
  option broadcast-address $BROADCASTADDRESS;
  option time-offset 0;
  option routers $DHCP_GATEWAY;
  option domain-name "$FQDN";
  option domain-name-servers $DHCP_DNSSERVER1, $DHCP_DNSSERVER2;
  option netbios-name-servers $DHCP_NETBIOSSERVER;
  option ntp-servers $DHCP_NTPSERVER1, $DHCP_NTPSERVER2;
  pool {
    max-lease-time $DHCP_MAX_LEASE_TIME; # 30 minutes
    range $DHCP_FIRST_IP_ADDRESS $DHCP_LAST_IP_ADDRESS;
  }
}
EOT

sudo systemctl stop isc-dhcp-server
sudo systemctl start isc-dhcp-server

#Check if the ISC-DHCP-Server configuration passes ISC-DHCP-Server's test.
if [ $(systemctl is-active isc-dhcp-server) -eq "0" ] ; then
	DHCPD_STATUS=1
	sudo systemctl enable isc-dhcp-server
else
	DHCPD_STATUS=0
	setterm -term linux -back red -fore white
	echo "###########################################################"
	echo "# Error: Installation stopped!                            #"
	echo "###########################################################"
	echo "Reason:"
	echo "- Your DHCP settings are incorrect."
	echo ""
	echo "Solution:"
	echo "- Make sure that the settings abide to:"
	echo "	- Not containing any illegal characters!"
	echo "	- Containing a correct FQDN, NetBiosname and DCName."
	echo "  - Check: systemctl isc-dhcp-server status -l, for more details."
	echo "###########################################################"
	setterm -default
	exit
fi

fi


###########################################################
# 14.(Optional)          Configure SELinux                #
###########################################################
#SELinux is a security module for the Linux kernel.
#It allows us to create security policy for each process.
#The policies include: Allowing files to be accessed, Allowing services to be run.

#Creates a script that wil check the next day which permissions NTP, SAMBA and DHCP need.
if [ "$SELINUX" -eq "1" ]; then
sudo apt-get install selinux-basic selinux-policy-defaults
sudo mkdir -p $LOCATION_OF_IMPORTANT_FILES/SELinux/Rules 
sudo touch /etc/cron.daily/Configure-SELinux.sh
sudo cat <<EOT >> /etc/cron.daily/Configure-SELinux.sh
# Generated by the Avorix Domain Controller install script $VERSION
# Generated on $(date)
#
sudo grep smb /var/log/audit/audit.log | sudo audit2allow -M $LOCATION_OF_IMPORTANT_FILES/Kerberos/Configuration/smb
sudo grep ntp /var/log/audit/audit.log | sudo audit2allow -M $LOCATION_OF_IMPORTANT_FILES/Kerberos/Configuration/ntp
sudo grep dhcp /var/log/audit/audit.log | sudo audit2allow -M $LOCATION_OF_IMPORTANT_FILES/Kerberos/Configuration/dhcp
sudo semodule -i $LOCATION_OF_IMPORTANT_FILES/Kerberos/Configuration/smb
sudo semodule -i $LOCATION_OF_IMPORTANT_FILES/Kerberos/Configuration/ntp 
sudo semodule -i $LOCATION_OF_IMPORTANT_FILES/Kerberos/Configuration/dhcp
sudo mv -Rf /etc/selinux/config.replacer /etc/selinux/config
sudo rm -Rf /etc/cron.daily/Configure-SELinux.sh
EOT

#This file will be replaced with the original /etc/selinux/config once the above script is ran.
sudo touch /etc/selinux/config.replacer
sudo cat <<EOT >> /etc/selinux/config.replacer
# Generated by the Avorix Domain Controller install script $VERSION
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
# 15.(Optional)  Configure automatic security updates     #
###########################################################
if [ "$AUTOMATIC_SECURITY_UPDATES" -eq "1" ]; then
#Check daily for updates and install the security updates.
sudo cat <<EOT >> /etc/cron.daily/Install-Security-Updates
# Generated by the Avorix Domain Controller install script $VERSION
# Generated on $(date)
#
sudo echo "**************" >> $LOCATION_OF_IMPORTANT_FILES/General/Logs/Security-Updates.log
sudo date >> $LOCATION_OF_IMPORTANT_FILES/General/Logs/Security-Updates.log
sudo aptitude update >> $LOCATION_OF_IMPORTANT_FILES/General/Logs/Security-Updates.log
sudo aptitude safe-upgrade -o Aptitude::Delete-Unused=false --assume-yes --target-release `lsb_release -cs`-security >> $LOCATION_OF_IMPORTANT_FILES/General/Logs/Security-Updates.log
sudo echo "Security updates (if any) installed"
EOT
fi

###########################################################
# 16. (Optional)  Test & Enable the Firewall              #
###########################################################
if [ "$FIREWALL" -eq "1" ]; then

sudo systemctl stop firewalld
sudo systemctl start firewalld

if [ $(systemctl is-active firewalld) -eq "0" ] ; then
	FIREWALL_STATUS=1
	sudo systemctl enable firewalld
else
	FIREWALL_STATUS=0
	setterm -term linux -back red -fore white
	echo "###########################################################"
	echo "# Error: Installation stopped!                            #"
	echo "###########################################################"
	echo "Reason:"
	echo "- Your port settings are incorrect."
	echo ""
	echo "Solution:"
	echo "- Make sure that the port numbers abide to:"
	echo "	- Not containing any illegal characters!"
	echo "	- Containing a port number between 1 - 65535."
	echo "	- Containing a port number that is not reserved."
	echo "  - Check: systemctl firewalld status -l, for more details."
	echo "###########################################################"
	setterm -default
	exit
fi
fi

###########################################################
# 16.          Log the current installation               #
###########################################################

sudo cat <<EOT >> $LOCATION_OF_IMPORTANT_FILES/General/Logs/Installation.txt
#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!#
#!!!!!!!!!!!!!!! Do not Remove This File !!!!!!!!!!!!!!!!!#
#!!!!! By deleting this file the developers will not !!!!!#
#!!!!!!!!!! will not support provide support to you! !!!!!#
#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!#

###########################################################
# 1.                      General                         #
###########################################################
1. Script version: $VERSION
2. Installation date: $(date)
3. Operating System: $(cat /etc/*-release)
4. Location of the important files: $LOCATION_OF_IMPORTANT_FILES
5. Timezone and Region: $TIMEZONE / $REGION
6. Correct Network settings: $(if [ "$DHCPCD_STATUS" -eq "1" ]; then echo "Yes"; else echo "No"; fi)


###########################################################
# 2.                      Modules                         #
###########################################################
1. DHCP: $(if [ "$DHCP_SERVER" -eq "1" ]; then echo "Yes"; else echo "No"; fi)
2. SSH: $(if [ "$SSH_SERVER" -eq "1" ]; then echo "Yes"; else echo "No"; fi)


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


$(if ["$FIREWALL" -eq "1" ] ; then
echo "##############"
echo "###Firewall###"
echo "##############"
echo "";
echo "Installed correctly: $(if [ "$FIREWALL_STATUS" -eq "1" ]; then echo "Yes"; else echo "No"; fi)"
echo "";
echo "### Packages ###"
echo "FirewallD:"
dpkg -p firewalld
fi)


$(if ["$SELINUX" -eq "1" ] ; then
echo "##############"
echo "###SELinux ###"
echo "##############"
echo "";
echo "### Packages ###"
ehco "SELinux-Basics"
dpkg -p seliux-basics
echo "";
ehco "SELinux-Policy-Default"
dpkg -p seliux-basics
fi)


$(if ["$DHCP_SERVER" -eq "1" ] ; then
echo "##############"
echo "###  DHCP  ###"
echo "##############"
echo "";
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
EOT
reboot

