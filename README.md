# Avorix-Domain-Controller
A Raspberry Pi based domain controller developed for business and education.

The project is currently mainly focused on installing a Active Directory Domain Controller on a Raspberry Pi running Raspbian. While implementing best security practices and device independence (same data and the same configuration files can be shared between different systems running Avorix DC without reconfiguration).

Functionality:
- Complete emulation of an Active Directory Domain Controller, which includes support for policies.
- Windows and Linux file server.
- DHCP server.
- DNS server.
- NTP server.
- Device independence by store all configuration files and data files in a custom folder structure that is supported by all installation.
- SSH with 2 Factor Authentication and mechanisms against bruteforcing.
- An easy to configure update schedule.
- An anti-exploitation framework that adapts itself to the installed configuration.

What it currently does not provide:
- A graphical installation process.
- The ability to 2-way replicate the "sysvol"-share between Windows based en Linux based domain controllers.


#[Install here!](https://github.com/RHeijmann/Avorix-Domain-Controller/wiki/Installation)
