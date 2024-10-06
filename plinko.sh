#!/bin/bash
# Made by Elvie for the Horse Plinko Cyber Challenge, Fall 2024 - Cargo Box

# Lock the root account
passwd -l root

# SSH hardening
echo "PermitRootLogin no" >> /etc/ssh/sshd_config
echo "Protocol 2" >> /etc/ssh/sshd_config
# SSH whitelist - only allow hkeating and plinktern
echo "AllowUsers hkeating plinktern" >> /etc/ssh/sshd_config

# Install necessary packages
apt install ufw -y

# Deny dangerous ports (e.g., Metasploit default port)
ufw deny 4444

# Set firewall rules for necessary services on Cargo box
ufw allow OpenSSH       # Allow SSH access
ufw allow ftp           # Allow FTP
ufw allow 20/tcp        # FTP data transfer
ufw allow 990/tcp       # FTP secure control connection
ufw enable

# Remove nopasswdlogon group to prevent passwordless logins
echo "Removing nopasswdlogon group"
sed -i -e '/nopasswdlogin/d' /etc/group

# Set correct permissions on sensitive files
chmod 644 /etc/passwd

# Backup the scoring file and set immutable attribute
cp /files/ImaHorse.png ~
cp /files/ImaHorse.png /bin
cp /files/ImaHorse.png /media
cp /files/ImaHorse.png /var
chattr +i /files/ImaHorse.png

# Configure vsftpd for scoring user (FTP service setup)
echo "hkeating" >> /etc/vsftpd.userlist
echo "userlist_enable=YES" >> /etc/vsftpd.conf
echo "userlist_file=/etc/vsftpd.userlist" >> /etc/vsftpd.conf
echo "userlist_deny=NO" >> /etc/vsftpd.conf
echo "chroot_local_user=NO" >> /etc/vsftpd.conf

# General FTP hardening
echo "anonymous_enable=NO" >> /etc/vsftpd.conf
echo "local_enable=YES" >> /etc/vsftpd.conf
echo "write_enable=YES" >> /etc/vsftpd.conf
echo "xferlog_enable=YES" >> /etc/vsftpd.conf
echo "ascii_upload_enable=NO" >> /etc/vsftpd.conf
echo "ascii_download_enable=NO" >> /etc/vsftpd.conf
service vsftpd restart

# Update the system and install useful monitoring tools
apt update -y
apt install fail2ban -y
apt install tmux -y
apt install curl -y
apt install whowatch -y
apt install unattended-upgrades -y
dpkg-reconfigure --priority=low unattended-upgrades

# Disable USB storage to prevent unauthorized devices
echo "blacklist usb-storage" >> /etc/modprobe.d/blacklist.conf
update-initramfs -u

# Disable IPv6 to reduce the attack surface
echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
sysctl -p

# Kernel hardening with sysctl
echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
sysctl -p

# Install auditd for system auditing
apt install auditd -y
systemctl enable auditd
auditctl -w /etc/passwd -p wa -k passwd_changes
auditctl -w /etc/shadow -p wa -k shadow_changes
auditctl -w /etc/group -p wa -k group_changes

# Change passwords for all non-system users (IDs >= 999)
for user in $( sed 's/:.*//' /etc/passwd);
do
  if [[ $(id -u $user) -ge 999 && "$user" != "nobody" ]]
  then
    (echo "PASSWORD!"; echo "PASSWORD!") | passwd "$user"
  fi
done

# Check for password-related inconsistencies
pwck

# Lock down critical configuration files to prevent changes by attackers
chattr +i /etc/vsftpd.userlist
chattr +i /etc/vsftpd.conf
chattr +i /etc/ssh/sshd_config
