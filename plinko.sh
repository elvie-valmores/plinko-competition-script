#!/bin/bash
# Made by Elvie for the Horse Plinko Cyber Challenge, Fall 2024 - Cargo Box

# Lock the root account
passwd -l root

# Remove all SSH keys from all authorized_keys files
rm -f /root/.ssh/authorized_keys
rm -f /home/*/.ssh/authorized_keys

# SSH hardening
echo "PermitRootLogin no" >> /etc/ssh/sshd_config
echo "Protocol 2" >> /etc/ssh/sshd_config
# SSH whitelist - only allow hkeating and plinktern
echo "AllowUsers hkeating plinktern" >> /etc/ssh/sshd_config

# Additional SSH security settings
echo "PasswordAuthentication no" >> /etc/ssh/sshd_config
echo "MaxAuthTries 3" >> /etc/ssh/sshd_config
echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config
echo "ClientAliveInterval 300" >> /etc/ssh/sshd_config
echo "AllowTcpForwarding no" >> /etc/ssh/sshd_config

# Install necessary packages
apt install ufw -y

# Set firewall rules for necessary services on Cargo box
# Reset UFW rules to default (deny all incoming, allow all outgoing)
ufw reset

# Set default policies
ufw default deny incoming  # Deny all incoming traffic by default
ufw default allow outgoing  # Allow all outgoing traffic by default

# Allow necessary ports
ufw allow OpenSSH       # Allow SSH access (port 22)
ufw allow ftp           # Allow FTP (port 21)
ufw allow 20/tcp        # Allow FTP data transfer (port 20)
ufw allow 990/tcp       # Allow FTPS secure control connection (port 990)
ufw allow 3306/tcp      # Allow MySQL (if required)

# Enable UFW firewall
ufw enable

# Remove nopasswdlogon group to prevent passwordless logins
echo "Removing nopasswdlogon group"
sed -i -e '/nopasswdlogin/d' /etc/group

# Set correct permissions on sensitive files
chmod 644 /etc/passwd

# Ensure the scoring file exists and is immutable for anonymous FTP access
chmod 644 /var/ftp/ImaHorse.jpg
chattr +i /var/ftp/ImaHorse.jpg

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

# Download pspy for process monitoring
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64
chmod +x pspy64

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
