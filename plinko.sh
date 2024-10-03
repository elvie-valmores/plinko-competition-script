#!/bin/bash
# Made by Elvie for the Horse Plinko Cyber Challenge, Fall 2024

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

# Set firewall rules for necessary services (adjust per Plinko requirements)
ufw allow 'Apache Secure' # HTTPS
ufw allow OpenSSH
ufw allow ftp
ufw allow http
ufw allow 20/tcp  # FTP data transfer
ufw allow 990/tcp # FTP secure control connection
ufw allow 3306/tcp # MySQL
ufw enable

# Secure Apache (important for the MediaWiki site)
sudo chown -R root:root /etc/apache2

# Remove nopasswdlogon group to prevent passwordless logins
echo "Removing nopasswdlogon group"
sed -i -e '/nopasswdlogin/d' /etc/group

# Set correct permissions on sensitive files
chmod 644 /etc/passwd

# Backup file needed for scoring and set immutable attribute
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
apt install ranger -y
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