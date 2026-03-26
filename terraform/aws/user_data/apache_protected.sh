#!/bin/bash
# apache_protected.sh — hardened Apache

set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y apache2 iptables

# SYN cookies ON
echo "net.ipv4.tcp_syncookies=1"        >> /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog=4096" >> /etc/sysctl.conf
sysctl -p

# Enable mod_reqtimeout
a2enmod reqtimeout
cat > /etc/apache2/conf-available/reqtimeout.conf << 'EOF'
<IfModule mod_reqtimeout.c>
    RequestReadTimeout header=10-20,MinRate=500
    RequestReadTimeout body=10-30,MinRate=500
</IfModule>
EOF
a2enconf reqtimeout

# iptables SYN rate limit
iptables -A INPUT -p tcp --syn -m limit --limit 50/s --limit-burst 100 -j ACCEPT
iptables -A INPUT -p tcp --syn -j DROP
iptables -A INPUT -p tcp --dport 80 -m connlimit --connlimit-above 20 -j REJECT

cat > /var/www/html/index.html << 'HTML'
<!DOCTYPE html><html><body>
<h1>DOSArena — Apache Protected</h1>
<p>mod_reqtimeout enabled, SYN cookies active, rate limiting on.</p>
</body></html>
HTML

systemctl enable apache2
systemctl restart apache2
echo "[+] apache-protected ready"
