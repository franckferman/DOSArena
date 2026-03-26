#!/bin/bash
# Bootstrap apache-vuln node — intentionally misconfigured Apache

set -e
export DEBIAN_FRONTEND=noninteractive

apt-get update -qq
apt-get install -y apache2

# Disable SYN cookies (vulnerable)
echo "net.ipv4.tcp_syncookies=0"            >> /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog=128"     >> /etc/sysctl.conf
sysctl -p

# Vulnerable Apache config — no timeouts, low MaxRequestWorkers
cat > /etc/apache2/sites-available/000-default.conf << 'EOF'
<VirtualHost *:80>
    DocumentRoot /var/www/html
    # No mod_reqtimeout — Slowloris-vulnerable
    # No rate limiting
    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
EOF

# Low MaxRequestWorkers
cat > /etc/apache2/mods-available/mpm_prefork.conf << 'EOF'
<IfModule mpm_prefork_module>
    StartServers          5
    MinSpareServers       5
    MaxSpareServers       10
    MaxRequestWorkers     150
    MaxConnectionsPerChild 0
</IfModule>
EOF

# No timeouts
cat >> /etc/apache2/apache2.conf << 'EOF'
Timeout 300
KeepAlive On
KeepAliveTimeout 0
EOF

# Disable mod_reqtimeout explicitly
a2dismod reqtimeout 2>/dev/null || true

# Basic content
cat > /var/www/html/index.html << 'HTML'
<!DOCTYPE html>
<html><body>
<h1>DOSArena — Apache Vulnerable</h1>
<p>Endpoints: /search /api /upload /login</p>
</body></html>
HTML

for ep in search api upload login; do
    cp /var/www/html/index.html /var/www/html/${ep}.html
done

systemctl enable apache2
systemctl restart apache2

echo "[+] apache-vuln ready (SYN cookies=0, no timeouts, MaxWorkers=150)"
