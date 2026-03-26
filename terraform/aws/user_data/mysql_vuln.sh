#!/bin/bash
# mysql_vuln.sh — MySQL with low max_connections
set -e; export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y mysql-server

# Set max_connections very low for NUKE demonstration
mysql -e "SET GLOBAL max_connections = 50;" 2>/dev/null || true

cat >> /etc/mysql/mysql.conf.d/mysqld.cnf << 'EOF'
max_connections    = 50
connect_timeout    = 10
wait_timeout       = 60
bind-address       = 0.0.0.0
EOF

# Create test user accessible from attacker subnet
mysql -e "CREATE USER IF NOT EXISTS 'labuser'@'10.0.%' IDENTIFIED BY 'labpass';" 2>/dev/null || true
mysql -e "GRANT ALL ON testdb.* TO 'labuser'@'10.0.%';" 2>/dev/null || true
mysql -e "CREATE DATABASE IF NOT EXISTS testdb;" 2>/dev/null || true

systemctl enable mysql && systemctl restart mysql
echo "[+] mysql-vuln ready (max_connections=50)"
