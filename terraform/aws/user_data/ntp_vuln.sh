#!/bin/bash
# ntp_vuln.sh — NTPd with monlist enabled
set -e; export DEBIAN_FRONTEND=noninteractive
apt-get update -qq && apt-get install -y ntp
cat > /etc/ntp.conf << 'EOF'
driftfile /var/lib/ntp/ntp.drift
restrict default nomodify notrap nopeer
restrict 0.0.0.0 mask 0.0.0.0 nomodify notrap
# monlist NOT disabled — intentionally vulnerable
# disable monitor  <- commented out
server 127.127.1.0
fudge  127.127.1.0 stratum 10
EOF
systemctl enable ntp && systemctl restart ntp
echo "[+] ntp-vuln ready (monlist enabled)"
