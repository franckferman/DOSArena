#!/bin/bash
# snmp_vuln.sh — Net-SNMP with community 'public'
set -e; export DEBIAN_FRONTEND=noninteractive
apt-get update -qq && apt-get install -y snmpd
cat > /etc/snmp/snmpd.conf << 'EOF'
rocommunity public default
view systemview included .1
agentAddress udp:161
sysDescr DOSArena SNMP Vulnerable Target
sysContact lab@dosarena.local
sysName snmp-vuln.dosarena.local
EOF
systemctl enable snmpd && systemctl restart snmpd
echo "[+] snmp-vuln ready (community=public, full MIB-II)"
