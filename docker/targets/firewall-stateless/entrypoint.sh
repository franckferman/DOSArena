#!/bin/bash
# Stateless firewall — INTENTIONALLY VULNERABLE
# Rules based on ports only, no connection tracking
# ACK flood and XMAS packets pass through freely

# Flush existing rules
iptables -F
iptables -X

# VULNERABLE: simple port-based rules, no -m state/conntrack
iptables -A INPUT  -p tcp --dport 80  -j ACCEPT   # HTTP in
iptables -A INPUT  -p tcp --dport 443 -j ACCEPT   # HTTPS in
iptables -A INPUT  -p icmp            -j ACCEPT   # ICMP in
iptables -A INPUT  -i lo              -j ACCEPT   # Loopback
iptables -A OUTPUT -j ACCEPT                      # All out
# No default DROP — everything else also passes

# What this means:
# - ACK packets to port 80 -> ACCEPTED (no session check)
# - XMAS packets to port 80 -> ACCEPTED (no flag validation)
# - RST packets to port 80 -> ACCEPTED
# A stateful rule would be: -m state --state ESTABLISHED,RELATED

echo "[*] Stateless firewall rules applied"
echo "    ACK flood:  WILL PASS THROUGH"
echo "    XMAS flood: WILL PASS THROUGH"
echo "    SYN flood:  WILL PASS THROUGH"

# Start nginx behind the firewall
nginx -g "daemon off;"
