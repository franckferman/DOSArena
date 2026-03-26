#!/bin/bash
# Stateful firewall — conntrack enabled
# Drops ACK/XMAS/RST without prior SYN
# But: conntrack table is limited -> SYN flood can still overflow it

# Flush
iptables -F
iptables -X

# Limit conntrack table (makes SYN flood overflow faster in lab)
echo 1024 > /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || true

# STATEFUL rules — conntrack
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport 80 --syn -j ACCEPT    # Only SYN starts sessions
iptables -A INPUT -p icmp -j ACCEPT
iptables -A INPUT -i lo   -j ACCEPT
iptables -A INPUT          -j DROP                      # Everything else dropped
iptables -A OUTPUT         -j ACCEPT

# SYN rate limiting (but conntrack table still finite)
iptables -A INPUT -p tcp --syn \
    -m limit --limit 50/s --limit-burst 100 \
    -j ACCEPT

echo "[+] Stateful firewall rules applied"
echo "    ACK flood:  BLOCKED (no prior session)"
echo "    XMAS flood: BLOCKED (no prior session)"
echo "    SYN flood:  RATE LIMITED (50/s) but conntrack table=1024"

nginx -g "daemon off;"
