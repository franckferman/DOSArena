#!/bin/bash
# Apply iptables rate limiting before starting Apache

# SYN flood protection via iptables
iptables -A INPUT -p tcp --syn -m limit --limit 50/s --limit-burst 100 -j ACCEPT
iptables -A INPUT -p tcp --syn -j DROP

# Connection limit per source IP
iptables -A INPUT -p tcp --dport 80 -m connlimit --connlimit-above 20 -j REJECT

# HTTP request rate limit (new connections)
iptables -N HTTP_RATELIMIT 2>/dev/null || true
iptables -A INPUT -p tcp --dport 80 -m state --state NEW -j HTTP_RATELIMIT
iptables -A HTTP_RATELIMIT -m recent --set --name HTTP
iptables -A HTTP_RATELIMIT -m recent --update --seconds 1 --hitcount 100 \
    --name HTTP -j DROP

echo "[+] iptables rules applied"
echo "[+] SYN rate limit: 50/s burst 100"
echo "[+] Connection limit per IP: 20"
echo "[+] HTTP new conn rate limit: 100/s"

exec httpd -D FOREGROUND
