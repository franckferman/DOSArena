#!/bin/bash
# dns_open.sh — BIND9 open resolver
set -e; export DEBIAN_FRONTEND=noninteractive
apt-get update -qq && apt-get install -y bind9 bind9utils
cat > /etc/bind/named.conf.options << 'EOF'
options {
    directory "/var/cache/bind";
    recursion yes;
    allow-recursion { any; };
    allow-query { any; };
    dnssec-validation no;
    listen-on { any; };
    listen-on-v6 { none; };
};
EOF
systemctl enable named && systemctl restart named
echo "[+] dns-open ready (open resolver, ANY queries allowed)"
