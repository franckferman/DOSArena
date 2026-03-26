#!/bin/bash
# nginx_protected.sh
set -e; export DEBIAN_FRONTEND=noninteractive
apt-get update -qq && apt-get install -y nginx
echo "net.ipv4.tcp_syncookies=1" >> /etc/sysctl.conf && sysctl -p
cat > /etc/nginx/nginx.conf << 'EOF'
worker_processes auto;
events { worker_connections 1024; use epoll; }
http {
    limit_req_zone  $binary_remote_addr zone=rl:10m rate=100r/s;
    limit_conn_zone $binary_remote_addr zone=cl:10m;
    client_header_timeout 10s;
    client_body_timeout   10s;
    keepalive_timeout     30s;
    server {
        listen 80;
        limit_req  zone=rl burst=200 nodelay;
        limit_conn cl 20;
        location / { return 200 "DOSArena nginx Protected\n"; }
    }
}
EOF
systemctl enable nginx && systemctl restart nginx
echo "[+] nginx-protected ready"
