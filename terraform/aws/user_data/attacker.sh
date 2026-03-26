#!/bin/bash
# Bootstrap attacker node — installs FloodKit and dependencies

set -e
export DEBIAN_FRONTEND=noninteractive

apt-get update -qq
apt-get install -y --no-install-recommends \
    python3 python3-pip python3-dev \
    gcc build-essential libpcap-dev \
    tcpdump nmap hping3 \
    iproute2 iputils-ping \
    ncat net-tools \
    dnsutils snmp ntpdate \
    iperf3 curl wget git vim

pip3 install --quiet scapy aiohttp click rich pyyaml

# Install Rust (for FloodKit native backend)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --quiet
source /root/.cargo/env

# Install Go
wget -q https://go.dev/dl/go1.22.linux-amd64.tar.gz
tar -C /usr/local -xzf go1.22.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> /root/.bashrc
rm go1.22.linux-amd64.tar.gz

# Clone FloodKit
git clone https://github.com/your-org/floodkit /opt/floodkit 2>/dev/null || \
    echo "[!] FloodKit not cloned — upload manually or mount"

# Create lab shortcuts
cat >> /root/.bashrc << 'EOF'
alias targets='cat /opt/dosarena/targets.txt'
alias scenarios='python3 /opt/dosarena/scenarios/run.py list'
echo ""
echo "DOSArena Attacker Node — AWS"
echo "  targets    — show all target IPs"
echo "  scenarios  — list available scenarios"
echo ""
EOF

# Write targets file
mkdir -p /opt/dosarena/scenarios
cat > /opt/dosarena/targets.txt << 'EOF'
DOSArena AWS Lab — Targets
=========================
10.0.2.20   apache-vuln         HTTP 80  (Slowloris, SYN, HTTP flood)
10.0.2.30   dns-open            UDP 53   (DNS amp ~60x)
10.0.2.31   ntp-vuln            UDP 123  (NTP amp ~550x)
10.0.2.32   snmp-vuln           UDP 161  (SNMP amp ~650x)
10.0.2.40   mysql-vuln          TCP 3306 (NUKE connection starvation)
10.0.3.20   apache-protected    HTTP 80  (hardened — try to bypass)
10.0.3.21   nginx-protected     HTTP 80  (hardened — try to bypass)
EOF

echo "[+] Attacker node ready"
