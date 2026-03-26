<div id="top" align="center">

[![License][license-shield]](https://github.com/franckferman/DOSArena/blob/stable/LICENSE)
[![Platform][platform-shield]](https://github.com/franckferman/DOSArena/releases)

<h1 align="center">DOSArena</h1>
<p align="center">
  <em>The first DoS/DDoS training platform with live proof-of-impact scoring.</em><br>
  8 scenarios. 15 containers. Flags are only issued when your attack is actually working.
</p>

</div>

---

## Table of Contents

<details open>
  <summary><strong>Click to collapse/expand</strong></summary>
  <ol>
    <li><a href="#what-is-dosarena">What is DOSArena</a></li>
    <li><a href="#attack-taxonomy">Attack Taxonomy</a></li>
    <li><a href="#judge-architecture">Judge Architecture</a></li>
    <li><a href="#project-structure">Project Structure</a></li>
    <li><a href="#network-topology">Network Topology</a></li>
    <li><a href="#quick-start--docker">Quick Start — Docker</a></li>
    <li><a href="#scenarios">Scenarios</a></li>
    <li><a href="#flag-system">Flag System</a></li>
    <li><a href="#judge-api">Judge API</a></li>
    <li><a href="#quick-start--terraform-aws">Quick Start — Terraform AWS</a></li>
    <li><a href="#monitoring">Monitoring</a></li>
    <li><a href="#troubleshooting">Troubleshooting</a></li>
    <li><a href="#bibliography">Bibliography</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
  </ol>
</details>

---

## What is DOSArena

DOSArena is a purpose-built lab environment for learning denial-of-service techniques through hands-on execution. It is the companion platform for [Floodles](https://github.com/franckferman/Floodles), the modular DoS/DDoS testing toolkit.

Classic CTF challenges ask you to find a flag in a file. DOSArena inverts this: you **prove a service is unavailable**. The judge service continuously polls every target every 5 seconds. When it confirms your attack is working — by observing degraded HTTP responses, exhausted connection tables, anomalous packet rates, or active amplification — it generates a time-windowed cryptographic flag. Your attack must still be running when you submit it.

Two deployment modes:

- **Docker** — full local lab on a single machine, 15 containers across 4 isolated networks
- **Terraform** — cloud deployment on AWS, one attacker node and seven target instances

The platform documentation is at [franckferman.github.io/DOSArena](https://franckferman.github.io/DOSArena/).

---

## Attack Taxonomy

DOSArena covers three categories of DoS/DDoS techniques across the OSI stack.

### Layer 3/4 — Network and Transport

**SYN Flood (scenario 01)**

TCP connection establishment requires the server to allocate a Transmission Control Block (TCB) in kernel memory for each incoming SYN packet and place the entry in the SYN backlog queue (`tcp_max_syn_backlog`, default 128-1024; set to 8 in this lab). If SYN cookies are disabled (`tcp_syncookies = 0`), this memory is allocated before the client completes the handshake. With spoofed source IPs, the SYN-ACK replies go to non-existent hosts that never send a final ACK. Each half-open entry persists for ~75 seconds (the SYN-RECV retransmission timeout). When the backlog fills, subsequent SYN packets are silently dropped.

Memory cost is negligible: 128 entries x ~200 bytes per TCB = ~25 KB. At just 2 PPS the queue stays permanently saturated (128 / 75s = 1.7 PPS to fill it). SYN cookies (RFC 4987) solve this by encoding connection state into the ISN (Initial Sequence Number) using a hash of `(src_ip, src_port, dst_ip, dst_port, timestamp)`. No memory is allocated until the ACK arrives and validates the ISN.

**ACK Flood / Stateless Firewall Bypass (scenario 03)**

A stateless packet filter evaluates each packet independently against a fixed ruleset (source/destination IP, port, protocol). It carries no memory between packets. An `iptables` rule `-A INPUT -p tcp --dport 80 -j ACCEPT` passes any TCP packet destined for port 80 — including ACK packets sent without a prior SYN. A stateful firewall maintains a connection tracking table (`nf_conntrack`) and rejects packets whose state does not match an established session.

In a real engagement, ACK bypass is used to probe services hidden behind stateless filters, trigger RST storms on the backend, or saturate CPU with kernel TCP stack processing at near line-rate.

### Layer 4 Amplification — Distributed Reflective DoS (DRDoS)

All three amplification scenarios share the same structure: a small request sent with a spoofed source IP (set to the victim's address) causes a reflector to send a disproportionately large response to the victim.

| Reflector | Protocol | Request | Response | Factor |
|-----------|----------|---------|----------|--------|
| BIND9 open resolver | DNS ANY query (UDP/53) | ~50 B | ~3,000 B | ~60x |
| NTPd monlist (mode 7, code 42) | NTP (UDP/123) | 8 B | up to 43,200 B | ~550x |
| Net-SNMP GetBulkRequest | SNMP v2c (UDP/161) | ~60 B | up to 65,507 B | ~650x |

**DNS amplification (scenario 04):** A DNS ANY query for a large domain record (e.g., `isc.org ANY`) returns TXT, MX, NS, and A records in a single response. BIND9 configured as an open resolver (`recursion yes; allow-recursion { any; };`) will answer for any domain from any source, making it an ideal reflector.

**NTP monlist (scenario 05):** NTP mode 7 (`private` mode) with request code 42 (`MON_GETLIST_1`) returns up to 600 client IP entries, each 72 bytes. An 8-byte NTP request triggers up to 480 UDP packets (600 × 72 = 43,200 B) in response. This was disclosed in CVE-2013-5211 and patched in NTPd 4.2.7p26 with `disable monitor`. The lab target runs an unpatched version.

**SNMP amplification (scenario 06):** SNMP v2c GetBulkRequest with `max-repetitions=255` targeting the MIB-II root (`.1.3.6.1.2.1`) dumps the entire device MIB — system info, interfaces, IP routing tables, TCP connections, UDP stats. Community string `public` is the default in most Net-SNMP deployments. Response fills multiple UDP datagrams up to the 65,507-byte UDP payload limit.

The judge gates these three scenarios with an active-attack detection mechanism: it reads Docker stats twice (1 second apart) and confirms the reflector container's RX packet rate exceeds 50 PPS before issuing the flag.

### Layer 7 — Application

**Slowloris (scenario 02):** Robert Hansen's 2009 attack exploits Apache's prefork/worker concurrency model. Each HTTP connection consumes one worker thread. HTTP/1.1 requests terminate with a blank line (`\r\n\r\n`). An attacker opens many connections, sends a partial request, then drip-feeds junk headers (e.g., `X-Custom-1234: value\r\n`) at one per 10 seconds — never completing the request. Workers block indefinitely waiting for the terminating blank line. With 200 sockets against a server configured `MaxRequestWorkers 150`, the server is fully saturated at under 1 KB/s total bandwidth. Event-driven servers (nginx, HAProxy) are immune: a single thread manages thousands of connections in a non-blocking I/O loop.

**Slow POST / RUDY (scenario 08):** R-U-Dead-Yet extends the Slowloris concept to the request body. The attacker sends a complete, valid HTTP header including `Content-Length: 10000000`, then delivers the declared body at one byte every 10 seconds. Servers protected against Slowloris with `mod_reqtimeout` on headers still wait for the full declared body to arrive. Workers are tied up for the same reason — the connection is legitimate from the HTTP protocol perspective.

**TCP Connection Starvation (scenario 07):** Databases accept TCP connections before any application-level authentication. Each incoming TCP connection (after the 3-way handshake) consumes a slot from the database's `max_connections` pool. On MySQL 8.0, the default is 151; this target is configured at 50. An attacker opens 60 TCP connections to port 3306, holds them open (no SQL sent, just the TCP connection), and subsequent legitimate clients receive `ERROR 1040 (HY000): Too many connections`. No MySQL credentials are required.

---

## Judge Architecture

The judge is an async Python service (`aiohttp`) that runs the entire scoring engine: target polling, attack detection, flag generation, flag verification, score tracking, and hint delivery.

### Polling Loop

```
every 5 seconds:
  for each scenario:
    probe(target) -> ProbeResult(success: bool, detail: str, latency_ms: float)
    if success:
      generate_flag(scenario_id, current_time_window)
      update state
```

Each scenario has a dedicated probe function matched to the attack type:

| Probe | Detection method |
|-------|-----------------|
| `probe_http` | HTTP GET with configurable latency threshold (2000-5000ms) or status codes 429/503/500 |
| `probe_syn_flood` | Docker stats: RX PPS on `dosarena_apache_vuln` >= 1000 PPS |
| `probe_slowloris` | `/proc/net/tcp` inside container: ESTABLISHED connections to port 80 (hex `0050`) in state `01` >= 50 |
| `probe_dns` / `probe_ntp` / `probe_snmp` | Protocol capability confirmed AND RX PPS on reflector container >= 50 PPS (active-attack gate) |
| `probe_db` | TCP connect to port 3306/5432: "Too many connections" in banner, connection refused, or timeout |

### Slowloris Detection via Docker Exec API

The judge reads `/proc/net/tcp` from inside the target container without a shell or SSH. It calls the Docker Engine API over the Unix socket (`/var/run/docker.sock`) using a custom `http.client` subclass:

```
POST /containers/dosarena_apache_vuln/exec
  { "AttachStdout": true, "Cmd": ["cat", "/proc/net/tcp"] }
-> exec_id

POST /exec/<exec_id>/start
-> multiplexed stream (8-byte header per chunk: [stream_type, 0, 0, 0, size_be_4])

parse stdout chunks:
  for each line in /proc/net/tcp:
    local_addr = parts[1]   # hex: "00000000:0050" for 0.0.0.0:80
    state      = parts[3]   # "01" = ESTABLISHED, "03" = SYN_RECV
    if local_addr ends with ":0050" and state == "01":
      count++
```

This unambiguously distinguishes Slowloris (ESTABLISHED connections, state `01`) from SYN flood (SYN_RECV entries, state `03`).

### HMAC-SHA256 Time-Windowed Flags

Flags are generated with a sliding time window keyed by HMAC-SHA256:

```python
window = int(time.time()) // FLAG_TTL   # FLAG_TTL = 300s (5 min)
payload = f"{scenario_id}:{window}".encode()
sig = hmac.new(SECRET.encode(), payload, sha256).hexdigest()[:24]
flag = f"DOSARENA{{{scenario_id.upper()}_{sig}}}"
```

Verification accepts two windows (current and previous) to handle clock skew between generation and submission:

```python
def verify_flag(scenario_id, flag):
    cur = _window()
    for w in [cur, cur - 1]:
        if hmac.compare_digest(flag, generate_flag(scenario_id, w)):
            return True
    return False
```

A valid flag submission also requires that the judge has independently confirmed degradation (`probe.success == True`) at the moment of submission — preventing flag reuse after an attack stops.

---

## Project Structure

```
DOSArena/
├── Makefile                     All commands: up / down / clean / shell / status / tf-*
├── README.md
│
├── judge/                       Judge service
│   ├── judge.py                 Async polling + HMAC flag generation + REST API
│   ├── hints.py                 Progressive hints — 3 levels per scenario
│   ├── writeups.py              Full writeups — unlocked after correct submission
│   └── Dockerfile
│
├── ui/
│   └── cli.py                   Player terminal interface (Rich TUI)
│
├── docs/                        Static site (GitHub Pages)
│   ├── index.html               Landing page
│   └── dashboard.html           Live monitoring dashboard
│
├── docker/                      Local lab
│   ├── docker-compose.yml       Full lab: 15 containers, 4 networks
│   ├── attacker/                Attacker node — Floodles, hping3, Scapy, nmap, ntp/snmp tools
│   ├── monitor/                 Prometheus config + node-exporter
│   ├── scenarios/               Scenario runner and target reference (run.py)
│   └── targets/                 8 vulnerable + 2 hardened targets
│       ├── apache-vuln/         Apache 2.4, MaxRequestWorkers=150, tcp_syncookies=0
│       ├── apache-protected/    Apache + mod_reqtimeout + iptables + SYN cookies
│       ├── nginx-protected/     nginx event-driven + rate limiting + header timeouts
│       ├── dns-open/            BIND9 — recursion yes, allow-recursion any
│       ├── ntp-vuln/            NTPd 4.2.6 — monlist enabled, disable monitor absent
│       ├── snmp-vuln/           Net-SNMP — community=public, no ACL
│       ├── firewall-stateless/  iptables rules without -m state
│       └── firewall-stateful/   iptables + conntrack, limited connection table
│
└── terraform/aws/               Cloud lab
    ├── main.tf                  VPC + 7 EC2 instances + security groups
    ├── variables.tf
    └── user_data/               Bootstrap scripts per target
```

---

## Network Topology

```
10.0.1.0/24  Attacker Network
  10.0.1.10  attacker          Floodles, hping3, Scapy, nmap, ntpdc, snmpwalk, tcpdump

10.0.2.0/24  DMZ — Vulnerable Targets (IP masquerade disabled)
  10.0.2.20  apache-vuln       HTTP:80   SYN flood, Slowloris, Slow POST
  10.0.2.30  dns-open          UDP:53    DNS amplification (~60x)
  10.0.2.31  ntp-vuln          UDP:123   NTP monlist (~550x)
  10.0.2.32  snmp-vuln         UDP:161   SNMP GetBulk (~650x)
  10.0.2.40  mysql-vuln        TCP:3306  max_connections=50
  10.0.2.41  postgres-vuln     TCP:5432  max_connections=30
  10.0.2.50  fw-stateless      HTTP:80   ACK/XMAS flood bypass
  10.0.2.51  fw-stateful       HTTP:80   conntrack table overflow

10.0.3.0/24  Protected Targets (IP masquerade disabled)
  10.0.3.20  apache-protected  HTTP:80   mod_reqtimeout + SYN cookies + iptables rate limit
  10.0.3.21  nginx-protected   HTTP:80   event-driven + client_header_timeout + limit_conn

10.0.99.0/24 Management Network
  10.0.99.10 attacker          (also on this subnet)
  10.0.99.20 prometheus        :9090
  10.0.99.21 grafana           :3000     admin / dosarena
  10.0.99.30 judge             :8888     DOSArena Judge API
```

The DMZ and protected subnets have `com.docker.network.bridge.enable_ip_masquerade: "false"` — outbound traffic from targets cannot reach the internet, preventing accidental external amplification.

---

## Quick Start — Docker

### Requirements

- Docker 20.10+ and Docker Compose v2 (`docker compose`, not legacy `docker-compose` v1)
- Linux host recommended — `NET_RAW` capability is required for raw socket attacks (SYN flood, ACK flood, amplification with spoofed source IPs)
- Minimum 4 GB RAM, 8 GB free disk space
- GNU `make` (optional — direct `docker compose` equivalents documented below)

Docker socket access — either run with `sudo`, or add your user to the docker group:

```bash
sudo usermod -aG docker $USER   # then log out and back in
```

### Deploy

```bash
# Build images and start the full lab
make up

# Open attacker shell
make shell

# Check all services are up
make status
```

Without `make`:

```bash
docker compose -f docker/docker-compose.yml up -d --build
docker compose -f docker/docker-compose.yml exec attacker bash
docker compose -f docker/docker-compose.yml ps
docker compose -f docker/docker-compose.yml down
```

### Web Interfaces

| Interface | URL | Credentials |
|-----------|-----|-------------|
| Judge API | http://localhost:8888/status | — |
| Grafana | http://localhost:3000 | admin / dosarena |
| Prometheus | http://localhost:9090 | — |

### Player Name

Default player name is `player1`, set in `docker/docker-compose.yml`:

```yaml
environment:
  PLAYER_NAME: "yourname"
  JUDGE_URL: "http://10.0.99.30:8888"
```

Or override at runtime inside the attacker container:

```bash
export PLAYER_NAME="yourname"
```

### Inside the Attacker Container

```bash
# List all scenarios and their current state
python3 /opt/scenarios/run.py list

# Display full instructions for a scenario
python3 /opt/scenarios/run.py run 01

# Get a hint (costs points)
python3 /opt/ui/cli.py hint 01
python3 /opt/ui/cli.py hint 01 --level 2

# Submit a flag
python3 /opt/ui/cli.py submit 01

# Read full writeup after solving
python3 /opt/ui/cli.py writeup 01

# Scoreboard
python3 /opt/ui/cli.py scoreboard
```

### Floodles — Attack Commands per Scenario

[Floodles](https://github.com/franckferman/Floodles) is the primary attack toolkit pre-installed in the attacker container. Raw socket commands (SYN flood, ACK flood, amplification) require root (`sudo`) for kernel-level packet crafting.

```bash
# 01 — SYN Flood (fills tcp_max_syn_backlog, requires spoofed IPs -> root)
sudo floodles syn 10.0.2.20 80 --duration 30

# 02 — Slowloris (holds worker threads, no root required)
floodles slow 10.0.2.20 80 --duration 60

# 03 — ACK Flood (stateless firewall bypass, requires raw socket -> root)
sudo floodles ack 10.0.2.50 80 --duration 30

# 04 — DNS Amplification (spoofed source -> victim, open resolver as reflector)
sudo floodles dns 10.0.2.30 --target <victim_ip> --duration 30

# 05 — NTP Amplification (monlist mode 7 code 42)
sudo floodles ntp 10.0.2.31 --target <victim_ip> --duration 30

# 06 — SNMP Amplification (GetBulkRequest, community=public)
sudo floodles sniper 10.0.2.32 --target <victim_ip> --duration 30

# 07 — TCP connection starvation (MySQL max_connections=50, no auth needed)
floodles nuke 10.0.2.40 3306 --duration 30

# 08 — Slow POST / RUDY (HTTP body drip, no root required)
floodles slowpost 10.0.2.20 80 --duration 60
```

> **Amplification scenarios (04/05/06):** The judge confirms the reflector is *capable* of amplification on every poll, but only issues the flag when an active attack is detected on the reflector (RX PPS > 50). Keep the attack running at the moment of submission.

Run `floodles --help` or `floodles <command> --help` for all available options.

### Stop the Lab

```bash
make down     # Stop containers, keep images
make clean    # Full cleanup including images
```

---

## Scenarios

| # | Name | Target | Technique | Difficulty | Points |
|---|------|--------|-----------|------------|--------|
| 01 | SYN Flood — TCP backlog exhaustion | 10.0.2.20:80 | L4 — SYN flood, spoofed IPs | Easy | 100 |
| 02 | Slowloris — HTTP worker pool | 10.0.2.20:80 | L7 — slow headers | Easy | 100 |
| 03 | ACK Bypass — stateless firewall | 10.0.2.50:80 | L4 — stateless bypass | Medium | 150 |
| 04 | DNS Amplification — open resolver | 10.0.2.30:53 | L3 — DRDoS (~60x) | Easy | 100 |
| 05 | NTP Amplification — monlist | 10.0.2.31:123 | L3 — DRDoS (~550x) | Easy | 100 |
| 06 | SNMP Amplification — GetBulk | 10.0.2.32:161 | L3 — DRDoS (~650x) | Medium | 150 |
| 07 | TCP Starvation — MySQL connections | 10.0.2.40:3306 | L4 — connection table | Medium | 150 |
| 08 | Slow POST — RUDY body timeout | 10.0.2.20:80 | L7 — slow body | Hard | 200 |
| | | | **Total** | | **1,050** |

### Target Vulnerability Configuration

Each vulnerable target has deliberately degraded security controls. The protected counterparts run the same service with defenses enabled — allowing direct comparison under identical attack conditions.

**apache-vuln (10.0.2.20)**

```apache
# Vulnerable configuration
MaxRequestWorkers 150       # Fixed worker pool (no event MPM)
KeepAliveTimeout 0          # No keep-alive timeout
# mod_reqtimeout NOT loaded  <- No header or body read timeout
```

```bash
# Kernel — SYN cookie protection disabled
net.ipv4.tcp_syncookies = 0
net.ipv4.tcp_max_syn_backlog = 8     # Lab value — fills in milliseconds at low PPS
net.core.somaxconn = 8
```

**dns-open (10.0.2.30)**

```named
// BIND9 — open recursive resolver
recursion yes;
allow-recursion { any; };    // Answers ANY query from ANY source
```

**ntp-vuln (10.0.2.31)**

```ntp
# NTPd 4.2.6 — monlist not disabled
# disable monitor is absent -> mode 7 MON_GETLIST_1 requests answered
```

**snmp-vuln (10.0.2.32)**

```snmp
# Net-SNMP
rocommunity public          # Default community string, no source ACL
# No view restriction on OID tree
```

**mysql-vuln (10.0.2.40)**

```sql
-- MySQL 8.0
SET GLOBAL max_connections = 50;  -- Far below default (151)
-- No per-user connection limits
-- No TCP connection rate limiting
```

**fw-stateless (10.0.2.50)**

```bash
# iptables rules without connection tracking
iptables -A INPUT -p tcp --dport 80 -j ACCEPT   # Passes ALL TCP to port 80
# No -m state, no -m conntrack
# ACK packets without prior SYN pass through
```

---

## Flag System

Flags are HMAC-SHA256 tokens bound to a time window (default: 5 minutes) and a scenario ID. They are generated the moment the judge confirms degradation and re-generated on every subsequent successful poll:

```
Format:  DOSARENA{SCENARIO_ID_hmac_truncated_hex}
Example: DOSARENA{01_a3f9c2d18e4b7f3d2c1b}
```

**Submission rules:**

1. The attack must be running at the moment of submission — the judge must have confirmed degradation within the last 5 seconds
2. Flags expire after the current and previous time windows (up to ~10 minutes grace period)
3. A correct submission unlocks the full technical writeup immediately
4. Hints cost points: Level 1 = -10 pts, Level 2 = -25 pts, Level 3 = -50 pts
5. Each scenario can only be solved once per player

**Hint system:**

Each scenario has 3 progressive hints:
- **Level 1** — direction nudge, does not reveal the attack type
- **Level 2** — vulnerability class, kernel parameters or config to inspect
- **Level 3** — near-explicit command with tool and parameters

---

## Judge API

| Endpoint | Method | Body / Params | Description |
|----------|--------|---------------|-------------|
| `/status` | GET | — | All scenarios, targets, degradation state, active flags |
| `/submit` | POST | `{"player", "scenario", "flag"}` | Flag submission |
| `/hint/<id>` | GET | `?level=1\|2\|3` | Progressive hint for scenario |
| `/writeup/<id>` | GET | — | Full writeup (always accessible via API) |
| `/scoreboard` | GET | — | Ranked player list |
| `/health` | GET | — | Service health check |

```bash
# Check all targets and current degradation state
curl http://localhost:8888/status | python3 -m json.tool

# Submit a flag
curl -X POST http://localhost:8888/submit \
  -H "Content-Type: application/json" \
  -d '{"player":"yourname","scenario":"01","flag":"DOSARENA{01_...}"}'

# Get hint
curl "http://localhost:8888/hint/01?level=2"

# Scoreboard
curl http://localhost:8888/scoreboard
```

---

## Quick Start — Terraform AWS

### Requirements

- [Terraform 1.x+](https://developer.hashicorp.com/terraform/downloads)
- AWS CLI configured (`aws configure`) with permissions for VPC, EC2, Security Groups, and Elastic IPs
- An existing EC2 key pair in the target region

```bash
# Create your variables file (do not commit this)
cat > terraform/aws/terraform.tfvars << EOF
key_pair = "your-keypair-name"
your_ip  = "$(curl -s ifconfig.me)/32"
region   = "eu-west-1"
EOF

# Deploy (~5 min)
make tf-init
make tf-apply

# SSH to attacker node
ssh ubuntu@<attacker_ip> -i ~/.ssh/your-keypair.pem

# Tear down when done
make tf-destroy
```

**Estimated AWS cost:** ~$0.35/hour with default instance types (t3.medium attacker + t3.small x7 targets).

---

## Monitoring

```bash
# Live bandwidth per host (inside attacker container)
iftop -i eth0 -n

# Connection state breakdown
watch -n1 'ss -s'

# SYN-RECV count (SYN flood indicator)
watch -n1 'ss -s | grep SYN-RECV'

# SYN packets only
tcpdump -i eth0 -n 'tcp[tcpflags] & tcp-syn != 0'

# ESTABLISHED connections to port 80 (Slowloris indicator)
watch -n1 'ss -tn dst :80 state established | wc -l'

# Grafana dashboard (host)
open http://localhost:3000   # admin/dosarena

# Judge poll log
docker compose -f docker/docker-compose.yml logs -f judge
```

---

## Troubleshooting

### `docker-compose` v1 incompatible with Docker 28+

The legacy `docker-compose` v1 (Python binary) was removed from the Docker Engine API in Docker 28.x. Use Compose v2:

```bash
# Ubuntu 24.04
sudo apt-get install docker-compose-v2

# Verify
docker compose version   # should print v2.x
```

### SYN flood sends packets but judge never shows degraded

The host kernel's reverse path filter (`rp_filter`) drops packets with spoofed source IPs on Docker bridge interfaces. `make up` disables it automatically. If you started containers without `make up`, run this on the host:

```bash
sudo bash -c 'for i in $(ls /proc/sys/net/ipv4/conf/); do sysctl -w net.ipv4.conf.$i.rp_filter=0; done'
```

This must be re-applied after every host reboot.

### Raw socket attacks fail (SYN flood, ACK flood)

Raw socket attacks require `NET_RAW` capability. On macOS with Docker Desktop, kernel-level capabilities are restricted. Use a Linux host or a Linux VM.

### Judge reports targets unreachable but containers are up

The judge runs on the management network (`10.0.99.30`). If a container started but its service is not ready yet, wait 5-10 seconds and check `/status` again:

```bash
curl http://localhost:8888/status | python3 -m json.tool
```

### Container exits immediately

```bash
docker compose -f docker/docker-compose.yml logs <service-name>
```

---

## Bibliography

[1] Eddy, W. (2007). *TCP SYN Flooding Attacks and Common Mitigations*. RFC 4987. IETF.

[2] Mirkovic, J., & Reiher, P. (2004). A taxonomy of DDoS attack and DDoS defense mechanisms. *ACM SIGCOMM Computer Communication Review*, 34(2), 39-53.

[3] Paxson, V. (2001). An Analysis of Using Reflectors for Distributed Denial-of-Service Attacks. *ACM SIGCOMM Computer Communication Review*, 31(3), 38-47. — foundational analysis of DRDoS/amplification attacks.

[4] Ferguson, P., & Senie, D. (2000). *Network Ingress Filtering: Defeating Denial of Service Attacks which employ IP Source Address Spoofing*. RFC 2827. IETF. — BCP 38, the mitigation for spoofed-source attacks.

[5] Hansen, R. (2009). *Slowloris HTTP DoS*. ha.ckers.org. — original disclosure of the Slowloris technique.

[6] US-CERT Advisory (TA14-013A). (2014). *UDP-Based Amplification Attacks*. — NTP monlist CVE-2013-5211, SNMP, DNS amplification classification.

[7] Cloudflare. (2023). *Understanding SYN floods*. Cloudflare Blog. — production-scale analysis of SYN cookie performance.

[8] Linux kernel documentation. `net/ipv4/tcp_input.c` — `tcp_conn_request()`, SYN backlog and SYN cookie implementation.

---

## License

GNU Affero General Public License v3.0. See [LICENSE](https://github.com/franckferman/DOSArena/blob/stable/LICENSE) for details.

<p align="right">(<a href="#top">Back to top</a>)</p>

---

## Contact

[![ProtonMail][protonmail-shield]](mailto:contact@franckferman.fr)
[![LinkedIn][linkedin-shield]](https://www.linkedin.com/in/franckferman)
[![Twitter][twitter-shield]](https://www.twitter.com/franckferman)

<p align="right">(<a href="#top">Back to top</a>)</p>

<!-- MARKDOWN LINKS & IMAGES -->
[license-shield]: https://img.shields.io/github/license/franckferman/DOSArena.svg?style=for-the-badge
[platform-shield]: https://img.shields.io/badge/Platform-Linux%20%7C%20AWS-lightgrey?style=for-the-badge
[protonmail-shield]: https://img.shields.io/badge/ProtonMail-8B89CC?style=for-the-badge&logo=protonmail&logoColor=blueviolet
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=blue
[twitter-shield]: https://img.shields.io/badge/-Twitter-black.svg?style=for-the-badge&logo=twitter&colorB=blue
