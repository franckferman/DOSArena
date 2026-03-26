"""
writeups/writeups.py
Full writeups — revealed after a scenario is solved.

Each writeup contains:
  - Vulnerability explanation (why it exists)
  - Attack mechanics (what happens step by step)
  - Real-world context (where this is seen in the wild)
  - Detection (how defenders detect it)
  - Mitigation (how to fix it)
  - Further reading
"""

WRITEUPS = {
    "01": {
        "title": "SYN Flood — TCP Backlog Exhaustion",
        "tldr": "The server allocates memory for every SYN it receives. Without SYN cookies, this memory fills up and no new connections can be accepted.",

        "vulnerability": """
The TCP three-way handshake (SYN → SYN-ACK → ACK) requires the server to maintain
state for each half-open connection. When it receives a SYN, it allocates a
Transmission Control Block (TCB) in kernel memory and puts the entry into the
SYN queue (syn_backlog).

apache-vuln has:
  net.ipv4.tcp_syncookies = 0       <- SYN cookies disabled
  net.ipv4.tcp_max_syn_backlog = 128 <- Only 128 half-open connections

With spoofed source IPs, the SYN-ACKs go to random hosts that never send a final
ACK. Each entry stays in the queue for ~75 seconds (default SYN retransmit timeout).
When the queue is full, new SYN packets are silently dropped.
        """,

        "mechanics": """
1. Attacker sends SYN with source IP = random (spoofed)
2. Server allocates TCB (~200 bytes), puts in SYN queue, sends SYN-ACK
3. SYN-ACK goes to spoofed IP (which sends RST or nothing)
4. Server waits for ACK that never comes (75s timeout)
5. Repeat x1000: SYN queue fills, new connections get ECONNREFUSED

Memory cost: 128 entries × 200 bytes = ~25KB to completely block the server
PPS needed: ~2 PPS to keep 128 entries full (128 / 75s ≈ 1.7 PPS)
        """,

        "real_world": """
SYN floods have been used since the mid-1990s. Notable incidents:
- 1996: Panix ISP taken offline for days by SYN flood
- 2000: Major sites (Yahoo, CNN, Amazon) hit in coordinated DDoS campaign
- Still used today as part of multi-vector DDoS attacks

Modern mitigation: SYN cookies (RFC 4987) encode connection state in the
ISN (Initial Sequence Number) of the SYN-ACK using a cryptographic hash.
No memory allocated until the ACK confirms the client is real.
        """,

        "detection": """
Server-side indicators:
  ss -s | grep SYN-RECV        # Queue filling up
  netstat -s | grep "SYNs to LISTEN"  # Dropped SYN count
  /proc/net/snmp -> TcpExt: SyncookiesSent (if cookies enabled)

Network indicators:
  High rate of SYN packets from many different source IPs
  No corresponding ACK for most SYNs (asymmetric traffic)
  SYN-ACK replies going to many different destinations
        """,

        "mitigation": """
1. Enable SYN cookies (primary defense):
   sysctl -w net.ipv4.tcp_syncookies=1
   Add to /etc/sysctl.conf for persistence

2. Increase SYN backlog (buys time, not a real fix):
   sysctl -w net.ipv4.tcp_max_syn_backlog=4096

3. Upstream rate limiting (firewall):
   iptables -A INPUT -p tcp --syn -m limit --limit 50/s --limit-burst 100 -j ACCEPT
   iptables -A INPUT -p tcp --syn -j DROP

4. Anti-DDoS hardware/cloud scrubbing (for large-scale attacks)

apache-protected has all of these enabled. Try the same attack — it should have
no impact on that server.
        """,

        "further_reading": [
            "RFC 4987 — TCP SYN Flooding Attacks and Common Mitigations",
            "Linux kernel: net/ipv4/tcp_input.c — tcp_conn_request()",
            "Cloudflare blog: SYN packet handling in the wild",
        ],
    },

    "02": {
        "title": "Slowloris — HTTP Worker Pool Exhaustion",
        "tldr": "Apache assigns one thread per connection. By keeping connections alive while sending headers one byte at a time, all workers can be tied up with zero bandwidth.",

        "vulnerability": """
Apache prefork/worker MPM assigns a dedicated thread or process to each active
HTTP connection. This pool has a maximum size (MaxRequestWorkers, default 150-256).

HTTP/1.1 specifies a request ends when the server receives a blank line (\\r\\n\\r\\n).
Until that blank line arrives, Apache's thread must stay alive and wait.

apache-vuln has:
  MaxRequestWorkers = 150       <- 150 concurrent connections maximum
  KeepAliveTimeout = 0          <- No timeout on keep-alive connections
  mod_reqtimeout NOT loaded     <- No header read timeout

This means a connection sending headers at 1 byte/minute is held open indefinitely.
        """,

        "mechanics": """
1. Open 200 TCP connections to Apache
2. On each: send partial HTTP request (no final \\r\\n\\r\\n):
   "GET / HTTP/1.1\\r\\nHost: target\\r\\nUser-Agent: ...\\r\\n"
3. Every 10 seconds, drip a junk header on each socket:
   "X-Custom-1234: randomvalue\\r\\n"
4. Never send the final \\r\\n — request never completes
5. All 150 workers are blocked, new connections get ECONNREFUSED

Bandwidth used: 200 sockets × 30 bytes/10s = 600 bytes/sec total
That is less than a single ping — yet the server is fully DoS'd.
        """,

        "real_world": """
Slowloris was released by Robert 'RSnake' Hansen in 2009.
It brought down sites using Apache with zero bandwidth, from a single laptop.

Particularly impactful because:
- Works with a standard TCP stack (no root required)
- Cannot be filtered by bandwidth-based DDoS mitigation
- Works through most firewalls (TCP port 80 is allowed)

Real-world use: reported in multiple hacktivism campaigns (2009-2012 era).
        """,

        "detection": """
Server-side:
  netstat -n | grep :80 | grep ESTABLISHED | wc -l  # Rising connections
  Apache error log: "server reached MaxRequestWorkers"
  watch -n1 'ss -tn dst :80 state established | wc -l'

Network indicators:
  Many long-lived connections with minimal data transfer
  Source IP sending small bursts (the keep-alive headers) every 10-15s
  No request ever completes (no response ever sent by server)
        """,

        "mitigation": """
1. mod_reqtimeout (primary Apache defense):
   RequestReadTimeout header=10-20,MinRate=500
   RequestReadTimeout body=10-30,MinRate=500
   This kills any connection sending headers slower than 500 bytes/sec.

2. Switch to nginx (event-driven, no thread-per-connection):
   nginx handles 10,000+ slow connections on a single worker thread.
   client_header_timeout 10s;  <- closes slow header connections

3. HAProxy in front of Apache:
   timeout client 30s  <- maximum time between data from client

4. Rate limit connections per source IP:
   iptables -A INPUT -p tcp --dport 80 -m connlimit --connlimit-above 20 -j REJECT

Try nginx-protected (10.0.3.21) — same Slowloris attack has zero effect.
        """,

        "further_reading": [
            "Slowloris original release: ha.ckers.org/slowloris/",
            "CVE-2007-6750 — Apache mod_reqtimeout bypass",
            "nginx architecture: 'The C10K problem' by Dan Kegel",
        ],
    },

    "03": {
        "title": "Stateless Firewall Bypass via ACK Flood",
        "tldr": "A firewall that only checks port numbers will pass ACK packets without verifying they belong to an established connection.",

        "vulnerability": """
Firewalls come in two flavors:

STATELESS (packet filter):
  Rules: "allow TCP port 80 inbound"
  Decision: based on packet headers only (src/dst IP, port, protocol)
  No memory of prior packets — each packet evaluated independently
  Result: a spoofed ACK to port 80 matches the rule and passes

STATEFUL (connection tracking):
  Maintains a table of established connections (src_ip:port, dst_ip:port, state)
  Decision: based on both packet headers AND connection state
  An ACK with no prior SYN in the state table → DROP
  Result: spoofed ACK packets are invisible to the server

fw-stateless (10.0.2.50) uses simple iptables rules without -m state.
fw-stateful  (10.0.2.51) uses iptables with -m state --state ESTABLISHED,RELATED.
        """,

        "mechanics": """
Stateless bypass:
1. Send ACK packet: src=random_ip, dst=10.0.2.50:80
2. iptables rule: -A INPUT -p tcp --dport 80 -j ACCEPT -> MATCH (no state check)
3. Packet delivered to nginx backend
4. nginx sees ACK without prior connection -> sends RST
5. RST goes to spoofed IP

Impact: each ACK causes kernel RST generation on the server.
At high rate: CPU busy generating RSTs, bandwidth consumed by RST storm.

Real bypass scenario: An attacker behind a stateless firewall can send
ACK-flagged packets to probe the network or bypass SYN-based filters.
        """,

        "detection": """
If you are the target:
  iptables -n -v -L | grep "state"  <- is conntrack used?
  watch -n1 'conntrack -L | wc -l'  <- connection tracking table size
  tcpdump -n 'tcp[tcpflags] & tcp-ack != 0 and not tcp[tcpflags] & tcp-syn != 0'
    <- Shows ACK-only packets (should be rare without prior SYNs)
        """,

        "mitigation": """
1. Use stateful inspection (primary fix):
   iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
   iptables -A INPUT -p tcp --dport 80 --syn -j ACCEPT
   iptables -A INPUT -j DROP

2. Enable connection tracking (automatically stateful):
   modprobe nf_conntrack
   iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

3. Use a proper stateful firewall appliance (pfSense, OPNsense, Cisco ASA)
   instead of bare iptables rules.
        """,

        "further_reading": [
            "iptables man page — -m state / -m conntrack",
            "RFC 3128 — Protection Against a Variant of the Tiny Fragment Attack",
            "Cisco: 'Understanding ACK Flooding'",
        ],
    },
}

def get_writeup(scenario_id: str) -> dict:
    """Return writeup for a scenario, or None if not solved."""
    return WRITEUPS.get(scenario_id)
