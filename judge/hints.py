"""
judge/hints.py
Progressive hint system — 3 levels per scenario.

Level 1: Direction nudge (doesn't reveal the technique)
Level 2: Technical hint (reveals the vulnerability class)
Level 3: Near-explicit (reveals the tool and parameter)

Cost model (if scoring is enabled):
  Level 1: -10 points
  Level 2: -25 points
  Level 3: -50 points
"""

HINTS = {
    "01": [
        # Level 1 — Direction
        "The server must allocate memory for each incoming connection attempt. "
        "What happens when you exhaust that allocation pool?",

        # Level 2 — Technical
        "TCP connections begin with a SYN packet. The server holds half-open "
        "connections in a queue with limited capacity. "
        "Check: sysctl net.ipv4.tcp_max_syn_backlog on the target. "
        "Check: sysctl net.ipv4.tcp_syncookies — if 0, the server is fully vulnerable.",

        # Level 3 — Near-explicit
        "Use a SYN flood against port 80. "
        "Start with 4 threads, increase to 16 for full saturation. "
        "Monitor with: watch -n1 'ss -s' and look for SYN-RECV climbing. "
        "Command: sudo floodkit syn 10.0.2.20 80 -t 16 -d 60",
    ],

    "02": [
        "A web server has a finite number of workers. Each worker handles one "
        "connection at a time. What if you held all workers busy doing nothing?",

        "Apache prefork assigns one thread per connection. HTTP/1.1 requires "
        "a blank line (CRLF CRLF) to end a request. "
        "A connection sending headers slowly but never finishing ties up a worker indefinitely. "
        "Check MaxRequestWorkers in Apache's config — that's your target count.",

        "Use Slowloris with socket_count > MaxRequestWorkers (150 on this target). "
        "Command: floodkit slow 10.0.2.20 -s 200 -d 120 "
        "Verify: curl --connect-timeout 3 http://10.0.2.20/ should timeout.",
    ],

    "03": [
        "Not all firewalls are equal. Some inspect packet content and connection state. "
        "Others just look at port numbers. "
        "Can you tell which type this firewall is?",

        "A stateless firewall uses rules like 'allow port 80'. "
        "An ACK packet directed at port 80 matches that rule — even without a prior SYN. "
        "A stateful firewall tracks connection state and rejects ACK without prior SYN. "
        "Use tcpdump on the monitor to see if ACK packets reach the server behind the firewall.",

        "The stateless firewall is at 10.0.2.50. "
        "Run: sudo floodkit ack 10.0.2.50 80 -t 4 -d 30 "
        "Simultaneously run: tcpdump -i eth0 -n 'host 10.0.2.50 and tcp[tcpflags] & tcp-ack != 0' "
        "If you see ACK packets — they passed the firewall. That is your proof.",
    ],

    "04": [
        "This DNS server might answer questions it should not be answering. "
        "Specifically, it might answer questions for domains it has no authority over, "
        "and from sources it has no business serving.",

        "An 'open resolver' is a DNS server that accepts recursive queries from any IP. "
        "A DNS ANY query asks for all records of a domain — the response is much larger than the request. "
        "This creates an amplification primitive: small request, large response. "
        "Test with: dig @10.0.2.30 isc.org ANY",

        "Verify the amplification factor: "
        "Send a ~50 byte query, measure the response size. "
        "Command: dig @10.0.2.30 isc.org ANY | wc -c "
        "Factor = response_bytes / 50. If > 10x — it is a valid reflector. "
        "The judge will confirm when you query it.",
    ],

    "05": [
        "NTP keeps your clocks synchronized. But some NTP servers answer a very specific "
        "management command that returns a lot more data than the original request. "
        "Which command is that?",

        "NTP mode 7 has a command called 'monlist' (code 42). "
        "It returns the last 600 clients that queried the server. "
        "Request = 8 bytes. Response = up to 43,200 bytes. That is ~550x amplification. "
        "This was patched in NTPd 4.2.7p26 with 'disable monitor'. "
        "This server has not applied that fix.",

        "Probe the NTP server directly: "
        "ntpdc -c monlist 10.0.2.31 "
        "Or in Python: send bytes [0x17,0x00,0x03,0x2a,0x00,0x00,0x00,0x00] to UDP:123 "
        "and measure the response size. "
        "The judge polls this automatically — just confirm it responds.",
    ],

    "06": [
        "Network equipment uses a management protocol that can be queried for its configuration. "
        "This server is running a version of that protocol with weak authentication "
        "and no query restrictions.",

        "SNMP v2c uses a 'community string' as its only authentication. "
        "The default community string is 'public'. "
        "GetBulkRequest asks for up to 255 repetitions of each OID — "
        "targeting the MIB-II root dumps the entire device configuration. "
        "Request = ~60 bytes. Response = up to 65,507 bytes. ~650x amplification. "
        "Test: snmpwalk -v2c -c public 10.0.2.32 .1.3.6.1.2.1.1",

        "Confirm vulnerability: "
        "snmpwalk -v2c -c public 10.0.2.32 .1.3.6.1.2.1 "
        "If it returns data — vulnerable. "
        "In a real audit: find internal equipment with community=public using "
        "nmap -sU -p 161 --script snmp-info <subnet>. "
        "The judge confirms when GetBulk returns > 100 bytes.",
    ],

    "07": [
        "Databases have connection limits. Those limits exist for good reason — "
        "but what happens when you reach them? "
        "You do not need to authenticate to test this.",

        "TCP connections to a database go through a 3-way handshake before any authentication. "
        "If you open many TCP connections and hold them open, "
        "you consume slots from max_connections — even before sending any SQL. "
        "MySQL's default max_connections is 151. This server is configured with a much lower limit.",

        "Connect to MySQL but do not authenticate — just hold the TCP connection open. "
        "Repeat 60 times (target has max_connections=50). "
        "Command: floodkit nuke 10.0.2.40 --port 3306 -s 60 --variant hold -d 60 "
        "Verify: mysql -h 10.0.2.40 -u labuser -plabpass -e 'SELECT 1;' "
        "Expected: ERROR 1040 (HY000): Too many connections",
    ],

    "08": [
        "Slowloris sends incomplete headers. But what if the headers are complete "
        "and only the body is being dripped slowly? "
        "Does this server have a body read timeout?",

        "HTTP POST requires a body. The server knows how much to expect via Content-Length. "
        "If you declare Content-Length: 10000000 (10 MB) and send 1 byte every 10 seconds, "
        "the server must keep the connection open waiting for the remaining bytes. "
        "This works even on servers with header timeouts (like a Slowloris-protected server). "
        "This is called a Slow POST attack, also known as RUDY (R-U-Dead-Yet).",

        "Use Slow POST against apache-vuln: "
        "floodkit slowpost 10.0.2.20 -s 150 --cl 10000000 -d 120 "
        "The Content-Length declares 10MB but only 1 byte/10s is sent. "
        "Worker pool fills just like Slowloris but via the body channel. "
        "Verify: curl --connect-timeout 3 http://10.0.2.20/ should time out.",
    ],
}

HINT_COSTS = {1: 10, 2: 25, 3: 50}  # Points deducted per hint level
