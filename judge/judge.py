#!/usr/bin/env python3
"""
judge/judge.py
DOSArena — Automated Judge Service

Polls all targets every 5 seconds.
Issues HMAC-SHA256 time-windowed flags when degradation is confirmed.

API:
  GET  /status          All scenarios + degradation state + active flags
  POST /submit          Submit {"player", "scenario", "flag"}
  GET  /hint/<id>       Progressive hint (param: ?level=1|2|3)
  GET  /scoreboard      Ranked player list
  GET  /health          Health check
"""

import asyncio
import hashlib
import hmac
import time
import socket
import json
import os
import http.client
from dataclasses import dataclass, field, asdict
from typing import Optional
from aiohttp import web, ClientSession, ClientTimeout, ClientError, TCPConnector

# ── Config ──────────────────────────────────────────────────────────────────
SECRET   = os.environ.get("JUDGE_SECRET", "dosarena-dev-secret-change-in-prod")
FLAG_TTL = int(os.environ.get("FLAG_TTL", "300"))

TARGETS = {
    "apache-vuln":      os.environ.get("TARGET_APACHE_VULN",      "10.0.2.20"),
    "apache-protected": os.environ.get("TARGET_APACHE_PROTECTED",  "10.0.3.20"),
    "nginx-protected":  os.environ.get("TARGET_NGINX_PROTECTED",   "10.0.3.21"),
    "dns-open":         os.environ.get("TARGET_DNS",               "10.0.2.30"),
    "ntp-vuln":         os.environ.get("TARGET_NTP",               "10.0.2.31"),
    "snmp-vuln":        os.environ.get("TARGET_SNMP",              "10.0.2.32"),
    "mysql-vuln":       os.environ.get("TARGET_MYSQL",             "10.0.2.40"),
    "postgres-vuln":    os.environ.get("TARGET_POSTGRES",          "10.0.2.41"),
    "fw-stateless":     os.environ.get("TARGET_FW_STATELESS",      "10.0.2.50"),
    "fw-stateful":      os.environ.get("TARGET_FW_STATEFUL",       "10.0.2.51"),
}

# ── Flag generation ──────────────────────────────────────────────────────────
def _window(ttl: int = FLAG_TTL) -> int:
    return int(time.time()) // ttl

def generate_flag(scenario_id: str, window: Optional[int] = None) -> str:
    w = window if window is not None else _window()
    payload = f"{scenario_id}:{w}".encode()
    sig = hmac.new(SECRET.encode(), payload, hashlib.sha256).hexdigest()[:24]
    return f"DOSARENA{{{scenario_id.upper()}_{sig}}}"

def verify_flag(scenario_id: str, flag: str) -> bool:
    cur = _window()
    for w in [cur, cur - 1]:
        if hmac.compare_digest(flag, generate_flag(scenario_id, w)):
            return True
    return False

# ── Docker stats (active-attack detection) ───────────────────────────────────
DOCKER_SOCK = "/var/run/docker.sock"
AMP_PPS_THRESHOLD = 50  # packets/sec on the reflector to count as an active attack

class _UnixSocketHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection that connects via a Unix domain socket instead of TCP."""
    def __init__(self, sock_path):
        super().__init__("localhost")
        self._sock_path = sock_path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(self._sock_path)
        self.sock = s

def _docker_stats_once(container_name: str) -> dict:
    """Return the raw stats dict from the Docker API for one container (stream=false)."""
    conn = _UnixSocketHTTPConnection(DOCKER_SOCK)
    try:
        conn.request("GET", f"/containers/{container_name}/stats?stream=false")
        resp = conn.getresponse()
        raw = resp.read()
        return json.loads(raw)
    finally:
        conn.close()

def get_container_established_count(container_name: str, port: int) -> int:
    """
    Count ESTABLISHED (state 01) TCP connections to the given port inside a container
    by exec-ing `cat /proc/net/tcp` via the Docker exec API over the Unix socket.

    The Docker exec API returns a multiplexed stream where each chunk is prefixed with
    an 8-byte header: [stream_type(1B), 0, 0, 0, size_big_endian(4B)], followed by
    `size` bytes of payload.  We reassemble all stdout chunks then scan each line.

    /proc/net/tcp columns (space-separated, 0-indexed):
      0: sl  1: local_address (ADDR:PORT hex)  2: rem_address  3: st (state hex)  ...
    Port is encoded big-endian in the hex field: port 80 = 0050, so we look for ":0050".
    State 01 = ESTABLISHED.

    Returns 0 on any error.
    """
    port_hex = f"{port:04X}"  # e.g. 80 -> "0050"
    try:
        conn = _UnixSocketHTTPConnection(DOCKER_SOCK)
        # Step 1: create exec instance
        body = json.dumps({
            "AttachStdout": True,
            "AttachStderr": False,
            "Cmd": ["cat", "/proc/net/tcp"],
        }).encode()
        conn.request(
            "POST",
            f"/containers/{container_name}/exec",
            body=body,
            headers={"Content-Type": "application/json", "Content-Length": str(len(body))},
        )
        resp = conn.getresponse()
        exec_info = json.loads(resp.read())
        exec_id = exec_info.get("Id", "")
        conn.close()

        # Step 2: start exec and read multiplexed stream
        conn = _UnixSocketHTTPConnection(DOCKER_SOCK)
        start_body = json.dumps({"Detach": False, "Tty": False}).encode()
        conn.request(
            "POST",
            f"/exec/{exec_id}/start",
            body=start_body,
            headers={"Content-Type": "application/json", "Content-Length": str(len(start_body))},
        )
        resp = conn.getresponse()
        raw = resp.read()
        conn.close()

        # Step 3: parse Docker multiplexed stream (8-byte header per chunk)
        stdout_data = b""
        offset = 0
        while offset + 8 <= len(raw):
            stream_type = raw[offset]
            size = int.from_bytes(raw[offset + 4: offset + 8], "big")
            payload = raw[offset + 8: offset + 8 + size]
            if stream_type == 1:  # stdout
                stdout_data += payload
            offset += 8 + size

        # Step 4: count ESTABLISHED connections to our port
        count = 0
        for line in stdout_data.decode("utf-8", errors="replace").splitlines():
            parts = line.split()
            # skip header line and any short/malformed lines
            if len(parts) < 4 or parts[0] == "sl":
                continue
            local_addr = parts[1]   # e.g. "00000000:0050"
            state      = parts[3]   # e.g. "01"
            if local_addr.endswith(f":{port_hex}") and state == "01":
                count += 1
        return count
    except Exception:
        return 0

def get_container_rx_pps(container_name: str) -> float:
    """
    Return received packets-per-second for the given container by taking two
    Docker stats readings 1 second apart and computing the delta.
    Returns 0.0 on any error (socket missing, container not found, etc.).
    """
    try:
        s1 = _docker_stats_once(container_name)
        time.sleep(1)
        s2 = _docker_stats_once(container_name)

        def _total_rx(stats: dict) -> int:
            nets = stats.get("networks", {})
            return sum(v.get("rx_packets", 0) for v in nets.values())

        rx1 = _total_rx(s1)
        rx2 = _total_rx(s2)
        return max(0.0, float(rx2 - rx1))
    except Exception:
        return 0.0

# ── Probes ───────────────────────────────────────────────────────────────────
@dataclass
class ProbeResult:
    target:      str
    scenario_id: str
    success:     bool
    detail:      str = ""
    latency_ms:  float = 0.0
    timestamp:   float = field(default_factory=time.time)
    def to_dict(self): return asdict(self)

async def probe_http(session, ip, sid, threshold_ms=3000, connect_ms=None):
    url = f"http://{ip}/"
    t0 = time.perf_counter()
    connect_timeout = (connect_ms / 1000) if connect_ms else (threshold_ms / 1000 + 0.5)
    try:
        async with session.get(url, timeout=ClientTimeout(total=threshold_ms/1000+0.5, connect=connect_timeout)) as r:
            lat = (time.perf_counter()-t0)*1000
            await r.read()
            if lat > threshold_ms:
                return ProbeResult(ip, sid, True, f"Response time {lat:.0f}ms > threshold", lat)
            if r.status in (503, 429, 500):
                return ProbeResult(ip, sid, True, f"HTTP {r.status}", lat)
            return ProbeResult(ip, sid, False, f"OK ({r.status}, {lat:.0f}ms)", lat)
    except asyncio.TimeoutError:
        return ProbeResult(ip, sid, True, f"Timeout after {threshold_ms:.0f}ms", threshold_ms)
    except ClientError as e:
        return ProbeResult(ip, sid, True, f"Connection error: {e}", 0)

async def probe_dns(ip, sid):
    # dosarena.local ANY — authoritative zone, no recursion needed
    query = b'\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x08dosarena\x05local\x00\x00\xff\x00\x01'
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.sendto(query, (ip, 53))
        try:
            data, _ = s.recvfrom(4096)
            amp_capable = len(data) > 50
            amp_factor  = len(data) // 30
        except socket.timeout:
            return ProbeResult(ip, sid, False, "DNS not responding to ANY")

        if not amp_capable:
            return ProbeResult(ip, sid, False, f"DNS response too small for amplification")

        # Gate: reflector must be receiving high traffic (active attack in progress)
        pps = get_container_rx_pps("dosarena_dns_open")
        if pps < AMP_PPS_THRESHOLD:
            return ProbeResult(ip, sid, False,
                f"Open resolver confirmed (~{amp_factor}x amp) but no active attack detected ({pps:.0f} pps < {AMP_PPS_THRESHOLD} threshold)")
        return ProbeResult(ip, sid, True,
            f"Open resolver: {len(data)}B response (~{amp_factor}x amp), attack active ({pps:.0f} pps)")
    except Exception as e:
        return ProbeResult(ip, sid, False, f"DNS error: {e}")

async def probe_ntp(ip, sid):
    payload = bytes([0x17,0x00,0x03,0x2a,0x00,0x00,0x00,0x00])
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.sendto(payload, (ip, 123))
        try:
            data, _ = s.recvfrom(4096)
            factor = len(data) / len(payload)
        except socket.timeout:
            return ProbeResult(ip, sid, False, "NTP monlist: no response")

        # Gate: reflector must be receiving high traffic (active attack in progress)
        pps = get_container_rx_pps("dosarena_ntp_vuln")
        if pps < AMP_PPS_THRESHOLD:
            return ProbeResult(ip, sid, False,
                f"NTP monlist confirmed ({len(data)}B, ~{factor:.0f}x) but no active attack detected ({pps:.0f} pps < {AMP_PPS_THRESHOLD} threshold)")
        return ProbeResult(ip, sid, True,
            f"monlist: {len(data)}B (~{factor:.0f}x), attack active ({pps:.0f} pps)")
    except Exception as e:
        return ProbeResult(ip, sid, False, f"NTP error: {e}")

async def probe_snmp(ip, sid):
    payload = bytes([
        0x30,0x26,0x02,0x01,0x01,0x04,0x06,0x70,0x75,0x62,0x6c,0x69,0x63,
        0xa5,0x19,0x02,0x04,0x00,0x00,0x00,0x01,0x02,0x01,0x00,0x02,0x01,
        0xff,0x30,0x0b,0x30,0x09,0x06,0x05,0x2b,0x06,0x01,0x02,0x01,0x05,0x00
    ])
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.sendto(payload, (ip, 161))
        try:
            data, _ = s.recvfrom(65535)
            factor = len(data) / len(payload)
        except socket.timeout:
            return ProbeResult(ip, sid, False, "SNMP: no response")

        # Gate: reflector must be receiving high traffic (active attack in progress)
        pps = get_container_rx_pps("dosarena_snmp_vuln")
        if pps < AMP_PPS_THRESHOLD:
            return ProbeResult(ip, sid, False,
                f"SNMP GetBulk confirmed ({len(data)}B, ~{factor:.0f}x) but no active attack detected ({pps:.0f} pps < {AMP_PPS_THRESHOLD} threshold)")
        return ProbeResult(ip, sid, True,
            f"GetBulk: {len(data)}B (~{factor:.0f}x), attack active ({pps:.0f} pps)")
    except Exception as e:
        return ProbeResult(ip, sid, False, f"SNMP error: {e}")

async def probe_db(ip, port, sid):
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=3)
        try:
            banner = await asyncio.wait_for(reader.read(256), timeout=1)
            writer.close()
            b = banner.decode("latin-1", errors="replace")
            if "Too many connections" in b or "max_connections" in b:
                return ProbeResult(ip, sid, True, f"Connection table full: {b[:60].strip()}")
            return ProbeResult(ip, sid, False, f"Accepting connections ({len(banner)}B banner)")
        except asyncio.TimeoutError:
            writer.close()
            return ProbeResult(ip, sid, True, "Connected but no banner — possible starvation")
    except (ConnectionRefusedError, OSError) as e:
        return ProbeResult(ip, sid, True, f"Refused: {e}")
    except asyncio.TimeoutError:
        return ProbeResult(ip, sid, True, "Timeout — starvation confirmed")

async def probe_syn_flood(ip):
    """Detect active SYN flood by measuring RX packet rate on the target container."""
    pps = get_container_rx_pps("dosarena_apache_vuln")
    if pps >= 1000:
        return ProbeResult(ip, "01", True, f"SYN flood detected ({pps:.0f} pps on target)", pps)
    return ProbeResult(ip, "01", False, f"No active SYN flood ({pps:.0f} pps < 1000 threshold)")

async def probe_slowloris(ip):
    """
    Detect an active Slowloris attack by counting ESTABLISHED TCP connections to port 80
    inside the dosarena_apache_vuln container via /proc/net/tcp.

    Slowloris holds many long-lived ESTABLISHED connections; a SYN flood produces
    SYN_RECV (state 03) entries instead, so the two attacks are unambiguous.

    Threshold: >= 50 ESTABLISHED connections to port 80 = attack confirmed.
    """
    count = get_container_established_count("dosarena_apache_vuln", 80)
    if count >= 50:
        return ProbeResult(ip, "02", True,
                           f"Slowloris: {count} ESTABLISHED connections")
    return ProbeResult(ip, "02", False,
                       f"No Slowloris ({count} ESTABLISHED < 50 threshold)")

# ── Scenarios ────────────────────────────────────────────────────────────────
SCENARIOS = {
    "01": {
        "name":       "SYN Flood — Break the Apache backlog",
        "target_key": "apache-vuln",
        "difficulty": "Easy", "points": 100,
        "probe": lambda s,ip: probe_syn_flood(ip),
    },
    "02": {
        "name":       "Slowloris — Fill the worker pool",
        "target_key": "apache-vuln",
        "difficulty": "Easy", "points": 100,
        "probe": lambda s,ip: probe_slowloris(ip),
    },
    "03": {
        "name":       "ACK Bypass — Stateless firewall proof",
        "target_key": "fw-stateless",
        "difficulty": "Medium", "points": 150,
        "probe": lambda s,ip: probe_http(s, ip, "03", 5000),
    },
    "04": {
        "name":       "DNS Amplification — Open resolver (~60x)",
        "target_key": "dns-open",
        "difficulty": "Easy", "points": 100,
        "probe": lambda s,ip: probe_dns(ip, "04"),
    },
    "05": {
        "name":       "NTP Amplification — monlist (~550x)",
        "target_key": "ntp-vuln",
        "difficulty": "Easy", "points": 100,
        "probe": lambda s,ip: probe_ntp(ip, "05"),
    },
    "06": {
        "name":       "SNMP Amplification — GetBulk (~650x)",
        "target_key": "snmp-vuln",
        "difficulty": "Medium", "points": 150,
        "probe": lambda s,ip: probe_snmp(ip, "06"),
    },
    "07": {
        "name":       "TCP Starvation — MySQL connection table",
        "target_key": "mysql-vuln",
        "difficulty": "Medium", "points": 150,
        "probe": lambda s,ip: probe_db(ip, 3306, "07"),
    },
    "08": {
        "name":       "Slow POST — RUDY body timeout abuse",
        "target_key": "apache-vuln",
        "difficulty": "Hard", "points": 200,
        "probe": lambda s,ip: probe_http(s, ip, "08", 2000),
    },
}

# ── State ─────────────────────────────────────────────────────────────────────
class ArenaState:
    def __init__(self):
        self.probes:  dict[str, ProbeResult] = {}
        self.scores:  dict[str, int]         = {}
        self.solves:  dict[str, list]        = {}
        self.flags:   dict[str, str]         = {}

    def update_probe(self, sid, result):
        self.probes[sid] = result
        if result.success:
            self.flags[sid] = generate_flag(sid)

    def submit(self, player, sid, flag):
        if sid not in SCENARIOS:
            return {"ok": False, "reason": "Unknown scenario"}
        if not verify_flag(sid, flag):
            return {"ok": False, "reason": "Invalid or expired flag"}
        r = self.probes.get(sid)
        if not r or not r.success:
            return {"ok": False, "reason": "Flag format correct but judge has not confirmed degradation yet. Keep the attack running."}
        if sid in self.solves.get(player, []):
            return {"ok": False, "reason": "Already solved"}
        pts = SCENARIOS[sid]["points"]
        self.scores[player] = self.scores.get(player, 0) + pts
        self.solves.setdefault(player, []).append(sid)
        return {"ok": True, "points": pts, "total": self.scores[player],
                "message": f"Correct! +{pts} pts. {SCENARIOS[sid]['name']} solved."}

    def status(self):
        return {
            "scenarios": {
                sid: {
                    "name":       s["name"],
                    "difficulty": s["difficulty"],
                    "points":     s["points"],
                    "target_ip":  TARGETS.get(s["target_key"], "?"),
                    "degraded":   self.probes.get(sid, ProbeResult("","",False)).success,
                    "detail":     self.probes.get(sid, ProbeResult("","","")).detail,
                }
                for sid, s in SCENARIOS.items()
            },
            "active_flags": {
                sid: flag for sid, flag in self.flags.items()
                if self.probes.get(sid, ProbeResult("","",False)).success
            },
        }

# ── Polling loop ──────────────────────────────────────────────────────────────
async def poll(state: ArenaState):
    while True:
        async with ClientSession(connector=TCPConnector(force_close=True)) as session:
            for sid, sc in SCENARIOS.items():
                ip = TARGETS.get(sc["target_key"])
                if not ip:
                    continue
                try:
                    r = await sc["probe"](session, ip)
                    state.update_probe(sid, r)
                except Exception as e:
                    state.probes[sid] = ProbeResult(ip, sid, False, f"Probe error: {e}")
        await asyncio.sleep(5)

# ── HTTP handlers ─────────────────────────────────────────────────────────────
async def h_status(req):
    return web.json_response(req.app["state"].status())

async def h_submit(req):
    state = req.app["state"]
    try:
        b = await req.json()
        r = state.submit(b.get("player","anonymous"), b.get("scenario",""), b.get("flag",""))
        return web.json_response(r, status=200 if r["ok"] else 400)
    except Exception as e:
        return web.json_response({"ok": False, "reason": str(e)}, status=400)

async def h_scoreboard(req):
    state = req.app["state"]
    board = sorted(
        [{"player": p, "score": s, "solves": state.solves.get(p, [])}
         for p, s in state.scores.items()],
        key=lambda x: x["score"], reverse=True
    )
    return web.json_response({"scoreboard": board})

async def h_hint(req):
    sid   = req.match_info.get("id", "")
    level = int(req.rel_url.query.get("level", "1"))
    if sid not in SCENARIOS:
        return web.json_response({"error": "Unknown scenario"}, status=404)
    from hints import HINTS
    hints = HINTS.get(sid, [])
    if level < 1 or level > len(hints):
        return web.json_response({"hint": None, "max_level": len(hints)})
    return web.json_response({"scenario": sid, "level": level, "hint": hints[level-1], "max_level": len(hints)})

async def h_writeup(req):
    sid = req.match_info.get("id", "")
    from writeups import WRITEUPS
    w = WRITEUPS.get(sid)
    if not w:
        return web.json_response({"error": "Not found or not yet unlocked"}, status=404)
    return web.json_response({"scenario": sid, **w})

async def h_health(req):
    return web.json_response({"status": "ok", "service": "DOSArena Judge"})

async def start_poll(app):
    app["task"] = asyncio.create_task(poll(app["state"]))

async def stop_poll(app):
    app["task"].cancel()
    try: await app["task"]
    except asyncio.CancelledError: pass

def make_app():
    app = web.Application()
    app["state"] = ArenaState()
    app.on_startup.append(start_poll)
    app.on_cleanup.append(stop_poll)
    app.router.add_get( "/",              lambda r: web.HTTPFound("/status"))
    app.router.add_get( "/status",       h_status)
    app.router.add_post("/submit",        h_submit)
    app.router.add_get( "/scoreboard",    h_scoreboard)
    app.router.add_get( "/hint/{id}",     h_hint)
    app.router.add_get( "/writeup/{id}",  h_writeup)
    app.router.add_get( "/health",        h_health)
    return app

if __name__ == "__main__":
    port = int(os.environ.get("JUDGE_PORT", "8888"))
    print(f"[*] DOSArena Judge — http://0.0.0.0:{port}")
    print(f"[*] Flag TTL: {FLAG_TTL}s")
    web.run_app(make_app(), port=port, print=None)
