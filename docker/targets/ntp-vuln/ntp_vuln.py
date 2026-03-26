#!/usr/bin/env python3
"""
Fake NTPd — simulates NTP monlist (mode 7, request code 42) amplification.

Debian's ntp package for bullseye has mode 7 compiled out (post CVE-2013-5211
patch). This replaces ntpd entirely with a minimal Python UDP server that:
  - Responds to monlist requests with a large payload (~550x amplification)
  - Responds to regular NTP client queries (mode 3) with a valid server reply

Request:  8 bytes  (mode 7, code 42)
Response: ~4400 bytes (60 fake client records x 72 bytes + header)
Factor:   ~550x
"""

import socket
import struct
import time

NTP_PORT = 123
FAKE_RECORDS = 60  # 60 x 72B = 4320B + 8B header = 4328B -> ~541x on 8B query


def make_fake_record(i: int) -> bytes:
    src_ip   = struct.pack(">I", 0x0A000200 + (i % 254) + 1)  # 10.0.2.x
    dst_ip   = struct.pack(">I", 0x0A00021F)                   # 10.0.2.31
    flags    = struct.pack(">I", 0x00000001)
    last_ts  = struct.pack(">Q", int(time.time()) - i * 10)
    first_ts = struct.pack(">Q", int(time.time()) - i * 300)
    count    = struct.pack(">I", i * 50 + 1)
    padding  = b'\x00' * (72 - 4 - 4 - 4 - 8 - 8 - 4)
    return src_ip + dst_ip + flags + last_ts + first_ts + count + padding


# Pre-build response once at startup
_RECORDS = b''.join(make_fake_record(i) for i in range(FAKE_RECORDS))
_MONLIST_RESP = bytes([
    0x97,          # R=1 M=0 VN=2 Mode=7 (response)
    0x80,          # authenticated
    0x00,          # seq
    0x2a,          # MON_GETLIST_1 = 42
    0x00, FAKE_RECORDS & 0xFF,  # err=0, nItems
    0x00,          # mbz
    72,            # item size
]) + _RECORDS

# Minimal NTP server reply for mode-3 (client) queries — 48 bytes
_NTP_SERVER_REPLY = bytearray(48)
_NTP_SERVER_REPLY[0] = 0x24   # LI=0 VN=4 Mode=4 (server)
_NTP_SERVER_REPLY[1] = 1      # stratum 1
_NTP_SERVER_REPLY[2] = 6      # poll interval
_NTP_SERVER_REPLY[3] = 0xEC   # precision
_NTP_SERVER_REPLY = bytes(_NTP_SERVER_REPLY)


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', NTP_PORT))
    factor = len(_MONLIST_RESP) / 8
    print(
        f"[*] Fake NTPd monlist listening on UDP:{NTP_PORT} "
        f"— monlist response {len(_MONLIST_RESP)}B (~{factor:.0f}x)",
        flush=True
    )
    while True:
        try:
            data, addr = sock.recvfrom(1024)
            if not data:
                continue
            mode = data[0] & 0x07
            if mode == 7 and len(data) >= 4 and data[3] == 0x2a:
                sock.sendto(_MONLIST_RESP, addr)
                print(f"[+] monlist {addr[0]} -> {len(_MONLIST_RESP)}B", flush=True)
            elif mode == 3:
                sock.sendto(_NTP_SERVER_REPLY, addr)
        except Exception as e:
            print(f"[!] {e}", flush=True)


if __name__ == '__main__':
    main()
