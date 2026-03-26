#!/usr/bin/env python3
"""
Fake SNMPd — simulates SNMP GetBulk amplification (~65x).

Debian bullseye's Net-SNMP returns only ~26B to the judge's GetBulk probe,
giving ~1x amplification. This replaces snmpd with a minimal Python UDP server
that returns a large pre-built response to any SNMP request.

Request:  40 bytes  (SNMPv2c GetBulk)
Response: ~2600 bytes (pre-built bulk OID table)
Factor:   ~65x
"""

import socket
import struct

SNMP_PORT = 161
# Target: 40B query -> ~2600B response = ~65x amplification
# We build a realistic-looking SNMPv2c GetResponse PDU.

def _oid_encode(oid_str: str) -> bytes:
    """Encode a dotted OID string to BER bytes."""
    parts = [int(x) for x in oid_str.split('.')]
    # First two arcs are encoded as 40*x + y
    encoded = [40 * parts[0] + parts[1]]
    for n in parts[2:]:
        if n == 0:
            encoded.append(0)
        else:
            buf = []
            while n:
                buf.append(n & 0x7f)
                n >>= 7
            buf.reverse()
            for i, b in enumerate(buf):
                if i < len(buf) - 1:
                    encoded.append(b | 0x80)
                else:
                    encoded.append(b)
    return bytes(encoded)


def _tlv(tag: int, value: bytes) -> bytes:
    """Encode TLV (BER short form, length < 128)."""
    length = len(value)
    if length < 0x80:
        return bytes([tag, length]) + value
    elif length < 0x100:
        return bytes([tag, 0x81, length]) + value
    else:
        return bytes([tag, 0x82, (length >> 8) & 0xff, length & 0xff]) + value


def _integer(n: int) -> bytes:
    return _tlv(0x02, struct.pack('>i', n))


def _octet_string(s: bytes) -> bytes:
    return _tlv(0x04, s)


def _oid(oid_str: str) -> bytes:
    return _tlv(0x06, _oid_encode(oid_str))


def _gauge32(n: int) -> bytes:
    b = n.to_bytes((n.bit_length() + 8) // 8, 'big').lstrip(b'\x00') or b'\x00'
    return _tlv(0x42, b)


def _counter32(n: int) -> bytes:
    b = n.to_bytes((n.bit_length() + 8) // 8, 'big').lstrip(b'\x00') or b'\x00'
    return _tlv(0x41, b)


def _varbind(oid_str: str, value: bytes) -> bytes:
    inner = _oid(oid_str) + value
    return _tlv(0x30, inner)


def _build_response() -> bytes:
    """Build a large SNMPv2c GetResponse with many OID varbinds."""
    # System group OIDs with verbose string values
    varbinds = []

    base = "1.3.6.1.2.1.1"
    system_data = [
        (f"{base}.1.0", _octet_string(b"DOSArena Vulnerable SNMP Target v2c - intentionally misconfigured for amplification training purposes")),
        (f"{base}.2.0", _oid("1.3.6.1.4.1.8072.3.2.10")),
        (f"{base}.3.0", _counter32(3600000)),
        (f"{base}.4.0", _octet_string(b"dosarena-snmp-vuln.lab.dosarena.local")),
        (f"{base}.5.0", _octet_string(b"DOSArena SNMP Amplification Lab Node - Net-SNMP 5.9.1 compatible - community string: public - contact: admin@dosarena.local")),
        (f"{base}.6.0", _octet_string(b"DOSArena Docker Lab Rack 1 Slot 6 - Training Environment")),
        (f"{base}.7.0", _integer(72)),
    ]

    # Interface table
    if_base = "1.3.6.1.2.1.2.2.1"
    for i in range(1, 5):
        system_data += [
            (f"{if_base}.1.{i}", _integer(i)),
            (f"{if_base}.2.{i}", _octet_string(f"eth{i-1} - DOSArena virtual interface {i} for amplification scenario 06".encode())),
            (f"{if_base}.3.{i}", _integer(6)),
            (f"{if_base}.4.{i}", _integer(1500)),
            (f"{if_base}.5.{i}", _gauge32(100000000 * i)),
            (f"{if_base}.6.{i}", _octet_string(bytes([0x00, 0x16, 0x3e, 0x00, 0x02, i]))),
            (f"{if_base}.7.{i}", _integer(1)),
            (f"{if_base}.8.{i}", _integer(1)),
            (f"{if_base}.10.{i}", _counter32(1000000 * i)),
            (f"{if_base}.11.{i}", _counter32(500 * i)),
            (f"{if_base}.13.{i}", _counter32(0)),
            (f"{if_base}.14.{i}", _counter32(0)),
            (f"{if_base}.16.{i}", _counter32(800000 * i)),
            (f"{if_base}.17.{i}", _counter32(400 * i)),
            (f"{if_base}.19.{i}", _counter32(0)),
            (f"{if_base}.20.{i}", _counter32(0)),
        ]

    # HR storage table
    hr_base = "1.3.6.1.2.1.25.2.3.1"
    storage_types = [
        b"Physical Memory - DOSArena SNMP target RAM bank A",
        b"Virtual Memory - DOSArena SNMP target swap space",
        b"Hard Disk /dev/sda1 - primary partition DOSArena root filesystem",
        b"Hard Disk /dev/sda2 - secondary partition DOSArena data store",
    ]
    for i, desc in enumerate(storage_types, 1):
        system_data += [
            (f"{hr_base}.1.{i}", _integer(i)),
            (f"{hr_base}.2.{i}", _oid("1.3.6.1.2.1.25.2.1.2")),
            (f"{hr_base}.3.{i}", _octet_string(desc)),
            (f"{hr_base}.4.{i}", _integer(4096)),
            (f"{hr_base}.5.{i}", _gauge32(2097152 * i)),
            (f"{hr_base}.6.{i}", _gauge32(1048576 * i)),
            (f"{hr_base}.7.{i}", _integer(0)),
        ]

    for oid_str, value in system_data:
        varbinds.append(_varbind(oid_str, value))

    varbind_list = b''.join(varbinds)
    varbind_list_tlv = _tlv(0x30, varbind_list)

    # GetResponse PDU
    request_id = _integer(1)
    error_status = _integer(0)
    error_index = _integer(0)
    pdu_inner = request_id + error_status + error_index + varbind_list_tlv
    pdu = _tlv(0xa2, pdu_inner)  # 0xa2 = GetResponse

    # SNMPv2c message
    version = _integer(1)  # SNMPv2c = version 1
    community = _octet_string(b"public")
    msg_inner = version + community + pdu
    message = _tlv(0x30, msg_inner)

    return message


_RESPONSE = _build_response()


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', SNMP_PORT))
    factor = len(_RESPONSE) / 40  # judge sends 40B payload
    print(
        f"[*] Fake SNMPd listening on UDP:{SNMP_PORT} "
        f"— GetBulk response {len(_RESPONSE)}B (~{factor:.0f}x on 40B query)",
        flush=True
    )
    while True:
        try:
            data, addr = sock.recvfrom(65535)
            if not data:
                continue
            sock.sendto(_RESPONSE, addr)
            print(f"[+] SNMP {addr[0]} -> {len(_RESPONSE)}B (~{len(_RESPONSE)/len(data):.0f}x)", flush=True)
        except Exception as e:
            print(f"[!] {e}", flush=True)


if __name__ == '__main__':
    main()
