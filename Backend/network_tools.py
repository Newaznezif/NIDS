"""Network analysis utilities.

DNS lookups are performed for real using a minimal dependency-free DNS client
over UDP (stdlib socket + struct). Reverse DNS uses the OS resolver. CIDR
math is calculated locally. An SSRF guard protects any server-side fetch by
rejecting non-http(s) schemes and private/loopback/link-local destinations.
"""
import ipaddress
import socket
import struct
import random
from urllib.parse import urlparse

DNS_TIMEOUT = 4.0

QTYPES = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28, "PTR": 12}


class DnsError(Exception):
    pass


def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("idna") if label else b""
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def _parse_name(data: bytes, offset: int) -> tuple:
    labels = []
    jumped = False
    original_next = None
    while True:
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            pointer = struct.unpack("!H", data[offset:offset + 2])[0] & 0x3FFF
            if not jumped:
                original_next = offset + 2
            offset = pointer
            jumped = True
            continue
        labels.append(data[offset + 1:offset + 1 + length].decode("utf-8", errors="replace"))
        offset += 1 + length
    next_offset = original_next if jumped else offset
    return ".".join(labels), next_offset


def dns_query(name: str, qtype: str = "A", server: str = "8.8.8.8", timeout: float = DNS_TIMEOUT):
    """Issue a real DNS query and return a list of record value strings."""
    if qtype not in QTYPES:
        raise DnsError(f"Unsupported qtype {qtype}")
    tid = random.randint(0, 0xFFFF)
    header = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    question = _encode_name(name) + struct.pack("!HH", QTYPES[qtype], 1)
    packet = header + question

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (server, 53))
        data, _ = sock.recvfrom(4096)
    except socket.timeout:
        raise DnsError(f"DNS query timed out against {server}")
    except OSError as e:
        raise DnsError(f"DNS query failed: {e}")
    finally:
        sock.close()

    if len(data) < 12:
        raise DnsError("Truncated DNS response")
    r_tid, _flags, _qd, ancount, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
    if r_tid != tid:
        raise DnsError("DNS response id mismatch")

    offset = 12
    for _ in range(_qd):
        _, offset = _parse_name(data, offset)
        offset += 4

    results = []
    for _ in range(ancount):
        _name, offset = _parse_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlen]
        offset += rdlen
        try:
            if rtype == QTYPES["A"] and rdlen == 4:
                results.append(socket.inet_ntoa(rdata))
            elif rtype == QTYPES["AAAA"] and rdlen == 16:
                results.append(socket.inet_ntop(socket.AF_INET6, rdata))
            elif rtype in (QTYPES["NS"], QTYPES["CNAME"], QTYPES["PTR"]):
                val, _ = _parse_name(data, offset - rdlen)
                results.append(val)
            elif rtype == QTYPES["MX"]:
                pref = struct.unpack("!H", rdata[:2])[0]
                val, _ = _parse_name(data, offset - rdlen + 2)
                results.append(f"{pref} {val}")
            elif rtype == QTYPES["TXT"]:
                pos = 0
                parts = []
                while pos < rdlen:
                    ln = rdata[pos]
                    parts.append(rdata[pos + 1:pos + 1 + ln].decode("utf-8", errors="replace"))
                    pos += 1 + ln
                results.append("".join(parts))
        except Exception:
            continue
    return results


def resolve_a(name: str, server: str = "8.8.8.8"):
    return dns_query(name, "A", server)


def resolve_aaaa(name: str, server: str = "8.8.8.8"):
    return dns_query(name, "AAAA", server)


def reverse_dns(ip: str):
    """Real reverse lookup via the OS resolver. Returns [] when no PTR exists."""
    try:
        host = socket.gethostbyaddr(ip)
        return [host[0]]
    except (socket.herror, socket.gaierror, OSError):
        return []


def cidr_analysis(cidr: str) -> dict:
    """Local CIDR calculations. Provenance: CALCULATED."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except (ValueError, TypeError) as e:
        return {"valid": False, "error": f"Invalid CIDR or network: {e}"}
    hosts = list(net.hosts()) if net.num_addresses <= 65536 else []
    return {
        "valid": True,
        "network": str(net.network_address),
        "netmask": str(net.netmask),
        "prefixlen": net.prefixlen,
        "version": net.version,
        "num_addresses": net.num_addresses,
        "first_host": str(hosts[0]) if hosts else str(net.network_address),
        "last_host": str(hosts[-1]) if hosts else str(net.broadcast_address or net.network_address),
        "broadcast": str(net.broadcast_address) if net.version == 4 else None,
        "is_private": net.is_private,
        "sample_hosts": [str(h) for h in hosts[:10]],
        "provenance": "CALCULATED",
    }


def ssrf_check(url: str) -> tuple:
    """Validate a URL before any server-side fetch. Returns (ok, reason)."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return False, "Unparseable URL"
    if parsed.scheme not in ("http", "https"):
        return False, f"Scheme '{parsed.scheme}' not permitted (http/https only)"
    host = parsed.hostname
    if not host:
        return False, "No host in URL"
    try:
        addr = ipaddress.ip_address(host)
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved:
            return False, "Destination resolves to a private/loopback/link-local address"
    except ValueError:
        # Hostname (not literal IP): resolve and check every address.
        try:
            infos = socket.getaddrinfo(host, None)
        except socket.gaierror:
            return False, "Host does not resolve"
        for info in infos:
            ip = info[4][0]
            try:
                a = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_reserved:
                return False, f"Host resolves to non-public address {ip}"
    return True, ""
