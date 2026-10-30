"""Local split-DNS resolver (replaces dnsmasq on Windows).

* Domains from the dnsmasq-china-list are resolved by AliDNS (physical NIC).
* Everything else goes to resolvers whose IPs stay inside the VPN tunnel.
* Hardening equal to the macOS dnsmasq.conf: ``domain-needed``, ``bogus-priv``,
  ``stop-dns-rebind``, bounded concurrency and a TTL-aware cache.
"""

from __future__ import annotations

import ctypes
import http.client
import ipaddress
import logging
import random
import re
import socket
import ssl
import struct
import threading
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

log = logging.getLogger("zoog.dns")

RCODE_NOERROR = 0
RCODE_SERVFAIL = 2
RCODE_NXDOMAIN = 3
RCODE_NOTIMP = 4

QTYPE_A = 1
QTYPE_PTR = 12
QTYPE_AAAA = 28
QTYPE_OPT = 41

_DOMAIN_LINE = re.compile(r"^server=/([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*)/223\.5\.5\.5$")


def load_domain_file(path: Path, into: set[str]) -> int:
    """Strictly parse a ``server=/domain/223.5.5.5`` list (same rule as validate.sh)."""
    count = 0
    with open(path, encoding="utf-8") as handle:
        for number, raw in enumerate(handle, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            match = _DOMAIN_LINE.match(line)
            if not match:
                raise ValueError(f"{path}:{number}: unexpected directive: {line[:80]!r}")
            into.add(match.group(1).lower())
            count += 1
    return count


def load_cn_domains(paths: list[Path]) -> set[str]:
    domains: set[str] = set()
    for path in paths:
        load_domain_file(path, domains)
    return domains


# --------------------------------------------------------------------------- #
# DNS wire format helpers
# --------------------------------------------------------------------------- #

class Query:
    __slots__ = ("id", "flags", "name", "qtype", "qclass", "end")

    def __init__(self, qid: int, flags: int, name: str, qtype: int, qclass: int, end: int) -> None:
        self.id = qid
        self.flags = flags
        self.name = name
        self.qtype = qtype
        self.qclass = qclass
        self.end = end


def read_name(pkt: bytes, off: int) -> tuple[str, int]:
    labels: list[str] = []
    end: int | None = None
    hops = 0
    while True:
        if off >= len(pkt):
            raise ValueError("name out of bounds")
        length = pkt[off]
        if length == 0:
            off += 1
            break
        if length & 0xC0 == 0xC0:
            if off + 1 >= len(pkt):
                raise ValueError("bad pointer")
            if end is None:
                end = off + 2
            off = ((length & 0x3F) << 8) | pkt[off + 1]
            hops += 1
            if hops > 20:
                raise ValueError("pointer loop")
            continue
        if length & 0xC0:
            raise ValueError("bad label")
        off += 1
        if off + length > len(pkt):
            raise ValueError("label out of bounds")
        labels.append(pkt[off : off + length].decode("ascii", "replace"))
        off += length
    return ".".join(labels), (end if end is not None else off)


def parse_query(pkt: bytes) -> Query | None:
    if len(pkt) < 12:
        return None
    qid, flags, qdcount = struct.unpack("!HHH", pkt[:6])
    if flags & 0x8000 or qdcount != 1:
        return None
    try:
        name, off = read_name(pkt, 12)
        qtype, qclass = struct.unpack("!HH", pkt[off : off + 4])
    except (ValueError, struct.error):
        return None
    return Query(qid, flags, name, qtype, qclass, off + 4)


def _iter_records(pkt: bytes, off: int, count: int):
    for _ in range(count):
        _, off = read_name(pkt, off)
        rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", pkt[off : off + 10])
        off += 10
        if off + rdlen > len(pkt):
            raise ValueError("rdata out of bounds")
        yield rtype, rclass, ttl, off, rdlen
        off += rdlen


def _skip_questions(pkt: bytes, qdcount: int) -> int:
    off = 12
    for _ in range(qdcount):
        _, off = read_name(pkt, off)
        off += 4
    return off


def response_info(pkt: bytes) -> tuple[int, int | None, list[bytes]]:
    """(rcode, minimum TTL of answers, raw A/AAAA rdata of the answer section)."""
    if len(pkt) < 12:
        raise ValueError("short packet")
    flags = struct.unpack("!H", pkt[2:4])[0]
    qd, an, ns, ar = struct.unpack("!HHHH", pkt[4:12])
    off = _skip_questions(pkt, qd)
    addresses: list[bytes] = []
    ttls: list[int] = []
    for index, (rtype, _rc, ttl, roff, rdlen) in enumerate(_iter_records(pkt, off, an + ns + ar)):
        if rtype == QTYPE_OPT:
            continue
        if index < an + ns:
            ttls.append(ttl)
        if index < an:
            if rtype == QTYPE_A and rdlen == 4:
                addresses.append(pkt[roff : roff + 4])
            elif rtype == QTYPE_AAAA and rdlen == 16:
                addresses.append(pkt[roff : roff + 16])
    return flags & 0x000F, (min(ttls) if ttls else None), addresses


def edns_udp_size(pkt: bytes) -> int:
    """UDP payload size advertised by the client (512 without EDNS)."""
    try:
        qd, an, ns, ar = struct.unpack("!HHHH", pkt[4:12])
        off = _skip_questions(pkt, qd)
        for index, (rtype, rclass, _t, _o, _l) in enumerate(_iter_records(pkt, off, an + ns + ar)):
            if rtype == QTYPE_OPT and index >= an + ns:
                return max(512, rclass)
    except (ValueError, struct.error):
        pass
    return 512


def make_error(pkt: bytes, query: Query, rcode: int, truncated: bool = False) -> bytes:
    flags = 0x8000 | (query.flags & 0x7800) | (query.flags & 0x0100) | 0x0080 | rcode
    if truncated:
        flags |= 0x0200
    header = struct.pack("!HHHHHH", query.id, flags, 1, 0, 0, 0)
    return header + pkt[12 : query.end]


def make_truncated(response: bytes, query: Query) -> bytes:
    flags = (struct.unpack("!H", response[2:4])[0] | 0x0200)
    header = struct.pack("!HHHHHH", query.id, flags, 1, 0, 0, 0)
    return header + response[12 : query.end]


def build_query(name: str, qtype: int = QTYPE_A, qid: int | None = None) -> bytes:
    qid = random.getrandbits(16) if qid is None else qid
    question = b"".join(
        bytes([len(label)]) + label.encode("ascii") for label in name.rstrip(".").split(".")
    ) + b"\x00"
    return struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + question + struct.pack("!HH", qtype, 1)


def _is_rebind_address(raw: bytes) -> bool:
    try:
        address = ipaddress.ip_address(raw)
    except ValueError:
        return True
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_unspecified
    ) and not address.is_global


_PRIVATE_PTR = re.compile(
    r"(^|\.)(10|127|254\.169|168\.192|(1[6-9]|2[0-9]|3[01])\.172)\.in-addr\.arpa$", re.I
)


# --------------------------------------------------------------------------- #
# Resolver
# --------------------------------------------------------------------------- #

class DohUpstream:
    """DNS-over-HTTPS upstream (RFC 8484, POST) using a per-thread keep-alive connection.

    Used by the optional compatibility mode: it reaches AliDNS over ordinary HTTPS (443)
    when plain port-53 traffic leaving the physical NIC is blocked on the machine.
    """

    def __init__(self, host: str, path: str = "/dns-query", port: int = 443,
                 timeout: float = 3.0, use_tls: bool = True) -> None:
        self.host = host
        self.path = path
        self.port = port
        self.timeout = timeout
        self.use_tls = use_tls
        self._local = threading.local()
        self._context = ssl.create_default_context() if use_tls else None

    def __repr__(self) -> str:
        return f"DohUpstream({self.host}:{self.port}{self.path})"

    def _connection(self) -> http.client.HTTPConnection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            if self.use_tls:
                conn = http.client.HTTPSConnection(
                    self.host, self.port, timeout=self.timeout, context=self._context
                )
            else:
                conn = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
            self._local.conn = conn
        return conn

    def _drop(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                conn.close()
            except OSError:
                pass
        self._local.conn = None

    def query(self, pkt: bytes) -> bytes | None:
        original_id = pkt[:2]
        body = b"\x00\x00" + pkt[2:]  # RFC 8484: use ID 0 on the wire
        headers = {"Content-Type": "application/dns-message", "Accept": "application/dns-message"}
        for _attempt in range(2):  # a stale keep-alive connection gets one retry
            try:
                conn = self._connection()
                conn.request("POST", self.path, body=body, headers=headers)
                response = conn.getresponse()
                data = response.read()
            except (OSError, http.client.HTTPException):
                self._drop()
                continue
            if response.status != 200 or len(data) < 12:
                self._drop()
                return None
            return original_id + data[2:]
        return None


class Resolver:
    def __init__(
        self,
        cn_domains: set[str],
        cn_upstreams,
        foreign_upstreams,
        timeout: float = 2.0,
        cache_size: int = 10000,
    ) -> None:
        self.cn_domains = cn_domains
        self.cn_upstreams = tuple(cn_upstreams)
        self.foreign_upstreams = tuple(foreign_upstreams)
        self.timeout = timeout
        self.cache_size = cache_size
        self._cache: OrderedDict[tuple, tuple[float, bytes]] = OrderedDict()
        self._lock = threading.Lock()

    def is_cn(self, name: str) -> bool:
        labels = name.rstrip(".").lower().split(".")
        return any(".".join(labels[i:]) in self.cn_domains for i in range(len(labels)))

    def upstreams_for(self, name: str):
        return self.cn_upstreams if self.is_cn(name) else self.foreign_upstreams

    # -- cache -------------------------------------------------------------
    def _cache_get(self, key: tuple, qid: int) -> bytes | None:
        with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            expires, data = entry
            if expires < time.monotonic():
                del self._cache[key]
                return None
            self._cache.move_to_end(key)
        return struct.pack("!H", qid) + data[2:]

    def _cache_put(self, key: tuple, data: bytes, ttl: int) -> None:
        if ttl <= 0 or self.cache_size <= 0:
            return
        with self._lock:
            self._cache[key] = (time.monotonic() + ttl, data)
            self._cache.move_to_end(key)
            while len(self._cache) > self.cache_size:
                self._cache.popitem(last=False)

    # -- upstream I/O ------------------------------------------------------
    def _udp(self, pkt: bytes, upstream) -> bytes | None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            deadline = time.monotonic() + self.timeout
            sock.sendto(pkt, upstream)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                sock.settimeout(remaining)
                data, addr = sock.recvfrom(65535)
                if addr[0] == upstream[0] and addr[1] == upstream[1] and data[:2] == pkt[:2]:
                    return data
        except OSError:
            return None
        finally:
            sock.close()

    def _tcp(self, pkt: bytes, upstream) -> bytes | None:
        try:
            with socket.create_connection(upstream, timeout=self.timeout) as sock:
                sock.settimeout(self.timeout)
                sock.sendall(struct.pack("!H", len(pkt)) + pkt)
                header = _recv_exact(sock, 2)
                data = _recv_exact(sock, struct.unpack("!H", header)[0])
                return data if data[:2] == pkt[:2] else None
        except (OSError, struct.error):
            return None

    def _forward(self, pkt: bytes, upstreams) -> bytes | None:
        for upstream in upstreams:
            if isinstance(upstream, DohUpstream):
                data = upstream.query(pkt)
                if data is not None:
                    return data
                continue
            data = self._udp(pkt, upstream)
            if data is not None and len(data) >= 12 and data[2] & 0x02:  # TC bit
                data = self._tcp(pkt, upstream) or data
            if data is not None:
                return data
        return None

    # -- main entry --------------------------------------------------------
    def resolve(self, pkt: bytes) -> bytes | None:
        """Return the response for ``pkt`` (None = drop the query)."""
        query = parse_query(pkt)
        if query is None:
            return None
        if (query.flags >> 11) & 0xF != 0:
            return make_error(pkt, query, RCODE_NOTIMP)

        name = query.name.lower()
        if "." not in name and name:  # domain-needed
            return make_error(pkt, query, RCODE_NXDOMAIN)
        if query.qtype == QTYPE_PTR and _PRIVATE_PTR.search(name):  # bogus-priv
            return make_error(pkt, query, RCODE_NXDOMAIN)

        key = (name, query.qtype, query.qclass)
        cached = self._cache_get(key, query.id)
        if cached is not None:
            return cached

        response = self._forward(pkt, self.upstreams_for(name))
        if response is None:
            return make_error(pkt, query, RCODE_SERVFAIL)
        try:
            rcode, ttl, addresses = response_info(response)
        except (ValueError, struct.error):
            return make_error(pkt, query, RCODE_SERVFAIL)

        if name != "localhost" and any(_is_rebind_address(a) for a in addresses):
            log.warning("stop-dns-rebind: dropped private answer for %s", name)
            return make_error(pkt, query, RCODE_SERVFAIL)

        if rcode == RCODE_NOERROR and ttl is not None:
            self._cache_put(key, response, min(ttl, 300))
        elif rcode == RCODE_NXDOMAIN:
            self._cache_put(key, response, 60)
        return response


def _disable_udp_connreset(sock: socket.socket) -> None:
    """Stop Windows from raising WSAECONNRESET on UDP sockets after ICMP port-unreachable."""
    if not hasattr(ctypes, "WinDLL"):
        return
    try:
        returned = ctypes.c_ulong(0)
        flag = ctypes.c_ulong(0)
        ctypes.WinDLL("ws2_32").WSAIoctl(
            ctypes.c_size_t(sock.fileno()), 0x9800000C,  # SIO_UDP_CONNRESET
            ctypes.byref(flag), 4, None, 0, ctypes.byref(returned), None, None,
        )
    except (OSError, AttributeError):
        pass


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = []
    while size > 0:
        chunk = sock.recv(size)
        if not chunk:
            raise OSError("connection closed")
        chunks.append(chunk)
        size -= len(chunk)
    return b"".join(chunks)


# --------------------------------------------------------------------------- #
# Server
# --------------------------------------------------------------------------- #

class DnsProxy:
    """UDP + TCP listener bound to a single loopback address."""

    def __init__(self, resolver: Resolver, host: str = "127.0.0.1", port: int = 53,
                 max_inflight: int = 300, allowed_sources: set[str] | None = None) -> None:
        self.resolver = resolver
        self.host = host
        self.port = port
        self.allowed_sources = allowed_sources
        self._slots = threading.BoundedSemaphore(max_inflight)
        self._pool = ThreadPoolExecutor(max_workers=min(max_inflight, 64), thread_name_prefix="dns")
        self._stop = threading.Event()
        self._udp: socket.socket | None = None
        self._tcp: socket.socket | None = None
        self._threads: list[threading.Thread] = []

    @property
    def running(self) -> bool:
        return self._udp is not None and not self._stop.is_set()

    @property
    def udp_port(self) -> int:
        assert self._udp is not None
        return self._udp.getsockname()[1]

    @property
    def tcp_port(self) -> int:
        assert self._tcp is not None
        return self._tcp.getsockname()[1]

    def start(self) -> None:
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            udp.bind((self.host, self.port))
            tcp.bind((self.host, self.port if self.port else udp.getsockname()[1]))
            tcp.listen(64)
        except OSError:
            udp.close()
            tcp.close()
            raise
        if hasattr(socket, "SIO_UDP_CONNRESET"):
            try:
                udp.ioctl(socket.SIO_UDP_CONNRESET, False)  # type: ignore[attr-defined]
            except OSError:
                pass
        _disable_udp_connreset(udp)
        udp.settimeout(0.5)
        tcp.settimeout(0.5)
        self._udp, self._tcp = udp, tcp
        self._stop.clear()
        for target in (self._udp_loop, self._tcp_loop):
            thread = threading.Thread(target=target, daemon=True)
            thread.start()
            self._threads.append(thread)

    def stop(self) -> None:
        self._stop.set()
        for sock in (self._udp, self._tcp):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        self._udp = self._tcp = None
        self._pool.shutdown(wait=False, cancel_futures=True)

    # -- UDP ---------------------------------------------------------------
    def _udp_loop(self) -> None:
        sock = self._udp
        while not self._stop.is_set() and sock is not None:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    return
                time.sleep(0.05)
                continue
            if self.allowed_sources is not None and addr[0] not in self.allowed_sources:
                continue  # not a local client
            if self._slots.acquire(blocking=False):
                try:
                    self._pool.submit(self._handle_udp, sock, data, addr)
                except RuntimeError:
                    self._slots.release()
                    return

    def _handle_udp(self, sock: socket.socket, data: bytes, addr) -> None:
        try:
            response = self.resolver.resolve(data)
            if response is None:
                return
            if len(response) > edns_udp_size(data):
                query = parse_query(data)
                if query is not None:
                    response = make_truncated(response, query)
            sock.sendto(response, addr)
        except OSError:
            pass
        except Exception:  # never let a worker die silently
            log.exception("udp handler failed")
        finally:
            self._slots.release()

    # -- TCP ---------------------------------------------------------------
    def _tcp_loop(self) -> None:
        sock = self._tcp
        while not self._stop.is_set() and sock is not None:
            try:
                conn, peer = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    return
                time.sleep(0.05)
                continue
            if self.allowed_sources is not None and peer[0] not in self.allowed_sources:
                conn.close()
                continue
            if self._slots.acquire(blocking=False):
                try:
                    self._pool.submit(self._handle_tcp, conn)
                except RuntimeError:
                    self._slots.release()
                    conn.close()
                    return
            else:
                conn.close()

    def _handle_tcp(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(5.0)
            while not self._stop.is_set():
                try:
                    header = _recv_exact(conn, 2)
                except OSError:
                    return
                data = _recv_exact(conn, struct.unpack("!H", header)[0])
                response = self.resolver.resolve(data)
                if response is None:
                    return
                conn.sendall(struct.pack("!H", len(response)) + response)
        except (OSError, struct.error):
            pass
        except Exception:
            log.exception("tcp handler failed")
        finally:
            try:
                conn.close()
            finally:
                self._slots.release()


# --------------------------------------------------------------------------- #
# Client helper (self-check and `status`)
# --------------------------------------------------------------------------- #

def query_a(name: str, server: tuple[str, int] = ("127.0.0.1", 53), timeout: float = 2.0) -> list[str]:
    """Resolve ``name`` through ``server`` and return its IPv4 answers."""
    pkt = build_query(name, QTYPE_A)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(pkt, server)
        data, _ = sock.recvfrom(65535)
    except OSError:
        return []
    finally:
        sock.close()
    if data[:2] != pkt[:2]:
        return []
    try:
        rcode, _ttl, addresses = response_info(data)
    except (ValueError, struct.error):
        return []
    if rcode != RCODE_NOERROR:
        return []
    return [socket.inet_ntoa(a) for a in addresses if len(a) == 4]
