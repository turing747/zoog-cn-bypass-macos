"""DNS wire format, domain matching and end-to-end split behaviour with fake upstreams."""

import socket
import struct
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from zoog_cn_bypass import dnsproxy as d  # noqa: E402


def a_response(pkt: bytes, address: str, ttl: int = 60, rcode: int = 0, truncated: bool = False) -> bytes:
    query = d.parse_query(pkt)
    assert query is not None
    flags = 0x8180 | rcode | (0x0200 if truncated else 0)
    question = pkt[12 : query.end]
    if rcode:
        return struct.pack("!HHHHHH", query.id, flags, 1, 0, 0, 0) + question
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, ttl, 4) + socket.inet_aton(address)
    return struct.pack("!HHHHHH", query.id, flags, 1, 1, 0, 0) + question + answer


class FakeUpstream:
    """UDP (+optional TCP) DNS server answering every A query with a fixed address."""

    def __init__(self, address: str, truncate_udp: bool = False):
        self.address = address
        self.truncate_udp = truncate_udp
        self.queries: list[str] = []
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", 0))
        self.port = self.udp.getsockname()[1]
        self.udp.settimeout(0.2)
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.bind(("127.0.0.1", self.port))
        self.tcp.listen(5)
        self.tcp.settimeout(0.2)
        self.stop = threading.Event()
        self.threads = [threading.Thread(target=self._udp_loop, daemon=True),
                        threading.Thread(target=self._tcp_loop, daemon=True)]
        for t in self.threads:
            t.start()

    @property
    def endpoint(self):
        return ("127.0.0.1", self.port)

    def _udp_loop(self):
        while not self.stop.is_set():
            try:
                data, addr = self.udp.recvfrom(4096)
            except (socket.timeout, OSError):
                continue
            q = d.parse_query(data)
            if q:
                self.queries.append(q.name)
                self.udp.sendto(a_response(data, self.address, truncated=self.truncate_udp), addr)

    def _tcp_loop(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.tcp.accept()
            except (socket.timeout, OSError):
                continue
            with conn:
                try:
                    n = struct.unpack("!H", d._recv_exact(conn, 2))[0]
                    data = d._recv_exact(conn, n)
                    q = d.parse_query(data)
                    if q:
                        self.queries.append(q.name)
                        resp = a_response(data, self.address)
                        conn.sendall(struct.pack("!H", len(resp)) + resp)
                except OSError:
                    pass

    def close(self):
        self.stop.set()
        self.udp.close()
        self.tcp.close()


class WireFormat(unittest.TestCase):
    def test_build_and_parse_query(self):
        pkt = d.build_query("www.Baidu.com", d.QTYPE_A, qid=0x1234)
        q = d.parse_query(pkt)
        self.assertEqual((q.id, q.name.lower(), q.qtype, q.qclass), (0x1234, "www.baidu.com", 1, 1))

    def test_rejects_garbage_and_responses(self):
        self.assertIsNone(d.parse_query(b""))
        self.assertIsNone(d.parse_query(b"\x00" * 11))
        pkt = bytearray(d.build_query("a.com"))
        pkt[2] |= 0x80  # QR bit: this is a response
        self.assertIsNone(d.parse_query(bytes(pkt)))
        self.assertIsNone(d.parse_query(struct.pack("!HHHHHH", 1, 0, 1, 0, 0, 0) + b"\x3f" + b"a" * 5))

    def test_compression_loop_is_rejected(self):
        evil = struct.pack("!HHHHHH", 1, 0x0100, 1, 0, 0, 0) + b"\xc0\x0c" + struct.pack("!HH", 1, 1)
        self.assertIsNone(d.parse_query(evil))

    def test_response_info(self):
        pkt = d.build_query("x.com")
        rcode, ttl, addrs = d.response_info(a_response(pkt, "9.9.9.9", ttl=42))
        self.assertEqual((rcode, ttl, addrs), (0, 42, [bytes([9, 9, 9, 9])]))

    def test_edns_size(self):
        pkt = bytearray(d.build_query("x.com"))
        pkt[10:12] = struct.pack("!H", 1)
        pkt += b"\x00" + struct.pack("!HHIH", 41, 4096, 0, 0)
        self.assertEqual(d.edns_udp_size(bytes(pkt)), 4096)
        self.assertEqual(d.edns_udp_size(d.build_query("x.com")), 512)

    def test_rebind_classification(self):
        for raw in ("10.1.2.3", "192.168.1.1", "127.0.0.1", "169.254.1.1", "0.0.0.0", "172.16.0.9"):
            self.assertTrue(d._is_rebind_address(socket.inet_aton(raw)), raw)
        for raw in ("223.5.5.5", "1.1.1.1", "93.184.216.34"):
            self.assertFalse(d._is_rebind_address(socket.inet_aton(raw)), raw)
        self.assertTrue(d._is_rebind_address(socket.inet_pton(socket.AF_INET6, "::1")))
        self.assertTrue(d._is_rebind_address(socket.inet_pton(socket.AF_INET6, "fe80::1")))
        self.assertFalse(d._is_rebind_address(socket.inet_pton(socket.AF_INET6, "2400:3200::1")))


class DomainMatching(unittest.TestCase):
    def setUp(self):
        self.r = d.Resolver({"baidu.com", "qq.com", "a1.mzstatic.com"}, [], [])

    def test_suffix_match(self):
        for name in ("baidu.com", "www.baidu.com", "a.b.c.qq.com", "WWW.BAIDU.COM.", "a1.mzstatic.com"):
            self.assertTrue(self.r.is_cn(name), name)

    def test_non_matches(self):
        for name in ("google.com", "notbaidu.com", "baidu.com.evil.org", "mzstatic.com", "com", ""):
            self.assertFalse(self.r.is_cn(name), name)


class EndToEnd(unittest.TestCase):
    def setUp(self):
        self.cn = FakeUpstream("223.1.1.1")
        self.foreign = FakeUpstream("93.184.216.34")
        self.resolver = d.Resolver({"baidu.com"}, [self.cn.endpoint], [self.foreign.endpoint], timeout=1.0)
        self.proxy = d.DnsProxy(self.resolver, "127.0.0.1", 0)
        self.proxy.start()
        self.addCleanup(self.proxy.stop)
        self.addCleanup(self.cn.close)
        self.addCleanup(self.foreign.close)

    def ask(self, name):
        return d.query_a(name, ("127.0.0.1", self.proxy.udp_port), 2.0)

    def test_split_routing_of_queries(self):
        self.assertEqual(self.ask("www.baidu.com"), ["223.1.1.1"])
        self.assertEqual(self.ask("www.google.com"), ["93.184.216.34"])
        self.assertIn("www.baidu.com", self.cn.queries)
        self.assertNotIn("www.baidu.com", self.foreign.queries)
        self.assertIn("www.google.com", self.foreign.queries)
        self.assertNotIn("www.google.com", self.cn.queries)

    def test_cache_avoids_second_upstream_query(self):
        self.ask("cached.example.org")
        self.ask("cached.example.org")
        self.assertEqual(self.foreign.queries.count("cached.example.org"), 1)

    def test_domain_needed(self):
        self.assertEqual(self.ask("intranethost"), [])
        self.assertEqual(self.foreign.queries + self.cn.queries, [])

    def test_bogus_priv_reverse_lookup(self):
        pkt = d.build_query("1.0.168.192.in-addr.arpa", d.QTYPE_PTR)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        sock.sendto(pkt, ("127.0.0.1", self.proxy.udp_port))
        data, _ = sock.recvfrom(4096)
        sock.close()
        self.assertEqual(data[3] & 0x0F, d.RCODE_NXDOMAIN)
        self.assertEqual(self.foreign.queries, [])

    def test_stop_dns_rebind(self):
        self.foreign.address = "192.168.1.1"
        self.assertEqual(self.ask("rebind.example.org"), [])  # SERVFAIL, answer dropped
        self.foreign.address = "127.0.0.1"
        self.assertEqual(self.ask("rebind2.example.org"), [])

    def test_tcp_listener(self):
        with socket.create_connection(("127.0.0.1", self.proxy.tcp_port), timeout=2) as sock:
            pkt = d.build_query("www.baidu.com")
            sock.sendall(struct.pack("!H", len(pkt)) + pkt)
            n = struct.unpack("!H", d._recv_exact(sock, 2))[0]
            data = d._recv_exact(sock, n)
        self.assertEqual(d.response_info(data)[2], [bytes([223, 1, 1, 1])])

    def test_truncated_upstream_falls_back_to_tcp(self):
        trunc = FakeUpstream("93.184.216.99", truncate_udp=True)
        self.addCleanup(trunc.close)
        resolver = d.Resolver(set(), [], [trunc.endpoint], timeout=1.0, cache_size=0)
        response = resolver.resolve(d.build_query("big.example.org"))
        self.assertEqual(d.response_info(response)[2], [bytes([93, 184, 216, 99])])

    def test_upstream_failure_returns_servfail(self):
        dead = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dead.bind(("127.0.0.1", 0))  # nobody answers
        self.addCleanup(dead.close)
        resolver = d.Resolver(set(), [], [dead.getsockname()], timeout=0.3)
        response = resolver.resolve(d.build_query("timeout.example.org"))
        self.assertEqual(response[3] & 0x0F, d.RCODE_SERVFAIL)

    def test_failover_to_secondary_upstream(self):
        dead = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dead.bind(("127.0.0.1", 0))
        self.addCleanup(dead.close)
        resolver = d.Resolver(set(), [], [dead.getsockname(), self.foreign.endpoint], timeout=0.3)
        response = resolver.resolve(d.build_query("failover.example.org"))
        self.assertEqual(d.response_info(response)[2], [bytes([93, 184, 216, 34])])

    def test_concurrent_queries(self):
        results = []

        def worker(i):
            results.append(self.ask(f"h{i}.example.org"))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(40)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(10)
        self.assertEqual(len(results), 40)
        self.assertTrue(all(r == ["93.184.216.34"] for r in results))


class DohTests(unittest.TestCase):
    """DoH upstream against a tiny local HTTP server speaking application/dns-message."""

    def setUp(self):
        import http.server

        outer = self
        self.requests = []

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                outer.requests.append((self.path, self.headers["Content-Type"], body[:2]))
                if outer.status != 200:
                    self.send_response(outer.status)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                resp = a_response(body, "223.9.9.9")
                self.send_response(200)
                self.send_header("Content-Type", "application/dns-message")
                self.send_header("Content-Length", str(len(resp)))
                self.end_headers()
                self.wfile.write(resp)

            def log_message(self, *a):
                pass

        self.status = 200
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.shutdown)
        self.doh = d.DohUpstream("127.0.0.1", "/dns-query", self.server.server_address[1], use_tls=False)

    def test_query_roundtrip_restores_original_id_and_uses_id_zero_on_wire(self):
        pkt = d.build_query("www.baidu.com", qid=0xBEEF)
        data = self.doh.query(pkt)
        self.assertEqual(data[:2], b"\xbe\xef")
        self.assertEqual(d.response_info(data)[2], [bytes([223, 9, 9, 9])])
        self.assertEqual(self.requests[0], ("/dns-query", "application/dns-message", b"\x00\x00"))

    def test_keepalive_reuses_connection_and_http_error_returns_none(self):
        for i in range(3):
            self.assertIsNotNone(self.doh.query(d.build_query(f"a{i}.baidu.com")))
        self.status = 500
        self.assertIsNone(self.doh.query(d.build_query("x.baidu.com")))

    def test_resolver_uses_doh_for_cn_and_udp_for_foreign(self):
        foreign = FakeUpstream("93.184.216.34")
        self.addCleanup(foreign.close)
        resolver = d.Resolver({"baidu.com"}, [self.doh], [foreign.endpoint], timeout=1.0)
        cn = resolver.resolve(d.build_query("www.baidu.com"))
        other = resolver.resolve(d.build_query("www.example.org"))
        self.assertEqual(d.response_info(cn)[2], [bytes([223, 9, 9, 9])])
        self.assertEqual(d.response_info(other)[2], [bytes([93, 184, 216, 34])])
        self.assertEqual(foreign.queries, ["www.example.org"])

    def test_resolver_falls_back_between_doh_endpoints(self):
        dead = d.DohUpstream("127.0.0.1", "/dns-query", 1, timeout=0.3, use_tls=False)
        resolver = d.Resolver({"baidu.com"}, [dead, self.doh], [], timeout=1.0)
        response = resolver.resolve(d.build_query("www.baidu.com"))
        self.assertEqual(d.response_info(response)[2], [bytes([223, 9, 9, 9])])


class AllowedSources(unittest.TestCase):
    def test_foreign_source_addresses_are_ignored(self):
        up = FakeUpstream("93.184.216.34")
        self.addCleanup(up.close)
        resolver = d.Resolver(set(), [], [up.endpoint], timeout=1.0)
        proxy = d.DnsProxy(resolver, "127.0.0.1", 0, allowed_sources={"10.99.99.99"})
        proxy.start()
        self.addCleanup(proxy.stop)
        self.assertEqual(d.query_a("www.example.org", ("127.0.0.1", proxy.udp_port), 0.8), [])
        self.assertEqual(up.queries, [])
        proxy.allowed_sources = {"127.0.0.1"}
        self.assertEqual(d.query_a("www.example.org", ("127.0.0.1", proxy.udp_port), 2.0), ["93.184.216.34"])


if __name__ == "__main__":
    unittest.main()
