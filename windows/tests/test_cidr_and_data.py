"""Validation rules and shipped data files (Windows twin of tests/validate.sh)."""

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from zoog_cn_bypass import config, dnsproxy  # noqa: E402
from zoog_cn_bypass.routes import (  # noqa: E402
    load_networks,
    valid_ipv4_cidr,
    valid_ipv4_gateway,
    valid_ipv6_cidr,
    valid_ipv6_gateway,
)

DATA = config.source_data_dir()


class CidrValidation(unittest.TestCase):
    def test_accepts_public_china_prefixes(self):
        for cidr in ("223.5.5.0/24", "114.112.0.0/12", "1.0.1.0/24", "202.96.0.0/16"):
            self.assertTrue(valid_ipv4_cidr(cidr), cidr)

    def test_rejects_private_and_special_ranges(self):
        for cidr in (
            "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "192.168.1.0/24",
            "172.16.0.0/12", "172.20.0.0/16", "100.64.0.0/10", "100.100.100.0/24", "0.0.0.0/8",
        ):
            self.assertFalse(valid_ipv4_cidr(cidr), cidr)

    def test_rejects_protected_resolvers(self):
        self.assertFalse(valid_ipv4_cidr("1.1.1.1/32"))
        self.assertFalse(valid_ipv4_cidr("8.8.8.0/24"))
        self.assertFalse(valid_ipv4_cidr("1.1.1.0/24"))
        self.assertFalse(valid_ipv4_cidr("8.0.0.0/8"))

    def test_rejects_bad_prefix_lengths_and_garbage(self):
        for cidr in ("1.2.3.0/7", "1.2.3.4/33", "1.2.3.4/24", "abc", "", "1.2.3/24"):
            self.assertFalse(valid_ipv4_cidr(cidr), cidr)

    def test_ipv6(self):
        self.assertTrue(valid_ipv6_cidr("2400:3200::/32"))
        self.assertTrue(valid_ipv6_cidr("240c::/18"))
        self.assertFalse(valid_ipv6_cidr("fe80::/10"))
        self.assertFalse(valid_ipv6_cidr("fc00::/7"))
        self.assertFalse(valid_ipv6_cidr("2400::/8"))
        self.assertFalse(valid_ipv6_cidr("2400::1/32"))

    def test_gateways(self):
        self.assertTrue(valid_ipv4_gateway("192.168.0.1"))
        self.assertFalse(valid_ipv4_gateway("0.0.0.0"))
        self.assertFalse(valid_ipv4_gateway(""))
        self.assertTrue(valid_ipv6_gateway("fe80::1"))
        self.assertFalse(valid_ipv6_gateway("2400::1"))
        self.assertFalse(valid_ipv6_gateway("::"))


@unittest.skipIf(DATA is None, "repository data directory not found")
class DataFiles(unittest.TestCase):
    def test_ipv4_list_is_complete_and_valid(self):
        lines = [l for l in (DATA / "cn-ipv4.txt").read_text().splitlines() if l.strip()]
        loaded = load_networks(DATA / "cn-ipv4.txt", 4)
        self.assertGreater(len(lines), 5000)
        self.assertEqual(len(loaded), len(lines), "every shipped IPv4 line must pass validation")

    def test_ipv6_list_is_complete_and_valid(self):
        lines = [l for l in (DATA / "cn-ipv6.txt").read_text().splitlines() if l.strip()]
        loaded = load_networks(DATA / "cn-ipv6.txt", 6)
        self.assertGreater(len(lines), 1900)
        self.assertEqual(len(loaded), len(lines))

    def test_domain_files_are_strict(self):
        domains = dnsproxy.load_cn_domains(
            [DATA / "accelerated-domains.china.conf", DATA / "apple.china.conf"]
        )
        self.assertGreater(len(domains), 50000)
        self.assertIn("baidu.com", domains)
        self.assertIn("a1.mzstatic.com", domains)

    def test_domain_loader_rejects_foreign_directives(self):
        import tempfile

        for bad in ("server=/evil.com/8.8.8.8", "address=/evil.com/1.2.3.4", "conf-file=/etc/x"):
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "bad.conf"
                path.write_text("# ok\n" + bad + "\n")
                with self.assertRaises(ValueError):
                    dnsproxy.load_domain_file(path, set())

    def test_no_machine_specific_paths(self):
        root = Path(__file__).resolve().parents[1]
        marker = "C:" + "\\Users\\"
        for path in root.rglob("*.py"):
            if path.name == "test_cidr_and_data.py":
                continue
            self.assertNotIn(marker, path.read_text(encoding="utf-8"), str(path))

    def test_alidns_conversion(self):
        from zoog_cn_bypass.updatedata import alidns_conversion

        out = alidns_conversion("server=/qq.com/114.114.114.114\n# c\n\n")
        self.assertIn("server=/qq.com/223.5.5.5", out)
        with self.assertRaises(ValueError):
            alidns_conversion("server=/qq.com/114.114.114.114\nrebind-domain-ok=/x/\n")


if __name__ == "__main__":
    unittest.main()
