"""Read-only checks of the real Windows API layer (skipped off Windows)."""

import ctypes
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from zoog_cn_bypass import wfp, winnet  # noqa: E402


@unittest.skipUnless(winnet.IS_WINDOWS, "Windows only")
class WinNetReadOnly(unittest.TestCase):
    def test_struct_sizes_match_windows_headers(self):
        self.assertEqual(ctypes.sizeof(winnet.MIB_IPFORWARD_ROW2), 104)
        self.assertEqual(ctypes.sizeof(winnet.MIB_IF_ROW2), 1352)
        if ctypes.sizeof(ctypes.c_void_p) == 8:
            self.assertEqual(ctypes.sizeof(wfp.FWP_VALUE0), 16)
            self.assertEqual(ctypes.sizeof(wfp.FWPM_FILTER_CONDITION0), 40)
            self.assertEqual(ctypes.sizeof(wfp.FWPM_ACTION0), 20)
            self.assertEqual(ctypes.sizeof(wfp.FWPM_FILTER0), 200)

    def test_wfp_luid_and_readonly_status(self):
        loopback = next(a for a in winnet.list_adapters() if a.if_type == 24)
        self.assertIsNotNone(wfp.ifindex_to_luid(loopback.index))
        self.assertIsInstance(wfp.wfp_permits_active(), bool)

    def test_adapters_have_loopback(self):
        adapters = winnet.list_adapters()
        self.assertTrue(any(a.if_type == 24 for a in adapters))

    def test_routes_and_best_route(self):
        rows = winnet.list_routes(winnet.AF_INET)
        self.assertTrue(rows)
        self.assertTrue(any(r.prefix == "127.0.0.0" and r.prefixlen == 8 for r in rows))
        self.assertEqual(winnet.best_route_interface("127.0.0.1"),
                         next(a.index for a in winnet.list_adapters() if a.if_type == 24))
        self.assertTrue(winnet.list_routes(winnet.AF_INET6) is not None)

    def test_interface_metric_is_readable(self):
        loopback = next(a for a in winnet.list_adapters() if a.if_type == 24)
        self.assertGreater(winnet.interface_metric(loopback.index, winnet.AF_INET), 0)

    def test_sockaddr_roundtrip(self):
        for address in ("223.5.5.5", "2400:3200::1"):
            self.assertEqual(winnet._sockaddr_to_str(winnet._sockaddr(address)), address)


if __name__ == "__main__":
    unittest.main()
