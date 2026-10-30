"""Reconcile logic with a simulated routing table (no admin rights, no real changes)."""

import ipaddress
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from zoog_cn_bypass import config  # noqa: E402
from zoog_cn_bypass.daemon import Reconciler  # noqa: E402
from zoog_cn_bypass.routes import StateStore  # noqa: E402
from zoog_cn_bypass.winnet import Adapter, RouteRow  # noqa: E402

ETH, WIFI, VETH, VPN, TS = 25, 23, 26, 87, 89


class FakeNet:
    """Longest-prefix routing simulation: base routes + routes added by the daemon."""

    def __init__(self):
        self.adapters_list = [
            Adapter(ETH, "Ethernet", "Realtek Gaming 2.5GbE Family Controller", 6, True),
            Adapter(WIFI, "WLAN", "Intel(R) Wi-Fi 6 AX201 160MHz", 71, False),
            Adapter(VETH, "vEthernet (Default Switch)", "Hyper-V Virtual Ethernet Adapter", 6, True),
            Adapter(VPN, "ZoogVPN TUN", "ZoogVPN TUN Tunnel", 53, True),
            Adapter(TS, "Tailscale", "Tailscale Tunnel", 53, True),
        ]
        self.eth_gw = "192.168.0.1"
        self.v6_gw = None
        self.vpn_up = True
        self.vpn_default = True  # does the tunnel carry the default route?
        self.extra_defaults = []  # (ifindex, prefixlen, gateway) of other default-ish routes
        self.added: dict[tuple[str, int, str], None] = {}
        self.add_calls = 0
        self.delete_calls = 0
        self.break_adds = False
        self.metrics = {ETH: 25, WIFI: 40, VETH: 15, VPN: 3, TS: 5}

    # backend interface -----------------------------------------------------
    def adapters(self):
        return [a if a.index != VPN else Adapter(a.index, a.alias, a.description, a.if_type, self.vpn_up)
                for a in self.adapters_list]

    def _base_routes(self, family):
        rows = []
        if family == 4:
            rows.append(RouteRow(ETH, "0.0.0.0", 0, self.eth_gw, 256, 3))
            rows.append(RouteRow(VETH, "0.0.0.0", 0, "172.26.176.254", 256, 3))  # must be ignored
            if self.vpn_up and self.vpn_default:
                rows.append(RouteRow(VPN, "0.0.0.0", 1, "10.20.136.21", 0, 3))
                rows.append(RouteRow(VPN, "128.0.0.0", 1, "10.20.136.21", 0, 3))
            for ifindex, plen, gw in self.extra_defaults:
                rows.append(RouteRow(ifindex, "0.0.0.0" if plen == 0 else "128.0.0.0", plen, gw, 0, 3))
        elif self.v6_gw:
            rows.append(RouteRow(ETH, "::", 0, self.v6_gw, 256, 3))
        return rows

    def routes(self, family):
        rows = self._base_routes(family)
        for (net, ifindex, gw) in self.added:
            n = ipaddress.ip_network(net)
            if (n.version == 4) == (family == 4):
                rows.append(RouteRow(ifindex, str(n.network_address), n.prefixlen, gw, config.ROUTE_METRIC, 3))
        return rows

    def best_ifindex(self, address):
        ip = ipaddress.ip_address(address)
        best = None
        for row in self.routes(4 if ip.version == 4 else 6):
            net = ipaddress.ip_network(f"{row.prefix}/{row.prefixlen}")
            if ip in net and (best is None or row.prefixlen > best[0]):
                best = (row.prefixlen, row.ifindex)
        return best[1] if best else None

    def interface_metric(self, ifindex, family):
        return self.metrics.get(ifindex, 0)

    def add_routes(self, family, ifindex, gateway, networks, metric):
        self.add_calls += 1
        if self.break_adds:
            return 0
        for n in networks:
            self.added[(n, ifindex, gateway)] = None
        return len(networks)

    def delete_routes(self, family, ifindex, gateway, networks, metric):
        self.delete_calls += 1
        for n in networks:
            self.added.pop((n, ifindex, gateway), None)
        return len(networks)


class FakeNrpt:
    def __init__(self):
        self.present = False
        self.adds = 0
        self.server = None

    def exists(self, force=False):
        return self.present

    def add(self, server="127.0.0.1"):
        self.present = True
        self.adds += 1
        self.server = server
        return True

    def remove(self):
        self.present = False
        self.server = None
        return True


class ReconcileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.net = FakeNet()
        self.nrpt = FakeNrpt()
        self.dns_ok = True
        self.store = StateStore(Path(self.tmp.name))
        self.r = Reconciler(
            self.net, self.nrpt, lambda: self.dns_ok, self.store, config.Settings(),
            networks={4: ["223.0.0.0/12", "114.112.0.0/12", "202.96.0.0/16"], 6: ["2400:3200::/32", "240c::/18"]},
        )

    def test_connected_applies_routes_and_dns(self):
        self.assertTrue(self.r.reconcile())
        self.assertEqual(self.net.best_ifindex("223.5.5.5"), ETH)
        self.assertEqual(self.net.best_ifindex("114.114.114.114"), ETH)
        self.assertEqual(self.net.best_ifindex("1.1.1.1"), VPN)
        self.assertEqual(self.net.best_ifindex("8.8.8.8"), VPN)
        self.assertEqual(self.net.best_ifindex("93.184.216.34"), VPN)
        self.assertTrue(self.nrpt.present)
        self.assertEqual(self.store.read_state(), "192.168.0.1|25||")
        self.assertEqual(self.store.active_count(4), 3)
        self.assertEqual(self.store.active_count(6), 0)  # no physical IPv6 gateway

    def test_second_run_is_idempotent(self):
        self.r.reconcile()
        calls = (self.net.add_calls, self.nrpt.adds)
        self.r.reconcile()
        self.assertEqual((self.net.add_calls, self.nrpt.adds), calls)

    def test_ipv6_added_when_physical_gateway_exists(self):
        self.net.v6_gw = "fe80::1"
        self.r.reconcile()
        self.assertEqual(self.store.active_count(6), 2)
        self.assertEqual(self.net.best_ifindex("2400:3200::1"), ETH)
        self.assertEqual(self.store.read_state(), "192.168.0.1|25|fe80::1|25")

    def test_gateway_change_replaces_routes(self):
        self.r.reconcile()
        self.net.eth_gw = "192.168.1.1"
        self.r.reconcile()
        self.assertTrue(all(gw == "192.168.1.1" for (_, _, gw) in self.net.added))
        self.assertEqual(len(self.net.added), 3)
        self.assertEqual(self.store.read_state(), "192.168.1.1|25||")

    def test_vpn_disconnect_clears_dns_and_keeps_current_routes(self):
        self.r.reconcile()
        self.net.vpn_up = False
        self.r.reconcile()
        self.assertFalse(self.nrpt.present)
        self.assertEqual(len(self.net.added), 3)  # standby: kept for fast reconnect
        self.net.vpn_up = True
        self.r.reconcile()
        self.assertTrue(self.nrpt.present)

    def test_disconnect_with_changed_gateway_removes_routes(self):
        self.r.reconcile()
        self.net.vpn_up = False
        self.net.eth_gw = "10.9.9.1"  # moved to another network
        self.r.reconcile()
        self.assertEqual(len(self.net.added), 0)
        self.assertIsNone(self.store.read_state())

    def test_other_vpn_default_route_removes_standby_routes(self):
        self.r.reconcile()
        self.net.vpn_up = False
        self.net.extra_defaults = [(TS, 1, "100.100.0.1")]
        self.r.reconcile()
        self.assertEqual(len(self.net.added), 0)

    def test_tailscale_without_default_route_is_not_another_vpn(self):
        self.r.reconcile()
        self.net.vpn_up = False
        self.r.reconcile()
        self.assertEqual(len(self.net.added), 3)

    def test_verification_failure_rolls_back(self):
        self.net.break_adds = True
        self.assertFalse(self.r.reconcile())
        self.assertEqual(len(self.net.added), 0)
        self.assertIsNone(self.store.read_state())
        self.assertFalse(self.nrpt.present)
        self.assertIn("rolled back", self.store.read_error())

    def test_up_tunnel_not_carrying_default_route_does_nothing(self):
        self.net.vpn_default = False  # adapter up but 1.1.1.1 exits via Ethernet
        self.assertTrue(self.r.reconcile())
        self.assertEqual(len(self.net.added), 0)
        self.assertFalse(self.nrpt.present)
        self.assertIn("not routed through", self.store.read_error())

    def test_dns_probe_failure_removes_override_but_keeps_routes(self):
        self.r.reconcile()
        self.dns_ok = False
        self.assertFalse(self.r.reconcile())
        self.assertFalse(self.nrpt.present)
        self.assertEqual(len(self.net.added), 3)
        self.assertIn("not ready", self.store.read_error())
        self.dns_ok = True
        self.assertTrue(self.r.reconcile())
        self.assertTrue(self.nrpt.present)
        self.assertIsNone(self.store.read_error())

    def test_no_physical_gateway(self):
        self.net.adapters_list[0] = Adapter(ETH, "Ethernet", "Realtek", 6, False)
        self.assertFalse(self.r.reconcile())
        self.assertEqual(len(self.net.added), 0)
        self.assertIn("no physical IPv4 gateway", self.store.read_error())

    def test_virtual_adapters_are_never_physical_gateways(self):
        self.net.adapters_list[0] = Adapter(ETH, "Ethernet", "Realtek", 6, False)  # unplug NIC
        self.assertIsNone(self.r.physical(4))  # only vEthernet has a default route left

    def test_lowest_metric_physical_adapter_wins(self):
        net = self.net
        net.adapters_list[1] = Adapter(WIFI, "WLAN", "Intel(R) Wi-Fi 6 AX201 160MHz", 71, True)
        original = net._base_routes

        def with_wifi(family):
            rows = original(family)
            if family == 4:
                rows.append(RouteRow(WIFI, "0.0.0.0", 0, "192.168.8.1", 256, 3))
            return rows

        net._base_routes = with_wifi
        self.assertEqual(self.r.physical(4), ("192.168.0.1", ETH))  # 256+25 < 256+40
        net.metrics[ETH] = 90
        self.assertEqual(self.r.physical(4), ("192.168.8.1", WIFI))

    def test_stop_removes_everything(self):
        self.r.reconcile()
        self.r.stop()
        self.assertEqual(len(self.net.added), 0)
        self.assertFalse(self.nrpt.present)
        self.assertFalse(self.store.has_any())

    def test_crash_recovery_uses_recorded_intent(self):
        """Routes recorded but state never written (crash mid-way) are still deleted."""
        self.store.write_active(4, "192.168.0.1", ETH, ["223.0.0.0/12"])
        self.net.added[("223.0.0.0/12", ETH, "192.168.0.1")] = None
        self.net.vpn_up = False
        self.net.eth_gw = "10.9.9.1"
        self.r.reconcile()
        self.assertEqual(len(self.net.added), 0)

    def test_custom_vpn_pattern(self):
        self.net.adapters_list[3] = Adapter(VPN, "CorpTunnel", "Acme Tunnel", 53, True)
        self.assertTrue(self.r.reconcile())
        self.assertEqual(len(self.net.added), 0)  # not recognised as ZoogVPN
        self.r.settings = config.Settings({"vpn_adapter_patterns": ["Acme"]})
        self.r.reconcile()
        self.assertEqual(len(self.net.added), 3)

    def test_dry_run_plan_changes_nothing(self):
        lines = self.r.describe_plan()
        self.assertTrue(any("ZoogVPN TUN" in l for l in lines))
        self.assertEqual(len(self.net.added), 0)
        self.assertFalse(self.nrpt.present)

    def test_compat_mode_points_nrpt_at_tunnel_address_and_follows_changes(self):
        address = {"value": "10.20.136.22"}
        self.r.dns_address = lambda: address["value"]
        self.r.reconcile()
        self.assertEqual(self.nrpt.server, "10.20.136.22")
        adds = self.nrpt.adds
        self.r.reconcile()
        self.assertEqual(self.nrpt.adds, adds)  # unchanged address: no churn
        address["value"] = "10.20.136.26"  # reconnect gave the tunnel a new address
        self.r.reconcile()
        self.assertEqual(self.nrpt.server, "10.20.136.26")
        self.assertEqual(self.nrpt.adds, adds + 1)

    def test_no_dns_address_means_no_override(self):
        self.r.dns_address = lambda: None
        self.r.reconcile()
        self.assertFalse(self.nrpt.present)
        self.assertEqual(len(self.net.added), 3)  # routing still works
        self.assertIn("no listen address", self.store.read_error())


if __name__ == "__main__":
    unittest.main()
