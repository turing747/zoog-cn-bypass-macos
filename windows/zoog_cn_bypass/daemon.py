"""Reconcile loop: the Windows counterpart of src/daemon.sh."""

from __future__ import annotations

import ctypes
import logging
import logging.handlers
import signal
import socket
import threading
from pathlib import Path

from . import config, dnsproxy, winnet
from .nrpt import Nrpt
from .routes import (
    StateStore,
    load_networks,
    valid_ipv4_gateway,
    valid_ipv6_gateway,
)

log = logging.getLogger("zoog")


def _contains(text: str, patterns) -> bool:
    lowered = text.lower()
    return any(p.lower() in lowered for p in patterns)


class Reconciler:
    """Adds/removes China-direct routes and the DNS override as ZoogVPN comes and goes."""

    def __init__(self, net, nrpt, dns_probe, store: StateStore, settings: config.Settings,
                 networks: dict[int, list[str]] | None = None, data_dir: Path | None = None,
                 dns_address=None) -> None:
        self.net = net
        self.nrpt = nrpt
        self.dns_probe = dns_probe
        self.store = store
        self.settings = settings
        self._networks = networks
        self._data_dir = data_dir
        # Address the system resolver is pointed to (127.0.0.1, or the tunnel IP in compat mode).
        self.dns_address = dns_address or (lambda: config.LOCAL_DNS)

    # -- helpers -----------------------------------------------------------
    def networks(self, family: int) -> list[str]:
        if self._networks is None:
            data = self._data_dir or config.runtime_data_dir()
            self._networks = {
                4: load_networks(data / "cn-ipv4.txt", 4),
                6: load_networks(data / "cn-ipv6.txt", 6),
            }
        return self._networks[family]

    def _message(self, text: str) -> None:
        log.info(text)

    def log_once(self, text: str) -> None:
        if self.store.read_error() != text:
            self.store.write_error(text)
            log.warning(text)

    def is_vpn(self, adapter: winnet.Adapter) -> bool:
        return _contains(adapter.alias + " " + adapter.description, self.settings.vpn_patterns)

    def is_physical(self, adapter: winnet.Adapter) -> bool:
        if adapter.if_type not in config.PHYSICAL_IF_TYPES or not adapter.up:
            return False
        return not _contains(adapter.alias + " " + adapter.description, self.settings.virtual_patterns)

    # -- detection ---------------------------------------------------------
    def detect_vpn(self) -> tuple[winnet.Adapter | None, str]:
        """(VPN adapter carrying foreign traffic, explanation when there is none)."""
        adapters = self.net.adapters()
        foreign = self.net.best_ifindex(config.FOREIGN_PROBE_V4)
        by_index = {a.index: a for a in adapters}
        if foreign is not None:
            adapter = by_index.get(foreign)
            if adapter is not None and adapter.up and self.is_vpn(adapter):
                return adapter, ""
        up_vpns = [a for a in adapters if a.up and self.is_vpn(a) and a.if_type == 53]
        if up_vpns:
            return None, (
                f"VPN adapter '{up_vpns[0].alias}' is up, but foreign traffic is not routed "
                "through it"
            )
        return None, "no ZoogVPN tunnel is connected"

    def physical(self, family: int) -> tuple[str, int] | None:
        adapters = {a.index: a for a in self.net.adapters()}
        best: tuple[int, int, str] | None = None
        for row in self.net.routes(family):
            if row.prefixlen != 0:
                continue
            adapter = adapters.get(row.ifindex)
            if adapter is None or not self.is_physical(adapter):
                continue
            if family == 4 and not valid_ipv4_gateway(row.gateway):
                continue
            if family == 6 and not valid_ipv6_gateway(row.gateway):
                continue
            metric = row.metric + self.net.interface_metric(row.ifindex, 2 if family == 4 else 23)
            candidate = (metric, row.ifindex, row.gateway)
            if best is None or candidate < best:
                best = candidate
        return (best[2], best[1]) if best else None

    def other_vpn_connected(self) -> bool:
        adapters = {a.index: a for a in self.net.adapters()}
        for row in self.net.routes(4):
            if row.prefixlen not in (0, 1):
                continue
            adapter = adapters.get(row.ifindex)
            if (
                adapter
                and adapter.up
                and adapter.if_type in config.TUNNEL_IF_TYPES
                and not self.is_vpn(adapter)
            ):
                return True
        return False

    @staticmethod
    def expected_state(v4: tuple[str, int], v6: tuple[str, int] | None) -> str:
        gw6, if6 = (v6[0], v6[1]) if v6 else ("", "")
        return f"{v4[0]}|{v4[1]}|{gw6}|{if6}"

    def routes_current_without_state(self, if4: int, if6: int | None) -> bool:
        for probe in config.CN_PROBES_V4:
            if self.net.best_ifindex(probe) != if4:
                return False
        if if6 is not None:
            for probe in config.CN_PROBES_V6:
                if self.net.best_ifindex(probe) != if6:
                    return False
        return True

    def routes_current(self, expected: str, if4: int, if6: int | None) -> bool:
        return self.store.read_state() == expected and self.routes_current_without_state(if4, if6)

    # -- route management --------------------------------------------------
    def remove_recorded_routes(self) -> None:
        for family in (4, 6):
            active = self.store.read_active(family)
            if active:
                gateway, ifindex, networks = active
                self.net.delete_routes(family, ifindex, gateway, networks, config.ROUTE_METRIC)
            self.store.clear_active(family)
        self.store.clear_state()

    def add_routes(self, family: int, gateway: str, ifindex: int) -> None:
        networks = self.networks(family)
        # Record the intent first: if we crash half-way, cleanup knows what to delete.
        self.store.write_active(family, gateway, ifindex, networks)
        self.net.add_routes(family, ifindex, gateway, networks, config.ROUTE_METRIC)

    # -- DNS override ------------------------------------------------------
    def clear_dns_override(self) -> None:
        if self.nrpt.exists():
            self.nrpt.remove()

    def ensure_dns_override(self, vpn: winnet.Adapter) -> bool:
        foreign = self.net.best_ifindex(config.FOREIGN_PROBE_V4)
        if foreign != vpn.index:
            self.clear_dns_override()
            self.log_once("ZoogVPN is connected, but foreign traffic is not routed through the tunnel")
            return False
        address = self.dns_address()
        if not address:
            self.clear_dns_override()
            self.log_once("China split DNS has no listen address yet (tunnel address not available)")
            return False
        if not self.dns_probe():
            self.clear_dns_override()
            self.log_once(
                "China split DNS is not ready; the system DNS override was removed "
                f"({address}:53 did not answer - a VPN DNS-leak protection or firewall may block "
                "port 53; see `compat` in the README)"
            )
            return False
        if self.nrpt.exists() and getattr(self.nrpt, "server", address) in (address, None):
            return True
        if not self.nrpt.add(address) or not self.nrpt.exists(force=True):
            self.clear_dns_override()
            self.log_once("China split DNS could not become the default Windows resolver")
            return False
        self._message(f"China split DNS active on {address}")
        return True

    def _finish_dns(self, vpn: winnet.Adapter) -> bool:
        if self.ensure_dns_override(vpn):
            self.store.clear_error()
            return True
        return False

    # -- main --------------------------------------------------------------
    def reconcile(self) -> bool:
        vpn, reason = self.detect_vpn()
        if vpn is None:
            self.clear_dns_override()
            if self.store.has_any():
                v4 = self.physical(4)
                v6 = self.physical(6)
                if v4 is None:
                    self.remove_recorded_routes()
                    self._message("China-direct routes removed: no physical IPv4 gateway")
                else:
                    expected = self.expected_state(v4, v6)
                    if self.other_vpn_connected() or not self.routes_current(
                        expected, v4[1], v6[1] if v6 else None
                    ):
                        self.remove_recorded_routes()
                        self._message("China-direct routes removed while ZoogVPN is disconnected")
            if reason.startswith("VPN adapter"):
                self.log_once(reason)
            else:
                self.store.clear_error()
            return True

        v4 = self.physical(4)
        if v4 is None:
            self.clear_dns_override()
            self.log_once("ZoogVPN connected, but no physical IPv4 gateway was found")
            return False
        v6 = self.physical(6)
        if0 = v6[1] if v6 else None
        expected = self.expected_state(v4, v6)

        if self.routes_current(expected, v4[1], if0):
            return self._finish_dns(vpn)

        self.remove_recorded_routes()
        self.add_routes(4, v4[0], v4[1])
        if v6:
            self.add_routes(6, v6[0], v6[1])

        if self.detect_vpn()[0] is None:
            self.remove_recorded_routes()
            return True

        if not self.routes_current_without_state(v4[1], if0):
            self.remove_recorded_routes()
            self.log_once("China-direct route verification failed; all added routes were rolled back")
            return False

        self.store.write_state(expected)
        self._message(
            f"China-direct routing active on interface {v4[1]}: "
            f"{self.store.active_count(4)} IPv4 and {self.store.active_count(6)} IPv6 routes"
        )
        return self._finish_dns(vpn)

    def stop(self) -> None:
        """Equivalent of `daemon.sh stop`."""
        self.nrpt.remove()
        self.remove_recorded_routes()
        self.store.clear_error()

    def describe_plan(self) -> list[str]:
        """Read-only report of what `reconcile` would do (for --dry-run)."""
        lines: list[str] = []
        vpn, reason = self.detect_vpn()
        if vpn is None:
            lines.append(f"VPN: not active ({reason}); nothing would be applied")
        else:
            lines.append(f"VPN: {vpn.alias} (ifIndex {vpn.index})")
        v4 = self.physical(4)
        v6 = self.physical(6)
        lines.append(
            f"Physical IPv4: {v4[0]} via ifIndex {v4[1]}" if v4 else "Physical IPv4: none found"
        )
        lines.append(
            f"Physical IPv6: {v6[0]} via ifIndex {v6[1]}" if v6 else "Physical IPv6: none (IPv6 China routes skipped)"
        )
        lines.append(f"Would add {len(self.networks(4))} IPv4 and {len(self.networks(6)) if v6 else 0} IPv6 routes")
        lines.append("Would add NRPT rule: '.' -> " + config.LOCAL_DNS)
        return lines


# --------------------------------------------------------------------------- #
# status
# --------------------------------------------------------------------------- #

def _interface_label(net, ifindex: int | None) -> str:
    if ifindex is None:
        return "unknown"
    for adapter in net.adapters():
        if adapter.index == ifindex:
            return adapter.alias
    return f"ifIndex {ifindex}"


def collect_status(net=None, settings: config.Settings | None = None) -> list[str]:
    net = net or winnet.WinNet()
    settings = settings or config.Settings.load()
    store = StateStore(config.state_dir()) if config.state_dir().exists() else None
    reconciler = Reconciler(net, Nrpt(), lambda: True, store or StateStore(config.state_dir()), settings)

    vpn, reason = reconciler.detect_vpn()
    task = winnet.run_powershell(
        "$t = Get-ScheduledTask -TaskName '%s' -ErrorAction SilentlyContinue; "
        "if ($t) { $t.State } else { 'NotInstalled' }; "
        "(Get-DnsClientNrptRule | Where-Object { $_.Comment -eq '%s' } | Measure-Object).Count"
        % (config.TASK_NAME, config.NRPT_COMMENT),
        timeout=30,
    )
    output = task.stdout.split()
    task_state = output[0] if output else "Unknown"
    nrpt_active = len(output) > 1 and output[-1] != "0"

    # Reading SYSTEM-owned tasks needs elevation; the daemon heartbeat is the reliable signal.
    heartbeat = store.heartbeat_age() if store else None
    if heartbeat is not None and heartbeat < 20:
        task_state = f"Running (daemon heartbeat {heartbeat:.0f}s ago)"
    elif task_state in ("NotInstalled", "Unknown") and (config.install_dir() / "app").exists():
        task_state = "Unknown (installed; run `status` as Administrator for task details)"

    dns_host = config.LOCAL_DNS
    if settings.compat_mode:
        dns_host = (winnet.tunnel_source_address() if vpn else None) or config.LOCAL_DNS
    dns_target = (dns_host, config.LOCAL_DNS_PORT)
    dns_answer = dnsproxy.query_a("www.baidu.com", dns_target, 2.0)
    dns_listening = bool(dns_answer)

    state = store.read_state() if store else None
    if state:
        routing = "active" if vpn else "standby (routes retained for fast reconnect)"
    else:
        routing = "inactive"

    lines = [
        f"ZoogVPN: {'Connected (' + vpn.alias + ', ifIndex ' + str(vpn.index) + ')' if vpn else 'Disconnected'}",
        f"Scheduled task: {task_state}",
        f"Local DNS service: {'listening on ' + dns_host + ':' + str(config.LOCAL_DNS_PORT) if dns_listening else 'not responding'}",
        f"Compatibility mode: {'ON (DNS on tunnel address, domestic DNS over DoH)' if settings.compat_mode else 'off'}",
        f"Split DNS override (NRPT): {'active' if nrpt_active else 'inactive'}",
        f"China-direct routing: {routing}",
        f"Installed IPv4 routes: {store.active_count(4) if store else 0}",
        f"Installed IPv6 routes: {store.active_count(6) if store else 0}",
    ]
    if vpn is None and reason:
        lines.append(f"Note: {reason}")
    error = store.read_error() if store else None
    if error:
        lines.append(f"Last error: {error}")

    cn_if = net.best_ifindex(config.CN_PROBES_V4[0])
    foreign_if = net.best_ifindex(config.FOREIGN_PROBE_V4)
    lines.append(f"Route check - China {config.CN_PROBES_V4[0]}: {_interface_label(net, cn_if)}")
    lines.append(f"Route check - foreign {config.FOREIGN_PROBE_V4}: {_interface_label(net, foreign_if)}")

    resolver_name = "DNS check"
    if not dns_listening:
        resolver_name = "System DNS check"  # whatever resolver Windows currently uses (the VPN's)
    for host in ("www.baidu.com", "www.qq.com", "www.cloudflare.com"):
        if dns_listening:
            answers = dns_answer if host == "www.baidu.com" else dnsproxy.query_a(
                host, dns_target, 2.0
            )
        else:
            answers = _system_resolve(host)
        if answers:
            label = _interface_label(net, net.best_ifindex(answers[-1]))
            lines.append(f"{resolver_name} - {host}: {answers[-1]} via {label}")
        else:
            lines.append(f"{resolver_name} - {host}: unresolved")

    ip_split = bool(state) and vpn is not None and cn_if is not None and cn_if != foreign_if
    if ip_split and nrpt_active and dns_listening:
        verdict = "IP split ACTIVE, DNS split ACTIVE"
    elif ip_split:
        verdict = (
            "IP split ACTIVE (China IPs go direct), DNS split INACTIVE "
            "(domains are resolved by the VPN's DNS; local port 53 is not reachable)"
            if not dns_listening
            else "IP split ACTIVE, DNS split INACTIVE"
        )
    else:
        verdict = "China-direct split is NOT active"
    lines.append(f"Summary: {verdict}")
    return lines


def _system_resolve(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    except OSError:
        return []
    return list(dict.fromkeys(info[4][0] for info in infos))


# --------------------------------------------------------------------------- #
# cleanup / daemon
# --------------------------------------------------------------------------- #

def cleanup(net=None) -> list[str]:
    """Rescue command: remove everything this tool added, even without usable state."""
    net = net or winnet.WinNet()
    messages: list[str] = []
    store = StateStore(config.state_dir())
    reconciler = Reconciler(net, Nrpt(), lambda: True, store, config.Settings.load(), networks={4: [], 6: []})
    reconciler.nrpt.remove()
    messages.append("NRPT rule removed")
    reconciler.remove_recorded_routes()
    messages.append("Recorded routes removed")

    # Sweep: NETMGMT routes carrying our marker metric that match the China lists.
    try:
        data = config.runtime_data_dir()
        known = {4: set(load_networks(data / "cn-ipv4.txt", 4)), 6: set(load_networks(data / "cn-ipv6.txt", 6))}
    except (OSError, FileNotFoundError):
        known = {4: set(), 6: set()}
    swept = 0
    for family in (4, 6):
        for row in net.routes(family):
            if row.protocol == winnet.MIB_IPPROTO_NETMGMT and row.metric == config.ROUTE_METRIC:
                if f"{row.prefix}/{row.prefixlen}" in known[family]:
                    net.delete_routes(family, row.ifindex, row.gateway, [f"{row.prefix}/{row.prefixlen}"], row.metric)
                    swept += 1
    if swept:
        messages.append(f"Swept {swept} leftover routes")
    store.clear_error()
    return messages


def _setup_logging(to_file: bool) -> None:
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    if to_file:
        config.log_dir().mkdir(parents=True, exist_ok=True)
        handler: logging.Handler = logging.handlers.RotatingFileHandler(
            config.log_dir() / "daemon.log", maxBytes=1_000_000, backupCount=3, encoding="utf-8"
        )
    else:
        handler = logging.StreamHandler()
    handler.setFormatter(fmt)
    root.addHandler(handler)


def _acquire_mutex():
    if not winnet.IS_WINDOWS:
        return object()
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateMutexW.restype = ctypes.c_void_p
    kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
    handle = kernel32.CreateMutexW(None, False, config.MUTEX_NAME)
    if not handle or ctypes.get_last_error() == 183:  # ERROR_ALREADY_EXISTS
        return None
    return handle


def run_daemon(foreground_log: bool = False) -> int:
    if not winnet.is_admin():
        print("daemon requires an elevated (Administrator) process")
        return 77
    mutex = _acquire_mutex()
    if mutex is None:
        print("another ZoogCNBypass daemon is already running")
        return 0
    _setup_logging(to_file=not foreground_log)
    settings = config.Settings.load()
    data = config.runtime_data_dir()
    store = StateStore(config.state_dir())

    domains = dnsproxy.load_cn_domains(
        [data / "accelerated-domains.china.conf", data / "apple.china.conf"]
    )
    cn_upstreams = (
        [dnsproxy.DohUpstream(host, path) for host, path in settings.doh_upstreams]
        if settings.compat_mode
        else settings.cn_upstreams
    )
    resolver = dnsproxy.Resolver(domains, cn_upstreams, settings.foreign_upstreams)
    proxy: dnsproxy.DnsProxy | None = None
    current = {"address": None}  # address the proxy listens on and the probe queries

    def probe() -> bool:
        address = current["address"]
        if not address:
            return False
        target = (address, config.LOCAL_DNS_PORT)
        return bool(dnsproxy.query_a("www.baidu.com", target)) and bool(
            dnsproxy.query_a("example.com", target)
        )

    nrpt = Nrpt()
    reconciler = Reconciler(
        winnet.WinNet(), nrpt, probe, store, settings, data_dir=data,
        dns_address=lambda: current["address"],
    )

    stop = threading.Event()

    def request_stop(*_args) -> None:
        stop.set()

    for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), request_stop)

    log.info(
        "ZoogCNBypass daemon starting (%d domestic domains, compat mode %s)",
        len(domains), "ON" if settings.compat_mode else "off",
    )
    # A rule left behind by a crashed run would point at a dead resolver.
    nrpt.remove()
    try:
        while not stop.is_set():
            # Normal mode: loopback. Compat mode: the tunnel address, which is where the VPN
            # client leaves port 53 usable; it changes with every connection.
            wanted = config.LOCAL_DNS
            if settings.compat_mode:
                # Only trust the source address while the foreign route really is the tunnel,
                # otherwise it would be the physical NIC's address.
                wanted = winnet.tunnel_source_address() if reconciler.detect_vpn()[0] else None
            if proxy is not None and (wanted is None or proxy.host != wanted or not proxy.running):
                proxy.stop()
                proxy = None
                current["address"] = None
            if proxy is None and wanted:
                candidate = dnsproxy.DnsProxy(
                    resolver, wanted, config.LOCAL_DNS_PORT,
                    allowed_sources={wanted, "127.0.0.1"},  # this machine only
                )
                try:
                    candidate.start()
                    proxy = candidate
                    current["address"] = wanted
                    log.info("DNS proxy listening on %s:%d", wanted, config.LOCAL_DNS_PORT)
                except OSError as error:
                    reconciler.log_once(f"Local DNS proxy cannot bind {wanted}:{config.LOCAL_DNS_PORT}: {error}")
            try:
                reconciler.reconcile()
            except Exception:
                log.exception("reconcile failed")
            store.touch_heartbeat()
            stop.wait(settings.poll_seconds)
    finally:
        log.info("ZoogCNBypass daemon stopping")
        try:
            reconciler.stop()
        finally:
            if proxy is not None:
                proxy.stop()
    return 0
