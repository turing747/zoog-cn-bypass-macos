"""Windows networking primitives built on ctypes (no third-party packages).

Only IP Helper (iphlpapi), shell32 and kernel32 are used.
"""

from __future__ import annotations

import ctypes
import ipaddress
import os
import re
import socket
import subprocess
from ctypes import wintypes
from dataclasses import dataclass

AF_INET = 2
AF_INET6 = 23

NO_ERROR = 0
ERROR_NOT_FOUND = 1168
ERROR_OBJECT_ALREADY_EXISTS = 5010

MIB_IPPROTO_NETMGMT = 3
NL_ROUTE_ORIGIN_MANUAL = 0
IF_OPER_STATUS_UP = 1

CREATE_NO_WINDOW = 0x08000000

IS_WINDOWS = os.name == "nt"

_FILTER_INSTANCE = re.compile(r"-\d{4}$")


@dataclass(frozen=True)
class Adapter:
    index: int
    alias: str
    description: str
    if_type: int
    up: bool


@dataclass(frozen=True)
class RouteRow:
    ifindex: int
    prefix: str
    prefixlen: int
    gateway: str
    metric: int
    protocol: int


if IS_WINDOWS:

    class SOCKADDR_IN(ctypes.Structure):
        _fields_ = [
            ("sin_family", ctypes.c_ushort),
            ("sin_port", ctypes.c_ushort),
            ("sin_addr", ctypes.c_ubyte * 4),
            ("sin_zero", ctypes.c_ubyte * 8),
        ]

    class SOCKADDR_IN6(ctypes.Structure):
        _fields_ = [
            ("sin6_family", ctypes.c_ushort),
            ("sin6_port", ctypes.c_ushort),
            ("sin6_flowinfo", ctypes.c_ulong),
            ("sin6_addr", ctypes.c_ubyte * 16),
            ("sin6_scope_id", ctypes.c_ulong),
        ]

    class SOCKADDR_INET(ctypes.Union):
        _fields_ = [
            ("Ipv4", SOCKADDR_IN),
            ("Ipv6", SOCKADDR_IN6),
            ("si_family", ctypes.c_ushort),
        ]

    class IP_ADDRESS_PREFIX(ctypes.Structure):
        _fields_ = [("Prefix", SOCKADDR_INET), ("PrefixLength", ctypes.c_ubyte)]

    class MIB_IPFORWARD_ROW2(ctypes.Structure):
        _fields_ = [
            ("InterfaceLuid", ctypes.c_uint64),
            ("InterfaceIndex", ctypes.c_ulong),
            ("DestinationPrefix", IP_ADDRESS_PREFIX),
            ("NextHop", SOCKADDR_INET),
            ("SitePrefixLength", ctypes.c_ubyte),
            ("ValidLifetime", ctypes.c_ulong),
            ("PreferredLifetime", ctypes.c_ulong),
            ("Metric", ctypes.c_ulong),
            ("Protocol", ctypes.c_ulong),
            ("Loopback", ctypes.c_ubyte),
            ("AutoconfigureAddress", ctypes.c_ubyte),
            ("Publish", ctypes.c_ubyte),
            ("Immortal", ctypes.c_ubyte),
            ("Age", ctypes.c_ulong),
            ("Origin", ctypes.c_ulong),
        ]

    class MIB_IF_ROW2(ctypes.Structure):
        _fields_ = [
            ("InterfaceLuid", ctypes.c_uint64),
            ("InterfaceIndex", ctypes.c_ulong),
            ("InterfaceGuid", ctypes.c_ubyte * 16),
            ("Alias", ctypes.c_wchar * 257),
            ("Description", ctypes.c_wchar * 257),
            ("PhysicalAddressLength", ctypes.c_ulong),
            ("PhysicalAddress", ctypes.c_ubyte * 32),
            ("PermanentPhysicalAddress", ctypes.c_ubyte * 32),
            ("Mtu", ctypes.c_ulong),
            ("Type", ctypes.c_ulong),
            ("TunnelType", ctypes.c_ulong),
            ("MediaType", ctypes.c_ulong),
            ("PhysicalMediumType", ctypes.c_ulong),
            ("AccessType", ctypes.c_ulong),
            ("DirectionType", ctypes.c_ulong),
            ("InterfaceAndOperStatusFlags", ctypes.c_ubyte),
            ("OperStatus", ctypes.c_ulong),
            ("AdminStatus", ctypes.c_ulong),
            ("MediaConnectState", ctypes.c_ulong),
            ("NetworkGuid", ctypes.c_ubyte * 16),
            ("ConnectionType", ctypes.c_ulong),
            ("TransmitLinkSpeed", ctypes.c_uint64),
            ("ReceiveLinkSpeed", ctypes.c_uint64),
            ("Stats", ctypes.c_uint64 * 18),
        ]

    class MIB_IPINTERFACE_ROW(ctypes.Structure):
        _fields_ = [
            ("Family", ctypes.c_ushort),
            ("InterfaceLuid", ctypes.c_uint64),
            ("InterfaceIndex", ctypes.c_ulong),
            ("MaxReassemblySize", ctypes.c_ulong),
            ("InterfaceIdentifier", ctypes.c_uint64),
            ("MinRouterAdvertisementInterval", ctypes.c_ulong),
            ("MaxRouterAdvertisementInterval", ctypes.c_ulong),
            ("Flags", ctypes.c_ubyte * 9),
            ("RouterDiscoveryBehavior", ctypes.c_int),
            ("DadTransmits", ctypes.c_ulong),
            ("BaseReachableTime", ctypes.c_ulong),
            ("RetransmitTime", ctypes.c_ulong),
            ("PathMtuDiscoveryTimeout", ctypes.c_ulong),
            ("LinkLocalAddressBehavior", ctypes.c_int),
            ("LinkLocalAddressTimeout", ctypes.c_ulong),
            ("ZoneIndices", ctypes.c_ulong * 16),
            ("SitePrefixLength", ctypes.c_ulong),
            ("Metric", ctypes.c_ulong),
            ("NlMtu", ctypes.c_ulong),
            ("Connected", ctypes.c_ubyte),
            ("SupportsWakeUpPatterns", ctypes.c_ubyte),
            ("SupportsNeighborDiscovery", ctypes.c_ubyte),
            ("SupportsRouterDiscovery", ctypes.c_ubyte),
            ("ReachableTime", ctypes.c_ulong),
            ("TransmitOffload", ctypes.c_ubyte),
            ("ReceiveOffload", ctypes.c_ubyte),
            ("DisableDefaultRoutes", ctypes.c_ubyte),
            # Safety margin so a layout mismatch can never corrupt memory.
            ("_pad", ctypes.c_ubyte * 64),
        ]

    iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)

    _PTR = ctypes.c_void_p
    iphlpapi.InitializeIpForwardEntry.argtypes = [_PTR]
    iphlpapi.InitializeIpForwardEntry.restype = None
    iphlpapi.CreateIpForwardEntry2.argtypes = [_PTR]
    iphlpapi.CreateIpForwardEntry2.restype = ctypes.c_ulong
    iphlpapi.DeleteIpForwardEntry2.argtypes = [_PTR]
    iphlpapi.DeleteIpForwardEntry2.restype = ctypes.c_ulong
    iphlpapi.GetBestRoute2.argtypes = [_PTR, ctypes.c_ulong, _PTR, _PTR, ctypes.c_ulong, _PTR, _PTR]
    iphlpapi.GetBestRoute2.restype = ctypes.c_ulong
    iphlpapi.GetIpForwardTable2.argtypes = [ctypes.c_ushort, _PTR]
    iphlpapi.GetIpForwardTable2.restype = ctypes.c_ulong
    iphlpapi.GetIfTable2.argtypes = [_PTR]
    iphlpapi.GetIfTable2.restype = ctypes.c_ulong
    iphlpapi.GetIpInterfaceEntry.argtypes = [_PTR]
    iphlpapi.GetIpInterfaceEntry.restype = ctypes.c_ulong
    iphlpapi.FreeMibTable.argtypes = [_PTR]
    iphlpapi.FreeMibTable.restype = None

    class SHELLEXECUTEINFOW(ctypes.Structure):
        _fields_ = [
            ("cbSize", wintypes.DWORD),
            ("fMask", ctypes.c_ulong),
            ("hwnd", wintypes.HWND),
            ("lpVerb", wintypes.LPCWSTR),
            ("lpFile", wintypes.LPCWSTR),
            ("lpParameters", wintypes.LPCWSTR),
            ("lpDirectory", wintypes.LPCWSTR),
            ("nShow", ctypes.c_int),
            ("hInstApp", wintypes.HINSTANCE),
            ("lpIDList", ctypes.c_void_p),
            ("lpClass", wintypes.LPCWSTR),
            ("hkeyClass", wintypes.HKEY),
            ("dwHotKey", wintypes.DWORD),
            ("hIconOrMonitor", wintypes.HANDLE),
            ("hProcess", wintypes.HANDLE),
        ]


def _require_windows() -> None:
    if not IS_WINDOWS:
        raise OSError("this operation requires Windows")


def _family_of(address: str) -> int:
    return AF_INET6 if ":" in address else AF_INET


def _sockaddr(address: str):
    family = _family_of(address)
    sa = SOCKADDR_INET()
    raw = socket.inet_pton(family, address.split("%")[0])
    if family == AF_INET:
        sa.Ipv4.sin_family = AF_INET
        for i, value in enumerate(raw):
            sa.Ipv4.sin_addr[i] = value
    else:
        sa.Ipv6.sin6_family = AF_INET6
        for i, value in enumerate(raw):
            sa.Ipv6.sin6_addr[i] = value
    return sa


def _sockaddr_to_str(sa) -> str:
    family = sa.si_family
    if family == AF_INET:
        return socket.inet_ntop(AF_INET, bytes(sa.Ipv4.sin_addr))
    if family == AF_INET6:
        return socket.inet_ntop(AF_INET6, bytes(sa.Ipv6.sin6_addr))
    return ""


def is_admin() -> bool:
    if not IS_WINDOWS:
        return os.geteuid() == 0  # type: ignore[attr-defined]
    try:
        return bool(shell32.IsUserAnAdmin())
    except OSError:
        return False


def best_route_interface(address: str) -> int | None:
    """Interface index Windows would use to reach ``address`` right now."""
    _require_windows()
    dest = _sockaddr(address)
    best = MIB_IPFORWARD_ROW2()
    source = SOCKADDR_INET()
    rc = iphlpapi.GetBestRoute2(
        None, 0, None, ctypes.byref(dest), 0, ctypes.byref(best), ctypes.byref(source)
    )
    if rc != NO_ERROR:
        return None
    return int(best.InterfaceIndex)


def list_routes(family: int) -> list[RouteRow]:
    _require_windows()
    table = ctypes.c_void_p()
    rc = iphlpapi.GetIpForwardTable2(family, ctypes.byref(table))
    if rc != NO_ERROR:
        raise OSError(rc, "GetIpForwardTable2 failed")
    rows: list[RouteRow] = []
    try:
        count = ctypes.c_ulong.from_address(table.value).value
        size = ctypes.sizeof(MIB_IPFORWARD_ROW2)
        base = table.value + 8  # NumEntries + padding to 8-byte alignment
        for i in range(count):
            row = MIB_IPFORWARD_ROW2.from_address(base + i * size)
            rows.append(
                RouteRow(
                    ifindex=int(row.InterfaceIndex),
                    prefix=_sockaddr_to_str(row.DestinationPrefix.Prefix),
                    prefixlen=int(row.DestinationPrefix.PrefixLength),
                    gateway=_sockaddr_to_str(row.NextHop),
                    metric=int(row.Metric),
                    protocol=int(row.Protocol),
                )
            )
    finally:
        iphlpapi.FreeMibTable(table)
    return rows


def list_adapters() -> list[Adapter]:
    _require_windows()
    table = ctypes.c_void_p()
    rc = iphlpapi.GetIfTable2(ctypes.byref(table))
    if rc != NO_ERROR:
        raise OSError(rc, "GetIfTable2 failed")
    adapters: list[Adapter] = []
    try:
        count = ctypes.c_ulong.from_address(table.value).value
        size = ctypes.sizeof(MIB_IF_ROW2)
        base = table.value + 8
        for i in range(count):
            row = MIB_IF_ROW2.from_address(base + i * size)
            if _FILTER_INSTANCE.search(row.Description):
                continue  # NDIS filter instances ("...-WFP ...-0000"), not real adapters
            adapters.append(
                Adapter(
                    index=int(row.InterfaceIndex),
                    alias=row.Alias,
                    description=row.Description,
                    if_type=int(row.Type),
                    up=int(row.OperStatus) == IF_OPER_STATUS_UP,
                )
            )
    finally:
        iphlpapi.FreeMibTable(table)
    return adapters


def interface_metric(ifindex: int, family: int) -> int:
    _require_windows()
    row = MIB_IPINTERFACE_ROW()
    row.Family = family
    row.InterfaceIndex = ifindex
    if iphlpapi.GetIpInterfaceEntry(ctypes.byref(row)) != NO_ERROR:
        return 0
    return int(row.Metric)


def _forward_row(prefix: str, ifindex: int, gateway: str, metric: int):
    network = ipaddress.ip_network(prefix, strict=True)
    row = MIB_IPFORWARD_ROW2()
    iphlpapi.InitializeIpForwardEntry(ctypes.byref(row))
    row.InterfaceLuid = 0
    row.InterfaceIndex = ifindex
    row.DestinationPrefix.Prefix = _sockaddr(str(network.network_address))
    row.DestinationPrefix.PrefixLength = network.prefixlen
    row.NextHop = _sockaddr(gateway)
    row.Metric = metric
    row.Protocol = MIB_IPPROTO_NETMGMT
    row.Origin = NL_ROUTE_ORIGIN_MANUAL
    return row


def add_route(prefix: str, ifindex: int, gateway: str, metric: int) -> bool:
    """Add a non-persistent route. An already existing identical route counts as success."""
    _require_windows()
    row = _forward_row(prefix, ifindex, gateway, metric)
    rc = iphlpapi.CreateIpForwardEntry2(ctypes.byref(row))
    return rc in (NO_ERROR, ERROR_OBJECT_ALREADY_EXISTS)


def delete_route(prefix: str, ifindex: int, gateway: str, metric: int) -> bool:
    _require_windows()
    row = _forward_row(prefix, ifindex, gateway, metric)
    rc = iphlpapi.DeleteIpForwardEntry2(ctypes.byref(row))
    return rc in (NO_ERROR, ERROR_NOT_FOUND)


def run_hidden(args: list[str], timeout: float = 60.0) -> subprocess.CompletedProcess:
    """Run a helper process without flashing a console window."""
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        creationflags=CREATE_NO_WINDOW if IS_WINDOWS else 0,
    )


def run_powershell(script: str, timeout: float = 60.0) -> subprocess.CompletedProcess:
    return run_hidden(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            "[Console]::OutputEncoding=[Text.Encoding]::UTF8; " + script,
        ],
        timeout=timeout,
    )


def tunnel_source_address(probe: str = "1.1.1.1") -> str | None:
    """Local IPv4 address Windows would use as source towards ``probe`` (the tunnel IP when
    foreign traffic goes through the VPN). A UDP connect() sends nothing."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect((probe, 53))
            address = sock.getsockname()[0]
        finally:
            sock.close()
    except OSError:
        return None
    return None if address.startswith(("0.", "127.")) else address


def flush_dns_cache() -> None:
    try:
        run_hidden(["ipconfig.exe", "/flushdns"], timeout=15)
    except (OSError, subprocess.SubprocessError):
        pass


def run_elevated(arguments: list[str], executable: str) -> int:
    """Run ``executable arguments`` through a UAC prompt and wait for it."""
    _require_windows()
    info = SHELLEXECUTEINFOW()
    info.cbSize = ctypes.sizeof(SHELLEXECUTEINFOW)
    info.fMask = 0x00000040  # SEE_MASK_NOCLOSEPROCESS
    info.lpVerb = "runas"
    info.lpFile = executable
    info.lpParameters = subprocess.list2cmdline(arguments)
    info.nShow = 0  # SW_HIDE
    if not shell32.ShellExecuteExW(ctypes.byref(info)):
        return 1223  # ERROR_CANCELLED: user declined the UAC prompt
    kernel32.WaitForSingleObject(info.hProcess, 0xFFFFFFFF)
    code = wintypes.DWORD()
    kernel32.GetExitCodeProcess(info.hProcess, ctypes.byref(code))
    kernel32.CloseHandle(info.hProcess)
    return int(code.value)


class WinNet:
    """The network backend used by the daemon (swapped for a fake in tests)."""

    def adapters(self) -> list[Adapter]:
        return list_adapters()

    def routes(self, family: int) -> list[RouteRow]:
        return list_routes(AF_INET if family == 4 else AF_INET6)

    def best_ifindex(self, address: str) -> int | None:
        return best_route_interface(address)

    def interface_metric(self, ifindex: int, family: int) -> int:
        return interface_metric(ifindex, family)

    def add_routes(self, family: int, ifindex: int, gateway: str, networks: list[str], metric: int) -> int:
        return sum(1 for network in networks if add_route(network, ifindex, gateway, metric))

    def delete_routes(self, family: int, ifindex: int, gateway: str, networks: list[str], metric: int) -> int:
        return sum(1 for network in networks if delete_route(network, ifindex, gateway, metric))
