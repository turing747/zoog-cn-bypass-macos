"""WFP (Windows Filtering Platform) permit rules for ZoogVPN Kill Switch compatibility.

When ZoogVPN's Kill Switch is enabled, it adds ``ZoogKillSwitch`` filters in
``FWPM_SUBLAYER_UNIVERSAL`` on ``FWPM_LAYER_ALE_AUTH_CONNECT_V4`` and ``V6``:
  * ``weight = 1``: catch-all ``FWP_ACTION_BLOCK``;
  * ``weight = 2``: ``FWP_ACTION_PERMIT`` only for the ZoogVPN TUN interface,
    RFC1918 (10/8, 172.16/12, 192.168/16), 127.0.0.1, 1.1.1.1, 223.5.5.5 and
    ZoogVPN's own servers.

That catch-all block breaks two things whenever ZoogVPN is connected:
  1. Tailscale: ``tailscaled.exe`` on Windows binds its outbound control-plane,
     DERP and UDP STUN/disco sockets (``IP_UNICAST_IF``) to the interface
     holding the ``0.0.0.0/0`` route (the physical NIC, since OpenVPN uses
     ``0.0.0.0/1`` + ``128.0.0.0/1``). ``ZoogKillSwitch`` blocks the physical
     NIC and also blocks the ``Tailscale`` Wintun interface and ``100.64.0.0/10``
     (CGNAT) / ``fd7a:115c:a1e0::/48`` (ULA), causing ``tailscaled.exe`` to fail
     with ``WSAEACCES (10013)`` and appear offline to all other Tailscale nodes
     (or stay stuck at ``Starting...`` when restarted).
  2. China-direct routes: routes added by ZoogCNBypass point to the physical NIC,
     so ``ZoogKillSwitch`` blocks every China IP except ``223.5.5.5``.

To solve both while keeping foreign traffic inside the VPN tunnel, this module
installs ``weight = 3`` ``FWP_ACTION_PERMIT`` filters in ``FWPM_SUBLAYER_UNIVERSAL``
for:
  * the active physical adapter LUID (used by China-direct routes and Tailscale's
    ``IP_UNICAST_IF`` sockets);
  * the Tailscale adapter LUID, ``100.64.0.0/10``, ``fd7a:115c:a1e0::/48`` and
    Tailscale binaries (``tailscaled.exe``, ``tailscale.exe``, ``tailscale-ipn.exe``);
  * IPv6 loopback ``::1/128``.
"""

from __future__ import annotations

import ctypes
import ipaddress
import logging
import os
import time
import uuid
from ctypes import wintypes
from pathlib import Path

from . import winnet

log = logging.getLogger("zoog.wfp")

WFP_FILTER_NAME = "ZoogCNBypass"
WFP_FILTER_DESC = "ZoogCNBypass split routing and Tailscale permit"
WFP_WEIGHT = 3

RPC_C_AUTHN_WINNT = 10

# FWP_DATA_TYPE values from Windows SDK shared/fwptypes.h:
# FWP_SINGLE_DATA_TYPE_MAX = 0xFF, so FWP_V4_ADDR_MASK = 0x100 and FWP_V6_ADDR_MASK = 0x101.
FWP_EMPTY = 0
FWP_UINT8 = 1
FWP_UINT64 = 4
FWP_BYTE_BLOB_TYPE = 12
FWP_V4_ADDR_MASK = 0x100
FWP_V6_ADDR_MASK = 0x101

FWP_MATCH_EQUAL = 0
FWP_ACTION_PERMIT = 0x00001002

FWP_E_FILTER_NOT_FOUND = 0x80320003

_LAYER_ALE_AUTH_CONNECT_V4 = "c38d57d1-05a7-4c33-904f-7fbceee60e82"
_LAYER_ALE_AUTH_CONNECT_V6 = "4a72393b-319f-44bc-84c3-ba54dcb3b6b4"
_SUBLAYER_UNIVERSAL = "eebecc03-ced4-4380-819a-2734397b2b74"
_COND_IP_LOCAL_INTERFACE = "4cd62a49-59c3-4969-b7f3-bda5d32890a4"
_COND_IP_REMOTE_ADDRESS = "b235ae9a-1d64-49b8-a44c-5ff3d9095045"
_COND_ALE_APP_ID = "d78e1e87-8644-4ea5-9437-d809ecefc971"

_WFP_NAMESPACE = uuid.UUID("8f5c41f7-2918-4d9c-963b-7461696c7a67")

_STATIC_ROLES = (
    "physical-v4",
    "physical-v6",
    "loopback-v6",
    "tailscale-cgnat-v4",
    "tailscale-ula-v6",
    "tailscale-if-v4",
    "tailscale-if-v6",
    "tailscale-if-v4-1",
    "tailscale-if-v6-1",
    "tailscale-app-v4-tailscaled",
    "tailscale-app-v6-tailscaled",
    "tailscale-app-v4-tailscale",
    "tailscale-app-v6-tailscale",
    "tailscale-app-v4-tailscale-ipn",
    "tailscale-app-v6-tailscale-ipn",
)


class GUID(ctypes.Structure):
    _fields_ = [("Data", ctypes.c_ubyte * 16)]

    @classmethod
    def from_uuid(cls, value: uuid.UUID) -> "GUID":
        return cls((ctypes.c_ubyte * 16)(*value.bytes_le))

    @classmethod
    def from_str(cls, text: str) -> "GUID":
        return cls.from_uuid(uuid.UUID(text))


class FWP_BYTE_BLOB(ctypes.Structure):
    _fields_ = [("size", ctypes.c_uint32), ("data", ctypes.c_void_p)]


class FWPM_DISPLAY_DATA0(ctypes.Structure):
    _fields_ = [("name", wintypes.LPCWSTR), ("description", wintypes.LPCWSTR)]


class FWP_V4_ADDR_AND_MASK(ctypes.Structure):
    _fields_ = [("addr", ctypes.c_uint32), ("mask", ctypes.c_uint32)]


class FWP_V6_ADDR_AND_MASK(ctypes.Structure):
    _fields_ = [("addr", ctypes.c_ubyte * 16), ("prefixLength", ctypes.c_uint8)]


class _FWP_VALUE_UNION(ctypes.Union):
    _fields_ = [
        ("uint8", ctypes.c_uint8),
        ("uint16", ctypes.c_uint16),
        ("uint32", ctypes.c_uint32),
        ("uint64", ctypes.POINTER(ctypes.c_uint64)),
        ("v4AddrMask", ctypes.POINTER(FWP_V4_ADDR_AND_MASK)),
        ("v6AddrMask", ctypes.POINTER(FWP_V6_ADDR_AND_MASK)),
        ("byteBlob", ctypes.POINTER(FWP_BYTE_BLOB)),
    ]


class FWP_VALUE0(ctypes.Structure):
    _fields_ = [("type", ctypes.c_int), ("u", _FWP_VALUE_UNION)]


class FWP_CONDITION_VALUE0(ctypes.Structure):
    _fields_ = [("type", ctypes.c_int), ("u", _FWP_VALUE_UNION)]


class FWPM_FILTER_CONDITION0(ctypes.Structure):
    _fields_ = [
        ("fieldKey", GUID),
        ("matchType", ctypes.c_int),
        ("conditionValue", FWP_CONDITION_VALUE0),
    ]


class _FWPM_ACTION_UNION(ctypes.Union):
    _fields_ = [
        ("filterType", GUID),
        ("calloutKey", GUID),
        ("bitmapIndex", ctypes.c_uint8),
    ]


class FWPM_ACTION0(ctypes.Structure):
    _fields_ = [("type", ctypes.c_uint32), ("u", _FWPM_ACTION_UNION)]


class _FWPM_FILTER_CONTEXT_UNION(ctypes.Union):
    _fields_ = [("rawContext", ctypes.c_uint64), ("providerContextKey", GUID)]


class FWPM_FILTER0(ctypes.Structure):
    _fields_ = [
        ("filterKey", GUID),
        ("displayData", FWPM_DISPLAY_DATA0),
        ("flags", ctypes.c_uint32),
        ("providerKey", ctypes.POINTER(GUID)),
        ("providerData", FWP_BYTE_BLOB),
        ("layerKey", GUID),
        ("subLayerKey", GUID),
        ("weight", FWP_VALUE0),
        ("numFilterConditions", ctypes.c_uint32),
        ("filterCondition", ctypes.POINTER(FWPM_FILTER_CONDITION0)),
        ("action", FWPM_ACTION0),
        ("context", _FWPM_FILTER_CONTEXT_UNION),
        ("reserved", ctypes.POINTER(GUID)),
        ("filterId", ctypes.c_uint64),
        ("effectiveWeight", FWP_VALUE0),
    ]


if winnet.IS_WINDOWS:
    _fwpuclnt = ctypes.WinDLL("fwpuclnt", use_last_error=True)
    _iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)

    _PTR = ctypes.c_void_p
    _iphlpapi.ConvertInterfaceIndexToLuid.argtypes = [
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_uint64),
    ]
    _iphlpapi.ConvertInterfaceIndexToLuid.restype = ctypes.c_ulong

    _fwpuclnt.FwpmEngineOpen0.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        _PTR,
        _PTR,
        ctypes.POINTER(_PTR),
    ]
    _fwpuclnt.FwpmEngineOpen0.restype = ctypes.c_ulong
    _fwpuclnt.FwpmEngineClose0.argtypes = [_PTR]
    _fwpuclnt.FwpmEngineClose0.restype = ctypes.c_ulong

    _fwpuclnt.FwpmTransactionBegin0.argtypes = [_PTR, ctypes.c_uint32]
    _fwpuclnt.FwpmTransactionBegin0.restype = ctypes.c_ulong
    _fwpuclnt.FwpmTransactionCommit0.argtypes = [_PTR]
    _fwpuclnt.FwpmTransactionCommit0.restype = ctypes.c_ulong
    _fwpuclnt.FwpmTransactionAbort0.argtypes = [_PTR]
    _fwpuclnt.FwpmTransactionAbort0.restype = ctypes.c_ulong

    _fwpuclnt.FwpmFilterAdd0.argtypes = [
        _PTR,
        ctypes.POINTER(FWPM_FILTER0),
        _PTR,
        ctypes.POINTER(ctypes.c_uint64),
    ]
    _fwpuclnt.FwpmFilterAdd0.restype = ctypes.c_ulong
    _fwpuclnt.FwpmFilterDeleteByKey0.argtypes = [_PTR, ctypes.POINTER(GUID)]
    _fwpuclnt.FwpmFilterDeleteByKey0.restype = ctypes.c_ulong
    _fwpuclnt.FwpmFilterGetByKey0.argtypes = [_PTR, ctypes.POINTER(GUID), ctypes.POINTER(_PTR)]
    _fwpuclnt.FwpmFilterGetByKey0.restype = ctypes.c_ulong

    _fwpuclnt.FwpmGetAppIdFromFileName0.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(_PTR)]
    _fwpuclnt.FwpmGetAppIdFromFileName0.restype = ctypes.c_ulong
    _fwpuclnt.FwpmFreeMemory0.argtypes = [ctypes.POINTER(_PTR)]
    _fwpuclnt.FwpmFreeMemory0.restype = None


def role_guid(role: str) -> GUID:
    return GUID.from_uuid(uuid.uuid5(_WFP_NAMESPACE, role))


def ifindex_to_luid(ifindex: int) -> int | None:
    if not winnet.IS_WINDOWS:
        return None
    luid = ctypes.c_uint64()
    if _iphlpapi.ConvertInterfaceIndexToLuid(int(ifindex), ctypes.byref(luid)) != 0:
        return None
    return int(luid.value)


def tailscale_executables() -> list[Path]:
    candidates: list[Path] = []
    seen: set[str] = set()
    for env_name in ("ProgramFiles", "ProgramFiles(x86)"):
        base = os.environ.get(env_name)
        if not base:
            continue
        ts_dir = Path(base) / "Tailscale"
        for exe_name in ("tailscaled.exe", "tailscale.exe", "tailscale-ipn.exe"):
            path = ts_dir / exe_name
            key = str(path).lower()
            if key not in seen and path.is_file():
                seen.add(key)
                candidates.append(path)
    return candidates


def kick_tailscale() -> None:
    """Wake ``tailscaled`` out of any control-plane/DERP backoff after WFP permits change."""
    if not winnet.IS_WINDOWS:
        return
    winnet.flush_dns_cache()
    for exe in tailscale_executables():
        if exe.name.lower() == "tailscale.exe":
            try:
                res = winnet.run_hidden([str(exe), "debug", "rebind"], timeout=5.0)
                combined = (res.stdout or "") + (res.stderr or "")
                if res.returncode != 0 and "NoState" in combined:
                    log.info("Tailscale is stuck in NoState (Starting...); restarting Tailscale service")
                    winnet.run_powershell(
                        "Restart-Service -Name Tailscale -Force -ErrorAction SilentlyContinue",
                        timeout=15.0,
                    )
                    return
                winnet.run_hidden([str(exe), "debug", "force-netmap-update"], timeout=5.0)
            except Exception:
                pass
            break


def _build_base_filter(role: str, layer_guid: str, cond: FWPM_FILTER_CONDITION0) -> FWPM_FILTER0:
    flt = FWPM_FILTER0()
    flt.filterKey = role_guid(role)
    flt.displayData.name = WFP_FILTER_NAME
    flt.displayData.description = WFP_FILTER_DESC
    flt.flags = 0  # non-persistent: never survives reboot if daemon is uninstalled
    flt.layerKey = GUID.from_str(layer_guid)
    flt.subLayerKey = GUID.from_str(_SUBLAYER_UNIVERSAL)
    flt.weight.type = FWP_UINT8
    flt.weight.u.uint8 = WFP_WEIGHT
    flt.numFilterConditions = 1
    flt.filterCondition = ctypes.pointer(cond)
    flt.action.type = FWP_ACTION_PERMIT
    return flt


def _add_interface_permit(engine, role: str, family: int, luid_value: int) -> bool:
    layer = _LAYER_ALE_AUTH_CONNECT_V4 if family == 4 else _LAYER_ALE_AUTH_CONNECT_V6
    luid = ctypes.c_uint64(luid_value)
    cond = FWPM_FILTER_CONDITION0()
    cond.fieldKey = GUID.from_str(_COND_IP_LOCAL_INTERFACE)
    cond.matchType = FWP_MATCH_EQUAL
    cond.conditionValue.type = FWP_UINT64
    cond.conditionValue.u.uint64 = ctypes.pointer(luid)
    flt = _build_base_filter(role, layer, cond)
    key = flt.filterKey
    _fwpuclnt.FwpmFilterDeleteByKey0(engine, ctypes.byref(key))
    filter_id = ctypes.c_uint64()
    rc = _fwpuclnt.FwpmFilterAdd0(engine, ctypes.byref(flt), None, ctypes.byref(filter_id))
    if rc != 0:
        log.warning("FwpmFilterAdd0(%s) failed: 0x%08x", role, rc)
        return False
    return True


def _add_v4_subnet_permit(engine, role: str, cidr: str) -> bool:
    net = ipaddress.IPv4Network(cidr, strict=True)
    v4 = FWP_V4_ADDR_AND_MASK(
        addr=int(net.network_address),
        mask=int(net.netmask),
    )
    cond = FWPM_FILTER_CONDITION0()
    cond.fieldKey = GUID.from_str(_COND_IP_REMOTE_ADDRESS)
    cond.matchType = FWP_MATCH_EQUAL
    cond.conditionValue.type = FWP_V4_ADDR_MASK
    cond.conditionValue.u.v4AddrMask = ctypes.pointer(v4)
    flt = _build_base_filter(role, _LAYER_ALE_AUTH_CONNECT_V4, cond)
    key = flt.filterKey
    _fwpuclnt.FwpmFilterDeleteByKey0(engine, ctypes.byref(key))
    filter_id = ctypes.c_uint64()
    rc = _fwpuclnt.FwpmFilterAdd0(engine, ctypes.byref(flt), None, ctypes.byref(filter_id))
    if rc != 0:
        log.warning("FwpmFilterAdd0(%s) failed: 0x%08x", role, rc)
        return False
    return True


def _add_v6_subnet_permit(engine, role: str, cidr: str) -> bool:
    net = ipaddress.IPv6Network(cidr, strict=True)
    v6 = FWP_V6_ADDR_AND_MASK(
        addr=(ctypes.c_ubyte * 16)(*net.network_address.packed),
        prefixLength=net.prefixlen,
    )
    cond = FWPM_FILTER_CONDITION0()
    cond.fieldKey = GUID.from_str(_COND_IP_REMOTE_ADDRESS)
    cond.matchType = FWP_MATCH_EQUAL
    cond.conditionValue.type = FWP_V6_ADDR_MASK
    cond.conditionValue.u.v6AddrMask = ctypes.pointer(v6)
    flt = _build_base_filter(role, _LAYER_ALE_AUTH_CONNECT_V6, cond)
    key = flt.filterKey
    _fwpuclnt.FwpmFilterDeleteByKey0(engine, ctypes.byref(key))
    filter_id = ctypes.c_uint64()
    rc = _fwpuclnt.FwpmFilterAdd0(engine, ctypes.byref(flt), None, ctypes.byref(filter_id))
    if rc != 0:
        log.warning("FwpmFilterAdd0(%s) failed: 0x%08x", role, rc)
        return False
    return True


def _add_app_permit(engine, role: str, family: int, exe_path: Path) -> bool:
    blob_ptr = ctypes.c_void_p()
    if _fwpuclnt.FwpmGetAppIdFromFileName0(str(exe_path), ctypes.byref(blob_ptr)) != 0 or not blob_ptr.value:
        return False
    try:
        layer = _LAYER_ALE_AUTH_CONNECT_V4 if family == 4 else _LAYER_ALE_AUTH_CONNECT_V6
        cond = FWPM_FILTER_CONDITION0()
        cond.fieldKey = GUID.from_str(_COND_ALE_APP_ID)
        cond.matchType = FWP_MATCH_EQUAL
        cond.conditionValue.type = FWP_BYTE_BLOB_TYPE
        cond.conditionValue.u.byteBlob = ctypes.cast(blob_ptr, ctypes.POINTER(FWP_BYTE_BLOB))
        flt = _build_base_filter(role, layer, cond)
        key = flt.filterKey
        _fwpuclnt.FwpmFilterDeleteByKey0(engine, ctypes.byref(key))
        filter_id = ctypes.c_uint64()
        rc = _fwpuclnt.FwpmFilterAdd0(engine, ctypes.byref(flt), None, ctypes.byref(filter_id))
        if rc != 0:
            log.warning("FwpmFilterAdd0(%s) failed: 0x%08x", role, rc)
            return False
        return True
    finally:
        _fwpuclnt.FwpmFreeMemory0(ctypes.byref(blob_ptr))


def _delete_all_in_engine(engine, extra_roles: tuple[str, ...] = ()) -> int:
    deleted = 0
    for role in _STATIC_ROLES + extra_roles:
        key = role_guid(role)
        if _fwpuclnt.FwpmFilterDeleteByKey0(engine, ctypes.byref(key)) == 0:
            deleted += 1
    return deleted


def wfp_permits_active() -> bool:
    """Read-only check (works without Administrator rights)."""
    if not winnet.IS_WINDOWS:
        return False
    engine = ctypes.c_void_p()
    if _fwpuclnt.FwpmEngineOpen0(None, RPC_C_AUTHN_WINNT, None, None, ctypes.byref(engine)) != 0:
        return False
    try:
        for role in ("physical-v4", "tailscale-cgnat-v4"):
            key = role_guid(role)
            ptr = ctypes.c_void_p()
            rc = _fwpuclnt.FwpmFilterGetByKey0(engine, ctypes.byref(key), ctypes.byref(ptr))
            if ptr.value:
                _fwpuclnt.FwpmFreeMemory0(ctypes.byref(ptr))
            if rc != 0:
                return False
        return True
    finally:
        _fwpuclnt.FwpmEngineClose0(engine)


def ensure_wfp_permits(
    v4_ifindex: int,
    v6_ifindex: int | None = None,
    tailscale_ifindexes: tuple[int, ...] = (),
) -> tuple[bool, bool]:
    """Ensure WFP permit rules are installed. Returns ``(ok, newly_installed)``."""
    if not winnet.IS_WINDOWS:
        return True, False
    v4_luid = ifindex_to_luid(v4_ifindex)
    if v4_luid is None:
        return False, False
    v6_luid = ifindex_to_luid(v6_ifindex) if v6_ifindex is not None else None
    ts_luids = [
        luid
        for idx in tailscale_ifindexes
        for luid in (ifindex_to_luid(idx),)
        if luid is not None
    ]

    engine = ctypes.c_void_p()
    if _fwpuclnt.FwpmEngineOpen0(None, RPC_C_AUTHN_WINNT, None, None, ctypes.byref(engine)) != 0:
        return False, False
    try:
        if _fwpuclnt.FwpmTransactionBegin0(engine, 0) != 0:
            return False, False
        try:
            _delete_all_in_engine(engine)
            ok = _add_interface_permit(engine, "physical-v4", 4, v4_luid)
            if v6_luid is not None:
                ok = _add_interface_permit(engine, "physical-v6", 6, v6_luid) and ok
            ok = _add_v6_subnet_permit(engine, "loopback-v6", "::1/128") and ok
            ok = _add_v4_subnet_permit(engine, "tailscale-cgnat-v4", "100.64.0.0/10") and ok
            ok = _add_v6_subnet_permit(engine, "tailscale-ula-v6", "fd7a:115c:a1e0::/48") and ok
            for i, luid in enumerate(ts_luids[:2]):
                suffix = "" if i == 0 else f"-{i}"
                ok = _add_interface_permit(engine, f"tailscale-if-v4{suffix}", 4, luid) and ok
                ok = _add_interface_permit(engine, f"tailscale-if-v6{suffix}", 6, luid) and ok
            for exe in tailscale_executables():
                stem = exe.stem.lower()
                _add_app_permit(engine, f"tailscale-app-v4-{stem}", 4, exe)
                _add_app_permit(engine, f"tailscale-app-v6-{stem}", 6, exe)
            if not ok:
                _fwpuclnt.FwpmTransactionAbort0(engine)
                return False, False
            if _fwpuclnt.FwpmTransactionCommit0(engine) != 0:
                return False, False
            log.info("WFP Kill Switch permit rules active (physical ifIndex %d, tailscale %s)", v4_ifindex, tailscale_ifindexes)
            return True, True
        except Exception:
            _fwpuclnt.FwpmTransactionAbort0(engine)
            raise
    finally:
        _fwpuclnt.FwpmEngineClose0(engine)


def remove_wfp_permits() -> bool:
    """Remove all WFP filters created by ZoogCNBypass."""
    if not winnet.IS_WINDOWS:
        return True
    engine = ctypes.c_void_p()
    if _fwpuclnt.FwpmEngineOpen0(None, RPC_C_AUTHN_WINNT, None, None, ctypes.byref(engine)) != 0:
        return False
    try:
        if _fwpuclnt.FwpmTransactionBegin0(engine, 0) != 0:
            return False
        try:
            _delete_all_in_engine(engine)
            return _fwpuclnt.FwpmTransactionCommit0(engine) == 0
        except Exception:
            _fwpuclnt.FwpmTransactionAbort0(engine)
            return False
    finally:
        _fwpuclnt.FwpmEngineClose0(engine)


class WfpPermit:
    """Stateful wrapper with a short cache to avoid re-building WFP rules every 3 seconds."""

    def __init__(self, cache_seconds: float = 3.0) -> None:
        self.cache_seconds = cache_seconds
        self._target: tuple[int, int | None, tuple[int, ...]] | None = None
        self._checked_at = 0.0

    def ensure(
        self,
        v4_ifindex: int,
        v6_ifindex: int | None = None,
        tailscale_ifindexes: tuple[int, ...] = (),
    ) -> bool:
        wanted = (v4_ifindex, v6_ifindex, tuple(sorted(tailscale_ifindexes)))
        now = time.monotonic()
        if self._target == wanted:
            if now - self._checked_at < self.cache_seconds:
                return True
            if wfp_permits_active():
                self._checked_at = now
                return True
        ok, installed = ensure_wfp_permits(v4_ifindex, v6_ifindex, wanted[2])
        if ok:
            self._target = wanted
            self._checked_at = now
            if installed:
                kick_tailscale()
        return ok

    def remove(self) -> bool:
        self._target = None
        self._checked_at = 0.0
        return remove_wfp_permits()
