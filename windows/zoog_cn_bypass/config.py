"""Paths, constants and optional user configuration."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

TASK_NAME = "ZoogCNBypass"
NRPT_COMMENT = "ZoogCNBypass"
MUTEX_NAME = "Global\\ZoogCNBypass"

LOCAL_DNS = "127.0.0.1"
LOCAL_DNS_PORT = 53

# Upstreams (ip, port). Domestic names go to AliDNS directly over the physical
# NIC; everything else goes to resolvers whose IPs stay inside the VPN tunnel.
CN_UPSTREAMS = (("223.5.5.5", 53), ("223.6.6.6", 53))
FOREIGN_UPSTREAMS = (("1.1.1.1", 53), ("8.8.8.8", 53))
# DoH endpoints (host, path) used for domestic names in compatibility mode.
DOH_UPSTREAMS = (("223.5.5.5", "/dns-query"), ("223.6.6.6", "/dns-query"))

# Probe addresses (same idea as daemon.sh).
FOREIGN_PROBE_V4 = "1.1.1.1"
CN_PROBES_V4 = ("223.5.5.5", "114.114.114.114")
CN_PROBES_V6 = ("2400:3200::1", "240c::6666")

# Route metric used for every route we add; also lets `cleanup` recognise them.
ROUTE_METRIC = 5

# Adapter name/description patterns (case-insensitive substrings).
DEFAULT_VPN_PATTERNS = ("ZoogVPN", "Wintun", "Amnezia", "WireGuard", "OpenVPN", "TAP-Windows")
DEFAULT_VIRTUAL_PATTERNS = (
    "ZoogVPN", "Wintun", "Amnezia", "WireGuard", "OpenVPN", "TAP-", "Tailscale",
    "vEthernet", "Hyper-V", "VMware", "VirtualBox", "Sangfor", "Bluetooth",
    "Wi-Fi Direct", "Loopback", "WSL", "Npcap", "Teredo", "ISATAP", "6to4",
)
PHYSICAL_IF_TYPES = (6, 71, 243, 244)  # Ethernet, Wi-Fi, WWAN
TUNNEL_IF_TYPES = (23, 53, 131)  # PPP, proprietary virtual (Wintun/TAP), tunnel


def install_dir() -> Path:
    override = os.environ.get("ZOOG_CN_HOME")
    if override:
        return Path(override)
    return Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "ZoogCNBypass"


def app_dir() -> Path:
    return install_dir() / "app"


def installed_data_dir() -> Path:
    return install_dir() / "data"


def state_dir() -> Path:
    return install_dir() / "state"


def log_dir() -> Path:
    return install_dir() / "logs"


def package_dir() -> Path:
    return Path(__file__).resolve().parent


def frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def source_data_dir() -> Path | None:
    """Data shipped with the repo (windows/../data) or bundled with an exe."""
    candidates = [package_dir().parent.parent / "data", package_dir() / "data"]
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidates.insert(0, Path(meipass) / "data")
    for candidate in candidates:
        if (candidate / "cn-ipv4.txt").is_file():
            return candidate
    return None


def runtime_data_dir() -> Path:
    """Data used by the daemon: installed copy first, repo copy as a fallback."""
    installed = installed_data_dir()
    if (installed / "cn-ipv4.txt").is_file():
        return installed
    source = source_data_dir()
    if source is None:
        raise FileNotFoundError("cn-ipv4.txt not found; run `install` or run from the repository")
    return source


DATA_FILES = (
    "cn-ipv4.txt",
    "cn-ipv6.txt",
    "accelerated-domains.china.conf",
    "apple.china.conf",
)


class Settings:
    """Defaults, overridable through ``<install dir>\\config.json``."""

    def __init__(self, overrides: dict | None = None) -> None:
        overrides = overrides or {}
        self.vpn_patterns = tuple(overrides.get("vpn_adapter_patterns", DEFAULT_VPN_PATTERNS))
        self.virtual_patterns = tuple(
            overrides.get("virtual_adapter_patterns", DEFAULT_VIRTUAL_PATTERNS)
        )
        self.poll_seconds = float(overrides.get("poll_seconds", 3.0))
        self.cn_upstreams = tuple(
            (str(h), int(p)) for h, p in overrides.get("cn_upstreams", CN_UPSTREAMS)
        )
        self.foreign_upstreams = tuple(
            (str(h), int(p)) for h, p in overrides.get("foreign_upstreams", FOREIGN_UPSTREAMS)
        )
        # Compatibility mode (opt-in): for VPN clients whose DNS-leak protection blocks
        # port 53 on every non-tunnel interface (including 127.0.0.1).
        self.compat_mode = bool(overrides.get("compat_mode", False))
        self.doh_upstreams = tuple(
            (str(h), str(p)) for h, p in overrides.get("doh_upstreams", DOH_UPSTREAMS)
        )

    @classmethod
    def load(cls) -> "Settings":
        path = install_dir() / "config.json"
        try:
            return cls(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, ValueError, TypeError):
            return cls()


DEFAULT_CONFIG_JSON = json.dumps(
    {
        "vpn_adapter_patterns": list(DEFAULT_VPN_PATTERNS),
        "virtual_adapter_patterns": list(DEFAULT_VIRTUAL_PATTERNS),
        "poll_seconds": 3.0,
        "compat_mode": False,
    },
    indent=2,
) + "\n"
