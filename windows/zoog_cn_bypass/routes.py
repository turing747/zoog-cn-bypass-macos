"""CIDR validation (mirrors daemon.sh) and the persistent state store."""

from __future__ import annotations

import ipaddress
import os
import time
from pathlib import Path

_PRIVATE_V4 = tuple(
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "192.168.0.0/16",
        "172.16.0.0/12",
        "100.64.0.0/10",
    )
)
_PROTECTED_V4 = (ipaddress.ip_network("1.1.1.1/32"), ipaddress.ip_network("8.8.8.8/32"))


def valid_ipv4_cidr(text: str) -> bool:
    try:
        net = ipaddress.IPv4Network(text, strict=True)
    except ValueError:
        return False
    if not 8 <= net.prefixlen <= 32:
        return False
    return not any(net.overlaps(p) for p in _PRIVATE_V4 + _PROTECTED_V4)


def valid_ipv6_cidr(text: str) -> bool:
    try:
        net = ipaddress.IPv6Network(text, strict=True)
    except ValueError:
        return False
    if text[:1] not in ("2", "3"):
        return False
    return 16 <= net.prefixlen <= 128


def valid_ipv4_gateway(text: str) -> bool:
    try:
        address = ipaddress.IPv4Address(text)
    except ValueError:
        return False
    return not (address.is_unspecified or address.is_multicast or address.is_loopback)


def valid_ipv6_gateway(text: str) -> bool:
    try:
        address = ipaddress.IPv6Address(text.split("%")[0])
    except ValueError:
        return False
    return address in ipaddress.ip_network("fe80::/10")


def load_networks(path: Path, family: int) -> list[str]:
    """Load, validate and de-duplicate a route list; invalid lines are skipped."""
    check = valid_ipv4_cidr if family == 4 else valid_ipv6_cidr
    seen: dict[str, None] = {}
    with open(path, encoding="utf-8") as handle:
        for raw in handle:
            line = raw.strip()
            if line and check(line):
                seen[line] = None
    return list(seen)


class StateStore:
    """Small text-file state kept under ``<install dir>\\state``."""

    def __init__(self, directory: Path) -> None:
        self.dir = Path(directory)
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass  # read-only users (status) may not be allowed to create it
        self.state_file = self.dir / "state"
        self.error_file = self.dir / "error"

    def _active_file(self, family: int) -> Path:
        return self.dir / f"active-v{family}.txt"

    @staticmethod
    def _atomic_write(path: Path, text: str) -> None:
        temporary = path.with_name(path.name + f".{os.getpid()}.tmp")
        temporary.write_text(text, encoding="utf-8")
        os.replace(temporary, path)

    def read_state(self) -> str | None:
        try:
            return self.state_file.read_text(encoding="utf-8").strip()
        except OSError:
            return None

    def write_state(self, state: str) -> None:
        self._atomic_write(self.state_file, state + "\n")

    def read_active(self, family: int) -> tuple[str, int, list[str]] | None:
        """(gateway, ifindex, networks) of the routes we installed, if any."""
        try:
            lines = self._active_file(family).read_text(encoding="utf-8").splitlines()
        except OSError:
            return None
        if not lines:
            return None
        try:
            gateway, ifindex = lines[0].split("|")
            return gateway, int(ifindex), [n for n in lines[1:] if n]
        except ValueError:
            return None

    def write_active(self, family: int, gateway: str, ifindex: int, networks: list[str]) -> None:
        body = f"{gateway}|{ifindex}\n" + "".join(f"{n}\n" for n in networks)
        self._atomic_write(self._active_file(family), body)

    def active_count(self, family: int) -> int:
        active = self.read_active(family)
        return len(active[2]) if active else 0

    def clear_active(self, family: int) -> None:
        self._unlink(self._active_file(family))

    def clear_state(self) -> None:
        self._unlink(self.state_file)

    def has_any(self) -> bool:
        return (
            self.state_file.exists()
            or self._active_file(4).exists()
            or self._active_file(6).exists()
        )

    def read_error(self) -> str | None:
        try:
            return self.error_file.read_text(encoding="utf-8").strip() or None
        except OSError:
            return None

    def write_error(self, message: str) -> None:
        self._atomic_write(self.error_file, message + "\n")

    def clear_error(self) -> None:
        self._unlink(self.error_file)

    def touch_heartbeat(self) -> None:
        try:
            self._atomic_write(self.dir / "heartbeat", f"{time.time():.0f}\n")
        except OSError:
            pass

    def heartbeat_age(self) -> float | None:
        """Seconds since the daemon last completed a loop (None if never)."""
        try:
            return max(0.0, time.time() - float((self.dir / "heartbeat").read_text().strip()))
        except (OSError, ValueError):
            return None

    @staticmethod
    def _unlink(path: Path) -> None:
        try:
            path.unlink()
        except OSError:
            pass
