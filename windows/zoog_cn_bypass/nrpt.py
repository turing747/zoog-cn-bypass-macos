"""System default resolver override through a catch-all NRPT rule.

``Add-DnsClientNrptRule -Namespace '.'`` is the Windows counterpart of the macOS
``SupplementalMatchDomains = ""`` scutil entry: every name that has no more
specific NRPT rule (e.g. Tailscale's) is sent to the local split-DNS proxy.
"""

from __future__ import annotations

import time

from . import winnet
from .config import LOCAL_DNS, NRPT_COMMENT

_EXISTS_SCRIPT = (
    "(Get-DnsClientNrptRule | Where-Object { $_.Comment -eq '%s' } | Measure-Object).Count"
    % NRPT_COMMENT
)


def _count_rules() -> int | None:
    try:
        result = winnet.run_powershell(_EXISTS_SCRIPT, timeout=30)
    except Exception:
        return None
    if result.returncode != 0:
        return None
    try:
        return int(result.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return None


class Nrpt:
    """NRPT control with a short-lived cache (PowerShell is slow to start)."""

    def __init__(self, cache_seconds: float = 30.0) -> None:
        self.cache_seconds = cache_seconds
        self.server: str | None = None  # name server of the rule this process added
        self._known: bool | None = None
        self._checked_at = 0.0

    def exists(self, force: bool = False) -> bool:
        now = time.monotonic()
        if force or self._known is None or now - self._checked_at > self.cache_seconds:
            count = _count_rules()
            self._known = bool(count) if count is not None else bool(self._known)
            self._checked_at = now
        return bool(self._known)

    def add(self, server: str = LOCAL_DNS) -> bool:
        self.remove()  # never leave duplicates behind
        script = (
            "Add-DnsClientNrptRule -Namespace '.' -NameServers '%s' "
            "-Comment '%s' -DisplayName 'ZoogCNBypass split DNS' -ErrorAction Stop | Out-Null"
            % (server, NRPT_COMMENT)
        )
        result = winnet.run_powershell(script, timeout=60)
        ok = result.returncode == 0
        self._known = ok if ok else self.exists(force=True)
        self.server = server if ok else None
        self._checked_at = time.monotonic()
        if ok:
            winnet.flush_dns_cache()
        return ok

    def remove(self) -> bool:
        script = (
            "Get-DnsClientNrptRule | Where-Object { $_.Comment -eq '%s' } | "
            "Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue" % NRPT_COMMENT
        )
        result = winnet.run_powershell(script, timeout=60)
        self._known = False
        self.server = None
        self._checked_at = time.monotonic()
        winnet.flush_dns_cache()
        return result.returncode == 0
