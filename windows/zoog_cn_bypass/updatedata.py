"""Refresh data/ from APNIC and dnsmasq-china-list (port of scripts/update-data.sh)."""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import tempfile
import urllib.request
from pathlib import Path

from . import config

APNIC_URL = "https://ftp.apnic.net/stats/apnic/delegated-apnic-latest"
ACCELERATED_URL = "https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf"
APPLE_URL = "https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/apple.china.conf"
COMMIT_URL = "https://api.github.com/repos/felixonmars/dnsmasq-china-list/commits/master"

_LINE = re.compile(r"^server=/[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*/223\.5\.5\.5$")


def _download(url: str, destination: Path) -> None:
    if not url.startswith("https://"):
        raise ValueError("only https downloads are allowed")
    request = urllib.request.Request(url, headers={"User-Agent": "zoog-cn-bypass"})
    with urllib.request.urlopen(request, timeout=120) as response, open(destination, "wb") as handle:
        shutil.copyfileobj(response, handle)


def alidns_conversion(text: str) -> str:
    """Rewrite 114DNS upstream to AliDNS and verify that only `server=` lines remain."""
    converted = text.replace("114.114.114.114", "223.5.5.5")
    for number, raw in enumerate(converted.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if not _LINE.match(line):
            raise ValueError(f"unexpected directive at line {number}: {line[:80]!r}")
    return converted


def _load_generator(root: Path):
    path = root / "scripts" / "generate-routes.py"
    spec = importlib.util.spec_from_file_location("generate_routes", path)
    if spec is None or spec.loader is None:
        raise ImportError(path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def update(target: Path | None = None) -> list[str]:
    """Download, validate and atomically replace the files under ``target`` (default: repo data/)."""
    source = config.source_data_dir()
    target = target or source
    if target is None:
        raise FileNotFoundError("data directory not found")
    root = target.parent
    if not (root / "scripts" / "generate-routes.py").is_file():
        raise FileNotFoundError("update-data must be run from the repository checkout")

    messages: list[str] = []
    with tempfile.TemporaryDirectory(prefix="zoog-cn-data-") as tmp:
        tmpdir = Path(tmp)
        delegated = tmpdir / "delegated-apnic-latest"
        _download(APNIC_URL, delegated)
        _download(ACCELERATED_URL, tmpdir / "accelerated.conf")
        _download(APPLE_URL, tmpdir / "apple.conf")

        generator = _load_generator(root)
        ipv4, ipv6 = generator.generate(delegated)
        generator.write_networks(tmpdir / "cn-ipv4.txt", ipv4)
        generator.write_networks(tmpdir / "cn-ipv6.txt", ipv6)
        (tmpdir / "accelerated-domains.china.conf").write_text(
            alidns_conversion((tmpdir / "accelerated.conf").read_text(encoding="utf-8")), encoding="utf-8")
        (tmpdir / "apple.china.conf").write_text(
            alidns_conversion((tmpdir / "apple.conf").read_text(encoding="utf-8")), encoding="utf-8")

        for name in config.DATA_FILES:
            os.replace(tmpdir / name, target / name)
        messages.append(f"Generated {len(ipv4)} IPv4 and {len(ipv6)} IPv6 prefixes")

        snapshot = ""
        for line in delegated.read_text(encoding="utf-8").splitlines():
            parts = line.split("|")
            if len(parts) > 3 and parts[0] == "2" and parts[1] == "apnic":
                snapshot = parts[2]
                break
        messages.append(f"APNIC snapshot: {snapshot or 'unknown'}")
        try:
            request = urllib.request.Request(COMMIT_URL, headers={"User-Agent": "zoog-cn-bypass"})
            with urllib.request.urlopen(request, timeout=30) as response:
                messages.append("dnsmasq-china-list commit: " + json.load(response)["sha"])
        except Exception:  # informational only
            messages.append("dnsmasq-china-list commit: unknown")
    return messages
