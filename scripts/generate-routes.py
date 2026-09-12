#!/usr/bin/env python3

"""Generate exact mainland-China IPv4 and IPv6 prefixes from APNIC data."""

from __future__ import annotations

import argparse
import ipaddress
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("delegated_file", type=Path)
    parser.add_argument("ipv4_output", type=Path)
    parser.add_argument("ipv6_output", type=Path)
    return parser.parse_args()


def generate(source: Path) -> tuple[list[ipaddress.IPv4Network], list[ipaddress.IPv6Network]]:
    ipv4: set[ipaddress.IPv4Network] = set()
    ipv6: set[ipaddress.IPv6Network] = set()

    for raw_line in source.read_text(encoding="utf-8").splitlines():
        if not raw_line or raw_line.startswith("#"):
            continue
        fields = raw_line.split("|")
        if len(fields) < 7:
            continue
        _, country, resource_type, start, value, _, status = fields[:7]
        if country != "CN" or status not in {"allocated", "assigned"}:
            continue

        if resource_type == "ipv4":
            first = ipaddress.IPv4Address(start)
            last = ipaddress.IPv4Address(int(first) + int(value) - 1)
            ipv4.update(ipaddress.summarize_address_range(first, last))
        elif resource_type == "ipv6":
            ipv6.add(ipaddress.IPv6Network(f"{start}/{value}", strict=False))

    collapsed_ipv4 = ipaddress.collapse_addresses(ipv4)
    collapsed_ipv6 = ipaddress.collapse_addresses(ipv6)
    return (
        sorted(collapsed_ipv4, key=lambda network: (int(network.network_address), network.prefixlen)),
        sorted(collapsed_ipv6, key=lambda network: (int(network.network_address), network.prefixlen)),
    )


def write_networks(path: Path, networks: list[ipaddress._BaseNetwork]) -> None:
    path.write_text("".join(f"{network}\n" for network in networks), encoding="utf-8")


def main() -> None:
    args = parse_args()
    ipv4, ipv6 = generate(args.delegated_file)
    write_networks(args.ipv4_output, ipv4)
    write_networks(args.ipv6_output, ipv6)
    print(f"Generated {len(ipv4)} IPv4 and {len(ipv6)} IPv6 prefixes")


if __name__ == "__main__":
    main()
