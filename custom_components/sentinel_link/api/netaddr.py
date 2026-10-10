"""Local addresses of this node for display (pure, no hub imports apart from ifaddr which ships with the hub)."""
from __future__ import annotations

import ipaddress
from typing import Any, Iterable

SKIP_PREFIX = ("lo", "docker", "br-", "veth", "virbr", "tailscale", "ts", "wg", "tun", "zt", "cni", "flannel", "kube")


def local_addresses(adapters: Iterable[tuple[str, list[str]]]) -> list[dict[str, str]]:
    """[(interface, [ip, ...]), ...] -> private IPv4 addresses on real interfaces, wired names first. VPN, container and loopback are never listed."""
    out: list[dict[str, str]] = []
    for name, ips in adapters:
        if name.lower().startswith(SKIP_PREFIX):
            continue
        for raw in ips:
            try:
                ip = ipaddress.ip_address(raw)
            except ValueError:
                continue
            if ip.version != 4 or not ip.is_private or ip.is_loopback or ip.is_link_local or ip in ipaddress.ip_network("100.64.0.0/10"):
                continue
            out.append({"interface": name, "ip": str(ip)})
    out.sort(key=lambda x: (not x["interface"].startswith(("en", "eth")), x["interface"], x["ip"]))
    return out


def local_urls(addrs: list[dict[str, str]], port: int = 443) -> list[str]:
    return [f"https://{a['ip']}" + ("" if port == 443 else f":{port}") for a in addrs]


def read_adapters() -> list[tuple[str, list[str]]]:
    try:
        import ifaddr
    except ImportError:  # pragma: no cover
        return []
    return [(a.nice_name, [i.ip for i in a.ips if isinstance(i.ip, str)]) for a in ifaddr.get_adapters()]
