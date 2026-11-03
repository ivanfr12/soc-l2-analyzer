from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address, IPv4Network, IPv6Network
from typing import Literal

IPCategory = Literal[
    "private", "public", "documentation", "special", "unknown", "missing", "invalid"
]

_PRIVATE_NETWORKS: tuple[IPv4Network | IPv6Network, ...] = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
)
_DOCUMENTATION_NETWORKS: tuple[IPv4Network | IPv6Network, ...] = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)


@dataclass(frozen=True)
class IPClassification:
    value: str | None
    category: IPCategory
    source: str
    registry_validation_status: Literal["not_loaded"]


def classify_ip(value: object) -> IPClassification:
    if value is None or (isinstance(value, str) and not value.strip()):
        return IPClassification(None, "missing", "input", "not_loaded")
    if not isinstance(value, str):
        return IPClassification(str(value), "invalid", "input", "not_loaded")

    text = value.strip()
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return IPClassification(text, "invalid", "input", "not_loaded")

    if any(address in network for network in _DOCUMENTATION_NETWORKS):
        category: IPCategory = "documentation"
    elif any(address in network for network in _PRIVATE_NETWORKS):
        category = "private"
    elif not address.is_global:
        category = "special"
    else:
        category = "public"

    return IPClassification(
        str(address),
        category,
        "CPython ipaddress plus explicit RFC 1918/RFC 4193/RFC 5737/RFC 3849 ranges",
        "not_loaded",
    )
