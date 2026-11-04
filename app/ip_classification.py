from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from typing import Literal

from app.iana_registry import (
    ARTIFACT_VERSION,
    IANARegistry,
    IPNetwork,
    RegistryPrefix,
    ValidationStatus,
    load_iana_registry,
)

IPCategory = Literal[
    "private", "public", "documentation", "special", "unknown", "missing", "invalid"
]

_PRIVATE_NETWORKS: tuple[IPNetwork, ...] = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
)
_DOCUMENTATION_NETWORKS: tuple[IPNetwork, ...] = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
    ipaddress.ip_network("3fff::/20"),
)

_DEFAULT_REGISTRY = load_iana_registry()


@dataclass(frozen=True)
class IPClassification:
    value: str | None
    category: IPCategory
    source: str
    registry_validation_status: ValidationStatus


def registry_validation_status() -> ValidationStatus:
    return _DEFAULT_REGISTRY.validation_status


def registry_diagnostics() -> tuple[str, ...]:
    return _DEFAULT_REGISTRY.diagnostics


def _mapped_registry_address(
    address: IPv4Address | IPv6Address,
) -> IPv4Address | IPv6Address:
    if isinstance(address, IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def _prefixes_for_registry(registry: IANARegistry) -> tuple[RegistryPrefix, ...]:
    if registry.validation_status != "verified":
        return ()
    return registry.prefixes


def _classify_address(
    address: IPv4Address | IPv6Address,
    registry: IANARegistry,
) -> IPCategory:
    if any(address in network for network in _PRIVATE_NETWORKS):
        return "private"
    if any(address in network for network in _DOCUMENTATION_NETWORKS):
        return "documentation"
    if address.is_multicast:
        return "special"

    matches = [
        prefix
        for prefix in _prefixes_for_registry(registry)
        if address.version == prefix.network.version and address in prefix.network
    ]
    if not matches:
        return "unknown"
    special_purpose_matches = [
        prefix for prefix in matches if prefix.source_type == "spar"
    ]
    selected_source = special_purpose_matches or [
        prefix for prefix in matches if prefix.source_type == "address_space"
    ]
    selected_source.sort(
        key=lambda item: (
            -item.network.prefixlen,
            item.registry_id,
            item.name,
        )
    )
    selected_prefix = selected_source[0]
    if selected_prefix.source_type == "spar":
        attributes = selected_prefix.attributes
        if attributes is not None and attributes.global_reachability is True:
            return "public"
        return "special"
    return selected_prefix.category


def classify_ip(
    value: object, registry: IANARegistry | None = None
) -> IPClassification:
    active_registry = registry or _DEFAULT_REGISTRY
    status = active_registry.validation_status
    if value is None or (isinstance(value, str) and not value.strip()):
        return IPClassification(None, "missing", "input", status)
    if not isinstance(value, str):
        return IPClassification(str(value), "invalid", "input", status)

    text = value.strip()
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return IPClassification(text, "invalid", "input", status)

    is_mapped = isinstance(address, IPv6Address) and address.ipv4_mapped is not None
    classification_address = _mapped_registry_address(address)
    category = _classify_address(classification_address, active_registry)
    if status == "verified":
        source = f"IANA snapshots {ARTIFACT_VERSION}"
    else:
        source = "IANA snapshots declared_unverified; clasificación conservadora"
    if is_mapped:
        source += (
            "; IPv4-mapped IPv6; clasificada mediante IPv4 embebida "
            f"{classification_address}"
        )

    return IPClassification(
        text if is_mapped else str(address),
        category,
        source,
        status,
    )
