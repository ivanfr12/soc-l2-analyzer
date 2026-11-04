from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Literal

IANA_NAMESPACE = "http://www.iana.org/assignments"
ARTIFACT_VERSION = "iana-ip-table/1.0"
SNAPSHOT_DIRECTORY = Path(__file__).resolve().parents[1] / "data" / "iana"
ValidationStatus = Literal["verified", "declared_unverified"]
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPCategory = Literal[
    "private", "public", "documentation", "special", "unknown"
]
RegistrySource = Literal["spar", "address_space"]


@dataclass(frozen=True)
class SPARAttributes:
    source: bool | None
    destination: bool | None
    forwardable: bool | None
    global_reachability: bool | None
    reserved_by_protocol: bool | None


@dataclass(frozen=True)
class RegistryPrefix:
    network: IPNetwork
    category: IPCategory
    registry_id: str
    name: str
    source_type: RegistrySource
    attributes: SPARAttributes | None = None


@dataclass(frozen=True)
class SnapshotMetadata:
    registry_id: str
    name: str
    url: str
    updated: str
    format: str
    retrieved_at: str
    filename: str
    sha256: str
    record_count: int
    validation_status: str


@dataclass(frozen=True)
class IANARegistry:
    validation_status: ValidationStatus
    prefixes: tuple[RegistryPrefix, ...]
    snapshots: tuple[SnapshotMetadata, ...]
    diagnostics: tuple[str, ...]


@dataclass(frozen=True)
class _SnapshotSpec:
    registry_id: str
    name: str
    url: str
    filename: str
    kind: Literal["spar4", "spar6", "space4", "space6"]
    title: str


_SNAPSHOT_SPECS = (
    _SnapshotSpec(
        "iana-ipv4-special-registry",
        "IPv4 Special-Purpose Address Registry",
        "https://www.iana.org/assignments/iana-ipv4-special-registry/"
        "iana-ipv4-special-registry.xml",
        "iana-ipv4-special-registry.xml",
        "spar4",
        "IPv4 Special-Purpose Address Space",
    ),
    _SnapshotSpec(
        "iana-ipv6-special-registry",
        "IPv6 Special-Purpose Address Registry",
        "https://www.iana.org/assignments/iana-ipv6-special-registry/"
        "iana-ipv6-special-registry.xml",
        "iana-ipv6-special-registry.xml",
        "spar6",
        "IPv6 Special-Purpose Address Space",
    ),
    _SnapshotSpec(
        "ipv4-address-space",
        "IPv4 Address Space Registry",
        "https://www.iana.org/assignments/ipv4-address-space/"
        "ipv4-address-space.xml",
        "ipv4-address-space.xml",
        "space4",
        "IPv4 Address Space",
    ),
    _SnapshotSpec(
        "ipv6-address-space",
        "IPv6 Address Space Registry",
        "https://www.iana.org/assignments/ipv6-address-space/"
        "ipv6-address-space.xml",
        "ipv6-address-space.xml",
        "space6",
        "IPv6 Address Space",
    ),
)
_SNAPSHOT_SPEC_BY_ID = {spec.registry_id: spec for spec in _SNAPSHOT_SPECS}
_IPV4_ABBREVIATED_PREFIX = re.compile(r"^(\d{1,3})/8$")
_IPV4_STATUSES = {"ALLOCATED", "LEGACY", "RESERVED"}


def _tag(name: str) -> str:
    return f"{{{IANA_NAMESPACE}}}{name}"


def _child_text(element: ET.Element, name: str) -> str | None:
    child = element.find(_tag(name))
    if child is None or child.text is None:
        return None
    value = child.text.strip()
    return value or None


def _parse_boolean(value: str | None, field: str, registry_id: str) -> bool | None:
    if value is None:
        return None
    normalized = value.casefold()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    if normalized == "n/a":
        return None
    raise ValueError(f"{registry_id}: atributo SPAR {field} inválido: {value!r}.")


def _parse_prefix(value: str, expected_version: int, registry_id: str) -> IPNetwork:
    abbreviated = _IPV4_ABBREVIATED_PREFIX.fullmatch(value)
    if abbreviated:
        first_octet = int(abbreviated.group(1))
        if first_octet > 255:
            raise ValueError(f"{registry_id}: prefijo IPv4 inválido: {value!r}.")
        value = f"{first_octet}.0.0.0/8"
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        raise ValueError(f"{registry_id}: prefijo inválido: {value!r}.") from exc
    if network.version != expected_version:
        raise ValueError(
            f"{registry_id}: se esperaba IPv{expected_version}, recibió {value!r}."
        )
    return network


def _metadata_from_manifest(
    entry: object, spec: _SnapshotSpec, artifact_version: str
) -> SnapshotMetadata:
    if not isinstance(entry, dict):
        raise ValueError(f"{spec.registry_id}: metadatos de snapshot inválidos.")
    expected_values = {
        "registry_id": spec.registry_id,
        "name": spec.name,
        "url": spec.url,
        "format": "XML",
        "filename": spec.filename,
        "validation_status": "verified",
    }
    for field, expected in expected_values.items():
        if entry.get(field) != expected:
            raise ValueError(
                f"{spec.registry_id}: metadato {field!r} no coincide con la fuente."
            )
    if artifact_version != ARTIFACT_VERSION:
        raise ValueError(f"Versión de artefacto no admitida: {artifact_version!r}.")

    updated = entry.get("updated")
    retrieved_at = entry.get("retrieved_at")
    sha256 = entry.get("sha256")
    record_count = entry.get("record_count")
    if not isinstance(updated, str):
        raise ValueError(f"{spec.registry_id}: falta la fecha updated.")
    if not isinstance(retrieved_at, str):
        raise ValueError(f"{spec.registry_id}: falta la fecha de recuperación.")
    try:
        if date.fromisoformat(updated).isoformat() != updated:
            raise ValueError
        if date.fromisoformat(retrieved_at).isoformat() != retrieved_at:
            raise ValueError
    except ValueError as exc:
        raise ValueError(f"{spec.registry_id}: fecha inválida en metadatos.") from exc
    if not isinstance(sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", sha256):
        raise ValueError(f"{spec.registry_id}: SHA-256 de metadatos inválido.")
    if (
        not isinstance(record_count, int)
        or isinstance(record_count, bool)
        or record_count <= 0
    ):
        raise ValueError(f"{spec.registry_id}: cantidad de registros inválida.")
    return SnapshotMetadata(
        registry_id=spec.registry_id,
        name=spec.name,
        url=spec.url,
        updated=updated,
        format="XML",
        retrieved_at=retrieved_at,
        filename=spec.filename,
        sha256=sha256,
        record_count=record_count,
        validation_status="verified",
    )


def _parse_records(
    root: ET.Element, spec: _SnapshotSpec
) -> tuple[tuple[RegistryPrefix, ...], int]:
    records = root.findall(f".//{_tag('record')}")
    if not records:
        raise ValueError(f"{spec.registry_id}: no contiene registros.")

    prefixes: list[RegistryPrefix] = []
    expected_version = 6 if spec.kind.endswith("6") else 4
    for index, record in enumerate(records, start=1):
        if spec.kind.startswith("spar"):
            raw_prefix = _child_text(record, "address")
            name = _child_text(record, "name")
            if raw_prefix is None or name is None:
                raise ValueError(
                    f"{spec.registry_id}: registro {index} sin address o name."
                )
            raw_prefixes = [item.strip() for item in raw_prefix.split(",")]
            if any(not item for item in raw_prefixes):
                raise ValueError(
                    f"{spec.registry_id}: lista de prefijos vacía en registro {index}."
                )
            attributes = SPARAttributes(
                source=_parse_boolean(
                    _child_text(record, "source"), "source", spec.registry_id
                ),
                destination=_parse_boolean(
                    _child_text(record, "destination"),
                    "destination",
                    spec.registry_id,
                ),
                forwardable=_parse_boolean(
                    _child_text(record, "forwardable"),
                    "forwardable",
                    spec.registry_id,
                ),
                global_reachability=_parse_boolean(
                    _child_text(record, "global"), "global", spec.registry_id
                ),
                reserved_by_protocol=_parse_boolean(
                    _child_text(record, "reserved"), "reserved", spec.registry_id
                ),
            )
            for item in raw_prefixes:
                prefixes.append(
                    RegistryPrefix(
                        network=_parse_prefix(
                            item, expected_version, spec.registry_id
                        ),
                        category="special",
                        registry_id=spec.registry_id,
                        name=name,
                        source_type="spar",
                        attributes=attributes,
                    )
                )
            continue

        raw_prefix = _child_text(record, "prefix")
        if raw_prefix is None:
            raise ValueError(f"{spec.registry_id}: registro {index} sin prefix.")
        network = _parse_prefix(raw_prefix, expected_version, spec.registry_id)
        if spec.kind == "space4":
            name = _child_text(record, "designation")
            status = _child_text(record, "status")
            if name is None or status is None or status not in _IPV4_STATUSES:
                raise ValueError(
                    f"{spec.registry_id}: registro {index} sin designation/status "
                    "válidos."
                )
            category: IPCategory = "unknown"
        else:
            name = _child_text(record, "description")
            if name is None:
                raise ValueError(
                    f"{spec.registry_id}: registro {index} sin description."
                )
            category = "public" if name == "Global Unicast" else "unknown"
        prefixes.append(
            RegistryPrefix(
                network=network,
                category=category,
                registry_id=spec.registry_id,
                name=name,
                source_type="address_space",
            )
        )

    return tuple(prefixes), len(records)


def load_iana_registry(
    snapshots_directory: Path = SNAPSHOT_DIRECTORY,
    manifest_path: Path | None = None,
) -> IANARegistry:
    manifest_file = manifest_path or snapshots_directory / "manifest.json"
    diagnostics: list[str] = []
    all_prefixes: list[RegistryPrefix] = []
    metadata: list[SnapshotMetadata] = []

    try:
        manifest_bytes = manifest_file.read_bytes()
        manifest = json.loads(manifest_bytes)
    except OSError as exc:
        return IANARegistry(
            "declared_unverified",
            (),
            (),
            (f"No se pudo leer el manifiesto IANA: {exc}.",),
        )
    except json.JSONDecodeError as exc:
        return IANARegistry(
            "declared_unverified",
            (),
            (),
            (f"El manifiesto IANA no es JSON válido: {exc}.",),
        )
    except UnicodeDecodeError as exc:
        return IANARegistry(
            "declared_unverified",
            (),
            (),
            (f"El manifiesto IANA no tiene codificación UTF-8 válida: {exc}.",),
        )

    if not isinstance(manifest, dict):
        return IANARegistry(
            "declared_unverified",
            (),
            (),
            ("El manifiesto IANA debe ser un objeto JSON.",),
        )
    entries = manifest.get("snapshots")
    if not isinstance(entries, list):
        return IANARegistry(
            "declared_unverified",
            (),
            (),
            ("El manifiesto IANA no contiene la lista snapshots.",),
        )
    if manifest.get("artifact_version") != ARTIFACT_VERSION:
        diagnostics.append("La versión del artefacto IANA no coincide.")

    entries_by_id: dict[str, object] = {}
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(
            entry.get("registry_id"), str
        ):
            diagnostics.append("El manifiesto contiene una entrada sin registry_id.")
            continue
        registry_id = entry["registry_id"]
        if registry_id in entries_by_id:
            diagnostics.append(f"Snapshot duplicado en manifiesto: {registry_id}.")
        entries_by_id[registry_id] = entry
    if set(entries_by_id) != set(_SNAPSHOT_SPEC_BY_ID):
        diagnostics.append("El manifiesto no contiene exactamente los cuatro registros.")

    for spec in _SNAPSHOT_SPECS:
        entry = entries_by_id.get(spec.registry_id)
        if entry is None:
            diagnostics.append(f"Falta snapshot en manifiesto: {spec.registry_id}.")
            continue
        try:
            snapshot_metadata = _metadata_from_manifest(
                entry, spec, manifest.get("artifact_version", "")
            )
            path = snapshots_directory / spec.filename
            content = path.read_bytes()
            actual_hash = hashlib.sha256(content).hexdigest()
            if actual_hash != snapshot_metadata.sha256:
                raise ValueError(f"{spec.filename}: SHA-256 no coincide.")
            root = ET.fromstring(content)
            if root.tag != _tag("registry"):
                raise ValueError(f"{spec.filename}: raíz XML no es registry IANA.")
            if root.get("id") != spec.registry_id:
                raise ValueError(f"{spec.filename}: registry_id XML inesperado.")
            if _child_text(root, "title") != spec.title:
                raise ValueError(f"{spec.filename}: título XML inesperado.")
            updated = _child_text(root, "updated")
            if updated != snapshot_metadata.updated:
                raise ValueError(f"{spec.filename}: updated no coincide.")
            if date.fromisoformat(updated or "").isoformat() != updated:
                raise ValueError(f"{spec.filename}: fecha updated no es ISO válida.")
            parsed_prefixes, xml_record_count = _parse_records(root, spec)
            if xml_record_count != snapshot_metadata.record_count:
                raise ValueError(
                    f"{spec.filename}: cantidad de registros no coincide con "
                    "el manifiesto."
                )
        except ET.ParseError as exc:
            diagnostics.append(f"{spec.filename}: XML malformado: {exc}.")
            continue
        except (OSError, ValueError) as exc:
            diagnostics.append(str(exc))
            continue

        metadata.append(snapshot_metadata)
        all_prefixes.extend(parsed_prefixes)

    if diagnostics or len(metadata) != len(_SNAPSHOT_SPECS):
        return IANARegistry(
            "declared_unverified",
            (),
            tuple(metadata),
            tuple(diagnostics),
        )

    ordered_prefixes = tuple(
        sorted(
            all_prefixes,
            key=lambda item: (
                item.network.version,
                -item.network.prefixlen,
                int(item.network.network_address),
                item.registry_id,
                item.name,
            ),
        )
    )
    return IANARegistry(
        "verified",
        ordered_prefixes,
        tuple(metadata),
        (),
    )
