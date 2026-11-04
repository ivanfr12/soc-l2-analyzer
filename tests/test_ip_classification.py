import ipaddress
import hashlib
import json
import shutil
from pathlib import Path

import pytest

from app.iana_registry import (
    ARTIFACT_VERSION,
    IANARegistry,
    RegistryPrefix,
    SPARAttributes,
    SNAPSHOT_DIRECTORY,
    load_iana_registry,
)
from app.ip_classification import classify_ip


@pytest.mark.parametrize(
    ("value", "category"),
    [
        ("10.0.0.1", "private"),
        ("172.16.0.1", "private"),
        ("192.168.1.1", "private"),
        ("fc00::1", "private"),
        ("fd12:3456::1", "private"),
        ("192.0.2.91", "documentation"),
        ("198.51.100.77", "documentation"),
        ("203.0.113.74", "documentation"),
        ("2001:db8::1", "documentation"),
        ("3fff::1", "documentation"),
        ("127.0.0.1", "special"),
        ("100.64.0.1", "special"),
        ("224.0.0.1", "special"),
        ("ff02::1", "special"),
        ("8.8.8.8", "unknown"),
        ("1.1.1.1", "unknown"),
        ("192.0.0.8", "special"),
        ("192.0.0.9", "public"),
        ("192.0.0.10", "public"),
        ("192.0.0.170", "special"),
        ("192.0.0.171", "special"),
        ("192.88.99.1", "special"),
        ("2001:20::1", "public"),
        ("2001:30::1", "public"),
        ("2002::1", "special"),
        ("2001::1", "special"),
        ("2001:4860:4860::8888", "public"),
        ("240.0.0.1", "special"),
        ("240.1.1.1", "special"),
        ("4000::1", "unknown"),
        (None, "missing"),
        ("", "missing"),
        ("not-an-ip", "invalid"),
        (123, "invalid"),
    ],
)
def test_ip_classification_categories(value: object, category: str) -> None:
    classification = classify_ip(value)

    assert classification.category == category
    assert classification.registry_validation_status == "verified"


def test_rfc5737_and_documentation_prefixes_never_classify_as_public() -> None:
    for address in (
        "192.0.2.91",
        "198.51.100.77",
        "203.0.113.74",
        "2001:db8::1",
        "3fff::1",
    ):
        assert classify_ip(address).category == "documentation"


def test_rfc1918_and_ula_remain_private() -> None:
    for address in (
        "10.1.2.3",
        "172.31.255.254",
        "192.168.1.1",
        "fc00::1",
        "fdff:ffff::1",
    ):
        assert classify_ip(address).category == "private"


def test_special_registry_entries_override_broader_address_space_prefixes() -> None:
    assert classify_ip("192.0.0.1").category == "special"
    assert classify_ip("192.1.0.1").category == "unknown"
    assert classify_ip("240.0.0.1").category == "special"


def test_ipv4_mapped_ipv6_preserves_input_and_reports_embedded_ipv4() -> None:
    original = "::FFFF:8.8.8.8"

    classification = classify_ip(original)

    assert classification.value == original
    assert classification.category == "unknown"
    assert "IPv4-mapped IPv6" in classification.source
    assert "8.8.8.8" in classification.source


def test_ipv4_mapped_ipv6_uses_embedded_documentation_category() -> None:
    classification = classify_ip("::ffff:192.0.2.1")

    assert classification.value == "::ffff:192.0.2.1"
    assert classification.category == "documentation"
    assert "IPv4-mapped IPv6" in classification.source


def _registry_with_prefixes(
    prefixes: tuple[RegistryPrefix, ...],
) -> IANARegistry:
    return IANARegistry("verified", prefixes, (), ())


def test_spar_precedes_longer_administrative_allocation_prefix() -> None:
    spar = RegistryPrefix(
        network=ipaddress.ip_network("240.0.0.0/4"),
        category="special",
        registry_id="iana-ipv4-special-registry",
        name="Reserved",
        source_type="spar",
    )
    administrative = RegistryPrefix(
        network=ipaddress.ip_network("240.0.0.0/8"),
        category="unknown",
        registry_id="ipv4-address-space",
        name="Future use",
        source_type="address_space",
    )
    registry = _registry_with_prefixes((spar, administrative))

    assert classify_ip("240.0.0.1", registry).category == "special"


def test_longest_prefix_match_is_applied_within_spar_source() -> None:
    broad = RegistryPrefix(
        network=ipaddress.ip_network("192.0.0.0/24"),
        category="special",
        registry_id="iana-ipv4-special-registry",
        name="IETF Protocol Assignments",
        source_type="spar",
    )
    specific = RegistryPrefix(
        network=ipaddress.ip_network("192.0.0.0/29"),
        category="special",
        registry_id="iana-ipv4-special-registry",
        name="IPv4 Service Continuity Prefix",
        source_type="spar",
    )
    administrative = RegistryPrefix(
        network=ipaddress.ip_network("192.0.0.0/8"),
        category="unknown",
        registry_id="ipv4-address-space",
        name="Administered by ARIN",
        source_type="address_space",
    )
    registry = _registry_with_prefixes((broad, specific, administrative))

    assert classify_ip("192.0.0.1", registry).category == "special"
    reversed_registry = _registry_with_prefixes(
        tuple(reversed((broad, specific, administrative)))
    )
    assert classify_ip("192.0.0.1", reversed_registry).category == "special"


def test_spar_lpm_selects_specific_global_attribute_independent_of_order() -> None:
    broad = RegistryPrefix(
        network=ipaddress.ip_network("198.18.0.0/15"),
        category="special",
        registry_id="iana-ipv4-special-registry",
        name="Broad test range",
        source_type="spar",
        attributes=SPARAttributes(True, True, True, True, False),
    )
    specific = RegistryPrefix(
        network=ipaddress.ip_network("198.18.0.1/32"),
        category="special",
        registry_id="iana-ipv4-special-registry",
        name="Specific test range",
        source_type="spar",
        attributes=SPARAttributes(True, True, True, False, False),
    )
    registry = _registry_with_prefixes((broad, specific))
    reversed_registry = _registry_with_prefixes((specific, broad))

    assert classify_ip("198.18.0.1", registry).category == "special"
    assert classify_ip("198.18.0.1", reversed_registry).category == "special"
    assert classify_ip("198.18.0.2", registry).category == "public"
    assert classify_ip("198.18.0.2", reversed_registry).category == "public"


@pytest.mark.parametrize(
    ("address", "expected_global", "expected_category"),
    [
        ("192.0.0.9", True, "public"),
        ("192.0.0.10", True, "public"),
        ("192.0.0.8", False, "special"),
        ("192.88.99.1", None, "special"),
        ("2001:20::1", True, "public"),
        ("2001:30::1", True, "public"),
        ("2002::1", None, "special"),
        ("2001::1", None, "special"),
    ],
)
def test_spar_global_reachability_controls_category_without_claiming_connectivity(
    address: str, expected_global: bool | None, expected_category: str
) -> None:
    classification = classify_ip(address)
    parsed_address = ipaddress.ip_address(address)
    matching = [
        entry
        for entry in load_iana_registry().prefixes
        if entry.source_type == "spar"
        and parsed_address.version == entry.network.version
        and parsed_address in entry.network
    ]
    winner = max(matching, key=lambda entry: entry.network.prefixlen)

    assert winner.attributes is not None
    assert winner.attributes.global_reachability is expected_global
    assert classification.category == expected_category
    assert "reachable" not in classification.source.casefold()
    assert "connectivity" not in classification.source.casefold()


@pytest.mark.parametrize(
    ("address", "expected_category"),
    [
        ("192.0.0.170", "special"),
        ("192.0.0.171", "special"),
        ("192.31.196.1", "public"),
        ("192.52.193.1", "public"),
        ("192.175.48.1", "public"),
        ("240.0.0.1", "special"),
    ],
)
def test_spar_and_address_space_overlaps_follow_spar_semantics(
    address: str, expected_category: str
) -> None:
    assert classify_ip(address).category == expected_category


def test_classification_is_invariant_to_order_of_complete_prefix_table() -> None:
    registry = load_iana_registry()
    reversed_registry = _registry_with_prefixes(tuple(reversed(registry.prefixes)))

    for address in (
        "8.8.8.8",
        "192.0.0.1",
        "100.64.0.1",
        "240.0.0.1",
        "2001:4860:4860::8888",
        "fe80::1",
    ):
        assert classify_ip(address, registry).category == classify_ip(
            address, reversed_registry
        ).category


def test_rfc5737_never_classifies_as_public() -> None:
    for address in ("192.0.2.91", "198.51.100.77", "203.0.113.74"):
        classification = classify_ip(address)
        assert classification.category == "documentation"
        assert classification.category != "public"
        assert classification.registry_validation_status == "verified"


def test_four_official_snapshots_are_validated_and_hashed_from_saved_bytes() -> None:
    registry = load_iana_registry()

    assert registry.validation_status == "verified"
    assert registry.diagnostics == ()
    assert len(registry.snapshots) == 4
    for snapshot in registry.snapshots:
        content = (SNAPSHOT_DIRECTORY / snapshot.filename).read_bytes()
        assert snapshot.format == "XML"
        assert snapshot.updated
        assert snapshot.retrieved_at == "2026-11-03"
        assert snapshot.sha256 == hashlib.sha256(content).hexdigest()
        assert snapshot.validation_status == "verified"
        assert snapshot.record_count > 0


def test_snapshot_metadata_names_the_four_required_iana_registries() -> None:
    registry = load_iana_registry()

    assert {snapshot.registry_id for snapshot in registry.snapshots} == {
        "iana-ipv4-special-registry",
        "iana-ipv6-special-registry",
        "ipv4-address-space",
        "ipv6-address-space",
    }
    assert {snapshot.url for snapshot in registry.snapshots} == {
        "https://www.iana.org/assignments/iana-ipv4-special-registry/"
        "iana-ipv4-special-registry.xml",
        "https://www.iana.org/assignments/iana-ipv6-special-registry/"
        "iana-ipv6-special-registry.xml",
        "https://www.iana.org/assignments/ipv4-address-space/"
        "ipv4-address-space.xml",
        "https://www.iana.org/assignments/ipv6-address-space/"
        "ipv6-address-space.xml",
    }
    assert ARTIFACT_VERSION == "iana-ip-table/1.0"


def test_ipv4_and_ipv6_registry_prefixes_are_loaded() -> None:
    registry = load_iana_registry()
    networks = {prefix.network.with_prefixlen for prefix in registry.prefixes}

    assert "8.0.0.0/8" in networks
    assert "2000::/3" in networks
    assert all(
        prefix.network.version in (4, 6) for prefix in registry.prefixes
    )


def test_spar_attributes_are_independent_and_missing_is_not_false() -> None:
    registry = load_iana_registry()
    teredo = next(
        prefix
        for prefix in registry.prefixes
        if prefix.registry_id == "iana-ipv6-special-registry"
        and prefix.network.with_prefixlen == "2001::/32"
    )
    assert teredo.attributes is not None
    assert teredo.source_type == "spar"
    assert teredo.attributes.source is True
    assert teredo.attributes.destination is True
    assert teredo.attributes.forwardable is True
    assert teredo.attributes.global_reachability is None
    assert teredo.attributes.reserved_by_protocol is False


def test_spar_n_a_values_are_not_interpreted_as_false() -> None:
    registry = load_iana_registry()
    deprecated = next(
        prefix
        for prefix in registry.prefixes
        if prefix.registry_id == "iana-ipv4-special-registry"
        and prefix.network.with_prefixlen == "192.88.99.0/24"
    )

    assert deprecated.attributes is not None
    assert deprecated.attributes.source is None
    assert deprecated.attributes.destination is None
    assert deprecated.attributes.forwardable is None


def test_ipv4_address_space_assignment_alone_does_not_make_address_public() -> None:
    registry = load_iana_registry()
    allocated_ipv4 = next(
        prefix
        for prefix in registry.prefixes
        if prefix.registry_id == "ipv4-address-space"
        and prefix.network.with_prefixlen == "8.0.0.0/8"
    )

    assert allocated_ipv4.category == "unknown"
    assert allocated_ipv4.source_type == "address_space"
    assert classify_ip("8.8.8.8").category == "unknown"


def test_ipv6_global_unicast_designation_is_explicit_public_evidence() -> None:
    registry = load_iana_registry()
    global_unicast = next(
        prefix
        for prefix in registry.prefixes
        if prefix.registry_id == "ipv6-address-space"
        and prefix.network.with_prefixlen == "2000::/3"
    )

    assert global_unicast.name == "Global Unicast"
    assert global_unicast.category == "public"
    assert classify_ip("2001:4860:4860::8888").category == "public"


def test_generated_prefix_table_is_deterministic() -> None:
    first = load_iana_registry()
    second = load_iana_registry()

    assert first.prefixes == second.prefixes
    assert first.snapshots == second.snapshots


def _copy_snapshot_bundle(directory: Path) -> None:
    directory.mkdir(exist_ok=True)
    for path in SNAPSHOT_DIRECTORY.iterdir():
        if path.is_file():
            shutil.copyfile(path, directory / path.name)


def _rewrite_manifest_hash(directory: Path, filename: str) -> None:
    manifest_path = directory / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    snapshot = next(
        item for item in manifest["snapshots"] if item["filename"] == filename
    )
    snapshot["sha256"] = hashlib.sha256(
        (directory / filename).read_bytes()
    ).hexdigest()
    manifest_path.write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )


def test_missing_snapshot_fails_closed_and_marks_registry_unverified(
    tmp_path: Path,
) -> None:
    _copy_snapshot_bundle(tmp_path)
    (tmp_path / "ipv6-address-space.xml").unlink()
    registry = load_iana_registry(tmp_path)

    assert registry.validation_status == "declared_unverified"
    assert registry.prefixes == ()
    assert any("ipv6-address-space.xml" in item for item in registry.diagnostics)
    assert classify_ip("8.8.8.8", registry).category == "unknown"
    assert classify_ip("8.8.8.8", registry).registry_validation_status == (
        "declared_unverified"
    )
    assert classify_ip("192.0.2.1", registry).category == "documentation"


def test_snapshot_hash_mismatch_fails_closed(tmp_path: Path) -> None:
    _copy_snapshot_bundle(tmp_path)
    path = tmp_path / "ipv4-address-space.xml"
    path.write_bytes(path.read_bytes() + b"\n")

    registry = load_iana_registry(tmp_path)

    assert registry.validation_status == "declared_unverified"
    assert registry.prefixes == ()
    assert any("SHA-256 no coincide" in item for item in registry.diagnostics)


def test_snapshot_source_metadata_mismatch_fails_closed(tmp_path: Path) -> None:
    _copy_snapshot_bundle(tmp_path)
    manifest_path = tmp_path / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["snapshots"][0]["url"] = "https://example.invalid/registry.xml"
    manifest_path.write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )

    registry = load_iana_registry(tmp_path)

    assert registry.validation_status == "declared_unverified"
    assert registry.prefixes == ()
    assert any("metadato 'url'" in item for item in registry.diagnostics)


def test_malformed_xml_fails_validation_without_partial_table(tmp_path: Path) -> None:
    _copy_snapshot_bundle(tmp_path)
    filename = "iana-ipv4-special-registry.xml"
    (tmp_path / filename).write_bytes(b"<registry")
    _rewrite_manifest_hash(tmp_path, filename)

    registry = load_iana_registry(tmp_path)

    assert registry.validation_status == "declared_unverified"
    assert registry.prefixes == ()
    assert any(
        "iana-ipv4-special-registry.xml: XML malformado" in item
        for item in registry.diagnostics
    )


def test_incomplete_spar_record_is_reported_not_discarded(
    tmp_path: Path,
) -> None:
    _copy_snapshot_bundle(tmp_path)
    filename = "iana-ipv4-special-registry.xml"
    path = tmp_path / filename
    content = path.read_bytes().replace(
        b"<name>\"This network\"</name>",
        b"<missing-name>\"This network\"</missing-name>",
        1,
    )
    path.write_bytes(content)
    _rewrite_manifest_hash(tmp_path, filename)

    registry = load_iana_registry(tmp_path)

    assert registry.validation_status == "declared_unverified"
    assert registry.prefixes == ()
    assert any("sin address o name" in item for item in registry.diagnostics)


def test_malformed_prefix_is_reported_and_not_partially_loaded(
    tmp_path: Path,
) -> None:
    _copy_snapshot_bundle(tmp_path)
    filename = "ipv4-address-space.xml"
    path = tmp_path / filename
    content = path.read_bytes().replace(
        b"<prefix>000/8</prefix>",
        b"<prefix>bad-prefix/8</prefix>",
        1,
    )
    path.write_bytes(content)
    _rewrite_manifest_hash(tmp_path, filename)

    registry = load_iana_registry(tmp_path)

    assert registry.validation_status == "declared_unverified"
    assert registry.prefixes == ()
    assert any("prefijo inválido" in item for item in registry.diagnostics)
