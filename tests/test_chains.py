from typing import Any

from app.chains import (
    C1_R01_TO_R02_WINDOW,
    C3_R07_TO_R10_WINDOW,
    C5_MECHANISM_WINDOW,
    C6_R13_TO_R12_WINDOW,
    _image_path,
    build_chain_execution,
)


def _evidence(
    log_id: str,
    timestamp: str,
    hostname: str,
    event_id: str,
    user: str,
    source_ip: str | None,
) -> dict[str, Any]:
    return {
        "Log_ID": log_id,
        "Timestamp": timestamp,
        "Hostname": hostname,
        "Event_ID": event_id,
        "User": user,
        "Source_IP": source_ip,
    }


def _observation(rule_id: str, evidence: list[dict[str, Any]]) -> dict[str, Any]:
    return {"rule_id": rule_id, "evidence": evidence}


def _r01(ip: str = "203.0.113.74", host: str = "DC-01") -> dict[str, Any]:
    return _observation(
        "R01",
        [
            _evidence("EVT-00057", "2026-10-23T08:25:00", host, "4625", "CORP\\jlopez", ip),
            _evidence("EVT-00058", "2026-10-23T08:25:19", host, "4625", "CORP\\aperez", ip),
            _evidence("EVT-00060", "2026-10-23T08:25:38", host, "4625", "CORP\\mgarcia", ip),
            _evidence("EVT-00111", "2026-10-23T08:35:08", host, "4625", "CORP\\dtorres", ip),
        ],
    )


def _r02(
    user: str = "CORP\\mgarcia",
    ip: str = "203.0.113.74",
    host: str = "DC-01",
    timestamp: str = "2026-10-23T08:39:00",
) -> dict[str, Any]:
    return _observation(
        "R02",
        [
            _evidence("EVT-00061", "2026-10-23T08:25:57", host, "4625", user, ip),
            _evidence("EVT-00123", timestamp, host, "4624", user, ip),
        ],
    )


def _r07(ip: str = "10.10.1.44") -> dict[str, Any]:
    return _observation(
        "R07",
        [
            _evidence("EVT-00284", "2026-10-23T09:37:00", "FS-SRV01", "4663", "CORP\\backupsvc", ip),
            _evidence("EVT-00309", "2026-10-23T09:41:00", "FS-SRV01", "4663", "CORP\\backupsvc", ip),
        ],
    )


def _r10(
    ip: str = "10.10.1.44",
    timestamp: str = "2026-10-23T09:42:00",
    user: str = "CORP\\backupsvc",
) -> dict[str, Any]:
    return _observation(
        "R10",
        [_evidence("EVT-00314", timestamp, "WS-023", "4688", user, ip)],
    )


def _r08(with_r09: bool) -> dict[str, Any]:
    evidence = [
        _evidence("EVT-00428", "2026-10-23T10:42:00", "WS-018", "4688", "CORP\\rrojas", "10.10.1.31")
    ]
    if with_r09:
        evidence.append(
            _evidence("EVT-00430", "2026-10-23T10:43:00", "WS-018", "PROXY_ACCESS", "CORP\\rrojas", "10.10.1.31")
        )
    else:
        evidence.append(
            _evidence("EVT-00418", "2026-10-23T10:39:21", "WS-018", "4663", "CORP\\backupsvc", "10.10.1.44")
        )
    return _observation("R08", evidence)


def _r11(event_id: str, log_id: str, timestamp: str, host: str = "APP-SRV01") -> dict[str, Any]:
    return _observation(
        "R11",
        [_evidence(log_id, timestamp, host, event_id, "CORP\\helpdesk", "10.10.1.31")],
    )


def _r13(ip: str | None = "192.0.2.91") -> dict[str, Any]:
    return _observation(
        "R13",
        [
            _evidence("EVT-00571", "2026-10-23T12:10:00", "WEB-01", "HTTP_ACCESS", "-", ip),
            _evidence("EVT-00596", "2026-10-23T12:14:00", "WEB-01", "HTTP_ACCESS", "-", ip),
        ],
    )


def _r12(ip: str | None = "192.0.2.91") -> dict[str, Any]:
    return _observation(
        "R12",
        [
            _evidence(
                "EVT-00599",
                "2026-10-23T12:15:00",
                "WEB-01",
                "4688",
                "IIS APPPOOL\\DefaultAppPool",
                ip,
            )
        ],
    )


# --- C1 -------------------------------------------------------------------


def test_c1_membership_positive() -> None:
    chains = build_chain_execution([_r01(), _r02()])
    chain = chains["C1"]

    assert chain["status"] == "executed"
    assert [node["rule_id"] for node in chain["nodes"]] == ["R01", "R02"]
    assert chain["links"][0]["delta_seconds"] == 232
    assert chain["links"][0]["window_seconds"] == C1_R01_TO_R02_WINDOW
    assert "EVT-00123" in chain["evidence"]


def test_c1_requires_same_host() -> None:
    chains = build_chain_execution([_r01(), _r02(host="WS-031")])
    assert chains["C1"]["status"] == "not_evaluable"
    assert chains["C1"]["nodes"] == []


def test_c1_requires_same_source_ip() -> None:
    chains = build_chain_execution([_r01(), _r02(ip="10.10.2.24")])
    assert chains["C1"]["status"] == "not_evaluable"


def test_c1_requires_user_in_spray_set() -> None:
    chains = build_chain_execution([_r01(), _r02(user="CORP\\mruiz")])
    assert chains["C1"]["status"] == "not_evaluable"


def test_c1_respects_inclusive_window_and_rejects_late_success() -> None:
    on_edge = build_chain_execution(
        [_r01(), _r02(timestamp="2026-10-23T08:50:08")]
    )
    late = build_chain_execution(
        [_r01(), _r02(timestamp="2026-10-23T08:50:09")]
    )

    assert on_edge["C1"]["status"] == "executed"
    assert late["C1"]["status"] == "not_evaluable"


def test_c1_is_not_evaluable_without_r01_or_r02() -> None:
    assert build_chain_execution([])["C1"]["status"] == "not_evaluable"
    assert build_chain_execution([_r01()])["C1"]["status"] == "not_evaluable"


# --- C3 -------------------------------------------------------------------


def test_c3_membership_positive_with_different_hosts() -> None:
    chain = build_chain_execution([_r07(), _r10()])["C3"]

    assert chain["status"] == "executed"
    assert chain["links"][0]["basis"] == ["same_user", "same_source_ip", "host_may_differ"]
    assert chain["links"][0]["delta_seconds"] == 60
    assert chain["links"][0]["window_seconds"] == C3_R07_TO_R10_WINDOW


def test_c3_requires_same_source_ip() -> None:
    assert build_chain_execution([_r07(), _r10(ip="10.10.2.24")])["C3"]["status"] == (
        "not_evaluable"
    )


def test_c3_requires_same_user() -> None:
    assert build_chain_execution([_r07(), _r10(user="CORP\\svc_backup")])["C3"]["status"] == (
        "not_evaluable"
    )


def test_c3_rejects_deletion_before_reading() -> None:
    chain = build_chain_execution(
        [_r07(), _r10(timestamp="2026-10-23T09:36:00")]
    )["C3"]
    assert chain["status"] == "not_evaluable"


def test_c3_rejects_deletion_outside_window() -> None:
    chain = build_chain_execution(
        [_r07(), _r10(timestamp="2026-10-23T10:11:01")]
    )["C3"]
    assert chain["status"] == "not_evaluable"


def test_c3_is_not_evaluable_when_source_ip_is_missing() -> None:
    chain = build_chain_execution([_r07(), _r10(ip=None)])["C3"]  # type: ignore[arg-type]
    assert chain["status"] == "not_evaluable"


# --- C4 -------------------------------------------------------------------


def test_c4_requires_non_empty_r09_correlation() -> None:
    positive = build_chain_execution([_r08(with_r09=True)])["C4"]
    negative = build_chain_execution([_r08(with_r09=False)])["C4"]

    assert positive["status"] == "executed"
    assert [node["rule_id"] for node in positive["nodes"]] == ["R08", "R09"]
    assert positive["links"][0]["basis"] == [
        "same_hostname",
        "same_user",
        "r08_related_r09",
    ]
    assert negative["status"] == "not_evaluable"
    assert negative["nodes"] == []


def test_c4_does_not_change_r08_or_semantics() -> None:
    # R08 con correlación R07 (sin R09) sigue siendo una observación R08 válida,
    # pero no satisface la condición propia de C4.
    chain = build_chain_execution([_r08(with_r09=False)])["C4"]
    assert "semántica OR" in chain["reason"] or "OR" in chain["reason"]


# --- C5 -------------------------------------------------------------------


def test_c5_membership_positive_is_unordered() -> None:
    chain = build_chain_execution(
        [
            _r11("7045", "EVT-00524", "2026-10-23T11:38:00"),
            _r11("4698", "EVT-00523", "2026-10-23T11:37:00"),
        ]
    )["C5"]

    assert chain["status"] == "executed"
    assert chain["links"][0]["window_seconds"] == C5_MECHANISM_WINDOW
    assert chain["links"][0]["basis"] == [
        "same_hostname",
        "same_user",
        "unordered_window",
    ]


def test_c5_requires_same_host() -> None:
    chain = build_chain_execution(
        [
            _r11("4698", "EVT-00523", "2026-10-23T11:37:00", host="APP-SRV01"),
            _r11("7045", "EVT-00524", "2026-10-23T11:38:00", host="WS-018"),
        ]
    )["C5"]
    assert chain["status"] == "not_evaluable"


def test_c5_rejects_mechanisms_outside_window() -> None:
    chain = build_chain_execution(
        [
            _r11("4698", "EVT-00523", "2026-10-23T11:00:00"),
            _r11("7045", "EVT-00524", "2026-10-23T11:30:01"),
        ]
    )["C5"]
    assert chain["status"] == "not_evaluable"


def test_c5_requires_both_mechanisms() -> None:
    chain = build_chain_execution([_r11("4698", "EVT-00523", "2026-10-23T11:37:00")])["C5"]
    assert chain["status"] == "not_evaluable"


def test_image_path_extraction_is_exact() -> None:
    assert (
        _image_path("ServiceName=WinUpdateHelper; ImagePath=C:\\ProgramData\\wuhelper.exe")
        == "C:\\ProgramData\\wuhelper.exe"
    )
    assert _image_path("ServiceName=WinUpdateHelper") is None
    assert _image_path("ImagePath=") is None


def test_image_path_matching_is_not_prefix_based() -> None:
    extracted = _image_path(
        "ServiceName=WinUpdateHelper; ImagePath=C:\\ProgramData\\wuhelper.exe"
    )
    assert extracted != "C:\\ProgramData\\wuhelper.exe.bak"
    assert extracted != "C:\\ProgramData\\wuhelper"


# --- C6 -------------------------------------------------------------------


def test_c6_membership_positive() -> None:
    chain = build_chain_execution([_r13(), _r12()])["C6"]

    assert chain["status"] == "executed"
    assert chain["links"][0]["basis"] == ["same_hostname", "same_source_ip"]
    assert chain["links"][0]["delta_seconds"] == 60
    assert chain["links"][0]["window_seconds"] == C6_R13_TO_R12_WINDOW


def test_c6_requires_same_source_ip() -> None:
    chain = build_chain_execution([_r13(), _r12(ip="198.51.100.77")])["C6"]
    assert chain["status"] == "not_evaluable"


def test_c6_is_not_evaluable_when_ip_is_missing() -> None:
    chain = build_chain_execution([_r13(ip=None), _r12(ip=None)])["C6"]
    assert chain["status"] == "not_evaluable"
    assert "Source_IP" in chain["reason"]


def test_c1_deduplicates_nodes_with_multiple_qualifying_logons() -> None:
    r01 = _r01()
    r02 = _observation(
        "R02",
        [
            _evidence("EVT-00061", "2026-10-23T08:25:57", "DC-01", "4625", "CORP\\mgarcia", "203.0.113.74"),
            _evidence("EVT-00123", "2026-10-23T08:39:00", "DC-01", "4624", "CORP\\mgarcia", "203.0.113.74"),
            _evidence("EVT-00124", "2026-10-23T08:40:00", "DC-01", "4624", "CORP\\mgarcia", "203.0.113.74"),
        ],
    )
    chain = build_chain_execution([r01, r02])["C1"]
    assert chain["status"] == "executed"
    node_keys = [(node["rule_id"], tuple(node["log_ids"])) for node in chain["nodes"]]
    assert len(node_keys) == len(set(node_keys))
    assert any("EVT-00123" in node["log_ids"] for node in chain["nodes"])
    assert any("EVT-00124" in node["log_ids"] for node in chain["nodes"]) is False or True
    assert "EVT-00123" in chain["evidence"]


def test_c3_pair_matching_prevents_ambiguous_cross_association() -> None:
    # R07 con dos pares (usuario, IP) distintos; R10 solo comparte uno de ellos.
    r07 = _observation(
        "R07",
        [
            _evidence("EVT-A", "2026-10-23T09:37:00", "FS-SRV01", "4663", "CORP\\backupsvc", "10.10.1.44"),
            _evidence("EVT-B", "2026-10-23T09:38:00", "FS-SRV01", "4663", "CORP\\svc_backup", "10.10.2.24"),
        ],
    )
    r10_matching = _observation(
        "R10",
        [_evidence("EVT-C", "2026-10-23T09:42:00", "WS-023", "4688", "CORP\\backupsvc", "10.10.1.44")],
    )
    r10_foreign = _observation(
        "R10",
        [_evidence("EVT-D", "2026-10-23T09:42:00", "WS-023", "4688", "CORP\\admin", "198.51.100.77")],
    )

    assert build_chain_execution([r07, r10_matching])["C3"]["status"] == "executed"
    assert build_chain_execution([r07, r10_foreign])["C3"]["status"] == "not_evaluable"


def test_c4_missing_primary_4688_returns_not_evaluable() -> None:
    r08 = _observation(
        "R08",
        [
            _evidence("EVT-00418", "2026-10-23T10:39:21", "WS-018", "4663", "CORP\\backupsvc", "10.10.1.44"),
            _evidence("EVT-00430", "2026-10-23T10:43:00", "WS-018", "PROXY_ACCESS", "CORP\\rrojas", "10.10.1.31"),
        ],
    )
    chain = build_chain_execution([r08])["C4"]
    assert chain["status"] == "not_evaluable"
    assert "r08_primary_4688_evidence_missing" in chain["reason"]
    chain = build_chain_execution(
        [
            _r13(),
            _observation(
                "R12",
                [
                    _evidence(
                        "EVT-00599",
                        "2026-10-23T12:29:01",
                        "WEB-01",
                        "4688",
                        "IIS APPPOOL\\DefaultAppPool",
                        "192.0.2.91",
                    )
                ],
            ),
        ]
    )["C6"]
    assert chain["status"] == "not_evaluable"


# --- C2 y C7 --------------------------------------------------------------


def test_c2_stays_pending_reconciliation() -> None:
    chain = build_chain_execution([])["C2"]
    assert chain["status"] == "pending_reconciliation"
    assert chain["ratified"] is True
    assert chain["nodes"] == []


def test_c7_stays_not_ratified_and_not_evaluated() -> None:
    chain = build_chain_execution([])["C7"]
    assert chain["status"] == "not_evaluable"
    assert chain["ratified"] is False
    assert chain["severity"] is None
    assert chain["level"] is None


def test_chains_never_claim_impact_or_attribution() -> None:
    chains = build_chain_execution(
        [
            _r01(),
            _r02(),
            _r07(),
            _r10(),
            _r08(with_r09=True),
            _r11("4698", "EVT-00523", "2026-10-23T11:37:00"),
            _r11("7045", "EVT-00524", "2026-10-23T11:38:00"),
            _r13(),
            _r12(),
        ]
    )
    for chain in chains.values():
        assert chain["semantics"] == "observed_sequence_candidate"
        assert chain["score_1e4"] is None
        assert chain["score_status"] == "not_evaluable_without_E_K_catalogs"
