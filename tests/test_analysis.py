import os
import re
from collections import Counter
from datetime import datetime, timedelta
from io import BytesIO
from pathlib import Path

import pytest
from openpyxl import Workbook, load_workbook

from app.analysis import analyze_workbook, ingest_workbook

_ORIGINAL_R01_LOG_IDS = (
    "EVT-00057",
    "EVT-00058",
    "EVT-00060",
    "EVT-00061",
    "EVT-00063",
    "EVT-00065",
    "EVT-00066",
    "EVT-00068",
    "EVT-00069",
    "EVT-00071",
    "EVT-00073",
    "EVT-00074",
    "EVT-00075",
    "EVT-00077",
    "EVT-00078",
    "EVT-00079",
    "EVT-00081",
    "EVT-00084",
    "EVT-00085",
    "EVT-00086",
    "EVT-00088",
    "EVT-00092",
    "EVT-00094",
    "EVT-00096",
    "EVT-00099",
    "EVT-00100",
    "EVT-00101",
    "EVT-00104",
    "EVT-00105",
    "EVT-00107",
    "EVT-00108",
    "EVT-00110",
    "EVT-00111",
)


def _minimal_workbook(rows: list[list[object]]) -> bytes:
    workbook = Workbook()
    worksheet = workbook.active
    worksheet.title = "SIEM Export"
    worksheet.append(
        [
            "Log_ID",
            "Timestamp",
            "Hostname",
            "Event_ID",
            "User",
            "Source_IP",
            "Destination",
            "Log_Source",
            "Event_Description",
            "Process_CommandLine",
            "Result",
            "Severity",
        ]
    )
    for row in rows:
        worksheet.append(row)
    stream = BytesIO()
    workbook.save(stream)
    return stream.getvalue()


def _base_row(log_id: str, event_id: int = 7036) -> list[object]:
    return [
        log_id,
        "2026-10-23 08:00:00",
        "WS-014",
        event_id,
        "CORP\\user",
        "10.10.1.14",
        None,
        "System",
        "Service entered running state",
        None,
        "Success",
        "Informational",
    ]


def _proxy_row(
    log_id: str,
    command_line: object,
    *,
    hostname: object = "PROXY-01",
    user: object = "CORP\\user",
    destination: object = "203.0.113.20:443",
    timestamp: str = "2026-10-23 08:00:00",
) -> list[object]:
    row = _base_row(log_id, "PROXY_ACCESS")
    row[1] = timestamp
    row[2] = hostname
    row[4] = user
    row[5] = "192.0.2.10"
    row[6] = destination
    row[7] = "Proxy"
    row[8] = "Proxy access record"
    row[9] = command_line
    return row


def _r07_row(
    log_id: str,
    command_line: object,
    *,
    event_id: object = 4663,
    user: object = "CORP\\backupsvc",
    hostname: object = "FS-SRV01",
    destination: object = "\\\\FS-SRV01\\Finance",
    timestamp: str = "2026-10-23 09:00:00",
    log_source: object = "Security",
) -> list[object]:
    row = _base_row(log_id, event_id)
    row[1] = timestamp
    row[2] = hostname
    row[4] = user
    row[6] = destination
    row[7] = log_source
    row[8] = "Object access"
    row[9] = command_line
    return row


def _r08_row(
    log_id: str,
    command_line: object,
    *,
    user: object = r"CORP\backupsvc",
    hostname: object = "FS-SRV01",
    timestamp: str = "2026-10-23 09:00:00",
) -> list[object]:
    row = _base_row(log_id, 4688)
    row[1] = timestamp
    row[2] = hostname
    row[4] = user
    row[8] = "Process creation"
    row[9] = command_line
    return row


def _http_row(
    log_id: object,
    timestamp: str,
    *,
    source_ip: object = "192.0.2.91",
    uri: object = "/safe",
    result: object = 200,
    hostname: object = "WEB-01",
    user: object = "-",
) -> list[object]:
    row = _base_row(str(log_id), "HTTP_ACCESS")
    row[0] = log_id
    row[1] = timestamp
    row[2] = hostname
    row[4] = user
    row[5] = source_ip
    row[7] = "IIS"
    row[8] = "HTTP request"
    row[9] = uri
    row[10] = result
    return row


def _r01_row(
    log_id: str,
    timestamp: str,
    user: object = "CORP\\user",
    source_ip: object = "10.10.1.14",
    hostname: object = "WS-014",
) -> list[object]:
    row = _base_row(log_id, 4625)
    row[1] = timestamp
    row[2] = hostname
    row[4] = user
    row[5] = source_ip
    row[8] = "An account failed to log on"
    row[10] = "Failure"
    return row


def _observation_for_rule(result: dict[str, object], rule_id: str) -> dict[str, object]:
    return next(
        item for item in result["observations"] if item["rule_id"] == rule_id
    )


def _assert_observation_does_not_infer_impact(
    observation: dict[str, object],
) -> None:
    assert observation["impact_demonstrated"] is False
    assert observation["incident_attribution"] is False
    assert observation["level"] is None
    assert observation["score_1e4"] is None
    assert observation["confidence_basis_points"] is None


def test_partial_analysis_separates_pending_rules_and_activity() -> None:
    result = analyze_workbook(_minimal_workbook([_base_row("EVT-TEST-1")]))

    assert result["status"] == "partial"
    assert result["completeness"]["records_seen"] == 1
    assert result["completeness"]["records_evaluated"] == 1
    assert result["rule_execution"]["R03"]["status"] == "executed"
    assert result["rule_execution"]["R08"]["status"] == "executed"
    assert result["rule_execution"]["R09"]["status"] == "executed"
    assert result["chain_execution"]["C1"]["status"] == "not_evaluable"
    assert result["chain_execution"]["C2"]["status"] == "pending_reconciliation"
    assert result["chain_execution"]["C7"]["ratified"] is False
    assert result["observations"] == []
    assert result["activity_summary"] == {
        "records_loaded": 1,
        "observations_emitted": 0,
        "no_observations_means_no_rule_match_not_no_activity": True,
    }


def test_r02_observation_traces_failures_and_success() -> None:
    rows = []
    for index in range(3):
        row = _base_row(f"EVT-FAIL-{index}", 4625)
        row[1] = f"2026-10-23 08:0{index}:00"
        row[8] = "An account failed to log on"
        row[10] = "Failure"
        rows.append(row)
    success = _base_row("EVT-SUCCESS", 4624)
    success[1] = "2026-10-23 08:04:00"
    success[8] = "An account was successfully logged on"
    rows.append(success)

    result = analyze_workbook(_minimal_workbook(rows))
    observation = next(
        item for item in result["observations"] if item["rule_id"] == "R02"
    )

    assert [item["Log_ID"] for item in observation["evidence"]] == [
        "EVT-FAIL-0",
        "EVT-FAIL-1",
        "EVT-FAIL-2",
        "EVT-SUCCESS",
    ]
    assert observation["impact_demonstrated"] is False
    assert observation["incident_attribution"] is False
    assert observation["score_1e4"] is None


def test_r02_includes_exact_window_boundary_and_preserves_input_evidence_order() -> None:
    success = _base_row("EVT-R02-SUCCESS", 4624)
    success[1] = "2026-10-23 08:15:00"

    at_boundary = _base_row("EVT-R02-BOUNDARY", 4625)
    at_boundary[1] = "2026-10-23 08:00:00"

    later_failure = _base_row("EVT-R02-LATER", 4625)
    later_failure[1] = "2026-10-23 08:14:00"

    earlier_failure = _base_row("EVT-R02-EARLIER", 4625)
    earlier_failure[1] = "2026-10-23 08:01:00"

    too_old = _base_row("EVT-R02-TOO-OLD", 4625)
    too_old[1] = "2026-10-23 07:59:59"

    same_time = _base_row("EVT-R02-SAME-TIME", 4625)
    same_time[1] = "2026-10-23 08:15:00"

    other_user = _base_row("EVT-R02-OTHER-USER", 4625)
    other_user[1] = "2026-10-23 08:10:00"
    other_user[4] = "CORP\\other"

    other_host = _base_row("EVT-R02-OTHER-HOST", 4625)
    other_host[1] = "2026-10-23 08:10:00"
    other_host[2] = "WS-OTHER"

    rows = [
        at_boundary,
        success,
        later_failure,
        too_old,
        same_time,
        other_user,
        earlier_failure,
        other_host,
    ]
    result = analyze_workbook(_minimal_workbook(rows))
    observation = _observation_for_rule(result, "R02")

    assert [item["Log_ID"] for item in observation["evidence"]] == [
        "EVT-R02-BOUNDARY",
        "EVT-R02-LATER",
        "EVT-R02-EARLIER",
        "EVT-R02-SUCCESS",
    ]
    _assert_observation_does_not_infer_impact(observation)


def test_r02_does_not_match_fewer_than_three_eligible_failures() -> None:
    first_failure = _base_row("EVT-R02-FAIL-1", 4625)
    first_failure[1] = "2026-10-23 08:00:00"

    second_failure = _base_row("EVT-R02-FAIL-2", 4625)
    second_failure[1] = "2026-10-23 08:01:00"

    same_time_failure = _base_row("EVT-R02-SAME-TIME", 4625)
    same_time_failure[1] = "2026-10-23 08:02:00"

    success = _base_row("EVT-R02-SUCCESS", 4624)
    success[1] = "2026-10-23 08:02:00"

    result = analyze_workbook(
        _minimal_workbook(
            [first_failure, second_failure, same_time_failure, success]
        )
    )

    assert not any(item["rule_id"] == "R02" for item in result["observations"])
    assert result["rule_execution"]["R02"]["matched_observation_count"] == 0


def test_r01_matches_exact_minimum_and_traces_ordered_evidence() -> None:
    rows = [
        _r01_row("EVT-R01-5", "2026-10-23 08:04:00", "user-c"),
        _r01_row("EVT-R01-3", "2026-10-23 08:02:00", "user-a"),
        _r01_row("EVT-R01-1", "2026-10-23 08:00:00", "user-a"),
        _r01_row("EVT-R01-4", "2026-10-23 08:03:00", "user-b"),
        _r01_row("EVT-R01-2", "2026-10-23 08:01:00", "user-b"),
    ]

    result = analyze_workbook(_minimal_workbook(rows))
    observation = _observation_for_rule(result, "R01")

    assert [item["Log_ID"] for item in observation["evidence"]] == [
        "EVT-R01-1",
        "EVT-R01-2",
        "EVT-R01-3",
        "EVT-R01-4",
        "EVT-R01-5",
    ]
    assert result["rule_execution"]["R01"]["status"] == "executed"
    assert result["rule_execution"]["R01"]["matched_observation_count"] == 1
    assert result["rule_execution"]["R01"]["records_evaluated"] == 5
    _assert_observation_does_not_infer_impact(observation)
    assert "no demuestra autenticación exitosa" in observation["description"]


@pytest.mark.parametrize(
    "rows",
    [
        [
            _r01_row(f"EVT-R01-FOUR-{index}", f"2026-10-23 08:0{index}:00", f"user-{index}")
            for index in range(4)
        ],
        [
            _r01_row(
                f"EVT-R01-TWO-USERS-{index}",
                f"2026-10-23 08:0{index}:00",
                "user-a" if index % 2 == 0 else "user-b",
            )
            for index in range(5)
        ],
    ],
)
def test_r01_rejects_below_count_or_distinct_user_thresholds(
    rows: list[list[object]],
) -> None:
    result = analyze_workbook(_minimal_workbook(rows))

    assert not any(item["rule_id"] == "R01" for item in result["observations"])
    assert result["rule_execution"]["R01"]["matched_observation_count"] == 0


def test_r01_excludes_left_boundary_and_includes_right_boundary() -> None:
    left_boundary_rows = [
        _r01_row("EVT-R01-LEFT", "2026-10-23 08:00:00", "user-a"),
        _r01_row("EVT-R01-LEFT-2", "2026-10-23 08:00:01", "user-b"),
        _r01_row("EVT-R01-LEFT-3", "2026-10-23 08:00:02", "user-c"),
        _r01_row("EVT-R01-LEFT-4", "2026-10-23 08:09:59", "user-a"),
        _r01_row("EVT-R01-LEFT-5", "2026-10-23 08:10:00", "user-b"),
    ]
    left_result = analyze_workbook(_minimal_workbook(left_boundary_rows))
    assert not any(item["rule_id"] == "R01" for item in left_result["observations"])

    right_boundary_rows = [
        _r01_row("EVT-R01-RIGHT-1", "2026-10-23 08:00:01", "user-a"),
        _r01_row("EVT-R01-RIGHT-2", "2026-10-23 08:00:02", "user-b"),
        _r01_row("EVT-R01-RIGHT-3", "2026-10-23 08:01:00", "user-c"),
        _r01_row("EVT-R01-RIGHT-4", "2026-10-23 08:02:00", "user-a"),
        _r01_row("EVT-R01-RIGHT-5", "2026-10-23 08:10:00", "user-b"),
    ]
    right_result = analyze_workbook(_minimal_workbook(right_boundary_rows))
    observation = _observation_for_rule(right_result, "R01")
    assert "EVT-R01-RIGHT-5" in [
        item["Log_ID"] for item in observation["evidence"]
    ]


def test_r01_does_not_combine_events_outside_one_sliding_window() -> None:
    rows = [
        _r01_row("EVT-R01-OLD-1", "2026-10-23 08:00:00", "user-a"),
        _r01_row("EVT-R01-OLD-2", "2026-10-23 08:00:01", "user-b"),
        _r01_row("EVT-R01-OLD-3", "2026-10-23 08:00:02", "user-c"),
        _r01_row("EVT-R01-NEW-1", "2026-10-23 08:10:01", "user-a"),
        _r01_row("EVT-R01-NEW-2", "2026-10-23 08:10:02", "user-b"),
    ]

    result = analyze_workbook(_minimal_workbook(rows))

    assert not any(item["rule_id"] == "R01" for item in result["observations"])


def test_r01_does_not_mix_different_ips_or_hostnames() -> None:
    rows = [
        _r01_row("EVT-R01-A1", "2026-10-23 08:00:00", "user-a"),
        _r01_row("EVT-R01-A2", "2026-10-23 08:01:00", "user-b"),
        _r01_row("EVT-R01-A3", "2026-10-23 08:02:00", "user-c"),
        _r01_row("EVT-R01-B1", "2026-10-23 08:00:00", "user-a", hostname="WS-OTHER"),
        _r01_row("EVT-R01-B2", "2026-10-23 08:01:00", "user-b", hostname="WS-OTHER"),
        _r01_row("EVT-R01-C1", "2026-10-23 08:00:00", "user-c", source_ip="10.10.1.99"),
        _r01_row("EVT-R01-C2", "2026-10-23 08:01:00", "user-d", source_ip="10.10.1.99"),
    ]

    result = analyze_workbook(_minimal_workbook(rows))

    assert not any(item["rule_id"] == "R01" for item in result["observations"])


@pytest.mark.parametrize(
    "source_ip",
    [
        "10.10.1.14",
        "192.0.0.9",
        "100.64.0.1",
        "203.0.113.74",
        "8.8.8.8",
    ],
)
def test_r01_accepts_syntactically_valid_ips_regardless_of_category(
    source_ip: str,
) -> None:
    rows = [
        _r01_row(
            f"EVT-R01-IP-{index}",
            f"2026-10-23 08:0{index}:00",
            f"user-{index % 3}",
            source_ip=source_ip,
        )
        for index in range(5)
    ]

    result = analyze_workbook(_minimal_workbook(rows))

    assert _observation_for_rule(result, "R01")["evidence"]


@pytest.mark.parametrize("source_ip", [None, "not-an-ip"])
def test_r01_excludes_missing_or_invalid_ips(source_ip: object) -> None:
    rows = [
        _r01_row(
            f"EVT-R01-BAD-IP-{index}",
            f"2026-10-23 08:0{index}:00",
            f"user-{index % 3}",
            source_ip=source_ip,
        )
        for index in range(5)
    ]

    result = analyze_workbook(_minimal_workbook(rows))

    assert not any(item["rule_id"] == "R01" for item in result["observations"])


def test_r01_does_not_count_null_or_blank_users_as_distinct() -> None:
    rows = [
        _r01_row("EVT-R01-USER-1", "2026-10-23 08:00:00", None),
        _r01_row("EVT-R01-USER-2", "2026-10-23 08:01:00", ""),
        _r01_row("EVT-R01-USER-3", "2026-10-23 08:02:00", "   "),
        _r01_row("EVT-R01-USER-4", "2026-10-23 08:03:00", "user-a"),
        _r01_row("EVT-R01-USER-5", "2026-10-23 08:04:00", "user-b"),
    ]

    result = analyze_workbook(_minimal_workbook(rows))

    assert not any(item["rule_id"] == "R01" for item in result["observations"])
    assert result["rule_execution"]["R01"]["records_evaluated"] == 5


def test_r01_blank_user_events_count_but_are_preserved_as_evidence() -> None:
    rows = [
        _r01_row("EVT-R01-USERLESS", "2026-10-23 08:00:00", None),
        _r01_row("EVT-R01-USER-A", "2026-10-23 08:01:00", "user-a"),
        _r01_row("EVT-R01-USER-B", "2026-10-23 08:02:00", "user-b"),
        _r01_row("EVT-R01-USER-C", "2026-10-23 08:03:00", "user-c"),
        _r01_row("EVT-R01-USER-D", "2026-10-23 08:04:00", "user-a"),
    ]

    result = analyze_workbook(_minimal_workbook(rows))

    observation = _observation_for_rule(result, "R01")
    assert [item["Log_ID"] for item in observation["evidence"]] == [
        "EVT-R01-USERLESS",
        "EVT-R01-USER-A",
        "EVT-R01-USER-B",
        "EVT-R01-USER-C",
        "EVT-R01-USER-D",
    ]


def test_r01_deduplicates_identical_log_ids_without_double_counting() -> None:
    rows = [
        _r01_row("EVT-R01-DUP-1", "2026-10-23 08:00:00", "user-a"),
        _r01_row("EVT-R01-DUP-2", "2026-10-23 08:01:00", "user-b"),
        _r01_row("EVT-R01-DUP-3", "2026-10-23 08:02:00", "user-c"),
        _r01_row("EVT-R01-DUP-4", "2026-10-23 08:03:00", "user-a"),
    ]
    result_below_threshold = analyze_workbook(
        _minimal_workbook(rows + [rows[0].copy()])
    )
    assert not any(
        item["rule_id"] == "R01" for item in result_below_threshold["observations"]
    )

    five_unique = rows + [
        _r01_row("EVT-R01-DUP-5", "2026-10-23 08:04:00", "user-b")
    ]
    result_at_threshold = analyze_workbook(
        _minimal_workbook(five_unique + [five_unique[0].copy()])
    )
    evidence_ids = [
        item["Log_ID"]
        for item in _observation_for_rule(result_at_threshold, "R01")["evidence"]
    ]
    assert evidence_ids == [
        "EVT-R01-DUP-1",
        "EVT-R01-DUP-2",
        "EVT-R01-DUP-3",
        "EVT-R01-DUP-4",
        "EVT-R01-DUP-5",
    ]


def test_r01_excludes_conflicting_log_ids_and_reports_them_in_existing_reason() -> None:
    rows = [
        _r01_row("EVT-R01-CONFLICT", "2026-10-23 08:00:00", "user-a"),
        _r01_row("EVT-R01-CONFLICT", "2026-10-23 08:00:00", "user-d"),
        _r01_row("EVT-R01-CLEAN-1", "2026-10-23 08:01:00", "user-a"),
        _r01_row("EVT-R01-CLEAN-2", "2026-10-23 08:02:00", "user-b"),
        _r01_row("EVT-R01-CLEAN-3", "2026-10-23 08:03:00", "user-c"),
        _r01_row("EVT-R01-CLEAN-4", "2026-10-23 08:04:00", "user-a"),
    ]

    result = analyze_workbook(_minimal_workbook(rows))

    assert not any(item["rule_id"] == "R01" for item in result["observations"])
    assert "EVT-R01-CONFLICT" in result["rule_execution"]["R01"]["reason"]
    assert "conflicto de identidad" in result["rule_execution"]["R01"]["reason"]


def test_r01_consolidates_overlapping_windows_and_preserves_all_evidence() -> None:
    rows = [
        _r01_row(
            f"EVT-R01-OVERLAP-{index}",
            f"2026-10-23 08:0{index}:00",
            f"user-{index % 3}",
        )
        for index in range(8)
    ]

    result = analyze_workbook(_minimal_workbook(rows))

    observations = [
        item for item in result["observations"] if item["rule_id"] == "R01"
    ]
    assert len(observations) == 1
    evidence_ids = [item["Log_ID"] for item in observations[0]["evidence"]]
    assert evidence_ids == [f"EVT-R01-OVERLAP-{index}" for index in range(8)]
    assert len(evidence_ids) == len(set(evidence_ids))


def test_r01_consolidates_separate_qualifying_windows_for_the_same_key() -> None:
    rows = [
        _r01_row(
            f"EVT-R01-CLUSTER-{cluster}-{index}",
            f"2026-10-23 08:{minute:02d}:00",
            f"user-{index % 3}",
        )
        for cluster, start_minute in ((1, 0), (2, 20))
        for index, minute in enumerate(range(start_minute, start_minute + 5))
    ]

    result = analyze_workbook(_minimal_workbook(rows))

    observations = [
        item for item in result["observations"] if item["rule_id"] == "R01"
    ]
    assert len(observations) == 1
    assert len(observations[0]["evidence"]) == 10
    assert result["rule_execution"]["R01"]["matched_observation_count"] == 1


def test_r01_marks_initially_incomplete_coverage_without_inventing_events() -> None:
    rows = [
        _r01_row(
            f"EVT-R01-COVERAGE-{index}",
            f"2026-10-23 08:0{index}:00",
            f"user-{index % 3}",
        )
        for index in range(5)
    ]

    result = analyze_workbook(_minimal_workbook(rows))
    observation = _observation_for_rule(result, "R01")

    assert "cobertura inicial parcial" in observation["description"]
    assert "no se infiere actividad fuera del workbook" in observation["description"]
    assert "cobertura inicial parcial" in result["rule_execution"]["R01"]["reason"]
    assert "08:00:00" not in observation["description"]


def test_r07_emits_one_observation_with_literal_command_evidence() -> None:
    rows = [
        _r07_row(
            f"EVT-R07-{index:02}",
            f"File access: document-{index}.xlsx",
            timestamp=f"2026-10-23 09:0{index}:00",
        )
        for index in range(10)
    ]

    result = analyze_workbook(_minimal_workbook(rows))
    observation = _observation_for_rule(result, "R07")

    assert result["rule_execution"]["R07"]["status"] == "executed"
    assert result["rule_execution"]["R07"]["records_in_scope"] == 10
    assert result["rule_execution"]["R07"]["records_evaluated"] == 10
    assert result["rule_execution"]["R07"]["matched_observation_count"] == 1
    assert [item["Log_ID"] for item in observation["evidence"]] == [
        f"EVT-R07-{index:02}" for index in range(10)
    ]
    assert "10 valores literales distintos" in observation["description"]
    assert "no demuestra ejecución" in observation["description"]
    assert observation["severity"] is None
    assert observation["severity_status"] == "not_defined"
    assert observation["score_1e4"] is None
    assert observation["confidence_basis_points"] is None
    assert observation["level"] is None
    assert observation["impact_demonstrated"] is False
    assert observation["incident_attribution"] is False
    assert "Process_CommandLine" not in observation["evidence"][0]


def test_r07_selects_only_event_4663_and_does_not_use_log_source() -> None:
    rows = [
        _r07_row(
            f"EVT-R07-SOURCE-{index:02}",
            f"File access: document-{index}.xlsx",
            log_source="Custom source",
        )
        for index in range(9)
    ]
    rows.append(
        _r07_row(
            "EVT-R07-NON-4663",
            "File access: document-extra.xlsx",
            event_id=7036,
        )
    )

    result = analyze_workbook(_minimal_workbook(rows))

    assert result["rule_execution"]["R07"]["records_in_scope"] == 9
    assert result["rule_execution"]["R07"]["records_evaluated"] == 9
    assert result["rule_execution"]["R07"]["matched_observation_count"] == 0
    assert not any(item["rule_id"] == "R07" for item in result["observations"])


def test_r07_identical_duplicate_log_id_counts_once() -> None:
    rows = [
        _r07_row(
            f"EVT-R07-DUP-{index:02}",
            f"File access: document-{index}.xlsx",
        )
        for index in range(9)
    ]
    rows.append(rows[0].copy())

    result = analyze_workbook(_minimal_workbook(rows))

    assert result["rule_execution"]["R07"]["records_in_scope"] == 10
    assert result["rule_execution"]["R07"]["records_evaluated"] == 9
    assert result["rule_execution"]["R07"]["matched_observation_count"] == 0
    assert "Se deduplicaron 1 filas idénticas" in result["rule_execution"]["R07"]["reason"]


def test_r07_excludes_conflicting_id_across_event_ids() -> None:
    rows = [
        _r07_row(
            f"EVT-R07-CONFLICT-{index:02}",
            f"File access: document-{index}.xlsx",
        )
        for index in range(9)
    ]
    rows.append(_r07_row("EVT-R07-CROSS-CONFLICT", "File access: extra.xlsx"))
    rows.append(
        _r07_row(
            "EVT-R07-CROSS-CONFLICT",
            "Different event content",
            event_id=7036,
        )
    )

    result = analyze_workbook(_minimal_workbook(rows))

    assert result["rule_execution"]["R07"]["records_evaluated"] == 9
    assert result["rule_execution"]["R07"]["matched_observation_count"] == 0
    assert "EVT-R07-CROSS-CONFLICT" in result["rule_execution"]["R07"]["reason"]


def test_r07_conflict_signature_preserves_cell_types() -> None:
    rows = [
        _r07_row(
            f"EVT-R07-TYPED-{index:02}",
            f"File access: document-{index}.xlsx",
        )
        for index in range(9)
    ]
    rows.append(
        _r07_row("EVT-R07-TYPED-CONFLICT", "File access: extra.xlsx", event_id=4663)
    )
    rows.append(
        _r07_row(
            "EVT-R07-TYPED-CONFLICT",
            "File access: extra.xlsx",
            event_id="4663",
        )
    )

    result = analyze_workbook(_minimal_workbook(rows))

    assert result["rule_execution"]["R07"]["matched_observation_count"] == 0
    assert "EVT-R07-TYPED-CONFLICT" in result["rule_execution"]["R07"]["reason"]


def test_r07_invalid_timestamp_is_reported_without_uncaught_error() -> None:
    rows = [
        _r07_row(
            f"EVT-R07-TIME-{index:02}",
            f"File access: document-{index}.xlsx",
        )
        for index in range(9)
    ]
    rows.append(
        _r07_row(
            "EVT-R07-INVALID-TIME",
            "File access: document-extra.xlsx",
            timestamp="invalid timestamp",
        )
    )

    result = analyze_workbook(_minimal_workbook(rows))

    assert result["rule_execution"]["R07"]["records_evaluated"] == 9
    assert result["rule_execution"]["R07"]["matched_observation_count"] == 0
    assert "EVT-R07-INVALID-TIME" in result["rule_execution"]["R07"]["reason"]


def test_r08_integrates_qualified_r07_and_r09_evidence_without_changing_contract() -> None:
    rows = [
        _r07_row(
            f"EVT-R08-R07-{index:02}",
            f"File access: document-{index}.xlsx",
            timestamp="2026-10-23 08:59:00",
        )
        for index in range(10)
    ]
    rows.extend(
        _proxy_row(
            f"EVT-R08-R09-{index:02}",
            f"bytes_out={index + 1} uri=/upload/session/{index}",
            hostname="FS-SRV01",
            user=r"CORP\backupsvc",
            timestamp="2026-10-23 09:00:00",
        )
        for index in range(10)
    )
    rows.append(
        _r08_row(
            "EVT-R08-ARCHIVE",
            r'7z.exe a "C:\Users\Public\archive.7z" C:\Finance\*.xlsx',
        )
    )

    result = analyze_workbook(_minimal_workbook(rows))
    observation = _observation_for_rule(result, "R08")

    assert result["contract"] == "analysis-partial/1"
    assert result["rule_execution"]["R08"]["status"] == "executed"
    assert result["rule_execution"]["R08"]["records_in_scope"] == 1
    assert result["rule_execution"]["R08"]["matched_observation_count"] == 1
    evidence_ids = [item["Log_ID"] for item in observation["evidence"]]
    evidence_order = [
        (item["Timestamp"], item["Log_ID"]) for item in observation["evidence"]
    ]
    assert evidence_order == sorted(evidence_order)
    assert len(evidence_ids) == len(set(evidence_ids)) == 21
    assert "EVT-R08-ARCHIVE" in evidence_ids
    assert "R07 (" in observation["description"]
    assert "R09 (" in observation["description"]
    assert "staging local" in observation["description"]
    assert "no demuestra causalidad" in observation["description"]
    assert observation["severity"] is None
    assert observation["severity_status"] == "not_defined"
    assert observation["score_1e4"] is None
    assert observation["confidence_basis_points"] is None
    assert observation["level"] is None


def test_r08_does_not_correlate_with_unqualified_r07_activity() -> None:
    rows = [
        _r07_row(
            f"EVT-R08-UNQUALIFIED-{index:02}",
            f"File access: document-{index}.xlsx",
            timestamp="2026-10-23 08:59:00",
        )
        for index in range(9)
    ]
    rows.append(
        _r08_row(
            "EVT-R08-UNQUALIFIED-ARCHIVE",
            r"tar.exe -a -c -f C:\Temp\archive.tar C:\Finance",
        )
    )

    result = analyze_workbook(_minimal_workbook(rows))

    assert result["rule_execution"]["R07"]["matched_observation_count"] == 0
    assert result["rule_execution"]["R08"]["matched_observation_count"] == 0
    assert not any(item["rule_id"] == "R08" for item in result["observations"])
    assert "EVT-R08-UNQUALIFIED-ARCHIVE" in result["rule_execution"]["R08"]["reason"]


def test_r01_result_is_independent_of_input_row_order() -> None:
    rows = [
        _r01_row(
            f"EVT-R01-ORDER-{index}",
            f"2026-10-23 08:0{index}:00",
            f"user-{index % 3}",
        )
        for index in range(7)
    ]
    forward = analyze_workbook(_minimal_workbook(rows))
    reversed_result = analyze_workbook(_minimal_workbook(list(reversed(rows))))

    forward_r01 = [
        item for item in forward["observations"] if item["rule_id"] == "R01"
    ]
    reversed_r01 = [
        item for item in reversed_result["observations"] if item["rule_id"] == "R01"
    ]
    assert forward_r01 == reversed_r01
    assert forward["rule_execution"]["R01"] == reversed_result["rule_execution"]["R01"]


def test_r01_orders_equal_timestamp_evidence_by_log_id() -> None:
    rows = [
        _r01_row("EVT-R01-TIE-Z", "2026-10-23 08:00:00", "user-a"),
        _r01_row("EVT-R01-TIE-C", "2026-10-23 08:00:00", "user-b"),
        _r01_row("EVT-R01-TIE-B", "2026-10-23 08:00:00", "user-c"),
        _r01_row("EVT-R01-TIE-A", "2026-10-23 08:00:00", "user-a"),
        _r01_row("EVT-R01-TIE-D", "2026-10-23 08:00:00", "user-b"),
    ]

    result = analyze_workbook(_minimal_workbook(rows))
    evidence_ids = [
        item["Log_ID"] for item in _observation_for_rule(result, "R01")["evidence"]
    ]

    assert evidence_ids == sorted(evidence_ids)


@pytest.mark.parametrize(
    ("source_ip", "category"),
    [
        ("2001:4860:4860::8888", "public"),
        ("192.0.0.9", "public"),
        ("203.0.113.7", "documentation"),
    ],
)
def test_r03_matches_public_and_documentation_ip_categories(
    source_ip: str, category: str
) -> None:
    row = _base_row("EVT-R03-MATCH", 4624)
    row[5] = source_ip

    result = analyze_workbook(_minimal_workbook([row]))
    observation = _observation_for_rule(result, "R03")

    assert observation["evidence"] == [
        {
            "Log_ID": "EVT-R03-MATCH",
            "Timestamp": "2026-10-23T08:00:00",
            "Hostname": "WS-014",
            "Event_ID": "4624",
            "User": "CORP\\user",
            "Source_IP": source_ip,
            "source_ip_category": category,
            "ip_classification_source": observation["evidence"][0][
                "ip_classification_source"
            ],
            "ip_registry_validation_status": "verified",
        }
    ]
    _assert_observation_does_not_infer_impact(observation)


@pytest.mark.parametrize(
    "source_ip",
    [
        "10.0.0.1",
        "127.0.0.1",
        "192.0.0.8",
        "100.64.0.1",
        "8.8.8.8",
        "not-an-ip",
    ],
)
def test_r03_does_not_match_private_special_or_invalid_ip(source_ip: str) -> None:
    row = _base_row("EVT-R03-NO-MATCH", 4624)
    row[5] = source_ip

    result = analyze_workbook(_minimal_workbook([row]))

    assert not any(item["rule_id"] == "R03" for item in result["observations"])
    assert result["rule_execution"]["R03"]["matched_observation_count"] == 0


@pytest.mark.parametrize("source_ip", [None, "   "])
def test_r03_missing_required_ip_is_not_evaluated(source_ip: object) -> None:
    row = _base_row("EVT-R03-MISSING-IP", 4624)
    row[5] = source_ip

    result = analyze_workbook(_minimal_workbook([row]))

    assert result["completeness"]["records_evaluated"] == 0
    assert result["completeness"]["records_not_evaluable"] == 1
    assert not any(item["rule_id"] == "R03" for item in result["observations"])


@pytest.mark.parametrize(
    "source_ip",
    ["8.8.8.8", "100.64.0.1", "240.0.0.1", "4000::1"],
)
def test_r03_does_not_match_ip_without_public_or_documentation_category(
    source_ip: str,
) -> None:
    row = _base_row("EVT-R03-NON-QUALIFYING-IP", 4624)
    row[5] = source_ip

    result = analyze_workbook(_minimal_workbook([row]))

    assert not any(item["rule_id"] == "R03" for item in result["observations"])
    assert result["rule_execution"]["R03"]["matched_observation_count"] == 0


@pytest.mark.parametrize(
    "description",
    [
        "LogonType=10",
        "logontype = 10; remote interactive",
    ],
)
def test_r04_matches_case_insensitive_logon_type_ten(description: str) -> None:
    row = _base_row("EVT-R04-MATCH", 4624)
    row[5] = "203.0.113.7"
    row[8] = description

    result = analyze_workbook(_minimal_workbook([row]))
    observation = _observation_for_rule(result, "R04")

    assert [item["Log_ID"] for item in observation["evidence"]] == [
        "EVT-R04-MATCH"
    ]
    _assert_observation_does_not_infer_impact(observation)
    assert observation["severity"] is None
    assert observation["severity_status"] == "not_defined"


@pytest.mark.parametrize(
    ("event_id", "source_ip", "description"),
    [
        (4625, "8.8.8.8", "LogonType=10"),
        (4624, "10.0.0.1", "LogonType=10"),
        (4624, "8.8.8.8", "LogonType=3"),
        (4624, "8.8.8.8", ""),
    ],
)
def test_r04_rejects_nonmatching_event_ip_or_logon_type(
    event_id: int, source_ip: str, description: str
) -> None:
    row = _base_row("EVT-R04-NO-MATCH", event_id)
    row[5] = source_ip
    row[8] = description or "No logon type supplied"

    result = analyze_workbook(_minimal_workbook([row]))

    assert not any(item["rule_id"] == "R04" for item in result["observations"])


@pytest.mark.parametrize(
    "indicator",
    [
        "-EncodedCommand payload",
        "-enc payload",
        "-NoProfile",
        "[Convert]::FromBase64String(value)",
    ],
)
def test_r05_matches_each_documented_command_indicator(indicator: str) -> None:
    row = _base_row("EVT-R05-MATCH", 4688)
    row[9] = f"powershell.exe {indicator}"

    result = analyze_workbook(_minimal_workbook([row]))
    observation = _observation_for_rule(result, "R05")

    assert [item["Log_ID"] for item in observation["evidence"]] == [
        "EVT-R05-MATCH"
    ]
    _assert_observation_does_not_infer_impact(observation)


@pytest.mark.parametrize(
    ("event_id", "command"),
    [
        (4104, "powershell.exe -EncodedCommand payload"),
        (4688, "powershell.exe -ExecutionPolicy Bypass"),
        (4688, None),
    ],
)
def test_r05_rejects_wrong_event_unlisted_indicator_and_null_command(
    event_id: int, command: object
) -> None:
    row = _base_row("EVT-R05-NO-MATCH", event_id)
    row[9] = command

    result = analyze_workbook(_minimal_workbook([row]))

    assert not any(item["rule_id"] == "R05" for item in result["observations"])


@pytest.mark.parametrize(
    "command",
    [
        "vssadmin.exe delete shadows /all /quiet",
        "wmic.exe shadowcopy delete",
        "bcdedit.exe /set {default} recoveryenabled no",
    ],
)
def test_r10_matches_each_documented_command_branch(command: str) -> None:
    row = _base_row("EVT-R10-MATCH", 4688)
    row[9] = command

    result = analyze_workbook(_minimal_workbook([row]))
    observation = _observation_for_rule(result, "R10")

    assert [item["Log_ID"] for item in observation["evidence"]] == [
        "EVT-R10-MATCH"
    ]
    _assert_observation_does_not_infer_impact(observation)


@pytest.mark.parametrize(
    ("event_id", "command"),
    [
        (4104, "vssadmin.exe delete shadows"),
        (4688, "vssadmin.exe list shadows"),
        (4688, "wmic.exe shadowcopy list"),
        (4688, "bcdedit.exe recoveryenabled yes"),
        (4688, None),
    ],
)
def test_r10_rejects_incomplete_branch_or_wrong_event(
    event_id: int, command: object
) -> None:
    row = _base_row("EVT-R10-NO-MATCH", event_id)
    row[9] = command

    result = analyze_workbook(_minimal_workbook([row]))

    assert not any(item["rule_id"] == "R10" for item in result["observations"])


@pytest.mark.parametrize(
    ("user", "description", "command"),
    [
        ("IIS APPPOOL\\DefaultAppPool", "", "cmd.exe /c whoami"),
        ("CORP\\user", "parent=w3wp.exe", "powershell.exe -NoProfile"),
        ("CORP\\user", "parent=W3WP.EXE", "whoami.exe"),
        ("CORP\\user", "parent=w3wp.exe", "net.exe group"),
    ],
)
def test_r12_matches_service_identity_or_web_parent_and_allowed_command(
    user: str, description: str, command: str
) -> None:
    row = _base_row("EVT-R12-MATCH", 4688)
    row[4] = user
    row[8] = description or "Process created"
    row[9] = command

    result = analyze_workbook(_minimal_workbook([row]))
    observation = _observation_for_rule(result, "R12")

    assert [item["Log_ID"] for item in observation["evidence"]] == [
        "EVT-R12-MATCH"
    ]
    _assert_observation_does_not_infer_impact(observation)
    assert observation["severity"] is None
    assert observation["severity_status"] == "not_defined"


@pytest.mark.parametrize(
    ("event_id", "user", "description", "command"),
    [
        (4104, "IIS APPPOOL\\DefaultAppPool", "", "cmd.exe"),
        (4688, "CORP\\user", "Process created", "cmd.exe"),
        (4688, "CORP\\user", "parent=w3wp.exe", "prefixwhoami"),
        (4688, "CORP\\user", "parent=w3wp.exe", None),
        (4688, "CORP\\user", "parent=w3wp.exe", "netgroup.exe"),
    ],
)
def test_r12_rejects_wrong_event_missing_context_or_unlisted_command(
    event_id: int, user: str, description: str, command: object
) -> None:
    row = _base_row("EVT-R12-NO-MATCH", event_id)
    row[4] = user
    row[8] = description or "Process created"
    row[9] = command

    result = analyze_workbook(_minimal_workbook([row]))

    assert not any(item["rule_id"] == "R12" for item in result["observations"])


def test_r13_pipeline_emits_traced_observation_independent_of_r12() -> None:
    rows = [
        _http_row(
            f"EVT-R13-{index:02}",
            f"2026-10-23 12:00:{index * 5:02}",
            uri="/ADMIN/",
            result=200,
        )
        for index in range(10)
    ]
    r12 = _base_row("EVT-R12-INDEPENDENT", 4688)
    r12[1] = "2026-10-23 12:02:00"
    r12[2] = "WEB-01"
    r12[4] = "IIS APPPOOL\\DefaultAppPool"
    r12[9] = "cmd.exe /c whoami"
    rows.append(r12)

    result = analyze_workbook(_minimal_workbook(rows))
    observation = _observation_for_rule(result, "R13")

    assert result["contract"] == "analysis-partial/1"
    assert set(observation) == {
        "rule_id",
        "rule_name",
        "observation_type",
        "description",
        "evidence",
        "impact_demonstrated",
        "incident_attribution",
        "severity",
        "severity_status",
        "level",
        "level_status",
        "score_1e4",
        "confidence_basis_points",
        "confidence_status",
    }
    assert result["rule_execution"]["R13"]["status"] == "executed"
    assert result["rule_execution"]["R13"]["records_in_scope"] == 10
    assert result["rule_execution"]["R13"]["records_evaluated"] == 10
    assert result["rule_execution"]["R13"]["matched_observation_count"] == 1
    assert [item["Log_ID"] for item in observation["evidence"]] == [
        f"EVT-R13-{index:02}" for index in range(10)
    ]
    assert "categoría documentation" in observation["description"]
    assert "no confirma automatización" in observation["description"]
    assert all(
        item["Log_ID"] != "EVT-R12-INDEPENDENT"
        for item in observation["evidence"]
    )
    _assert_observation_does_not_infer_impact(observation)
    assert observation["severity"] is None
    assert observation["severity_status"] == "not_defined"


def test_r13_does_not_require_hostname_user_uri_or_valid_result() -> None:
    rows = [
        _http_row(
            f"EVT-R13-OPTIONAL-{index:02}",
            f"2026-10-23 12:00:{index * 5:02}",
            uri="/upload/file",
            result=None,
            hostname=None,
            user=None,
        )
        for index in range(10)
    ]

    result = analyze_workbook(_minimal_workbook(rows))

    assert result["rule_execution"]["R13"]["records_evaluated"] == 10
    observation = _observation_for_rule(result, "R13")
    assert "0 resultados HTTP válidos" in observation["description"]
    assert all(item["Hostname"] is None and item["User"] is None for item in observation["evidence"])


def test_r13_excludes_log_id_conflict_with_other_event_type() -> None:
    rows = [
        _http_row(
            f"EVT-R13-CROSS-{index:02}",
            f"2026-10-23 12:00:{index * 5:02}",
            uri="/admin",
            result=200,
        )
        for index in range(10)
    ]
    conflict = _base_row("EVT-R13-CROSS-00", 7036)
    rows.append(conflict)

    result = analyze_workbook(_minimal_workbook(rows))

    assert result["rule_execution"]["R13"]["matched_observation_count"] == 0
    assert result["rule_execution"]["R13"]["records_evaluated"] == 9
    assert "EVT-R13-CROSS-00" in result["rule_execution"]["R13"]["reason"]


def test_target_rules_are_deterministic_for_identical_workbook() -> None:
    r02_failure_1 = _base_row("EVT-DET-FAIL-1", 4625)
    r02_failure_2 = _base_row("EVT-DET-FAIL-2", 4625)
    r02_failure_3 = _base_row("EVT-DET-FAIL-3", 4625)
    r02_success = _base_row("EVT-DET-SUCCESS", 4624)
    r02_success[1] = "2026-10-23 08:04:00"
    r03 = _base_row("EVT-DET-R03", 4624)
    r03[5] = "8.8.8.8"
    r04 = _base_row("EVT-DET-R04", 4624)
    r04[5] = "8.8.8.8"
    r04[8] = "LogonType=10"
    r05 = _base_row("EVT-DET-R05", 4688)
    r05[9] = "powershell.exe -EncodedCommand payload"
    r10 = _base_row("EVT-DET-R10", 4688)
    r10[9] = "vssadmin.exe delete shadows"
    r12 = _base_row("EVT-DET-R12", 4688)
    r12[4] = "IIS APPPOOL\\DefaultAppPool"
    r12[9] = "cmd.exe /c whoami"
    content = _minimal_workbook(
        [
            r02_failure_1,
            r02_failure_2,
            r02_failure_3,
            r02_success,
            r03,
            r04,
            r05,
            r10,
            r12,
        ]
    )

    first = analyze_workbook(content)
    second = analyze_workbook(content)

    assert first == second


@pytest.mark.parametrize(
    ("event_id", "indicator"),
    [
        (4688, "net view"),
        (4688, "Get-SmbShare"),
        (4688, "Get-LocalGroupMember"),
        (4688, "whoami"),
        (4688, "net group"),
        (4104, "net view"),
        (4104, "Get-SmbShare"),
        (4104, "Get-LocalGroupMember"),
        (4104, "whoami"),
        (4104, "net group"),
    ],
)
def test_r06_matches_each_catalogued_indicator_for_supported_events(
    event_id: int, indicator: str
) -> None:
    row = _base_row("EVT-RECON", event_id)
    if event_id == 4688:
        row[9] = f"C:\\Windows\\System32\\{indicator} -Name Administrators"
    else:
        row[8] = f"Script block: {indicator} -Name Administrators"

    result = analyze_workbook(_minimal_workbook([row]))
    observations = [
        item for item in result["observations"] if item["rule_id"] == "R06"
    ]

    assert len(observations) == 1
    assert observations[0]["evidence"][0]["Log_ID"] == "EVT-RECON"
    assert result["rule_execution"]["R06"]["matched_observation_count"] == 1


@pytest.mark.parametrize("event_id", [4688, 4104])
@pytest.mark.parametrize(
    "command",
    [
        "xnet view",
        "net viewer",
        "get-smbsharex",
        "xget-localgroupmember",
        "prefixwhoami",
        "net groupish",
        "net view-something",
    ],
)
def test_r06_rejects_accidental_substring_matches(
    event_id: int, command: str
) -> None:
    row = _base_row("EVT-R06-NEGATIVE", event_id)
    row[9 if event_id == 4688 else 8] = command

    result = analyze_workbook(_minimal_workbook([row]))

    assert not any(item["rule_id"] == "R06" for item in result["observations"])


@pytest.mark.parametrize("event_id", [4688, 4104])
@pytest.mark.parametrize("command", [None, ""])
def test_r06_ignores_null_or_empty_command_fields(
    event_id: int, command: object
) -> None:
    row = _base_row("EVT-R06-EMPTY", event_id)
    row[9] = command
    row[8] = command

    result = analyze_workbook(_minimal_workbook([row]))

    assert not any(item["rule_id"] == "R06" for item in result["observations"])


def test_r06_excludes_unsupported_event_ids() -> None:
    row = _base_row("EVT-R06-WRONG-EVENT", 4624)
    row[9] = "whoami"

    result = analyze_workbook(_minimal_workbook([row]))

    assert not any(item["rule_id"] == "R06" for item in result["observations"])


def test_r06_uses_case_insensitive_command_and_argument_matching() -> None:
    row = _base_row("EVT-R06-ARGS", 4688)
    row[9] = r"C:\Windows\System32\NET.EXE VIEW \\server /DOMAIN"

    result = analyze_workbook(_minimal_workbook([row]))

    assert any(item["rule_id"] == "R06" for item in result["observations"])


def test_r06_emits_one_observation_per_matching_record_without_grouping() -> None:
    row = _base_row("EVT-RECON", 4104)
    row[8] = "Get-LocalGroupMember Administrators"
    second_row = _base_row("EVT-RECON-2", 4688)
    second_row[9] = "whoami.exe /all"

    result = analyze_workbook(_minimal_workbook([row, second_row]))
    observations = [
        item for item in result["observations"] if item["rule_id"] == "R06"
    ]

    assert [item["evidence"][0]["Log_ID"] for item in observations] == [
        "EVT-RECON",
        "EVT-RECON-2",
    ]
    assert result["rule_execution"]["R06"]["status"] == "executed"
    assert result["rule_execution"]["R06"]["matched_observation_count"] == 2
    assert all(
        "no demuestra ejecución exitosa" in item["description"]
        for item in observations
    )


def test_r06_deduplicates_repeated_evidence_and_sorts_independently_of_rows() -> None:
    later = _base_row("EVT-R06-B", 4688)
    later[1] = "2026-10-23 08:02:00"
    later[9] = "whoami"
    earlier = _base_row("EVT-R06-A", 4104)
    earlier[1] = "2026-10-23 08:01:00"
    earlier[8] = "net view"

    forward = analyze_workbook(_minimal_workbook([later, earlier, earlier]))
    reverse = analyze_workbook(_minimal_workbook([earlier, earlier, later]))

    def r06_evidence(result: dict[str, object]) -> list[tuple[str, str]]:
        return [
            (
                item["evidence"][0]["Timestamp"],
                item["evidence"][0]["Log_ID"],
            )
            for item in result["observations"]
            if item["rule_id"] == "R06"
        ]

    assert r06_evidence(forward) == [
        ("2026-10-23T08:01:00", "EVT-R06-A"),
        ("2026-10-23T08:02:00", "EVT-R06-B"),
    ]
    assert r06_evidence(reverse) == r06_evidence(forward)
    assert forward["rule_execution"]["R06"]["matched_observation_count"] == 2


@pytest.mark.parametrize("event_id", [4698, 7045])
@pytest.mark.parametrize(
    "indicator",
    [
        r"C:\ProgramData",
        r"C:\Temp",
        r"C:\Users\Public",
        "%APPDATA%",
    ],
)
def test_r11_matches_each_catalogued_path_for_supported_events(
    event_id: int, indicator: str
) -> None:
    row = _base_row("EVT-R11-MATCH", event_id)
    row[9] = f'ImagePath="{indicator}\\service.exe" -arg'

    result = analyze_workbook(_minimal_workbook([row]))
    observations = [
        item for item in result["observations"] if item["rule_id"] == "R11"
    ]

    assert len(observations) == 1
    assert observations[0]["evidence"][0]["Log_ID"] == "EVT-R11-MATCH"
    assert observations[0]["evidence"][0]["Event_ID"] == str(event_id)
    assert "no acredita ejecución ni persistencia" in observations[0]["description"]


@pytest.mark.parametrize("event_id", [4698, 7045])
@pytest.mark.parametrize("command", [None, "", "   "])
def test_r11_ignores_null_or_empty_command_line(
    event_id: int, command: object
) -> None:
    row = _base_row("EVT-R11-EMPTY", event_id)
    row[9] = command

    result = analyze_workbook(_minimal_workbook([row]))

    assert not any(item["rule_id"] == "R11" for item in result["observations"])


@pytest.mark.parametrize(
    "command",
    [
        r"C:\ProgramDatabase\service.exe",
        r"C:\Tempest\service.exe",
        r"C:\Users\Publicity\service.exe",
        r"%APPDATA%Backup\service.exe",
        r"XC:\ProgramData\service.exe",
        r"D:\ProgramData\service.exe",
        r"C:\ProgramDataBackup\service.exe",
        r"C:\Temp:stream",
    ],
)
def test_r11_rejects_longer_or_accidental_path_substrings(command: str) -> None:
    row = _base_row("EVT-R11-PREFIX", 7045)
    row[9] = command

    result = analyze_workbook(_minimal_workbook([row]))

    assert not any(item["rule_id"] == "R11" for item in result["observations"])


def test_r11_matches_case_insensitive_paths_with_forward_slashes_and_arguments() -> None:
    row = _base_row("EVT-R11-ARGUMENTS", 7045)
    row[9] = 'sc.exe create Sample binPath= "c:/USERS/Public/service.exe" --flag'

    result = analyze_workbook(_minimal_workbook([row]))
    observation = _observation_for_rule(result, "R11")

    assert observation["evidence"][0]["Log_ID"] == "EVT-R11-ARGUMENTS"


def test_r11_does_not_read_paths_only_from_event_description() -> None:
    row = _base_row("EVT-R11-DESCRIPTION", 4698)
    row[8] = r"ImagePath=C:\ProgramData\service.exe"

    result = analyze_workbook(_minimal_workbook([row]))

    assert not any(item["rule_id"] == "R11" for item in result["observations"])


def test_r11_does_not_match_unlisted_paths_or_unsupported_event_ids() -> None:
    row = _base_row("EVT-R11-OTHER-EVENT", 4688)
    row[9] = r"C:\ProgramData\service.exe"
    ordinary = _base_row("EVT-R11-ORDINARY", 4698)
    ordinary[9] = r"C:\Windows\System32\svchost.exe"

    result = analyze_workbook(_minimal_workbook([row, ordinary]))

    assert not any(item["rule_id"] == "R11" for item in result["observations"])


def test_r11_repeated_records_are_deduplicated_and_order_is_row_independent() -> None:
    later = _base_row("EVT-R11-B", 7045)
    later[1] = "2026-10-23 09:00:00"
    later[9] = r"ImagePath=C:\Temp\service.exe"
    earlier = _base_row("EVT-R11-A", 4698)
    earlier[1] = "2026-10-23 08:00:00"
    earlier[9] = r"Action=C:\ProgramData\task.exe"

    forward = analyze_workbook(_minimal_workbook([later, earlier, earlier]))
    reverse = analyze_workbook(_minimal_workbook([earlier, earlier, later]))

    def r11_evidence(result: dict[str, object]) -> list[tuple[str, str]]:
        return [
            (
                item["evidence"][0]["Timestamp"],
                item["evidence"][0]["Log_ID"],
            )
            for item in result["observations"]
            if item["rule_id"] == "R11"
        ]

    assert r11_evidence(forward) == [
        ("2026-10-23T08:00:00", "EVT-R11-A"),
        ("2026-10-23T09:00:00", "EVT-R11-B"),
    ]
    assert r11_evidence(reverse) == r11_evidence(forward)
    assert forward["rule_execution"]["R11"]["matched_observation_count"] == 2


def test_r11_is_pointwise_and_does_not_emit_periodicity_or_grouping() -> None:
    first = _base_row("EVT-R11-EARLY", 4698)
    first[1] = "2026-10-23 08:00:00"
    first[9] = r"Action=C:\ProgramData\task.exe"
    second = _base_row("EVT-R11-LATE", 7045)
    second[1] = "2026-10-23 08:05:00"
    second[9] = r"ImagePath=C:\ProgramData\service.exe"

    result = analyze_workbook(_minimal_workbook([first, second]))
    observations = [
        item for item in result["observations"] if item["rule_id"] == "R11"
    ]

    assert len(observations) == 2
    assert all(len(item["evidence"]) == 1 for item in observations)
    assert result["rule_execution"]["R11"]["status"] == "executed"
    assert result["rule_execution"]["R11"]["reason"] is None
    assert [
        item["evidence"][0]["Log_ID"] for item in observations
    ] == ["EVT-R11-EARLY", "EVT-R11-LATE"]
    assert all(
        "periodic" not in item["description"].casefold()
        and "agrup" not in item["description"].casefold()
        for item in observations
    )
    assert set(observations[0]) == {
        "rule_id",
        "rule_name",
        "observation_type",
        "description",
        "evidence",
        "impact_demonstrated",
        "incident_attribution",
        "severity",
        "severity_status",
        "level",
        "level_status",
        "score_1e4",
        "confidence_basis_points",
        "confidence_status",
    }
    assert set(observations[0]["evidence"][0]) == {
        "Log_ID",
        "Timestamp",
        "Hostname",
        "Event_ID",
        "User",
        "Source_IP",
        "source_ip_category",
        "ip_classification_source",
        "ip_registry_validation_status",
    }
    assert set(result["rule_execution"]["R11"]) == {
        "name",
        "status",
        "matched_observation_count",
        "records_in_scope",
        "records_evaluated",
        "reason",
    }
    assert set(result) == {
        "activity_summary",
        "analysis_id",
        "analysis_id_reason",
        "analysis_id_status",
        "canon_version",
        "chain_execution",
        "completeness",
        "completion_status",
        "content_sha256",
        "content_sha256_status",
        "contract",
        "file_sha256",
        "ip_classification_status",
        "non_evaluable_records",
        "observations",
        "rule_execution",
        "schema_version",
        "status",
        "timezone_status",
    }


def test_r09_ingestion_parses_bytes_only_for_proxy_access_and_preserves_group_key() -> None:
    proxy = _proxy_row(
        "EVT-R09-PROXY",
        "bytes_out=52428800 uri=/upload",
        hostname="PROXY-A",
        user="CORP\\analyst",
        destination="203.0.113.22:443",
    )
    unrelated = _base_row("EVT-R09-OTHER", 7036)
    unrelated[9] = "bytes_out=999999999"

    ingestion = ingest_workbook(_minimal_workbook([proxy, unrelated]))

    proxy_record = next(
        record for record in ingestion.records if record.log_id == "EVT-R09-PROXY"
    )
    unrelated_record = next(
        record for record in ingestion.records if record.log_id == "EVT-R09-OTHER"
    )
    assert (
        proxy_record.hostname,
        proxy_record.user,
        proxy_record.destination,
    ) == ("PROXY-A", "CORP\\analyst", "203.0.113.22:443")
    assert proxy_record.log_id == "EVT-R09-PROXY"
    assert proxy_record.proxy_bytes_out is not None
    assert proxy_record.proxy_bytes_out.proxy_bytes_out_field_observed is True
    assert proxy_record.proxy_bytes_out.proxy_recorded_bytes_out == "52428800"
    assert proxy_record.proxy_bytes_out.observed_bytes_out_value == 52_428_800
    assert proxy_record.proxy_bytes_out.observed_bytes_out_sum == 52_428_800
    assert proxy_record.proxy_bytes_out.severity_eligible is False
    assert unrelated_record.proxy_bytes_out is None


def test_r09_emits_count_only_observation_with_traced_evidence() -> None:
    rows = [
        _proxy_row(
            f"EVT-R09-{index:02}",
            "bytes_out=6000000 uri=/upload",
        )
        for index in range(10)
    ]
    content = _minimal_workbook(rows)

    result = analyze_workbook(content)

    assert result["rule_execution"]["R09"]["status"] == "executed"
    assert result["rule_execution"]["R09"]["records_in_scope"] == 10
    assert result["rule_execution"]["R09"]["records_evaluated"] == 10
    assert result["rule_execution"]["R09"]["matched_observation_count"] == 1
    observation = _observation_for_rule(result, "R09")
    assert [item["Log_ID"] for item in observation["evidence"]] == [
        f"EVT-R09-{index:02}" for index in range(10)
    ]
    assert "cantidad de eventos únicos" in observation["description"]
    assert observation["severity"] is None
    assert observation["severity_status"] == "not_defined"
    assert observation["impact_demonstrated"] is False
    assert observation["incident_attribution"] is False
    assert "exfiltración" in observation["description"]
    assert set(observation) == {
        "confidence_basis_points",
        "confidence_status",
        "description",
        "evidence",
        "impact_demonstrated",
        "incident_attribution",
        "level",
        "level_status",
        "observation_type",
        "rule_id",
        "rule_name",
        "score_1e4",
        "severity",
        "severity_status",
    }
    assert set(result) == {
        "activity_summary",
        "analysis_id",
        "analysis_id_reason",
        "analysis_id_status",
        "canon_version",
        "chain_execution",
        "completeness",
        "completion_status",
        "content_sha256",
        "content_sha256_status",
        "contract",
        "file_sha256",
        "ip_classification_status",
        "non_evaluable_records",
        "observations",
        "rule_execution",
        "schema_version",
        "status",
        "timezone_status",
    }


def test_r09_volume_only_observation_is_not_severity_eligible_or_impact() -> None:
    row = _proxy_row("EVT-R09-BYTES", "bytes_out=52428800 uri=/upload")
    result = analyze_workbook(_minimal_workbook([row]))
    observation = _observation_for_rule(result, "R09")
    ingestion = ingest_workbook(_minimal_workbook([row]))

    assert len(observation["evidence"]) == 1
    assert observation["evidence"][0]["Log_ID"] == "EVT-R09-BYTES"
    assert "exclusivamente por bytes" in observation["description"]
    assert "no es elegible para severidad" in observation["description"]
    assert "transferencia exitosa" in observation["description"]
    assert observation["severity"] is None
    assert observation["severity_status"] == "not_defined"
    assert observation["impact_demonstrated"] is False
    assert observation["incident_attribution"] is False
    assert ingestion.r09_events[0].bytes_out.severity_eligible is False


def test_r09_uses_event_id_source_not_log_source_alias() -> None:
    row = _proxy_row("EVT-R09-WRONG-SOURCE", "bytes_out=52428800")
    row[3] = 7036
    row[7] = "PROXY_ACCESS"

    result = analyze_workbook(_minimal_workbook([row]))

    assert result["rule_execution"]["R09"]["records_in_scope"] == 0
    assert result["rule_execution"]["R09"]["matched_observation_count"] == 0


def test_r09_reports_conflicts_and_excluded_incomplete_records() -> None:
    conflict_first = _proxy_row("EVT-R09-CONFLICT", "bytes_out=100")
    conflict_second = _proxy_row("EVT-R09-CONFLICT", "bytes_out=200")
    missing_key = _proxy_row("EVT-R09-NO-USER", "bytes_out=100", user=" ")
    missing_timestamp = _proxy_row(
        "EVT-R09-NO-TIME", "bytes_out=100", timestamp=""
    )

    result = analyze_workbook(
        _minimal_workbook(
            [conflict_first, conflict_second, missing_key, missing_timestamp]
        )
    )
    reason = result["rule_execution"]["R09"]["reason"]

    assert result["rule_execution"]["R09"]["status"] == "executed"
    assert result["rule_execution"]["R09"]["records_in_scope"] == 4
    assert result["rule_execution"]["R09"]["records_evaluated"] == 0
    assert "EVT-R09-CONFLICT" in reason
    assert "2 versiones" in reason
    assert "EVT-R09-NO-USER" in reason
    assert "EVT-R09-NO-TIME" in reason
    assert result["rule_execution"]["R09"]["matched_observation_count"] == 0


def test_r09_excludes_proxy_version_when_same_log_id_conflicts_with_other_event() -> None:
    proxy = _proxy_row("EVT-R09-CROSS-CONFLICT", "bytes_out=52428800")
    other_event = _base_row("EVT-R09-CROSS-CONFLICT", 7036)

    result = analyze_workbook(_minimal_workbook([proxy, other_event]))

    assert result["rule_execution"]["R09"]["records_evaluated"] == 0
    assert result["rule_execution"]["R09"]["matched_observation_count"] == 0
    assert "EVT-R09-CROSS-CONFLICT" in result["rule_execution"]["R09"]["reason"]


def test_r09_proxy_input_order_does_not_change_logical_result() -> None:
    rows = [
        _proxy_row(
            f"EVT-R09-DET-{index:02}",
            f"bytes_out={index * 100} uri=/upload",
            timestamp=f"2026-10-23 08:{index:02}:00",
        )
        for index in range(3)
    ]

    forward = analyze_workbook(_minimal_workbook(rows))
    reverse = analyze_workbook(_minimal_workbook(list(reversed(rows))))

    assert forward["observations"] == reverse["observations"]
    assert forward["rule_execution"]["R09"] == reverse["rule_execution"]["R09"]


def test_analysis_is_deterministic_for_identical_input() -> None:
    content = _minimal_workbook([_base_row("EVT-TEST-1")])

    assert analyze_workbook(content) == analyze_workbook(content)


def test_invalid_timestamp_isolated_as_non_evaluable_record() -> None:
    row = _base_row("EVT-BAD-TIME")
    row[1] = "not-a-timestamp"

    result = analyze_workbook(_minimal_workbook([row]))

    assert result["completeness"]["records_seen"] == 1
    assert result["completeness"]["records_evaluated"] == 0
    assert result["completeness"]["records_not_evaluable"] == 1
    assert result["non_evaluable_records"] == [
        {"log_id": "EVT-BAD-TIME", "code": "invalid_timestamp"}
    ]


def test_invalid_ip_does_not_satisfy_r03() -> None:
    row = _base_row("EVT-BAD-IP", 4624)
    row[5] = "not-an-ip"

    result = analyze_workbook(_minimal_workbook([row]))

    assert result["completeness"]["records_evaluated"] == 1
    assert result["completeness"]["records_not_evaluable"] == 0
    assert result["completeness"]["records_with_non_evaluable_ip"] == 1
    assert result["rule_execution"]["R03"]["matched_observation_count"] == 0
    assert not any(item["rule_id"] == "R03" for item in result["observations"])
    assert result["ip_classification_status"] == "verified"


def test_original_workbook_loads_715_records_and_only_emits_traced_matches() -> None:
    workbook_path = os.environ.get("SOC_L2_CHALLENGE_WORKBOOK")
    if not workbook_path:
        pytest.skip("Defina SOC_L2_CHALLENGE_WORKBOOK para probar el workbook original.")

    result = analyze_workbook(Path(workbook_path).read_bytes())

    assert result["completeness"]["records_seen"] == 715
    assert result["completeness"]["records_evaluated"] == 715
    assert result["completeness"]["records_not_evaluable"] == 0
    assert result["completeness"]["rules_executed"] == 13
    assert result["completeness"]["rules_partially_executed"] == 0
    assert result["completeness"]["rules_pending"] == 0
    assert result["rule_execution"]["R07"]["status"] == "executed"
    assert result["rule_execution"]["R07"]["records_in_scope"] == 64
    assert result["rule_execution"]["R07"]["records_evaluated"] == 53
    assert result["rule_execution"]["R09"]["reason"] is None
    assert result["rule_execution"]["R08"]["status"] == "executed"
    assert result["rule_execution"]["R08"]["matched_observation_count"] == 1
    assert result["rule_execution"]["R13"]["status"] == "executed"
    assert result["rule_execution"]["R13"]["records_in_scope"] == 21
    assert result["rule_execution"]["R13"]["records_evaluated"] == 21
    assert result["rule_execution"]["R13"]["matched_observation_count"] == 1
    assert result["analysis_id"] is None
    assert result["content_sha256"] is None

    evidence_ids = {
        (observation["rule_id"], evidence["Log_ID"])
        for observation in result["observations"]
        for evidence in observation["evidence"]
    }
    assert ("R03", "EVT-00123") in evidence_ids
    assert ("R03", "EVT-00188") in evidence_ids
    assert ("R04", "EVT-00188") in evidence_ids
    assert ("R05", "EVT-00198") in evidence_ids
    assert ("R05", "EVT-00280") in evidence_ids
    assert ("R06", "EVT-00207") in evidence_ids
    assert ("R06", "EVT-00214") in evidence_ids
    assert ("R10", "EVT-00314") in evidence_ids
    assert ("R11", "EVT-00523") in evidence_ids
    assert ("R11", "EVT-00524") in evidence_ids
    assert ("R12", "EVT-00599") in evidence_ids


def test_all_original_observations_have_expected_evidence_and_predicates() -> None:
    workbook_path = os.environ.get("SOC_L2_CHALLENGE_WORKBOOK")
    if not workbook_path:
        pytest.skip("Defina SOC_L2_CHALLENGE_WORKBOOK para probar el workbook original.")

    content = Path(workbook_path).read_bytes()
    result = analyze_workbook(content)
    source = load_workbook(BytesIO(content), read_only=True, data_only=True)
    try:
        rows = source["SIEM Export"].iter_rows(values_only=True)
        headers = next(rows)
        source_rows = {
            row[headers.index("Log_ID")]: {
                header: row[index] for index, header in enumerate(headers)
            }
            for row in rows
            if row[headers.index("Log_ID")] is not None
        }
    finally:
        source.close()

    actual = Counter(
        (
            observation["rule_id"],
            tuple(item["Log_ID"] for item in observation["evidence"]),
        )
        for observation in result["observations"]
    )
    expected = Counter(
        {
            ("R01", _ORIGINAL_R01_LOG_IDS): 1,
            ("R02", ("EVT-00061", "EVT-00074", "EVT-00086", "EVT-00104", "EVT-00123")): 1,
            ("R03", ("EVT-00123",)): 1,
            ("R02", ("EVT-00174", "EVT-00175", "EVT-00178", "EVT-00180", "EVT-00188")): 1,
            ("R03", ("EVT-00188",)): 1,
            ("R04", ("EVT-00188",)): 1,
            ("R05", ("EVT-00198",)): 1,
            ("R06", ("EVT-00207",)): 1,
            ("R06", ("EVT-00214",)): 1,
            ("R05", ("EVT-00280",)): 1,
            ("R10", ("EVT-00314",)): 1,
            ("R11", ("EVT-00523",)): 1,
            ("R11", ("EVT-00524",)): 1,
            ("R06", ("EVT-00599",)): 1,
            ("R12", ("EVT-00599",)): 1,
            (
                "R09",
                (
                    "EVT-00430",
                    "EVT-00431",
                    "EVT-00432",
                    "EVT-00435",
                    "EVT-00436",
                    "EVT-00438",
                    "EVT-00439",
                    "EVT-00440",
                    "EVT-00441",
                    "EVT-00443",
                    "EVT-00444",
                    "EVT-00445",
                    "EVT-00448",
                    "EVT-00450",
                    "EVT-00451",
                    "EVT-00453",
                    "EVT-00455",
                    "EVT-00456",
                    "EVT-00457",
                    "EVT-00458",
                    "EVT-00460",
                    "EVT-00461",
                ),
            ): 1,
            (
                "R07",
                (
                    "EVT-00284",
                    "EVT-00286",
                    "EVT-00289",
                    "EVT-00290",
                    "EVT-00291",
                    "EVT-00293",
                    "EVT-00296",
                    "EVT-00298",
                    "EVT-00300",
                    "EVT-00302",
                    "EVT-00303",
                    "EVT-00305",
                    "EVT-00306",
                    "EVT-00307",
                    "EVT-00308",
                    "EVT-00309",
                ),
            ): 1,
            (
                "R08",
                (
                    "EVT-00428",
                    "EVT-00430",
                    "EVT-00431",
                    "EVT-00432",
                    "EVT-00435",
                    "EVT-00436",
                    "EVT-00438",
                    "EVT-00439",
                    "EVT-00440",
                    "EVT-00441",
                    "EVT-00443",
                    "EVT-00444",
                    "EVT-00445",
                    "EVT-00448",
                    "EVT-00450",
                    "EVT-00451",
                    "EVT-00453",
                    "EVT-00455",
                    "EVT-00456",
                    "EVT-00457",
                    "EVT-00458",
                    "EVT-00460",
                    "EVT-00461",
                ),
            ): 1,
            (
                "R13",
                (
                    "EVT-00571",
                    "EVT-00572",
                    "EVT-00573",
                    "EVT-00574",
                    "EVT-00576",
                    "EVT-00577",
                    "EVT-00579",
                    "EVT-00581",
                    "EVT-00582",
                    "EVT-00583",
                    "EVT-00584",
                    "EVT-00585",
                    "EVT-00586",
                    "EVT-00588",
                    "EVT-00589",
                    "EVT-00590",
                    "EVT-00591",
                    "EVT-00592",
                    "EVT-00593",
                    "EVT-00595",
                    "EVT-00596",
                ),
            ): 1,
        }
    )
    assert actual == expected
    assert sum(actual.values()) == 19

    for observation in result["observations"]:
        rule_id = observation["rule_id"]
        rows_for_observation = [
            source_rows[evidence["Log_ID"]] for evidence in observation["evidence"]
        ]
        assert all(evidence["Log_ID"] in source_rows for evidence in observation["evidence"])
        assert observation["impact_demonstrated"] is False
        assert observation["incident_attribution"] is False
        assert observation["score_1e4"] is None
        assert observation["confidence_basis_points"] is None
        assert observation["level"] is None
        if rule_id in ("R03", "R11"):
            assert observation["severity_status"] == "ratified"
            assert observation["severity"] == {"R03": "Low", "R11": "Medium"}[
                rule_id
            ]
        else:
            assert observation["severity_status"] == "not_defined"
            assert observation["severity"] is None

        if rule_id == "R02":
            success = rows_for_observation[-1]
            failures = rows_for_observation[:-1]
            success_time = datetime.fromisoformat(success["Timestamp"])
            assert str(success["Event_ID"]) == "4624"
            assert all(str(row["Event_ID"]) == "4625" for row in failures)
            assert all(
                row["Hostname"] == success["Hostname"]
                and row["User"] == success["User"]
                and 0
                < (
                    success_time
                    - datetime.fromisoformat(row["Timestamp"])
                ).total_seconds()
                <= 15 * 60
                for row in failures
            )
        elif rule_id in ("R03", "R04"):
            row = rows_for_observation[0]
            assert str(row["Event_ID"]) == "4624"
            assert observation["evidence"][0]["source_ip_category"] in (
                "documentation",
                "public",
            )
            if rule_id == "R04":
                assert re.search(r"\bLogonType\s*=\s*10\b", row["Event_Description"])
        elif rule_id in ("R05", "R06", "R10", "R12"):
            row = rows_for_observation[0]
            command = (row["Process_CommandLine"] or "").casefold()
            description = (row["Event_Description"] or "").casefold()
            if rule_id == "R05":
                assert str(row["Event_ID"]) == "4688"
                assert any(
                    indicator in command
                    for indicator in (
                        "-encodedcommand",
                        "-enc ",
                        "-noprofile",
                        "frombase64string",
                    )
                )
            elif rule_id == "R06":
                assert str(row["Event_ID"]) in ("4688", "4104")
                combined = f"{command} {description}".replace("net.exe ", "net ")
                assert any(
                    term in combined
                    for term in (
                        "net view",
                        "get-smbshare",
                        "get-localgroupmember",
                        "whoami",
                        "net group",
                    )
                )
            elif rule_id == "R10":
                assert str(row["Event_ID"]) == "4688"
                assert "vssadmin" in command and "delete" in command and "shadows" in command
            else:
                assert str(row["Event_ID"]) == "4688"
                assert row["User"].casefold().startswith("iis apppool\\") or (
                    "parent=w3wp.exe" in description
                )
                assert any(
                    executable in command
                    for executable in ("cmd.exe", "powershell.exe", "whoami", "net.exe")
                )
        elif rule_id == "R11":
            row = rows_for_observation[0]
            assert str(row["Event_ID"]) in ("4698", "7045")
            command = (row["Process_CommandLine"] or "").casefold()
            assert any(
                path in command
                for path in (
                    r"c:\programdata",
                    r"c:\temp",
                    r"c:\users\public",
                    "%appdata%",
                )
            )
        elif rule_id == "R08":
            archive = source_rows["EVT-00428"]
            assert str(archive["Event_ID"]) == "4688"
            assert "7z.exe a C:\\Users\\Public\\archive.7z" in archive["Process_CommandLine"]
            assert "R09 (" in observation["description"]
            assert "R07 (" not in observation["description"]
            assert all(
                row["Hostname"] == archive["Hostname"]
                and row["User"] == archive["User"]
                and str(row["Event_ID"]) == "PROXY_ACCESS"
                for row in rows_for_observation
                if row["Log_ID"] != "EVT-00428"
            )
        elif rule_id == "R13":
            assert all(str(row["Event_ID"]) == "HTTP_ACCESS" for row in rows_for_observation)
            assert {row["Source_IP"] for row in rows_for_observation} == {"192.0.2.91"}
            assert "categoría documentation" in observation["description"]
            assert "no confirma automatización" in observation["description"]
        elif rule_id == "R07":
            assert all(str(row["Event_ID"]) == "4663" for row in rows_for_observation)
            assert all(
                (row["User"], row["Hostname"], row["Destination"])
                == (
                    "CORP\\backupsvc",
                    "FS-SRV01",
                    "\\\\FS-SRV01\\Finance",
                )
                for row in rows_for_observation
            )
            commands = [row["Process_CommandLine"] for row in rows_for_observation]
            assert all(isinstance(command, str) and command.strip() for command in commands)
            assert len(set(commands)) == 16
            assert "10 valores literales distintos" in observation["description"]
            times = [
                datetime.fromisoformat(row["Timestamp"])
                for row in rows_for_observation
            ]
            assert max(times) - min(times) == timedelta(minutes=4)
        elif rule_id == "R09":
            assert all(str(row["Event_ID"]) == "PROXY_ACCESS" for row in rows_for_observation)
            assert all(row["Log_Source"] == "Proxy" for row in rows_for_observation)
            assert all(
                row["Hostname"] == rows_for_observation[0]["Hostname"]
                and row["User"] == rows_for_observation[0]["User"]
                and row["Destination"] == rows_for_observation[0]["Destination"]
                for row in rows_for_observation
            )
            timestamps = [
                datetime.fromisoformat(row["Timestamp"])
                for row in rows_for_observation
            ]
            assert timestamps == sorted(timestamps)
            assert observation["severity"] is None
            assert observation["severity_status"] == "not_defined"
            assert "no demuestran transferencia exitosa" in observation["description"]
