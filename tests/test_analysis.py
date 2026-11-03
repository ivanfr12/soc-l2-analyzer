import os
import re
from collections import Counter
from datetime import datetime
from io import BytesIO
from pathlib import Path

import pytest
from openpyxl import Workbook, load_workbook

from app.analysis import analyze_workbook


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


def test_partial_analysis_separates_pending_rules_and_activity() -> None:
    result = analyze_workbook(_minimal_workbook([_base_row("EVT-TEST-1")]))

    assert result["status"] == "partial"
    assert result["completeness"]["records_seen"] == 1
    assert result["completeness"]["records_evaluated"] == 1
    assert result["rule_execution"]["R03"]["status"] == "executed"
    assert result["rule_execution"]["R09"]["status"] == "pending"
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


def test_r06_emits_point_observation_without_claiming_window_correlation() -> None:
    row = _base_row("EVT-RECON", 4104)
    row[8] = "Get-LocalGroupMember Administrators"

    result = analyze_workbook(_minimal_workbook([row]))
    observation = next(
        item for item in result["observations"] if item["rule_id"] == "R06"
    )

    assert observation["evidence"][0]["Log_ID"] == "EVT-RECON"
    assert result["rule_execution"]["R06"]["status"] == "partially_executed"
    assert "no se aplicó agrupación temporal" in observation["description"]


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
    assert result["ip_classification_status"] == "provisional_without_iana_snapshots"


def test_original_workbook_loads_715_records_and_only_emits_traced_matches() -> None:
    workbook_path = os.environ.get("SOC_L2_CHALLENGE_WORKBOOK")
    if not workbook_path:
        pytest.skip("Defina SOC_L2_CHALLENGE_WORKBOOK para probar el workbook original.")

    result = analyze_workbook(Path(workbook_path).read_bytes())

    assert result["completeness"]["records_seen"] == 715
    assert result["completeness"]["records_evaluated"] == 715
    assert result["completeness"]["records_not_evaluable"] == 0
    assert result["completeness"]["rules_executed"] == 6
    assert result["completeness"]["rules_partially_executed"] == 2
    assert result["completeness"]["rules_pending"] == 5
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
        }
    )
    assert actual == expected
    assert sum(actual.values()) == 14

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
