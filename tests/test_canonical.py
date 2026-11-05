from datetime import datetime

import pytest

from io import BytesIO

from openpyxl import Workbook

from app.analysis import ingest_workbook
from app.canonical import (
    PROVISIONAL_STATUS,
    analysis_id_from_fingerprint,
    canonical_row,
    canonical_value,
    content_sha256,
    logical_fingerprint,
)


def _minimal_workbook(rows):
    workbook = Workbook()
    worksheet = workbook.active
    worksheet.title = "SIEM Export"
    worksheet.append(
        ["Log_ID", "Timestamp", "Hostname", "Event_ID", "User", "Source_IP",
         "Destination", "Log_Source", "Event_Description", "Process_CommandLine",
         "Result", "Severity"]
    )
    for row in rows:
        worksheet.append(row)
    stream = BytesIO()
    workbook.save(stream)
    return stream.getvalue()
_ROW = (
    "EVT-00001",
    "2026-10-23 08:25:00",
    "DC-01",
    4625,
    "CORP\\jlopez",
    "203.0.113.74",
    "DC-01",
    "Security",
    "An account failed to log on - bad password",
    None,
    "Failure",
    "Medium",
)

_OTHER_ROW = (
    "EVT-00002",
    "2026-10-23 08:25:19",
    "DC-01",
    4625,
    "CORP\\aperez",
    "203.0.113.74",
    "DC-01",
    "Security",
    "An account failed to log on - bad password",
    None,
    "Failure",
    "Medium",
)


def test_canonical_row_uses_json_array_with_fixed_field_order() -> None:
    assert canonical_row(_ROW) == (
        '["EVT-00001","2026-10-23 08:25:00","DC-01",4625,"CORP\\\\jlopez",'
        '"203.0.113.74","DC-01","Security",'
        '"An account failed to log on - bad password",null,"Failure","Medium"]'
    )


def test_null_and_empty_string_are_different_representations() -> None:
    assert canonical_value(None) is None
    assert canonical_value("") == ""
    assert canonical_row([None]) != canonical_row([""])


def test_integer_and_numeric_string_are_not_equated() -> None:
    assert canonical_row([4625]) != canonical_row(["4625"])


def test_boolean_is_not_equated_with_integer() -> None:
    assert canonical_row([True]) != canonical_row([1])


def test_datetime_uses_fixed_microsecond_precision() -> None:
    assert canonical_value(datetime(2026, 10, 23, 8, 25)) == {
        "$type": "datetime",
        "value": "2026-10-23T08:25:00.000000",
    }
    assert canonical_value(datetime(2026, 10, 23, 8, 25, 0, 123456)) == {
        "$type": "datetime",
        "value": "2026-10-23T08:25:00.123456",
    }


def test_datetime_and_iso_string_are_not_equated() -> None:
    moment = datetime(2026, 10, 23, 8, 25)
    assert canonical_row([moment]) != canonical_row(["2026-10-23T08:25:00.000000"])


def test_unknown_types_are_rejected_instead_of_coerced() -> None:
    with pytest.raises(TypeError):
        canonical_value(object())


def test_nan_and_infinity_are_rejected() -> None:
    with pytest.raises(ValueError):
        canonical_value(float("nan"))
    with pytest.raises(ValueError):
        canonical_value(float("inf"))


def test_content_sha256_is_independent_of_row_order() -> None:
    assert content_sha256([_ROW, _OTHER_ROW]) == content_sha256(
        [_OTHER_ROW, _ROW]
    )


def test_content_sha256_preserves_identical_duplicates() -> None:
    assert content_sha256([_ROW]) != content_sha256([_ROW, _ROW])


def test_content_sha256_changes_when_content_changes() -> None:
    changed = list(_ROW)
    changed[4] = "CORP\\mgarcia"
    assert content_sha256([_ROW]) != content_sha256([tuple(changed)])


def test_content_sha256_of_empty_workbook_is_stable() -> None:
    assert content_sha256([]) == content_sha256(iter(()))


def _base_result() -> dict[str, object]:
    return {
        "contract": "analysis-partial/1",
        "schema_version": "1.0",
        "canon_version": "cj/1",
        "file_sha256": "a" * 64,
        "content_sha256": "b" * 64,
        "analysis_id": "A-" + "c" * 32,
        "status": "partial",
        "observations": [
            {
                "rule_id": "R01",
                "evidence": [
                    {"Log_ID": "EVT-1", "Timestamp": "2026-10-23T08:25:00"},
                    {"Log_ID": "EVT-2", "Timestamp": "2026-10-23T08:25:19"},
                ],
            },
            {
                "rule_id": "R10",
                "evidence": [{"Log_ID": "EVT-9", "Timestamp": "2026-10-23T09:42:00"}],
            },
        ],
        "rule_execution": {"R01": {"status": "executed"}},
        "chain_execution": {"C1": {"status": "executed"}},
        "non_evaluable_records": [],
    }


def test_fingerprint_ignores_file_sha256_generated_at_and_row_index() -> None:
    baseline = logical_fingerprint(_base_result())
    changed = _base_result()
    changed["file_sha256"] = "d" * 64
    changed["generated_at"] = "2026-11-04T00:00:00"
    changed["row_index"] = 42
    assert logical_fingerprint(changed) == baseline


def test_fingerprint_ignores_analysis_id_to_avoid_self_reference() -> None:
    baseline = logical_fingerprint(_base_result())
    changed = _base_result()
    changed["analysis_id"] = "A-" + "f" * 32
    assert logical_fingerprint(changed) == baseline


def test_fingerprint_is_stable_under_observation_and_evidence_permutation() -> None:
    baseline = logical_fingerprint(_base_result())
    changed = _base_result()
    changed["observations"] = list(reversed(changed["observations"]))  # type: ignore[arg-type]
    changed["observations"][0]["evidence"] = list(  # type: ignore[index]
        reversed(changed["observations"][0]["evidence"])  # type: ignore[index]
    )
    assert logical_fingerprint(changed) == baseline


def test_fingerprint_changes_with_contract_and_versions() -> None:
    baseline = logical_fingerprint(_base_result())
    for field, value in (
        ("contract", "analysis-partial/2"),
        ("schema_version", "2.0"),
        ("canon_version", "cj/2"),
    ):
        changed = _base_result()
        changed[field] = value
        assert logical_fingerprint(changed) != baseline


def test_fingerprint_changes_with_content_sha256() -> None:
    baseline = logical_fingerprint(_base_result())
    changed = _base_result()
    changed["content_sha256"] = "e" * 64
    assert logical_fingerprint(changed) != baseline


def test_analysis_id_is_content_addressed_and_has_no_self_reference() -> None:
    fingerprint = logical_fingerprint(_base_result())
    analysis_id = analysis_id_from_fingerprint(fingerprint)

    assert analysis_id == "A-" + fingerprint[:32]
    assert len(analysis_id) == 34

    result = _base_result()
    result["analysis_id"] = analysis_id
    assert logical_fingerprint(result) == fingerprint


def test_ingest_rejects_non_canonical_cell_value() -> None:
    from unittest.mock import patch

    from app.excel import WorkbookValidationError

    content = _minimal_workbook(
        [
            [
                "EVT-1", "2026-10-23 08:00:00", "DC-01", 4625, "CORP\\u",
                "10.10.1.1", "DC-01", "Security", "desc", None, "Failure", "Medium",
            ]
        ]
    )
    with patch("app.analysis.canonical_row", side_effect=ValueError("tipo no canónico")):
        with pytest.raises(WorkbookValidationError) as exc_info:
            ingest_workbook(content)
    assert exc_info.value.code == "invalid_cell_value"
