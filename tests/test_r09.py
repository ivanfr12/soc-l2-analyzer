import os
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from openpyxl import load_workbook

from app.r09 import (
    R09Metrics,
    R09Event,
    evaluate_r09,
    observe_proxy_bytes_out,
    parse_observed_bytes_out,
    r09_matches,
    sliding_r09_windows,
)


_BASE_TIME = datetime(2026, 10, 23, 8, 0)


def _event(
    log_id: str | None,
    seconds: float = 0,
    *,
    hostname: object = "PROXY-01",
    user: object = "CORP\\user",
    destination: object = "203.0.113.20:443",
    command_line: str | None = None,
    signature: str | None = None,
) -> R09Event:
    timestamp = _BASE_TIME + timedelta(seconds=seconds)
    observed = observe_proxy_bytes_out(command_line)
    return R09Event(
        log_id=log_id,
        timestamp=timestamp,
        hostname=hostname,
        user=user,
        destination=destination,
        bytes_out=observed,
        content_signature=((str, signature or f"{log_id}:{timestamp}:{command_line}"),),
        evidence={
            "Log_ID": log_id,
            "Timestamp": timestamp.isoformat(),
            "Hostname": hostname,
            "Event_ID": "PROXY_ACCESS",
            "User": user,
            "Destination": destination,
        },
    )


@pytest.mark.parametrize(
    ("metrics", "expected"),
    [
        (R09Metrics(count=10, observed_bytes_out_sum=None), True),
        (R09Metrics(count=9, observed_bytes_out_sum=None), False),
        (R09Metrics(count=1, observed_bytes_out_sum=52_428_800), True),
        (R09Metrics(count=9, observed_bytes_out_sum=52_428_799), False),
        (R09Metrics(count=10, observed_bytes_out_sum=52_428_800), True),
    ],
)
def test_r09_count_and_volume_thresholds(
    metrics: R09Metrics, expected: bool
) -> None:
    assert r09_matches(metrics) is expected


def test_parses_observed_bytes_out_without_treating_missing_as_zero() -> None:
    assert parse_observed_bytes_out("bytes_out=52428800 uri=/upload") == 52_428_800
    assert parse_observed_bytes_out("uri=/upload") is None
    assert parse_observed_bytes_out(None) is None


@pytest.mark.parametrize(
    ("command_line", "expected"),
    [
        ("bytes_out=52428800", 52_428_800),
        ("bytes_out=52428799 uri=/upload", 52_428_799),
        ("bytes_out=52428801 uri=/upload", 52_428_801),
        ("bytes_out=0", 0),
        ("bytes_out=999999999999999999999999999999999999999999", 999999999999999999999999999999999999999999),
    ],
)
def test_parser_extracts_unsigned_integer_values(
    command_line: str, expected: int
) -> None:
    assert parse_observed_bytes_out(command_line) == expected


@pytest.mark.parametrize(
    "command_line",
    [
        None,
        "",
        "   ",
        "bytes_out=",
        "bytes_out=-1",
        "bytes_out=1.5",
        "bytes_out=abc",
        "bytes_out=12x",
        "bytes_out=12, uri=/upload",
        "bytes_in=52428800 uri=/upload",
        "other_bytes_out=52428800 uri=/upload",
        "uri=/upload bytes_out_extra=52428800",
    ],
)
def test_parser_does_not_extract_missing_malformed_or_other_fields(
    command_line: str | None,
) -> None:
    assert parse_observed_bytes_out(command_line) is None


def test_proxy_byte_observation_is_not_severity_eligible() -> None:
    observed = observe_proxy_bytes_out("bytes_out=123 uri=/upload")
    missing = observe_proxy_bytes_out("uri=/upload")

    assert observed.proxy_bytes_out_field_observed is True
    assert observed.proxy_recorded_bytes_out == "123"
    assert observed.observed_bytes_out_value == 123
    assert observed.observed_bytes_out_sum == 123
    assert observed.severity_eligible is False
    assert missing.proxy_bytes_out_field_observed is False
    assert missing.observed_bytes_out_value is None
    assert missing.observed_bytes_out_sum is None


def test_r09_count_and_bytes_conditions_are_inclusive_and_or_combined() -> None:
    assert r09_matches(R09Metrics(count=10, observed_bytes_out_sum=None))
    assert r09_matches(R09Metrics(count=1, observed_bytes_out_sum=52_428_800))
    assert r09_matches(R09Metrics(count=10, observed_bytes_out_sum=52_428_800))
    assert not r09_matches(R09Metrics(count=9, observed_bytes_out_sum=52_428_799))


def test_r09_metrics_reject_negative_aggregate_values() -> None:
    with pytest.raises(ValueError, match="no pueden ser negativas"):
        r09_matches(R09Metrics(count=-1, observed_bytes_out_sum=None))
    with pytest.raises(ValueError, match="no pueden ser negativas"):
        r09_matches(R09Metrics(count=1, observed_bytes_out_sum=-1))


def test_window_excludes_event_exactly_at_left_boundary() -> None:
    events = tuple(_event(f"old-{index}", seconds=0) for index in range(9)) + (
        _event("anchor", seconds=15 * 60),
    )

    windows = sliding_r09_windows(events)
    anchor_window = windows[-1]

    assert anchor_window.metrics.count == 1
    assert [event.log_id for event in anchor_window.events] == ["anchor"]
    assert evaluate_r09(events).findings == ()


def test_window_includes_event_immediately_after_left_boundary() -> None:
    events = tuple(
        _event(f"near-{index}", seconds=0.000001) for index in range(9)
    ) + (_event("anchor", seconds=15 * 60),)

    anchor_window = sliding_r09_windows(events)[-1]

    assert anchor_window.metrics.count == 10
    assert r09_matches(anchor_window.metrics)


def test_window_includes_event_at_right_boundary_and_excludes_future_event() -> None:
    events = tuple(_event(f"at-anchor-{index}") for index in range(10))
    window = sliding_r09_windows(events)[0]
    assert window.metrics.count == 10
    assert all(event.timestamp == window.anchor_time for event in window.events)

    future_events = tuple(_event(f"past-{index}") for index in range(9)) + (
        _event("future", seconds=0.000001),
    )
    future_windows = sliding_r09_windows(future_events)
    assert future_windows[0].metrics.count == 9
    assert "future" not in {
        event.log_id for event in future_windows[0].events
    }


def test_sliding_windows_handle_different_anchors_and_distributed_events() -> None:
    events = tuple(_event(f"early-{index}", seconds=0) for index in range(6))
    events += tuple(_event(f"middle-{index}", seconds=10 * 60) for index in range(4))
    events += tuple(_event(f"late-{index}", seconds=16 * 60) for index in range(4))

    windows = sliding_r09_windows(events)

    assert [window.metrics.count for window in windows] == [6, 10, 8]
    finding = evaluate_r09(events).findings[0]
    assert len(finding.evidence) == 10
    assert all(not item["Log_ID"].startswith("late-") for item in finding.evidence)


def test_identical_timestamps_and_reversed_input_are_deterministic() -> None:
    events = tuple(_event(f"same-{index}", seconds=5) for index in range(10))
    forward = evaluate_r09(events)
    reverse = evaluate_r09(tuple(reversed(events)))

    assert len(sliding_r09_windows(events)) == 1
    assert sliding_r09_windows(events)[0].metrics.count == 10
    assert forward == reverse
    assert [item["Log_ID"] for item in forward.findings[0].evidence] == [
        f"same-{index}" for index in range(10)
    ]


@pytest.mark.parametrize("count", [9, 10, 12])
def test_unique_event_count_threshold(count: int) -> None:
    result = evaluate_r09(tuple(_event(f"count-{index}") for index in range(count)))

    assert bool(result.findings) is (count >= 10)


def test_identical_log_id_and_content_counts_once() -> None:
    events = tuple(_event(f"unique-{index}") for index in range(8))
    duplicate = _event("duplicate", signature="same-content")
    result = evaluate_r09(events + (duplicate, duplicate))

    assert result.records_evaluated == 9
    assert result.identical_duplicates_collapsed == 1
    assert result.conflicting_log_ids == ()
    assert result.findings == ()


def test_conflicting_log_id_versions_are_all_excluded() -> None:
    events = tuple(_event(f"unique-{index}") for index in range(9))
    first = _event("conflict", signature="content-a")
    second = _event("conflict", signature="content-b")
    result = evaluate_r09(events + (first, second))

    assert result.conflicting_log_ids == ("conflict",)
    assert result.conflicting_record_count == 2
    assert result.records_evaluated == 9
    assert result.findings == ()


@pytest.mark.parametrize(
    ("value", "expected_sum", "matches"),
    [
        ("bytes_out=52428800", 52_428_800, True),
        ("bytes_out=52428799", 52_428_799, False),
        ("bytes_out=52428801", 52_428_801, True),
        (None, None, False),
        ("", None, False),
        ("bytes_out=", None, False),
        ("bytes_out=-1", None, False),
        ("bytes_out=broken", None, False),
        ("bytes_out=1.5", None, False),
    ],
)
def test_volume_threshold_uses_only_valid_nonnegative_values(
    value: str | None, expected_sum: int | None, matches: bool
) -> None:
    result = evaluate_r09((_event("bytes", command_line=value),))

    assert bool(result.findings) is matches
    if matches:
        assert result.findings[0].observed_bytes_out_sum == expected_sum
        assert result.findings[0].matched_count_threshold is False
        assert result.findings[0].matched_bytes_threshold is True
        assert result.findings[0].severity_eligible is False


def test_mixed_valid_and_invalid_bytes_sum_only_valid_values() -> None:
    events = (
        _event("valid-a", command_line="bytes_out=20000000"),
        _event("invalid", seconds=1, command_line="bytes_out=-1"),
        _event("valid-b", seconds=2, command_line="bytes_out=32428800"),
        _event("empty", seconds=3, command_line="bytes_out="),
    )
    result = evaluate_r09(events)

    assert len(result.findings) == 1
    assert result.findings[0].observed_bytes_out_sum == 52_428_800
    assert result.findings[0].severity_eligible is False
    assert len(result.findings[0].evidence) == 4


def test_large_byte_value_qualifies_without_count_threshold() -> None:
    result = evaluate_r09(
        (_event("large", command_line="bytes_out=999999999999999999999999"),)
    )

    assert len(result.findings) == 1
    assert result.findings[0].matched_count_threshold is False
    assert result.findings[0].matched_bytes_threshold is True


def test_finding_reports_count_and_bytes_when_both_thresholds_qualify() -> None:
    events = tuple(
        _event(f"both-{index}", command_line="bytes_out=5242880")
        for index in range(10)
    )
    result = evaluate_r09(events)

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.matched_count_threshold is True
    assert finding.matched_bytes_threshold is True
    assert finding.severity_eligible is True
    assert finding.observed_bytes_out_sum == 52_428_800


@pytest.mark.parametrize(
    "key_field",
    ["hostname", "user", "destination"],
)
def test_grouping_separates_each_key_component(key_field: str) -> None:
    events = tuple(
        _event(
            f"left-{index}",
            **{key_field: f"left-{key_field}"},
        )
        for index in range(9)
    ) + (
        _event("right", **{key_field: f"right-{key_field}"}),
    )

    assert evaluate_r09(events).findings == ()


@pytest.mark.parametrize("invalid", [None, "", "   ", 7])
def test_incomplete_or_invalid_key_components_are_excluded(invalid: object) -> None:
    event = _event("incomplete", user=invalid)
    result = evaluate_r09((event,))

    assert result.records_evaluated == 0
    assert result.incomplete_key_log_ids == ("incomplete",)
    assert result.findings == ()


def test_missing_log_ids_are_excluded() -> None:
    result = evaluate_r09((_event(None),))

    assert result.missing_log_id_count == 1
    assert result.records_evaluated == 0


def test_invalid_timestamps_are_reported_and_excluded() -> None:
    event = _event("invalid-time")
    event = R09Event(
        **{
            **event.__dict__,
            "timestamp": None,
            "evidence": None,
        }
    )
    result = evaluate_r09((event,))

    assert result.invalid_timestamp_log_ids == ("invalid-time",)
    assert result.records_evaluated == 0


def test_overlapping_qualified_windows_consolidate_contributing_evidence() -> None:
    events = tuple(
        _event(f"first-{index}", seconds=index * 60) for index in range(10)
    ) + tuple(
        _event(f"second-{index}", seconds=(20 + index) * 60)
        for index in range(10)
    )
    result = evaluate_r09(events)

    assert len(result.findings) == 1
    evidence_ids = [item["Log_ID"] for item in result.findings[0].evidence]
    assert len(evidence_ids) == 20
    assert len(set(evidence_ids)) == 20
    assert result.findings[0].matched_count_threshold is True


def test_unqualified_window_events_are_not_added_to_consolidated_evidence() -> None:
    events = tuple(_event(f"below-{index}", seconds=0) for index in range(9))
    events += tuple(
        _event(f"qualifying-{index}", seconds=20 * 60)
        for index in range(10)
    )
    result = evaluate_r09(events)

    assert len(result.findings) == 1
    evidence_ids = {item["Log_ID"] for item in result.findings[0].evidence}
    assert len(evidence_ids) == 10
    assert not any(log_id.startswith("below-") for log_id in evidence_ids)


def test_r09_matches_original_proxy_transfer_sequence() -> None:
    workbook_path = os.environ.get("SOC_L2_CHALLENGE_WORKBOOK")
    if not workbook_path:
        pytest.skip("Defina SOC_L2_CHALLENGE_WORKBOOK para validar R09 con el dataset.")

    workbook = load_workbook(
        Path(workbook_path), read_only=True, data_only=True
    )
    try:
        worksheet = workbook["SIEM Export"]
        rows = worksheet.iter_rows(values_only=True)
        headers = next(rows)
        column_index = {name: index for index, name in enumerate(headers)}
        proxy_rows = [
            row
            for row in rows
            if str(row[column_index["Event_ID"]]) == "PROXY_ACCESS"
        ]
    finally:
        workbook.close()

    groups = {
        (
            row[column_index["Hostname"]],
            row[column_index["User"]],
            row[column_index["Destination"]],
        )
        for row in proxy_rows
    }
    byte_values = [
        parse_observed_bytes_out(row[column_index["Process_CommandLine"]])
        for row in proxy_rows
    ]
    timestamps = [
        datetime.fromisoformat(row[column_index["Timestamp"]])
        for row in proxy_rows
    ]
    assert len(proxy_rows) == 22
    assert len(groups) == 1
    assert all(value is not None for value in byte_values)
    observed_bytes_out_sum = sum(value for value in byte_values if value is not None)
    assert observed_bytes_out_sum == 253_305_558
    assert (max(timestamps) - min(timestamps)).total_seconds() <= 15 * 60
    assert r09_matches(
        R09Metrics(count=len(proxy_rows), observed_bytes_out_sum=observed_bytes_out_sum)
    )
