from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.r07 import R07Event, evaluate_r07, sliding_r07_windows

_BASE_TIME = datetime(2026, 10, 23, 9, 0)


def _event(
    log_id: str | None,
    seconds: float = 0,
    *,
    user: object = "CORP\\backupsvc",
    hostname: object = "FS-SRV01",
    destination: object = "\\\\FS-SRV01\\Finance",
    command: object = "File access: file-0.xlsx",
    signature: str | None = None,
    timestamp: datetime | None = None,
) -> R07Event:
    event_time = timestamp or (_BASE_TIME + timedelta(seconds=seconds))
    return R07Event(
        log_id=log_id,
        timestamp=event_time,
        user=user,
        hostname=hostname,
        destination=destination,
        process_command_line=command,
        content_signature=((str, signature if signature is not None else str(log_id)),),
        evidence={
            "Log_ID": log_id,
            "Timestamp": event_time.isoformat(),
            "Event_ID": "4663",
        },
    )


@pytest.mark.parametrize(("count", "expected"), [(9, False), (10, True), (12, True)])
def test_distinct_command_threshold_is_inclusive(
    count: int, expected: bool
) -> None:
    events = tuple(
        _event(f"id-{index}", command=f"File access: file-{index}.xlsx")
        for index in range(count)
    )

    assert bool(evaluate_r07(events).findings) is expected


def test_event_exactly_at_left_boundary_is_excluded() -> None:
    events = (_event("left", seconds=0, command="left"),)
    events += tuple(
        _event(f"inside-{index}", seconds=590 + index, command=f"inside-{index}")
        for index in range(9)
    )
    events += (_event("anchor", seconds=600, command="anchor"),)

    anchor_window = sliding_r07_windows(events)[-1]

    assert anchor_window.anchor_time == _BASE_TIME + timedelta(minutes=10)
    assert anchor_window.distinct_command_count == 10
    assert "left" not in {event.log_id for event in anchor_window.events}
    assert "anchor" in {event.log_id for event in anchor_window.events}


def test_event_immediately_after_left_boundary_is_included() -> None:
    events = (_event("after-left", seconds=0.000001, command="after-left"),)
    events += tuple(
        _event(f"inside-{index}", seconds=590 + index, command=f"inside-{index}")
        for index in range(8)
    )
    events += (_event("anchor", seconds=600, command="anchor"),)

    anchor_window = sliding_r07_windows(events)[-1]

    assert anchor_window.distinct_command_count == 10
    assert "after-left" in {event.log_id for event in anchor_window.events}


def test_event_at_right_boundary_is_included_and_future_event_is_not() -> None:
    events = tuple(
        _event(f"before-{index}", seconds=index + 1, command=f"before-{index}")
        for index in range(9)
    ) + (
        _event("at-anchor", seconds=600, command="at-anchor"),
        _event("future", seconds=601, command="future"),
    )

    window = sliding_r07_windows(events)[-2]

    assert window.anchor_time == _BASE_TIME + timedelta(minutes=10)
    assert window.distinct_command_count == 10
    assert "at-anchor" in {event.log_id for event in window.events}


def test_each_event_time_can_anchor_a_sliding_window_without_clock_alignment() -> None:
    events = tuple(
        _event(
            f"slide-{index}",
            timestamp=datetime(2026, 10, 23, 9, 39, 24) + timedelta(seconds=index),
            command=f"File access: {index}",
        )
        for index in range(10)
    )

    windows = sliding_r07_windows(events)

    assert len(windows) == 10
    assert windows[-1].anchor_time == datetime(2026, 10, 23, 9, 39, 33)
    assert windows[-1].distinct_command_count == 10
    assert len(evaluate_r07(events).findings) == 1


def test_ten_distinct_commands_outside_one_sliding_window_do_not_qualify() -> None:
    events = tuple(
        _event(f"early-{index}", seconds=index, command=f"early-{index}")
        for index in range(5)
    ) + tuple(
        _event(
            f"late-{index}",
            seconds=11 * 60 + index,
            command=f"late-{index}",
        )
        for index in range(5)
    )

    assert not evaluate_r07(events).findings


def test_repeated_commands_count_once_for_distinct_threshold() -> None:
    events = tuple(
        _event(f"repeat-{index}", command=f"command-{index % 9}")
        for index in range(10)
    )

    assert not evaluate_r07(events).findings


def test_case_and_whitespace_differences_are_literal_distinct_values() -> None:
    commands = [
        "File access: a",
        "file access: a",
        " File access: a",
        "File access: a ",
        "File access: b",
        "File access: c",
        "File access: d",
        "File access: e",
        "File access: f",
        "File access: g",
    ]
    events = tuple(
        _event(f"literal-{index}", command=command)
        for index, command in enumerate(commands)
    )

    assert len(evaluate_r07(events).findings) == 1


@pytest.mark.parametrize("command", [None, "", "   ", 7])
def test_missing_empty_whitespace_or_nontext_commands_do_not_count(
    command: object,
) -> None:
    events = tuple(
        _event(f"valid-{index}", command=f"command-{index}")
        for index in range(9)
    ) + (_event("invalid-command", command=command),)

    assert not evaluate_r07(events).findings


@pytest.mark.parametrize(
    "field",
    ["user", "hostname", "destination"],
)
@pytest.mark.parametrize("invalid", [None, "", "   ", 7])
def test_incomplete_or_nontext_keys_are_excluded(field: str, invalid: object) -> None:
    events = tuple(
        _event(
            f"invalid-key-{index}",
            command=f"command-{index}",
            **{field: invalid},
        )
        for index in range(10)
    )

    result = evaluate_r07(events)

    assert not result.findings
    assert result.records_evaluated == 0
    assert len(result.incomplete_key_log_ids) == 10


def test_identical_log_id_and_content_counts_once() -> None:
    events = tuple(
        _event(f"unique-{index}", command=f"command-{index}")
        for index in range(9)
    )
    repeated = _event("duplicate", command="command-8", signature="same-row")

    result = evaluate_r07(events + (repeated, repeated))

    assert not result.findings
    assert result.identical_duplicates_collapsed == 1
    assert result.records_evaluated == 10
    assert sliding_r07_windows(tuple(events) + (repeated,))[0].distinct_command_count == 9


def test_all_versions_of_conflicting_log_id_are_excluded() -> None:
    events = tuple(
        _event(f"unique-{index}", command=f"command-{index}")
        for index in range(9)
    )
    events += (
        _event("conflict", command="command-9", signature="version-a"),
        _event("conflict", command="command-9", signature="version-b"),
    )

    result = evaluate_r07(events)

    assert not result.findings
    assert result.conflicting_log_ids == ("conflict",)
    assert result.conflicting_record_count == 2
    assert result.records_evaluated == 9


def test_externally_detected_conflict_is_excluded_before_windowing() -> None:
    events = tuple(
        _event(f"unique-{index}", command=f"command-{index}")
        for index in range(9)
    ) + (_event("cross-source-conflict", command="command-9"),)

    result = evaluate_r07(
        events,
        externally_conflicting_log_ids=("cross-source-conflict",),
    )

    assert not result.findings
    assert result.conflicting_log_ids == ("cross-source-conflict",)


def test_overlapping_qualified_windows_consolidate_evidence_once() -> None:
    events = tuple(
        _event(f"overlap-{index}", seconds=index * 30, command=f"command-{index}")
        for index in range(12)
    )

    result = evaluate_r07(events)

    assert len(result.findings) == 1
    log_ids = [item["Log_ID"] for item in result.findings[0].evidence]
    assert len(log_ids) == 12
    assert len(set(log_ids)) == 12


def test_unqualified_events_are_not_included_in_consolidated_evidence() -> None:
    early = tuple(
        _event(f"early-{index}", command=f"early-{index}")
        for index in range(9)
    )
    qualifying = tuple(
        _event(
            f"qualified-{index}",
            seconds=20 * 60 + index,
            command=f"qualified-{index}",
        )
        for index in range(10)
    )

    result = evaluate_r07(early + qualifying)

    assert len(result.findings) == 1
    ids = {item["Log_ID"] for item in result.findings[0].evidence}
    assert ids == {f"qualified-{index}" for index in range(10)}


@pytest.mark.parametrize("field", ["user", "hostname", "destination"])
def test_different_groups_do_not_combine_or_share_evidence(field: str) -> None:
    first = tuple(
        _event(f"first-{index}", command=f"first-command-{index}")
        for index in range(9)
    )
    second = tuple(
        _event(
            f"second-{index}",
            command=f"second-command-{index}",
            **{field: f"other-{field}"},
        )
        for index in range(9)
    )

    assert not evaluate_r07(first + second).findings

    qualifying = first + (
        _event("first-last", command="first-command-9"),
    ) + second
    result = evaluate_r07(qualifying)

    assert len(result.findings) == 1
    assert result.findings[0].key == (
        "CORP\\backupsvc",
        "FS-SRV01",
        "\\\\FS-SRV01\\Finance",
    )


@pytest.mark.parametrize("field", ["user", "hostname", "destination"])
def test_key_values_are_not_trimmed_or_case_normalized(field: str) -> None:
    first = tuple(
        _event(f"literal-{index}", command=f"command-{index}")
        for index in range(9)
    )
    changed = _event(
        "different-key",
        command="command-9",
        **{field: " " + str(getattr(first[0], field)).swapcase()},
    )

    assert not evaluate_r07(first + (changed,)).findings


def test_invalid_timestamps_are_reported_and_excluded() -> None:
    valid = tuple(
        _event(f"valid-{index}", command=f"command-{index}")
        for index in range(9)
    )
    invalid = _event("invalid-time", command="command-9")
    invalid = R07Event(
        **{**invalid.__dict__, "timestamp": None, "evidence": None}
    )

    result = evaluate_r07(valid + (invalid,))

    assert not result.findings
    assert result.invalid_timestamp_log_ids == ("invalid-time",)
    assert result.records_evaluated == 9


def test_same_timestamps_and_reversed_input_are_deterministic() -> None:
    events = tuple(
        _event(
            f"same-{index:02}",
            timestamp=_BASE_TIME,
            command=f"command-{index}",
        )
        for index in range(10)
    )

    forward = evaluate_r07(events)
    reverse = evaluate_r07(tuple(reversed(events)))

    assert len(sliding_r07_windows(events)) == 1
    assert forward == reverse
    assert [item["Log_ID"] for item in forward.findings[0].evidence] == [
        f"same-{index:02}" for index in range(10)
    ]


def test_repeated_evaluation_of_identical_input_is_deterministic() -> None:
    events = tuple(
        _event(f"repeat-run-{index}", command=f"command-{index}")
        for index in range(10)
    )

    assert evaluate_r07(events) == evaluate_r07(events)


def test_evidence_is_sorted_by_timestamp_then_log_id() -> None:
    events = (
        _event("z-same-time", seconds=2, command="command-z"),
        _event("b-same-time", seconds=2, command="command-b"),
    ) + tuple(
        _event(f"id-{index:02}", seconds=index, command=f"command-{index}")
        for index in range(8)
    )

    evidence = evaluate_r07(events).findings[0].evidence
    ordering = [(item["Timestamp"], item["Log_ID"]) for item in evidence]

    assert ordering == sorted(ordering)


def test_missing_log_ids_are_excluded_from_evaluation() -> None:
    result = evaluate_r07((_event(None),))

    assert result.missing_log_id_count == 1
    assert result.records_evaluated == 0
    assert not result.findings
