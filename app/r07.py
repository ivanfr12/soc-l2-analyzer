from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Mapping

R07_DISTINCT_COMMAND_THRESHOLD = 10
R07_WINDOW = timedelta(minutes=10)


@dataclass(frozen=True)
class R07Event:
    log_id: str | None
    timestamp: datetime | None
    user: object
    hostname: object
    destination: object
    process_command_line: object
    content_signature: tuple[tuple[type, Any], ...]
    evidence: Mapping[str, Any] | None


@dataclass(frozen=True)
class R07Window:
    anchor_time: datetime
    events: tuple[R07Event, ...]
    distinct_command_count: int


@dataclass(frozen=True)
class R07Finding:
    key: tuple[str, str, str]
    evidence: tuple[Mapping[str, Any], ...]


@dataclass(frozen=True)
class R07Evaluation:
    findings: tuple[R07Finding, ...]
    records_evaluated: int
    identical_duplicates_collapsed: int
    conflicting_log_ids: tuple[str, ...]
    conflicting_record_count: int
    missing_log_id_count: int
    invalid_timestamp_log_ids: tuple[str, ...]
    incomplete_key_log_ids: tuple[str, ...]


def _valid_key_component(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _valid_command(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def sliding_r07_windows(events: tuple[R07Event, ...]) -> tuple[R07Window, ...]:
    ordered = tuple(
        sorted(
            events,
            key=lambda event: (event.timestamp, event.log_id or ""),
        )
    )
    windows: list[R07Window] = []
    command_counts: Counter[str] = Counter()
    left = 0
    right = 0
    start = 0

    while start < len(ordered):
        anchor_time = ordered[start].timestamp
        end = start + 1
        while end < len(ordered) and ordered[end].timestamp == anchor_time:
            end += 1

        while right < end:
            command = ordered[right].process_command_line
            if _valid_command(command):
                command_counts[command] += 1
            right += 1

        cutoff = anchor_time - R07_WINDOW
        while left < right and ordered[left].timestamp <= cutoff:
            command = ordered[left].process_command_line
            if _valid_command(command):
                command_counts[command] -= 1
                if command_counts[command] == 0:
                    del command_counts[command]
            left += 1

        windows.append(
            R07Window(
                anchor_time=anchor_time,
                events=ordered[left:right],
                distinct_command_count=len(command_counts),
            )
        )
        start = end

    return tuple(windows)


def evaluate_r07(
    events: tuple[R07Event, ...],
    externally_conflicting_log_ids: tuple[str, ...] = (),
) -> R07Evaluation:
    events_by_id: dict[str, list[R07Event]] = {}
    missing_log_id_count = 0
    for event in events:
        if event.log_id is None or not event.log_id.strip():
            missing_log_id_count += 1
            continue
        events_by_id.setdefault(event.log_id, []).append(event)

    conflicting_ids = set(externally_conflicting_log_ids)
    conflicting_ids.update(
        log_id
        for log_id, versions in events_by_id.items()
        if len({event.content_signature for event in versions}) > 1
    )
    conflicting_log_ids = tuple(sorted(conflicting_ids.intersection(events_by_id)))
    conflicting_record_count = sum(
        len(events_by_id[log_id]) for log_id in conflicting_log_ids
    )

    identical_duplicates_collapsed = 0
    unique_events: list[R07Event] = []
    for log_id, versions in events_by_id.items():
        if log_id in conflicting_ids:
            continue
        identical_duplicates_collapsed += len(versions) - 1
        unique_events.append(versions[0])

    invalid_timestamp_log_ids: list[str] = []
    incomplete_key_log_ids: list[str] = []
    events_by_key: dict[tuple[str, str, str], list[R07Event]] = {}
    for event in unique_events:
        if event.timestamp is None:
            invalid_timestamp_log_ids.append(event.log_id or "")
            continue
        if not all(
            _valid_key_component(value)
            for value in (event.user, event.hostname, event.destination)
        ):
            incomplete_key_log_ids.append(event.log_id or "")
            continue
        key = (event.user, event.hostname, event.destination)
        events_by_key.setdefault(key, []).append(event)

    findings: list[R07Finding] = []
    for key in sorted(events_by_key):
        contributing: dict[str, R07Event] = {}
        for window in sliding_r07_windows(tuple(events_by_key[key])):
            if window.distinct_command_count < R07_DISTINCT_COMMAND_THRESHOLD:
                continue
            for event in window.events:
                contributing[event.log_id or ""] = event

        if contributing:
            evidence = tuple(
                event.evidence
                for event in sorted(
                    contributing.values(),
                    key=lambda event: (event.timestamp, event.log_id or ""),
                )
                if event.evidence is not None
            )
            findings.append(R07Finding(key=key, evidence=evidence))

    return R07Evaluation(
        findings=tuple(findings),
        records_evaluated=sum(len(group) for group in events_by_key.values()),
        identical_duplicates_collapsed=identical_duplicates_collapsed,
        conflicting_log_ids=conflicting_log_ids,
        conflicting_record_count=conflicting_record_count,
        missing_log_id_count=missing_log_id_count,
        invalid_timestamp_log_ids=tuple(sorted(invalid_timestamp_log_ids)),
        incomplete_key_log_ids=tuple(sorted(incomplete_key_log_ids)),
    )
