from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Literal, Mapping

R09_COUNT_THRESHOLD = 10
R09_BYTES_THRESHOLD = 52_428_800
R09_WINDOW = timedelta(minutes=15)

_BYTES_OUT_PATTERN = re.compile(r"(?:^|\s)bytes_out=([^\s]*)")
_NON_NEGATIVE_INTEGER = re.compile(r"[0-9]+\Z")


@dataclass(frozen=True)
class R09Metrics:
    count: int
    observed_bytes_out_sum: int | None


@dataclass(frozen=True)
class ProxyBytesOutObservation:
    proxy_bytes_out_field_observed: bool
    proxy_recorded_bytes_out: str | None
    observed_bytes_out_value: int | None
    observed_bytes_out_sum: int | None
    severity_eligible: Literal[False] = False


@dataclass(frozen=True)
class R09Event:
    log_id: str | None
    timestamp: datetime | None
    hostname: object
    user: object
    destination: object
    bytes_out: ProxyBytesOutObservation
    content_signature: tuple[tuple[type, Any], ...]
    evidence: Mapping[str, Any] | None


@dataclass(frozen=True)
class R09Finding:
    key: tuple[str, str, str]
    evidence: tuple[Mapping[str, Any], ...]
    matched_count_threshold: bool
    matched_bytes_threshold: bool
    observed_bytes_out_sum: int | None

    @property
    def severity_eligible(self) -> Literal[False] | bool:
        return not (
            self.matched_bytes_threshold and not self.matched_count_threshold
        )


@dataclass(frozen=True)
class R09Window:
    anchor_time: datetime
    events: tuple[R09Event, ...]
    metrics: R09Metrics


@dataclass(frozen=True)
class R09Evaluation:
    findings: tuple[R09Finding, ...]
    records_evaluated: int
    identical_duplicates_collapsed: int
    conflicting_log_ids: tuple[str, ...]
    conflicting_record_count: int
    missing_log_id_count: int
    invalid_timestamp_log_ids: tuple[str, ...]
    incomplete_key_log_ids: tuple[str, ...]


def parse_observed_bytes_out(command_line: str | None) -> int | None:
    if command_line is None:
        return None
    match = _BYTES_OUT_PATTERN.search(command_line)
    if match is None or _NON_NEGATIVE_INTEGER.fullmatch(match.group(1)) is None:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def observe_proxy_bytes_out(command_line: str | None) -> ProxyBytesOutObservation:
    if command_line is None:
        return ProxyBytesOutObservation(False, None, None, None)
    match = _BYTES_OUT_PATTERN.search(command_line)
    if match is None:
        return ProxyBytesOutObservation(False, None, None, None)

    raw_value = match.group(1)
    value = parse_observed_bytes_out(command_line)
    return ProxyBytesOutObservation(True, raw_value, value, value)


def r09_matches(metrics: R09Metrics) -> bool:
    if metrics.count < 0 or (
        metrics.observed_bytes_out_sum is not None
        and metrics.observed_bytes_out_sum < 0
    ):
        raise ValueError("Las métricas R09 no pueden ser negativas.")
    return (
        metrics.count >= R09_COUNT_THRESHOLD
        or (
            metrics.observed_bytes_out_sum is not None
            and metrics.observed_bytes_out_sum >= R09_BYTES_THRESHOLD
        )
    )


def _valid_key_component(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def sliding_r09_windows(events: tuple[R09Event, ...]) -> tuple[R09Window, ...]:
    ordered = tuple(
        sorted(
            events,
            key=lambda event: (event.timestamp, event.log_id or ""),
        )
    )
    byte_prefix = [0]
    valid_byte_prefix = [0]
    for event in ordered:
        value = event.bytes_out.observed_bytes_out_value
        valid = value is not None and value >= 0
        byte_prefix.append(byte_prefix[-1] + (value if valid else 0))
        valid_byte_prefix.append(valid_byte_prefix[-1] + int(valid))

    windows: list[R09Window] = []
    left = 0
    start = 0
    while start < len(ordered):
        anchor_time = ordered[start].timestamp
        end = start + 1
        while end < len(ordered) and ordered[end].timestamp == anchor_time:
            end += 1

        cutoff = anchor_time - R09_WINDOW
        while ordered[left].timestamp <= cutoff:
            left += 1

        valid_bytes_count = valid_byte_prefix[end] - valid_byte_prefix[left]
        byte_sum = byte_prefix[end] - byte_prefix[left]
        windows.append(
            R09Window(
                anchor_time=anchor_time,
                events=ordered[left:end],
                metrics=R09Metrics(
                    count=end - left,
                    observed_bytes_out_sum=byte_sum if valid_bytes_count else None,
                ),
            )
        )
        start = end
    return tuple(windows)


def evaluate_r09(
    events: tuple[R09Event, ...],
    externally_conflicting_log_ids: tuple[str, ...] = (),
) -> R09Evaluation:
    events_by_id: dict[str, list[R09Event]] = {}
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

    unique_events: list[R09Event] = []
    identical_duplicates_collapsed = 0
    for log_id, versions in events_by_id.items():
        if log_id in conflicting_ids:
            continue
        identical_duplicates_collapsed += len(versions) - 1
        unique_events.append(versions[0])

    invalid_timestamp_log_ids: list[str] = []
    incomplete_key_log_ids: list[str] = []
    events_by_key: dict[tuple[str, str, str], list[R09Event]] = {}
    for event in unique_events:
        if event.timestamp is None:
            invalid_timestamp_log_ids.append(event.log_id or "")
            continue
        if not all(
            _valid_key_component(value)
            for value in (event.hostname, event.user, event.destination)
        ):
            incomplete_key_log_ids.append(event.log_id or "")
            continue
        key = (event.hostname, event.user, event.destination)
        events_by_key.setdefault(key, []).append(event)

    findings: list[R09Finding] = []
    for key in sorted(events_by_key):
        contributing: dict[str, R09Event] = {}
        matched_count_threshold = False
        matched_bytes_threshold = False
        max_qualified_bytes_sum: int | None = None
        for window in sliding_r09_windows(tuple(events_by_key[key])):
            observed_sum = window.metrics.observed_bytes_out_sum
            if r09_matches(window.metrics):
                count_match = window.metrics.count >= R09_COUNT_THRESHOLD
                bytes_match = (
                    observed_sum is not None
                    and observed_sum >= R09_BYTES_THRESHOLD
                )
                matched_count_threshold = matched_count_threshold or count_match
                matched_bytes_threshold = matched_bytes_threshold or bytes_match
                if bytes_match:
                    max_qualified_bytes_sum = max(
                        max_qualified_bytes_sum or 0, observed_sum
                    )
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
            findings.append(
                R09Finding(
                    key=key,
                    evidence=evidence,
                    matched_count_threshold=matched_count_threshold,
                    matched_bytes_threshold=matched_bytes_threshold,
                    observed_bytes_out_sum=max_qualified_bytes_sum,
                )
            )

    return R09Evaluation(
        findings=tuple(findings),
        records_evaluated=sum(len(group) for group in events_by_key.values()),
        identical_duplicates_collapsed=identical_duplicates_collapsed,
        conflicting_log_ids=conflicting_log_ids,
        conflicting_record_count=conflicting_record_count,
        missing_log_id_count=missing_log_id_count,
        invalid_timestamp_log_ids=tuple(sorted(invalid_timestamp_log_ids)),
        incomplete_key_log_ids=tuple(sorted(incomplete_key_log_ids)),
    )
