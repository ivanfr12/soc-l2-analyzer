from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Mapping

from app.ip_classification import IPClassification

R13_WINDOW = timedelta(minutes=5)
R13_REQUEST_THRESHOLD = 10
R13_ERROR_RATE_NUMERATOR = 30
R13_SCORE_CAP_1E4 = 7_500
_SENSITIVE_SEGMENTS = frozenset({"admin", "login", "api", "upload"})
_HTTP_RESULT = re.compile(r"[0-9]{3}\Z", re.ASCII)
_PERCENT_ESCAPE = re.compile(r"%([0-9A-Fa-f]{2})")
_UNRESERVED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)


@dataclass(frozen=True)
class R13Event:
    log_id: object
    timestamp: datetime | None
    source_ip: IPClassification
    uri: object
    result: object
    content_signature: tuple[tuple[type, Any], ...]
    evidence: Mapping[str, Any] | None


@dataclass(frozen=True)
class R13Metrics:
    request_count: int
    valid_result_count: int
    error_count: int
    sensitive_route_count: int

    @property
    def error_rate(self) -> float | None:
        if self.valid_result_count == 0:
            return None
        return self.error_count / self.valid_result_count

    @property
    def qualifies(self) -> bool:
        if self.request_count < R13_REQUEST_THRESHOLD:
            return False
        rate_qualifies = (
            self.valid_result_count > 0
            and self.error_count * 100
            >= self.valid_result_count * R13_ERROR_RATE_NUMERATOR
        )
        return rate_qualifies or self.sensitive_route_count >= 1


@dataclass(frozen=True)
class R13Finding:
    source_ip_key: str
    metrics: R13Metrics
    qualifying_window_log_ids: tuple[str, ...]
    evidence: tuple[Mapping[str, Any], ...]


@dataclass(frozen=True)
class R13Evaluation:
    findings: tuple[R13Finding, ...]
    records_evaluated: int
    identical_duplicates_collapsed: int
    conflicting_log_ids: tuple[str, ...]
    conflicting_record_count: int
    invalid_log_id_count: int
    invalid_timestamp_log_ids: tuple[str, ...]
    invalid_ip_log_ids: tuple[str, ...]


def cap_r13_score(score_1e4: int | None) -> int | None:
    return None if score_1e4 is None else min(score_1e4, R13_SCORE_CAP_1E4)


def _http_result(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 100 <= value <= 599 else None
    if not isinstance(value, str):
        return None
    text = value.strip(" ")
    if _HTTP_RESULT.fullmatch(text) is None:
        return None
    result = int(text)
    return result if 100 <= result <= 599 else None


def _path_has_sensitive_segment(uri: object) -> bool:
    if not isinstance(uri, str) or not uri.startswith("/"):
        return False
    if any(unicodedata.category(character) == "Cc" for character in uri):
        return False
    if "\\" in uri:
        return False

    index = 0
    while index < len(uri):
        if uri[index] == "%":
            if _PERCENT_ESCAPE.match(uri, index) is None:
                return False
            index += 3
        else:
            index += 1

    path = uri.split("#", 1)[0].split("?", 1)[0]
    decoded: list[str] = []
    index = 0
    while index < len(path):
        if path[index] != "%":
            decoded.append(path[index])
            index += 1
            continue
        byte = int(path[index + 1 : index + 3], 16)
        character = chr(byte)
        if character in _UNRESERVED:
            decoded.append(character)
        else:
            decoded.append(f"%{byte:02X}")
        index += 3

    return any(
        segment.isascii() and segment.lower() in _SENSITIVE_SEGMENTS
        for segment in "".join(decoded).split("/")
        if segment
    )


def _valid_log_id(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _source_ip_key(source_ip: IPClassification) -> str | None:
    if source_ip.category in ("missing", "invalid") or source_ip.value is None:
        return None
    try:
        return ipaddress.ip_address(source_ip.value).compressed
    except ValueError:
        return None


def _event_order(event: R13Event) -> tuple[datetime, str]:
    return event.timestamp, event.log_id


def evaluate_r13(
    events: tuple[R13Event, ...],
    externally_conflicting_log_ids: tuple[str, ...] = (),
) -> R13Evaluation:
    events_by_id: dict[str, list[R13Event]] = {}
    invalid_log_id_count = 0
    for event in events:
        if not _valid_log_id(event.log_id):
            invalid_log_id_count += 1
            continue
        events_by_id.setdefault(event.log_id, []).append(event)

    conflicting_ids = set(externally_conflicting_log_ids)
    conflicting_ids.update(
        log_id
        for log_id, versions in events_by_id.items()
        if len({event.content_signature for event in versions}) > 1
    )
    conflicting_log_ids = tuple(
        sorted(conflicting_ids.intersection(events_by_id))
    )
    conflicting_record_count = sum(
        len(events_by_id[log_id]) for log_id in conflicting_log_ids
    )

    identical_duplicates_collapsed = 0
    unique_events: list[R13Event] = []
    for log_id, versions in events_by_id.items():
        if log_id in conflicting_ids:
            continue
        identical_duplicates_collapsed += len(versions) - 1
        unique_events.append(versions[0])

    invalid_timestamp_log_ids: list[str] = []
    invalid_ip_log_ids: list[str] = []
    events_by_ip: dict[str, list[R13Event]] = {}
    for event in unique_events:
        log_id = event.log_id
        if event.timestamp is None:
            invalid_timestamp_log_ids.append(log_id)
            continue
        source_ip_key = _source_ip_key(event.source_ip)
        if source_ip_key is None:
            invalid_ip_log_ids.append(log_id)
            continue
        events_by_ip.setdefault(source_ip_key, []).append(event)

    findings: list[R13Finding] = []
    for source_ip_key in sorted(events_by_ip):
        ordered = tuple(sorted(events_by_ip[source_ip_key], key=_event_order))
        results = tuple(_http_result(event.result) for event in ordered)
        sensitive_routes = tuple(
            _path_has_sensitive_segment(event.uri) for event in ordered
        )
        contributors: dict[str, R13Event] = {}
        left = 0
        right = 0
        start = 0
        valid_result_count = 0
        error_count = 0
        sensitive_route_count = 0
        first_qualifying_metrics: R13Metrics | None = None
        first_qualifying_window_log_ids: tuple[str, ...] = ()

        while start < len(ordered):
            anchor_time = ordered[start].timestamp
            end = start + 1
            while end < len(ordered) and ordered[end].timestamp == anchor_time:
                end += 1

            while right < end:
                result = results[right]
                valid_result_count += result is not None
                error_count += result is not None and 400 <= result <= 599
                sensitive_route_count += sensitive_routes[right]
                right += 1

            cutoff = anchor_time - R13_WINDOW
            while left < right and ordered[left].timestamp <= cutoff:
                result = results[left]
                valid_result_count -= result is not None
                error_count -= result is not None and 400 <= result <= 599
                sensitive_route_count -= sensitive_routes[left]
                left += 1

            metrics = R13Metrics(
                request_count=right - left,
                valid_result_count=valid_result_count,
                error_count=error_count,
                sensitive_route_count=sensitive_route_count,
            )
            if metrics.qualifies:
                if first_qualifying_metrics is None:
                    first_qualifying_metrics = metrics
                    first_qualifying_window_log_ids = tuple(
                        event.log_id for event in ordered[left:right]
                    )
                for event in ordered[left:right]:
                    contributors[event.log_id] = event
            start = end

        if contributors and first_qualifying_metrics is not None:
            evidence = tuple(
                dict(event.evidence)
                for event in sorted(contributors.values(), key=_event_order)
                if event.evidence is not None
            )
            findings.append(
                R13Finding(
                    source_ip_key=source_ip_key,
                    metrics=first_qualifying_metrics,
                    qualifying_window_log_ids=first_qualifying_window_log_ids,
                    evidence=evidence,
                )
            )

    return R13Evaluation(
        findings=tuple(findings),
        records_evaluated=sum(len(group) for group in events_by_ip.values()),
        identical_duplicates_collapsed=identical_duplicates_collapsed,
        conflicting_log_ids=conflicting_log_ids,
        conflicting_record_count=conflicting_record_count,
        invalid_log_id_count=invalid_log_id_count,
        invalid_timestamp_log_ids=tuple(sorted(invalid_timestamp_log_ids)),
        invalid_ip_log_ids=tuple(sorted(invalid_ip_log_ids)),
    )
