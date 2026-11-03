from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

R09_COUNT_THRESHOLD = 10
R09_BYTES_THRESHOLD = 52_428_800

_BYTES_OUT_PATTERN = re.compile(r"(?:^|\s)bytes_out=(\d+)(?:\s|$)")


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


def parse_observed_bytes_out(command_line: str | None) -> int | None:
    if command_line is None:
        return None
    match = _BYTES_OUT_PATTERN.search(command_line)
    return int(match.group(1)) if match else None


def observe_proxy_bytes_out(command_line: str | None) -> ProxyBytesOutObservation:
    if command_line is None:
        return ProxyBytesOutObservation(False, None, None, None)
    match = _BYTES_OUT_PATTERN.search(command_line)
    if match is None:
        return ProxyBytesOutObservation(False, None, None, None)

    raw_value = match.group(1)
    value = int(raw_value)
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
