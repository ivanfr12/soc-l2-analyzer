import os
from datetime import datetime
from pathlib import Path

import pytest
from openpyxl import load_workbook

from app.r09 import (
    R09Metrics,
    observe_proxy_bytes_out,
    parse_observed_bytes_out,
    r09_matches,
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
