from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.analysis import _make_observation
from app.ip_classification import IPClassification, classify_ip
from app.r13 import R13Event, cap_r13_score, evaluate_r13
from app.scoring import apply_object_caps

_BASE_TIME = datetime(2026, 10, 23, 12, 0)


def _event(
    index: int,
    *,
    log_id: object | None = None,
    timestamp: datetime | None = None,
    source_ip: IPClassification | None = None,
    uri: object = "/safe",
    result: object = 200,
    signature: tuple[tuple[type, object], ...] | None = None,
) -> R13Event:
    event_id = f"EVT-{index:05}" if log_id is None else log_id
    event_time = _BASE_TIME + timedelta(seconds=index) if timestamp is None else timestamp
    ip = classify_ip("192.0.2.91") if source_ip is None else source_ip
    row_signature = signature or tuple(
        (type(value), value)
        for value in (event_id, event_time, ip.value, uri, result)
    )
    return R13Event(
        log_id=event_id,
        timestamp=event_time,
        source_ip=ip,
        uri=uri,
        result=result,
        content_signature=row_signature,
        evidence={
            "Log_ID": event_id,
            "Timestamp": event_time.isoformat(),
            "Source_IP": ip.value,
            "source_ip_category": ip.category,
        },
    )


def _events(
    count: int,
    *,
    source_ip: str = "192.0.2.91",
    start: datetime = _BASE_TIME,
    interval: timedelta = timedelta(seconds=10),
    uri: object = "/safe",
    result: object = 200,
) -> tuple[R13Event, ...]:
    ip = classify_ip(source_ip)
    return tuple(
        _event(
            index,
            timestamp=start + interval * index,
            source_ip=ip,
            uri=uri,
            result=result,
        )
        for index in range(count)
    )


def _finding(events: tuple[R13Event, ...]):
    evaluation = evaluate_r13(events)
    assert len(evaluation.findings) == 1
    return evaluation.findings[0]


@pytest.mark.parametrize(("count", "expected"), [(9, 0), (10, 1), (11, 1)])
def test_request_count_threshold_is_inclusive(count: int, expected: int) -> None:
    events = _events(count, result=500)

    assert len(evaluate_r13(events).findings) == expected


@pytest.mark.parametrize(
    ("error_count", "expected"),
    [(2, False), (3, True), (4, True)],
)
def test_error_rate_threshold_uses_exact_integer_comparison(
    error_count: int, expected: bool
) -> None:
    events = tuple(
        _event(index, result=500 if index < error_count else 200)
        for index in range(10)
    )

    assert bool(evaluate_r13(events).findings) is expected


@pytest.mark.parametrize(
    "route",
    [
        "/admin",
        "/login",
        "/api",
        "/upload",
        "/foo/admin/bar",
        "/ADMIN/",
        "/api/v1/export",
        "/login?user=admin",
        "/upload/file",
        "//foo///admin//bar/",
    ],
)
def test_sensitive_route_segments_qualify(route: str) -> None:
    events = _events(10, uri="/safe")[:-1] + (
        _event(9, uri=route, timestamp=_BASE_TIME + timedelta(seconds=90)),
    )

    assert _finding(events).metrics.sensitive_route_count == 1


@pytest.mark.parametrize(
    "route",
    [
        "/administrator",
        "/apiary",
        "/login2",
        "/upload-test",
        "/uploads",
        "/%2Fadmin",
        "/%5Cadmin",
        "/bad%escape/admin",
        "/bad\x00/admin",
        r"/foo\admin",
    ],
)
def test_nonmatching_or_invalid_sensitive_paths_do_not_qualify(route: str) -> None:
    events = _events(10, uri="/safe")[:-1] + (
        _event(9, uri=route, timestamp=_BASE_TIME + timedelta(seconds=90)),
    )

    assert evaluate_r13(events).findings == ()


def test_unreserved_url_encoding_is_decoded_once_and_query_is_ignored() -> None:
    assert _finding(_events(10, uri="/%61dmin?return=%2F")).metrics.sensitive_route_count == 10
    assert evaluate_r13(_events(10, uri="/safe?path=/admin")).findings == ()
    assert evaluate_r13(_events(10, uri="/safe#/admin")).findings == ()


@pytest.mark.parametrize(
    ("result", "valid", "errors"),
    [
        (200, 1, 0),
        (" 200 ", 1, 0),
        (302, 1, 0),
        ("404", 1, 1),
        (500, 1, 1),
        (99, 0, 0),
        (600, 0, 0),
        (True, 0, 0),
        (" 404\t", 0, 0),
        ("4٠4", 0, 0),
        (None, 0, 0),
        ("", 0, 0),
        ("success", 0, 0),
    ],
)
def test_result_parser_metrics(result: object, valid: int, errors: int) -> None:
    metrics = _finding(_events(10, uri="/admin", result=result)).metrics

    assert metrics.request_count == 10
    assert metrics.valid_result_count == valid * 10
    assert metrics.error_count == errors * 10


def test_invalid_results_remain_in_request_count_and_zero_denominator_is_safe() -> None:
    events = tuple(_event(index, result=None, uri="/admin") for index in range(10))
    finding = _finding(events)

    assert finding.metrics.request_count == 10
    assert finding.metrics.valid_result_count == 0
    assert finding.metrics.error_count == 0
    assert finding.metrics.error_rate is None

    no_route = tuple(_event(index, uri="/safe", result=None) for index in range(10))
    assert evaluate_r13(no_route).findings == ()


def test_invalid_uri_does_not_remove_request_from_error_rate_branch() -> None:
    events = tuple(
        _event(
            index,
            uri="/bad%escape",
            result=500 if index < 3 else 200,
        )
        for index in range(10)
    )

    finding = _finding(events)

    assert finding.metrics.request_count == 10
    assert finding.metrics.valid_result_count == 10
    assert finding.metrics.error_count == 3
    assert finding.metrics.sensitive_route_count == 0


def test_error_rate_denominator_uses_only_valid_results() -> None:
    events = tuple(
        _event(
            index,
            uri=None,
            result=500 if index < 2 else 200 if index == 2 else None,
        )
        for index in range(10)
    )

    finding = _finding(events)

    assert finding.metrics.request_count == 10
    assert finding.metrics.valid_result_count == 3
    assert finding.metrics.error_count == 2
    assert finding.metrics.sensitive_route_count == 0


@pytest.mark.parametrize(
    ("address", "category"),
    [
        ("192.0.2.91", "documentation"),
        ("10.0.0.7", "private"),
        ("224.0.0.7", "special"),
        ("8.8.8.8", "unknown"),
    ],
)
def test_all_valid_ip_categories_are_eligible(address: str, category: str) -> None:
    ip = classify_ip(address)
    assert ip.category == category

    finding = _finding(_events(10, source_ip=address, result=500))

    assert finding.source_ip_key
    assert finding.evidence[0]["source_ip_category"] == category


def test_public_category_is_eligible_and_preserves_classification() -> None:
    ip = IPClassification("198.18.0.1", "public", "fixture", "verified")
    finding = _finding(
        tuple(_event(index, source_ip=ip, result=500) for index in range(10))
    )

    assert finding.evidence[0]["source_ip_category"] == "public"


@pytest.mark.parametrize("address", [None, "not-an-ip"])
def test_missing_or_invalid_ip_is_excluded(address: object) -> None:
    ip = classify_ip(address)
    events = tuple(_event(index, source_ip=ip, result=500) for index in range(10))
    evaluation = evaluate_r13(events)

    assert evaluation.findings == ()
    assert evaluation.records_evaluated == 0
    assert len(evaluation.invalid_ip_log_ids) == 10


def test_ipv4_mapped_ipv6_keeps_its_group_separate_from_ipv4() -> None:
    mapped = classify_ip("::ffff:192.0.2.91")
    ipv4 = classify_ip("192.0.2.91")
    events = tuple(
        _event(index, source_ip=mapped, result=500) for index in range(5)
    ) + tuple(
        _event(index + 5, source_ip=ipv4, result=500) for index in range(5)
    )

    assert evaluate_r13(events).findings == ()


def test_ipv4_mapped_ipv6_evidence_preserves_original_address_representation() -> None:
    mapped = classify_ip("::ffff:192.0.2.91")
    finding = _finding(
        tuple(_event(index, source_ip=mapped, result=500) for index in range(10))
    )

    assert finding.evidence[0]["Source_IP"] == "::ffff:192.0.2.91"
    assert finding.evidence[0]["source_ip_category"] == "documentation"


def test_finding_preserves_the_first_qualifying_window_log_ids() -> None:
    events = _events(21, interval=timedelta(seconds=12), result=500)

    finding = _finding(events)

    assert finding.qualifying_window_log_ids == tuple(
        event.log_id for event in events[:10]
    )
    assert len(finding.evidence) == 21


def test_identical_log_id_duplicates_count_once() -> None:
    unique = _events(9, result=500)
    duplicate = R13Event(
        log_id=unique[0].log_id,
        timestamp=unique[0].timestamp,
        source_ip=unique[0].source_ip,
        uri=unique[0].uri,
        result=unique[0].result,
        content_signature=unique[0].content_signature,
        evidence=unique[0].evidence,
    )

    evaluation = evaluate_r13(unique + (duplicate,))

    assert evaluation.identical_duplicates_collapsed == 1
    assert evaluation.records_evaluated == 9
    assert evaluation.findings == ()


def test_conflicting_log_id_excludes_all_versions() -> None:
    events = list(_events(10, result=500))
    conflict = _event(
        0,
        log_id=events[0].log_id,
        timestamp=events[0].timestamp,
        source_ip=events[0].source_ip,
        uri="/changed",
        result=500,
    )

    evaluation = evaluate_r13(tuple(events) + (conflict,))

    assert evaluation.conflicting_log_ids == (events[0].log_id,)
    assert evaluation.conflicting_record_count == 2
    assert evaluation.records_evaluated == 9
    assert evaluation.findings == ()


def test_conflicting_signature_preserves_types() -> None:
    events = list(_events(10, result=500))
    duplicate = _event(
        0,
        log_id=events[0].log_id,
        timestamp=events[0].timestamp,
        source_ip=events[0].source_ip,
        result=events[0].result,
        signature=((int, 1),),
    )
    typed_variant = R13Event(
        log_id=duplicate.log_id,
        timestamp=duplicate.timestamp,
        source_ip=duplicate.source_ip,
        uri=duplicate.uri,
        result=duplicate.result,
        content_signature=((str, "1"),),
        evidence=duplicate.evidence,
    )

    evaluation = evaluate_r13(tuple(events) + (typed_variant,))

    assert evaluation.conflicting_log_ids == (events[0].log_id,)
    assert evaluation.records_evaluated == 9


@pytest.mark.parametrize("invalid_id", [None, "", "   ", 42])
def test_invalid_log_ids_are_excluded(invalid_id: object) -> None:
    events = list(_events(10, result=500))
    original = events[-1]
    events[-1] = R13Event(
        log_id=invalid_id,
        timestamp=original.timestamp,
        source_ip=original.source_ip,
        uri=original.uri,
        result=original.result,
        content_signature=original.content_signature,
        evidence=original.evidence,
    )

    evaluation = evaluate_r13(tuple(events))

    assert evaluation.invalid_log_id_count == 1
    assert evaluation.records_evaluated == 9
    assert evaluation.findings == ()


def test_invalid_timestamps_are_excluded_from_windows() -> None:
    events = list(_events(10, result=500))
    original = events[-1]
    events[-1] = R13Event(
        log_id=original.log_id,
        timestamp=None,
        source_ip=original.source_ip,
        uri=original.uri,
        result=original.result,
        content_signature=original.content_signature,
        evidence=original.evidence,
    )

    evaluation = evaluate_r13(tuple(events))

    assert evaluation.invalid_timestamp_log_ids == (original.log_id,)
    assert evaluation.records_evaluated == 9
    assert evaluation.findings == ()


def test_window_left_boundary_is_exclusive() -> None:
    times = [_BASE_TIME] + [
        _BASE_TIME + timedelta(minutes=5) for _ in range(9)
    ]
    events = tuple(
        _event(index, timestamp=stamp, result=500)
        for index, stamp in enumerate(times)
    )

    assert evaluate_r13(events).findings == ()


def test_window_right_boundary_is_inclusive() -> None:
    times = [_BASE_TIME + timedelta(microseconds=1)] + [
        _BASE_TIME + timedelta(minutes=5) - timedelta(seconds=30 * index)
        for index in range(1, 9)
    ] + [_BASE_TIME + timedelta(minutes=5)]
    events = tuple(
        _event(index, timestamp=stamp, result=500)
        for index, stamp in enumerate(times)
    )

    assert len(evaluate_r13(events).findings) == 1


def test_equal_timestamps_are_processed_as_a_single_anchor_batch() -> None:
    events = tuple(
        _event(index, timestamp=_BASE_TIME, result=500)
        for index in range(10)
    )

    finding = _finding(events)

    assert finding.metrics.request_count == 10
    assert len(finding.evidence) == 10


def test_overlapping_qualified_windows_consolidate_by_ip() -> None:
    events = _events(20, result=500, interval=timedelta(seconds=10))

    evaluation = evaluate_r13(events)

    assert len(evaluation.findings) == 1
    evidence_ids = [item["Log_ID"] for item in evaluation.findings[0].evidence]
    assert len(evidence_ids) == len(set(evidence_ids)) == 20
    assert evidence_ids == [event.log_id for event in events]


def test_different_ips_never_mix_and_same_ip_evidence_is_sorted() -> None:
    first_ip = classify_ip("192.0.2.10")
    second_ip = classify_ip("192.0.2.11")
    first = tuple(
        _event(index, source_ip=first_ip, result=500) for index in range(10)
    )
    second = tuple(
        _event(index + 10, source_ip=second_ip, result=500) for index in range(10)
    )

    evaluation = evaluate_r13(tuple(reversed(first + second)))

    assert len(evaluation.findings) == 2
    for finding in evaluation.findings:
        evidence_keys = [
            (item["Timestamp"], item["Log_ID"]) for item in finding.evidence
        ]
        assert evidence_keys == sorted(evidence_keys)


def test_evaluation_is_deterministic_when_input_order_is_reversed() -> None:
    events = _events(20, result=500, interval=timedelta(seconds=10))

    assert evaluate_r13(events) == evaluate_r13(tuple(reversed(events)))


def test_equal_timestamp_batch_orders_evidence_by_log_id_deterministically() -> None:
    log_ids = tuple(f"EVT-{letter}" for letter in "JIHGFEDCBA")
    events = tuple(
        _event(
            index,
            log_id=log_id,
            timestamp=_BASE_TIME,
            result=500,
        )
        for index, log_id in enumerate(log_ids)
    )

    evaluation = evaluate_r13(events)
    reversed_evaluation = evaluate_r13(tuple(reversed(events)))

    assert len(evaluation.findings) == 1
    finding = evaluation.findings[0]
    assert finding.metrics.request_count == 10
    assert [item["Log_ID"] for item in finding.evidence] == sorted(log_ids)
    assert {item["Timestamp"] for item in finding.evidence} == {
        _BASE_TIME.isoformat()
    }
    assert evaluation == reversed_evaluation


@pytest.mark.parametrize(
    ("score", "expected"),
    [(7_000, 7_000), (7_500, 7_500), (8_000, 7_500), (None, None)],
)
def test_r13_score_cap_is_applied_when_materializing_observation(
    score: int | None, expected: int | None
) -> None:
    observation = _make_observation(
        "R13",
        "Enumeración web automatizada",
        (),
        "Fixture de scoring evaluable.",
        level=4,
        score_1e4=score,
        confidence_basis_points=7_400,
    )

    assert observation["score_1e4"] == expected
    assert observation["level"] == 1
    assert observation["confidence_basis_points"] == 7_400


def test_r13_confidence_cap_remains_independent_from_score_cap() -> None:
    observation = _make_observation(
        "R13",
        "Enumeración web automatizada",
        (),
        "Fixture de scoring evaluable.",
        score_1e4=8_000,
        confidence_basis_points=8_000,
    )

    assert observation["score_1e4"] == 7_500
    assert observation["confidence_basis_points"] == 7_500


def test_other_rules_do_not_receive_the_r13_score_cap() -> None:
    observation = _make_observation(
        "R12",
        "Proceso hijo de un servicio web",
        (),
        "Fixture de scoring evaluable.",
        score_1e4=8_000,
    )

    assert observation["score_1e4"] == 8_000


def test_r13_scoring_configuration_caps_level_at_l1() -> None:
    assessment = apply_object_caps("R13", 4, 7_400)

    assert assessment.level == 1
    assert assessment.confidence_basis_points == 7_400


def test_r13_score_cap_uses_min_without_imputing_null() -> None:
    assert cap_r13_score(8_000) == 7_500
    assert cap_r13_score(7_000) == 7_000
    assert cap_r13_score(None) is None
