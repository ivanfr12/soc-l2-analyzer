import pytest

from app.scoring import (
    apply_level_cap,
    apply_numeric_cap,
    apply_object_caps,
    calculate_c_score,
    calculate_evidence_score,
    calculate_quality_score,
    calculate_score,
    confidence_band,
)


def test_evidence_and_quality_scores_require_evaluable_inputs() -> None:
    assert calculate_evidence_score([]).status == "pending"
    assert calculate_evidence_score(["supported", "unsupported"]).value == 0.5
    assert (
        calculate_evidence_score(["supported", "not_evaluable"]).value is None
    )
    assert calculate_quality_score({"K1": "passed"}).value is None
    assert calculate_quality_score(
        {
            "K1": "passed",
            "K2": "failed",
            "K3": "passed",
            "K4": "passed",
            "K5": "passed",
        }
    ).value == 0.8
    assert calculate_quality_score(
        {
            "K1": "passed",
            "K2": "failed",
            "K3": "passed",
            "K4": "not_evaluable",
            "K5": "passed",
        }
    ).value is None


@pytest.mark.parametrize(
    ("domains", "aspects", "expected"),
    [
        (1, 1, 0.30),
        (1, 2, 0.50),
        (1, 4, 0.50),
        (2, 1, 0.65),
        (3, 1, 1.00),
    ],
)
def test_corroboration_values(domains: int, aspects: int, expected: float) -> None:
    assert calculate_c_score(domains, aspects) == expected


def test_score_formula_and_non_evaluable_components() -> None:
    assert calculate_score(1.0, 0.30, 1.0) == 7_900
    assert calculate_score(None, 0.30, 1.0) is None
    assert calculate_score(1.0, 0.30, None) is None


def test_caps_use_min_and_confidence_bands_are_inclusive() -> None:
    assert apply_numeric_cap(8_000, 7_500) == 7_500
    assert apply_numeric_cap(7_000, None) == 7_000
    assert apply_level_cap(3, 1) == 1
    assert [confidence_band(value) for value in (7_000, 5_000, 2_500, 2_499)] == [
        "High",
        "Medium",
        "Low",
        "Info",
    ]


def test_ratified_object_caps_and_c2_pending_status() -> None:
    assert apply_object_caps("R06", 4, 9_000).level == 3
    assert apply_object_caps("R06", 4, 9_000).confidence_basis_points == 8_500
    assert apply_object_caps("R08", 4, 9_000).level == 4
    assert apply_object_caps("R08", 4, 9_000).confidence_basis_points == 9_000
    pending = apply_object_caps("C2", 3, 8_000)
    assert pending.status == "pending_reconciliation"
    assert pending.level is None
    assert pending.confidence_basis_points is None
