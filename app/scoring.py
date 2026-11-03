from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Sequence

EvidenceState = Literal["supported", "unsupported", "not_evaluable"]
QualityState = Literal["passed", "failed", "not_evaluable"]
EvidenceStatus = Literal["ready", "pending", "not_evaluable"]
QualityStatus = Literal["ready", "not_evaluable"]
ConfidenceBand = Literal["High", "Medium", "Low", "Info"]

K_CONTROL_IDS = ("K1", "K2", "K3", "K4", "K5")
LEVEL_CAPS = {
    "R01": 1,
    "R02": 2,
    "R03": 1,
    "R04": 0,
    "R05": 1,
    "R06": 3,
    "R07": 1,
    "R08": None,
    "R09": 1,
    "R10": 1,
    "R11": 3,
    "R12": 1,
    "R13": 1,
    "C1": 2,
    "C2": None,
    "C3": 2,
    "C4": 1,
    "C5": 3,
    "C6": 1,
}
CONFIDENCE_CAPS = {
    "R01": 7_500,
    "R02": 7_800,
    "R03": 7_500,
    "R04": 5_500,
    "R05": 7_500,
    "R06": 8_500,
    "R07": 7_500,
    "R08": None,
    "R09": 7_500,
    "R10": 7_500,
    "R11": 8_500,
    "R12": 7_500,
    "R13": 7_500,
    "C1": 7_800,
    "C2": None,
    "C3": 7_800,
    "C4": 7_500,
    "C5": 8_500,
    "C6": 7_500,
}


@dataclass(frozen=True)
class ComponentScore:
    value: float | None
    status: EvidenceStatus | QualityStatus


@dataclass(frozen=True)
class CappedAssessment:
    level: int | None
    confidence_basis_points: int | None
    status: Literal["capped", "pending_reconciliation"]


def calculate_evidence_score(states: Sequence[EvidenceState]) -> ComponentScore:
    if not states:
        return ComponentScore(value=None, status="pending")
    if "not_evaluable" in states:
        return ComponentScore(value=None, status="not_evaluable")
    if any(state not in ("supported", "unsupported") for state in states):
        raise ValueError("Estado E no reconocido.")
    return ComponentScore(
        value=sum(state == "supported" for state in states) / len(states),
        status="ready",
    )


def calculate_quality_score(controls: dict[str, QualityState]) -> ComponentScore:
    if set(controls) != set(K_CONTROL_IDS):
        return ComponentScore(value=None, status="not_evaluable")
    states = tuple(controls[control_id] for control_id in K_CONTROL_IDS)
    if "not_evaluable" in states:
        return ComponentScore(value=None, status="not_evaluable")
    if any(state not in ("passed", "failed") for state in states):
        raise ValueError("Estado K no reconocido.")
    return ComponentScore(
        value=sum(state == "passed" for state in states) / len(K_CONTROL_IDS),
        status="ready",
    )


def calculate_c_score(domain_count: int, aspect_count: int) -> float | None:
    if domain_count < 1 or aspect_count < 1:
        return None
    if domain_count == 1:
        return 0.30 if aspect_count == 1 else 0.50
    if domain_count == 2:
        return 0.65
    return 1.00


def calculate_score(
    evidence: float | None,
    corroboration: float | None,
    quality: float | None,
) -> int | None:
    if evidence is None or quality is None or corroboration is None:
        return None
    if any(not 0.0 <= value <= 1.0 for value in (evidence, corroboration, quality)):
        raise ValueError("E, C y K deben estar entre 0 y 1.")

    raw_score = 0.15 + 0.35 * evidence + 0.30 * corroboration + 0.20 * quality
    return round(raw_score * 10_000)


def apply_numeric_cap(value: int, cap: int | None) -> int:
    return value if cap is None else min(value, cap)


def apply_level_cap(level: int, cap: int | None) -> int:
    if not 0 <= level <= 4 or (cap is not None and not 0 <= cap <= 4):
        raise ValueError("El nivel y su tope deben estar entre L0 y L4.")
    return level if cap is None else min(level, cap)


def apply_object_caps(
    object_id: str, level: int | None, confidence_basis_points: int | None
) -> CappedAssessment:
    if object_id not in LEVEL_CAPS:
        raise ValueError(f"No hay topes ratificados para {object_id}.")
    if object_id == "C2":
        return CappedAssessment(
            level=None,
            confidence_basis_points=None,
            status="pending_reconciliation",
        )

    level_cap = LEVEL_CAPS[object_id]
    confidence_cap = CONFIDENCE_CAPS[object_id]
    return CappedAssessment(
        level=(
            None if level is None else apply_level_cap(level, level_cap)
        ),
        confidence_basis_points=(
            None
            if confidence_basis_points is None
            else apply_numeric_cap(confidence_basis_points, confidence_cap)
        ),
        status="capped",
    )


def confidence_band(basis_points: int) -> ConfidenceBand:
    if not 0 <= basis_points <= 10_000:
        raise ValueError("Confidence debe estar entre 0 y 10000 basis points.")
    if basis_points >= 7_000:
        return "High"
    if basis_points >= 5_000:
        return "Medium"
    if basis_points >= 2_500:
        return "Low"
    return "Info"
