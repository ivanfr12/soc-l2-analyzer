from __future__ import annotations

import ipaddress
import re
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from io import BytesIO
from typing import Any, Literal

from openpyxl import load_workbook

from app.config import (
    ANALYSIS_SCHEMA_VERSION,
    CANON_VERSION,
    REQUIRED_COLUMNS,
    REQUIRED_SHEET,
)
from app.excel import XLSX_CONTENT_ERRORS, WorkbookValidationError, inspect_workbook
from app.hashes import file_sha256
from app.ip_classification import (
    IPClassification,
    classify_ip,
    registry_validation_status,
)
from app.r07 import R07Event, evaluate_r07
from app.r08 import R08Event, evaluate_r08
from app.r09 import (
    ProxyBytesOutObservation,
    R09Event,
    evaluate_r09,
    observe_proxy_bytes_out,
)
from app.r13 import R13Event, cap_r13_score, evaluate_r13
from app.scoring import apply_object_caps

RuleStatus = Literal[
    "executed", "partially_executed", "pending", "not_evaluable"
]


@dataclass(frozen=True)
class SIEMRecord:
    log_id: str | None
    timestamp: datetime | None
    hostname: str | None
    event_id: str | None
    user: str | None
    source_ip: IPClassification
    destination: str | None
    log_source: str | None
    event_description: str | None
    process_command_line: str | None
    result: str | None
    severity: str | None
    proxy_bytes_out: ProxyBytesOutObservation | None = None


@dataclass(frozen=True)
class IngestIssue:
    log_id: str | None
    code: str


@dataclass(frozen=True)
class IngestedWorkbook:
    records: tuple[SIEMRecord, ...]
    issues: tuple[IngestIssue, ...]
    records_seen: int
    r01_candidates: tuple[SIEMRecord, ...]
    r01_records_in_scope: int
    r01_conflicting_log_ids: tuple[str, ...]
    dataset_start: datetime | None
    has_invalid_timestamp: bool
    r07_events: tuple[R07Event, ...]
    r07_records_in_scope: int
    r07_conflicting_log_ids: tuple[str, ...]
    r08_events: tuple[R08Event, ...]
    r08_records_in_scope: int
    r08_conflicting_log_ids: tuple[str, ...]
    r09_events: tuple[R09Event, ...]
    r09_records_in_scope: int
    r09_conflicting_log_ids: tuple[str, ...]
    r13_events: tuple[R13Event, ...]
    r13_records_in_scope: int
    r13_conflicting_log_ids: tuple[str, ...]


_REQUIRED_NON_NULL = (
    "Log_ID",
    "Timestamp",
    "Hostname",
    "Event_ID",
    "User",
    "Source_IP",
    "Log_Source",
    "Event_Description",
    "Result",
    "Severity",
)
_RULE_NAMES = {
    "R01": "Rociado de credenciales",
    "R02": "Logon exitoso posterior a fallos",
    "R03": "Logon desde IP externa",
    "R04": "RDP desde IP externa",
    "R05": "PowerShell ofuscado",
    "R06": "Comandos de reconocimiento",
    "R07": "Lectura masiva de archivos en un share",
    "R08": "Herramienta de archivado hacia ruta temporal/pública",
    "R09": "Transferencia saliente volumétrica",
    "R10": "Eliminación de shadow copies",
    "R11": "Persistencia vía tarea programada o servicio",
    "R12": "Proceso hijo de un servicio web",
    "R13": "Enumeración web automatizada",
}
_PENDING_RULE_REASONS: dict[str, str] = {}
_WINDOW_SECONDS = {
    "R02": 15 * 60,
}
_R01_WINDOW = timedelta(minutes=10)
_RULE_EVENT_IDS = {
    "R01": ("4625",),
    "R02": ("4624", "4625"),
    "R03": ("4624",),
    "R04": ("4624",),
    "R05": ("4688",),
    "R06": ("4688", "4104"),
    "R07": ("4663",),
    "R08": ("4688",),
    "R09": ("PROXY_ACCESS",),
    "R10": ("4688",),
    "R11": ("4698", "7045"),
    "R12": ("4688",),
    "R13": ("HTTP_ACCESS",),
}
_PATH_INDICATORS = (
    r"c:\programdata",
    r"c:\temp",
    r"c:\users\public",
    r"%appdata%",
)
_PATH_INDICATOR_PATTERNS = tuple(
    re.compile(
        r"(?<![\w.-])"
        + re.escape(indicator).replace(r"\\", r"[\\/]")
        + r"(?=$|[\\/]|[\s\"'`,;)\]}])",
        re.IGNORECASE,
    )
    for indicator in _PATH_INDICATORS
)
_RECOGNITION_PATTERNS = (
    re.compile(r"(?<![\w.-])net(?:\.exe)?\s+view(?![\w.-])"),
    re.compile(r"(?<![\w.-])get-smbshare(?![\w.-])"),
    re.compile(r"(?<![\w.-])get-localgroupmember(?![\w.-])"),
    re.compile(r"(?<![\w.-])whoami(?:\.exe)?(?![\w.-])"),
    re.compile(r"(?<![\w.-])net(?:\.exe)?\s+group(?![\w.-])"),
)


def _text(value: object) -> str | None:
    if value is None:
        return None
    return str(value)


def _event_id(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value).strip()


def _timestamp(value: object) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.strip())
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is not None and parsed.utcoffset() is not None:
        return None
    return parsed


def _row_content_signature(
    row: tuple[Any, ...], width: int
) -> tuple[tuple[type, Any], ...]:
    values = row[:width] + (None,) * max(0, width - len(row))
    return tuple((type(value), value) for value in values)


def ingest_workbook(content: bytes) -> IngestedWorkbook:
    inspect_workbook(content)
    try:
        workbook = load_workbook(BytesIO(content), read_only=True, data_only=True)
    except XLSX_CONTENT_ERRORS as exc:
        raise WorkbookValidationError(
            "corrupt_xlsx", "No se pudo leer el contenido interno del XLSX."
        ) from exc
    records: list[SIEMRecord] = []
    issues: list[IngestIssue] = []
    r01_candidates: list[SIEMRecord] = []
    r01_records_in_scope = 0
    r01_ids_in_scope: set[str] = set()
    content_by_log_id: dict[str, list[tuple[tuple[type, Any], ...]]] = {}
    r07_events: list[R07Event] = []
    r07_records_in_scope = 0
    r07_ids_in_scope: set[str] = set()
    r08_events: list[R08Event] = []
    r08_records_in_scope = 0
    r08_ids_in_scope: set[str] = set()
    r09_events: list[R09Event] = []
    r09_records_in_scope = 0
    r09_ids_in_scope: set[str] = set()
    r13_events: list[R13Event] = []
    r13_records_in_scope = 0
    r13_ids_in_scope: set[str] = set()
    timestamps: list[datetime] = []
    has_invalid_timestamp = False
    records_seen = 0
    try:
        worksheet = workbook[REQUIRED_SHEET]
        rows = worksheet.iter_rows(values_only=True)
        headers = next(rows)
        indexes = {value: index for index, value in enumerate(headers)}
        for row in rows:
            if not any(value is not None for value in row):
                continue
            records_seen += 1
            row_signature = _row_content_signature(row, len(headers))
            values = {
                column: row[indexes[column]] if indexes[column] < len(row) else None
                for column in REQUIRED_COLUMNS
            }
            log_id = _text(values["Log_ID"])
            if log_id is not None and log_id.strip():
                signatures = content_by_log_id.setdefault(log_id, [])
                if row_signature not in signatures:
                    signatures.append(row_signature)
            missing = [
                column
                for column in _REQUIRED_NON_NULL
                if values[column] is None
                or (isinstance(values[column], str) and not values[column].strip())
            ]
            event_id = _event_id(values["Event_ID"])
            if event_id == "PROXY_ACCESS":
                r09_records_in_scope += 1
                if log_id is not None and log_id.strip():
                    r09_ids_in_scope.add(log_id)
            if event_id == "HTTP_ACCESS":
                r13_records_in_scope += 1
                if log_id is not None and log_id.strip():
                    r13_ids_in_scope.add(log_id)
            if event_id == "4663":
                r07_records_in_scope += 1
                if log_id is not None and log_id.strip():
                    r07_ids_in_scope.add(log_id)
            if event_id == "4688":
                r08_records_in_scope += 1
                if log_id is not None and log_id.strip():
                    r08_ids_in_scope.add(log_id)
            if event_id == "4625":
                r01_records_in_scope += 1
                if log_id is not None and log_id.strip():
                    r01_ids_in_scope.add(log_id)
            timestamp = _timestamp(values["Timestamp"])
            if timestamp is not None:
                timestamps.append(timestamp)
            else:
                has_invalid_timestamp = True
            if timestamp is None and "Timestamp" not in missing:
                issues.append(IngestIssue(log_id, "invalid_timestamp"))

            hostname = _text(values["Hostname"])
            source_ip = classify_ip(values["Source_IP"])
            process_command_line = _text(values["Process_CommandLine"])
            proxy_bytes_out = (
                observe_proxy_bytes_out(process_command_line)
                if event_id == "PROXY_ACCESS"
                else None
            )
            record = SIEMRecord(
                log_id=log_id,
                timestamp=timestamp,
                hostname=hostname,
                event_id=event_id,
                user=_text(values["User"]),
                source_ip=source_ip,
                destination=_text(values["Destination"]),
                log_source=_text(values["Log_Source"]),
                event_description=_text(values["Event_Description"]),
                process_command_line=process_command_line,
                result=_text(values["Result"]),
                severity=_text(values["Severity"]),
                proxy_bytes_out=proxy_bytes_out,
            )
            if event_id == "4663":
                r07_events.append(
                    R07Event(
                        log_id=log_id,
                        timestamp=timestamp,
                        user=values["User"],
                        hostname=values["Hostname"],
                        destination=values["Destination"],
                        process_command_line=values["Process_CommandLine"],
                        content_signature=row_signature,
                        evidence=_event_reference(record),
                    )
                )
            if event_id == "4688":
                r08_events.append(
                    R08Event(
                        log_id=log_id,
                        timestamp=timestamp,
                        hostname=values["Hostname"],
                        user=values["User"],
                        process_command_line=values["Process_CommandLine"],
                        event_id=event_id,
                        content_signature=row_signature,
                        evidence=_event_reference(record),
                    )
                )
            if event_id == "PROXY_ACCESS":
                r09_events.append(
                    R09Event(
                        log_id=log_id,
                        timestamp=timestamp,
                        hostname=values["Hostname"],
                        user=values["User"],
                        destination=values["Destination"],
                        bytes_out=proxy_bytes_out,
                        content_signature=row_signature,
                        evidence=_event_reference(record),
                    )
                )
            if event_id == "HTTP_ACCESS":
                r13_events.append(
                    R13Event(
                        log_id=values["Log_ID"],
                        timestamp=timestamp,
                        source_ip=source_ip,
                        uri=values["Process_CommandLine"],
                        result=values["Result"],
                        content_signature=row_signature,
                        evidence=_event_reference(record),
                    )
                )
            if timestamp is None:
                continue
            if event_id == "4625":
                if (
                    timestamp is not None
                    and hostname is not None
                    and hostname.strip()
                    and source_ip.category not in ("missing", "invalid")
                    and log_id is not None
                    and log_id.strip()
                ):
                    r01_candidates.append(record)

            if missing:
                issues.extend(IngestIssue(log_id, f"missing_{column}") for column in missing)
                continue

            records.append(record)
    except XLSX_CONTENT_ERRORS as exc:
        raise WorkbookValidationError(
            "corrupt_xlsx", "No se pudo leer el contenido interno del XLSX."
        ) from exc
    finally:
        workbook.close()
    all_conflicting_log_ids = tuple(
        sorted(
            log_id
            for log_id, signatures in content_by_log_id.items()
            if len(signatures) > 1
        )
    )
    conflicting_log_ids = tuple(
        sorted(set(all_conflicting_log_ids).intersection(r01_ids_in_scope))
    )
    r09_conflicting_log_ids = tuple(
        sorted(set(all_conflicting_log_ids).intersection(r09_ids_in_scope))
    )
    r07_conflicting_log_ids = tuple(
        sorted(set(all_conflicting_log_ids).intersection(r07_ids_in_scope))
    )
    r08_conflicting_log_ids = tuple(
        sorted(set(all_conflicting_log_ids).intersection(r08_ids_in_scope))
    )
    r13_conflicting_log_ids = tuple(
        sorted(set(all_conflicting_log_ids).intersection(r13_ids_in_scope))
    )
    conflicts = set(conflicting_log_ids)
    unique_candidates: dict[str, SIEMRecord] = {}
    for candidate in r01_candidates:
        candidate_id = candidate.log_id
        if candidate_id is not None and candidate_id not in conflicts:
            unique_candidates.setdefault(candidate_id, candidate)
    return IngestedWorkbook(
        records=tuple(records),
        issues=tuple(issues),
        records_seen=records_seen,
        r01_candidates=tuple(unique_candidates.values()),
        r01_records_in_scope=r01_records_in_scope,
        r01_conflicting_log_ids=conflicting_log_ids,
        dataset_start=min(timestamps) if timestamps else None,
        has_invalid_timestamp=has_invalid_timestamp,
        r07_events=tuple(r07_events),
        r07_records_in_scope=r07_records_in_scope,
        r07_conflicting_log_ids=r07_conflicting_log_ids,
        r08_events=tuple(r08_events),
        r08_records_in_scope=r08_records_in_scope,
        r08_conflicting_log_ids=r08_conflicting_log_ids,
        r09_events=tuple(r09_events),
        r09_records_in_scope=r09_records_in_scope,
        r09_conflicting_log_ids=r09_conflicting_log_ids,
        r13_events=tuple(r13_events),
        r13_records_in_scope=r13_records_in_scope,
        r13_conflicting_log_ids=r13_conflicting_log_ids,
    )


def _event_reference(record: SIEMRecord) -> dict[str, Any]:
    return {
        "Log_ID": record.log_id,
        "Timestamp": record.timestamp.isoformat() if record.timestamp else None,
        "Hostname": record.hostname,
        "Event_ID": record.event_id,
        "User": record.user,
        "Source_IP": record.source_ip.value,
        "source_ip_category": record.source_ip.category,
        "ip_classification_source": record.source_ip.source,
        "ip_registry_validation_status": record.source_ip.registry_validation_status,
    }


def _point_rule_matches(record: SIEMRecord) -> tuple[tuple[str, str], ...]:
    command = (record.process_command_line or "").casefold()
    description = (record.event_description or "").casefold()
    matches: list[tuple[str, str]] = []

    if record.event_id == "4624" and record.source_ip.category in (
        "documentation",
        "public",
    ):
        matches.append(
            ("R03", "Observación de autenticación con IP documentation/public.")
        )

    if (
        record.event_id == "4624"
        and re.search(r"\blogontype\s*=\s*10\b", description)
        and record.source_ip.category in ("documentation", "public")
    ):
        matches.append(
            ("R04", "Observación de logon tipo RDP con IP documentation/public.")
        )

    if record.event_id == "4688" and any(
        indicator in command
        for indicator in (
            "-encodedcommand",
            "-enc ",
            "-noprofile",
            "frombase64string",
        )
    ):
        matches.append(
            ("R05", "El comando contiene un indicador documentado de PowerShell.")
        )

    recognition_text = f"{command} {description}"
    if record.event_id in ("4688", "4104") and any(
        pattern.search(recognition_text) for pattern in _RECOGNITION_PATTERNS
    ):
        matches.append(
            (
                "R06",
                "El texto del registro coincide con un indicador de R06; "
                "esto no demuestra ejecución exitosa ni intención.",
            )
        )

    if record.event_id == "4688" and (
        (
            "vssadmin" in command
            and "delete" in command
            and "shadows" in command
        )
        or (
            "wmic" in command
            and "shadowcopy" in command
            and "delete" in command
        )
        or (
            "bcdedit" in command
            and re.search(r"\brecoveryenabled\s+no(?:\s|$)", command)
        )
    ):
        matches.append(
            ("R10", "El comando coincide con una condición documentada de R10.")
        )

    if record.event_id in ("4698", "7045") and any(
        pattern.search(record.process_command_line or "")
        for pattern in _PATH_INDICATOR_PATTERNS
    ):
        matches.append(
            (
                "R11",
                "El registro incluye una ruta catalogada por R11; "
                "esto no acredita ejecución ni persistencia.",
            )
        )

    is_web_service_user = (record.user or "").casefold().startswith("iis apppool\\")
    has_web_parent = "parent=w3wp.exe" in description
    has_command = re.search(
        r"(?<![a-z0-9_])(?:cmd\.exe|powershell\.exe|whoami(?:\.exe)?|net\.exe)"
        r"(?![a-z0-9_.])",
        command,
    ) is not None
    if record.event_id == "4688" and has_command and (
        is_web_service_user or has_web_parent
    ):
        matches.append(
            ("R12", "Proceso observado con identidad/padre de servicio web.")
        )

    return tuple(matches)


def _evaluate_r01(
    candidates: tuple[SIEMRecord, ...],
    dataset_start: datetime | None,
    has_invalid_timestamp: bool,
    conflicting_log_ids: tuple[str, ...],
) -> tuple[list[dict[str, Any]], str | None]:
    grouped: dict[tuple[str, str], list[SIEMRecord]] = {}
    for candidate in candidates:
        if (
            candidate.timestamp is None
            or candidate.hostname is None
            or candidate.source_ip.value is None
        ):
            continue
        address = str(ipaddress.ip_address(candidate.source_ip.value))
        grouped.setdefault((address, candidate.hostname), []).append(candidate)

    observations: list[dict[str, Any]] = []
    for key in sorted(grouped):
        events = sorted(
            grouped[key],
            key=lambda record: (record.timestamp, record.log_id or ""),
        )
        timestamps = [record.timestamp for record in events]
        left = 0
        right = 0
        user_counts: Counter[str] = Counter()
        evidence_by_id: dict[str, SIEMRecord] = {}
        has_partial_coverage = False

        for anchor in sorted(set(timestamps)):
            while right < len(events) and timestamps[right] <= anchor:
                user = events[right].user
                if user is not None and user.strip():
                    user_counts[user] += 1
                right += 1

            cutoff = anchor - _R01_WINDOW
            while left < right and timestamps[left] <= cutoff:
                user = events[left].user
                if user is not None and user.strip():
                    user_counts[user] -= 1
                    if user_counts[user] == 0:
                        del user_counts[user]
                left += 1

            if right - left < 5 or len(user_counts) < 3:
                continue

            for record in events[left:right]:
                if record.log_id is not None:
                    evidence_by_id[record.log_id] = record
            if dataset_start is not None and cutoff < dataset_start:
                has_partial_coverage = True

        if not evidence_by_id:
            continue

        evidence = tuple(
            sorted(
                evidence_by_id.values(),
                key=lambda record: (record.timestamp, record.log_id or ""),
            )
        )
        description = (
            "Se observaron al menos cinco eventos 4625 y tres usuarios "
            "identificables de la misma IP y hostname en ventanas deslizantes "
            "de 10 minutos consolidadas. La secuencia es compatible con fuerza "
            "bruta; no demuestra autenticación exitosa, compromiso ni atribución."
        )
        if has_partial_coverage:
            description += (
                " Existe cobertura inicial parcial en las ventanas detectadas; "
                "no se infiere actividad fuera del workbook."
        )
        if has_invalid_timestamp:
            description += (
                " La cobertura temporal inicial no puede determinarse por "
                "completo porque hay timestamps ausentes o inválidos."
            )
        observations.append(
            _make_observation(
                "R01",
                _RULE_NAMES["R01"],
                evidence,
                description,
            )
        )

    reason_parts: list[str] = []
    if conflicting_log_ids:
        reason_parts.append(
            "R01 excluyó Log_ID con conflicto de identidad: "
            + ", ".join(conflicting_log_ids)
            + "."
        )
    if dataset_start is not None and any(
        candidate.timestamp is not None
        and candidate.timestamp - _R01_WINDOW < dataset_start
        for candidate in candidates
    ):
        reason_parts.append(
            "Algunas ventanas evaluadas por R01 tienen cobertura inicial parcial "
            "respecto del primer "
            "timestamp válido del dataset; no se infiere actividad fuera del workbook."
        )
    if has_invalid_timestamp:
        reason_parts.append(
            "La cobertura temporal inicial no puede determinarse por completo "
            "porque hay timestamps ausentes o inválidos."
        )
    return observations, " ".join(reason_parts) or None


def _rule_statuses() -> dict[str, dict[str, Any]]:
    rules: dict[str, dict[str, Any]] = {}
    for rule_id, name in _RULE_NAMES.items():
        if rule_id in _PENDING_RULE_REASONS:
            status: RuleStatus = "pending"
            reason = _PENDING_RULE_REASONS[rule_id]
        elif rule_id in (
            "R01",
            "R02",
            "R03",
            "R04",
            "R05",
            "R06",
            "R07",
            "R08",
            "R09",
            "R11",
            "R10",
            "R12",
            "R13",
        ):
            status = "executed"
            reason = None
        else:
            status = "partially_executed"
            reason = (
                "Se evalúa la condición puntual documentada; la agrupación temporal "
                "y la evaluación de periodicidad no se infieren."
            )
        rules[rule_id] = {
            "name": name,
            "status": status,
            "matched_observation_count": 0,
            "records_in_scope": 0,
            "records_evaluated": 0,
            "reason": reason,
        }
    return rules


def _make_observation(
    rule_id: str,
    rule_name: str,
    records: tuple[SIEMRecord, ...],
    reason: str,
    *,
    evidence: tuple[dict[str, Any], ...] | None = None,
    level: int | None = None,
    score_1e4: int | None = None,
    confidence_basis_points: int | None = None,
) -> dict[str, Any]:
    severities: dict[str, str] = {"R03": "Low", "R11": "Medium"}
    severity = severities.get(rule_id)
    assessment = apply_object_caps(rule_id, level, confidence_basis_points)
    return {
        "rule_id": rule_id,
        "rule_name": rule_name,
        "observation_type": "deterministic_rule_match",
        "description": reason,
        "evidence": (
            list(evidence)
            if evidence is not None
            else [_event_reference(record) for record in records]
        ),
        "impact_demonstrated": False,
        "incident_attribution": False,
        "severity": severity,
        "severity_status": "ratified" if severity is not None else "not_defined",
        "level": assessment.level,
        "level_status": (
            "capped" if level is not None else "not_evaluable_in_partial_contract"
        ),
        "score_1e4": (
            cap_r13_score(score_1e4) if rule_id == "R13" else score_1e4
        ),
        "confidence_basis_points": assessment.confidence_basis_points,
        "confidence_status": (
            "capped"
            if confidence_basis_points is not None
            else "not_evaluable_without_E_K_catalogs"
        ),
    }


def _evaluate_rules(
    records: tuple[SIEMRecord, ...],
    r01_candidates: tuple[R01Candidate, ...],
    r01_records_in_scope: int,
    dataset_start: datetime | None,
    has_invalid_timestamp: bool,
    r01_conflicting_log_ids: tuple[str, ...],
    r07_events: tuple[R07Event, ...],
    r07_records_in_scope: int,
    r07_conflicting_log_ids: tuple[str, ...],
    r08_events: tuple[R08Event, ...],
    r08_records_in_scope: int,
    r08_conflicting_log_ids: tuple[str, ...],
    r09_events: tuple[R09Event, ...],
    r09_records_in_scope: int,
    r09_conflicting_log_ids: tuple[str, ...],
    r13_events: tuple[R13Event, ...],
    r13_records_in_scope: int,
    r13_conflicting_log_ids: tuple[str, ...],
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    rules = _rule_statuses()
    for rule_id, rule in rules.items():
        event_ids = _RULE_EVENT_IDS[rule_id]
        rule["records_in_scope"] = sum(
            record.event_id in event_ids for record in records
        )
        if rule["status"] in ("executed", "partially_executed"):
            rule["records_evaluated"] = rule["records_in_scope"]

    r01_observations, r01_reason = _evaluate_r01(
        r01_candidates,
        dataset_start,
        has_invalid_timestamp,
        r01_conflicting_log_ids,
    )
    rules["R01"]["records_in_scope"] = r01_records_in_scope
    rules["R01"]["records_evaluated"] = len(r01_candidates)
    rules["R01"]["matched_observation_count"] = len(r01_observations)
    rules["R01"]["reason"] = r01_reason
    r07_evaluation = evaluate_r07(
        r07_events,
        externally_conflicting_log_ids=r07_conflicting_log_ids,
    )
    rules["R07"]["records_in_scope"] = r07_records_in_scope
    rules["R07"]["records_evaluated"] = r07_evaluation.records_evaluated
    rules["R07"]["matched_observation_count"] = len(r07_evaluation.findings)
    r07_reason_parts: list[str] = []
    if r07_evaluation.identical_duplicates_collapsed:
        r07_reason_parts.append(
            f"Se deduplicaron {r07_evaluation.identical_duplicates_collapsed} "
            "filas idénticas por Log_ID."
        )
    if r07_evaluation.conflicting_log_ids:
        r07_reason_parts.append(
            f"Se excluyeron {r07_evaluation.conflicting_record_count} versiones "
            "de Log_ID conflictivos: "
            + ", ".join(r07_evaluation.conflicting_log_ids)
            + "."
        )
    if r07_evaluation.missing_log_id_count:
        r07_reason_parts.append(
            f"Se excluyeron {r07_evaluation.missing_log_id_count} registros sin Log_ID."
        )
    if r07_evaluation.invalid_timestamp_log_ids:
        r07_reason_parts.append(
            "Se excluyeron registros con timestamp ausente o inválido: "
            + ", ".join(r07_evaluation.invalid_timestamp_log_ids)
            + "."
        )
    if r07_evaluation.incomplete_key_log_ids:
        r07_reason_parts.append(
            "Se excluyeron registros con clave incompleta o inválida: "
            + ", ".join(r07_evaluation.incomplete_key_log_ids)
            + "."
        )
    rules["R07"]["reason"] = " ".join(r07_reason_parts) or None
    r09_evaluation = evaluate_r09(
        r09_events,
        externally_conflicting_log_ids=r09_conflicting_log_ids,
    )
    rules["R09"]["records_in_scope"] = r09_records_in_scope
    rules["R09"]["records_evaluated"] = r09_evaluation.records_evaluated
    rules["R09"]["matched_observation_count"] = len(r09_evaluation.findings)
    r09_reason_parts: list[str] = []
    if r09_evaluation.identical_duplicates_collapsed:
        r09_reason_parts.append(
            f"Se deduplicaron {r09_evaluation.identical_duplicates_collapsed} "
            "filas idénticas por Log_ID."
        )
    if r09_evaluation.conflicting_log_ids:
        r09_reason_parts.append(
            f"Se excluyeron {r09_evaluation.conflicting_record_count} versiones "
            "de Log_ID conflictivos: "
            + ", ".join(r09_evaluation.conflicting_log_ids)
            + "."
        )
    if r09_evaluation.missing_log_id_count:
        r09_reason_parts.append(
            f"Se excluyeron {r09_evaluation.missing_log_id_count} registros sin Log_ID."
        )
    if r09_evaluation.invalid_timestamp_log_ids:
        r09_reason_parts.append(
            "Se excluyeron registros con timestamp ausente o inválido: "
            + ", ".join(r09_evaluation.invalid_timestamp_log_ids)
            + "."
        )
    if r09_evaluation.incomplete_key_log_ids:
        r09_reason_parts.append(
            "Se excluyeron registros con clave incompleta o inválida: "
            + ", ".join(r09_evaluation.incomplete_key_log_ids)
            + "."
        )
    rules["R09"]["reason"] = " ".join(r09_reason_parts) or None
    r13_evaluation = evaluate_r13(
        r13_events,
        externally_conflicting_log_ids=r13_conflicting_log_ids,
    )
    rules["R13"]["status"] = "executed"
    rules["R13"]["records_in_scope"] = r13_records_in_scope
    rules["R13"]["records_evaluated"] = r13_evaluation.records_evaluated
    rules["R13"]["matched_observation_count"] = len(r13_evaluation.findings)
    r13_reason_parts: list[str] = []
    if r13_evaluation.identical_duplicates_collapsed:
        r13_reason_parts.append(
            f"Se deduplicaron {r13_evaluation.identical_duplicates_collapsed} "
            "filas idénticas por Log_ID."
        )
    if r13_evaluation.conflicting_log_ids:
        r13_reason_parts.append(
            f"Se excluyeron {r13_evaluation.conflicting_record_count} versiones "
            "de Log_ID conflictivos: "
            + ", ".join(r13_evaluation.conflicting_log_ids)
            + "."
        )
    if r13_evaluation.invalid_log_id_count:
        r13_reason_parts.append(
            f"Se excluyeron {r13_evaluation.invalid_log_id_count} registros con "
            "Log_ID ausente, vacío o no textual."
        )
    if r13_evaluation.invalid_timestamp_log_ids:
        r13_reason_parts.append(
            "Se excluyeron de las ventanas registros con timestamp ausente o "
            "inválido: "
            + ", ".join(r13_evaluation.invalid_timestamp_log_ids)
            + "."
        )
    if r13_evaluation.invalid_ip_log_ids:
        r13_reason_parts.append(
            "Se excluyeron de las ventanas registros con Source_IP ausente o "
            "inválida: "
            + ", ".join(r13_evaluation.invalid_ip_log_ids)
            + "."
        )
    rules["R13"]["reason"] = " ".join(r13_reason_parts) or None
    r08_evaluation = evaluate_r08(
        r08_events,
        r07_evidence=tuple(
            evidence for finding in r07_evaluation.findings for evidence in finding.evidence
        ),
        r09_evidence=tuple(
            evidence for finding in r09_evaluation.findings for evidence in finding.evidence
        ),
        externally_conflicting_log_ids=r08_conflicting_log_ids,
    )
    rules["R08"]["records_in_scope"] = r08_records_in_scope
    rules["R08"]["records_evaluated"] = r08_evaluation.records_evaluated
    rules["R08"]["matched_observation_count"] = len(r08_evaluation.findings)
    r08_reason_parts: list[str] = []
    if r08_evaluation.identical_duplicates_collapsed:
        r08_reason_parts.append(
            f"Se deduplicaron {r08_evaluation.identical_duplicates_collapsed} "
            "filas idénticas por Log_ID."
        )
    if r08_evaluation.conflicting_log_ids:
        r08_reason_parts.append(
            f"Se excluyeron {r08_evaluation.conflicting_record_count} versiones "
            "de Log_ID conflictivos: "
            + ", ".join(r08_evaluation.conflicting_log_ids)
            + "."
        )
    if r08_evaluation.missing_log_id_count:
        r08_reason_parts.append(
            f"Se excluyeron {r08_evaluation.missing_log_id_count} registros sin Log_ID."
        )
    for label, log_ids in (
        ("timestamp ausente o inválido", r08_evaluation.invalid_timestamp_log_ids),
        ("Hostname/User ausente o inválido", r08_evaluation.incomplete_identity_log_ids),
        ("Process_CommandLine ausente o no textual", r08_evaluation.invalid_command_log_ids),
        ("herramienta no ratificada", r08_evaluation.unsupported_command_log_ids),
        ("herramienta/salida no identificable o ruta fuera del alcance", r08_evaluation.invalid_output_path_log_ids),
        ("sin evidencia R08 consistente", r08_evaluation.missing_evidence_log_ids),
    ):
        if log_ids:
            r08_reason_parts.append(
                f"Se excluyeron registros con {label}: " + ", ".join(log_ids) + "."
            )
    if r08_evaluation.unrelated_log_ids:
        r08_reason_parts.append(
            "No se encontró relación R07/R09 con identidad y ventana válidas para: "
            + ", ".join(r08_evaluation.unrelated_log_ids)
            + "."
        )
    rules["R08"]["reason"] = " ".join(r08_reason_parts) or None

    observations: list[dict[str, Any]] = []
    point_matches: dict[str, list[SIEMRecord]] = {}

    for record in records:
        if record.event_id == "4624" and record.timestamp is not None:
            matching_failures = [
                earlier
                for earlier in records
                if earlier.event_id == "4625"
                and earlier.user == record.user
                and earlier.hostname == record.hostname
                and earlier.timestamp is not None
                and 0 < (record.timestamp - earlier.timestamp).total_seconds()
                <= _WINDOW_SECONDS["R02"]
            ]
            if len(matching_failures) >= 3:
                match_records = tuple(matching_failures + [record])
                observations.append(
                    _make_observation(
                        "R02",
                        _RULE_NAMES["R02"],
                        match_records,
                        "Tres o más fallos preceden a un logon exitoso del mismo usuario/host.",
                    )
                )
                rules["R02"]["matched_observation_count"] += 1

        for rule_id, description in _point_rule_matches(record):
            point_matches.setdefault(rule_id, []).append(record)
            observations.append(
                _make_observation(rule_id, _RULE_NAMES[rule_id], (record,), description)
            )
            rules[rule_id]["matched_observation_count"] += 1

    for rule_id, group in point_matches.items():
        if rule_id in ("R11",):
            rules[rule_id]["matched_observation_count"] = len(group)

    r06_observations = [
        observation
        for observation in observations
        if observation["rule_id"] == "R06"
    ]
    unique_r06_observations = {
        tuple(sorted(observation["evidence"][0].items())): observation
        for observation in r06_observations
    }
    sorted_r06_observations = sorted(
        unique_r06_observations.values(),
        key=lambda observation: (
            observation["evidence"][0]["Timestamp"] or "",
            observation["evidence"][0]["Log_ID"] or "",
            repr(tuple(sorted(observation["evidence"][0].items()))),
        ),
    )
    observations = [
        observation
        for observation in observations
        if observation["rule_id"] != "R06"
    ] + sorted_r06_observations
    rules["R06"]["matched_observation_count"] = len(sorted_r06_observations)

    r11_observations = [
        observation
        for observation in observations
        if observation["rule_id"] == "R11"
    ]
    unique_r11_observations = {
        tuple(sorted(observation["evidence"][0].items())): observation
        for observation in r11_observations
    }
    sorted_r11_observations = sorted(
        unique_r11_observations.values(),
        key=lambda observation: (
            observation["evidence"][0]["Timestamp"] or "",
            observation["evidence"][0]["Log_ID"] or "",
            repr(tuple(sorted(observation["evidence"][0].items()))),
        ),
    )
    observations = [
        observation
        for observation in observations
        if observation["rule_id"] != "R11"
    ] + sorted_r11_observations
    rules["R11"]["matched_observation_count"] = len(sorted_r11_observations)

    for finding in r09_evaluation.findings:
        if finding.matched_count_threshold and finding.matched_bytes_threshold:
            criteria = (
                "Se calificaron ventanas por cantidad de eventos únicos y por "
                "bytes observados."
            )
        elif finding.matched_count_threshold:
            criteria = "Se calificó al menos una ventana por cantidad de eventos únicos."
        else:
            criteria = (
                "Se calificó al menos una ventana exclusivamente por bytes "
                "observados; no es elegible para severidad por este criterio."
            )
        observations.append(
            _make_observation(
                "R09",
                _RULE_NAMES["R09"],
                (),
                criteria
                + " Los valores no demuestran transferencia exitosa, exfiltración "
                "ni impacto.",
                evidence=tuple(dict(item) for item in finding.evidence),
            )
        )

    for finding in r07_evaluation.findings:
        observations.append(
            _make_observation(
                "R07",
                _RULE_NAMES["R07"],
                (),
                "Se observaron al menos 10 valores literales distintos de "
                "Process_CommandLine en una ventana deslizante de 10 minutos "
                "para la misma clave (User, Hostname, Destination). El campo "
                "puede describir accesos a archivos y no demuestra ejecución, "
                "exfiltración ni impacto.",
                evidence=tuple(dict(item) for item in finding.evidence),
            )
        )

    for finding in r08_evaluation.findings:
        related_rules: list[str] = []
        if finding.related_r07_log_ids:
            related_rules.append(
                "R07 (" + ", ".join(finding.related_r07_log_ids) + ")"
            )
        if finding.related_r09_log_ids:
            related_rules.append(
                "R09 (" + ", ".join(finding.related_r09_log_ids) + ")"
            )
        destination_label = (
            "staging local"
            if finding.archive.destination_kind == "local_staging"
            else "destino de red"
        )
        observations.append(
            _make_observation(
                "R08",
                _RULE_NAMES["R08"],
                (),
                f"Se observó la herramienta {finding.archive.tool} con salida "
                f"{finding.archive.output_path} ({destination_label}); se asocia "
                f"temporal e identitariamente con {' y '.join(related_rules)}. "
                "Esta asociación contextual no demuestra causalidad, transferencia "
                "exitosa, exfiltración ni impacto.",
                evidence=tuple(dict(item) for item in finding.evidence),
            )
        )

    for finding in r13_evaluation.findings:
        metrics = finding.metrics
        error_rate = (
            "no calculable"
            if metrics.error_rate is None
            else f"{metrics.error_count}/{metrics.valid_result_count} "
            f"({metrics.error_rate:.2%})"
        )
        category = next(
            (
                item.get("source_ip_category")
                for item in finding.evidence
                if item.get("source_ip_category") is not None
            ),
            "unknown",
        )
        observations.append(
            _make_observation(
                "R13",
                _RULE_NAMES["R13"],
                (),
                f"Se observó en Source_IP {finding.source_ip_key} "
                f"(categoría {category}) una ventana calificante con "
                f"{metrics.request_count} solicitudes, {metrics.valid_result_count} "
                f"resultados HTTP válidos, {metrics.error_count} respuestas 4xx/5xx "
                f"(tasa {error_rate}) y {metrics.sensitive_route_count} solicitudes "
                "a rutas sensibles. La evidencia describe solicitudes observadas; "
                "no confirma automatización, intención maliciosa, éxito, impacto "
                "ni atribución, ni infiere actividad fuera de los registros disponibles.",
                evidence=tuple(dict(item) for item in finding.evidence),
            )
        )

    return rules, r01_observations + observations


def analyze_workbook(content: bytes) -> dict[str, Any]:
    ingestion = ingest_workbook(content)
    rules, observations = _evaluate_rules(
        ingestion.records,
        ingestion.r01_candidates,
        ingestion.r01_records_in_scope,
        ingestion.dataset_start,
        ingestion.has_invalid_timestamp,
        ingestion.r01_conflicting_log_ids,
        ingestion.r07_events,
        ingestion.r07_records_in_scope,
        ingestion.r07_conflicting_log_ids,
        ingestion.r08_events,
        ingestion.r08_records_in_scope,
        ingestion.r08_conflicting_log_ids,
        ingestion.r09_events,
        ingestion.r09_records_in_scope,
        ingestion.r09_conflicting_log_ids,
        ingestion.r13_events,
        ingestion.r13_records_in_scope,
        ingestion.r13_conflicting_log_ids,
    )
    invalid_ip_count = sum(
        record.source_ip.category in ("invalid", "missing", "unknown")
        for record in ingestion.records
    )
    pending_count = sum(rule["status"] == "pending" for rule in rules.values())
    partial_count = sum(
        rule["status"] == "partially_executed" for rule in rules.values()
    )
    executed_count = sum(rule["status"] == "executed" for rule in rules.values())
    not_evaluable_rule_count = sum(
        rule["status"] == "not_evaluable" for rule in rules.values()
    )
    not_evaluable_count = ingestion.records_seen - len(ingestion.records)
    chains = {
        chain_id: {
            "status": (
                "pending_reconciliation"
                if chain_id == "C2"
                else "not_evaluable"
            ),
            "ratified": True,
            "reason": (
                "La conciliación de C2 permanece pendiente por decisión ratificada."
                if chain_id == "C2"
                else "Falta la condición exacta de membership y enlaces admisibles."
            ),
        }
        for chain_id in ("C1", "C2", "C3", "C4", "C5", "C6")
    }
    chains["C7"] = {
        "status": "not_evaluable",
        "ratified": False,
        "reason": "C7 no se evalúa ni activa porque es un candidato no ratificado.",
    }

    return {
        "contract": "analysis-partial/1",
        "schema_version": ANALYSIS_SCHEMA_VERSION,
        "canon_version": CANON_VERSION,
        "analysis_id": None,
        "analysis_id_status": "not_evaluable",
        "analysis_id_reason": (
            "cj/1 canónica no puede verificarse sin los vectores y la serialización "
            "aprobados; no se sustituye por un hash de bytes."
        ),
        "file_sha256": file_sha256(content),
        "content_sha256": None,
        "content_sha256_status": "not_evaluable",
        "status": "partial",
        "completion_status": "partial",
        "timezone_status": "undefined",
        "completeness": {
            "records_seen": ingestion.records_seen,
            "records_evaluated": len(ingestion.records),
            "records_not_evaluable": not_evaluable_count,
            "records_with_non_evaluable_ip": invalid_ip_count,
            "rules_total": len(rules),
            "rules_executed": executed_count,
            "rules_partially_executed": partial_count,
            "rules_pending": pending_count,
            "rules_not_evaluable": not_evaluable_rule_count,
            "chains_not_evaluable": 5,
            "chains_pending_reconciliation": 1,
            "chains_not_ratified": 1,
        },
        "rule_execution": rules,
        "chain_execution": chains,
        "non_evaluable_records": [asdict(issue) for issue in ingestion.issues],
        "ip_classification_status": registry_validation_status(),
        "observations": observations,
        "activity_summary": {
            "records_loaded": len(ingestion.records),
            "observations_emitted": len(observations),
            "no_observations_means_no_rule_match_not_no_activity": True,
        },
    }
