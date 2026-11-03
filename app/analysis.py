from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from datetime import datetime
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
from app.ip_classification import IPClassification, classify_ip

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


@dataclass(frozen=True)
class IngestIssue:
    log_id: str | None
    code: str


@dataclass(frozen=True)
class IngestedWorkbook:
    records: tuple[SIEMRecord, ...]
    issues: tuple[IngestIssue, ...]
    records_seen: int


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
_PENDING_RULE_REASONS = {
    "R01": "Falta definir la alineación de las ventanas de 10 minutos.",
    "R07": "Falta definir la alineación de las ventanas de 10 minutos.",
    "R08": "Depende de correlación temporal R07/R09 y de ventanas no resueltas.",
    "R09": "La alineación y superposición de ventanas de 15 minutos no está definida.",
    "R13": "Falta definir la alineación de las ventanas de 5 minutos.",
}
_WINDOW_SECONDS = {
    "R02": 15 * 60,
}
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
_RECOGNITION_TERMS = (
    "net view",
    "get-smbshare",
    "get-localgroupmember",
    "whoami",
    "net group",
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
            values = {
                column: row[indexes[column]] if indexes[column] < len(row) else None
                for column in REQUIRED_COLUMNS
            }
            log_id = _text(values["Log_ID"])
            missing = [
                column
                for column in _REQUIRED_NON_NULL
                if values[column] is None
                or (isinstance(values[column], str) and not values[column].strip())
            ]
            timestamp = _timestamp(values["Timestamp"])
            if timestamp is None and "Timestamp" not in missing:
                issues.append(IngestIssue(log_id, "invalid_timestamp"))
                continue
            if missing:
                issues.extend(IngestIssue(log_id, f"missing_{column}") for column in missing)
                continue

            records.append(
                SIEMRecord(
                    log_id=log_id,
                    timestamp=timestamp,
                    hostname=_text(values["Hostname"]),
                    event_id=_event_id(values["Event_ID"]),
                    user=_text(values["User"]),
                    source_ip=classify_ip(values["Source_IP"]),
                    destination=_text(values["Destination"]),
                    log_source=_text(values["Log_Source"]),
                    event_description=_text(values["Event_Description"]),
                    process_command_line=_text(values["Process_CommandLine"]),
                    result=_text(values["Result"]),
                    severity=_text(values["Severity"]),
                )
            )
    except XLSX_CONTENT_ERRORS as exc:
        raise WorkbookValidationError(
            "corrupt_xlsx", "No se pudo leer el contenido interno del XLSX."
        ) from exc
    finally:
        workbook.close()
    return IngestedWorkbook(tuple(records), tuple(issues), records_seen)


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
    recognition_text = re.sub(r"\bnet\.exe(?=\s)", "net", recognition_text)
    if record.event_id in ("4688", "4104") and any(
        term in recognition_text for term in _RECOGNITION_TERMS
    ):
        matches.append(
            (
                "R06",
                "El registro contiene un comando de reconocimiento documentado; "
                "no se aplicó agrupación temporal.",
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
        indicator in command for indicator in _PATH_INDICATORS
    ):
        matches.append(
            ("R11", "Evento de tarea/servicio con una ruta indicada por R11.")
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


def _rule_statuses() -> dict[str, dict[str, Any]]:
    rules: dict[str, dict[str, Any]] = {}
    for rule_id, name in _RULE_NAMES.items():
        if rule_id in _PENDING_RULE_REASONS:
            status: RuleStatus = "pending"
            reason = _PENDING_RULE_REASONS[rule_id]
        elif rule_id in ("R02", "R03", "R04", "R05", "R10", "R12"):
            status = "executed"
            reason = None
        else:
            status = "partially_executed"
            reason = {
                "R06": "Se evalúan comandos por registro; no se agrupan en 10 minutos.",
                "R11": (
                    "Se evalúa la condición puntual; no se infieren agrupación "
                    "temporal ni periodicidad."
                ),
            }.get(
                rule_id,
                "Se evalúa la condición puntual documentada; la agrupación temporal "
                "y la evaluación de periodicidad no se infieren.",
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
) -> dict[str, Any]:
    severities: dict[str, str] = {"R03": "Low", "R11": "Medium"}
    severity = severities.get(rule_id)
    return {
        "rule_id": rule_id,
        "rule_name": rule_name,
        "observation_type": "deterministic_rule_match",
        "description": reason,
        "evidence": [_event_reference(record) for record in records],
        "impact_demonstrated": False,
        "incident_attribution": False,
        "severity": severity,
        "severity_status": "ratified" if severity is not None else "not_defined",
        "level": None,
        "level_status": "not_evaluable_in_partial_contract",
        "score_1e4": None,
        "confidence_basis_points": None,
        "confidence_status": "not_evaluable_without_E_K_catalogs",
    }


def _evaluate_rules(
    records: tuple[SIEMRecord, ...],
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    rules = _rule_statuses()
    for rule_id, rule in rules.items():
        event_ids = _RULE_EVENT_IDS[rule_id]
        rule["records_in_scope"] = sum(
            record.event_id in event_ids for record in records
        )
        if rule["status"] in ("executed", "partially_executed"):
            rule["records_evaluated"] = rule["records_in_scope"]

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

    return rules, observations


def analyze_workbook(content: bytes) -> dict[str, Any]:
    ingestion = ingest_workbook(content)
    rules, observations = _evaluate_rules(ingestion.records)
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
        "ip_classification_status": "provisional_without_iana_snapshots",
        "observations": observations,
        "activity_summary": {
            "records_loaded": len(ingestion.records),
            "observations_emitted": len(observations),
            "no_observations_means_no_rule_match_not_no_activity": True,
        },
    }
