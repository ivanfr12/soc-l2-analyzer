"""Memberships de cadena C1–C6 ratificadas en Fase 4.

El módulo consume **observaciones ya emitidas** por el análisis y, cuando una
membership lo requiere, los registros crudos para evidencia contextual
opcional. No vuelve a evaluar reglas ni modifica sus predicados.

Todas las cadenas se presentan como *secuencias observadas candidatas*: no se
afirma compromiso, causalidad, explotación, exfiltración, éxito, impacto ni
atribución. Un enlace que no puede verificarse se reporta como
``not_evaluable``; nunca se degrada a una asociación inventada.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any, Mapping, Sequence

if TYPE_CHECKING:  # pragma: no cover - solo para tipado, evita import circular
    from app.analysis import SIEMRecord

#: Ventanas ratificadas, en segundos.
C1_R01_TO_R02_WINDOW = 15 * 60
C1_CONTEXTUAL_4672_WINDOW = 60 * 60
C3_R07_TO_R10_WINDOW = 30 * 60
C5_MECHANISM_WINDOW = 30 * 60
C5_EXECUTION_WINDOW = 60 * 60
C6_R13_TO_R12_WINDOW = 15 * 60
C4_R08_WINDOW = 15 * 60

SEMANTICS = "observed_sequence_candidate"

_META: dict[str, dict[str, Any]] = {
    "C1": {
        "name": "Rociado de credenciales contra DC-01 desde IP externa",
        "level": 2,
        "severity": "Medium",
        "reference_score_1e4": 4500,
    },
    "C2": {
        "name": "Acceso RDP, reconocimiento, acceso a Finance y salida",
        "level": None,
        "severity": "Low",
        "reference_score_1e4": None,
    },
    "C3": {
        "name": "Lectura masiva de Finance y eliminación de shadow copies",
        "level": 2,
        "severity": "Medium",
        "reference_score_1e4": 4500,
    },
    "C4": {
        "name": "Archivo comprimido y transferencia saliente masiva",
        "level": 1,
        "severity": "Medium",
        "reference_score_1e4": 6900,
    },
    "C5": {
        "name": "Persistencia en APP-SRV01 (tarea programada + servicio)",
        "level": 3,
        "severity": "Medium",
        "reference_score_1e4": 7975,
    },
    "C6": {
        "name": "Enumeración web y ejecución de comandos en WEB-01",
        "level": 1,
        "severity": "Low",
        "reference_score_1e4": 6900,
    },
    "C7": {
        "name": "Candidato no ratificado",
        "level": None,
        "severity": None,
        "reference_score_1e4": None,
    },
}


def _parse_timestamp(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str) and value.strip():
        try:
            return datetime.fromisoformat(value.strip())
        except ValueError:
            return None
    return None


def _normalize_ip(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


@dataclass(frozen=True)
class _Node:
    rule_id: str
    evidence: tuple[Mapping[str, Any], ...]
    log_ids: tuple[str, ...]
    hostnames: frozenset[str]
    users: frozenset[str]
    source_ips: frozenset[str]
    user_ip_pairs: frozenset[tuple[str, str]]
    first_ts: datetime | None
    last_ts: datetime | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "log_ids": list(self.log_ids),
            "hostnames": sorted(self.hostnames),
            "users": sorted(self.users),
            "source_ips": sorted(self.source_ips),
            "first_timestamp": self.first_ts.isoformat() if self.first_ts else None,
            "last_timestamp": self.last_ts.isoformat() if self.last_ts else None,
        }

    def items_with_event(self, event_id: str) -> tuple[Mapping[str, Any], ...]:
        return tuple(
            item
            for item in self.evidence
            if str(item.get("Event_ID")) == event_id
        )


def _node(rule_id: str, observation: Mapping[str, Any]) -> _Node:
    evidence = tuple(
        dict(item) for item in observation.get("evidence", ()) if isinstance(item, Mapping)
    )
    log_ids: set[str] = set()
    hostnames: set[str] = set()
    users: set[str] = set()
    source_ips: set[str] = set()
    user_ip_pairs: set[tuple[str, str]] = set()
    stamps: list[datetime] = []
    for item in evidence:
        log_id = item.get("Log_ID")
        if log_id:
            log_ids.add(str(log_id))
        hostname = item.get("Hostname")
        if isinstance(hostname, str) and hostname:
            hostnames.add(hostname)
        user = item.get("User")
        if isinstance(user, str) and user:
            users.add(user)
        address = _normalize_ip(item.get("Source_IP"))
        if address:
            source_ips.add(address)
            if isinstance(user, str) and user:
                user_ip_pairs.add((user, address))
        timestamp = _parse_timestamp(item.get("Timestamp"))
        if timestamp is not None:
            stamps.append(timestamp)
    return _Node(
        rule_id=rule_id,
        evidence=evidence,
        log_ids=tuple(sorted(log_ids)),
        hostnames=frozenset(hostnames),
        users=frozenset(users),
        source_ips=frozenset(source_ips),
        user_ip_pairs=frozenset(user_ip_pairs),
        first_ts=min(stamps) if stamps else None,
        last_ts=max(stamps) if stamps else None,
    )


def _nodes(observations: Sequence[Mapping[str, Any]], rule_id: str) -> list[_Node]:
    return [
        _node(rule_id, observation)
        for observation in observations
        if observation.get("rule_id") == rule_id
    ]


def _forward_delta(
    origin: _Node, target: _Node, window: int
) -> int | None:
    """Delta direccional ``target.first - origin.last`` dentro de ventana."""

    if origin.last_ts is None or target.first_ts is None:
        return None
    delta = int((target.first_ts - origin.last_ts).total_seconds())
    if 0 <= delta <= window:
        return delta
    return None


def _chain(
    chain_id: str,
    *,
    status: str,
    reason: str,
    nodes: Sequence[_Node] = (),
    links: Sequence[Mapping[str, Any]] = (),
    contextual: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    meta = _META[chain_id]
    evidence: set[str] = set()
    for node in nodes:
        evidence.update(node.log_ids)
    for entry in contextual:
        evidence.update(str(log_id) for log_id in entry.get("log_ids", ()))
    return {
        "chain_id": chain_id,
        "name": meta["name"],
        "status": status,
        "ratified": True,
        "reason": reason,
        "semantics": SEMANTICS,
        "level": meta["level"],
        "severity": meta["severity"],
        "severity_status": "ratified",
        "score_1e4": None,
        "score_status": "not_evaluable_without_E_K_catalogs",
        "reference_score_1e4": meta["reference_score_1e4"],
        "evidence": sorted(evidence),
        "nodes": [node.as_dict() for node in nodes],
        "links": list(links),
        "contextual_evidence": list(contextual),
    }


def _not_evaluable(chain_id: str, reason: str) -> dict[str, Any]:
    return _chain(chain_id, status="not_evaluable", reason=reason)


def _link(
    origin: _Node,
    target: _Node,
    basis: Sequence[str],
    delta: int,
    window: int,
) -> dict[str, Any]:
    return {
        "from_rule": origin.rule_id,
        "to_rule": target.rule_id,
        "basis": list(basis),
        "delta_seconds": delta,
        "window_seconds": window,
    }


def _evaluate_c1(
    observations: Sequence[Mapping[str, Any]],
    records: Sequence["SIEMRecord"],
) -> dict[str, Any]:
    r01_nodes = _nodes(observations, "R01")
    r02_nodes = _nodes(observations, "R02")
    if not r01_nodes or not r02_nodes:
        return _not_evaluable(
            "C1",
            "No coinciden observaciones R01 y R02 en la misma ejecución; no se "
            "infiere una secuencia de rociado con logon exitoso.",
        )

    nodes: list[_Node] = []
    seen_nodes: set[tuple[str, tuple[str, ...]]] = set()
    links: list[dict[str, Any]] = []
    contextual: list[dict[str, Any]] = []
    for spray in r01_nodes:
        if not spray.source_ips or not spray.hostnames or not spray.users:
            continue
        for success_node in r02_nodes:
            for item in success_node.items_with_event("4624"):
                user = item.get("User")
                hostname = item.get("Hostname")
                address = _normalize_ip(item.get("Source_IP"))
                timestamp = _parse_timestamp(item.get("Timestamp"))
                if (
                    not isinstance(user, str)
                    or hostname not in spray.hostnames
                    or address is None
                    or address not in spray.source_ips
                    or user not in spray.users
                    or timestamp is None
                    or spray.last_ts is None
                ):
                    continue
                delta = int((timestamp - spray.last_ts).total_seconds())
                if not 0 <= delta <= C1_R01_TO_R02_WINDOW:
                    continue
                for candidate in (spray, success_node):
                    key = (candidate.rule_id, candidate.log_ids)
                    if key not in seen_nodes:
                        seen_nodes.add(key)
                        nodes.append(candidate)
                links.append(
                    _link(
                        spray,
                        success_node,
                        ("same_source_ip", "same_hostname", "user_in_spray_set"),
                        delta,
                        C1_R01_TO_R02_WINDOW,
                    )
                )
                contextual.extend(
                    _c1_contextual(records, user, address, timestamp)
                )

    if not links:
        return _not_evaluable(
            "C1",
            "R01 y R02 existen, pero ningún logon exitoso comparte IP, host y "
            "usuario rociado dentro de la ventana de 15 minutos.",
        )

    reason = (
        "Se observó un rociado de credenciales (R01) seguido de un logon exitoso "
        "(R02) del mismo usuario, host y Source_IP dentro de 15 minutos. La "
        "secuencia es candidata: no demuestra compromiso, éxito sostenido, "
        "impacto ni atribución."
    )
    if contextual:
        reason += (
            " El evento 4672 se incluye solo como contexto asociado por usuario "
            "+ IP; no exige el mismo host y no constituye identidad de sesión."
        )
    return _chain(
        "C1", status="executed", reason=reason, nodes=nodes, links=links, contextual=contextual
    )


def _c1_contextual(
    records: Sequence["SIEMRecord"],
    user: str,
    address: str,
    success_ts: datetime,
) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for record in records:
        if record.event_id != "4672" or record.user != user:
            continue
        if record.timestamp is None:
            continue
        record_ip = _normalize_ip(record.source_ip.value)
        if record_ip != address:
            continue
        delta = int((record.timestamp - success_ts).total_seconds())
        if not 0 <= delta <= C1_CONTEXTUAL_4672_WINDOW:
            continue
        entries.append(
            {
                "rule_id": "4672",
                "log_ids": [record.log_id] if record.log_id else [],
                "basis": ["same_user", "same_source_ip", "host_may_differ"],
                "delta_seconds": delta,
                "window_seconds": C1_CONTEXTUAL_4672_WINDOW,
                "note": (
                    "Contexto opcional: no es membership de C1, no prueba "
                    "identidad de sesión y no se usa para afirmar privilegio "
                    "efectivo."
                ),
            }
        )
    return entries


def _evaluate_c3(observations: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    r07_nodes = _nodes(observations, "R07")
    r10_nodes = _nodes(observations, "R10")
    if not r07_nodes or not r10_nodes:
        return _not_evaluable(
            "C3",
            "No coinciden observaciones R07 y R10 en la misma ejecución; no se "
            "infiere una secuencia de recolección y destrucción.",
        )

    nodes: list[_Node] = []
    links: list[dict[str, Any]] = []
    for reading in r07_nodes:
        for deletion in r10_nodes:
            if not reading.user_ip_pairs or not deletion.user_ip_pairs:
                continue
            if not reading.user_ip_pairs & deletion.user_ip_pairs:
                continue
            delta = _forward_delta(reading, deletion, C3_R07_TO_R10_WINDOW)
            if delta is None:
                continue
            nodes.extend((reading, deletion))
            links.append(
                _link(
                    reading,
                    deletion,
                    ("same_user", "same_source_ip", "host_may_differ"),
                    delta,
                    C3_R07_TO_R10_WINDOW,
                )
            )

    if not links:
        return _not_evaluable(
            "C3",
            "R07 y R10 existen, pero no comparten usuario y Source_IP dentro de "
            "la ventana de 30 minutos.",
        )

    return _chain(
        "C3",
        status="executed",
        reason=(
            "Se observó lectura masiva en un share (R07) y eliminación de shadow "
            "copies (R10) con el mismo usuario y Source_IP dentro de 30 minutos, "
            "admitiendo hosts diferentes. Es una asociación observada: no prueba "
            "identidad de sesión, intención, destrucción efectiva ni impacto."
        ),
        nodes=nodes,
        links=links,
    )


def _evaluate_c4(observations: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    r08_nodes = _nodes(observations, "R08")
    if not r08_nodes:
        return _not_evaluable(
            "C4",
            "No hay observación R08 en la ejecución; no se infiere archivado ni "
            "transferencia.",
        )

    nodes: list[_Node] = []
    links: list[dict[str, Any]] = []
    for archive in r08_nodes:
        upload_items = archive.items_with_event("PROXY_ACCESS")
        if not upload_items:
            continue
        anchor_items = archive.items_with_event("4688")
        if not anchor_items:
            return _not_evaluable(
                "C4",
                "r08_primary_4688_evidence_missing: R08 no dispone de evidencia "
                "primaria 4688 para establecer el ancla temporal; R09 no se usa "
                "como sustituto.",
            )
        upload = _node("R09", {"evidence": upload_items})
        anchor = _node("R08", {"evidence": anchor_items})
        delta = _forward_delta(anchor, upload, C4_R08_WINDOW)
        if delta is None:
            continue
        nodes.extend((archive, upload))
        links.append(
            _link(
                archive,
                upload,
                ("same_hostname", "same_user", "r08_related_r09"),
                delta,
                C4_R08_WINDOW,
            )
        )

    if not links:
        return _not_evaluable(
            "C4",
            "R08 se emitió sin correlación R09 (solo R07 o sin correlación). C4 "
            "exige R09 no vacío como condición propia de la cadena; la semántica "
            "OR interna de R08 no se modifica.",
        )

    return _chain(
        "C4",
        status="executed",
        reason=(
            "Se observó una herramienta de archivado (R08) con correlación R09 no "
            "vacía sobre el mismo host y usuario dentro de 15 minutos. La cadena "
            "es candidata: no demuestra transferencia exitosa, exfiltración, "
            "impacto ni atribución. R08 conserva su semántica OR entre R07 y R09."
        ),
        nodes=nodes,
        links=links,
    )


def _evaluate_c5(
    observations: Sequence[Mapping[str, Any]],
    records: Sequence["SIEMRecord"],
) -> dict[str, Any]:
    r11_nodes = _nodes(observations, "R11")
    tasks = [node for node in r11_nodes if node.items_with_event("4698")]
    services = [node for node in r11_nodes if node.items_with_event("7045")]
    if not tasks or not services:
        return _not_evaluable(
            "C5",
            "No coinciden una observación R11 de tarea programada (4698) y una de "
            "servicio (7045) en la misma ejecución.",
        )

    nodes: list[_Node] = []
    links: list[dict[str, Any]] = []
    contextual: list[dict[str, Any]] = []
    for task in tasks:
        for service in services:
            if not task.hostnames & service.hostnames:
                continue
            if not task.users & service.users:
                continue
            if task.first_ts is None or service.first_ts is None:
                continue
            gap = abs(int((service.first_ts - task.first_ts).total_seconds()))
            if gap > C5_MECHANISM_WINDOW:
                continue
            nodes.extend((task, service))
            links.append(
                {
                    "from_rule": "R11",
                    "to_rule": "R11",
                    "basis": ["same_hostname", "same_user", "unordered_window"],
                    "delta_seconds": gap,
                    "window_seconds": C5_MECHANISM_WINDOW,
                }
            )
            contextual.extend(_c5_executions(records, service))

    if not links:
        return _not_evaluable(
            "C5",
            "Existen observaciones R11, pero la tarea y el servicio no comparten "
            "host y usuario dentro de la ventana de 30 minutos.",
        )

    reason = (
        "Se observaron dos mecanismos de persistencia (tarea programada 4698 y "
        "servicio 7045) en el mismo host y usuario dentro de 30 minutos, sin "
        "imponer orden. La secuencia es candidata: no demuestra persistencia "
        "efectiva, malware, impacto ni atribución."
    )
    if contextual:
        reason += (
            " Las ejecuciones 4688 se incluyen solo cuando su línea de comando "
            "iguala exactamente el ImagePath del servicio."
        )
    return _chain(
        "C5", status="executed", reason=reason, nodes=nodes, links=links, contextual=contextual
    )


def _image_path(command_line: str) -> str | None:
    """Extrae el valor exacto de ``ImagePath`` de una línea 7045.

    No hay coincidencia por prefijos ni por subcadenas: se toma el valor
    completo del token ``ImagePath=`` y se compara por igualdad exacta.
    """

    for part in command_line.split(";"):
        candidate = part.strip()
        if candidate.startswith("ImagePath="):
            value = candidate[len("ImagePath=") :].strip()
            return value or None
    return None


def _c5_executions(
    records: Sequence["SIEMRecord"], service: _Node
) -> list[dict[str, Any]]:
    service_items = service.items_with_event("7045")
    if not service_items:
        return []
    service_log_id = service_items[0].get("Log_ID")
    image_path: str | None = None
    for record in records:
        if record.log_id == service_log_id and record.process_command_line:
            image_path = _image_path(record.process_command_line)
            break
    if not image_path or service.last_ts is None:
        return []

    entries: list[dict[str, Any]] = []
    for record in records:
        if record.event_id != "4688" or record.timestamp is None:
            continue
        if record.hostname not in service.hostnames:
            continue
        if record.user not in service.users:
            continue
        if (record.process_command_line or "").strip() != image_path:
            continue
        delta = int((record.timestamp - service.last_ts).total_seconds())
        if not 0 <= delta <= C5_EXECUTION_WINDOW:
            continue
        entries.append(
            {
                "rule_id": "4688",
                "log_ids": [record.log_id] if record.log_id else [],
                "basis": ["same_hostname", "same_user", "exact_image_path"],
                "delta_seconds": delta,
                "window_seconds": C5_EXECUTION_WINDOW,
                "note": (
                    "Contexto opcional: la igualdad de ImagePath es exacta; no se "
                    "usa coincidencia por prefijos ni periodicidad."
                ),
            }
        )
    return entries


def _evaluate_c6(observations: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    r13_nodes = _nodes(observations, "R13")
    r12_nodes = _nodes(observations, "R12")
    if not r13_nodes or not r12_nodes:
        return _not_evaluable(
            "C6",
            "No coinciden observaciones R13 y R12 en la misma ejecución; no se "
            "infiere enumeración seguida de ejecución de comandos.",
        )

    nodes: list[_Node] = []
    links: list[dict[str, Any]] = []
    missing_ip = False
    for enumeration in r13_nodes:
        for execution in r12_nodes:
            if not enumeration.hostnames or not execution.hostnames:
                continue
            if not enumeration.hostnames & execution.hostnames:
                continue
            if not execution.source_ips or not enumeration.source_ips:
                missing_ip = True
                continue
            if not enumeration.source_ips & execution.source_ips:
                continue
            delta = _forward_delta(enumeration, execution, C6_R13_TO_R12_WINDOW)
            if delta is None:
                continue
            nodes.extend((enumeration, execution))
            links.append(
                _link(
                    enumeration,
                    execution,
                    ("same_hostname", "same_source_ip"),
                    delta,
                    C6_R13_TO_R12_WINDOW,
                )
            )

    if not links:
        if missing_ip:
            return _not_evaluable(
                "C6",
                "La ejecución R12 o la enumeración R13 no tienen Source_IP "
                "evaluable; la cadena exige host + IP y no se degrada a una "
                "asociación por host.",
            )
        return _not_evaluable(
            "C6",
            "R13 y R12 existen, pero no comparten host y Source_IP dentro de la "
            "ventana de 15 minutos.",
        )

    return _chain(
        "C6",
        status="executed",
        reason=(
            "Se observó enumeración web (R13) y ejecución de comandos (R12) sobre "
            "el mismo host y Source_IP dentro de 15 minutos. La correlación "
            "host/aplicación es compatible con H-02. La secuencia es candidata: no "
            "demuestra explotación, éxito, impacto ni atribución."
        ),
        nodes=nodes,
        links=links,
    )


def _pending_c2() -> dict[str, Any]:
    return _chain(
        "C2",
        status="pending_reconciliation",
        reason=(
            "La conciliación de C2 permanece pendiente por decisión ratificada: "
            "sus nodos no comparten host, IP ni identificador de sesión."
        ),
    )


def _c7() -> dict[str, Any]:
    chain = _chain(
        "C7",
        status="not_evaluable",
        reason="C7 no se evalúa ni activa porque es un candidato no ratificado.",
    )
    chain["ratified"] = False
    chain["level"] = None
    chain["severity"] = None
    chain["severity_status"] = "not_defined"
    chain["reference_score_1e4"] = None
    return chain


def build_chain_execution(
    observations: Sequence[Mapping[str, Any]],
    records: Sequence["SIEMRecord"] = (),
) -> dict[str, dict[str, Any]]:
    """Construye ``chain_execution`` a partir de observaciones ya emitidas."""

    return {
        "C1": _evaluate_c1(observations, records),
        "C2": _pending_c2(),
        "C3": _evaluate_c3(observations),
        "C4": _evaluate_c4(observations),
        "C5": _evaluate_c5(observations, records),
        "C6": _evaluate_c6(observations),
        "C7": _c7(),
    }


def chain_summary(chains: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    """Resumen de estados para el contrato ``analysis-partial/1``."""

    summary: dict[str, Any] = {}
    for chain_id, chain in chains.items():
        entry = {
            "status": chain["status"],
            "ratified": chain["ratified"],
            "reason": chain["reason"],
        }
        summary[chain_id] = entry
    return summary
