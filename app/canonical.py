"""Canonicalización determinista ``cj/1`` (D-1, D-3, D-4, D-5, D-6, D-8, D-9).

Este módulo implementa únicamente las decisiones ratificadas. No declara
``cj/1`` completo: la verificación con los tres vectores de D-7 sigue
pendiente y los valores que produce se exponen como provisionales.

Representación canónica de valores (D-6)
----------------------------------------
Se serializa con ``json.dumps(..., ensure_ascii=False, separators=(",", ":"))``
y ``allow_nan=False``. No hay conversiones implícitas que equiparen tipos
distintos:

===========================  ==========================================
Valor de celda               Representación canónica
===========================  ==========================================
``None``                     ``null``
``bool``                     ``true`` / ``false`` (antes que ``int``)
``int``                      literal entero (``4625``)
``float``                    literal flotante de ida y vuelta; ``NaN`` e
                             ``inf`` se rechazan con ``ValueError``
``str``                      cadena sin transformar; ``""`` se conserva
                             como ``""`` y es distinto de ``null``
``datetime`` naive           ``{"$type":"datetime","value":"YYYY-MM-DDTHH:MM:SS.ffffff"}``
                             (6 dígitos fijos, sin offset)
``datetime`` con zona        igual, con sufijo ``+HH:MM`` / ``-HH:MM``
``date``                     ``{"$type":"date","value":"YYYY-MM-DD"}``
cualquier otro tipo          ``TypeError`` (nunca ``str()`` silencioso)
===========================  ==========================================

Los tipos temporales se etiquetan de forma explícita para que una celda
``datetime`` y una cadena ISO con el mismo instante **nunca** colisionen: son
tipos distintos y no se equiparan. El resto de los tipos ya queda distinguido
por la propia sintaxis JSON (``4625`` vs ``"4625"``, ``null`` vs ``""``,
``true`` vs ``1``).

Serialización de filas (D-1)
----------------------------
Cada fila es un array JSON con los 12 campos en el orden exacto de
``REQUIRED_COLUMNS``. No se usan objetos JSON, de modo que el orden de claves
no introduce ambigüedad. Las filas se separan con ``\\n`` y el flujo completo
termina en ``\\n`` cuando contiene filas.

Orden de filas para ``content_sha256`` (D-2 acotado)
----------------------------------------------------
El orden de filas no altera ``content_sha256`` (decisión ratificada). Para
lograrlo las filas canónicas se ordenan por sus propios bytes. **No** se
eliminan duplicados idénticos ni se excluyen conflictos: la deduplicación y la
exclusión siguen siendo específicas de cada regla.

Claves de orden estables (D-4)
------------------------------
- ``observations``: ``(rule_id, primer Timestamp de evidencia, primer Log_ID,
  JSON canónico de la observación)``.
- ``evidence`` dentro de cada observación: ``(Timestamp, Log_ID, JSON
  canónico)``.
- ``non_evaluable_records``: ``(log_id, code)``.
- ``rule_execution`` y ``chain_execution``: claves ordenadas por
  ``json.dumps(sort_keys=True)``.
- ``chains[].nodes``: ``(rule_id, first_timestamp, primer Log_ID)``.
- ``chains[].links``: ``(from_rule, to_rule, delta_seconds)``.
- ``chains[].evidence`` y ``contextual_evidence``: ``Log_ID`` ascendente.

Exclusiones de ``logical_fingerprint`` (D-3)
--------------------------------------------
Ya ratificadas: ``file_sha256``, ``generated_at``, ``row_index``, rutas,
duración y memoria. Se agrega ``analysis_id`` para evitar autorreferencia
(D-5). No se retira ninguna exclusión ratificada.
"""

from __future__ import annotations

import json
from datetime import date, datetime
from hashlib import sha256
from typing import Any, Iterable, Mapping, Sequence

ROW_SEPARATOR = "\n"

#: Campos que nunca forman parte de ``logical_fingerprint``.
FINGERPRINT_EXCLUDED_FIELDS = frozenset(
    {
        # Exclusiones ya ratificadas.
        "file_sha256",
        "generated_at",
        "row_index",
        "file_name",
        "source_path",
        "source_paths",
        "duration_ms",
        "memory_bytes",
        # Necesaria para que el identificador no dependa de sí mismo (D-5).
        "analysis_id",
    }
)

#: Estado honesto mientras D-7 siga sin ratificar.
PROVISIONAL_STATUS = "provisional_unratified_vectors"


def _canonical_datetime(value: datetime) -> str:
    base = f"{value.strftime('%Y-%m-%dT%H:%M:%S')}.{value.microsecond:06d}"
    offset = value.utcoffset()
    if offset is None:
        return base
    total = int(offset.total_seconds())
    sign = "+" if total >= 0 else "-"
    total = abs(total)
    return f"{base}{sign}{total // 3600:02d}:{(total % 3600) // 60:02d}"


def canonical_value(value: Any) -> Any:
    """Devuelve la representación canónica JSON de un valor de celda."""

    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, datetime):
        return {"$type": "datetime", "value": _canonical_datetime(value)}
    if isinstance(value, date):
        return {"$type": "date", "value": value.isoformat()}
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise ValueError("Los valores NaN e infinito no son canónicos.")
        return value
    if isinstance(value, str):
        return value
    raise TypeError(f"Tipo no canónico: {type(value).__name__}")


def canonical_row(values: Sequence[Any]) -> str:
    """Serializa una fila como array JSON canónico."""

    return json.dumps(
        [canonical_value(value) for value in values],
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    )


def canonical_rows(rows: Iterable[Sequence[Any]]) -> str:
    """Serializa todas las filas conservando cada una de ellas."""

    ordered = sorted(canonical_row(row) for row in rows)
    if not ordered:
        return ""
    return ROW_SEPARATOR.join(ordered) + ROW_SEPARATOR


def content_sha256(rows: Iterable[Sequence[Any]]) -> str:
    """SHA-256 de las filas canónicas, independiente del orden de entrada.

    Conserva todas las filas: no colapsa duplicados idénticos ni excluye
    conflictos, porque esas decisiones son específicas de cada regla.
    """

    return sha256(canonical_rows(rows).encode("utf-8")).hexdigest()


def _strip_volatile(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            key: _strip_volatile(item)
            for key, item in value.items()
            if key not in FINGERPRINT_EXCLUDED_FIELDS
        }
    if isinstance(value, (list, tuple)):
        return [_strip_volatile(item) for item in value]
    return value


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    )


def _evidence_order(item: Mapping[str, Any]) -> tuple[str, str, str]:
    return (
        str(item.get("Timestamp") or ""),
        str(item.get("Log_ID") or ""),
        canonical_json(dict(item)),
    )


def _observation_order(item: Mapping[str, Any]) -> tuple[str, str, str, str]:
    evidence = sorted(
        (dict(entry) for entry in item.get("evidence", ())),
        key=_evidence_order,
    )
    first = evidence[0] if evidence else {}
    return (
        str(item.get("rule_id") or ""),
        str(first.get("Timestamp") or ""),
        str(first.get("Log_ID") or ""),
        canonical_json({**dict(item), "evidence": evidence}),
    )


def _ordered_payload(result: Mapping[str, Any]) -> dict[str, Any]:
    payload = dict(_strip_volatile(result))

    observations = []
    for observation in result.get("observations", ()):
        item = dict(observation)
        item["evidence"] = sorted(
            (dict(entry) for entry in item.get("evidence", ())),
            key=_evidence_order,
        )
        observations.append(item)
    payload["observations"] = sorted(observations, key=_observation_order)

    payload["non_evaluable_records"] = sorted(
        (dict(record) for record in result.get("non_evaluable_records", ())),
        key=lambda record: (
            str(record.get("log_id") or ""),
            str(record.get("code") or ""),
        ),
    )

    for field in ("rule_execution", "chain_execution"):
        section = payload.get(field)
        if isinstance(section, Mapping):
            payload[field] = {
                str(key): value for key, value in sorted(section.items())
            }

    return payload


def logical_fingerprint(result: Mapping[str, Any]) -> str:
    """SHA-256 del resultado lógico, con orden estable y exclusiones ratificadas."""

    encoded = canonical_json(_ordered_payload(result)).encode("utf-8")
    return sha256(encoded).hexdigest()


def analysis_id_from_fingerprint(fingerprint: str) -> str:
    """Identificador content-addressed sin autorreferencia."""

    return f"A-{fingerprint[:32]}"
