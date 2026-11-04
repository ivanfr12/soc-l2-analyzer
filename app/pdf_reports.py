from __future__ import annotations

import ipaddress
from collections import Counter
from datetime import date, datetime
from io import BytesIO
from pathlib import Path
from typing import Any, Literal
from xml.sax.saxutils import escape

import reportlab
from openpyxl import load_workbook
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    Flowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.analysis import ingest_workbook
from app.hashes import file_sha256
from app.r13 import R13Finding, evaluate_r13

ReportType = Literal["executive", "technical"]


class ReportContentMismatchError(ValueError):
    """El resultado del análisis no corresponde al workbook usado para el PDF."""
SOURCE_FIELDS = (
    "Destination",
    "Log_Source",
    "Event_Description",
    "Process_CommandLine",
    "Result",
    "Severity",
)
SOURCE_FIELD_LABELS = {
    "Severity": "Severity (valor original del evento)",
}


class _ObservationPageState:
    page_number: int | None = None
    continuation_pages: set[int]

    def __init__(self) -> None:
        self.page_number = None
        self.continuation_pages = set()


class _ObservationPageAnchor(Flowable):
    def __init__(self, state: _ObservationPageState) -> None:
        super().__init__()
        self.state = state
        self.width = 0
        self.height = 0

    def wrap(self, available_width: float, available_height: float) -> tuple[float, float]:
        return 0, 0

    def draw(self) -> None:
        self.state.page_number = self.canv.getPageNumber()


class _EvidenceContinuation(Flowable):
    def __init__(
        self,
        rule_id: str,
        state: _ObservationPageState,
        font_name: str,
        font_size: float,
        leading: float,
    ) -> None:
        super().__init__()
        self.rule_id = rule_id
        self.state = state
        self.font_name = font_name
        self.font_size = font_size
        self.leading = leading
        self.width = 0
        self.height = 0
        self._is_continuation = False

    def wrap(self, available_width: float, available_height: float) -> tuple[float, float]:
        page_number = self.canv.getPageNumber()
        self._is_continuation = (
            self.state.page_number is not None
            and page_number > self.state.page_number
            and page_number not in self.state.continuation_pages
        )
        self.width = available_width
        self.height = self.leading if self._is_continuation else 0
        return self.width, self.height

    def draw(self) -> None:
        page_number = self.canv.getPageNumber()
        if (
            self._is_continuation
            and page_number not in self.state.continuation_pages
        ):
            self.canv.setFont(self.font_name, self.font_size)
            self.canv.setFillColor(colors.HexColor("#263F52"))
            self.canv.drawString(
                0,
                1,
                f"{self.rule_id} · continuación de evidencias",
            )
            self.state.continuation_pages.add(page_number)


def _register_fonts() -> tuple[str, str]:
    fonts_dir = Path(reportlab.__file__).parent / "fonts"
    regular_path = fonts_dir / "Vera.ttf"
    bold_path = fonts_dir / "VeraBd.ttf"
    if regular_path.is_file() and bold_path.is_file():
        if "SOCVera" not in pdfmetrics.getRegisteredFontNames():
            pdfmetrics.registerFont(TTFont("SOCVera", str(regular_path)))
        if "SOCVera-Bold" not in pdfmetrics.getRegisteredFontNames():
            pdfmetrics.registerFont(TTFont("SOCVera-Bold", str(bold_path)))
        return "SOCVera", "SOCVera-Bold"
    return "Helvetica", "Helvetica-Bold"


def _source_records(content: bytes) -> tuple[dict[str, Any], set[str]]:
    workbook = load_workbook(BytesIO(content), read_only=True, data_only=True)
    try:
        worksheet = workbook["SIEM Export"]
        rows = worksheet.iter_rows(values_only=True)
        headers = next(rows)
        columns = {value: index for index, value in enumerate(headers) if isinstance(value, str)}
        by_id: dict[str, dict[str, Any]] = {}
        duplicates: set[str] = set()
        for row in rows:
            log_id_value = row[columns["Log_ID"]] if columns["Log_ID"] < len(row) else None
            if log_id_value is None:
                continue
            log_id = str(log_id_value)
            if log_id in by_id:
                duplicates.add(log_id)
                by_id.pop(log_id, None)
                continue
            if log_id not in duplicates:
                by_id[log_id] = {
                    field: row[index] if index < len(row) else None
                    for field, index in columns.items()
                    if field in SOURCE_FIELDS
                }
        return by_id, duplicates
    finally:
        workbook.close()


def _display(value: Any) -> str:
    if value is None:
        return "Vacío en el registro original"
    if isinstance(value, datetime):
        return value.isoformat(sep=" ")
    if isinstance(value, date):
        return value.isoformat()
    return str(value)


def _require_result_matches_content(
    result: dict[str, Any], content: bytes
) -> None:
    expected = result.get("file_sha256")
    if (
        not isinstance(expected, str)
        or len(expected) != 64
        or any(character not in "0123456789abcdef" for character in expected)
    ):
        raise ReportContentMismatchError(
            "El resultado del análisis no contiene un SHA-256 hexadecimal válido."
        )
    try:
        actual = file_sha256(content)
    except TypeError as exc:
        raise ReportContentMismatchError(
            "El contenido del workbook no permite calcular su SHA-256."
        ) from exc
    if actual != expected:
        raise ReportContentMismatchError(
            "El resultado del análisis no corresponde al contenido del workbook."
        )


def _timezone_description(status: Any) -> str:
    if status == "undefined":
        return (
            "La zona horaria no está definida en este contrato parcial ni "
            "determinada por el análisis disponible; los timestamps se presentan "
            "tal como fueron recibidos, sin conversión."
        )
    if status is None:
        return "La zona horaria no está especificada."
    return f"Estado de zona horaria informado: {status}."


def _r13_findings(content: bytes) -> dict[str, R13Finding]:
    ingestion = ingest_workbook(content)
    evaluation = evaluate_r13(
        ingestion.r13_events,
        externally_conflicting_log_ids=ingestion.r13_conflicting_log_ids,
    )
    return {finding.source_ip_key: finding for finding in evaluation.findings}


def _r13_evidence_groups(
    observation: dict[str, Any],
    findings: dict[str, R13Finding],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    source_ip = next(
        (
            item.get("Source_IP")
            for item in observation["evidence"]
            if item.get("Source_IP") is not None
        ),
        None,
    )
    if not isinstance(source_ip, str):
        raise ValueError("La observación R13 no contiene Source_IP.")
    try:
        source_ip_key = ipaddress.ip_address(source_ip).compressed
    except ValueError as exc:
        raise ValueError("La observación R13 contiene Source_IP inválida.") from exc

    finding = findings.get(source_ip_key)
    if finding is None:
        raise ValueError(
            "No se pudo reproducir la ventana R13 para la evidencia del informe."
        )
    all_ids = tuple(
        str(item["Log_ID"])
        for item in observation["evidence"]
        if item.get("Log_ID") is not None
    )
    qualifying_ids = finding.qualifying_window_log_ids
    if not set(qualifying_ids).issubset(all_ids):
        raise ValueError(
            "La ventana R13 reproducida no coincide con la evidencia de la observación."
        )
    qualifying_set = set(qualifying_ids)
    contextual_ids = tuple(log_id for log_id in all_ids if log_id not in qualifying_set)
    return qualifying_ids, contextual_ids


def _shared_evidence_description(result: dict[str, Any]) -> str | None:
    rules_by_log_id: dict[str, set[str]] = {}
    for observation in result["observations"]:
        for evidence in observation["evidence"]:
            log_id = evidence.get("Log_ID")
            if log_id is not None:
                rules_by_log_id.setdefault(str(log_id), set()).add(
                    observation["rule_id"]
                )
    shared = [
        f'{log_id} ({", ".join(sorted(rule_ids))})'
        for log_id, rule_ids in sorted(rules_by_log_id.items())
        if len(rule_ids) > 1
    ]
    if not shared:
        return None
    return (
        "Un mismo Log_ID puede respaldar más de una regla; su reutilización no "
        "representa eventos independientes. Evidencia compartida: "
        + "; ".join(shared)
        + "."
    )


def _r08_evidence_summary(observation: dict[str, Any]) -> str | None:
    evidence = observation["evidence"]
    primary = [
        item
        for item in evidence
        if item.get("Event_ID") == "4688" and item.get("Log_ID") is not None
    ]
    if not primary:
        return None
    primary_ids = {str(item["Log_ID"]) for item in primary}
    related_by_rule: dict[str, list[str]] = {"R07": [], "R09": []}
    other_related: list[str] = []
    for item in evidence:
        log_id = item.get("Log_ID")
        if log_id is None or str(log_id) in primary_ids:
            continue
        event_id = item.get("Event_ID")
        if event_id == "4663":
            related_by_rule["R07"].append(str(log_id))
        elif event_id == "PROXY_ACCESS":
            related_by_rule["R09"].append(str(log_id))
        else:
            other_related.append(str(log_id))

    parts = [
        "Evidencia primaria R08: " + ", ".join(sorted(primary_ids)) + "."
    ]
    for rule_id, log_ids in related_by_rule.items():
        if log_ids:
            parts.append(
                f"Asociación temporal/identitaria {rule_id} "
                f"({len(log_ids)} registros): {', '.join(sorted(log_ids))}."
            )
    if other_related:
        parts.append(
            "Otras evidencias asociadas: " + ", ".join(sorted(other_related)) + "."
        )
    parts.append(
        "La asociación no demuestra causalidad, transferencia exitosa ni exfiltración."
    )
    return " ".join(parts)


def _paragraph(text: Any, style: ParagraphStyle) -> Paragraph:
    escaped = escape(str(text)).replace("\r\n", "\n").replace("\n", "<br/>")
    return Paragraph(escaped, style)


def _styles() -> tuple[dict[str, ParagraphStyle], str, str]:
    regular_font, bold_font = _register_fonts()
    base = getSampleStyleSheet()
    styles = {
        "title": ParagraphStyle(
            "ReportTitle",
            parent=base["Title"],
            fontName=bold_font,
            fontSize=20,
            leading=25,
            textColor=colors.HexColor("#12334A"),
            alignment=TA_LEFT,
            spaceAfter=8,
        ),
        "section": ParagraphStyle(
            "ReportSection",
            parent=base["Heading2"],
            fontName=bold_font,
            fontSize=13,
            leading=17,
            textColor=colors.HexColor("#116B84"),
            spaceBefore=10,
            spaceAfter=6,
        ),
        "subheading": ParagraphStyle(
            "ReportSubheading",
            parent=base["Heading3"],
            fontName=bold_font,
            fontSize=10,
            leading=13,
            textColor=colors.HexColor("#263F52"),
            spaceBefore=6,
            spaceAfter=3,
        ),
        "body": ParagraphStyle(
            "ReportBody",
            parent=base["BodyText"],
            fontName=regular_font,
            fontSize=8.5,
            leading=12,
            splitLongWords=1,
            spaceAfter=4,
        ),
        "small": ParagraphStyle(
            "ReportSmall",
            parent=base["BodyText"],
            fontName=regular_font,
            fontSize=7,
            leading=9,
            splitLongWords=1,
        ),
        "table_header": ParagraphStyle(
            "ReportTableHeader",
            parent=base["BodyText"],
            fontName=bold_font,
            fontSize=7,
            leading=9,
            textColor=colors.white,
            splitLongWords=1,
        ),
        "table_body": ParagraphStyle(
            "ReportTableBody",
            parent=base["BodyText"],
            fontName=regular_font,
            fontSize=7,
            leading=9,
            splitLongWords=1,
        ),
    }
    return styles, regular_font, bold_font


def _metadata_lines(result: dict[str, Any], styles: dict[str, ParagraphStyle]) -> list[Any]:
    analysis_id = result["analysis_id"] or "No evaluable"
    lines = [
        ("Identificador del análisis", analysis_id),
        ("SHA-256 del archivo", result["file_sha256"]),
        ("Contrato", result["contract"]),
        ("Schema / canon", f'{result["schema_version"]} / {result["canon_version"]}'),
        ("Estado", result["status"]),
    ]
    return [
        _paragraph(f"{label}: {value}", styles["body"])
        for label, value in lines
    ]


def _header_footer(canvas: Any, document: Any, title: str, regular_font: str) -> None:
    canvas.saveState()
    canvas.setFont(regular_font, 7)
    canvas.setFillColor(colors.HexColor("#64798A"))
    canvas.drawString(18 * mm, 12 * mm, f"SOC L2 Analyzer · {title}")
    canvas.drawRightString(A4[0] - 18 * mm, 12 * mm, f"Página {document.page}")
    canvas.restoreState()


def _document(title: str, story: list[Any], result: dict[str, Any]) -> bytes:
    styles, regular_font, _ = _styles()
    output = BytesIO()
    document = SimpleDocTemplate(
        output,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=17 * mm,
        bottomMargin=20 * mm,
        title=title,
        author="SOC L2 Analyzer",
        subject=f'Informe para el análisis {result["file_sha256"]}',
    )
    document.build(
        story,
        onFirstPage=lambda canvas, doc: _header_footer(canvas, doc, title, regular_font),
        onLaterPages=lambda canvas, doc: _header_footer(canvas, doc, title, regular_font),
    )
    return output.getvalue()


def build_executive_pdf(result: dict[str, Any], content: bytes) -> bytes:
    _require_result_matches_content(result, content)
    styles, _, _ = _styles()
    completeness = result["completeness"]
    observations = result["observations"]
    r13_findings = (
        _r13_findings(content)
        if any(item["rule_id"] == "R13" for item in observations)
        else {}
    )
    severities = Counter(
        item["severity"]
        for item in observations
        if item["severity"] is not None and item["severity_status"] == "ratified"
    )
    story: list[Any] = [
        _paragraph("Informe ejecutivo de análisis SIEM", styles["title"]),
        _paragraph(
            "Resultado parcial generado a partir de reglas deterministas. "
            "Las observaciones describen evidencia; no confirman incidentes, impacto ni atribución.",
            styles["body"],
        ),
        *_metadata_lines(result, styles),
        _paragraph("Alcance y metodología", styles["section"]),
        _paragraph(
            "Se procesó el workbook validado por la API y se aplicaron únicamente las "
            "reglas cuyo alcance figura como ejecutado o parcialmente ejecutado. "
            "No se presentan scoring ni severidades no evaluables como valores calculados. "
            "La severidad analítica ratificada es independiente del nivel y del score; "
            "por ejemplo, R11 puede tener severidad Medium con nivel y score no evaluables.",
            styles["body"],
        ),
        _paragraph("Estadísticas del análisis", styles["section"]),
        _paragraph(
            f'Registros vistos: {completeness["records_seen"]}; '
            f'evaluados globalmente: {completeness["records_evaluated"]}; '
            f'no evaluables globalmente: {completeness["records_not_evaluable"]}. '
            "El alcance y la evaluación por regla se detallan en la cobertura técnica.",
            styles["body"],
        ),
        _paragraph(
            f'Reglas ejecutadas: {completeness["rules_executed"]}; '
            f'parciales: {completeness["rules_partially_executed"]}; '
            f'pendientes: {completeness["rules_pending"]}; '
            f'no evaluables: {completeness["rules_not_evaluable"]}.',
            styles["body"],
        ),
        _paragraph(f"Observaciones emitidas: {len(observations)}.", styles["body"]),
        _paragraph("Severidades ratificadas", styles["section"]),
    ]
    if severities:
        story.extend(
            _paragraph(f"{name}: {count}", styles["body"])
            for name, count in sorted(severities.items())
        )
    else:
        story.append(
            _paragraph(
                "No hay severidades definidas en las observaciones de este resultado.",
                styles["body"],
            )
        )

    story.append(_paragraph("Hallazgos y evidencia relevante", styles["section"]))
    shared_evidence = _shared_evidence_description(result)
    if shared_evidence:
        story.append(_paragraph(shared_evidence, styles["body"]))
    if not observations:
        story.append(
            _paragraph(
                "No se emitieron observaciones. Esto significa que no hubo coincidencias "
                "en los predicados implementados; no demuestra ausencia de actividad.",
                styles["body"],
            )
        )
    for observation in observations:
        ids = ", ".join(
            str(item["Log_ID"]) for item in observation["evidence"] if item["Log_ID"] is not None
        ) or "No disponible"
        detail = [
            _paragraph(
                f'{observation["rule_id"]} · {observation["rule_name"]}',
                styles["subheading"],
            ),
            _paragraph(observation["description"], styles["body"]),
        ]
        if observation["rule_id"] == "R13":
            qualifying_ids, contextual_ids = _r13_evidence_groups(
                observation,
                r13_findings,
            )
            metrics = r13_findings[
                ipaddress.ip_address(
                    next(
                        item["Source_IP"]
                        for item in observation["evidence"]
                        if item.get("Source_IP") is not None
                    )
                ).compressed
            ].metrics
            detail.append(
                _paragraph(
                    f"Log_ID de la ventana que sustenta las métricas "
                    f"({metrics.request_count} solicitudes): "
                    f'{", ".join(qualifying_ids)}.',
                    styles["body"],
                )
            )
            if contextual_ids:
                detail.append(
                    _paragraph(
                        f"Evidencia adicional de otras ventanas calificantes "
                        f"({len(contextual_ids)} registros; no integra las métricas "
                        f"anteriores): {', '.join(contextual_ids)}.",
                        styles["body"],
                    )
                )
        elif observation["rule_id"] == "R08":
            summary = _r08_evidence_summary(observation)
            if summary:
                detail.append(_paragraph(summary, styles["body"]))
            else:
                detail.append(_paragraph(f"Log_ID: {ids}.", styles["body"]))
        else:
            detail.append(_paragraph(f"Log_ID: {ids}.", styles["body"]))
        detail.extend(
            [
                _paragraph(
                    f"Severidad: {observation['severity'] or 'No definida'}; "
                    f'nivel: {observation["level"] if observation["level"] is not None else "No evaluable"}; '
                    f'score: {observation["score_1e4"] if observation["score_1e4"] is not None else "No evaluable"}.',
                    styles["body"],
                ),
            _paragraph(
                f'Impacto demostrado: {"Sí" if observation["impact_demonstrated"] else "No"}; '
                f'atribución de incidente: {"Sí" if observation["incident_attribution"] else "No"}.',
                styles["body"],
                ),
            ]
        )
        story.append(KeepTogether(detail))

    story.append(_paragraph("Recomendaciones de validación", styles["section"]))
    if observations:
        for observation in observations:
            ids = ", ".join(
                str(item["Log_ID"])
                for item in observation["evidence"]
                if item["Log_ID"] is not None
            ) or "sin Log_ID disponible"
            story.append(
                _paragraph(
                    f'Revisar la evidencia fuente de {observation["rule_id"]} '
                    f"({ids}) y contrastarla con registros autorizados del entorno. "
                    "Esta recomendación no confirma actividad maliciosa ni impacto.",
                    styles["body"],
                )
            )
    else:
        story.append(
            _paragraph(
                "No se generan recomendaciones específicas al no existir observaciones.",
                styles["body"],
            )
        )

    story.append(_paragraph("Limitaciones", styles["section"]))
    story.append(
        _paragraph(
            _timezone_description(result["timezone_status"])
            + " "
            "Scoring y cadenas no ratificadas o no evaluables no se completan ni se infieren. "
            f'La cadena C2 permanece en estado '
            f'{result["chain_execution"]["C2"]["status"]}; no se presenta como incidente '
            "ni se le asigna score operativo. "
            "Las direcciones clasificadas como documentation, incluidos los rangos "
            "RFC 5737, no representan conexiones operativas a Internet. "
            "La validación de snapshots IANA no autentica el origen ni demuestra "
            "conectividad real. "
            "El informe refleja exclusivamente el resultado parcial de esta ejecución.",
            styles["body"],
        )
    )
    return _document("Informe Ejecutivo", story, result)


def _technical_rule_table(result: dict[str, Any], styles: dict[str, ParagraphStyle]) -> Table:
    data = [[
        _paragraph(value, styles["table_header"])
        for value in ("Regla", "Nombre", "Estado", "En alcance", "Evaluados", "Obs.")
    ]]
    for rule_id, rule in sorted(result["rule_execution"].items()):
        data.append([
            _paragraph(rule_id, styles["table_body"]),
            _paragraph(rule["name"], styles["table_body"]),
            _paragraph(rule["status"], styles["table_body"]),
            _paragraph(str(rule["records_in_scope"]), styles["table_body"]),
            _paragraph(str(rule["records_evaluated"]), styles["table_body"]),
            _paragraph(str(rule["matched_observation_count"]), styles["table_body"]),
        ])
    table = Table(data, colWidths=(17 * mm, 48 * mm, 31 * mm, 23 * mm, 23 * mm, 14 * mm), repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#173A50")),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#B8C6D0")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), (colors.white, colors.HexColor("#F2F6F8"))),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    return table


def build_technical_pdf(result: dict[str, Any], content: bytes) -> bytes:
    _require_result_matches_content(result, content)
    styles, _, _ = _styles()
    source_by_id, duplicate_ids = _source_records(content)
    observations = result["observations"]
    r13_findings = (
        _r13_findings(content)
        if any(item["rule_id"] == "R13" for item in observations)
        else {}
    )
    story: list[Any] = [
        _paragraph("Informe técnico de análisis SIEM", styles["title"]),
        _paragraph(
            "Alcance parcial. Los valores que no fueron evaluables se identifican como tales; "
            "las correlaciones no materializadas no se presentan como cadenas confirmadas. "
            "Una severidad analítica ratificada, como Medium para R11, es independiente "
            "del nivel y del score; esos campos pueden seguir no evaluables.",
            styles["body"],
        ),
        *_metadata_lines(result, styles),
        _paragraph("Integridad y metadatos", styles["section"]),
        _paragraph(
            f'Archivo identificado por SHA-256: {result["file_sha256"]}. '
            f'Filas vistas: {result["completeness"]["records_seen"]}; '
            f'filas evaluadas: {result["completeness"]["records_evaluated"]}.',
            styles["body"],
        ),
        _paragraph("Cobertura R01–R13", styles["section"]),
        _technical_rule_table(result, styles),
        _paragraph("Cadenas y correlaciones", styles["section"]),
    ]
    for chain_id, chain in sorted(result["chain_execution"].items()):
        story.append(
            _paragraph(
                f'{chain_id} · estado: {chain["status"]} · '
                f'ratificada: {"sí" if chain["ratified"] else "no"} · {chain["reason"]}',
                styles["body"],
            )
        )
    story.append(_paragraph("Observaciones y evidencia", styles["section"]))
    shared_evidence = _shared_evidence_description(result)
    if shared_evidence:
        story.append(_paragraph(shared_evidence, styles["body"]))
    if not observations:
        story.append(
            _paragraph(
                "No se emitieron observaciones bajo los predicados implementados. "
                "Esto no equivale a ausencia de actividad.",
                styles["body"],
            )
        )

    for observation in observations:
        story.append(PageBreak())
        page_state = _ObservationPageState()
        story.append(_ObservationPageAnchor(page_state))
        story.append(
            _paragraph(
                f'{observation["rule_id"]} · {observation["rule_name"]}',
                styles["subheading"],
            )
        )
        story.append(_paragraph(observation["description"], styles["body"]))
        story.append(
            _paragraph(
                f'Severidad: {observation["severity"] or "No definida"} '
                f'({observation["severity_status"]}); nivel: '
                f'{observation["level"] if observation["level"] is not None else "No evaluable"} '
                f'({observation["level_status"]}); score: '
                f'{observation["score_1e4"] if observation["score_1e4"] is not None else "No evaluable"}; '
                f'confidence: '
                f'{observation["confidence_basis_points"] if observation["confidence_basis_points"] is not None else "No evaluable"}.',
                styles["body"],
            )
        )
        story.append(
            _paragraph(
                f'Impacto demostrado: {"Sí" if observation["impact_demonstrated"] else "No"}; '
                f'atribución de incidente: {"Sí" if observation["incident_attribution"] else "No"}.',
                styles["body"],
            )
        )
        if observation["rule_id"] == "R13":
            qualifying_ids, contextual_ids = _r13_evidence_groups(
                observation,
                r13_findings,
            )
            source_ip = next(
                item["Source_IP"]
                for item in observation["evidence"]
                if item.get("Source_IP") is not None
            )
            metrics = r13_findings[ipaddress.ip_address(source_ip).compressed].metrics
            story.append(
                _paragraph(
                    f"Log_ID de la ventana que sustenta las métricas "
                    f"({metrics.request_count} solicitudes): "
                    f'{", ".join(qualifying_ids)}.',
                    styles["body"],
                )
            )
            if contextual_ids:
                story.append(
                    _paragraph(
                        f"Evidencia adicional de otras ventanas calificantes "
                        f"({len(contextual_ids)} registros; no integra las métricas "
                        f"anteriores): {', '.join(contextual_ids)}.",
                        styles["body"],
                    )
                )
        elif observation["rule_id"] == "R08":
            summary = _r08_evidence_summary(observation)
            if summary:
                story.append(_paragraph(summary, styles["body"]))
        story.append(_paragraph("Evidencia", styles["subheading"]))
        for evidence in observation["evidence"]:
            log_id_value = evidence["Log_ID"]
            log_id = str(log_id_value) if log_id_value is not None else None
            evidence_parts = [
                f'Log_ID: {_display(log_id_value)}',
                f'Timestamp: {_display(evidence["Timestamp"])}',
                f'Hostname: {_display(evidence["Hostname"])}',
                f'Event_ID: {_display(evidence["Event_ID"])}',
                f'User: {_display(evidence["User"])}',
                f'Source_IP: {_display(evidence["Source_IP"])}',
                f'Categoría IP: {_display(evidence["source_ip_category"])}',
                f'Fuente de clasificación IP: {_display(evidence["ip_classification_source"])}',
                f'Validación del snapshot IANA: {_display(evidence["ip_registry_validation_status"])}',
            ]
            if log_id is None:
                evidence_parts.append("Campos adicionales: no disponibles sin Log_ID.")
            elif log_id in duplicate_ids:
                evidence_parts.append(
                    "Campos originales adicionales: omitidos porque Log_ID no es único."
                )
            elif log_id not in source_by_id:
                evidence_parts.append(
                    "Campos originales adicionales: no encontrados para este Log_ID."
                )
            else:
                evidence_parts.extend(
                    f"{SOURCE_FIELD_LABELS.get(field, field)}: "
                    f"{_display(source_by_id[log_id].get(field))}"
                    for field in SOURCE_FIELDS
                )
            evidence_paragraph = _paragraph(
                " · ".join(evidence_parts),
                styles["small"],
            )
            story.append(
                KeepTogether(
                    [
                        _EvidenceContinuation(
                            observation["rule_id"],
                            page_state,
                            styles["small"].fontName,
                            styles["small"].fontSize,
                            styles["small"].leading,
                        ),
                        evidence_paragraph,
                    ]
                )
            )

    story.extend([
        _paragraph("Recomendaciones técnicas", styles["section"]),
        _paragraph(
            "Para cada observación, validar el Log_ID y los campos originales asociados "
            "contra fuentes autorizadas y el contexto operativo. Esta verificación es una "
            "recomendación y no una afirmación de incidente.",
            styles["body"],
        ),
        _paragraph("Limitaciones metodológicas", styles["section"]),
        _paragraph(
            _timezone_description(result["timezone_status"])
            + " "
            f'Estado de clasificación IP: {result["ip_classification_status"]}. '
            "El estado verified indica que los snapshots IANA se validaron contra "
            "su manifiesto y hashes; no autentica la IP de origen ni demuestra "
            "conectividad real. Las categorías documentation (incluidos rangos "
            "RFC 5737) no se presentan como conexiones operativas a Internet. "
            "No se infieren causalidad, éxito, impacto, atribución, scoring ausente ni "
            "correlaciones que no estén materializadas en el resultado.",
            styles["body"],
        ),
    ])
    return _document("Informe Técnico", story, result)


def build_pdf_report(
    report_type: ReportType, result: dict[str, Any], content: bytes
) -> bytes:
    if report_type == "executive":
        return build_executive_pdf(result, content)
    return build_technical_pdf(result, content)
