from __future__ import annotations

import os
from io import BytesIO
from pathlib import Path
import re
from typing import Any

import pytest
from fastapi.testclient import TestClient
from openpyxl import Workbook
from pypdf import PdfReader

from app.analysis import analyze_workbook
from app.hashes import file_sha256
from app.main import app
from app.pdf_reports import (
    ReportContentMismatchError,
    build_executive_pdf,
    build_pdf_report,
    build_technical_pdf,
)

client = TestClient(app)
REQUIRED_COLUMNS = (
    "Log_ID",
    "Timestamp",
    "Hostname",
    "Event_ID",
    "User",
    "Source_IP",
    "Destination",
    "Log_Source",
    "Event_Description",
    "Process_CommandLine",
    "Result",
    "Severity",
)


def make_workbook() -> bytes:
    workbook = Workbook()
    worksheet = workbook.active
    worksheet.title = "SIEM Export"
    worksheet.append(REQUIRED_COLUMNS)
    worksheet.append(
        [
            "EVT-00001",
            "2025-01-01T10:00:00",
            "HOST-01",
            "4624",
            "analyst",
            "192.0.2.10",
            "destination",
            "source",
            "Observed event",
            "command",
            "Success",
            "Medium",
        ]
    )
    output = BytesIO()
    workbook.save(output)
    return output.getvalue()


def _event_row(
    log_id: str,
    timestamp: str,
    event_id: object,
    *,
    hostname: str = "HOST-01",
    user: str = "analyst",
    source_ip: str = "192.0.2.10",
    destination: str | None = None,
    description: str = "Test event",
    command_line: str | None = None,
    result: object = "Success",
    severity: str = "Informational",
    log_source: str = "Test",
) -> list[object]:
    return [
        log_id,
        timestamp,
        hostname,
        event_id,
        user,
        source_ip,
        destination,
        log_source,
        description,
        command_line,
        result,
        severity,
    ]


_DOCUMENTED_HTTP_EVENTS = (
    ("00571", "12:10:00", "/uploads/test.aspx?cmd=whoami", 200),
    ("00572", "12:10:12", "/login?user=admin", 200),
    ("00573", "12:10:24", "/uploads/test.aspx?cmd=whoami", 404),
    ("00574", "12:10:36", "/uploads/test.aspx?cmd=whoami", 404),
    ("00576", "12:10:48", "/admin/", 500),
    ("00577", "12:11:00", "/api/v1/export", 200),
    ("00579", "12:11:12", "/login?user=admin", 200),
    ("00581", "12:11:24", "/admin/", 500),
    ("00582", "12:11:36", "/api/v1/export", 404),
    ("00583", "12:11:48", "/admin/", 500),
    ("00584", "12:12:00", "/admin/", 500),
    ("00585", "12:12:12", "/admin/", 404),
    ("00586", "12:12:24", "/login?user=admin", 500),
    ("00588", "12:12:36", "/api/v1/export", 404),
    ("00589", "12:12:48", "/login?user=admin", 500),
    ("00590", "12:13:00", "/api/v1/export", 500),
    ("00591", "12:13:12", "/login?user=admin", 404),
    ("00592", "12:13:24", "/login?user=admin", 200),
    ("00593", "12:13:36", "/login?user=admin", 500),
    ("00595", "12:13:48", "/login?user=admin", 500),
    ("00596", "12:14:00", "/api/v1/export", 200),
)


def _workbook_with_rows(rows: list[list[object]]) -> bytes:
    workbook = Workbook()
    worksheet = workbook.active
    worksheet.title = "SIEM Export"
    worksheet.append(REQUIRED_COLUMNS)
    for row in rows:
        worksheet.append(row)
    output = BytesIO()
    workbook.save(output)
    return output.getvalue()


def make_documented_web_scan_workbook() -> bytes:
    return _workbook_with_rows(
        [
            _event_row(
                f"EVT-{log_id}",
                f"2026-10-23 {time}",
                "HTTP_ACCESS",
                hostname="WEB-01",
                user="-",
                source_ip="192.0.2.91",
                description="HTTP request",
                command_line=uri,
                result=status,
                severity="Warning",
                log_source="HTTP",
            )
            for log_id, time, uri, status in _DOCUMENTED_HTTP_EVENTS
        ]
    )


def make_pdf_semantics_workbook() -> bytes:
    rows = []
    for index in range(10):
        rows.append(
            _event_row(
                f"EVT-R07-{index:02}",
                f"2026-10-23 09:00:{index:02}",
                4663,
                hostname="FS-01",
                user="CORP\\backupsvc",
                destination="\\\\FS-01\\Finance",
                description="File access",
                command_line=f"File access: document-{index}.xlsx",
                severity="Warning",
                log_source="Security",
            )
        )
    rows.append(
        _event_row(
            "EVT-00428",
            "2026-10-23 10:42:00",
            4688,
            hostname="WS-018",
            user="CORP\\rrojas",
            description="Process creation",
            command_line=(
                "7z.exe a C:\\Users\\Public\\archive.7z C:\\Legal\\*.docx"
            ),
            severity="High",
            log_source="Security",
        )
    )
    for index in range(10):
        rows.append(
            _event_row(
                f"EVT-R09-{index:02}",
                f"2026-10-23 10:{43 + index:02}:00",
                "PROXY_ACCESS",
                hostname="WS-018",
                user="CORP\\rrojas",
                source_ip="192.0.2.91",
                destination="203.0.113.88:443",
                description="Proxy access",
                command_line="bytes_out=100 uri=/upload",
                severity="Warning",
                log_source="Proxy",
            )
        )
    rows.append(
        _event_row(
            "EVT-00523",
            "2026-10-23 11:37:00",
            7045,
            hostname="APP-SRV01",
            user="CORP\\helpdesk",
            description="Service installation",
            command_line="ServiceName=Example; ImagePath=C:\\ProgramData\\svc.exe",
            severity="Warning",
            log_source="System",
        )
    )
    rows.append(
        _event_row(
            "EVT-00599",
            "2026-10-23 12:15:00",
            4688,
            hostname="WEB-01",
            user="IIS APPPOOL\\DefaultAppPool",
            description="Process creation",
            command_line="cmd.exe /c whoami",
            severity="Warning",
            log_source="Security",
        )
    )
    return _workbook_with_rows(rows)


@pytest.mark.parametrize(
    ("path", "filename"),
    [
        ("/reports/executive", "SOC_L2_Informe_Ejecutivo.pdf"),
        ("/reports/technical", "SOC_L2_Informe_Tecnico.pdf"),
    ],
)
def test_report_endpoint_returns_pdf_for_the_expected_file(
    path: str, filename: str
) -> None:
    content = make_workbook()
    response = client.post(
        path,
        files={"file": ("untrusted name.xlsx", content)},
        data={"expected_file_sha256": file_sha256(content)},
    )

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert response.headers["content-disposition"] == f'attachment; filename="{filename}"'
    assert response.headers["cache-control"] == "no-store"
    assert response.content.startswith(b"%PDF-")


def test_report_endpoint_rejects_a_hash_mismatch() -> None:
    content = make_workbook()
    response = client.post(
        "/reports/executive",
        files={"file": ("events.xlsx", content)},
        data={"expected_file_sha256": "0" * 64},
    )

    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "file_hash_mismatch"


def test_report_endpoint_rejects_invalid_workbooks() -> None:
    response = client.post(
        "/reports/technical",
        files={"file": ("events.xlsx", b"not an xlsx")},
        data={"expected_file_sha256": file_sha256(b"not an xlsx")},
    )

    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "not_xlsx"


def test_report_endpoint_requires_expected_sha256() -> None:
    content = make_workbook()
    response = client.post(
        "/reports/technical",
        files={"file": ("events.xlsx", content)},
    )

    assert response.status_code == 422


def test_builders_generate_pdf_when_result_matches_content() -> None:
    content = make_workbook()
    result = analyze_workbook(content)

    for builder in (build_executive_pdf, build_technical_pdf):
        pdf = builder(result, content)
        assert pdf.startswith(b"%PDF-")
        assert len(pdf) > 0


def test_builders_reject_result_from_another_workbook() -> None:
    content = make_workbook()
    other_result = analyze_workbook(make_documented_web_scan_workbook())

    for builder in (build_executive_pdf, build_technical_pdf):
        with pytest.raises(
            ReportContentMismatchError,
            match="no corresponde al contenido del workbook",
        ):
            builder(other_result, content)


def test_build_pdf_report_rejects_result_from_another_workbook() -> None:
    content = make_workbook()
    other_result = analyze_workbook(make_documented_web_scan_workbook())

    with pytest.raises(
        ReportContentMismatchError,
        match="no corresponde al contenido del workbook",
    ):
        build_pdf_report("executive", other_result, content)


@pytest.mark.parametrize("invalid_hash", [None, "", "not-a-hash", "0" * 63, 123])
def test_builders_reject_missing_or_invalid_hash(invalid_hash: object) -> None:
    content = make_workbook()
    result = dict(analyze_workbook(content))
    if invalid_hash is None:
        result.pop("file_sha256")
    else:
        result["file_sha256"] = invalid_hash

    for builder in (build_executive_pdf, build_technical_pdf):
        with pytest.raises(
            ReportContentMismatchError,
            match="SHA-256 hexadecimal válido",
        ):
            builder(result, content)


def test_builders_do_not_emit_partial_pdf_on_content_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    content = make_workbook()
    other_result = analyze_workbook(make_documented_web_scan_workbook())

    def fail_document(*args: object, **kwargs: object) -> bytes:
        raise AssertionError("No debe generarse un documento ante una inconsistencia.")

    monkeypatch.setattr("app.pdf_reports._document", fail_document)

    for builder in (build_executive_pdf, build_technical_pdf):
        with pytest.raises(
            ReportContentMismatchError,
            match="no corresponde al contenido del workbook",
        ):
            builder(other_result, content)


@pytest.fixture(scope="module")
def original_reports() -> dict[str, Any]:
    workbook_path = os.environ.get("SOC_L2_CHALLENGE_WORKBOOK")
    if not workbook_path:
        pytest.skip(
            "Defina SOC_L2_CHALLENGE_WORKBOOK para probar los informes con el dataset original."
        )

    content = Path(workbook_path).read_bytes()
    result = analyze_workbook(content)
    reports: dict[str, Any] = {"result": result, "text": {}}
    for report_type in ("executive", "technical"):
        response = client.post(
            f"/reports/{report_type}",
            files={"file": (Path(workbook_path).name, content)},
            data={"expected_file_sha256": file_sha256(content)},
        )
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/pdf"
        assert response.content.startswith(b"%PDF-")
        reader = PdfReader(BytesIO(response.content), strict=True)
        assert reader.pages
        extracted = [page.extract_text() or "" for page in reader.pages]
        assert all(text.strip() for text in extracted)
        reports["text"][report_type] = extracted
    return reports


def test_original_reports_open_and_contain_extractable_text(
    original_reports: dict[str, Any],
) -> None:
    for pages in original_reports["text"].values():
        assert pages
        assert all(text.strip() for text in pages)


def test_executive_report_distinguishes_seen_rows_and_pending_c2(
    original_reports: dict[str, Any],
) -> None:
    text = " ".join("\n".join(original_reports["text"]["executive"]).split())

    assert "Registros vistos: 715" in text
    assert "Registros en alcance:" not in text
    assert "alcance y la evaluación por regla" in text.casefold()
    assert "pending_reconciliation" in text
    assert "no se presenta como incidente" in text
    assert "score operativo" in text
    assert "C2" in text


def test_technical_report_preserves_evidence_rule_association_and_continuations(
    original_reports: dict[str, Any],
) -> None:
    pages = original_reports["text"]["technical"]
    result = original_reports["result"]
    expected_pairs = {
        (observation["rule_id"], str(evidence["Log_ID"]))
        for observation in result["observations"]
        for evidence in observation["evidence"]
        if evidence["Log_ID"] is not None
    }

    observed_pairs: set[tuple[str, str]] = set()
    for page_text in pages:
        current_rule: str | None = None
        for line in page_text.splitlines():
            continuation = re.match(
                r"^(R\d{2}) · continuación de evidencias$",
                line.strip(),
            )
            heading = re.match(r"^(R\d{2}) · ", line.strip())
            if continuation:
                current_rule = continuation.group(1)
            elif heading:
                current_rule = heading.group(1)
            if current_rule:
                observed_pairs.update(
                    (current_rule, log_id)
                    for log_id in re.findall(r"Log_ID: (EVT-[A-Za-z0-9_-]+)", line)
                )

    assert expected_pairs <= observed_pairs
    assert any("R13 · Enumeración web automatizada" in text for text in pages)
    assert any("Log_ID: EVT-" in text for text in pages)

    continued_pages = 0
    for page_text in pages[1:]:
        content_lines = [
            line.strip()
            for line in page_text.splitlines()
            if line.strip()
            and not line.startswith("SOC L2 Analyzer")
            and not re.fullmatch(r"Página \d+", line.strip())
        ]
        if content_lines and re.fullmatch(
            r"R\d{2} · continuación de evidencias",
            content_lines[0],
        ):
            assert sum(
                bool(
                    re.fullmatch(
                        r"R\d{2} · continuación de evidencias",
                        line.strip(),
                    )
                )
                for line in content_lines
            ) == 1
            assert len(content_lines) > 1
            assert content_lines[1].startswith("Log_ID: EVT-")
            continued_pages += 1
        elif content_lines and content_lines[0].startswith("Log_ID: EVT-"):
            assert re.fullmatch(
                r"R\d{2} · continuación de evidencias",
                content_lines[0],
            )
            continued_pages += 1
    assert continued_pages > 0


def test_technical_report_labels_original_severity_and_no_operational_scores(
    original_reports: dict[str, Any],
) -> None:
    text = " ".join("\n".join(original_reports["text"]["technical"]).split())
    result = original_reports["result"]

    assert "Severity (valor original del evento):" in text
    assert "Severidad: Medium (ratified)" in text
    assert "Severity: High" not in text
    assert all(
        observation["score_1e4"] is None
        and observation["confidence_basis_points"] is None
        for observation in result["observations"]
    )
    assert text.count("score: No evaluable") == len(result["observations"])
    assert not re.search(r"score:\s*(?!No evaluable\b)\S+", text)
    assert "estado: pending_reconciliation" in text
    assert not re.search(r"C2[^\n]*score:\s*(?!No evaluable\b)\S+", text)


def _report_text(path: str, content: bytes) -> str:
    response = client.post(
        path,
        files={"file": ("fixture.xlsx", content)},
        data={"expected_file_sha256": file_sha256(content)},
    )
    assert response.status_code == 200
    reader = PdfReader(BytesIO(response.content), strict=True)
    extracted = "\n".join(page.extract_text() or "" for page in reader.pages)
    # La extracción de PDF inserta saltos de línea por el ajuste de párrafo.
    # Se normaliza el espaciado para comparar frases completas sin alterar su
    # contenido; las aserciones conservan el texto íntegro.
    return " ".join(extracted.split())


def test_r13_reports_distinguish_metric_window_from_contextual_evidence() -> None:
    content = make_documented_web_scan_workbook()
    result = analyze_workbook(content)
    observation = next(
        item for item in result["observations"] if item["rule_id"] == "R13"
    )
    assert len(observation["evidence"]) == 21

    expected_window_ids = (
        "EVT-00571",
        "EVT-00572",
        "EVT-00573",
        "EVT-00574",
        "EVT-00576",
        "EVT-00577",
        "EVT-00579",
        "EVT-00581",
        "EVT-00582",
        "EVT-00583",
    )
    # Ambos informes declaran la limitación con redacción propia; se verifica la
    # frase efectiva de cada uno sin rebajar la comprobación semántica.
    ip_warning_by_report = {
        "/reports/executive": "no representan conexiones operativas a Internet",
        "/reports/technical": (
            "no se presentan como conexiones operativas a Internet"
        ),
    }
    for report_path in ("/reports/executive", "/reports/technical"):
        text = _report_text(report_path, content)
        assert "10 solicitudes" in text
        assert "10 resultados HTTP válidos" in text
        assert "6 respuestas 4xx/5xx" in text
        assert "7 solicitudes a rutas sensibles" in text
        assert "Log_ID de la ventana que sustenta las métricas" in text
        assert ", ".join(expected_window_ids) in text
        assert "Evidencia adicional de otras ventanas calificantes" in text
        assert "11 registros; no integra las métricas anteriores" in text
        for log_id, _, _, _ in _DOCUMENTED_HTTP_EVENTS:
            assert f"EVT-{log_id}" in text
        assert "La zona horaria no está definida en este contrato parcial" in text
        assert "undefined" not in text
        assert "documentation" in text
        assert ip_warning_by_report[report_path] in text


def test_pdf_explains_ratified_severity_is_independent_of_unavailable_score() -> None:
    content = make_pdf_semantics_workbook()
    result = analyze_workbook(content)
    r11 = next(item for item in result["observations"] if item["rule_id"] == "R11")

    assert r11["severity"] == "Medium"
    assert r11["severity_status"] == "ratified"
    assert r11["level"] is None
    assert r11["score_1e4"] is None

    text = _report_text("/reports/technical", content)
    assert "Medium (ratified)" in text
    assert "independiente del nivel y del score" in text
    assert "La zona horaria no está definida en este contrato parcial" in text
    assert "Estado de clasificación IP: verified" in text
    assert "no autentica la IP de origen" in text
    assert "undefined" not in text


def test_technical_pdf_summarizes_r08_r09_and_marks_reused_event_evidence() -> None:
    content = make_pdf_semantics_workbook()
    result = analyze_workbook(content)
    text = _report_text("/reports/technical", content)

    assert "Evidencia primaria R08: EVT-00428" in text
    assert "Asociación temporal/identitaria R09 (10 registros)" in text
    for index in range(10):
        log_id = f"EVT-R09-{index:02}"
        assert log_id in text
    assert "no demuestra causalidad, transferencia exitosa ni exfiltración" in text
    assert "EVT-00599 (R06, R12)" in text
    assert "su reutilización no representa eventos independientes" in text
    assert "cada valor distinto no equivale necesariamente a una lectura exitosa independiente" in text
    assert ("R06", "EVT-00599") in {
        (item["rule_id"], evidence["Log_ID"])
        for item in result["observations"]
        for evidence in item["evidence"]
    }
    assert ("R12", "EVT-00599") in {
        (item["rule_id"], evidence["Log_ID"])
        for item in result["observations"]
        for evidence in item["evidence"]
    }
