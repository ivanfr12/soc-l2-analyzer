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
