import os
from io import BytesIO
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from fastapi.testclient import TestClient
from openpyxl import Workbook

from app.config import MAX_UPLOAD_BYTES
from app.main import app

client = TestClient(app)


def make_workbook(sheet_name: str = "SIEM Export", columns: tuple[str, ...] | None = None) -> bytes:
    workbook = Workbook()
    worksheet = workbook.active
    worksheet.title = sheet_name
    if columns is not None:
        worksheet.append(columns)
        worksheet.append(["EVT-00001"] + [None] * (len(columns) - 1))
    stream = BytesIO()
    workbook.save(stream)
    return stream.getvalue()


def test_health_and_metadata() -> None:
    health_response = client.get("/health")
    meta_response = client.get("/meta")

    assert health_response.status_code == 200
    assert health_response.json() == {"status": "ok"}
    assert meta_response.status_code == 200
    assert meta_response.json()["max_upload_bytes"] == MAX_UPLOAD_BYTES
    assert meta_response.json()["analysis_available"] is True
    assert meta_response.json()["analysis_mode"] == "partial"


def test_swagger_documentation_is_available() -> None:
    docs_response = client.get("/docs")
    openapi_response = client.get("/openapi.json")

    assert docs_response.status_code == 200
    assert "swagger-ui" in docs_response.text.casefold()
    assert openapi_response.status_code == 200
    assert {
        "/health",
        "/meta",
        "/analyze",
        "/reports/executive",
        "/reports/technical",
    } <= set(
        openapi_response.json()["paths"]
    )


def test_valid_xlsx_returns_explicitly_partial_analysis() -> None:
    content = make_workbook(
        columns=(
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
    )
    response = client.post(
        "/analyze",
        files={
            "file": (
                "events.xlsx",
                content,
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            )
        },
    )

    assert response.status_code == 200
    result = response.json()
    assert result["contract"] == "analysis-partial/1"
    assert result["status"] == "partial"
    assert result["analysis_id"].startswith("A-")
    assert result["analysis_id_status"] == "provisional_unratified_vectors"
    assert result["content_sha256"] is not None
    assert result["content_sha256_status"] == "provisional_unratified_vectors"
    assert result["completeness"]["records_seen"] == 1
    assert result["rule_execution"]["R09"]["status"] == "executed"
    assert result["observations"] == []


def test_rejects_empty_file() -> None:
    response = client.post("/analyze", files={"file": ("events.xlsx", b"")})

    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "empty_file"


def test_rejects_corrupt_xlsx() -> None:
    response = client.post("/analyze", files={"file": ("events.xlsx", b"PK\x03\x04broken")})

    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "corrupt_xlsx"


def test_rejects_xlsx_with_corrupt_worksheet_xml_without_internal_error() -> None:
    content = make_workbook()
    corrupt = BytesIO()
    with ZipFile(BytesIO(content)) as original, ZipFile(
        corrupt, "w", ZIP_DEFLATED
    ) as changed:
        for item in original.infolist():
            item_content = original.read(item.filename)
            if item.filename == "xl/worksheets/sheet1.xml":
                item_content = b"<worksheet>"
            changed.writestr(item, item_content)

    response = client.post(
        "/analyze",
        files={"file": ("events.xlsx", corrupt.getvalue())},
    )

    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "corrupt_xlsx"
    assert "Traceback" not in response.text
    assert "ParseError" not in response.text


def test_rejects_non_xlsx_signature() -> None:
    response = client.post("/analyze", files={"file": ("events.xlsx", b"not an xlsx")})

    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "not_xlsx"


def test_rejects_upload_over_limit() -> None:
    response = client.post(
        "/analyze",
        files={"file": ("events.xlsx", b"x" * (MAX_UPLOAD_BYTES + 1))},
    )

    assert response.status_code == 413
    assert response.json()["detail"]["code"] == "file_too_large"


def test_rejects_missing_sheet() -> None:
    content = make_workbook(
        sheet_name="Wrong sheet",
        columns=("Log_ID", "Timestamp"),
    )
    response = client.post("/analyze", files={"file": ("events.xlsx", content)})

    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "missing_sheet"


def test_rejects_missing_columns() -> None:
    content = make_workbook(columns=("Log_ID", "Timestamp"))
    response = client.post("/analyze", files={"file": ("events.xlsx", content)})

    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "missing_columns"


def test_rejects_duplicate_columns() -> None:
    content = make_workbook(columns=("Log_ID", "Log_ID"))
    response = client.post("/analyze", files={"file": ("events.xlsx", content)})

    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "duplicate_columns"


def test_rejects_non_xlsx_extension() -> None:
    response = client.post("/analyze", files={"file": ("events.csv", b"data")})

    assert response.status_code == 415
    assert response.json()["detail"]["code"] == "invalid_extension"


def test_chains_happy_path_after_analyze() -> None:
    workbook_path = os.environ.get("SOC_L2_CHALLENGE_WORKBOOK")
    if not workbook_path:
        import pytest

        pytest.skip("Defina SOC_L2_CHALLENGE_WORKBOOK para probar chains.")

    content = Path(workbook_path).read_bytes()
    analyze_response = client.post(
        "/analyze",
        files={"file": ("challenge.xlsx", content, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")},
    )
    assert analyze_response.status_code == 200
    result = analyze_response.json()

    chains_response = client.post(
        "/chains",
        files={"file": ("challenge.xlsx", content, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")},
        data={"expected_file_sha256": result["file_sha256"]},
    )
    assert chains_response.status_code == 200
    payload = chains_response.json()
    assert payload["contract"] == "chain-execution/1"
    assert payload["file_sha256"] == result["file_sha256"]
    assert payload["semantics"] == "observed_sequence_candidate"

    chains = payload["chains"]
    assert set(chains) == {"C1", "C2", "C3", "C4", "C5", "C6", "C7"}
    assert chains["C1"]["status"] == "executed"
    assert chains["C1"]["level"] == 2
    assert chains["C1"]["severity"] == "Medium"
    assert chains["C1"]["reference_score_1e4"] == 4500
    assert len(chains["C1"]["evidence"]) == 35
    assert chains["C1"]["links"][0]["delta_seconds"] == 232
    assert chains["C3"]["status"] == "executed"
    assert chains["C4"]["status"] == "executed"
    assert chains["C4"]["links"][0]["delta_seconds"] == 60
    assert chains["C5"]["status"] == "executed"
    assert len(chains["C5"]["contextual_evidence"]) == 5
    assert chains["C6"]["status"] == "executed"


def test_chains_preserves_c2_and_c7_ratified_states() -> None:
    workbook_path = os.environ.get("SOC_L2_CHALLENGE_WORKBOOK")
    if not workbook_path:
        import pytest

        pytest.skip("Defina SOC_L2_CHALLENGE_WORKBOOK para probar chains.")

    content = Path(workbook_path).read_bytes()
    analyze_response = client.post(
        "/analyze",
        files={"file": ("challenge.xlsx", content, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")},
    )
    result = analyze_response.json()
    chains_response = client.post(
        "/chains",
        files={"file": ("challenge.xlsx", content, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")},
        data={"expected_file_sha256": result["file_sha256"]},
    )
    chains = chains_response.json()["chains"]
    assert chains["C2"]["status"] == "pending_reconciliation"
    assert chains["C2"]["ratified"] is True
    assert chains["C7"]["status"] == "not_evaluable"
    assert chains["C7"]["ratified"] is False


def test_chains_cache_miss_returns_409() -> None:
    from app.hashes import file_sha256

    content = make_workbook(
        columns=(
            "Log_ID", "Timestamp", "Hostname", "Event_ID", "User", "Source_IP",
            "Destination", "Log_Source", "Event_Description", "Process_CommandLine",
            "Result", "Severity",
        )
    )
    # Make this workbook distinct from any analyzed in other tests so the cache
    # genuinely has no entry for it.
    import io as _io
    from openpyxl import Workbook as _Workbook

    wb = _Workbook()
    ws = wb.active
    ws.title = "SIEM Export"
    ws.append(
        ["Log_ID", "Timestamp", "Hostname", "Event_ID", "User", "Source_IP",
         "Destination", "Log_Source", "Event_Description", "Process_CommandLine",
         "Result", "Severity"]
    )
    ws.append(
        ["EVT-CACHE-MISS-UNIQUE", "2026-10-23 09:00:00", "DC-01", 4625,
         "CORP\\u", "10.10.1.1", "DC-01", "Security", "desc", None, "Failure", "Medium"]
    )
    stream = _io.BytesIO()
    wb.save(stream)
    content = stream.getvalue()

    expected = file_sha256(content)
    response = client.post(
        "/chains",
        files={"file": ("events.xlsx", content, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")},
        data={"expected_file_sha256": expected},
    )
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "analysis_not_cached"


def test_chains_hash_mismatch_returns_409() -> None:
    content = make_workbook(
        columns=(
            "Log_ID", "Timestamp", "Hostname", "Event_ID", "User", "Source_IP",
            "Destination", "Log_Source", "Event_Description", "Process_CommandLine",
            "Result", "Severity",
        )
    )
    response = client.post(
        "/chains",
        files={"file": ("events.xlsx", content, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")},
        data={"expected_file_sha256": "f" * 64},
    )
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "file_hash_mismatch"


def test_chains_does_not_modify_analyze_result() -> None:
    workbook_path = os.environ.get("SOC_L2_CHALLENGE_WORKBOOK")
    if not workbook_path:
        import pytest

        pytest.skip("Defina SOC_L2_CHALLENGE_WORKBOOK para probar chains.")

    content = Path(workbook_path).read_bytes()
    first = client.post(
        "/analyze",
        files={"file": ("challenge.xlsx", content, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")},
    ).json()
    client.post(
        "/chains",
        files={"file": ("challenge.xlsx", content, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")},
        data={"expected_file_sha256": first["file_sha256"]},
    )
    second = client.post(
        "/analyze",
        files={"file": ("challenge.xlsx", content, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")},
    ).json()
    assert first == second


def test_chains_defensive_copy_isolates_cache() -> None:
    workbook_path = os.environ.get("SOC_L2_CHALLENGE_WORKBOOK")
    if not workbook_path:
        import pytest

        pytest.skip("Defina SOC_L2_CHALLENGE_WORKBOOK para probar chains.")

    content = Path(workbook_path).read_bytes()
    result = client.post(
        "/analyze",
        files={"file": ("challenge.xlsx", content, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")},
    ).json()
    response = client.post(
        "/chains",
        files={"file": ("challenge.xlsx", content, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")},
        data={"expected_file_sha256": result["file_sha256"]},
    )
    payload = response.json()
    payload["chains"]["C1"]["status"] = "tampered"
    payload["chains"]["C1"]["evidence"].append("EVT-FAKE")

    second = client.post(
        "/chains",
        files={"file": ("challenge.xlsx", content, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")},
        data={"expected_file_sha256": result["file_sha256"]},
    ).json()
    assert second["chains"]["C1"]["status"] == "executed"
    assert "EVT-FAKE" not in second["chains"]["C1"]["evidence"]
    workbook_path = os.environ.get("SOC_L2_CHALLENGE_WORKBOOK")
    if not workbook_path:
        import pytest

        pytest.skip("Defina SOC_L2_CHALLENGE_WORKBOOK para probar la API con el dataset.")

    content = Path(workbook_path).read_bytes()
    response = client.post(
        "/analyze",
        files={"file": ("challenge.xlsx", content)},
    )
    repeated_response = client.post(
        "/analyze",
        files={"file": ("challenge.xlsx", content)},
    )

    assert response.status_code == 200
    assert repeated_response.status_code == 200
    result = response.json()
    assert repeated_response.json() == result
    assert result["status"] == "partial"
    assert result["completeness"]["records_evaluated"] == 715
    assert result["rule_execution"]["R03"]["matched_observation_count"] == 2
    assert result["rule_execution"]["R03"]["records_in_scope"] == 111
    assert result["rule_execution"]["R03"]["records_evaluated"] == 111
    assert result["rule_execution"]["R09"]["status"] == "executed"
    assert result["rule_execution"]["R09"]["records_in_scope"] == 22
    assert result["rule_execution"]["R09"]["records_evaluated"] == 22
    assert result["rule_execution"]["R09"]["matched_observation_count"] == 1
    assert result["rule_execution"]["R13"]["status"] == "executed"
    assert result["rule_execution"]["R13"]["records_in_scope"] == 21
    assert result["rule_execution"]["R13"]["records_evaluated"] == 21
    assert result["rule_execution"]["R13"]["matched_observation_count"] == 1
    assert result["contract"] == "analysis-partial/1"
