from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import Response

from app.analysis import analyze_workbook
from app.config import (
    ANALYSIS_SCHEMA_VERSION,
    CANON_VERSION,
    MAX_UPLOAD_BYTES,
    REQUIRED_COLUMNS,
    REQUIRED_SHEET,
)
from app.excel import WorkbookValidationError
from app.hashes import file_sha256
from app.pdf_reports import build_pdf_report, ReportType

app = FastAPI(
    title="SOC L2 Analyzer API",
)

PDF_FILENAMES: dict[ReportType, str] = {
    "executive": "SOC_L2_Informe_Ejecutivo.pdf",
    "technical": "SOC_L2_Informe_Tecnico.pdf",
}


async def _read_upload(file: UploadFile) -> bytes:
    if not file.filename or not file.filename.lower().endswith(".xlsx"):
        raise HTTPException(
            status_code=415,
            detail={
                "code": "invalid_extension",
                "message": "El archivo debe tener extensión .xlsx.",
            },
        )

    content = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail={
                "code": "file_too_large",
                "message": "El archivo supera el límite de 10 MB.",
            },
        )
    return content


def _analyze_content(content: bytes) -> dict[str, Any]:
    try:
        return analyze_workbook(content)
    except WorkbookValidationError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": exc.code, "message": exc.message},
        ) from exc


async def _create_pdf_report(
    report_type: ReportType,
    file: UploadFile,
    expected_file_sha256: str,
) -> Response:
    try:
        content = await _read_upload(file)
        actual_hash = file_sha256(content)
        if actual_hash != expected_file_sha256:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "file_hash_mismatch",
                    "message": (
                        "El archivo no coincide con el análisis actual. "
                        "Volvé a analizar el archivo antes de exportar."
                    ),
                },
            )

        result = _analyze_content(content)
        pdf_content = build_pdf_report(report_type, result, content)
        return Response(
            content=pdf_content,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{PDF_FILENAMES[report_type]}"',
                "Cache-Control": "no-store",
            },
        )
    finally:
        await file.close()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/meta")
def metadata() -> dict[str, object]:
    return {
        "analysis_schema_version": ANALYSIS_SCHEMA_VERSION,
        "canon_version": CANON_VERSION,
        "max_upload_bytes": MAX_UPLOAD_BYTES,
        "required_sheet": REQUIRED_SHEET,
        "required_columns": list(REQUIRED_COLUMNS),
        "analysis_available": True,
        "analysis_mode": "partial",
    }


@app.post("/analyze")
async def analyze(file: UploadFile = File(...)) -> dict[str, Any]:
    try:
        return _analyze_content(await _read_upload(file))
    finally:
        await file.close()


@app.post("/reports/executive")
async def executive_report(
    file: UploadFile = File(...),
    expected_file_sha256: str = Form(...),
) -> Response:
    return await _create_pdf_report("executive", file, expected_file_sha256)


@app.post("/reports/technical")
async def technical_report(
    file: UploadFile = File(...),
    expected_file_sha256: str = Form(...),
) -> Response:
    return await _create_pdf_report("technical", file, expected_file_sha256)
