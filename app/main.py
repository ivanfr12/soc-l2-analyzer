from typing import Any

from fastapi import FastAPI, File, HTTPException, UploadFile

from app.analysis import analyze_workbook
from app.config import (
    ANALYSIS_SCHEMA_VERSION,
    CANON_VERSION,
    MAX_UPLOAD_BYTES,
    REQUIRED_COLUMNS,
    REQUIRED_SHEET,
)
from app.excel import WorkbookValidationError

app = FastAPI(
    title="SOC L2 Analyzer API",
)


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

        try:
            return analyze_workbook(content)
        except WorkbookValidationError as exc:
            raise HTTPException(
                status_code=exc.status_code,
                detail={"code": exc.code, "message": exc.message},
            ) from exc
    finally:
        await file.close()
