import copy
from collections import OrderedDict
from threading import Lock
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import Response

from app.analysis import analyze_workbook_detailed
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

#: Caché acotada de resultados de cadena producidos por el análisis.
#: Permite que ``POST /chains`` reutilice lo ya calculado sin volver a
#: evaluar reglas. No persiste nada en disco.
_CHAIN_CACHE_LIMIT = 8
_chain_cache: "OrderedDict[str, dict[str, Any]]" = OrderedDict()
_chain_cache_lock = Lock()


def _store_chains(file_hash: str, payload: dict[str, Any]) -> None:
    with _chain_cache_lock:
        _chain_cache[file_hash] = payload
        _chain_cache.move_to_end(file_hash)
        while len(_chain_cache) > _CHAIN_CACHE_LIMIT:
            _chain_cache.popitem(last=False)


def _load_chains(file_hash: str) -> dict[str, Any] | None:
    with _chain_cache_lock:
        payload = _chain_cache.get(file_hash)
        if payload is not None:
            _chain_cache.move_to_end(file_hash)
            return copy.deepcopy(payload)
        return None


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
        result, chains = analyze_workbook_detailed(content)
    except WorkbookValidationError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail={"code": exc.code, "message": exc.message},
        ) from exc
    _store_chains(
        result["file_sha256"],
        {
            "analysis_id": result["analysis_id"],
            "analysis_id_status": result["analysis_id_status"],
            "chains": chains,
        },
    )
    return result


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


@app.post("/chains")
async def chains(
    file: UploadFile = File(...),
    expected_file_sha256: str = Form(...),
) -> dict[str, Any]:
    """Expone el detalle de cadenas sin recalcular reglas.

    Reutiliza el resultado de cadena producido por ``POST /analyze``. Si el
    archivo no fue analizado en este proceso, responde 409 en lugar de volver a
    evaluar reglas.
    """

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
                        "Volvé a analizar el archivo antes de consultar cadenas."
                    ),
                },
            )
        cached = _load_chains(actual_hash)
        if cached is None:
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "analysis_not_cached",
                    "message": (
                        "No hay un análisis reciente para este archivo. "
                        "Ejecutá el análisis antes de consultar las cadenas."
                    ),
                },
            )
        return {
            "contract": "chain-execution/1",
            "file_sha256": actual_hash,
            "analysis_id": cached["analysis_id"],
            "analysis_id_status": cached["analysis_id_status"],
            "canon_version": CANON_VERSION,
            "semantics": "observed_sequence_candidate",
            "chains": cached["chains"],
        }
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
