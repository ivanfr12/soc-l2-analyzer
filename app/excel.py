from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO
from xml.etree.ElementTree import ParseError
from zlib import error as ZlibError
from zipfile import BadZipFile

from openpyxl import load_workbook
from openpyxl.utils.exceptions import InvalidFileException

from app.config import REQUIRED_COLUMNS, REQUIRED_SHEET

XLSX_CONTENT_ERRORS = (
    BadZipFile,
    EOFError,
    InvalidFileException,
    OSError,
    ParseError,
    ValueError,
    KeyError,
    ZlibError,
)


@dataclass(frozen=True)
class WorkbookSummary:
    sheet_name: str
    columns: tuple[str, ...]
    record_count: int


class WorkbookValidationError(Exception):
    def __init__(self, code: str, message: str, status_code: int = 422) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


def inspect_workbook(content: bytes) -> WorkbookSummary:
    if not content:
        raise WorkbookValidationError("empty_file", "El archivo está vacío.")

    if not content.startswith(b"PK\x03\x04"):
        raise WorkbookValidationError(
            "not_xlsx", "El archivo no tiene una firma válida de XLSX."
        )

    try:
        workbook = load_workbook(BytesIO(content), read_only=True, data_only=True)
    except XLSX_CONTENT_ERRORS as exc:
        raise WorkbookValidationError(
            "corrupt_xlsx", "No se pudo abrir el archivo como un XLSX válido."
        ) from exc

    try:
        if REQUIRED_SHEET not in workbook.sheetnames:
            raise WorkbookValidationError(
                "missing_sheet",
                f"Falta la hoja requerida «{REQUIRED_SHEET}».",
            )

        worksheet = workbook[REQUIRED_SHEET]
        header_row = next(
            worksheet.iter_rows(min_row=1, max_row=1, values_only=True), None
        )
        if header_row is None or not any(value is not None for value in header_row):
            raise WorkbookValidationError(
                "empty_sheet", f"La hoja «{REQUIRED_SHEET}» no contiene encabezados."
            )

        columns = tuple(value for value in header_row if isinstance(value, str))
        if len(set(columns)) != len(columns):
            raise WorkbookValidationError(
                "duplicate_columns",
                f"La hoja «{REQUIRED_SHEET}» contiene encabezados duplicados.",
            )

        missing_columns = [column for column in REQUIRED_COLUMNS if column not in columns]
        if missing_columns:
            raise WorkbookValidationError(
                "missing_columns",
                "Faltan columnas requeridas: " + ", ".join(missing_columns) + ".",
            )

        record_count = sum(
            1
            for row in worksheet.iter_rows(min_row=2, values_only=True)
            if any(value is not None for value in row)
        )
        if record_count == 0:
            raise WorkbookValidationError(
                "empty_dataset", f"La hoja «{REQUIRED_SHEET}» no contiene registros."
            )

        return WorkbookSummary(
            sheet_name=REQUIRED_SHEET,
            columns=columns,
            record_count=record_count,
        )
    except XLSX_CONTENT_ERRORS as exc:
        raise WorkbookValidationError(
            "corrupt_xlsx", "No se pudo leer el contenido interno del XLSX."
        ) from exc
    finally:
        workbook.close()
