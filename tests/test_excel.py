import os
from io import BytesIO
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

import pytest
from openpyxl import Workbook

from app.excel import WorkbookValidationError, inspect_workbook
from app.hashes import file_sha256


def test_rejects_xlsx_with_malformed_workbook_xml() -> None:
    source = BytesIO()
    Workbook().save(source)
    corrupt = BytesIO()

    with ZipFile(source) as original, ZipFile(corrupt, "w", ZIP_DEFLATED) as changed:
        for item in original.infolist():
            content = original.read(item.filename)
            if item.filename == "xl/workbook.xml":
                content = b"<workbook>"
            changed.writestr(item, content)

    with pytest.raises(WorkbookValidationError) as error:
        inspect_workbook(corrupt.getvalue())

    assert error.value.code == "corrupt_xlsx"


def test_original_challenge_workbook_has_715_records() -> None:
    workbook_path = os.environ.get("SOC_L2_CHALLENGE_WORKBOOK")
    if not workbook_path:
        pytest.skip("Defina SOC_L2_CHALLENGE_WORKBOOK para validar el dataset original.")

    content = Path(workbook_path).read_bytes()
    summary = inspect_workbook(content)

    assert summary.sheet_name == "SIEM Export"
    assert len(summary.columns) == 12
    assert summary.record_count == 715
    assert (
        file_sha256(content)
        == "0e5d5de56da596bf6b279a07f51e29498ad86782256cd842f42328543708a0c9"
    )
