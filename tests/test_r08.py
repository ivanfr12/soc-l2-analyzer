from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

import pytest

from app.r08 import R08Event, evaluate_r08, parse_archive_command

_BASE_TIME = datetime(2026, 10, 23, 10, 42)


def _event(
    log_id: str | None,
    *,
    command: object = r"7z.exe a C:\Users\Public\archive.7z C:\Legal\*.docx",
    timestamp: datetime | None = _BASE_TIME,
    hostname: object = "WS-018",
    user: object = r"CORP\rrojas",
    event_id: str | None = "4688",
    signature: str | None = None,
) -> R08Event:
    return R08Event(
        log_id=log_id,
        timestamp=timestamp,
        hostname=hostname,
        user=user,
        process_command_line=command,
        event_id=event_id,
        content_signature=((str, signature if signature is not None else str(log_id)),),
        evidence=(
            {
                "Log_ID": log_id,
                "Timestamp": timestamp.isoformat() if timestamp else None,
                "Hostname": hostname,
                "User": user,
                "Event_ID": event_id,
            }
            if timestamp is not None
            else None
        ),
    )


def _related(
    log_id: str,
    *,
    timestamp: datetime = _BASE_TIME,
    hostname: str = "WS-018",
    user: str = r"CORP\rrojas",
) -> dict[str, Any]:
    return {
        "Log_ID": log_id,
        "Timestamp": timestamp.isoformat(),
        "Hostname": hostname,
        "User": user,
        "Event_ID": "PROXY_ACCESS",
    }


@pytest.mark.parametrize(
    ("command", "tool", "path", "kind"),
    [
        (
            r"7z.exe a C:\Users\Public\archive.7z C:\Legal\*.docx",
            "7z.exe",
            r"C:\Users\Public\archive.7z",
            "local_staging",
        ),
        (
            r'"C:\Program Files\7-Zip\7z.exe" a "%TEMP%\archive.7z" source',
            "7z.exe",
            r"%TEMP%\archive.7z",
            "local_staging",
        ),
        (
            r"7z a C:\Temp\archive.7z source",
            "7z",
            r"C:\Temp\archive.7z",
            "local_staging",
        ),
        (
            r"rar.exe a C:\Temp\archive.rar source",
            "rar.exe",
            r"C:\Temp\archive.rar",
            "local_staging",
        ),
        (
            r"rar a \\fileserver\share\archive.rar source",
            "rar",
            r"\\fileserver\share\archive.rar",
            "network_destination",
        ),
        (
            r"tar.exe -a -c -f C:\Temp\finance.zip C:\Temp\reports",
            "tar.exe",
            r"C:\Temp\finance.zip",
            "local_staging",
        ),
        (
            r"tar -a -c -f \\fileserver\share\finance.tar C:\Temp\reports",
            "tar",
            r"\\fileserver\share\finance.tar",
            "network_destination",
        ),
        (
            r'Compress-Archive -Path "C:\Input Folder\*.docx" -DestinationPath "%TEMP%\archive.zip"',
            "compress-archive",
            r"%TEMP%\archive.zip",
            "local_staging",
        ),
        (
            r"Compress-Archive -Path source -DestinationPath \\fileserver\share\archive.zip",
            "compress-archive",
            r"\\fileserver\share\archive.zip",
            "network_destination",
        ),
    ],
)
def test_recognizes_ratified_tools_and_extracts_unambiguous_output(
    command: str, tool: str, path: str, kind: str
) -> None:
    parsed = parse_archive_command(command)

    assert parsed is not None
    assert parsed.tool == tool
    assert parsed.output_path == path
    assert parsed.destination_kind == kind


@pytest.mark.parametrize(
    "command",
    [
        r"foo7z.exe a C:\Temp\archive.7z source",
        r"powershell.exe -Command Compress-Archive -Path source -DestinationPath C:\Temp\out.zip",
        r"7z.exe x C:\Temp\archive.7z",
        r"rar.exe l C:\Temp\archive.rar",
        r"tar.exe -c C:\Temp\finance.zip C:\Temp\reports",
        r"tar.exe -x -f C:\Temp\archive.tar",
        r"tar.exe -f C:\Temp\archive.tar C:\Temp\reports",
        r"zip.exe a C:\Temp\archive.zip source",
        r"7zip.exe a C:\Temp\archive.7z source",
        r"7z.exe a C:\Other\archive.7z source",
        r"7z.exe a C:\Tempest\archive.7z source",
        r"7z.exe a C:\Temp\..\Windows\archive.7z source",
        r"7z.exe a \\server source",
        r'7z.exe a "C:\Temp\archive.7z source',
        r"Compress-Archive -Path C:\in -DestinationPath C:\Other\out.zip",
    ],
)
def test_rejects_unratified_tools_accidental_tokens_and_ambiguous_routes(
    command: str,
) -> None:
    assert parse_archive_command(command) is None


def test_local_staging_is_not_classified_as_public_network_destination() -> None:
    parsed = parse_archive_command(
        r"7z.exe a C:\Users\Public\archive.7z C:\Legal\*.docx"
    )

    assert parsed is not None
    assert parsed.destination_kind == "local_staging"


def test_event_requires_a_qualified_related_finding() -> None:
    result = evaluate_r08((_event("archive"),))

    assert result.findings == ()
    assert result.records_evaluated == 1
    assert result.unrelated_log_ids == ("archive",)


@pytest.mark.parametrize(
    ("offset", "included"),
    [
        (-timedelta(minutes=15), True),
        (timedelta(minutes=15), True),
        (-timedelta(minutes=15, seconds=1), False),
        (timedelta(minutes=15, seconds=1), False),
    ],
)
def test_correlation_window_is_inclusive_and_anchored_on_r08(
    offset: timedelta, included: bool
) -> None:
    result = evaluate_r08(
        (_event("archive"),),
        r07_evidence=(_related("related", timestamp=_BASE_TIME + offset),),
    )

    assert bool(result.findings) is included


@pytest.mark.parametrize(
    "identity",
    [
        {"hostname": "ws-018"},
        {"hostname": "WS-018 "},
        {"hostname": "WS-019"},
        {"user": r"corp\rrojas"},
        {"user": r"CORP\rrojas "},
        {"user": r"OTHER\rrojas"},
        {"hostname": ""},
        {"user": None},
    ],
)
def test_correlation_requires_exact_complete_hostname_and_user(
    identity: dict[str, object],
) -> None:
    related = _related("related")
    if "hostname" in identity:
        related["Hostname"] = identity["hostname"]
    if "user" in identity:
        related["User"] = identity["user"]

    result = evaluate_r08((_event("archive"),), r07_evidence=(related,))

    assert result.findings == ()


def test_r07_or_r09_relationships_are_independent_and_both_are_preserved() -> None:
    event = _event("archive")
    only_r07 = evaluate_r08((event,), r07_evidence=(_related("r07"),))
    only_r09 = evaluate_r08((event,), r09_evidence=(_related("r09"),))
    both = evaluate_r08(
        (event,),
        r07_evidence=(_related("same"),),
        r09_evidence=(_related("same"),),
    )

    assert only_r07.findings[0].related_r07_log_ids == ("r07",)
    assert only_r07.findings[0].related_r09_log_ids == ()
    assert only_r09.findings[0].related_r07_log_ids == ()
    assert only_r09.findings[0].related_r09_log_ids == ("r09",)
    assert both.findings[0].related_r07_log_ids == ("same",)
    assert both.findings[0].related_r09_log_ids == ("same",)
    assert [item["Log_ID"] for item in both.findings[0].evidence] == ["archive", "same"]


def test_only_qualified_source_evidence_with_valid_timestamp_and_identity_relates() -> None:
    invalid_items = (
        {"Log_ID": "bad-time", "Timestamp": "invalid", "Hostname": "WS-018", "User": r"CORP\rrojas"},
        {"Log_ID": "no-host", "Timestamp": _BASE_TIME.isoformat(), "User": r"CORP\rrojas"},
        {"Log_ID": "no-user", "Timestamp": _BASE_TIME.isoformat(), "Hostname": "WS-018"},
        {"Log_ID": "aware-time", "Timestamp": "2026-10-23T10:42:00+00:00", "Hostname": "WS-018", "User": r"CORP\rrojas"},
    )

    result = evaluate_r08((_event("archive"),), r07_evidence=invalid_items)

    assert result.findings == ()


def test_identical_duplicate_is_collapsed_and_conflicting_versions_are_excluded() -> None:
    event = _event("duplicate")
    duplicate_result = evaluate_r08(
        (event, event),
        r09_evidence=(_related("linked"),),
    )
    conflicting_result = evaluate_r08(
        (
            event,
            _event("duplicate", command=r"rar.exe a C:\Temp\archive.rar source", signature="other"),
        ),
        r09_evidence=(_related("linked"),),
    )
    cross_event_conflict_result = evaluate_r08(
        (event,),
        r09_evidence=(_related("linked"),),
        externally_conflicting_log_ids=("duplicate",),
    )

    assert duplicate_result.identical_duplicates_collapsed == 1
    assert len(duplicate_result.findings) == 1
    assert conflicting_result.findings == ()
    assert conflicting_result.conflicting_log_ids == ("duplicate",)
    assert cross_event_conflict_result.findings == ()
    assert cross_event_conflict_result.conflicting_record_count == 1


def test_invalid_event_fields_and_non_4688_are_excluded() -> None:
    events = (
        _event("wrong-event", event_id="7036"),
        _event("invalid-time", timestamp=None),
        _event("invalid-host", hostname=7),
        _event("invalid-user", user=" "),
        _event("invalid-command", command=None),
        _event("unsupported-command", command="powershell.exe -NoProfile"),
        _event("no-output", command="tar.exe -c C:\\Temp\\reports"),
        _event(None),
    )
    result = evaluate_r08(events, r09_evidence=(_related("linked"),))

    assert result.findings == ()
    assert result.invalid_timestamp_log_ids == ("invalid-time",)
    assert result.incomplete_identity_log_ids == ("invalid-host", "invalid-user")
    assert result.invalid_command_log_ids == ("invalid-command",)
    assert result.unsupported_command_log_ids == ("unsupported-command",)
    assert result.invalid_output_path_log_ids == ("no-output",)
    assert result.missing_log_id_count == 1


def test_timezone_aware_event_timestamp_is_excluded_without_error() -> None:
    event = _event(
        "aware-time",
        timestamp=datetime.fromisoformat("2026-10-23T10:42:00+00:00"),
    )

    result = evaluate_r08((event,), r09_evidence=(_related("linked"),))

    assert result.findings == ()
    assert result.invalid_timestamp_log_ids == ("aware-time",)


def test_multiple_archive_events_produce_separate_deterministic_findings() -> None:
    later = _event("later", timestamp=_BASE_TIME + timedelta(minutes=1))
    earlier = _event("earlier", timestamp=_BASE_TIME)
    related = (_related("z-related"), _related("a-related"))

    forward = evaluate_r08((later, earlier), r07_evidence=related)
    reverse = evaluate_r08((earlier, later), r07_evidence=tuple(reversed(related)))

    assert forward == reverse
    assert [finding.event.log_id for finding in forward.findings] == ["earlier", "later"]
    assert len(forward.findings) == 2
    evidence_order = [item["Log_ID"] for item in forward.findings[0].evidence]
    assert evidence_order == ["a-related", "earlier", "z-related"]


def test_missing_or_nontext_identity_does_not_match_and_nontext_command_does_not_qualify() -> None:
    result = evaluate_r08(
        (
            _event("missing-host", hostname=None),
            _event("numeric-command", command=7),
        ),
        r09_evidence=(_related("linked"),),
    )

    assert result.findings == ()
    assert "missing-host" in result.incomplete_identity_log_ids
    assert "numeric-command" in result.invalid_command_log_ids


def test_repeated_evaluation_is_deterministic() -> None:
    args = (
        (_event("archive"),),
    )
    kwargs = {"r09_evidence": (_related("proxy"),)}

    assert evaluate_r08(*args, **kwargs) == evaluate_r08(*args, **kwargs)
