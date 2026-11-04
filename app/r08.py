from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Literal, Mapping

R08_WINDOW = timedelta(minutes=15)
R08_ARCHIVE_TOOLS = frozenset(
    {"7z.exe", "7z", "rar.exe", "rar", "tar.exe", "tar", "compress-archive"}
)

DestinationKind = Literal["local_staging", "network_destination"]


@dataclass(frozen=True)
class R08Event:
    log_id: str | None
    timestamp: datetime | None
    hostname: object
    user: object
    process_command_line: object
    event_id: str | None
    content_signature: tuple[tuple[type, Any], ...]
    evidence: Mapping[str, Any] | None


@dataclass(frozen=True)
class R08ArchiveCommand:
    tool: str
    output_path: str
    destination_kind: DestinationKind


@dataclass(frozen=True)
class R08Finding:
    event: R08Event
    archive: R08ArchiveCommand
    evidence: tuple[Mapping[str, Any], ...]
    related_r07_log_ids: tuple[str, ...]
    related_r09_log_ids: tuple[str, ...]


@dataclass(frozen=True)
class R08Evaluation:
    findings: tuple[R08Finding, ...]
    records_evaluated: int
    identical_duplicates_collapsed: int
    conflicting_log_ids: tuple[str, ...]
    conflicting_record_count: int
    missing_log_id_count: int
    invalid_timestamp_log_ids: tuple[str, ...]
    incomplete_identity_log_ids: tuple[str, ...]
    invalid_command_log_ids: tuple[str, ...]
    unsupported_command_log_ids: tuple[str, ...]
    invalid_output_path_log_ids: tuple[str, ...]
    missing_evidence_log_ids: tuple[str, ...]
    unrelated_log_ids: tuple[str, ...]


def _tokenize(command_line: str) -> tuple[str, ...] | None:
    tokens: list[str] = []
    current: list[str] = []
    quote: str | None = None

    for character in command_line:
        if character in ("'", '"'):
            if quote is None:
                quote = character
            elif quote == character:
                quote = None
            else:
                current.append(character)
        elif character.isspace() and quote is None:
            if current:
                tokens.append("".join(current))
                current.clear()
        else:
            current.append(character)

    if quote is not None:
        return None
    if current:
        tokens.append("".join(current))
    return tuple(tokens)


def _tool_name(token: str) -> str:
    return token.replace("/", "\\").rsplit("\\", 1)[-1].casefold()


def _archive_output(tokens: tuple[str, ...], tool: str) -> str | None:
    lowered = tuple(token.casefold() for token in tokens)

    if tool in ("7z.exe", "7z", "rar.exe", "rar"):
        if (
            len(tokens) < 3
            or lowered[1] != "a"
            or tokens[2].startswith("-")
        ):
            return None
        return tokens[2]

    if tool in ("tar.exe", "tar"):
        index = 1
        creates_archive = False
        output_paths: list[str] = []
        while index < len(tokens):
            token = tokens[index]
            lowered_token = token.casefold()
            if lowered_token == "-c":
                creates_archive = True
            if lowered_token in ("-f", "--file"):
                if index + 1 >= len(tokens) or tokens[index + 1].startswith("-"):
                    return None
                output_paths.append(tokens[index + 1])
                index += 2
                continue
            if lowered_token.startswith("--file="):
                output_paths.append(token[len("--file=") :])
            elif not token.startswith("-"):
                break
            index += 1
        if creates_archive and len(output_paths) == 1:
            return output_paths[0]
        return None

    if tool == "compress-archive":
        output_paths: list[str] = []
        index = 1
        while index < len(tokens):
            token = tokens[index]
            lowered_token = token.casefold()
            if lowered_token == "-destinationpath":
                if index + 1 >= len(tokens):
                    return None
                output_paths.append(tokens[index + 1])
                index += 2
                continue
            if lowered_token.startswith("-destinationpath:"):
                output_paths.append(token[len("-destinationpath:") :])
            elif lowered_token.startswith("-destinationpath="):
                output_paths.append(token[len("-destinationpath=") :])
            index += 1
        return output_paths[0] if len(output_paths) == 1 else None

    return None


def _destination_kind(path: str) -> DestinationKind | None:
    windows_path = path.replace("/", "\\")
    folded_path = windows_path.casefold()
    if any(component in (".", "..") for component in windows_path.split("\\")):
        return None
    for root in (r"c:\temp", "%temp%", r"c:\users\public"):
        folded_root = root.casefold()
        if folded_path == folded_root or folded_path.startswith(folded_root + "\\"):
            return "local_staging"

    if windows_path.startswith("\\\\") and not windows_path.startswith(
        ("\\\\?\\", "\\\\.\\", "\\\\??\\")
    ):
        components = [component for component in windows_path[2:].split("\\") if component]
        if len(components) >= 2:
            return "network_destination"
    return None


def parse_archive_command(command_line: str) -> R08ArchiveCommand | None:
    tokens = _tokenize(command_line)
    if not tokens:
        return None

    tool = _tool_name(tokens[0])
    if tool not in R08_ARCHIVE_TOOLS:
        return None

    output_path = _archive_output(tokens, tool)
    if not output_path:
        return None
    destination_kind = _destination_kind(output_path)
    if destination_kind is None:
        return None

    return R08ArchiveCommand(
        tool=tool,
        output_path=output_path,
        destination_kind=destination_kind,
    )


def _valid_identity(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _parse_timestamp(value: object) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is not None and parsed.utcoffset() is not None:
        return None
    return parsed


def _related_evidence(
    values: tuple[Mapping[str, Any], ...],
) -> tuple[tuple[str, datetime, str, str, Mapping[str, Any]], ...]:
    result: list[tuple[str, datetime, str, str, Mapping[str, Any]]] = []
    for evidence in values:
        log_id = evidence.get("Log_ID")
        timestamp = _parse_timestamp(evidence.get("Timestamp"))
        hostname = evidence.get("Hostname")
        user = evidence.get("User")
        if (
            not isinstance(log_id, str)
            or not log_id.strip()
            or timestamp is None
            or not _valid_identity(hostname)
            or not _valid_identity(user)
        ):
            continue
        result.append((log_id, timestamp, hostname, user, evidence))
    return tuple(result)


def evaluate_r08(
    events: tuple[R08Event, ...],
    *,
    r07_evidence: tuple[Mapping[str, Any], ...] = (),
    r09_evidence: tuple[Mapping[str, Any], ...] = (),
    externally_conflicting_log_ids: tuple[str, ...] = (),
) -> R08Evaluation:
    events_by_id: dict[str, list[R08Event]] = {}
    missing_log_id_count = 0
    for event in events:
        if event.event_id != "4688":
            continue
        if event.log_id is None or not event.log_id.strip():
            missing_log_id_count += 1
            continue
        events_by_id.setdefault(event.log_id, []).append(event)

    conflicting_ids = set(externally_conflicting_log_ids)
    conflicting_ids.update(
        log_id
        for log_id, versions in events_by_id.items()
        if len({event.content_signature for event in versions}) > 1
    )
    conflicting_log_ids = tuple(sorted(conflicting_ids.intersection(events_by_id)))
    conflicting_record_count = sum(
        len(events_by_id[log_id]) for log_id in conflicting_log_ids
    )

    identical_duplicates_collapsed = 0
    unique_events: list[R08Event] = []
    for log_id, versions in events_by_id.items():
        if log_id in conflicting_ids:
            continue
        identical_duplicates_collapsed += len(versions) - 1
        unique_events.append(versions[0])

    valid_r07 = _related_evidence(r07_evidence)
    valid_r09 = _related_evidence(r09_evidence)
    invalid_timestamp_log_ids: list[str] = []
    incomplete_identity_log_ids: list[str] = []
    invalid_command_log_ids: list[str] = []
    unsupported_command_log_ids: list[str] = []
    invalid_output_path_log_ids: list[str] = []
    missing_evidence_log_ids: list[str] = []
    unrelated_log_ids: list[str] = []
    findings: list[R08Finding] = []
    records_evaluated = 0

    for event in unique_events:
        log_id = event.log_id or ""
        event_time = _parse_timestamp(event.timestamp)
        if event_time is None:
            invalid_timestamp_log_ids.append(log_id)
            continue
        if not _valid_identity(event.hostname) or not _valid_identity(event.user):
            incomplete_identity_log_ids.append(log_id)
            continue
        if (
            not isinstance(event.process_command_line, str)
            or not event.process_command_line.strip()
        ):
            invalid_command_log_ids.append(log_id)
            continue

        tokens = _tokenize(event.process_command_line)
        if not tokens or _tool_name(tokens[0]) not in R08_ARCHIVE_TOOLS:
            unsupported_command_log_ids.append(log_id)
            continue
        archive = parse_archive_command(event.process_command_line)
        if archive is None:
            invalid_output_path_log_ids.append(log_id)
            continue
        if (
            event.evidence is None
            or event.evidence.get("Log_ID") != event.log_id
            or _parse_timestamp(event.evidence.get("Timestamp")) != event_time
            or event.evidence.get("Hostname") != event.hostname
            or event.evidence.get("User") != event.user
        ):
            missing_evidence_log_ids.append(log_id)
            continue
        records_evaluated += 1

        lower_bound = event_time - R08_WINDOW
        upper_bound = event_time + R08_WINDOW

        def matches(
            evidence: tuple[str, datetime, str, str, Mapping[str, Any]],
        ) -> bool:
            _, timestamp, hostname, user, _ = evidence
            return (
                hostname == event.hostname
                and user == event.user
                and lower_bound <= timestamp <= upper_bound
            )

        related_r07 = tuple(item for item in valid_r07 if matches(item))
        related_r09 = tuple(item for item in valid_r09 if matches(item))
        if not related_r07 and not related_r09:
            unrelated_log_ids.append(log_id)
            continue

        evidence_by_id: dict[str, Mapping[str, Any]] = {
            log_id: event.evidence or {}
        }
        for related in (*related_r07, *related_r09):
            evidence_by_id.setdefault(related[0], related[4])
        ordered_evidence = tuple(
            sorted(
                evidence_by_id.values(),
                key=lambda evidence: (
                    _parse_timestamp(evidence.get("Timestamp")) or datetime.min,
                    evidence.get("Log_ID") or "",
                ),
            )
        )
        findings.append(
            R08Finding(
                event=event,
                archive=archive,
                evidence=ordered_evidence,
                related_r07_log_ids=tuple(sorted({item[0] for item in related_r07})),
                related_r09_log_ids=tuple(sorted({item[0] for item in related_r09})),
            )
        )

    findings.sort(key=lambda finding: (finding.event.timestamp, finding.event.log_id or ""))
    return R08Evaluation(
        findings=tuple(findings),
        records_evaluated=records_evaluated,
        identical_duplicates_collapsed=identical_duplicates_collapsed,
        conflicting_log_ids=conflicting_log_ids,
        conflicting_record_count=conflicting_record_count,
        missing_log_id_count=missing_log_id_count,
        invalid_timestamp_log_ids=tuple(sorted(invalid_timestamp_log_ids)),
        incomplete_identity_log_ids=tuple(sorted(incomplete_identity_log_ids)),
        invalid_command_log_ids=tuple(sorted(invalid_command_log_ids)),
        unsupported_command_log_ids=tuple(sorted(unsupported_command_log_ids)),
        invalid_output_path_log_ids=tuple(sorted(invalid_output_path_log_ids)),
        missing_evidence_log_ids=tuple(sorted(missing_evidence_log_ids)),
        unrelated_log_ids=tuple(sorted(unrelated_log_ids)),
    )
