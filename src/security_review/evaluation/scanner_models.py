"""Validated synthetic scanner cases and exact-match labels."""

from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TypeAlias

from security_review.scanner.files import ScanLimits

FindingKey: TypeAlias = tuple[str, str, int]
CaseLabel: TypeAlias = tuple[str, int]

_RULE_ID = re.compile(r"[A-Z]{2,4}[0-9]{3}\Z")
_CASE_ID = re.compile(r"[a-z][a-z0-9-]*\Z")


@dataclass(frozen=True, slots=True)
class ScannerCase:
    """One invented source file with exhaustively assessed rule labels."""

    case_id: str
    file_path: str
    source: str
    expected: frozenset[CaseLabel]
    is_benign: bool
    expected_diagnostics: tuple[str, ...] = ()
    unassessed_rules: frozenset[str] = frozenset()


def _string_list(value: object, name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"{name} must be a list of nonempty strings")
    if len(value) != len(set(value)):
        raise ValueError(f"duplicate {name}")
    return tuple(value)


def _case_from_object(raw: object, limits: ScanLimits) -> ScannerCase:
    if not isinstance(raw, dict):
        raise ValueError("case must be an object")
    required = {
        "case_id",
        "file_path",
        "source",
        "expected",
        "is_benign",
        "expected_diagnostics",
        "unassessed_rules",
    }
    if set(raw) != required:
        raise ValueError(f"case fields must be exactly {sorted(required)}")

    case_id = raw["case_id"]
    if not isinstance(case_id, str) or not _CASE_ID.fullmatch(case_id):
        raise ValueError("case_id must be a lowercase hyphenated identifier")

    file_path = raw["file_path"]
    if not isinstance(file_path, str) or not file_path or "\\" in file_path:
        raise ValueError("file_path must be a relative POSIX path")
    logical_path = PurePosixPath(file_path)
    if (
        logical_path.is_absolute()
        or ".." in logical_path.parts
        or "." in logical_path.parts
        or ":" in logical_path.parts[0]
        or logical_path.as_posix() != file_path
    ):
        raise ValueError("file_path must remain inside the temporary case directory")
    extension = ".env" if logical_path.name.lower() == ".env" else logical_path.suffix.lower()
    if extension not in limits.allowed_extensions:
        raise ValueError(f"unsupported extension: {extension or '<none>'}")

    source = raw["source"]
    if not isinstance(source, str) or not source.strip():
        raise ValueError("source must not be blank")
    if len(source.encode("utf-8")) > limits.max_file_bytes:
        raise ValueError("source is too large")

    labels = raw["expected"]
    if not isinstance(labels, list):
        raise ValueError("expected must be a list")
    parsed_labels: list[CaseLabel] = []
    line_count = len(source.splitlines())
    for label in labels:
        if not isinstance(label, dict) or set(label) != {"rule_id", "line_start"}:
            raise ValueError("label must contain rule_id and line_start")
        rule_id, line_start = label["rule_id"], label["line_start"]
        if not isinstance(rule_id, str) or not _RULE_ID.fullmatch(rule_id):
            raise ValueError("invalid rule_id")
        if (
            isinstance(line_start, bool)
            or not isinstance(line_start, int)
            or not (1 <= line_start <= line_count)
        ):
            raise ValueError("invalid line_start")
        parsed_labels.append((rule_id, line_start))
    if len(parsed_labels) != len(set(parsed_labels)):
        raise ValueError("duplicate label")

    is_benign = raw["is_benign"]
    if not isinstance(is_benign, bool) or is_benign != (not parsed_labels):
        raise ValueError("is_benign must equal the absence of expected labels")

    expected_diagnostics = _string_list(raw["expected_diagnostics"], "expected_diagnostics")
    unassessed_rules = _string_list(raw["unassessed_rules"], "unassessed_rules")
    if any(not _RULE_ID.fullmatch(rule_id) for rule_id in unassessed_rules):
        raise ValueError("invalid unassessed_rules rule_id")
    if {rule_id for rule_id, _ in parsed_labels}.intersection(unassessed_rules):
        raise ValueError("a labeled rule cannot also be unassessed")
    if unassessed_rules and not expected_diagnostics:
        raise ValueError("unassessed_rules require expected_diagnostics")
    if extension == ".py" and not expected_diagnostics:
        try:
            ast.parse(source)
        except (SyntaxError, RecursionError) as error:
            raise ValueError("invalid Python syntax without expected_diagnostics") from error

    return ScannerCase(
        case_id=case_id,
        file_path=file_path,
        source=source,
        expected=frozenset(parsed_labels),
        is_benign=is_benign,
        expected_diagnostics=expected_diagnostics,
        unassessed_rules=frozenset(unassessed_rules),
    )


def load_scanner_cases(path: Path) -> tuple[ScannerCase, ...]:
    """Load and reject ambiguous labels before any source reaches the scanner."""

    manifest = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or set(manifest) != {"schema_version", "cases"}:
        raise ValueError("manifest must contain schema_version and cases")
    if manifest["schema_version"] != 1:
        raise ValueError("unsupported schema_version")
    raw_cases = manifest["cases"]
    if not isinstance(raw_cases, list) or not raw_cases:
        raise ValueError("cases must be a nonempty list")
    limits = ScanLimits()
    cases = tuple(_case_from_object(raw, limits) for raw in raw_cases)
    ids = [case.case_id for case in cases]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate case_id")
    return cases
