"""Validate the SARIF contracts needed by GitHub Code Scanning."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlsplit

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
FORBIDDEN_SENTINEL = "sk-test-never-render-this"


@dataclass(frozen=True)
class ValidationResult:
    errors: tuple[str, ...]


def _mapping(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _items(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def _uri_error(uri: object, repository_root: Path, tracked: set[str] | None) -> str | None:
    if not isinstance(uri, str) or not uri:
        return "artifact URI must be a nonempty string"
    parsed = urlsplit(uri)
    if parsed.query or parsed.fragment:
        return f"artifact URI must be a path: {uri}"
    if parsed.scheme or parsed.netloc:
        return f"artifact URI must be relative: {uri}"
    decoded = uri
    for _ in range(3):
        decoded = unquote(decoded)
        normalized = decoded.replace("\\", "/")
        if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
            return f"artifact URI must be relative: {uri}"
        if ".." in normalized.split("/"):
            return f"artifact URI has traversal: {uri}"
        if "%" not in decoded:
            break
    relative = Path(*normalized.split("/"))
    candidate = (repository_root / relative).resolve()
    source_root = (repository_root / "src").resolve()
    if (
        not candidate.is_relative_to(source_root)
        or not candidate.is_file()
        or (tracked is not None and relative.as_posix() not in tracked)
    ):
        return f"artifact URI must resolve to a repository src file: {uri}"
    return None


def _result_errors(
    result: object,
    index: int,
    base_ids: dict[str, Any],
    seen: set[str],
    repository_root: Path,
    tracked: set[str] | None,
) -> list[str]:
    errors: list[str] = []
    item = _mapping(result)
    fingerprint = _mapping(item.get("partialFingerprints")).get("primaryLocationLineHash")
    if not isinstance(fingerprint, str) or not fingerprint:
        errors.append(f"result {index} missing primaryLocationLineHash")
    elif fingerprint in seen:
        errors.append(f"duplicate primaryLocationLineHash: {fingerprint}")
    else:
        seen.add(fingerprint)

    locations = _items(item.get("locations"))
    if not locations:
        errors.append(f"result {index} missing location")
    for location in locations:
        physical = _mapping(_mapping(location).get("physicalLocation"))
        artifact = _mapping(physical.get("artifactLocation"))
        uri_error = _uri_error(artifact.get("uri"), repository_root, tracked)
        if uri_error:
            errors.append(uri_error)
        base_id = artifact.get("uriBaseId")
        if base_id is not None and base_id not in base_ids:
            errors.append(f"undeclared uriBaseId: {base_id}")
        region = _mapping(physical.get("region"))
        start = region.get("startLine")
        end = region.get("endLine")
        if type(start) is not int or start < 1:
            errors.append(f"result {index} startLine must be >= 1")
        if end is not None and (
            type(end) is not int or end < 1 or (isinstance(start, int) and end < start)
        ):
            errors.append(f"result {index} endLine must be >= startLine")
    return errors


def _tracked_source_paths(repository_root: Path) -> set[str]:
    if not (repository_root / ".git").exists():
        raise FileNotFoundError("not a Git checkout")
    result = subprocess.run(  # noqa: S603 - fixed git command, no shell or hooks
        ["git", "-C", str(repository_root), "ls-files", "-z", "--", "src"],  # noqa: S607
        capture_output=True,
        check=True,
    )
    return {item.decode("utf-8") for item in result.stdout.split(b"\0") if item}


def validate_sarif(path: Path, *, repository_root: Path | None = None) -> ValidationResult:
    """Check importable structure, safe locations, and stable recognized fingerprints."""

    root = (
        Path(__file__).resolve().parents[1]
        if repository_root is None
        else repository_root.resolve()
    )
    raw = path.read_text(encoding="utf-8")
    errors: list[str] = []
    if FORBIDDEN_SENTINEL in raw:
        errors.append("controlled fake secret leaked into SARIF")
    try:
        payload = _mapping(json.loads(raw))
    except json.JSONDecodeError:
        return ValidationResult((*errors, "invalid SARIF JSON"))
    if payload.get("$schema") != SCHEMA:
        errors.append("SARIF schema must be 2.1.0")
    if payload.get("version") != "2.1.0":
        errors.append("SARIF version must be 2.1.0")
    runs = _items(payload.get("runs"))
    if not runs:
        errors.append("SARIF must contain a run")
    try:
        tracked = _tracked_source_paths(root)
    except FileNotFoundError:
        return ValidationResult((*errors, "SARIF repository root is not a Git checkout"))
    except subprocess.CalledProcessError:
        return ValidationResult((*errors, "could not list tracked source files"))
    seen: set[str] = set()
    for run in runs:
        run_data = _mapping(run)
        driver = _mapping(_mapping(run_data.get("tool")).get("driver"))
        if driver.get("name") != "SecRAGraph":
            errors.append("SARIF driver name must be SecRAGraph")
        base_ids = _mapping(run_data.get("originalUriBaseIds"))
        if base_ids:
            errors.append("SARIF URI bases are not supported")
        for index, result in enumerate(_items(run_data.get("results"))):
            errors.extend(_result_errors(result, index, base_ids, seen, root, tracked))
    return ValidationResult(tuple(errors))


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: python scripts/validate_sarif.py PATH", file=sys.stderr)
        return 2
    try:
        validation = validate_sarif(Path(args[0]))
    except OSError as error:
        print(f"could not read SARIF: {error}", file=sys.stderr)
        return 2
    for message in validation.errors:
        print(message, file=sys.stderr)
    if validation.errors:
        return 1
    print("SARIF validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
