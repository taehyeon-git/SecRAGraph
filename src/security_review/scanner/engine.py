"""Deterministic, non-executing source scanning engine."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from hashlib import sha256
from pathlib import PurePosixPath
from re import Match

from security_review.domain.models import Finding
from security_review.scanner.redaction import redact_match
from security_review.scanner.rules import DEFAULT_RULES, Rule


def _extension(file_path: str) -> str:
    path = PurePosixPath(file_path.replace("\\", "/"))
    if path.name.lower() == ".env":
        return ".env"
    return path.suffix.lower()


def _redacted_value(match: Match[str], rule: Rule, extension: str) -> str | None:
    if rule.redaction_group is None:
        return None
    raw_value = match.group(rule.redaction_group)
    quoted = raw_value.startswith(('"', "'"))
    if not quoted and extension not in {".env", ".ini", ".yaml", ".yml", ".toml"}:
        return None
    if extension == ".py":
        separator = match.string[match.end("key") : match.start("secret")]
        if ":" in separator and "=" not in separator and "{" not in match.string[: match.start()]:
            return None
    value = raw_value.strip("\"'")
    if len(value) < rule.minimum_redacted_length:
        return None
    if rule.placeholder_pattern is not None and rule.placeholder_pattern.fullmatch(value):
        return None
    return value


def _active_source_at(line: str, position: int, extension: str) -> bool:
    """Ignore secret-looking text inside a quoted example or line comment."""

    quote: str | None = None
    escaped = False
    for index, char in enumerate(line[:position]):
        if quote is not None:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        elif char in {'"', "'", "`"}:
            quote = char
        elif char == "#" and extension in {".py", ".yaml", ".yml", ".toml", ".ini", ".env"}:
            return False
        elif char == "/" and extension in {".js", ".ts"} and line[index : index + 2] == "//":
            return False
    return quote is None


def _eligible_matches(line: str, rule: Rule, extension: str) -> tuple[Match[str], ...]:
    matches: list[Match[str]] = []
    for match in rule.pattern.finditer(line):
        if rule.category == "secret":
            if not _active_source_at(line, match.start(), extension):
                continue
            if extension in {".py", ".js", ".ts"} and line[match.start()] in {'"', "'"}:
                before = line[: match.start()].rstrip()
                if not before or before[-1] not in "{,":
                    continue
        if rule.redaction_group is not None and _redacted_value(match, rule, extension) is None:
            continue
        matches.append(match)
    return tuple(matches)


def _redact_line(line: str, rules: Sequence[Rule]) -> str:
    # Evidence includes the whole line, including comments and examples that do not
    # qualify as findings. Mask their secret-shaped values before any report sees it.
    spans = {
        match.span(rule.redaction_group)
        for rule in rules
        if rule.redaction_group is not None
        for match in rule.pattern.finditer(line)
    }
    redacted = line
    for span in sorted(spans, reverse=True):
        redacted = redact_match(redacted, span)
    return redacted.strip()


def finding_id(rule_id: str, path: str, line_number: int, redacted: str) -> str:
    """Build a stable identifier using redacted evidence only."""

    payload = f"{rule_id}\0{path}\0{line_number}\0{redacted}".encode()
    return f"{rule_id}:{sha256(payload).hexdigest()[:16]}"


def scan_text(
    file_path: str,
    text: str,
    rules: Sequence[Rule] = DEFAULT_RULES,
    *,
    should_stop: Callable[[], bool] | None = None,
) -> tuple[Finding, ...]:
    """Scan decoded source text with extension-scoped deterministic rules."""

    normalized_path = file_path.replace("\\", "/")
    extension = _extension(normalized_path)
    applicable_rules = tuple(rule for rule in rules if extension in rule.extensions)
    findings: dict[str, Finding] = {}
    for line_number, line in enumerate(text.splitlines(), start=1):
        if should_stop is not None and should_stop():
            break
        redacted_evidence = _redact_line(line, applicable_rules)
        for rule in applicable_rules:
            if should_stop is not None and should_stop():
                break
            for _match in _eligible_matches(line, rule, extension):
                identifier = finding_id(
                    rule.rule_id,
                    normalized_path,
                    line_number,
                    redacted_evidence,
                )
                finding = Finding(
                    id=identifier,
                    rule_id=rule.rule_id,
                    category=rule.category,
                    severity=rule.severity,
                    file_path=normalized_path,
                    line_start=line_number,
                    message=rule.message,
                    redacted_evidence=redacted_evidence,
                    confidence=rule.confidence,
                    cwe_ids=rule.cwe_ids,
                    remediation=rule.remediation,
                )
                existing = findings.get(identifier)
                if existing is not None and existing != finding:
                    raise RuntimeError(f"finding ID collision for {identifier}")
                findings[identifier] = finding
    return tuple(
        sorted(
            findings.values(),
            key=lambda item: (item.file_path, item.line_start, item.rule_id, item.id),
        )
    )
