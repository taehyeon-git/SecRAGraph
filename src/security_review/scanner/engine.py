"""Deterministic, non-executing source scanning engine."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from hashlib import sha256
from pathlib import PurePosixPath
from re import Match

from security_review.domain.models import Finding
from security_review.scanner.node_tls import detect_node_tls_assignments
from security_review.scanner.python_calls import PythonCallScanStopped, detect_python_calls
from security_review.scanner.redaction import redact_match
from security_review.scanner.rules import DEFAULT_RULES, Rule

PROCESSING_TIME_LIMIT_EXCEEDED = "processing_time_limit_exceeded"
PYTHON_SYNTAX_ERROR = "python_syntax_error"
_PYTHON_CALL_RULES = frozenset({"PY001", "PY002", "PY003", "PY004"})


@dataclass(frozen=True, slots=True)
class ScanTextResult:
    """Findings plus stable coverage diagnostics for one decoded file."""

    findings: tuple[Finding, ...]
    warnings: tuple[str, ...] = ()


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
    if rule.pattern is None:
        return ()
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
        if rule.redaction_group is not None and rule.pattern is not None
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


def scan_text_detailed(
    file_path: str,
    text: str,
    rules: Sequence[Rule] = DEFAULT_RULES,
    *,
    should_stop: Callable[[], bool] | None = None,
) -> ScanTextResult:
    """Scan decoded source text and report any incomplete assessment."""

    normalized_path = file_path.replace("\\", "/")
    extension = _extension(normalized_path)
    applicable_rules = tuple(rule for rule in rules if extension in rule.extensions)
    regex_rules = tuple(rule for rule in applicable_rules if rule.pattern is not None)
    python_rules = {
        rule.rule_id: rule
        for rule in applicable_rules
        if extension == ".py" and rule.pattern is None and rule.rule_id in _PYTHON_CALL_RULES
    }
    node_tls_rule = next(
        (rule for rule in applicable_rules if rule.rule_id == "JS001" and rule.pattern is None),
        None,
    )
    findings: dict[str, Finding] = {}
    warnings: list[str] = []
    lines = text.splitlines()

    def add_finding(rule: Rule, line_number: int, redacted_evidence: str) -> None:
        identifier = finding_id(rule.rule_id, normalized_path, line_number, redacted_evidence)
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

    for line_number, line in enumerate(lines, start=1):
        if should_stop is not None and should_stop():
            warnings.append(PROCESSING_TIME_LIMIT_EXCEEDED)
            break
        redacted_evidence = _redact_line(line, applicable_rules)
        for rule in regex_rules:
            if should_stop is not None and should_stop():
                warnings.append(PROCESSING_TIME_LIMIT_EXCEEDED)
                break
            for _match in _eligible_matches(line, rule, extension):
                add_finding(rule, line_number, redacted_evidence)
        if warnings:
            break

    if python_rules and not warnings:
        try:
            for match in detect_python_calls(text, should_stop=should_stop):
                if should_stop is not None and should_stop():
                    raise PythonCallScanStopped
                ast_rule = python_rules.get(match.rule_id)
                if ast_rule is None:
                    continue
                redacted_evidence = _redact_line(lines[match.line_start - 1], applicable_rules)
                add_finding(ast_rule, match.line_start, redacted_evidence)
        except PythonCallScanStopped:
            warnings.append(PROCESSING_TIME_LIMIT_EXCEEDED)
        except (SyntaxError, RecursionError):
            warnings.append(PYTHON_SYNTAX_ERROR)

    if node_tls_rule is not None and not warnings:
        if should_stop is not None and should_stop():
            warnings.append(PROCESSING_TIME_LIMIT_EXCEEDED)
        else:
            node_lines = detect_node_tls_assignments(text, extension)
            if should_stop is not None and should_stop():
                warnings.append(PROCESSING_TIME_LIMIT_EXCEEDED)
            else:
                for line_number in node_lines:
                    redacted_evidence = _redact_line(lines[line_number - 1], applicable_rules)
                    add_finding(node_tls_rule, line_number, redacted_evidence)

    return ScanTextResult(
        findings=tuple(
            sorted(
                findings.values(),
                key=lambda item: (item.file_path, item.line_start, item.rule_id, item.id),
            )
        ),
        warnings=tuple(warnings),
    )


def scan_text(
    file_path: str,
    text: str,
    rules: Sequence[Rule] = DEFAULT_RULES,
    *,
    should_stop: Callable[[], bool] | None = None,
) -> tuple[Finding, ...]:
    """Compatibility wrapper for callers that only consume findings."""

    return scan_text_detailed(file_path, text, rules, should_stop=should_stop).findings
