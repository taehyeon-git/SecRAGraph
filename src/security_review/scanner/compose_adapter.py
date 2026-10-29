"""Inert policy inspection of declared Docker Compose service settings.

Only verified snapshot bytes are read. This adapter never resolves Compose's
effective configuration, interpolates variables, or opens referenced files.
"""

from __future__ import annotations

import math
import os
import re
import stat
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path, PurePosixPath
from time import monotonic
from typing import TypeAlias, cast

import yaml  # type: ignore[import-untyped]
from yaml.events import (  # type: ignore[import-untyped]
    AliasEvent,
    DocumentStartEvent,
    MappingStartEvent,
    ScalarEvent,
    SequenceStartEvent,
)
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode  # type: ignore[import-untyped]

from security_review.domain.models import Confidence, Finding, Severity
from security_review.scanner.compose_files import COMPOSE_POLICY_VERSION, is_compose_file
from security_review.scanner.external_common import (
    ExternalExecution,
    ExternalScanResult,
    ExternalStatus,
)
from security_review.scanner.external_detectors import (
    _is_link_like,
    _snapshot_files,
    _UnsafeSnapshot,
)

_ENGINE = "compose-policy"
_MAX_FILE_BYTES = 1_000_000
_MAX_TOTAL_BYTES = 20_000_000
_MAX_CANDIDATE_FILES = 500
_MAX_NODES = 10_000
_MAX_DEPTH = 64
_MAX_FINDINGS = 2_000

_RULES: tuple[str, ...] = (
    "COMPOSE/PRIVILEGED",
    "COMPOSE/HOST_NETWORK",
    "COMPOSE/HOST_PID",
    "COMPOSE/HOST_IPC",
    "COMPOSE/CAP_ADD_DANGEROUS",
    "COMPOSE/UNCONFINED_PROFILE",
    "COMPOSE/DOCKER_SOCKET",
    "COMPOSE/HOST_ROOT_MOUNT",
    "COMPOSE/EXPLICIT_ROOT_USER",
    "COMPOSE/PROVIDER",
)
_SEVERITIES = {
    "COMPOSE/PRIVILEGED": Severity.HIGH,
    "COMPOSE/HOST_NETWORK": Severity.MEDIUM,
    "COMPOSE/HOST_PID": Severity.HIGH,
    "COMPOSE/HOST_IPC": Severity.MEDIUM,
    "COMPOSE/CAP_ADD_DANGEROUS": Severity.HIGH,
    "COMPOSE/UNCONFINED_PROFILE": Severity.HIGH,
    "COMPOSE/DOCKER_SOCKET": Severity.HIGH,
    "COMPOSE/HOST_ROOT_MOUNT": Severity.HIGH,
    "COMPOSE/EXPLICIT_ROOT_USER": Severity.MEDIUM,
    "COMPOSE/PROVIDER": Severity.HIGH,
}
_PRIVILEGE_RULES = frozenset(
    {"COMPOSE/PRIVILEGED", "COMPOSE/CAP_ADD_DANGEROUS", "COMPOSE/EXPLICIT_ROOT_USER"}
)
_ALLOWED_TAGS = frozenset(
    f"tag:yaml.org,2002:{name}"
    for name in ("str", "int", "bool", "float", "null", "map", "seq", "timestamp", "binary")
)
_STRING_TAG = "tag:yaml.org,2002:str"
_BOOL_TAG = "tag:yaml.org,2002:bool"
_INT_TAG = "tag:yaml.org,2002:int"
_DYNAMIC = re.compile(r"\$\{|(?<!\$)\$[A-Za-z_][A-Za-z_0-9]*")
_NONCANONICAL_ZERO = re.compile(r"[+-]?0+|0[xX]0+|0[oO]0+|0[bB]0+")

_NodeMap: TypeAlias = dict[str, Node]


class _PolicyIssue(ValueError):
    """A stable, source-free reason why a file could not be fully inspected."""


def _result(
    started: float,
    status: ExternalStatus,
    *,
    eligible: tuple[str, ...] = (),
    inspected: tuple[str, ...] = (),
    skipped: tuple[tuple[str, str], ...] = (),
    checks: tuple[str, ...] = (),
    warnings: tuple[str, ...] = (),
    findings: tuple[Finding, ...] = (),
) -> ExternalScanResult:
    return ExternalScanResult(
        findings=findings,
        execution=ExternalExecution(
            scanner=_ENGINE,
            version=COMPOSE_POLICY_VERSION,
            status=status,
            eligible_files=eligible,
            inspected_files=inspected,
            skipped=skipped,
            checks=checks,
            duration_ms=max(0, int((monotonic() - started) * 1000)),
            warnings=warnings,
        ),
    )


def _check_deadline(deadline: float) -> None:
    if monotonic() >= deadline:
        raise _PolicyIssue("scanner_timeout")


def _read_file(root: Path, relative: str, deadline: float, remaining_bytes: int) -> bytes:
    """Read at most one file cap from a still-regular snapshot member."""
    _check_deadline(deadline)
    path = root / PurePosixPath(relative)
    if _is_link_like(path):
        raise _PolicyIssue("snapshot_contains_link")
    try:
        before = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode):
            raise _PolicyIssue("snapshot_contains_link")
        if before.st_size > _MAX_FILE_BYTES:
            raise _PolicyIssue("file_too_large")
        if before.st_size > remaining_bytes:
            raise _PolicyIssue("total_byte_limit_exceeded")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if not stat.S_ISREG(opened.st_mode) or (
                opened.st_dev,
                opened.st_ino,
            ) != (before.st_dev, before.st_ino):
                raise _PolicyIssue("snapshot_changed")
            if opened.st_size > _MAX_FILE_BYTES:
                raise _PolicyIssue("file_too_large")
            if opened.st_size > remaining_bytes:
                raise _PolicyIssue("total_byte_limit_exceeded")
            with os.fdopen(descriptor, "rb", closefd=False) as source:
                payload = source.read(opened.st_size)
            if len(payload) != opened.st_size or os.fstat(descriptor).st_size != opened.st_size:
                raise _PolicyIssue("snapshot_changed")
        finally:
            os.close(descriptor)
    except OSError as error:
        raise _PolicyIssue("unreadable_file") from error
    _check_deadline(deadline)
    return payload


def _preflight_yaml(source: str, deadline: float) -> None:
    """Reject aliases and excess parse work before composing any node graph."""
    count = 0
    depth = 0
    documents = 0
    try:
        for event in yaml.parse(source, Loader=yaml.SafeLoader):
            _check_deadline(deadline)
            if isinstance(event, DocumentStartEvent):
                documents += 1
                if documents > 1:
                    raise _PolicyIssue("multiple_documents")
            if isinstance(event, AliasEvent) or getattr(event, "anchor", None) is not None:
                raise _PolicyIssue("alias_unresolved")
            tag = getattr(event, "tag", None)
            if tag is not None and tag not in _ALLOWED_TAGS:
                raise _PolicyIssue("unsupported_yaml_tag")
            if isinstance(event, (ScalarEvent, MappingStartEvent, SequenceStartEvent)):
                count += 1
                if count > _MAX_NODES:
                    raise _PolicyIssue("node_limit_exceeded")
            if isinstance(event, (MappingStartEvent, SequenceStartEvent)):
                depth += 1
                if depth > _MAX_DEPTH:
                    raise _PolicyIssue("depth_limit_exceeded")
            if isinstance(event, (yaml.events.MappingEndEvent, yaml.events.SequenceEndEvent)):
                depth -= 1
    except yaml.YAMLError as error:
        raise _PolicyIssue("malformed_yaml") from error


def _validate_tree(root: Node, deadline: float) -> None:
    """Reject duplicate keys and unsupported tags throughout the document."""
    pending = [root]
    while pending:
        _check_deadline(deadline)
        node = pending.pop()
        if node.tag not in _ALLOWED_TAGS:
            raise _PolicyIssue("unsupported_yaml_tag")
        if isinstance(node, MappingNode):
            seen: set[str] = set()
            for key, value in node.value:
                if not isinstance(key, ScalarNode) or key.tag != _STRING_TAG:
                    if isinstance(key, ScalarNode) and key.value == "<<":
                        raise _PolicyIssue("merge_key_unresolved")
                    raise _PolicyIssue("unsupported_yaml_syntax")
                if key.value == "<<":
                    raise _PolicyIssue("merge_key_unresolved")
                if key.value in seen:
                    raise _PolicyIssue("duplicate_mapping_key")
                seen.add(key.value)
                pending.append(value)
        elif isinstance(node, SequenceNode):
            pending.extend(node.value)


def _entries(node: MappingNode) -> _NodeMap:
    return {key.value: value for key, value in node.value if isinstance(key, ScalarNode)}


def _dynamic(node: Node) -> bool:
    pending = [node]
    while pending:
        current = pending.pop()
        if isinstance(current, ScalarNode) and _DYNAMIC.search(current.value):
            return True
        if isinstance(current, MappingNode):
            pending.extend(value for _, value in current.value)
        elif isinstance(current, SequenceNode):
            pending.extend(current.value)
    return False


def _string(node: Node) -> str | None:
    if isinstance(node, ScalarNode) and node.tag == _STRING_TAG:
        return cast(str, node.value)
    return None


def _finding(rule: str, path: str, service: str, node: Node) -> Finding:
    line = node.start_mark.line + 1
    identity = "\0".join((COMPOSE_POLICY_VERSION, rule, path, service, str(line)))
    identifier = f"COMPOSE-{sha256(identity.encode('utf-8')).hexdigest()[:24]}"
    return Finding(
        id=identifier,
        rule_id=rule,
        category="configuration",
        severity=_SEVERITIES[rule],
        file_path=path,
        line_start=line,
        line_end=line,
        message="A potentially risky Compose setting is declared and may be overridden.",
        redacted_evidence="[REDACTED: declared Compose setting omitted]",
        confidence=Confidence.HIGH,
        cwe_ids=("CWE-250",) if rule in _PRIVILEGE_RULES else (),
        engine=_ENGINE,
        remediation="Review the declared setting and restrict service privileges or host access.",
    )


def _add(findings: list[Finding], rule: str, path: str, service: str, node: Node) -> None:
    if len(findings) >= _MAX_FINDINGS:
        raise _PolicyIssue("finding_limit_exceeded")
    findings.append(_finding(rule, path, service, node))


def _sequence_field(fields: _NodeMap, key: str, issues: set[str]) -> SequenceNode | None:
    value = fields.get(key)
    if value is None:
        return None
    if _dynamic(value):
        issues.add("dynamic_value_unresolved")
    if not isinstance(value, SequenceNode):
        issues.add("unsupported_policy_value")
        return None
    return value


def _check_mounts(
    fields: _NodeMap, path: str, service: str, findings: list[Finding], issues: set[str]
) -> None:
    volumes = _sequence_field(fields, "volumes", issues)
    if volumes is None:
        return
    matched: set[str] = set()
    for volume in volumes.value:
        source: str | None = None
        if isinstance(volume, ScalarNode):
            literal = _string(volume)
            if literal is None:
                issues.add("unsupported_mount_syntax")
                continue
            parts = literal.split(":")
            if len(parts) == 1 and parts[0].startswith("/"):
                continue  # An anonymous target has no declared host source.
            if len(parts) not in {2, 3} or not all(parts):
                issues.add("unsupported_mount_syntax")
                continue
            if not parts[1].startswith("/"):
                issues.add("unsupported_mount_syntax")
                continue
            source = parts[0]
        elif isinstance(volume, MappingNode):
            entries = _entries(volume)
            mount_type = entries.get("type")
            if mount_type is None or _string(mount_type) is None:
                issues.add("unsupported_mount_syntax")
                continue
            if _string(mount_type) != "bind":
                continue
            declared_source = entries.get("source")
            source = _string(declared_source) if declared_source is not None else None
            if source is None:
                issues.add("unsupported_mount_syntax")
                continue
        else:
            issues.add("unsupported_mount_syntax")
            continue
        if _DYNAMIC.search(source):
            continue
        if source in {"/var/run/docker.sock", "/run/docker.sock"}:
            rule = "COMPOSE/DOCKER_SOCKET"
        elif source == "/":
            rule = "COMPOSE/HOST_ROOT_MOUNT"
        else:
            continue
        if rule not in matched:
            _add(findings, rule, path, service, volume)
            matched.add(rule)


def _inspect_service(
    fields: _NodeMap, path: str, service: str, findings: list[Finding], issues: set[str]
) -> None:
    if "extends" in fields:
        issues.add("external_reference_unresolved")
    for key in (
        "privileged",
        "network_mode",
        "pid",
        "ipc",
        "cap_add",
        "security_opt",
        "volumes",
        "user",
        "provider",
    ):
        value = fields.get(key)
        if value is not None and _dynamic(value):
            issues.add("dynamic_value_unresolved")

    privileged = fields.get("privileged")
    if privileged is not None:
        if (
            isinstance(privileged, ScalarNode)
            and privileged.tag == _BOOL_TAG
            and privileged.value.lower() == "true"
        ):
            _add(findings, "COMPOSE/PRIVILEGED", path, service, privileged)
        elif not (
            isinstance(privileged, ScalarNode)
            and privileged.tag == _BOOL_TAG
            and privileged.value.lower() == "false"
        ):
            issues.add("unsupported_policy_value")

    for key, rule in (
        ("network_mode", "COMPOSE/HOST_NETWORK"),
        ("pid", "COMPOSE/HOST_PID"),
        ("ipc", "COMPOSE/HOST_IPC"),
    ):
        value = fields.get(key)
        if value is not None:
            literal = _string(value)
            if literal == "host":
                _add(findings, rule, path, service, value)
            elif literal is None:
                issues.add("unsupported_policy_value")

    capabilities = _sequence_field(fields, "cap_add", issues)
    if capabilities is not None:
        for item in capabilities.value:
            literal = _string(item)
            if literal in {"ALL", "SYS_ADMIN"}:
                _add(findings, "COMPOSE/CAP_ADD_DANGEROUS", path, service, item)
                break
            if literal is None:
                issues.add("unsupported_policy_value")

    security_options = _sequence_field(fields, "security_opt", issues)
    if security_options is not None:
        for item in security_options.value:
            literal = _string(item)
            if literal is None:
                issues.add("unsupported_policy_value")
                continue
            if literal in {
                "seccomp=unconfined",
                "seccomp:unconfined",
                "apparmor=unconfined",
                "apparmor:unconfined",
            }:
                _add(findings, "COMPOSE/UNCONFINED_PROFILE", path, service, item)
                break

    _check_mounts(fields, path, service, findings, issues)

    user = fields.get("user")
    if user is not None:
        if not isinstance(user, ScalarNode) or user.tag not in {_STRING_TAG, _INT_TAG}:
            issues.add("unsupported_policy_value")
        elif user.tag == _INT_TAG:
            if user.value == "0":
                _add(findings, "COMPOSE/EXPLICIT_ROOT_USER", path, service, user)
            elif re.fullmatch(r"[1-9][0-9]*", user.value) is None:
                issues.add("unsupported_policy_value")
        else:
            literal = user.value
            parts = literal.split(":")
            if literal in {"root", "0"} or (
                len(parts) == 2 and parts[0] in {"root", "0"} and bool(parts[1])
            ):
                _add(findings, "COMPOSE/EXPLICIT_ROOT_USER", path, service, user)
            elif _NONCANONICAL_ZERO.fullmatch(parts[0]) is not None or parts[0] in {"root", "0"}:
                issues.add("unsupported_policy_value")

    provider = fields.get("provider")
    if provider is not None:
        if isinstance(provider, MappingNode):
            _add(findings, "COMPOSE/PROVIDER", path, service, provider)
        else:
            issues.add("unsupported_policy_value")


def _inspect_document(
    node: Node, path: str, findings: list[Finding], issues: set[str], deadline: float
) -> tuple[bool, bool]:
    if not isinstance(node, MappingNode):
        issues.add("unsupported_compose_shape")
        return False, False
    top = _entries(node)
    if "include" in top:
        issues.add("external_reference_unresolved")
    services = top.get("services")
    if not isinstance(services, MappingNode):
        issues.add("unsupported_compose_shape")
        return False, False
    inspected = True
    evaluated = False
    for key, value in services.value:
        _check_deadline(deadline)
        if not isinstance(key, ScalarNode) or not isinstance(value, MappingNode):
            issues.add("unsupported_compose_shape")
            inspected = False
            continue
        _inspect_service(_entries(value), path, key.value, findings, issues)
        _check_deadline(deadline)
        evaluated = True
    return inspected, evaluated


@dataclass(frozen=True, slots=True)
class ComposePolicyAdapter:
    """Evaluate literal Compose declarations with fixed redacted findings."""

    def scan_snapshot(self, root: Path, timeout: float) -> ExternalScanResult:
        started = monotonic()
        try:
            paths = _snapshot_files(root)
        except _UnsafeSnapshot as error:
            return _result(started, "error", warnings=(str(error),))
        eligible = tuple(path for path in paths if is_compose_file(path))
        if not eligible:
            return _result(started, "skipped", warnings=("no_eligible_files",))
        if not math.isfinite(timeout) or timeout < 0:
            return _result(started, "error", eligible=eligible, warnings=("invalid_timeout",))
        if timeout == 0:
            return _result(started, "not_run", eligible=eligible, warnings=("scanner_timeout",))

        deadline = started + timeout
        root = root.absolute()
        findings: list[Finding] = []
        inspected: list[str] = []
        skipped: list[tuple[str, str]] = []
        warnings: list[str] = []
        total_bytes = 0
        checked_any = False
        grouped: dict[str, int] = {}
        for path in eligible:
            parent = str(PurePosixPath(path).parent)
            grouped[parent] = grouped.get(parent, 0) + 1
        if any(count > 1 for count in grouped.values()):
            warnings.append("effective_config_not_resolved")

        for index, path in enumerate(eligible):
            if index >= _MAX_CANDIDATE_FILES:
                skipped.append((path, "candidate_limit_exceeded"))
                warnings.append("candidate_limit_exceeded")
                continue
            if total_bytes >= _MAX_TOTAL_BYTES:
                skipped.append((path, "total_byte_limit_exceeded"))
                warnings.append("total_byte_limit_exceeded")
                continue
            try:
                payload = _read_file(root, path, deadline, _MAX_TOTAL_BYTES - total_bytes)
                if total_bytes + len(payload) > _MAX_TOTAL_BYTES:
                    raise _PolicyIssue("total_byte_limit_exceeded")
                total_bytes += len(payload)
                if b"\x00" in payload:
                    raise _PolicyIssue("binary_or_invalid_utf8")
                try:
                    source = payload.decode("utf-8")
                except UnicodeDecodeError as error:
                    raise _PolicyIssue("binary_or_invalid_utf8") from error
                _preflight_yaml(source, deadline)
                try:
                    node = yaml.compose(source, Loader=yaml.SafeLoader)
                except yaml.YAMLError as error:
                    raise _PolicyIssue("malformed_yaml") from error
                _check_deadline(deadline)
                if node is None:
                    raise _PolicyIssue("unsupported_compose_shape")
                _validate_tree(node, deadline)
                issues: set[str] = set()
                file_inspected, evaluated = _inspect_document(
                    node, path, findings, issues, deadline
                )
                checked_any |= evaluated
                if file_inspected:
                    inspected.append(path)
                else:
                    skipped.append((path, "unsupported_compose_shape"))
                warnings.extend(sorted(issues))
            except _PolicyIssue as error:
                reason = str(error)
                skipped.append((path, reason))
                warnings.append(reason)
                if reason in {"scanner_timeout", "finding_limit_exceeded"}:
                    for remaining in eligible[index + 1 :]:
                        skipped.append((remaining, reason))
                    break

        distinct_warnings = tuple(dict.fromkeys(warnings))
        status: ExternalStatus
        if not distinct_warnings:
            status = "completed"
        elif distinct_warnings == ("scanner_timeout",) and not inspected and not findings:
            status = "not_run"
        else:
            status = "partial"
        return _result(
            started,
            status,
            eligible=eligible,
            inspected=tuple(inspected),
            skipped=tuple(skipped),
            checks=_RULES if checked_any else (),
            warnings=distinct_warnings,
            findings=tuple(findings),
        )
