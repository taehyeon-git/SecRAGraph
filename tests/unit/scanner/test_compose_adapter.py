"""Contract tests for inert, bounded Docker Compose policy inspection."""

from __future__ import annotations

import json
import os
import socket
import subprocess
from pathlib import Path

import pytest

from security_review.domain.models import Severity
from security_review.scanner import compose_adapter
from security_review.scanner.compose_adapter import ComposePolicyAdapter


def _scan(tmp_path: Path, source: str, *, name: str = "compose.yaml"):
    (tmp_path / name).write_text(source, encoding="utf-8")
    return ComposePolicyAdapter().scan_snapshot(tmp_path, timeout=5)


@pytest.mark.parametrize(
    ("setting", "rule", "severity"),
    [
        ("privileged: true", "PRIVILEGED", Severity.HIGH),
        ("network_mode: host", "HOST_NETWORK", Severity.MEDIUM),
        ("pid: host", "HOST_PID", Severity.HIGH),
        ("ipc: host", "HOST_IPC", Severity.MEDIUM),
        ("cap_add: [SYS_ADMIN]", "CAP_ADD_DANGEROUS", Severity.HIGH),
        ("cap_add: [CAP_SYS_ADMIN]", "CAP_ADD_DANGEROUS", Severity.HIGH),
        ("cap_add: [ALL]", "CAP_ADD_DANGEROUS", Severity.HIGH),
        ("security_opt: [seccomp=unconfined]", "UNCONFINED_PROFILE", Severity.HIGH),
        ('security_opt: ["apparmor:unconfined"]', "UNCONFINED_PROFILE", Severity.HIGH),
        (
            'volumes: ["/var/run/docker.sock:/var/run/docker.sock:ro"]',
            "DOCKER_SOCKET",
            Severity.HIGH,
        ),
        ('volumes: ["/run/docker.sock:/socket"]', "DOCKER_SOCKET", Severity.HIGH),
        ('volumes: ["/:/host:ro"]', "HOST_ROOT_MOUNT", Severity.HIGH),
        ("volumes: [{type: bind, source: /, target: /host}]", "HOST_ROOT_MOUNT", Severity.HIGH),
        (
            "volumes: [{type: bind, source: /var/run/docker.sock, target: /socket}]",
            "DOCKER_SOCKET",
            Severity.HIGH,
        ),
        ("user: root", "EXPLICIT_ROOT_USER", Severity.MEDIUM),
        ('user: "0"', "EXPLICIT_ROOT_USER", Severity.MEDIUM),
        ("user: 0", "EXPLICIT_ROOT_USER", Severity.MEDIUM),
        ('user: "root:wheel"', "EXPLICIT_ROOT_USER", Severity.MEDIUM),
        ('user: "0:1000"', "EXPLICIT_ROOT_USER", Severity.MEDIUM),
        ("provider: {type: service, options: {foo: bar}}", "PROVIDER", Severity.HIGH),
    ],
)
def test_literal_service_settings_report_rule_and_source_line(
    tmp_path: Path, setting: str, rule: str, severity: Severity
) -> None:
    result = _scan(tmp_path, f"services:\n  web:\n    {setting}\n")

    assert result.execution.scanner == "compose-policy"
    assert result.execution.version == "2026.10.30.1"
    assert result.execution.status == "completed"
    assert result.execution.eligible_files == ("compose.yaml",)
    assert result.execution.inspected_files == ("compose.yaml",)
    assert len(result.execution.checks) == 10
    assert [(f.rule_id, f.severity, f.line_start, f.line_end) for f in result.findings] == [
        (f"COMPOSE/{rule}", severity, 3, 3)
    ]
    finding = result.findings[0]
    assert finding.file_path == "compose.yaml"
    assert finding.category == "configuration"
    assert finding.engine == "compose-policy"
    assert finding.redacted_evidence == "[REDACTED: declared Compose setting omitted]"
    assert "declared" in finding.message.lower()
    assert "overridden" in finding.message.lower()
    assert finding.cwe_ids == (
        ()
        if rule not in {"PRIVILEGED", "CAP_ADD_DANGEROUS", "EXPLICIT_ROOT_USER"}
        else ("CWE-250",)
    )


@pytest.mark.parametrize(
    "setting",
    [
        "privileged: false",
        "network_mode: bridge",
        "pid: service:db",
        "ipc: private",
        "cap_add: [NET_ADMIN]",
        'security_opt: ["seccomp=default"]',
        'volumes: ["data:/var/lib/data"]',
        'volumes: ["./src:/app"]',
        "volumes: [{type: volume, source: /, target: /host}]",
        "user: app",
        "user: 1000",
        "read_only: false",
    ],
)
def test_safe_controls_do_not_generate_findings(tmp_path: Path, setting: str) -> None:
    result = _scan(tmp_path, f"services:\n  web:\n    {setting}\n")
    assert result.execution.status == "completed"
    assert result.findings == ()


@pytest.mark.parametrize("literal", ["true", "True", "TRUE"])
def test_boolean_true_case_variants_are_reported(tmp_path: Path, literal: str) -> None:
    result = _scan(tmp_path, f"services:\n  web:\n    privileged: {literal}\n")
    assert result.execution.status == "completed"
    assert [finding.rule_id for finding in result.findings] == ["COMPOSE/PRIVILEGED"]


@pytest.mark.parametrize("literal", ['"true"', "yes", "ON", "1"])
def test_ambiguous_privileged_values_do_not_claim_clean_coverage(
    tmp_path: Path, literal: str
) -> None:
    result = _scan(tmp_path, f"services:\n  web:\n    privileged: {literal}\n")
    assert result.execution.status == "partial"
    assert "unsupported_policy_value" in result.execution.warnings
    assert result.findings == ()


@pytest.mark.parametrize("literal", ["00", "0x0", "+0", '"00"', '"0x0"', '"root:"', '"0:"'])
def test_ambiguous_root_user_literals_do_not_claim_clean_coverage(
    tmp_path: Path, literal: str
) -> None:
    result = _scan(tmp_path, f"services:\n  web:\n    user: {literal}\n")
    assert result.execution.status == "partial"
    assert "unsupported_policy_value" in result.execution.warnings
    assert result.findings == ()


def test_flow_style_and_comments_preserve_line_and_quote_semantics(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "# introductory comment\nservices: {web: {network_mode: 'host', privileged: true}}\n",
    )
    assert result.execution.status == "completed"
    assert {f.rule_id for f in result.findings} == {
        "COMPOSE/HOST_NETWORK",
        "COMPOSE/PRIVILEGED",
    }
    assert all(f.line_start == 2 for f in result.findings)


def test_partial_external_reference_keeps_independent_literal_finding(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "include: ./other.yaml\nservices:\n  secret-service:\n    privileged: true\n",
    )
    assert result.execution.status == "partial"
    assert "external_reference_unresolved" in result.execution.warnings
    assert result.execution.inspected_files == ("compose.yaml",)
    assert [f.rule_id for f in result.findings] == ["COMPOSE/PRIVILEGED"]
    assert "secret-service" not in json.dumps(result, default=str)


def test_dynamic_inspected_setting_marks_partial_but_keeps_literal_finding(tmp_path: Path) -> None:
    result = _scan(
        tmp_path,
        "services:\n  web:\n    privileged: true\n    network_mode: ${NETWORK_MODE}\n",
    )
    assert result.execution.status == "partial"
    assert "dynamic_value_unresolved" in result.execution.warnings
    assert [f.rule_id for f in result.findings] == ["COMPOSE/PRIVILEGED"]
    assert "NETWORK_MODE" not in str(result)


def test_extends_marks_partial_without_reading_reference(tmp_path: Path) -> None:
    result = _scan(tmp_path, "services:\n  web:\n    extends: ./base.yaml\n    pid: host\n")
    assert result.execution.status == "partial"
    assert "external_reference_unresolved" in result.execution.warnings
    assert [f.rule_id for f in result.findings] == ["COMPOSE/HOST_PID"]


def test_same_directory_files_leave_effective_configuration_unresolved(tmp_path: Path) -> None:
    (tmp_path / "compose.yaml").write_text(
        "services:\n  web:\n    privileged: true\n", encoding="utf-8"
    )
    (tmp_path / "compose.override.yaml").write_text(
        "services:\n  web:\n    privileged: false\n", encoding="utf-8"
    )
    result = ComposePolicyAdapter().scan_snapshot(tmp_path, timeout=5)
    assert result.execution.status == "partial"
    assert "effective_config_not_resolved" in result.execution.warnings
    assert result.execution.inspected_files == ("compose.override.yaml", "compose.yaml")
    assert [f.rule_id for f in result.findings] == ["COMPOSE/PRIVILEGED"]


def test_different_directories_are_separate_candidates(tmp_path: Path) -> None:
    for name in ("one", "two"):
        directory = tmp_path / name
        directory.mkdir()
        (directory / "compose.yaml").write_text("services:\n  web: {}\n", encoding="utf-8")
    result = ComposePolicyAdapter().scan_snapshot(tmp_path, timeout=5)
    assert result.execution.status == "completed"
    assert result.execution.inspected_files == ("one/compose.yaml", "two/compose.yaml")


def test_finding_ids_are_stable_and_distinguish_services(tmp_path: Path) -> None:
    source = "services:\n  first: {privileged: true}\n  second: {privileged: true}\n"
    first = _scan(tmp_path, source)
    second = ComposePolicyAdapter().scan_snapshot(tmp_path, timeout=5)
    assert [f.id for f in first.findings] == [f.id for f in second.findings]
    assert len({f.id for f in first.findings}) == 2
    assert "first" not in str(first)
    assert "second" not in str(first)


@pytest.mark.parametrize(
    ("source", "reason"),
    [
        ("services:\n  web: {privileged: true, privileged: false}\n", "duplicate_mapping_key"),
        ("services:\n  web: &service {privileged: true}\n", "alias_unresolved"),
        ("services:\n  web: *missing\n", "alias_unresolved"),
        ("services:\n  web: {<<: {privileged: true}}\n", "merge_key_unresolved"),
        ("services:\n  web: !evil {privileged: true}\n", "unsupported_yaml_tag"),
        ("services:\n  web: &web {extends: *web}\n", "alias_unresolved"),
        ("services: [\n", "malformed_yaml"),
        ("services: {}\n---\nservices: {}\n", "multiple_documents"),
        ("services: []\n", "unsupported_compose_shape"),
        ("services:\n  web: []\n", "unsupported_compose_shape"),
    ],
)
def test_unsafe_or_unsupported_yaml_never_claims_coverage(
    tmp_path: Path, source: str, reason: str
) -> None:
    result = _scan(tmp_path, source)
    assert result.execution.status == "partial"
    assert reason in result.execution.warnings
    assert result.execution.inspected_files == ()
    assert result.execution.checks == ()
    assert result.findings == ()
    assert ("compose.yaml", reason) in result.execution.skipped


@pytest.mark.parametrize("payload", [b"services:\n  web: \xff\n", b"services:\x00\n"])
def test_binary_or_invalid_utf8_is_not_parsed(tmp_path: Path, payload: bytes) -> None:
    (tmp_path / "compose.yaml").write_bytes(payload)
    result = ComposePolicyAdapter().scan_snapshot(tmp_path, timeout=5)
    assert result.execution.status == "partial"
    assert result.execution.inspected_files == ()
    assert result.execution.skipped == (("compose.yaml", "binary_or_invalid_utf8"),)


def test_oversized_file_is_skipped_before_parsing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(compose_adapter, "_MAX_FILE_BYTES", 30)
    result = _scan(tmp_path, "services:\n  web: {privileged: true}\n")
    assert result.execution.status == "partial"
    assert result.execution.skipped == (("compose.yaml", "file_too_large"),)
    assert result.findings == ()


def test_candidate_cap_preserves_first_checked_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(compose_adapter, "_MAX_CANDIDATE_FILES", 1)
    for name in ("a", "b"):
        directory = tmp_path / name
        directory.mkdir()
        (directory / "compose.yaml").write_text("services: {web: {}}\n", encoding="utf-8")
    result = ComposePolicyAdapter().scan_snapshot(tmp_path, timeout=5)
    assert result.execution.status == "partial"
    assert result.execution.eligible_files == ("a/compose.yaml", "b/compose.yaml")
    assert result.execution.inspected_files == ("a/compose.yaml",)
    assert result.execution.skipped == (("b/compose.yaml", "candidate_limit_exceeded"),)
    assert "candidate_inventory_incomplete" in result.execution.warnings


def test_discovery_entry_cap_does_not_report_no_eligible_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(compose_adapter, "_MAX_DISCOVERY_ENTRIES", 1, raising=False)
    (tmp_path / "readme-one.txt").write_text("one", encoding="utf-8")
    (tmp_path / "readme-two.txt").write_text("two", encoding="utf-8")
    result = ComposePolicyAdapter().scan_snapshot(tmp_path, timeout=5)
    assert result.execution.status == "partial"
    assert result.execution.eligible_files == ()
    assert "candidate_inventory_incomplete" in result.execution.warnings
    assert "snapshot_entry_limit_exceeded" in result.execution.warnings


def test_discovery_deadline_at_end_of_walk_does_not_claim_empty_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    now = [0.0]
    monkeypatch.setattr(compose_adapter, "monotonic", lambda: now[0])
    real_scandir = os.scandir

    class TimedScandir:
        def __init__(self, path: object) -> None:
            self._iterator = real_scandir(path)

        def __enter__(self) -> TimedScandir:
            self._iterator.__enter__()
            return self

        def __exit__(self, *_args: object) -> None:
            self._iterator.__exit__(None, None, None)
            now[0] = 2.0

        def __iter__(self):
            return iter(self._iterator)

    monkeypatch.setattr(compose_adapter.os, "scandir", TimedScandir)
    result = ComposePolicyAdapter().scan_snapshot(tmp_path, timeout=1)
    assert result.execution.status == "not_run"
    assert result.execution.warnings == ("scanner_timeout", "candidate_inventory_incomplete")


def test_total_byte_cap_preserves_first_checked_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(compose_adapter, "_MAX_TOTAL_BYTES", 30)
    for name in ("a", "b"):
        directory = tmp_path / name
        directory.mkdir()
        (directory / "compose.yaml").write_text("services: {web: {}}\n", encoding="utf-8")
    opened: list[str] = []
    real_open = compose_adapter.os.open

    def recording_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
        if str(path).endswith("compose.yaml"):
            opened.append(str(path))
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(compose_adapter.os, "open", recording_open)
    result = ComposePolicyAdapter().scan_snapshot(tmp_path, timeout=5)
    assert result.execution.status == "partial"
    assert result.execution.inspected_files == ("a/compose.yaml",)
    assert result.execution.skipped == (("b/compose.yaml", "total_byte_limit_exceeded"),)
    assert len(opened) == 1


def test_node_and_depth_caps_prevent_unbounded_yaml(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(compose_adapter, "_MAX_NODES", 4)
    nodes = _scan(tmp_path, "services: {web: {privileged: true}}\n")
    assert nodes.execution.skipped == (("compose.yaml", "node_limit_exceeded"),)
    monkeypatch.setattr(compose_adapter, "_MAX_NODES", 10_000)
    monkeypatch.setattr(compose_adapter, "_MAX_DEPTH", 2)
    depth = _scan(tmp_path, "services: {web: {privileged: true}}\n")
    assert depth.execution.skipped == (("compose.yaml", "depth_limit_exceeded"),)


def test_finding_cap_preserves_bounded_confirmed_findings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(compose_adapter, "_MAX_FINDINGS", 2)
    result = _scan(
        tmp_path,
        "services:\n  a: {privileged: true}\n  b: {privileged: true}\n  c: {privileged: true}\n",
    )
    assert result.execution.status == "partial"
    assert result.execution.inspected_files == ()
    assert result.execution.skipped == (("compose.yaml", "finding_limit_exceeded"),)
    assert len(result.findings) == 2


def test_expired_deadline_and_invalid_timeout_are_honest(tmp_path: Path) -> None:
    (tmp_path / "compose.yaml").write_text("services: {web: {}}\n", encoding="utf-8")
    expired = ComposePolicyAdapter().scan_snapshot(tmp_path, timeout=0)
    invalid = ComposePolicyAdapter().scan_snapshot(tmp_path, timeout=float("nan"))
    assert expired.execution.status == "not_run"
    assert expired.execution.warnings == ("scanner_timeout", "candidate_inventory_incomplete")
    assert expired.execution.eligible_files == ()
    assert invalid.execution.status == "error"
    assert invalid.execution.warnings == ("invalid_timeout",)


def test_zero_deadline_does_not_walk_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "compose.yaml").write_text("services: {web: {}}\n", encoding="utf-8")

    def forbidden_scandir(_path: object) -> None:
        raise AssertionError("expired scan traversed snapshot")

    monkeypatch.setattr(compose_adapter.os, "scandir", forbidden_scandir)
    result = ComposePolicyAdapter().scan_snapshot(tmp_path, timeout=0)
    assert result.execution.status == "not_run"
    assert result.execution.eligible_files == ()
    assert "candidate_inventory_incomplete" in result.execution.warnings


def test_parent_directory_symlink_swap_cannot_read_outside_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "compose.yaml").write_text("services: {web: {}}\n", encoding="utf-8")
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    (outside / "compose.yaml").write_text("services: {web: {privileged: true}}\n", encoding="utf-8")
    original_link_check = compose_adapter._is_link_like
    from security_review.scanner import external_detectors

    original_directory = tmp_path / "project-original"
    seen_final = 0
    swapped = False

    def swap_before_read(path: Path) -> bool:
        nonlocal seen_final, swapped
        if path.name == "compose.yaml":
            seen_final += 1
            if seen_final == 2:
                project.rename(original_directory)
                try:
                    os.symlink(outside, project, target_is_directory=True)
                except (NotImplementedError, OSError):
                    original_directory.rename(project)
                    pytest.skip("directory symlinks unavailable on this host")
                swapped = True
        return original_link_check(path)

    monkeypatch.setattr(compose_adapter, "_is_link_like", swap_before_read)
    monkeypatch.setattr(external_detectors, "_is_link_like", swap_before_read)
    try:
        result = ComposePolicyAdapter().scan_snapshot(tmp_path, timeout=5)
    finally:
        if swapped:
            project.unlink()
            original_directory.rename(project)
    assert swapped
    assert result.execution.status in {"partial", "error"}
    assert result.findings == ()
    assert result.execution.inspected_files == ()
    assert any(
        reason in result.execution.warnings
        for reason in ("snapshot_contains_link", "snapshot_changed", "unsafe_snapshot_path")
    )


def test_resolved_parent_escape_is_rejected_before_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    source = project / "compose.yaml"
    source.write_text("services: {web: {}}\n", encoding="utf-8")
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    outside_source = outside / "compose.yaml"
    outside_source.write_text("services: {web: {privileged: true}}\n", encoding="utf-8")
    real_resolve = Path.resolve

    def escaped_resolution(path: Path, *args: object, **kwargs: object) -> Path:
        if path == source:
            return outside_source
        return real_resolve(path, *args, **kwargs)

    with monkeypatch.context() as context:
        context.setattr(Path, "resolve", escaped_resolution)
        result = ComposePolicyAdapter().scan_snapshot(tmp_path, timeout=5)
    assert result.execution.status == "partial"
    assert result.execution.inspected_files == ()
    assert result.execution.skipped == (("project/compose.yaml", "unsafe_snapshot_path"),)
    assert result.findings == ()


def test_deadline_elapsed_during_service_evaluation_is_not_completed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "compose.yaml").write_text(
        "services: {web: {privileged: true}}\n", encoding="utf-8"
    )
    now = [0.0]
    monkeypatch.setattr(compose_adapter, "monotonic", lambda: now[0])
    real_inspect = compose_adapter._inspect_service

    def advance_after_inspection(*args: object, **kwargs: object) -> None:
        real_inspect(*args, **kwargs)
        now[0] = 2.0

    monkeypatch.setattr(compose_adapter, "_inspect_service", advance_after_inspection)
    result = ComposePolicyAdapter().scan_snapshot(tmp_path, timeout=1)
    assert result.execution.status == "partial"
    assert "scanner_timeout" in result.execution.warnings
    assert result.execution.inspected_files == ()
    assert [finding.rule_id for finding in result.findings] == ["COMPOSE/PRIVILEGED"]


def test_referenced_paths_are_not_opened_or_executed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    canary = "CANNOT_BE_READ_FROM_REFERENCE_2026"
    (tmp_path / "outside.env").write_text(canary, encoding="utf-8")
    (tmp_path / "compose.yaml").write_text(
        "services:\n  web:\n    env_file: outside.env\n"
        "    build: {context: .}\n    volumes: ['./src:/app']\n",
        encoding="utf-8",
    )
    opened: list[str] = []
    real_open = compose_adapter.os.open

    def guarded_open(path: object, flags: int, *args: object, **kwargs: object) -> int:
        opened.append(str(path))
        if str(path).endswith("outside.env"):
            raise AssertionError("referenced file was opened")
        return real_open(path, flags, *args, **kwargs)

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Compose inspection launched external work")

    monkeypatch.setattr(compose_adapter.os, "open", guarded_open)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    result = ComposePolicyAdapter().scan_snapshot(tmp_path, timeout=5)
    assert result.execution.status == "completed"
    assert any(path.endswith("compose.yaml") for path in opened)
    assert not any(path.endswith("outside.env") for path in opened)
    assert canary not in str(result)
