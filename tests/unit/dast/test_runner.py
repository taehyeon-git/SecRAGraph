"""Docker DAST runner safety and lifecycle contracts."""

from __future__ import annotations

import json
import subprocess
import tempfile
from collections.abc import Mapping
from pathlib import Path

import pytest

from security_review.dast import runner
from security_review.dast.differential import numeric_query_seeds
from security_review.dast.zap import sanitize_openapi


@pytest.fixture(autouse=True)
def _local_temporary_directory(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    original = tempfile.TemporaryDirectory

    def local_temporary_directory(*, prefix: str) -> tempfile.TemporaryDirectory[str]:
        return original(prefix=prefix, dir=tmp_path)

    monkeypatch.setattr(runner.tempfile, "TemporaryDirectory", local_temporary_directory)


def _openapi() -> bytes:
    return json.dumps(
        {
            "openapi": "3.1.0",
            "info": {"title": "Fixture", "version": "1"},
            "paths": {
                "/public": {
                    "get": {
                        "x-secragraph-dast-active": True,
                        "responses": {"200": {"description": "ok"}},
                    }
                },
                "/protected": {"get": {"responses": {"200": {"description": "ok"}}}},
            },
        }
    ).encode()


def _zap_report() -> bytes:
    return json.dumps(
        {
            "@version": "2.17.0",
            "site": [
                {
                    "@name": "http://secragraph-target:8765",
                    "alerts": [
                        {
                            "pluginid": "10021",
                            "riskcode": "1",
                            "confidence": "2",
                            "cweid": "693",
                            "instances": [
                                {
                                    "uri": "http://secragraph-target:8765/public?token=do-not-save",
                                    "method": "GET",
                                    "evidence": "do-not-save",
                                }
                            ],
                        }
                    ],
                }
            ],
        }
    ).encode()


def _numeric_openapi() -> bytes:
    schema = json.loads(_openapi())
    for path in ("/first-record", "/second-record", "/unmarked-record"):
        schema["paths"][path] = {
            "get": {
                "x-secragraph-dast-active": True,
                "parameters": [
                    {
                        "name": "record_id",
                        "in": "query",
                        "required": True,
                        "schema": {"type": "string", "examples": ["1"]},
                    }
                ],
                "responses": {"200": {"description": "ok"}},
            }
        }
    del schema["paths"]["/unmarked-record"]["get"]["x-secragraph-dast-active"]
    return json.dumps(schema).encode()


def _numeric_observations(*, unstable: bool = False) -> bytes:
    a, b, c = "a" * 64, "b" * 64, "c" * 64
    return json.dumps(
        {
            "results": [
                {
                    "path": "/first-record",
                    "parameter": "record_id",
                    "baseline": [[200, a], [200, b if unstable else a]],
                    "control": [[200, a], [200, a]],
                    "true": [[200, b], [200, b]],
                    "false": [[200, a], [200, a]],
                },
                {
                    "path": "/second-record",
                    "parameter": "record_id",
                    "baseline": [[200, a], [200, a]],
                    "control": [[422, c], [422, c]],
                    "true": [[422, c], [422, c]],
                    "false": [[422, c], [422, c]],
                },
            ]
        }
    ).encode()


def test_numeric_seeds_use_only_marked_active_gets_and_ignore_complex_schema() -> None:
    schema = json.loads(_numeric_openapi())
    schema["paths"]["/complex"] = {
        "get": {
            "x-secragraph-dast-active": True,
            "parameters": [
                {
                    "name": "record_id",
                    "in": "query",
                    "required": True,
                    "schema": {"type": ["integer", "null"]},
                }
            ],
        }
    }
    safe = sanitize_openapi(
        json.dumps(schema).encode(), origin="http://secragraph-target:8765", active=True
    )

    assert [
        (seed.path, seed.parameter, seed.baseline) for seed in numeric_query_seeds(safe.document)
    ] == [
        ("/first-record", "record_id", "1"),
        ("/second-record", "record_id", "1"),
    ]


class FakeDocker:
    def __init__(
        self,
        *,
        timeout_zap: bool = False,
        cleanup_failure: bool = False,
        image_present: bool = True,
        pull_fails: bool = False,
        active_marker: bool = True,
        active_permitted: bool = True,
        disposable: bool = True,
        inspected_id: str = "a" * 64,
        openapi_bytes: bytes | None = None,
        report_bytes: bytes | None = None,
        probe_bytes: bytes | None = None,
    ) -> None:
        self.calls: list[tuple[tuple[str, ...], dict[str, str] | None]] = []
        self.timeout_zap = timeout_zap
        self.cleanup_failure = cleanup_failure
        self.image_present = image_present
        self.pull_fails = pull_fails
        self.active_marker = active_marker
        self.active_permitted = active_permitted
        self.disposable = disposable
        self.inspected_id = inspected_id
        self.openapi_bytes = openapi_bytes
        self.report_bytes = report_bytes
        self.probe_bytes = probe_bytes
        self.marker_precreated = False

    def __call__(
        self,
        args: list[str],
        *,
        timeout: float,
        env: Mapping[str, str] | None = None,
        capture: bool = False,
    ) -> subprocess.CompletedProcess[bytes]:
        assert timeout > 0
        self.calls.append((tuple(args), dict(env) if env is not None else None))
        if args[:2] == ["inspect", "--format"]:
            if "{{json .}}" in args:
                return subprocess.CompletedProcess(
                    args,
                    0,
                    json.dumps(
                        {
                            "Id": self.inspected_id,
                            "State": {"Running": True},
                            "Config": {
                                "Labels": {
                                    "io.secragraph.dast.disposable": "true"
                                    if self.disposable
                                    else "false",
                                    "io.secragraph.dast.active-permitted": "true"
                                    if self.active_permitted
                                    else "false",
                                }
                            },
                        }
                    ).encode(),
                )
            output = b"true\n" if ".State.Running" in args[2] else b"true\n"
            return subprocess.CompletedProcess(args, 0, output)
        if args[:2] == ["image", "inspect"]:
            return subprocess.CompletedProcess(args, 0 if self.image_present else 1, b"")
        if args[0] == "pull":
            if not self.pull_fails:
                self.image_present = True
            return subprocess.CompletedProcess(args, 1 if self.pull_fails else 0, b"")
        if args[:2] == ["network", "create"]:
            return subprocess.CompletedProcess(args, 0, b"network-id\n")
        if args[:2] == ["network", "inspect"]:
            payload = [
                {
                    "Driver": "bridge",
                    "Internal": True,
                    "Options": {
                        "com.docker.network.bridge.gateway_mode_ipv4": "isolated",
                        "com.docker.network.bridge.gateway_mode_ipv6": "isolated",
                    },
                    "IPAM": {"Config": [{"Subnet": "172.29.0.0/16"}]},
                }
            ]
            return subprocess.CompletedProcess(args, 0, json.dumps(payload).encode())
        if args[:2] == ["network", "connect"]:
            return subprocess.CompletedProcess(args, 0, b"")
        if args[0] == "run" and "--entrypoint" in args:
            assert capture
            assert "--network" in args and "--read-only" in args
            if "NUMERIC_SQLI_PROBE_V1" in args[args.index("-c") + 1]:
                return subprocess.CompletedProcess(
                    args, 0, self.probe_bytes or _numeric_observations()
                )
            return subprocess.CompletedProcess(args, 0, self.openapi_bytes or _openapi())
        if args[0] == "run":
            assert "-f" in args and "openapi" in args
            assert "--network" in args and "--mount" in args
            assert not capture
            if self.timeout_zap:
                raise subprocess.TimeoutExpired(args, timeout)
            mount = args[args.index("--mount") + 1]
            source = mount.split("src=", 1)[1].split(",dst=", 1)[0]
            (Path(source) / "zap.json").write_bytes(
                self.report_bytes if self.report_bytes is not None else _zap_report()
            )
            if "-S" not in args:
                marker = Path(source) / "active-complete.marker"
                self.marker_precreated = marker.exists() and marker.read_bytes() == b""
                if self.active_marker:
                    marker.write_text("completed", encoding="ascii")
            return subprocess.CompletedProcess(args, 2, b"")
        if args[:2] == ["container", "rm"] or args[:2] == ["network", "disconnect"]:
            return subprocess.CompletedProcess(args, 0, b"")
        if args[:2] == ["network", "rm"]:
            return subprocess.CompletedProcess(args, 1 if self.cleanup_failure else 0, b"")
        raise AssertionError(f"unexpected Docker command: {args}")


def test_dast_runner_isolated_auth_and_sanitized_result(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeDocker()
    monkeypatch.setattr(runner, "_docker", fake)
    monkeypatch.setenv("TEST_DAST_HEADER", "Session do-not-save")

    result = runner.run_zap_api_scan(
        "disposable-api", 8765, "/openapi.json", auth_header_env="TEST_DAST_HEADER"
    )

    assert result.execution.engine == "zap"
    assert result.execution.kind == "dast"
    assert result.execution.status == "completed"
    assert result.execution.version == runner.ZAP_IMAGE
    assert result.execution.eligible_endpoints == ("GET /protected", "GET /public")
    assert result.execution.observed_alert_endpoints == ("GET /public",)
    assert len(result.findings) == 1
    assert result.findings[0].http_path == "/public"
    assert "do-not-save" not in result.findings[0].model_dump_json()
    assert "dast_redirects_within_isolated_network_possible" in result.warnings
    commands = [args for args, _ in fake.calls]
    assert ("image", "inspect", runner.ZAP_IMAGE) in commands
    assert not any(args[0] == "pull" for args in commands)
    network_create = next(args for args in commands if args[:2] == ("network", "create"))
    assert network_create[2:10] == (
        "--internal",
        "--driver",
        "bridge",
        "--opt",
        "com.docker.network.bridge.gateway_mode_ipv4=isolated",
        "--opt",
        "com.docker.network.bridge.gateway_mode_ipv6=isolated",
        network_create[-1],
    )
    assert any(args[:2] == ("network", "inspect") for args in commands)
    assert any(args[:2] == ("network", "connect") for args in commands)
    assert any(args[:2] == ("container", "rm") for args in commands)
    assert any(args[:2] == ("network", "disconnect") for args in commands)
    assert any(args[:2] == ("network", "rm") for args in commands)
    flattened = repr(commands)
    assert "do-not-save" not in flattened
    zap_run = next(args for args in commands if args[0] == "run" and "-S" in args)
    assert "ZAP_AUTH_HEADER_VALUE" in zap_run
    assert ("-z", "-silent") == zap_run[zap_run.index("-z") : zap_run.index("-z") + 2]
    assert ("-D", "5") == zap_run[zap_run.index("-D") : zap_run.index("-D") + 2]
    assert "-O" not in zap_run
    zap_env = next(env for args, env in fake.calls if args == zap_run)
    assert zap_env is not None and zap_env["ZAP_AUTH_HEADER_VALUE"] == "Session do-not-save"
    assert zap_env["ZAP_AUTH_HEADER_SITE"] == "secragraph-target"


def test_active_scan_requires_full_id_and_second_permission_label_before_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeDocker(active_permitted=False)
    monkeypatch.setattr(runner, "_docker", fake)
    with pytest.raises(runner.DastScanError, match="invalid_active_dast_container"):
        runner.run_zap_api_scan("disposable-api", 8765, "/openapi.json", active=True)
    with pytest.raises(runner.DastScanError, match="target_not_active_permitted"):
        runner.run_zap_api_scan("a" * 64, 8765, "/openapi.json", active=True)
    assert not any(args[:2] == ("network", "create") for args, _ in fake.calls)


@pytest.mark.parametrize(
    ("fake", "reason"),
    [
        (FakeDocker(disposable=False), "target_not_disposable"),
        (FakeDocker(inspected_id="b" * 64), "dast_target_unavailable"),
    ],
)
def test_active_scan_rejects_mislabelled_or_mismatched_target(
    monkeypatch: pytest.MonkeyPatch, fake: FakeDocker, reason: str
) -> None:
    monkeypatch.setattr(runner, "_docker", fake)
    with pytest.raises(runner.DastScanError, match=reason):
        runner.run_zap_api_scan("a" * 64, 8765, "/openapi.json", active=True)
    assert not any(args[:2] == ("network", "create") for args, _ in fake.calls)


def test_active_scan_uses_pinned_id_api_minimal_and_completion_marker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeDocker()
    monkeypatch.setattr(runner, "_docker", fake)
    result = runner.run_zap_api_scan("a" * 64, 8765, "/openapi.json", active=True)
    assert result.execution.status == "completed"
    assert result.execution.checks == ("openapi-active",)
    assert result.execution.eligible_endpoints == ("GET /public",)
    assert fake.marker_precreated
    assert "dast_passive_only" not in result.warnings
    assert "dast_active_scan_can_modify_target_state" in result.warnings
    assert "dast_active_seeds_not_request_allowlist" in result.warnings
    assert "dast_active_findings_limited_to_seed_routes" in result.warnings
    commands = [args for args, _ in fake.calls]
    assert any(args[:2] == ("network", "connect") and args[-1] == "a" * 64 for args in commands)
    assert any(
        args[:3] == ("network", "disconnect", "--force") and args[-1] == "a" * 64
        for args in commands
    )
    zap = next(args for args in commands if args[0] == "run" and "zap-api-scan.py" in args)
    assert ("-e", "PYTHONDONTWRITEBYTECODE=1") in tuple(zip(zap, zap[1:], strict=False))
    script_args = zap[zap.index("zap-api-scan.py") + 1 :]
    assert "-S" not in script_args and "-c" not in script_args
    assert script_args[script_args.index("--hook") + 1] == "/zap/wrk/active-hooks.py"
    assert result.supplemental_executions[0].engine == "dast-differential"
    assert result.supplemental_executions[0].status == "skipped"
    assert result.supplemental_executions[0].reason == "no_numeric_query_seed"


def test_active_numeric_seed_emits_separate_differential_finding_and_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeDocker(openapi_bytes=_numeric_openapi())
    monkeypatch.setattr(runner, "_docker", fake)

    result = runner.run_zap_api_scan("a" * 64, 8765, "/openapi.json", active=True)

    differential = [finding for finding in result.findings if finding.engine == "dast-differential"]
    assert [(finding.rule_id, finding.http_path) for finding in differential] == [
        ("DIFF/NUMERIC_SQLI", "/first-record")
    ]
    assert differential[0].cwe_ids == ("CWE-89",)
    assert "200" in differential[0].redacted_evidence
    assert "aaaaaaaaaaaa" in differential[0].redacted_evidence
    assert "bbbbbbbbbbbb" in differential[0].redacted_evidence
    assert "1 OR 1=1" not in differential[0].model_dump_json()
    assert result.execution.engine == "zap"
    assert len(result.supplemental_executions) == 1
    assert result.supplemental_executions[0].engine == "dast-differential"
    assert result.supplemental_executions[0].status == "completed"
    assert "numeric-sqli-requests-16" in result.supplemental_executions[0].checks
    assert set(result.supplemental_executions[0].eligible_endpoints) == {
        "GET /first-record",
        "GET /second-record",
    }
    probe = next(
        args
        for args, _ in fake.calls
        if args[0] == "run"
        and "--entrypoint" in args
        and "NUMERIC_SQLI_PROBE_V1" in args[args.index("-c") + 1]
    )
    assert "--rm" in probe
    assert "--read-only" in probe
    assert "--network" in probe
    assert "DAST_PROBE_FINGERPRINT_KEY" in probe
    probe_env = next(env for args, env in fake.calls if args == probe)
    assert probe_env is not None
    assert probe_env["DAST_PROBE_FINGERPRINT_KEY"] not in differential[0].model_dump_json()


def test_unstable_numeric_response_is_partial_without_differential_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeDocker(
        openapi_bytes=_numeric_openapi(), probe_bytes=_numeric_observations(unstable=True)
    )
    monkeypatch.setattr(runner, "_docker", fake)

    result = runner.run_zap_api_scan("a" * 64, 8765, "/openapi.json", active=True)

    assert result.execution.status == "completed"
    assert result.supplemental_executions[0].status == "partial"
    assert result.supplemental_executions[0].reason == "dast_differential_incomplete"
    assert not any(finding.engine == "dast-differential" for finding in result.findings)


def test_numeric_probe_rejects_redirect_as_partial(monkeypatch: pytest.MonkeyPatch) -> None:
    observations = json.loads(_numeric_observations())
    observations["results"][0]["true"] = [[302, "b" * 64], [302, "b" * 64]]
    fake = FakeDocker(
        openapi_bytes=_numeric_openapi(), probe_bytes=json.dumps(observations).encode()
    )
    monkeypatch.setattr(runner, "_docker", fake)

    result = runner.run_zap_api_scan("a" * 64, 8765, "/openapi.json", active=True)

    assert result.supplemental_executions[0].status == "partial"
    assert not any(finding.engine == "dast-differential" for finding in result.findings)


def test_numeric_probe_does_not_flag_reflected_control(monkeypatch: pytest.MonkeyPatch) -> None:
    observations = json.loads(_numeric_observations())
    observations["results"][0]["control"] = [[200, "c" * 64], [200, "c" * 64]]
    fake = FakeDocker(
        openapi_bytes=_numeric_openapi(), probe_bytes=json.dumps(observations).encode()
    )
    monkeypatch.setattr(runner, "_docker", fake)

    result = runner.run_zap_api_scan("a" * 64, 8765, "/openapi.json", active=True)

    assert result.supplemental_executions[0].status == "completed"
    assert not any(finding.engine == "dast-differential" for finding in result.findings)


def test_active_scan_missing_hook_marker_is_incomplete(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeDocker(active_marker=False)
    monkeypatch.setattr(runner, "_docker", fake)
    result = runner.run_zap_api_scan("a" * 64, 8765, "/openapi.json", active=True)
    assert result.execution.status == "error"
    assert result.execution.reason == "dast_active_scan_incomplete"


def test_runner_discards_out_of_seed_alert_without_losing_in_scope_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = json.loads(_zap_report())
    report["site"][0]["alerts"][0]["instances"].append(
        {"uri": "http://secragraph-target:8765/", "method": "GET"}
    )
    fake = FakeDocker(report_bytes=json.dumps(report).encode())
    monkeypatch.setattr(runner, "_docker", fake)
    active = runner.run_zap_api_scan("a" * 64, 8765, "/openapi.json", active=True)
    assert active.execution.status == "completed"
    assert active.execution.observed_alert_endpoints == ("GET /public",)
    passive = runner.run_zap_api_scan("disposable-api", 8765, "/openapi.json")
    assert passive.execution.status == "completed"
    assert passive.execution.observed_alert_endpoints == ("GET /public",)
    assert "dast_passive_findings_limited_to_openapi_routes" in passive.warnings


def test_active_timeout_keeps_partial_coverage_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeDocker(timeout_zap=True)
    monkeypatch.setattr(runner, "_docker", fake)
    result = runner.run_zap_api_scan("a" * 64, 8765, "/openapi.json", active=True)
    assert result.execution.status == "partial"
    assert result.execution.reason == "dast_scan_timeout"
    assert result.execution.checks == ("openapi-active",)
    assert result.execution.eligible_endpoints == ("GET /public",)
    commands = [args for args, _ in fake.calls]
    assert any(args[:2] == ("container", "rm") for args in commands)
    assert any(args[:2] == ("network", "disconnect") for args in commands)
    assert any(args[:2] == ("network", "rm") for args in commands)


def test_active_scan_without_marked_get_never_starts_zap(monkeypatch: pytest.MonkeyPatch) -> None:
    schema = json.loads(_openapi())
    del schema["paths"]["/public"]["get"]["x-secragraph-dast-active"]
    fake = FakeDocker(openapi_bytes=json.dumps(schema).encode())
    monkeypatch.setattr(runner, "_docker", fake)
    result = runner.run_zap_api_scan("a" * 64, 8765, "/openapi.json", active=True)
    assert result.execution.status == "error"
    assert result.execution.reason == "dast_openapi_invalid"
    assert not any(args[0] == "run" and "zap-api-scan.py" in args for args, _ in fake.calls)


def test_posix_bind_mount_uses_private_host_group_access(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeDocker()
    monkeypatch.setattr(runner, "_docker", fake)
    monkeypatch.setattr(runner, "_host_group_id", lambda: 1234)
    original_chmod = Path.chmod
    modes: list[tuple[str, int]] = []

    def record_chmod(path: Path, mode: int, *args: object, **kwargs: object) -> None:
        modes.append((path.name, mode))
        original_chmod(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "chmod", record_chmod)
    result = runner.run_zap_api_scan("disposable-api", 8765, "/openapi.json")

    assert result.execution.status == "completed"
    assert any(name.startswith("secragraph-dast-") and mode == 0o2770 for name, mode in modes)
    assert ("openapi.json", 0o640) in modes
    assert ("zap.json", 0o660) in modes
    zap_run = next(args for args, _ in fake.calls if args[0] == "run" and "-S" in args)
    assert zap_run[zap_run.index("--group-add") + 1] == "1234"


def test_posix_bind_mount_chmod_failure_aborts_before_docker_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeDocker()
    monkeypatch.setattr(runner, "_docker", fake)
    monkeypatch.setattr(runner, "_host_group_id", lambda: 1234)
    original_chmod = Path.chmod

    def deny_private_group(path: Path, mode: int, *args: object, **kwargs: object) -> None:
        if mode == 0o2770:
            raise OSError("permission denied")
        original_chmod(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "chmod", deny_private_group)
    result = runner.run_zap_api_scan("disposable-api", 8765, "/openapi.json")
    assert result.execution.status == "error"
    assert not any(args[:2] == ("network", "create") for args, _ in fake.calls)


def test_unlabelled_target_is_rejected_before_network_creation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeDocker()

    def reject_label(
        args: list[str],
        *,
        timeout: float,
        env: Mapping[str, str] | None = None,
        capture: bool = False,
    ) -> subprocess.CompletedProcess[bytes]:
        if args[:2] == ["inspect", "--format"] and ".Config.Labels" in args[2]:
            fake.calls.append((tuple(args), None))
            return subprocess.CompletedProcess(args, 0, b"<no value>\n")
        return fake(args, timeout=timeout, env=env, capture=capture)

    monkeypatch.setattr(runner, "_docker", reject_label)
    with pytest.raises(runner.DastScanError, match="target_not_disposable"):
        runner.run_zap_api_scan("ordinary-api", 8765, "/openapi.json")
    assert not any(args[:2] == ("network", "create") for args, _ in fake.calls)


def test_timeout_force_removes_named_container_and_marks_partial(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeDocker(timeout_zap=True)
    monkeypatch.setattr(runner, "_docker", fake)
    result = runner.run_zap_api_scan("disposable-api", 8765, "/openapi.json")

    assert result.execution.status == "partial"
    assert "dast_scan_timeout" in result.warnings
    commands = [args for args, _ in fake.calls]
    zap_run = next(args for args in commands if args[0] == "run" and "-S" in args)
    zap_name = zap_run[zap_run.index("--name") + 1]
    assert ("container", "rm", "-f", zap_name) in commands
    assert any(args[:2] == ("network", "rm") for args in commands)


def test_missing_pinned_image_is_pulled_before_network_and_helper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeDocker(image_present=False)
    monkeypatch.setattr(runner, "_docker", fake)

    result = runner.run_zap_api_scan("disposable-api", 8765, "/openapi.json")

    assert result.execution.status == "completed"
    commands = [args for args, _ in fake.calls]
    pull = ("pull", runner.ZAP_IMAGE)
    assert pull in commands
    assert commands.index(pull) < next(
        index for index, item in enumerate(commands) if item[:2] == ("network", "create")
    )


def test_failed_image_pull_is_incomplete_without_network_creation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeDocker(image_present=False, pull_fails=True)
    monkeypatch.setattr(runner, "_docker", fake)

    result = runner.run_zap_api_scan("disposable-api", 8765, "/openapi.json")

    assert result.execution.status == "error"
    assert "dast_zap_image_unavailable" in result.warnings
    commands = [args for args, _ in fake.calls]
    assert ("pull", runner.ZAP_IMAGE) in commands
    assert not any(item[:2] == ("network", "create") for item in commands)


def test_cleanup_failure_overrides_success(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeDocker(cleanup_failure=True)
    monkeypatch.setattr(runner, "_docker", fake)
    result = runner.run_zap_api_scan("disposable-api", 8765, "/openapi.json")
    assert result.execution.status == "error"
    assert "dast_cleanup_failed" in result.warnings


@pytest.mark.parametrize(
    "network_payload",
    [
        [{"Driver": "bridge", "Internal": True, "Options": {}, "IPAM": {"Config": []}}],
        [
            {
                "Driver": "bridge",
                "Internal": True,
                "Options": {
                    "com.docker.network.bridge.gateway_mode_ipv4": "isolated",
                    "com.docker.network.bridge.gateway_mode_ipv6": "isolated",
                },
                "IPAM": {"Config": [{"Subnet": "172.29.0.0/16", "Gateway": "172.29.0.1"}]},
            }
        ],
    ],
)
def test_network_without_verified_isolation_fails_before_target_connect(
    monkeypatch: pytest.MonkeyPatch, network_payload: list[dict[str, object]]
) -> None:
    fake = FakeDocker()

    def insecure_network(
        args: list[str],
        *,
        timeout: float,
        env: Mapping[str, str] | None = None,
        capture: bool = False,
    ) -> subprocess.CompletedProcess[bytes]:
        if args[:2] == ["network", "inspect"]:
            fake.calls.append((tuple(args), None))
            return subprocess.CompletedProcess(args, 0, json.dumps(network_payload).encode())
        return fake(args, timeout=timeout, env=env, capture=capture)

    monkeypatch.setattr(runner, "_docker", insecure_network)
    result = runner.run_zap_api_scan("disposable-api", 8765, "/openapi.json")

    assert result.execution.status == "error"
    assert "dast_network_isolation_failed" in result.warnings
    commands = [args for args, _ in fake.calls]
    assert not any(args[:2] == ("network", "connect") for args in commands)
    assert any(args[:2] == ("network", "rm") for args in commands)


def test_unsupported_gateway_mode_fails_before_target_connect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeDocker()

    def unsupported_network(
        args: list[str],
        *,
        timeout: float,
        env: Mapping[str, str] | None = None,
        capture: bool = False,
    ) -> subprocess.CompletedProcess[bytes]:
        if args[:2] == ["network", "create"]:
            fake.calls.append((tuple(args), None))
            return subprocess.CompletedProcess(args, 1, b"")
        return fake(args, timeout=timeout, env=env, capture=capture)

    monkeypatch.setattr(runner, "_docker", unsupported_network)
    result = runner.run_zap_api_scan("disposable-api", 8765, "/openapi.json")

    assert result.execution.status == "error"
    assert "dast_network_failed" in result.warnings
    commands = [args for args, _ in fake.calls]
    assert not any(args[:2] == ("network", "connect") for args in commands)
    assert any(args[:2] == ("network", "rm") for args in commands)


def test_report_parse_timeout_is_partial_and_still_cleans_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeDocker()
    monkeypatch.setattr(runner, "_docker", fake)

    def timed_out_parse(
        _raw: bytes,
        *,
        origin: str,
        eligible_endpoints: tuple[str, ...],
        deadline: float,
        active: bool,
    ) -> tuple[object, ...]:
        assert origin == "http://secragraph-target:8765"
        assert eligible_endpoints == ("GET /protected", "GET /public")
        assert deadline > 0
        assert active is False
        raise runner.DastReportError("zap_report_timeout")

    monkeypatch.setattr(runner, "parse_zap_report", timed_out_parse)
    result = runner.run_zap_api_scan("disposable-api", 8765, "/openapi.json")

    assert result.execution.status == "partial"
    assert "dast_scan_timeout" in result.warnings
    commands = [args for args, _ in fake.calls]
    assert any(args[:2] == ("container", "rm") for args in commands)
    assert any(args[:2] == ("network", "rm") for args in commands)


@pytest.mark.parametrize(
    "container,port,path",
    [
        ("-bad", 8765, "/openapi.json"),
        ("good", 0, "/openapi.json"),
        ("good", 8765, "http://outside/openapi.json"),
        ("good", 8765, "/openapi.json?token=abc"),
    ],
)
def test_invalid_caller_input_does_not_contact_docker(
    monkeypatch: pytest.MonkeyPatch, container: str, port: int, path: str
) -> None:
    def fail_if_called(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Docker should not be called")

    monkeypatch.setattr(runner, "_docker", fail_if_called)
    with pytest.raises(runner.DastScanError):
        runner.run_zap_api_scan(container, port, path)
