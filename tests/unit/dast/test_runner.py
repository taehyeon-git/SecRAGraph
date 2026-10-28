"""Docker DAST runner safety and lifecycle contracts."""

from __future__ import annotations

import json
import subprocess
import tempfile
from collections.abc import Mapping
from pathlib import Path

import pytest

from security_review.dast import runner


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
                "/public": {"get": {"responses": {"200": {"description": "ok"}}}},
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


class FakeDocker:
    def __init__(
        self,
        *,
        timeout_zap: bool = False,
        cleanup_failure: bool = False,
        image_present: bool = True,
        pull_fails: bool = False,
    ) -> None:
        self.calls: list[tuple[tuple[str, ...], dict[str, str] | None]] = []
        self.timeout_zap = timeout_zap
        self.cleanup_failure = cleanup_failure
        self.image_present = image_present
        self.pull_fails = pull_fails

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
            return subprocess.CompletedProcess(args, 0, _openapi())
        if args[0] == "run":
            assert "-S" in args and "-f" in args and "openapi" in args
            assert "--network" in args and "--mount" in args
            assert not capture
            if self.timeout_zap:
                raise subprocess.TimeoutExpired(args, timeout)
            mount = args[args.index("--mount") + 1]
            source = mount.split("src=", 1)[1].split(",dst=", 1)[0]
            (Path(source) / "zap.json").write_bytes(_zap_report())
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
    assert "-O" not in zap_run
    zap_env = next(env for args, env in fake.calls if args == zap_run)
    assert zap_env is not None and zap_env["ZAP_AUTH_HEADER_VALUE"] == "Session do-not-save"
    assert zap_env["ZAP_AUTH_HEADER_SITE"] == "secragraph-target"


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
        _raw: bytes, *, origin: str, eligible_endpoints: tuple[str, ...], deadline: float
    ) -> tuple[object, ...]:
        assert origin == "http://secragraph-target:8765"
        assert eligible_endpoints == ("GET /protected", "GET /public")
        assert deadline > 0
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
