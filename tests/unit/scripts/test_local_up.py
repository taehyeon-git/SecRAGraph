"""The local entrypoint must be safe to run again against persistent data."""

from __future__ import annotations

import os
import runpy
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import local_up


def test_runtime_secrets_are_written_once_and_reused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(local_up, "_volume_exists", lambda _docker: False)

    first = local_up._load_or_create_runtime_env(tmp_path, "docker")
    content = first.path.read_text(encoding="utf-8")
    assert first.path == tmp_path / "build/local/runtime.env"
    assert first.admin_password != first.reader_password
    assert len(first.admin_password) >= 32
    assert len(first.reader_password) >= 32
    assert f"POSTGRES_PASSWORD={first.admin_password}\n" in content
    assert f"SECRAGRAPH_READER_PASSWORD={first.reader_password}\n" in content

    monkeypatch.setattr(local_up, "_volume_exists", lambda _docker: True)
    second = local_up._load_or_create_runtime_env(tmp_path, "docker")
    assert (second.admin_password, second.reader_password) == (
        first.admin_password,
        first.reader_password,
    )
    assert first.path.read_text(encoding="utf-8") == content
    assert first.admin_password not in capsys.readouterr().out
    if os.name != "nt":
        assert first.path.stat().st_mode & 0o077 == 0


def test_existing_postgres_volume_without_saved_credentials_fails_closed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(local_up, "_volume_exists", lambda _docker: True)

    with pytest.raises(local_up.StartupError, match="existing PostgreSQL volume"):
        local_up._load_or_create_runtime_env(tmp_path, "docker")

    assert not (tmp_path / "build/local/runtime.env").exists()


def test_corrupt_runtime_state_is_rejected_without_regenerating_secrets(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    state = tmp_path / "build/local/runtime.env"
    state.parent.mkdir(parents=True)
    state.write_text("POSTGRES_PASSWORD=partial\n", encoding="utf-8")
    monkeypatch.setattr(
        local_up,
        "_volume_exists",
        lambda _docker: pytest.fail("volume must not be queried when state exists"),
    )

    with pytest.raises(local_up.StartupError, match="runtime.env"):
        local_up._load_or_create_runtime_env(tmp_path, "docker")

    assert state.read_text(encoding="utf-8") == "POSTGRES_PASSWORD=partial\n"


def test_runtime_state_read_is_bounded_and_rejects_oversized_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    state = tmp_path / "build/local/runtime.env"
    state.parent.mkdir(parents=True)
    state.write_bytes(b"X" * 2_000_000)
    original_read_text = Path.read_text

    def reject_unbounded_text_read(path: Path, *args: object, **kwargs: object) -> str:
        if path == state:
            pytest.fail("runtime.env must never be read with unbounded read_text")
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", reject_unbounded_text_read)
    monkeypatch.setattr(local_up, "_volume_exists", lambda _docker: False)

    with pytest.raises(local_up.StartupError, match="runtime.env"):
        local_up._load_or_create_runtime_env(tmp_path, "docker")


def test_link_like_runtime_path_is_rejected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(local_up, "_has_link_like_component", lambda _path: True)
    with pytest.raises(local_up.StartupError, match="Unsafe runtime.env"):
        local_up._load_or_create_runtime_env(tmp_path, "docker")


def test_docker_volume_check_matches_only_the_local_stack_volume(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[list[str]] = []
    output_targets: list[object] = []

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        seen.append(command)
        output_targets.append(kwargs.get("stdout"))
        return subprocess.CompletedProcess(
            command, 0, stdout="unrelated_postgres_data\nsecragraph_postgres_data\n", stderr=""
        )

    monkeypatch.setattr(local_up.subprocess, "run", fake_run)

    assert local_up._volume_exists("docker")
    assert seen == [
        [
            "docker",
            "volume",
            "ls",
            "--format",
            "{{.Name}}",
        ]
    ]
    assert output_targets == [subprocess.PIPE]

    def only_unrelated(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            command, 0, stdout="unrelated_postgres_data\nsecragraph_postgres_data_old\n", stderr=""
        )

    monkeypatch.setattr(local_up.subprocess, "run", only_unrelated)
    assert not local_up._volume_exists("docker")


def test_compose_uses_saved_secrets_without_argv_or_output_leak(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runtime = local_up.RuntimeSecrets(tmp_path / "runtime.env", "A" * 43, "B" * 43)
    calls: list[tuple[list[str], dict[str, object]]] = []

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(local_up.subprocess, "run", fake_run)
    environment = local_up._compose_environment(
        runtime,
        {
            "POSTGRES_PASSWORD": "wrong",
            "SECRAGRAPH_READER_PASSWORD": "wrong",
            "SECRAGRAPH_QDRANT_COLLECTION": "legacy-demo",
        },
    )
    local_up._start_compose("docker", runtime, environment, tmp_path)

    assert [command[-2:] for command, _ in calls] == [
        ["config", "--quiet"],
        ["--wait-timeout", "240"],
        ["-c", calls[2][0][-1]],
    ]
    assert all(command[:4] == ["docker", "compose", "-p", "secragraph"] for command, _ in calls)
    assert all(command[4:6] == ["--env-file", str(runtime.path)] for command, _ in calls)
    assert calls[1][0][6:] == ["up", "--build", "--detach", "--wait", "--wait-timeout", "240"]
    assert calls[2][0][6:12] == [
        "exec",
        "-T",
        "api",
        "/app/.venv/bin/python",
        "-c",
        calls[2][0][-1],
    ]
    assert all(name in calls[2][0][-1] for name in ("opengrep", "gitleaks", "checkov"))
    assert all("A" * 43 not in " ".join(command) for command, _ in calls)
    assert all("B" * 43 not in " ".join(command) for command, _ in calls)
    assert all(kwargs["shell"] is False for _, kwargs in calls)
    assert all(kwargs["stdout"] == subprocess.DEVNULL for _, kwargs in calls)
    assert all(kwargs["stderr"] == subprocess.DEVNULL for _, kwargs in calls)
    assert environment["POSTGRES_PASSWORD"] == "A" * 43
    assert environment["SECRAGRAPH_READER_PASSWORD"] == "B" * 43
    assert environment["SECRAGRAPH_QDRANT_COLLECTION"] == "secragraph-auto-cwe"


def test_compose_failure_never_echoes_process_stderr(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    runtime = local_up.RuntimeSecrets(tmp_path / "runtime.env", "A" * 43, "B" * 43)

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            command, 1, stdout="", stderr=f"POSTGRES_PASSWORD={runtime.admin_password}"
        )

    monkeypatch.setattr(local_up.subprocess, "run", fake_run)
    with pytest.raises(local_up.StartupError) as error:
        local_up._start_compose(
            "docker", runtime, local_up._compose_environment(runtime, {}), tmp_path
        )

    assert runtime.admin_password not in str(error.value)
    assert runtime.admin_password not in capsys.readouterr().err


def test_offline_compose_rebuilds_current_source_without_service_image_pull(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runtime = local_up.RuntimeSecrets(tmp_path / "runtime.env", "A" * 43, "B" * 43)
    commands: list[list[str]] = []

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(local_up.subprocess, "run", fake_run)
    local_up._start_compose(
        "docker", runtime, local_up._compose_environment(runtime, {}), tmp_path, True
    )

    assert commands[1][6:] == [
        "up",
        "--build",
        "--pull",
        "never",
        "--detach",
        "--wait",
        "--wait-timeout",
        "240",
    ]


def test_runtime_env_persists_compose_mode_and_ports_without_provider_key(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(local_up, "_volume_exists", lambda _docker: False)
    runtime = local_up._load_or_create_runtime_env(tmp_path, "docker")
    environment = local_up._compose_environment(
        runtime,
        {
            "API_PORT": "18000",
            "POSTGRES_PORT": "15432",
            "QDRANT_PORT": "16333",
            "WEB_PORT": "18501",
            "SECRAGRAPH_QDRANT_VECTOR_DIMENSION": "768",
            "SECRAGRAPH_OPENAI_API_KEY": "secret-provider-key",
            "SECRAGRAPH_AUTO_OSV_ENABLED": "false",
            "SECRAGRAPH_AUTO_CWE_ENABLED": "false",
        },
    )
    local_up._persist_compose_config(runtime, environment)

    content = runtime.path.read_text(encoding="utf-8")
    assert environment["SECRAGRAPH_OPENAI_API_KEY"] == "secret-provider-key"
    assert "SECRAGRAPH_QDRANT_COLLECTION=secragraph-auto-cwe\n" in content
    assert "SECRAGRAPH_AUTO_OSV_ENABLED=false\n" in content
    assert "SECRAGRAPH_AUTO_CWE_ENABLED=false\n" in content
    assert "SECRAGRAPH_OPENAI_API_KEY=\n" in content
    assert "secret-provider-key" not in content
    assert "API_PORT=18000\n" in content
    assert "POSTGRES_PORT=15432\n" in content
    assert "SECRAGRAPH_QDRANT_VECTOR_DIMENSION=768\n" in content
    monkeypatch.setattr(local_up, "_volume_exists", lambda _docker: True)
    reopened = local_up._load_or_create_runtime_env(tmp_path, "docker")
    new_shell = local_up._compose_environment(reopened, {})
    assert new_shell["SECRAGRAPH_QDRANT_COLLECTION"] == "secragraph-auto-cwe"
    assert new_shell["SECRAGRAPH_AUTO_OSV_ENABLED"] == "false"
    assert new_shell["SECRAGRAPH_AUTO_CWE_ENABLED"] == "false"
    assert new_shell["SECRAGRAPH_OPENAI_API_KEY"] == ""
    assert new_shell["API_PORT"] == "18000"
    assert new_shell["POSTGRES_PORT"] == "15432"
    assert new_shell["SECRAGRAPH_QDRANT_VECTOR_DIMENSION"] == "768"


def test_legacy_secret_state_can_be_upgraded_without_replacing_passwords(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    path = tmp_path / "build/local/runtime.env"
    path.parent.mkdir(parents=True)
    path.write_text(
        f"POSTGRES_PASSWORD={'A' * 43}\nSECRAGRAPH_READER_PASSWORD={'B' * 43}\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(local_up, "_volume_exists", lambda _docker: True)
    runtime = local_up._load_or_create_runtime_env(tmp_path, "docker")
    environment = local_up._compose_environment(runtime, {})
    local_up._persist_compose_config(runtime, environment)

    assert runtime.admin_password == "A" * 43
    assert runtime.reader_password == "B" * 43
    assert "SECRAGRAPH_QDRANT_COLLECTION=secragraph-auto-cwe\n" in path.read_text(encoding="utf-8")


def test_offline_evaluations_run_fixed_guide_rag_evidence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: list[tuple[list[str], dict[str, object]]] = []

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(local_up.subprocess, "run", fake_run)
    local_up._run_evaluations(tmp_path)

    assert [command[2] for command, _ in calls] == ["scripts.run_rag_evidence"]
    assert all(command[1] == "-m" for command, _ in calls)
    assert all(
        command[-2:] == ["--output-dir", str(tmp_path / "build/evidence")] for command, _ in calls
    )
    temporary = str(tmp_path / "build/local/tmp")
    assert (tmp_path / "build/local/tmp").is_dir()
    assert all(kwargs["env"]["TMPDIR"] == temporary for _, kwargs in calls)
    assert all(kwargs["env"]["TEMP"] == temporary for _, kwargs in calls)
    assert all(kwargs["env"]["TMP"] == temporary for _, kwargs in calls)


def test_keyless_entrypoint_runs_one_pipeline_and_skips_live_indexing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    events: list[str] = []
    monkeypatch.setattr(local_up, "_ROOT", tmp_path)
    monkeypatch.setattr(local_up, "_docker_executable", lambda: "docker")
    monkeypatch.setattr(local_up, "_check_docker", lambda _docker: events.append("docker"))
    monkeypatch.setattr(local_up, "_volume_exists", lambda _docker: False)
    corpus = SimpleNamespace(
        root=tmp_path / "corpus",
        manifest_path=tmp_path / "corpus/manifest.json",
        coverage_path=tmp_path / "corpus/coverage.json",
        status="official",
        document_count=7,
    )
    monkeypatch.setattr(
        local_up,
        "_prepare_corpus",
        lambda *_args, **_kwargs: (events.append("corpus"), corpus)[1],
    )
    monkeypatch.setattr(local_up, "_run_evaluations", lambda _root: events.append("evaluation"))
    monkeypatch.setattr(
        local_up,
        "_start_compose",
        lambda *_args: events.append("compose"),
    )
    monkeypatch.setattr(
        local_up, "_seed_synthetic_samples", lambda *_args: events.append("samples")
    )
    monkeypatch.setattr(local_up, "_ensure_first_member", lambda *_args: events.append("member"))
    monkeypatch.setattr(local_up, "_check_health", lambda *_args: events.append("health"))
    monkeypatch.setattr(
        local_up,
        "_apply_corpus",
        lambda *_args: pytest.fail("provider-backed indexing needs a configured key"),
    )
    monkeypatch.delenv("SECRAGRAPH_OPENAI_API_KEY", raising=False)

    assert local_up.main([]) == 0
    assert events == ["docker", "corpus", "evaluation", "compose", "samples", "member", "health"]
    output = capsys.readouterr().out
    assert "RAG indexing unavailable" in output
    assert "offline" in output.lower()
    assert "official" in output


def test_keyed_entrypoint_indexes_official_collector_result(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(local_up, "_ROOT", tmp_path)
    monkeypatch.setattr(local_up, "_docker_executable", lambda: "docker")
    monkeypatch.setattr(local_up, "_check_docker", lambda _docker: None)
    monkeypatch.setattr(local_up, "_volume_exists", lambda _docker: False)
    corpus = SimpleNamespace(
        root=tmp_path / "corpus",
        manifest_path=tmp_path / "corpus/manifest.json",
        coverage_path=tmp_path / "corpus/coverage.json",
        status="official",
        document_count=7,
    )
    monkeypatch.setattr(local_up, "_prepare_corpus", lambda *_args, **_kwargs: corpus)
    monkeypatch.setattr(local_up, "_run_evaluations", lambda _root: None)
    events: list[str] = []
    monkeypatch.setattr(
        local_up, "_stop_api_web", lambda *_args: events.append("stop"), raising=False
    )

    def start_keyless(_docker, _runtime, environment, _root, _offline):
        assert environment["SECRAGRAPH_OPENAI_API_KEY"] == ""
        events.append("keyless-up")

    def activate(_docker, _runtime, environment, _root):
        assert environment["SECRAGRAPH_OPENAI_API_KEY"] == "secret-provider-key"
        events.append("activate")

    monkeypatch.setattr(local_up, "_start_compose", start_keyless)
    monkeypatch.setattr(local_up, "_recreate_api_web", activate, raising=False)
    monkeypatch.setattr(local_up, "_seed_synthetic_samples", lambda *_args: None)
    monkeypatch.setattr(local_up, "_ensure_first_member", lambda *_args: None)
    monkeypatch.setattr(local_up, "_check_health", lambda *_args: events.append("health"))
    indexed: list[object] = []

    def sync(value, *_args):
        indexed.append(value)
        events.append("sync")

    monkeypatch.setattr(local_up, "_apply_corpus", sync)
    monkeypatch.setenv("SECRAGRAPH_OPENAI_API_KEY", "secret-provider-key")

    assert local_up.main([]) == 0
    assert indexed == [corpus]
    assert events == ["stop", "keyless-up", "health", "sync", "activate", "health"]
    output = capsys.readouterr().out
    assert "RAG corpus indexed: official" in output
    assert "secret-provider-key" not in output


def test_failed_corpus_sync_stops_keyless_api_web_without_echoing_provider_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(local_up, "_ROOT", tmp_path)
    monkeypatch.setattr(local_up, "_docker_executable", lambda: "docker")
    monkeypatch.setattr(local_up, "_check_docker", lambda _docker: None)
    monkeypatch.setattr(local_up, "_volume_exists", lambda _docker: False)
    corpus = SimpleNamespace(
        root=tmp_path / "corpus",
        manifest_path=tmp_path / "corpus/manifest.json",
        coverage_path=tmp_path / "corpus/coverage.json",
        status="official",
        document_count=7,
    )
    monkeypatch.setattr(local_up, "_prepare_corpus", lambda *_args, **_kwargs: corpus)
    monkeypatch.setattr(local_up, "_run_evaluations", lambda _root: None)
    events: list[str] = []
    monkeypatch.setattr(
        local_up, "_stop_api_web", lambda *_args: events.append("stop"), raising=False
    )

    def start_keyless(_docker, _runtime, environment, _root, _offline):
        assert environment["SECRAGRAPH_OPENAI_API_KEY"] == ""
        events.append("keyless-up")

    monkeypatch.setattr(local_up, "_start_compose", start_keyless)
    monkeypatch.setattr(local_up, "_seed_synthetic_samples", lambda *_args: None)
    monkeypatch.setattr(local_up, "_ensure_first_member", lambda *_args: None)
    monkeypatch.setattr(local_up, "_check_health", lambda *_args: events.append("health"))

    def failed_sync(*_args):
        events.append("sync-failed")
        raise local_up.StartupError("secret-provider-key must not appear")

    monkeypatch.setattr(local_up, "_apply_corpus", failed_sync)
    monkeypatch.setattr(
        local_up,
        "_recreate_api_web",
        lambda *_args: pytest.fail("provider activation is forbidden after sync failure"),
        raising=False,
    )
    monkeypatch.setenv("SECRAGRAPH_OPENAI_API_KEY", "secret-provider-key")

    assert local_up.main([]) == 1
    assert events == ["stop", "keyless-up", "health", "sync-failed", "stop"]
    captured = capsys.readouterr()
    assert "Corpus indexing failed" in captured.err
    assert "secret-provider-key" not in captured.err
    assert "RAG corpus indexed" not in captured.out
    assert "SECRAGRAPH_OPENAI_API_KEY=\n" in (tmp_path / "build/local/runtime.env").read_text(
        encoding="utf-8"
    )


def test_provider_lifecycle_commands_touch_only_api_and_web(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runtime = local_up.RuntimeSecrets(tmp_path / "runtime.env", "A" * 43, "B" * 43)
    commands: list[list[str]] = []

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(local_up.subprocess, "run", fake_run)
    environment = local_up._compose_environment(
        runtime, {"SECRAGRAPH_OPENAI_API_KEY": "secret-provider-key"}
    )

    local_up._stop_api_web("docker", runtime, environment, tmp_path)
    local_up._recreate_api_web("docker", runtime, environment, tmp_path)

    assert commands[0][6:] == ["stop", "web", "api"]
    assert commands[1][6:] == [
        "up",
        "--no-deps",
        "--no-build",
        "--force-recreate",
        "--detach",
        "--wait",
        "--wait-timeout",
        "240",
        "api",
        "web",
    ]
    assert all("secret-provider-key" not in " ".join(command) for command in commands)
    assert all("--volumes" not in command and "-v" not in command for command in commands)


def test_failed_provider_activation_stops_api_web_and_hides_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(local_up, "_ROOT", tmp_path)
    monkeypatch.setattr(local_up, "_docker_executable", lambda: "docker")
    monkeypatch.setattr(local_up, "_check_docker", lambda _docker: None)
    monkeypatch.setattr(local_up, "_volume_exists", lambda _docker: False)
    corpus = SimpleNamespace(
        root=tmp_path / "corpus",
        manifest_path=tmp_path / "corpus/manifest.json",
        coverage_path=tmp_path / "corpus/coverage.json",
        status="official",
        document_count=7,
    )
    monkeypatch.setattr(local_up, "_prepare_corpus", lambda *_args, **_kwargs: corpus)
    monkeypatch.setattr(local_up, "_run_evaluations", lambda _root: None)
    events: list[str] = []
    monkeypatch.setattr(local_up, "_stop_api_web", lambda *_args: events.append("stop"))
    monkeypatch.setattr(local_up, "_start_compose", lambda *_args: events.append("keyless-up"))
    monkeypatch.setattr(local_up, "_seed_synthetic_samples", lambda *_args: None)
    monkeypatch.setattr(local_up, "_ensure_first_member", lambda *_args: None)
    monkeypatch.setattr(local_up, "_check_health", lambda *_args: events.append("health"))
    monkeypatch.setattr(local_up, "_apply_corpus", lambda *_args: events.append("sync"))

    def failed_activation(*_args):
        events.append("activation-failed")
        raise local_up.StartupError("secret-provider-key must not appear")

    monkeypatch.setattr(local_up, "_recreate_api_web", failed_activation)
    monkeypatch.setenv("SECRAGRAPH_OPENAI_API_KEY", "secret-provider-key")

    assert local_up.main([]) == 1
    assert events == ["stop", "keyless-up", "health", "sync", "activation-failed", "stop"]
    captured = capsys.readouterr()
    assert "Provider activation failed" in captured.err
    assert "secret-provider-key" not in captured.err
    assert "RAG corpus indexed" not in captured.out


def test_failed_stop_recreates_api_web_without_provider_key(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runtime = local_up.RuntimeSecrets(tmp_path / "runtime.env", "A" * 43, "B" * 43)
    keyless = local_up._compose_environment(runtime, {"SECRAGRAPH_OPENAI_API_KEY": ""})

    def failed_stop(*_args):
        raise local_up.StartupError("stop unavailable")

    recreated: list[dict[str, str]] = []
    monkeypatch.setattr(local_up, "_stop_api_web", failed_stop)
    monkeypatch.setattr(
        local_up,
        "_recreate_api_web",
        lambda _docker, _runtime, env, _root: recreated.append(dict(env)),
    )

    outcome = local_up._secure_api_web_after_failure("docker", runtime, keyless, tmp_path)

    assert "without a provider key" in outcome
    assert recreated[0]["SECRAGRAPH_OPENAI_API_KEY"] == ""


def test_keyed_fallback_disables_live_rag_and_preserves_existing_qdrant_data(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(local_up, "_ROOT", tmp_path)
    monkeypatch.setattr(local_up, "_docker_executable", lambda: "docker")
    monkeypatch.setattr(local_up, "_check_docker", lambda _docker: None)
    monkeypatch.setattr(local_up, "_volume_exists", lambda _docker: False)
    corpus = SimpleNamespace(
        root=tmp_path / "corpus",
        manifest_path=tmp_path / "corpus/manifest.json",
        coverage_path=tmp_path / "corpus/coverage.json",
        status="fallback",
        document_count=1,
    )
    monkeypatch.setattr(local_up, "_prepare_corpus", lambda *_args, **_kwargs: corpus)
    monkeypatch.setattr(local_up, "_run_evaluations", lambda _root: None)
    compose_environments: list[dict[str, str]] = []
    monkeypatch.setattr(
        local_up,
        "_start_compose",
        lambda _docker, _runtime, environment, _root, _offline: compose_environments.append(
            dict(environment)
        ),
    )
    monkeypatch.setattr(local_up, "_seed_synthetic_samples", lambda *_args: None)
    monkeypatch.setattr(local_up, "_ensure_first_member", lambda *_args: None)
    monkeypatch.setattr(local_up, "_check_health", lambda *_args: None)
    monkeypatch.setattr(
        local_up,
        "_apply_corpus",
        lambda *_args: pytest.fail("fallback must not overwrite or mix Qdrant evidence"),
    )
    monkeypatch.setenv("SECRAGRAPH_OPENAI_API_KEY", "secret-provider-key")

    assert local_up.main([]) == 0
    assert compose_environments[0]["SECRAGRAPH_OPENAI_API_KEY"] == ""
    assert compose_environments[0]["SECRAGRAPH_QDRANT_COLLECTION"] == "secragraph-auto-cwe"
    output = capsys.readouterr().out
    assert "live RAG disabled" in output
    assert "project-authored" in output
    assert "secret-provider-key" not in output


def test_offline_option_disables_provider_and_automatic_osv_even_with_key(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(local_up, "_ROOT", tmp_path)
    monkeypatch.setattr(local_up, "_docker_executable", lambda: "docker")
    monkeypatch.setattr(local_up, "_check_docker", lambda _docker: None)
    monkeypatch.setattr(local_up, "_volume_exists", lambda _docker: False)
    corpus = SimpleNamespace(
        root=tmp_path / "corpus",
        manifest_path=tmp_path / "corpus/manifest.json",
        coverage_path=tmp_path / "corpus/coverage.json",
        status="cached",
        document_count=7,
    )
    offline_arguments: list[bool] = []

    def fake_prepare(_root: Path, *, offline: bool) -> object:
        offline_arguments.append(offline)
        return corpus

    monkeypatch.setattr(local_up, "_prepare_corpus", fake_prepare)
    monkeypatch.setattr(local_up, "_run_evaluations", lambda _root: None)
    compose_environments: list[dict[str, str]] = []
    monkeypatch.setattr(
        local_up,
        "_start_compose",
        lambda _docker, _runtime, environment, _root, _offline: compose_environments.append(
            dict(environment)
        ),
    )
    monkeypatch.setattr(local_up, "_seed_synthetic_samples", lambda *_args: None)
    monkeypatch.setattr(local_up, "_ensure_first_member", lambda *_args: None)
    monkeypatch.setattr(local_up, "_check_health", lambda *_args: None)
    monkeypatch.setattr(
        local_up,
        "_apply_corpus",
        lambda *_args: pytest.fail("offline mode must not call an embedding provider"),
    )
    monkeypatch.setenv("SECRAGRAPH_OPENAI_API_KEY", "secret-provider-key")
    monkeypatch.setenv("SECRAGRAPH_AUTO_OSV_ENABLED", "true")
    monkeypatch.setenv("SECRAGRAPH_AUTO_CWE_ENABLED", "true")

    assert local_up.main(["--offline"]) == 0
    assert offline_arguments == [True]
    assert compose_environments[0]["SECRAGRAPH_OPENAI_API_KEY"] == ""
    assert compose_environments[0]["SECRAGRAPH_AUTO_OSV_ENABLED"] == "false"
    assert compose_environments[0]["SECRAGRAPH_AUTO_CWE_ENABLED"] == "false"
    persisted = (tmp_path / "build/local/runtime.env").read_text(encoding="utf-8")
    assert "SECRAGRAPH_AUTO_OSV_ENABLED=false\n" in persisted
    assert "SECRAGRAPH_AUTO_CWE_ENABLED=false\n" in persisted
    assert "SECRAGRAPH_QDRANT_COLLECTION=secragraph-auto-cwe\n" in persisted
    assert "SECRAGRAPH_OPENAI_API_KEY=\n" in persisted
    output = capsys.readouterr().out
    assert "offline mode" in output
    assert "secret-provider-key" not in output


def test_normal_rerun_reenables_automatic_osv_after_offline_mode(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(local_up, "_ROOT", tmp_path)
    monkeypatch.setattr(local_up, "_docker_executable", lambda: "docker")
    monkeypatch.setattr(local_up, "_check_docker", lambda _docker: None)
    monkeypatch.setattr(local_up, "_volume_exists", lambda _docker: False)
    corpus = SimpleNamespace(
        root=tmp_path / "corpus",
        manifest_path=tmp_path / "corpus/manifest.json",
        coverage_path=tmp_path / "corpus/coverage.json",
        status="cached",
        document_count=7,
    )
    monkeypatch.setattr(local_up, "_prepare_corpus", lambda *_args, **_kwargs: corpus)
    monkeypatch.setattr(local_up, "_run_evaluations", lambda _root: None)
    modes: list[tuple[str, str]] = []
    monkeypatch.setattr(
        local_up,
        "_start_compose",
        lambda _docker, _runtime, env, _root, _offline: modes.append(
            (env["SECRAGRAPH_AUTO_OSV_ENABLED"], env["SECRAGRAPH_AUTO_CWE_ENABLED"])
        ),
    )
    monkeypatch.setattr(local_up, "_seed_synthetic_samples", lambda *_args: None)
    monkeypatch.setattr(local_up, "_ensure_first_member", lambda *_args: None)
    monkeypatch.setattr(local_up, "_check_health", lambda *_args: None)
    monkeypatch.setattr(local_up, "_apply_corpus", lambda *_args: None)
    monkeypatch.delenv("SECRAGRAPH_AUTO_OSV_ENABLED", raising=False)
    monkeypatch.delenv("SECRAGRAPH_AUTO_CWE_ENABLED", raising=False)
    monkeypatch.delenv("SECRAGRAPH_OPENAI_API_KEY", raising=False)

    assert local_up.main(["--offline"]) == 0
    assert local_up.main([]) == 0
    assert modes == [("false", "false"), ("true", "true")]
    assert "SECRAGRAPH_AUTO_OSV_ENABLED=true\n" in (tmp_path / "build/local/runtime.env").read_text(
        encoding="utf-8"
    )
    assert "SECRAGRAPH_AUTO_CWE_ENABLED=true\n" in (tmp_path / "build/local/runtime.env").read_text(
        encoding="utf-8"
    )


def test_failed_evaluation_keeps_previous_compose_mode(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(local_up, "_volume_exists", lambda _docker: False)
    runtime = local_up._load_or_create_runtime_env(tmp_path, "docker")
    local_up._persist_compose_config(
        runtime,
        local_up._compose_environment(runtime, {"SECRAGRAPH_AUTO_OSV_ENABLED": "false"}),
    )
    monkeypatch.setattr(local_up, "_ROOT", tmp_path)
    monkeypatch.setattr(local_up, "_docker_executable", lambda: "docker")
    monkeypatch.setattr(local_up, "_check_docker", lambda _docker: None)
    corpus = SimpleNamespace(
        root=tmp_path / "corpus",
        manifest_path=tmp_path / "corpus/manifest.json",
        coverage_path=tmp_path / "corpus/coverage.json",
        status="cached",
        document_count=7,
    )
    monkeypatch.setattr(local_up, "_prepare_corpus", lambda *_args, **_kwargs: corpus)

    def failed_evaluation(_root: Path) -> None:
        raise local_up.StartupError("evaluation failed")

    monkeypatch.setattr(local_up, "_run_evaluations", failed_evaluation)
    monkeypatch.setattr(
        local_up, "_start_compose", lambda *_args: pytest.fail("Compose must not start")
    )
    monkeypatch.delenv("SECRAGRAPH_AUTO_OSV_ENABLED", raising=False)

    assert local_up.main([]) == 1
    assert "SECRAGRAPH_AUTO_OSV_ENABLED=false\n" in runtime.path.read_text(encoding="utf-8")


def test_existing_knowledge_is_not_overwritten_by_synthetic_samples(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    class FakeConnection:
        def __init__(self) -> None:
            self.counts = iter((1, 0))

        def __enter__(self) -> FakeConnection:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def scalar(self, _statement: object) -> int:
            return next(self.counts)

    class FakeEngine:
        def __init__(self) -> None:
            self.disposed = False

        def connect(self) -> FakeConnection:
            return FakeConnection()

        def dispose(self) -> None:
            self.disposed = True

    engine = FakeEngine()
    monkeypatch.setattr(local_up, "_database_engine", lambda *_args: engine)
    monkeypatch.setattr(
        local_up,
        "import_intelligence_data",
        lambda *_args: pytest.fail("existing intelligence must be preserved"),
    )
    runtime = local_up.RuntimeSecrets(tmp_path / "runtime.env", "A" * 43, "B" * 43)

    local_up._seed_synthetic_samples(runtime, {}, tmp_path)

    assert engine.disposed
    assert "synthetic sample import skipped" in capsys.readouterr().out


def test_existing_member_skips_password_prompt_on_rerun(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    class FakeSession:
        def __init__(self, _engine: object) -> None:
            pass

        def __enter__(self) -> FakeSession:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def scalar(self, _statement: object) -> int:
            return 1

    class FakeEngine:
        disposed = False

        def dispose(self) -> None:
            self.disposed = True

    engine = FakeEngine()
    monkeypatch.setattr(local_up, "_database_engine", lambda *_args: engine)
    monkeypatch.setattr(local_up, "Session", FakeSession)
    monkeypatch.setattr(
        local_up, "_prompt_initial_member", lambda: pytest.fail("existing member needs no prompt")
    )
    runtime = local_up.RuntimeSecrets(tmp_path / "runtime.env", "A" * 43, "B" * 43)

    local_up._ensure_first_member(runtime, {})

    assert engine.disposed
    assert "Existing member account retained" in capsys.readouterr().out


def test_provider_indexing_keeps_key_out_of_command_arguments(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: list[tuple[list[str], dict[str, object]]] = []

    def fake_run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append((command, kwargs))
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(local_up.subprocess, "run", fake_run)
    corpus = SimpleNamespace(root=tmp_path / "corpus", manifest_path=tmp_path / "manifest.json")
    local_up._apply_corpus(
        corpus,
        {
            "SECRAGRAPH_OPENAI_API_KEY": "secret-provider-key",
            "SECRAGRAPH_QDRANT_COLLECTION": "secragraph-auto-cwe",
            "QDRANT_PORT": "26333",
        },
        tmp_path,
    )

    command, kwargs = calls[0]
    assert command[1:4] == ["-m", "security_review.cli", "sync-corpus"]
    assert command[4:8] == [str(corpus.root), "--manifest", str(corpus.manifest_path), "--apply"]
    assert "secret-provider-key" not in " ".join(command)
    assert kwargs["env"]["SECRAGRAPH_OPENAI_API_KEY"] == "secret-provider-key"
    assert kwargs["env"]["SECRAGRAPH_QDRANT_URL"] == "http://127.0.0.1:26333"
    assert kwargs["env"]["SECRAGRAPH_QDRANT_COLLECTION"] == "secragraph-auto-cwe"


def test_module_entrypoint_reaches_existing_volume_guard(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    script = tmp_path / "scripts/local_up.py"
    script.parent.mkdir()
    script.write_bytes(Path(local_up.__file__).read_bytes())
    monkeypatch.setattr(local_up.shutil, "which", lambda _name: "docker")

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        output = "secragraph_postgres_data\n" if command[1:3] == ["volume", "ls"] else ""
        return subprocess.CompletedProcess(command, 0, stdout=output, stderr="")

    monkeypatch.setattr(local_up.subprocess, "run", fake_run)
    monkeypatch.setattr(sys, "argv", [str(script)])

    with pytest.raises(SystemExit) as exit_code:
        runpy.run_path(str(script), run_name="__main__")

    assert exit_code.value.code == 1
    assert "existing PostgreSQL volume" in capsys.readouterr().err
    assert not (tmp_path / "build/local/runtime.env").exists()
