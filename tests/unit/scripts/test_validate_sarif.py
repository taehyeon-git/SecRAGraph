"""Contracts for the local Code Scanning SARIF gate."""

import json
import subprocess
from pathlib import Path

import pytest

from scripts.validate_sarif import validate_sarif


def make_sarif(
    uri: str = "src/app.py", fingerprint: str = "PY001:stable", line: int = 3
) -> dict[str, object]:
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "SecRAGraph"}},
                "results": [
                    {
                        "ruleId": "PY001",
                        "partialFingerprints": {"primaryLocationLineHash": fingerprint},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": uri},
                                    "region": {"startLine": line},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }


def check(
    tmp_path: Path, payload: dict[str, object], *, stage_sources: bool = True
) -> tuple[str, ...]:
    source = tmp_path / "src"
    source.mkdir(exist_ok=True)
    (source / "app.py").write_text("answer = 42\n", encoding="utf-8")
    if not (tmp_path / ".git").exists():
        subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)  # noqa: S603, S607
    if stage_sources:
        subprocess.run(  # noqa: S603 - fixed git command in a disposable test repository
            ["git", "-C", str(tmp_path), "add", "--", "src"],  # noqa: S607
            check=True,
        )
    path = tmp_path / "result.sarif"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return validate_sarif(path, repository_root=tmp_path).errors


def test_validator_accepts_minimal_valid_sarif(tmp_path: Path) -> None:
    assert check(tmp_path, make_sarif()) == ()


def test_validator_accepts_encoded_filename_characters(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "config file#1%.py").write_text("answer = 42\n", encoding="utf-8")
    assert check(tmp_path, make_sarif(uri="src/config%20file%231%25.py")) == ()


@pytest.mark.parametrize("uri", ["src/missing.py", "examples/insecure/x.py"])
def test_validator_rejects_missing_or_out_of_scope_source(tmp_path: Path, uri: str) -> None:
    if uri.startswith("examples/"):
        outside = tmp_path / uri
        outside.parent.mkdir(parents=True)
        outside.write_text("answer = 42\n", encoding="utf-8")
    assert check(tmp_path, make_sarif(uri=uri)) == (
        f"artifact URI must resolve to a repository src file: {uri}",
    )


def test_validator_rejects_untracked_source_in_git_checkout(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "untracked.py").write_text("answer = 42\n", encoding="utf-8")
    assert check(tmp_path, make_sarif(uri="src/untracked.py"), stage_sources=False) == (
        "artifact URI must resolve to a repository src file: src/untracked.py",
    )


def test_validator_requires_git_checkout(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("answer = 42\n", encoding="utf-8")
    path = tmp_path / "result.sarif"
    path.write_text(json.dumps(make_sarif()), encoding="utf-8")

    assert validate_sarif(path, repository_root=tmp_path).errors == (
        "SARIF repository root is not a Git checkout",
    )


@pytest.mark.parametrize("uri", ["C:/workspace/app.py", "/workspace/app.py", "file:///app.py"])
def test_validator_rejects_absolute_artifact_uri(tmp_path: Path, uri: str) -> None:
    assert check(tmp_path, make_sarif(uri=uri)) == (f"artifact URI must be relative: {uri}",)


@pytest.mark.parametrize("uri", ["../app.py", "src/%2e%2e/app.py", "src/..%5capp.py"])
def test_validator_rejects_artifact_traversal(tmp_path: Path, uri: str) -> None:
    assert check(tmp_path, make_sarif(uri=uri)) == (f"artifact URI has traversal: {uri}",)


def test_validator_rejects_wrong_schema_version(tmp_path: Path) -> None:
    payload = make_sarif()
    payload["version"] = "2.0.0"
    assert check(tmp_path, payload) == ("SARIF version must be 2.1.0",)


def test_validator_requires_driver_name(tmp_path: Path) -> None:
    payload = make_sarif()
    payload["runs"][0]["tool"]["driver"]["name"] = ""  # type: ignore[index]
    assert check(tmp_path, payload) == ("SARIF driver name must be SecRAGraph",)


def test_validator_rejects_duplicate_fingerprints(tmp_path: Path) -> None:
    payload = make_sarif()
    result = payload["runs"][0]["results"][0]  # type: ignore[index]
    payload["runs"][0]["results"].append(result)  # type: ignore[index]
    assert check(tmp_path, payload) == ("duplicate primaryLocationLineHash: PY001:stable",)


def test_validator_requires_recognized_fingerprint(tmp_path: Path) -> None:
    payload = make_sarif()
    result = payload["runs"][0]["results"][0]  # type: ignore[index]
    result["partialFingerprints"] = {"findingId": "PY001:stable"}
    assert check(tmp_path, payload) == ("result 0 missing primaryLocationLineHash",)


@pytest.mark.parametrize("line", [0, -1])
def test_validator_requires_one_based_line(tmp_path: Path, line: int) -> None:
    assert check(tmp_path, make_sarif(line=line)) == ("result 0 startLine must be >= 1",)


def test_validator_rejects_undeclared_base_id(tmp_path: Path) -> None:
    payload = make_sarif()
    location = payload["runs"][0]["results"][0]["locations"][0]["physicalLocation"][  # type: ignore[index]
        "artifactLocation"
    ]
    location["uriBaseId"] = "%SRCROOT%"
    assert check(tmp_path, payload) == ("undeclared uriBaseId: %SRCROOT%",)


def test_validator_rejects_declared_base_outside_repository(tmp_path: Path) -> None:
    payload = make_sarif()
    run = payload["runs"][0]  # type: ignore[index]
    run["originalUriBaseIds"] = {"%SRCROOT%": {"uri": "file:///tmp/outside/"}}
    artifact = run["results"][0]["locations"][0]["physicalLocation"][  # type: ignore[index]
        "artifactLocation"
    ]
    artifact["uriBaseId"] = "%SRCROOT%"
    assert "SARIF URI bases are not supported" in check(tmp_path, payload)


def test_validator_rejects_controlled_fake_secret(tmp_path: Path) -> None:
    payload = make_sarif()
    payload["runs"][0]["results"][0]["message"] = {  # type: ignore[index]
        "text": "sk-test-never-render-this"
    }
    assert check(tmp_path, payload) == ("controlled fake secret leaked into SARIF",)
