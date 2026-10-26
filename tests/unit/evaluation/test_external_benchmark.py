"""Pinned OWASP-style cases are data, never executed by the adapter."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from shutil import which

import pytest

from security_review.evaluation.external_benchmark import run_external_benchmark


def _git(root: Path, *arguments: str) -> str:
    executable = which("git")
    assert executable is not None
    result = subprocess.run(  # noqa: S603
        [executable, *arguments],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )
    return result.stdout.strip()


def _checkout(root: Path, *, missing: bool = False, duplicate: bool = False) -> tuple[str, str]:
    (root / "testcode").mkdir()
    cases = {
        "BenchmarkTest00001": "import subprocess\nsubprocess.run(user, shell=True)\n",
        "BenchmarkTest00002": "import subprocess\nsubprocess.run(user, shell=True)\n",
        "BenchmarkTest00003": "import pickle\nvalue = pickle.loads(user)\n",
        "BenchmarkTest00004": "import yaml\nvalue = yaml.safe_load(user)\n",
        "BenchmarkTest00005": 'cursor.execute(f"SELECT * FROM users WHERE id={user}")\n',
        "BenchmarkTest00006": "raise AssertionError('must never execute')\n",
    }
    for case_id, source in cases.items():
        if not (missing and case_id == "BenchmarkTest00003"):
            (root / "testcode" / f"{case_id}.py").write_text(source, encoding="utf-8")
    rows = [
        "# test name, category, real vulnerability, cwe, Benchmark version: 0.1",
        "BenchmarkTest00001,cmdi,true,78",
        "BenchmarkTest00002,cmdi,false,78",
        "BenchmarkTest00003,deserialization,true,502",
        "BenchmarkTest00004,deserialization,false,502",
        "BenchmarkTest00005,sqli,true,89",
        "BenchmarkTest00006,unsupported,true,999",
    ]
    if duplicate:
        rows.append("BenchmarkTest00001,cmdi,false,78")
    expected = root / "expectedresults-0.1.csv"
    expected.write_text("\n".join(rows) + "\n", encoding="utf-8")
    _git(root, "init", "-q")
    _git(root, "add", "expectedresults-0.1.csv", "testcode")
    _git(
        root,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.com",
        "commit",
        "-qm",
        "fixture",
    )
    return _git(root, "rev-parse", "HEAD"), hashlib.sha256(expected.read_bytes()).hexdigest()


def test_case_level_challenge_counts_and_unsupported_cwe_are_explicit(tmp_path: Path) -> None:
    revision, digest = _checkout(tmp_path)

    result = run_external_benchmark(tmp_path, revision, digest)

    assert (result.tp, result.fp, result.fn, result.tn) == (3, 1, 0, 1)
    assert result.labeled_total == 6
    assert result.challenge_labeled == 5
    assert result.scored_cases == 5
    assert result.unsupported_cwe_counts == {"CWE-999": 1}
    assert result.missing_case_ids == ()
    assert result.broad_cwe_challenge is True
    by_id = {case.case_id: case for case in result.cases}
    assert by_id["BenchmarkTest00005"].expected_rule_ids == ("PY005",)
    assert by_id["BenchmarkTest00003"].matched_rule_ids == ("PY006",)
    assert "pickle" in result.coverage_note


def test_cwe_502_ignores_unrelated_supported_rule_matches(tmp_path: Path) -> None:
    revision, digest = _checkout(tmp_path)
    source = tmp_path / "testcode" / "BenchmarkTest00003.py"
    source.write_text("import subprocess\nsubprocess.run(user, shell=True)\n", encoding="utf-8")
    _git(tmp_path, "add", "testcode/BenchmarkTest00003.py")
    _git(
        tmp_path,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.com",
        "commit",
        "-qm",
        "unrelated",
    )
    revision = _git(tmp_path, "rev-parse", "HEAD")

    result = run_external_benchmark(tmp_path, revision, digest)
    case = next(case for case in result.cases if case.case_id == "BenchmarkTest00003")

    assert case.expected_rule_ids == ("PY004", "PY006")
    assert case.matched_rule_ids == ()
    assert case.detected is False


def test_missing_challenge_source_is_recorded_without_shrinking_denominator(
    tmp_path: Path,
) -> None:
    revision, digest = _checkout(tmp_path, missing=True)

    result = run_external_benchmark(tmp_path, revision, digest)

    assert result.challenge_labeled == 5
    assert result.scored_cases == 4
    assert result.missing_case_ids == ("BenchmarkTest00003",)
    assert result.has_errors is True


@pytest.mark.parametrize("problem", ["revision", "digest", "duplicate", "dirty"])
def test_unpinned_or_malformed_inputs_are_rejected(tmp_path: Path, problem: str) -> None:
    revision, digest = _checkout(tmp_path, duplicate=problem == "duplicate")
    if problem == "revision":
        revision = "0" * 40
    elif problem == "digest":
        digest = "0" * 64
    elif problem == "dirty":
        (tmp_path / "testcode" / "BenchmarkTest00001.py").write_text("eval(user)", encoding="utf-8")

    with pytest.raises(ValueError):
        run_external_benchmark(tmp_path, revision, digest)


def test_cli_writes_error_record_and_returns_nonzero_for_missing_case(tmp_path: Path) -> None:
    from scripts.run_external_scanner_benchmark import main

    revision, digest = _checkout(tmp_path, missing=True)
    output = tmp_path / "evidence.json"
    exit_code = main(
        [
            "--root",
            str(tmp_path),
            "--revision",
            revision,
            "--expected-sha256",
            digest,
            "--output",
            str(output),
        ]
    )

    assert exit_code == 1
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["challenge_labeled"] == 5
    assert payload["missing_case_ids"] == ["BenchmarkTest00003"]
