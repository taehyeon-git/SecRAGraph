import hashlib
import json
from pathlib import Path

import pytest

from scripts.run_owasp_case_challenge import _is_complete, _isolated_taint_yaml
from security_review.evaluation.owasp_case_challenge import (
    ChallengeCase,
    ChallengeInputError,
    RuleSpec,
    load_pinned_cases,
    score_case_level,
)


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def test_case_level_scores_use_only_upstream_cwe_labels() -> None:
    cases = (
        ChallengeCase("BenchmarkTest00001", "CWE-78", True, "BenchmarkTest00001.py"),
        ChallengeCase("BenchmarkTest00002", "CWE-78", False, "BenchmarkTest00002.py"),
        ChallengeCase("BenchmarkTest00003", "CWE-89", True, "BenchmarkTest00003.py"),
        ChallengeCase("BenchmarkTest00004", "CWE-89", False, "BenchmarkTest00004.py"),
    )
    rules = (
        RuleSpec("OG/python_exec_a", "CWE-78", "python/a.yml", "0" * 64),
        RuleSpec("OG/python_sql_b", "CWE-89", "python/b.yml", "1" * 64),
    )
    scores = score_case_level(
        cases,
        rules,
        {
            "OG/python_exec_a": {"BenchmarkTest00001.py", "BenchmarkTest00002.py"},
            "OG/python_sql_b": set(),
        },
        {case.source_path for case in cases},
    )

    assert scores["overall"] == {"tp": 1, "fp": 1, "fn": 1, "tn": 1, "scored": 4, "unscored": 0}
    assert scores["by_rule"]["OG/python_exec_a"] == {
        "tp": 1,
        "fp": 1,
        "fn": 0,
        "tn": 0,
        "scored": 2,
        "unscored": 0,
    }
    assert scores["by_rule"]["OG/python_sql_b"] == {
        "tp": 0,
        "fp": 0,
        "fn": 1,
        "tn": 1,
        "scored": 2,
        "unscored": 0,
    }


def test_unscanned_case_is_not_false_negative() -> None:
    cases = (
        ChallengeCase("BenchmarkTest00001", "CWE-78", True, "BenchmarkTest00001.py"),
        ChallengeCase("BenchmarkTest00002", "CWE-78", False, "BenchmarkTest00002.py"),
    )
    rules = (RuleSpec("OG/python_exec_a", "CWE-78", "python/a.yml", "0" * 64),)

    scores = score_case_level(cases, rules, {}, {"BenchmarkTest00002.py"})

    assert scores["overall"] == {"tp": 0, "fp": 0, "fn": 0, "tn": 1, "scored": 1, "unscored": 1}


def test_complete_gate_does_not_require_explicitly_skipped_optional_timings() -> None:
    skipped = {"OG/rule": {"status": "not_run"}}

    assert _is_complete("completed", 0, skipped, timing_requested=False)
    assert not _is_complete("completed", 0, skipped, timing_requested=True)


def test_isolated_taint_yaml_keeps_only_requested_rule() -> None:
    combined = (
        "rules:\n"
        "  - id: python-web-command-taint\n"
        "    mode: taint\n"
        "    metadata:\n"
        "      cwe: CWE-78\n"
        "  - id: python-web-sql-taint\n"
        "    mode: taint\n"
        "    metadata:\n"
        "      cwe: CWE-89\n"
    )

    isolated = _isolated_taint_yaml(combined, "OG/python-web-command-taint")

    assert isolated.startswith("rules:\n  - id: python-web-command-taint\n")
    assert "python-web-sql-taint" not in isolated


def test_loader_verifies_csv_and_source_hashes_and_derives_labels(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    testcode = checkout / "testcode"
    testcode.mkdir(parents=True)
    git_ref = checkout / ".git" / "refs" / "heads" / "main"
    git_ref.parent.mkdir(parents=True)
    (checkout / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    git_ref.write_text("a" * 40 + "\n", encoding="utf-8")
    csv_body = (
        b"# source labels\nBenchmarkTest00001,cmdi,true,78\nBenchmarkTest00002,cmdi,false,78\n"
    )
    (checkout / "expectedresults-0.1.csv").write_bytes(csv_body)
    first = b"print('first')\n"
    second = b"print('second')\n"
    (testcode / "BenchmarkTest00001.py").write_bytes(first)
    (testcode / "BenchmarkTest00002.py").write_bytes(second)
    rules_root = tmp_path / "rules"
    (rules_root / "opengrep" / "python").mkdir(parents=True)
    (rules_root / "secragraph-taint").mkdir()
    rule_body = b'rules:\n- id: python_exec_a\n  metadata:\n    cwe: "CWE-78"\n'
    (rules_root / "opengrep" / "python" / "a.yml").write_bytes(rule_body)
    taint_body = b"rules:\n  - id: python-web-command-taint\n    metadata:\n      cwe: CWE-78\n"
    (rules_root / "secragraph-taint" / "python.yml").write_bytes(taint_body)
    manifest = {
        "schema_version": 1,
        "source_url": "https://github.com/OWASP-Benchmark/BenchmarkPython",
        "source_revision": "a" * 40,
        "license": "GPL-3.0-only",
        "ground_truth_path": "expectedresults-0.1.csv",
        "ground_truth_sha256": _sha(csv_body),
        "selected_cwes": ["CWE-78"],
        "source_hashes": {
            "BenchmarkTest00001": _sha(first),
            "BenchmarkTest00002": _sha(second),
        },
        "rules": [
            {
                "rule_id": "OG/python_exec_a",
                "cwe_id": "CWE-78",
                "config_path": "opengrep/python/a.yml",
                "sha256": _sha(rule_body),
            },
            {
                "rule_id": "OG/python-web-command-taint",
                "cwe_id": "CWE-78",
                "config_path": "secragraph-taint/python.yml",
                "sha256": _sha(taint_body),
            },
        ],
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    corpus = load_pinned_cases(checkout, manifest_path, rules_root)

    assert [(case.case_id, case.vulnerable) for case in corpus.cases] == [
        ("BenchmarkTest00001", True),
        ("BenchmarkTest00002", False),
    ]
    assert corpus.source_revision == "a" * 40
    assert len(corpus.rules) == 2

    git_ref.write_text("b" * 40 + "\n", encoding="utf-8")
    with pytest.raises(ChallengeInputError, match="source_revision_mismatch"):
        load_pinned_cases(checkout, manifest_path, rules_root)
    git_ref.write_text("a" * 40 + "\n", encoding="utf-8")

    (testcode / "BenchmarkTest00001.py").write_text("tampered\n", encoding="utf-8")
    with pytest.raises(ChallengeInputError, match="source_hash_mismatch"):
        load_pinned_cases(checkout, manifest_path, rules_root)
