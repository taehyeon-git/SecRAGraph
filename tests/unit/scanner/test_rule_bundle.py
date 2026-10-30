"""Provenance gate for rules executed on member uploads."""

import json
from hashlib import sha256
from pathlib import Path


def test_vendored_opengrep_rules_match_pinned_manifest() -> None:
    root = Path(__file__).resolve().parents[3] / "data" / "engines" / "opengrep"
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["upstream_commit"] == "1118d79823ae756534678378a4aac0cbfa5d3041"
    assert manifest["license"] == "MIT"
    assert (root / "LICENSE").read_text(encoding="utf-8").startswith("MIT License")
    actual = {
        path.relative_to(root).as_posix(): sha256(path.read_bytes()).hexdigest()
        for path in root.rglob("*.yml")
    }
    assert actual == manifest["files"]
    assert len(actual) == 79
    assert {
        path: patch["upstream_sha256"] for path, patch in manifest["local_patches"].items()
    } == {
        "python/sql/rule-hardcoded-sql-expression.yml": (
            "f054dce5ef49e24a0b1faa12f3787ea657f539f2b9c733498313c78681271559"
        ),
    }
    assert all(
        patch["upstream_sha256"] != actual[path] and patch["reason"]
        for path, patch in manifest["local_patches"].items()
    )


def test_owasp_challenge_rule_hashes_follow_bundled_rules() -> None:
    root = Path(__file__).resolve().parents[3] / "data" / "engines"
    challenge = json.loads(
        (root.parent / "evaluation" / "owasp_python_v0.1_challenge.json").read_text(
            encoding="utf-8"
        )
    )
    for rule in challenge["rules"]:
        actual = sha256(root.joinpath(*Path(rule["config_path"]).parts).read_bytes()).hexdigest()
        assert actual == rule["sha256"]
