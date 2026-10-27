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
