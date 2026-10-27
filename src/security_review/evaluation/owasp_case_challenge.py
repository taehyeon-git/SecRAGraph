"""Pinned, case-level OWASP BenchmarkPython challenge.

OWASP publishes a vulnerability boolean and CWE for each case, not source-line
or scanner-rule truth. This module deliberately scores only those broad labels.
"""

from __future__ import annotations

import csv
import json
import re
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path, PurePosixPath
from typing import Any

_SHA = re.compile(r"[0-9a-f]{64}\Z")
_REVISION = re.compile(r"[0-9a-f]{40}\Z")
_CASE = re.compile(r"BenchmarkTest[0-9]{5}\Z")
_CWE = re.compile(r"CWE-[1-9][0-9]{0,5}\Z")
_RULE = re.compile(r"OG/[A-Za-z0-9_.-]{1,110}\Z")
_MAX_MANIFEST_BYTES = 100_000
_MAX_CSV_BYTES = 2_000_000
_MAX_SOURCE_BYTES = 1_000_000
_MAX_RULE_BYTES = 100_000


class ChallengeInputError(ValueError):
    """A pinned input is missing or differs from the recorded source."""


@dataclass(frozen=True, slots=True)
class ChallengeCase:
    case_id: str
    cwe_id: str
    vulnerable: bool
    source_path: str


@dataclass(frozen=True, slots=True)
class RuleSpec:
    rule_id: str
    cwe_id: str
    config_path: str
    sha256: str


@dataclass(frozen=True, slots=True)
class ChallengeCorpus:
    source_url: str
    source_revision: str
    license: str
    ground_truth_sha256: str
    manifest_sha256: str
    cases: tuple[ChallengeCase, ...]
    rules: tuple[RuleSpec, ...]


def _read_bounded(path: Path, maximum: int, code: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ChallengeInputError(code)
    try:
        with path.open("rb") as stream:
            body = stream.read(maximum + 1)
    except OSError as error:
        raise ChallengeInputError(code) from error
    if len(body) > maximum or b"\x00" in body:
        raise ChallengeInputError(code)
    return body


def _sha_field(value: object, code: str) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise ChallengeInputError(code)
    return value


def _checkout_revision(checkout: Path) -> str:
    """Resolve the checked-out commit without requiring Git inside the scanner image."""

    git_dir = checkout / ".git"
    if git_dir.is_symlink() or not git_dir.is_dir():
        raise ChallengeInputError("git_checkout_required")
    try:
        head = _read_bounded(git_dir / "HEAD", 256, "git_head_unavailable").decode("ascii").strip()
    except UnicodeError as error:
        raise ChallengeInputError("git_head_invalid") from error
    if head.startswith("ref: "):
        ref = head[5:]
        logical = PurePosixPath(ref)
        if (
            not ref.startswith("refs/")
            or logical.is_absolute()
            or ".." in logical.parts
            or any(not re.fullmatch(r"[A-Za-z0-9_.-]+", part) for part in logical.parts)
        ):
            raise ChallengeInputError("git_head_invalid")
        ref_file = git_dir.joinpath(*logical.parts)
        if ref_file.is_file():
            try:
                head = _read_bounded(ref_file, 128, "git_ref_unavailable").decode("ascii").strip()
            except UnicodeError as error:
                raise ChallengeInputError("git_ref_invalid") from error
        else:
            try:
                packed = _read_bounded(
                    git_dir / "packed-refs", 200_000, "git_ref_unavailable"
                ).decode("ascii")
            except UnicodeError as error:
                raise ChallengeInputError("git_ref_invalid") from error
            matches = [
                line.split(" ", 1)[0] for line in packed.splitlines() if line.endswith(f" {ref}")
            ]
            if len(matches) != 1:
                raise ChallengeInputError("git_ref_unavailable")
            head = matches[0]
    if not _REVISION.fullmatch(head):
        raise ChallengeInputError("git_head_invalid")
    return head


def load_pinned_cases(checkout: Path, manifest_path: Path, rules_root: Path) -> ChallengeCorpus:
    """Verify the official label CSV and every selected source and rule file."""

    if checkout.is_symlink() or not checkout.is_dir():
        raise ChallengeInputError("checkout_unavailable")
    body = _read_bounded(manifest_path, _MAX_MANIFEST_BYTES, "manifest_unavailable")
    try:
        manifest: Any = json.loads(body.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ChallengeInputError("manifest_invalid") from error
    expected_fields = {
        "schema_version",
        "source_url",
        "source_revision",
        "license",
        "ground_truth_path",
        "ground_truth_sha256",
        "selected_cwes",
        "source_hashes",
        "rules",
    }
    if (
        not isinstance(manifest, dict)
        or set(manifest) != expected_fields
        or manifest["schema_version"] != 1
    ):
        raise ChallengeInputError("manifest_invalid")
    revision = manifest["source_revision"]
    if not isinstance(revision, str) or not _REVISION.fullmatch(revision):
        raise ChallengeInputError("source_revision_invalid")
    if _checkout_revision(checkout) != revision:
        raise ChallengeInputError("source_revision_mismatch")
    source_url = manifest["source_url"]
    license_id = manifest["license"]
    if (
        source_url != "https://github.com/OWASP-Benchmark/BenchmarkPython"
        or license_id != "GPL-3.0-only"
    ):
        raise ChallengeInputError("provenance_invalid")
    truth_path = manifest["ground_truth_path"]
    if truth_path != "expectedresults-0.1.csv":
        raise ChallengeInputError("ground_truth_path_invalid")
    truth_sha = _sha_field(manifest["ground_truth_sha256"], "ground_truth_hash_invalid")
    truth_body = _read_bounded(checkout / truth_path, _MAX_CSV_BYTES, "ground_truth_unavailable")
    if sha256(truth_body).hexdigest() != truth_sha:
        raise ChallengeInputError("ground_truth_hash_mismatch")
    selected_cwes = manifest["selected_cwes"]
    if (
        not isinstance(selected_cwes, list)
        or not selected_cwes
        or len(selected_cwes) != len(set(map(str, selected_cwes)))
        or any(not isinstance(value, str) or not _CWE.fullmatch(value) for value in selected_cwes)
    ):
        raise ChallengeInputError("selected_cwes_invalid")
    source_hashes = manifest["source_hashes"]
    if not isinstance(source_hashes, dict) or len(source_hashes) > 2_000:
        raise ChallengeInputError("source_hashes_invalid")
    for case_id, digest in source_hashes.items():
        if not isinstance(case_id, str) or not _CASE.fullmatch(case_id):
            raise ChallengeInputError("source_hashes_invalid")
        _sha_field(digest, "source_hashes_invalid")

    try:
        rows = list(
            csv.reader(
                line for line in truth_body.decode("utf-8").splitlines() if not line.startswith("#")
            )
        )
    except UnicodeError as error:
        raise ChallengeInputError("ground_truth_invalid") from error
    cases: list[ChallengeCase] = []
    all_ids: set[str] = set()
    for row in rows:
        if len(row) != 4 or not _CASE.fullmatch(row[0]) or row[0] in all_ids:
            raise ChallengeInputError("ground_truth_invalid")
        all_ids.add(row[0])
        if row[2] not in {"true", "false"} or not row[3].isdigit():
            raise ChallengeInputError("ground_truth_invalid")
        cwe_id = f"CWE-{row[3]}"
        if cwe_id not in selected_cwes:
            continue
        case_id = row[0]
        if case_id not in source_hashes:
            raise ChallengeInputError("source_hash_missing")
        source_name = f"{case_id}.py"
        source = _read_bounded(
            checkout / "testcode" / source_name, _MAX_SOURCE_BYTES, "source_unavailable"
        )
        if sha256(source).hexdigest() != source_hashes[case_id]:
            raise ChallengeInputError("source_hash_mismatch")
        try:
            source.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ChallengeInputError("source_invalid_utf8") from error
        cases.append(ChallengeCase(case_id, cwe_id, row[2] == "true", source_name))
    if {case.case_id for case in cases} != set(source_hashes):
        raise ChallengeInputError("source_hash_set_mismatch")

    raw_rules = manifest["rules"]
    if not isinstance(raw_rules, list) or not raw_rules or len(raw_rules) > 100:
        raise ChallengeInputError("rules_invalid")
    rules: list[RuleSpec] = []
    for item in raw_rules:
        if not isinstance(item, dict) or set(item) != {
            "rule_id",
            "cwe_id",
            "config_path",
            "sha256",
        }:
            raise ChallengeInputError("rule_invalid")
        rule_id, cwe_id, config_path = item["rule_id"], item["cwe_id"], item["config_path"]
        if (
            not isinstance(rule_id, str)
            or not _RULE.fullmatch(rule_id)
            or cwe_id not in selected_cwes
            or not isinstance(config_path, str)
        ):
            raise ChallengeInputError("rule_invalid")
        logical = PurePosixPath(config_path)
        vendor_rule = (
            len(logical.parts) >= 3
            and logical.parts[:2] == ("opengrep", "python")
            and logical.suffix == ".yml"
        )
        taint_rule = logical.as_posix() == "secragraph-taint/python.yml"
        if logical.is_absolute() or ".." in logical.parts or not (vendor_rule or taint_rule):
            raise ChallengeInputError("rule_path_invalid")
        digest = _sha_field(item["sha256"], "rule_hash_invalid")
        rule_file = rules_root.joinpath(*logical.parts)
        rule_body = _read_bounded(rule_file, _MAX_RULE_BYTES, "rule_unavailable")
        if sha256(rule_body).hexdigest() != digest:
            raise ChallengeInputError("rule_hash_mismatch")
        rules.append(RuleSpec(rule_id, cwe_id, config_path, digest))
    if len({rule.rule_id for rule in rules}) != len(rules):
        raise ChallengeInputError("duplicate_rule")
    return ChallengeCorpus(
        source_url,
        revision,
        license_id,
        truth_sha,
        sha256(body).hexdigest(),
        tuple(cases),
        tuple(rules),
    )


def _counts(
    cases: tuple[ChallengeCase, ...], detections: set[str], scanned: set[str]
) -> dict[str, int]:
    counts = {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "scored": 0, "unscored": 0}
    for case in cases:
        if case.source_path not in scanned:
            counts["unscored"] += 1
            continue
        counts["scored"] += 1
        positive = case.source_path in detections
        outcome = (
            "tp"
            if case.vulnerable and positive
            else "fn"
            if case.vulnerable
            else "fp"
            if positive
            else "tn"
        )
        counts[outcome] += 1
    return counts


def score_case_level(
    cases: tuple[ChallengeCase, ...],
    rules: tuple[RuleSpec, ...],
    findings_by_rule: dict[str, set[str]],
    scanned_paths: set[str],
) -> dict[str, object]:
    """Score broad CWE case labels; never infer ground-truth source lines."""

    by_rule = {
        rule.rule_id: _counts(
            tuple(case for case in cases if case.cwe_id == rule.cwe_id),
            findings_by_rule.get(rule.rule_id, set()),
            scanned_paths,
        )
        for rule in rules
    }
    by_cwe: dict[str, dict[str, int]] = {}
    for cwe_id in sorted({case.cwe_id for case in cases}):
        detections = set().union(
            *(findings_by_rule.get(rule.rule_id, set()) for rule in rules if rule.cwe_id == cwe_id)
        )
        by_cwe[cwe_id] = _counts(
            tuple(case for case in cases if case.cwe_id == cwe_id),
            detections,
            scanned_paths,
        )
    overall = {
        key: sum(group[key] for group in by_cwe.values())
        for key in ("tp", "fp", "fn", "tn", "scored", "unscored")
    }
    return {"overall": overall, "by_cwe": by_cwe, "by_rule": by_rule}
