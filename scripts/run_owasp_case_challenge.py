"""Measure Opengrep on pinned OWASP BenchmarkPython v0.1 case-level labels.

The 90 selected cases cover CWE-78/89/502. Sources are copied as inert text.
The upstream CSV has no vulnerable-line or per-rule labels; every rule score is
explicitly a broad-CWE challenge over all cases in that category.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
from collections import defaultdict
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, cast

from security_review.evaluation.owasp_case_challenge import (
    ChallengeInputError,
    load_pinned_cases,
    score_case_level,
)
from security_review.scanner.opengrep_adapter import OpengrepAdapter

_ROOT = Path(__file__).resolve().parents[1]
_MANIFEST = _ROOT / "data/evaluation/owasp_python_v0.1_challenge.json"
_RULES = _ROOT / "data/engines"


def _rate(top: int, bottom: int) -> str:
    return "N/A" if bottom == 0 else f"{top / bottom:.3f}"


def _table_row(label: str, score: dict[str, int], elapsed: int | None = None) -> str:
    precision = _rate(score["tp"], score["tp"] + score["fp"])
    recall = _rate(score["tp"], score["tp"] + score["fn"])
    return (
        f"| `{label}` | {score['tp']} | {score['fp']} | {score['fn']} | {score['tn']} | "
        f"{score['scored']} | {score['unscored']} | {precision} | {recall} | "
        f"{elapsed if elapsed is not None else '—'} |"
    )


def _markdown(payload: dict[str, Any]) -> str:
    coverage = payload["coverage"]
    metrics = payload["metrics"]
    lines = [
        "# OWASP BenchmarkPython case-level challenge",
        "",
        f"- Upstream revision: `{payload['source_revision']}`",
        f"- CSV SHA-256: `{payload['ground_truth_sha256']}`",
        f"- Manifest SHA-256: `{payload['manifest_sha256']}`",
        f"- Engine: Opengrep `{payload['engine_version'] or 'unavailable'}` / "
        "vendored MIT and project taint rules",
        f"- Engine status: `{coverage['engine_status']}`",
        f"- Cases scored: {metrics['overall']['scored']}/{coverage['cases_total']}",
        f"- Bundle scan time: {coverage['bundle_elapsed_ms']} ms",
        "",
        "The official CSV labels a **whole test case** as vulnerable or benign for one CWE. "
        "It does not identify a source line or assert complete sink coverage for any rule. "
        "Each rule's TP/FP/FN is therefore a broad-CWE challenge, not its intended-sink accuracy. "
        "Incomplete scans are unscored rather than false negatives. Rule times are separate "
        "single-rule scans on the cases in that rule's CWE; they are not additive to bundle time.",
        "",
        "| CWE / rule | TP | FP | FN | TN | Scored | Unscored | Precision | Recall | Time (ms) |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    lines.append(_table_row("overall CWE union", metrics["overall"], coverage["bundle_elapsed_ms"]))
    for cwe, score in sorted(metrics["by_cwe"].items()):
        lines.append(_table_row(cwe, score))
    lines.extend(
        [
            "",
            "## Per-rule broad-CWE challenge",
            "",
            "| Rule | TP | FP | FN | TN | Scored | Unscored | Precision | Recall | Time (ms) |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for rule, score in sorted(metrics["by_rule"].items()):
        lines.append(_table_row(rule, score, payload["per_rule_timing"][rule]["elapsed_ms"]))
    lines.extend(["", "## Coverage", ""])
    for rule, item in sorted(payload["per_rule_timing"].items()):
        if item["status"] != "completed":
            lines.append(f"- `{rule}` isolated timing scan: `{item['status']}` ({item['reason']}).")
    if all(item["status"] == "completed" for item in payload["per_rule_timing"].values()):
        lines.append("- All isolated rule timing scans completed.")
    if coverage["unassessed_finding_count"]:
        lines.append(
            f"- {coverage['unassessed_finding_count']} other-rule findings were outside "
            "the selected CWE/rule assessment and were not counted as false positives."
        )
    return "\n".join(lines).rstrip() + "\n"


def _is_complete(
    bundle_status: str,
    unscored_cases: int,
    timings: dict[str, dict[str, Any]],
    *,
    timing_requested: bool,
) -> bool:
    return (
        bundle_status == "completed"
        and unscored_cases == 0
        and (
            not timing_requested or all(item["status"] == "completed" for item in timings.values())
        )
    )


def _isolated_taint_yaml(combined: str, rule_id: str) -> str:
    """Keep one pinned local taint rule so its isolated timing is meaningful."""

    lines = combined.splitlines(keepends=True)
    starts = [
        index for index, line in enumerate(lines) if re.match(r"^  - id: [A-Za-z0-9-]+\s*$", line)
    ]
    raw_id = rule_id.removeprefix("OG/")
    selected = [index for index in starts if lines[index].strip() == f"- id: {raw_id}"]
    if len(selected) != 1 or not lines or lines[0].strip() != "rules:":
        raise ChallengeInputError("taint_rule_isolation_failed")
    start = selected[0]
    end = next((index for index in starts if index > start), len(lines))
    return "rules:\n" + "".join(lines[start:end])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, default=_ROOT / "build/evidence/external")
    parser.add_argument("--skip-rule-timing", action="store_true")
    parser.add_argument("--require-complete", action="store_true")
    args = parser.parse_args()
    try:
        corpus = load_pinned_cases(args.checkout, _MANIFEST, _RULES)
    except ChallengeInputError as error:
        parser.exit(2, f"pinned input error: {error}\n")

    staging_parent = os.environ.get("SECRAGRAPH_SNAPSHOT_TMPDIR")
    with TemporaryDirectory(prefix="secragraph-owasp-", dir=staging_parent) as temporary:
        stage = Path(temporary)
        for case in corpus.cases:
            shutil.copy2(args.checkout / "testcode" / case.source_path, stage / case.source_path)
        full = OpengrepAdapter(
            rules_root=_RULES / "opengrep",
            taint_rules_root=_RULES / "secragraph-taint",
        ).scan_snapshot(stage, timeout=120)
        scanned = (
            set(full.execution.inspected_files) if full.execution.status == "completed" else set()
        )
        rule_map = {item.rule_id: item for item in corpus.rules}
        detections: dict[str, set[str]] = defaultdict(set)
        unassessed = 0
        for finding in full.findings:
            rule = rule_map.get(finding.rule_id)
            matched_case = next(
                (item for item in corpus.cases if item.source_path == finding.file_path), None
            )
            if rule is None or matched_case is None or rule.cwe_id != matched_case.cwe_id:
                unassessed += 1
                continue
            detections[rule.rule_id].add(finding.file_path)
        metrics = score_case_level(corpus.cases, corpus.rules, detections, scanned)

        timings: dict[str, dict[str, Any]] = {}
        for rule in corpus.rules:
            if args.skip_rule_timing:
                timings[rule.rule_id] = {
                    "status": "not_run",
                    "reason": "explicitly_skipped",
                    "elapsed_ms": None,
                    "eligible_files": 0,
                    "scanned_files": 0,
                }
                continue
            with TemporaryDirectory(prefix="secragraph-owasp-rule-") as config_temporary:
                config_root = Path(config_temporary)
                vendor = config_root / "opengrep"
                (vendor / "python").mkdir(parents=True)
                (vendor / "javascript").mkdir()
                taint = config_root / "secragraph-taint"
                taint.mkdir()
                source_rule = _RULES.joinpath(*Path(rule.config_path).parts)
                if rule.config_path.startswith("opengrep/"):
                    shutil.copy2(source_rule, vendor / "python" / source_rule.name)
                    (taint / "python.yml").write_text("rules: []\n", encoding="utf-8")
                else:
                    (taint / "python.yml").write_text(
                        _isolated_taint_yaml(source_rule.read_text(encoding="utf-8"), rule.rule_id),
                        encoding="utf-8",
                    )
                (taint / "javascript.yml").write_text("rules: []\n", encoding="utf-8")
                with TemporaryDirectory(
                    prefix="secragraph-owasp-cwe-", dir=staging_parent
                ) as group_temporary:
                    group = Path(group_temporary)
                    for case in corpus.cases:
                        if case.cwe_id == rule.cwe_id:
                            shutil.copy2(stage / case.source_path, group / case.source_path)
                    measured = OpengrepAdapter(
                        rules_root=vendor,
                        taint_rules_root=taint,
                    ).scan_snapshot(group, timeout=90)
                timings[rule.rule_id] = {
                    "status": measured.execution.status,
                    "reason": measured.execution.warnings[0]
                    if measured.execution.warnings
                    else None,
                    "elapsed_ms": measured.execution.duration_ms,
                    "eligible_files": len(measured.execution.eligible_files),
                    "scanned_files": len(measured.execution.inspected_files),
                }

    payload: dict[str, Any] = {
        "scope": "external_case_level_challenge",
        "source_url": corpus.source_url,
        "source_revision": corpus.source_revision,
        "license": corpus.license,
        "ground_truth_sha256": corpus.ground_truth_sha256,
        "manifest_sha256": corpus.manifest_sha256,
        "engine_version": full.execution.version,
        "interpretation": (
            "Broad CWE case-level challenge; upstream provides no line-level or per-rule truth."
        ),
        "coverage": {
            "cases_total": len(corpus.cases),
            "engine_status": full.execution.status,
            "engine_reason": full.execution.warnings[0] if full.execution.warnings else None,
            "submitted_files": len(full.execution.eligible_files),
            "proven_scanned_files": len(full.execution.inspected_files),
            "bundle_elapsed_ms": full.execution.duration_ms,
            "unassessed_finding_count": unassessed,
        },
        "metrics": metrics,
        "per_rule_timing": timings,
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "owasp-python-case-challenge.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline=""
    )
    markdown = _markdown(payload)
    (args.output_dir / "owasp-python-case-challenge.md").write_text(
        markdown, encoding="utf-8", newline=""
    )
    print(markdown, end="")
    overall = cast(dict[str, int], metrics["overall"])
    return int(
        args.require_complete
        and not _is_complete(
            full.execution.status,
            overall["unscored"],
            timings,
            timing_requested=not args.skip_rule_timing,
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
