"""Scheduled and manual scans reuse the same guarded CI jobs."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[3]
EXPECTED_CI_JOBS = {
    "quality",
    "tests",
    "dependency-security",
    "container-build",
    "compose-smoke",
    "dast-evidence",
    "git-history-secrets",
    "pipeline-benchmark",
}


def _workflow(name: str) -> dict:
    value = yaml.safe_load((ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _events(workflow: dict) -> dict:
    # PyYAML's YAML 1.1 loader interprets the Actions `on` key as boolean True.
    value = workflow.get("on", workflow.get(True))
    assert isinstance(value, dict)
    return value


def test_both_workflows_run_weekly_and_on_demand_without_renaming_checks() -> None:
    ci = _workflow("ci.yml")
    codeql = _workflow("security-scan.yml")

    for workflow in (ci, codeql):
        events = _events(workflow)
        assert "push" in events and "pull_request" in events
        assert "workflow_dispatch" in events
        assert events["schedule"] == [{"cron": "17 3 * * 0"}]
    assert set(ci["jobs"]) == EXPECTED_CI_JOBS
    assert set(codeql["jobs"]) == {"codeql"}
    assert codeql["jobs"]["codeql"]["name"] == "CodeQL (${{ matrix.language }})"
    assert codeql["jobs"]["codeql"]["strategy"]["matrix"]["language"] == [
        "python",
        "javascript-typescript",
    ]


def test_rescan_concurrency_does_not_cancel_other_main_events() -> None:
    group = _workflow("ci.yml")["concurrency"]
    assert "github.event_name" in group["group"]
    assert "github.ref" in group["group"]
    assert "github.event_name == 'pull_request'" in group["cancel-in-progress"]
    assert "github.event_name == 'push'" in group["cancel-in-progress"]


def test_rescan_image_uses_current_sha_and_history_checks_main_ref() -> None:
    workflow = _workflow("ci.yml")
    image = workflow["jobs"]["container-build"]
    base = image["env"]["IMAGE_POLICY_BASE_SHA"]
    assert "github.event.pull_request.base.sha" in base
    assert "github.event.before" in base
    assert "github.sha" in base
    assert '--base-sha "$IMAGE_POLICY_BASE_SHA"' in str(image["steps"])

    history = workflow["jobs"]["git-history-secrets"]
    steps = history["steps"]
    checkout = next(step for step in steps if "actions/checkout@" in step.get("uses", ""))
    assert checkout["with"]["fetch-depth"] == 0
    generate = next(step for step in steps if step.get("id") == "history_generate")
    assert "scripts.run_history_evidence generate" in generate["run"]


def test_normalized_evidence_uploads_cover_only_trusted_main_events() -> None:
    jobs = _workflow("ci.yml")["jobs"]
    for name in (
        "quality",
        "container-build",
        "compose-smoke",
        "dast-evidence",
        "git-history-secrets",
    ):
        uploads = [
            step
            for step in jobs[name]["steps"]
            if "actions/upload-artifact@" in step.get("uses", "")
        ]
        assert len(uploads) == 1
        condition = uploads[0]["if"]
        assert "github.ref == 'refs/heads/main'" in condition
        for event_name in ("push", "schedule", "workflow_dispatch"):
            assert f"github.event_name == '{event_name}'" in condition
        assert "pull_request" not in condition
        assert uploads[0]["with"]["if-no-files-found"] == "error"

    aggregate = jobs["pipeline-benchmark"]
    assert set(aggregate["needs"]) == EXPECTED_CI_JOBS - {"pipeline-benchmark"}
    condition = aggregate["if"]
    assert "github.ref == 'refs/heads/main'" in condition
    assert "pull_request" not in condition
    for event_name in ("push", "schedule", "workflow_dispatch"):
        assert f"github.event_name == '{event_name}'" in condition
    downloads = [
        step for step in aggregate["steps"] if "actions/download-artifact@" in step.get("uses", "")
    ]
    assert len(downloads) == 5
    assert all(
        "run-id" not in step["with"] and "repository" not in step["with"] for step in downloads
    )
    uploads = [
        step for step in aggregate["steps"] if "actions/upload-artifact@" in step.get("uses", "")
    ]
    assert len(uploads) == 1
    assert uploads[0]["with"]["if-no-files-found"] == "error"
