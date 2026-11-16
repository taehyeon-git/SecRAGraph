# Container Image Debt Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reduce and verify the runtime image's Gitleaks and Debian severe findings while accurately assessing Checkov's remaining `ecdsa` finding.

**Architecture:** Build Gitleaks from an exact upstream tag with pinned Go and modules in a builder stage, then copy only the binary into the Python runtime. Remove only Debian packages that apt confirms are not required. Keep the Checkov dependency and its finding visible until an upstream fix exists.

**Tech Stack:** Docker, Go, Python, uv, Trivy 0.76.1, GitHub Actions.

**Spec:** [Container image debt reduction](../specs/2026-11-16-container-image-debt.md).

## Global Constraints

- Never run uploaded code or let member uploads trigger Git history, DAST, or image builds.
- Keep upstream source commit, builder image digest, Go module checksums, and scanner versions pinned.
- Do not change the baseline merely to suppress a new severe finding.
- Retain Gitleaks secret redaction and the existing nonroot runtime contract.

## Review Focus

- Different architecture: the builder must produce the right Linux binary for both amd64 and arm64, or reject unsupported architectures.
- Scanner result drift: compare positive and negative source fixtures plus deleted-file and merge-only Git secrets before shipping.
- Package removal: apt must remove only intended nonessential packages; test runtime and image metadata afterward.
- New dependency identity: a rebuilt binary must pass the unchanged exact-identity gate or be separately reviewed.
- Checkov overrides: hostile environment and `.checkov.yaml` must not enable external checks or signature operations.

---

### Task 1: Gitleaks rebuild and parity

**Files:** `Dockerfile`, `infra/scanners/install_tools.py`, `infra/scanners/` Gitleaks build inputs, relevant scanner tests, new evidence document.

- [ ] Reproduce the 42 `gobinary` baseline identities and verify v8.30.1 source commit.
- [ ] Build a patched binary with pinned Go/modules; inspect `go version -m` and run upstream tests.
- [ ] Run released and rebuilt binaries through the same source and Git-history fixtures; compare redacted finding identities.
- [ ] Integrate the verified builder into Docker and assert binary provenance in a focused build test.

### Task 2: Debian package reduction

**Files:** `Dockerfile`, container tests, new evidence document.

- [ ] Simulate apt purge on the current image and reject any protected/essential or additional removal.
- [ ] Purge only confirmed unused package(s) in the runtime stage.
- [ ] Build the image and run package, API, scanner, and Compose checks.

### Task 3: Checkov path assessment

**Files:** `tests/unit/scanner/test_external_detectors.py`, new evidence document.

- [ ] Confirm the advisory's affected operations and Checkov's actual import/call path.
- [ ] Add and run the hostile external-check environment regression assertion.
- [ ] Record why the package and advisory remain visible.

### Task 4: Image evidence and integration

**Files:** image evidence, `README.md` if counts change, CI policy only if a separately reviewed identity requires it.

- [ ] Rescan one immutable runtime image with fresh Trivy DB and CycloneDX SBOM; record image, DB, and artifact digests.
- [ ] Compare each category and advisory set with the prior record, without treating DB changes as remediation.
- [ ] Run focused tests and PR CI/CodeQL; review the final patch; merge only after passing checks.
