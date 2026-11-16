# Container image debt reduction (2026-11-16)

## Goal

Reduce severe findings in the deployed SecRAGraph runtime image without hiding packages, weakening the image gate, or changing scanner results. Record what remains with exact image and database identities.

## Current evidence

The [2026-11-16 image record](../../evidence/container-image-2026-11-16.md) has 95 HIGH, CRITICAL, or UNKNOWN package records: 42 in the Gitleaks Go binary, 52 in Debian packages (14 distinct advisories), and one in Checkov's `ecdsa` dependency. The static baseline is a gate for newly introduced identities, not a declaration that existing ones are safe.

## Design

1. Rebuild the **same Gitleaks v8.30.1 source** from its exact upstream commit with a pinned, patched Go toolchain and selected module versions. Preserve source and module provenance, compare source and Git-history secret detections with the released binary, and scan the resulting image. Ship the rebuilt binary only after parity and image checks pass.
2. Keep the official Python 3.11 Debian Trixie base. Purge only Debian packages shown unnecessary by `apt-get -s` and runtime tests. Preserve protected/essential packages and Python libraries needed by the app. Rebuild and rescan rather than subtracting predicted counts.
3. Trace Checkov's `ecdsa` dependency to the application scan path. Keep the advisory visible while no patched package exists. Add a regression assertion that untrusted Checkov external-check configuration cannot enter the subprocess, and document the resulting reachability assessment.
4. Preserve the gate's trusted baseline and exact-identity comparison. If a changed binary yields a new severe identity, either eliminate it or review a narrow baseline change with actual scan evidence before merging.

## Acceptance

- A pinned, verifiable Gitleaks source/build recipe and successful parity checks against the official v8.30.1 binary.
- A runtime image whose removed Debian packages are absent, with authenticated API and scanner smoke checks passing.
- Fresh Trivy 0.76.1 plus CycloneDX evidence, with old/new counts separated from changes in the advisory database.
- CI and CodeQL pass on the PR and on `main`; documentation states unresolved advisories without claiming they are fixed.
