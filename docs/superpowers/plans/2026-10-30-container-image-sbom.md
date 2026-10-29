# Container image scan and SBOM implementation plan

Design: [container-image-sbom.md](../../design/container-image-sbom.md).
Base: `c8f7800ebd740298478a6c705e51f0c0e04b51f3` (main after Git-history secrets).

## 1. Canonical model, persistence and reporting (TDD)

Write failing tests for image-only `Finding` locations and `ScanExecution`
provenance, then add fields and strict validation. An image finding has
`image_id=sha256:<64 hex>` and a bounded `image_resource`, with no source,
HTTP, Git or trace location. Add `upstream_severity` and `severity_source`
for truthful Trivy mapping. The image execution records config digest, tar
SHA-256, DB updated time, vulnerability and config counts, SBOM digest and
component count; image coverage cannot claim files/endpoints. Update finding
sort, Markdown, SARIF logical location/fingerprint, graph rebuild/protected
fields, SQLAlchemy row mapping, and migration 0009. Replace the existing
source/HTTP location check with an exactly-one source/HTTP/image check.
Downgrade refuses to lose image findings. Test old rows, round trip,
constraints, graph enrichment, and all three formats.

## 2. Bounded Trivy adapter and trusted-tar command (TDD)

Create `security_review/container_image/` parser and runner. Tests first:
small fixture JSON and CycloneDX documents for OS, Python, Go and config
findings; unknown severity; duplicate advisory/package; missing or malformed
metadata, oversized output and finding caps, timeout, nonzero process exit,
wrong `ArtifactType`, mismatched image config digests, missing/stale DB,
empty `Results`, missing `os-pkgs`/`lang-pkgs`/`config`, empty SBOM,
PURL/advisory URL/CWE validation, and no copied raw evidence. Runner takes a
trusted local tar path and Trivy binary/cache paths, checks exact file size
and SHA-256, verifies exactly one runnable `linux/amd64` manifest in the OCI
index/manifest/config blob chain or Docker archive manifest/config and matches
the expected local image ID to a verified digest,
calls Trivy through an argument list with explicit offline flags,
32 MiB output limits and 10-minute process deadlines, and hashes the tar
again to detect concurrent replacement. The tar is at most 2 GiB; findings
and SBOM components are capped at 10,000 and 100,000. It reads DB metadata
(`UpdatedAt` within 72 hours and not >5 minutes ahead) after a separate explicit DB
update step, never silently downloads during analysis. CycloneDX must
identify the same config digest as JSON and report a bounded component count.
The adapter returns normalized findings, completed execution, SBOM bytes,
and gate identities; errors produce a nonzero exit rather than a clean
report. Add `scan-image` to CLI for trusted local use, producing atomic
JSON/Markdown/SARIF/SBOM/manifest files from one result. Feed the findings
and execution through the shared LangGraph report path.

## 3. Policy baseline and CI pipeline (TDD)

Implement a versioned JSON baseline of the pinned image's current high,
critical and unknown vulnerability identities. Identity is deterministic
from result type/ecosystem, advisory ID, package identity and installed
version, without relying on Trivy's order, target display path or an image
tag. A gate script compares the current complete result to the checked-in
baseline and fails for newly seen severe identities or medium+ image-config
misconfiguration, including unknown severity. Removal of a previous record passes; duplicate identities
are rejected. The baseline cannot be regenerated implicitly during CI. PR CI
reads the baseline from the event's actual base SHA and rejects any change to
this file; the initial bootstrap PR is allowed only when that base SHA is
`c8f7800ebd740298478a6c705e51f0c0e04b51f3` and has no baseline.
Tests cover empty/new/removed/duplicated identities, DB-driven new advisory,
incomplete execution and malformed baseline. Record all current counts in
the report and documentation even when the delta is zero.

Extend `container-build` to install SHA-verified Trivy 0.76.1, refresh the
DB, build one `linux/amd64` runtime image with `--provenance=false`, save it
by `docker image inspect` exact ID,
invoke the CLI, validate CycloneDX, run the gate and publish complete
normalized artifacts only on main. No member upload image build, Docker
socket in the API, registry push, credentials, or raw PR Trivy artifact.
Use a consistent image tar/config digest in all outputs. CI has explicit
timeouts and fails on missing DB, tool failure and incomplete scan.

## 4. Real verification, evidence and integration

Run focused tests, full suite, Ruff, mypy, Bandit and PostgreSQL integration.
Build the actual runtime image locally, scan the saved exact-ID tar with the
pinned release and fresh DB, inspect normalized count and SBOM, and generate
the initial reviewed baseline. Re-run the gate on the same tar and verify a
synthetic new high finding fails. Document Trivy version/checksum, DB time,
image tar/config IDs, package counts, 384-record starting point, current
new-severe delta, limitations and reproduction. Update README and
architecture/operations docs to distinguish source SCA, IaC and image scan.
Request independent code/security review and fix concrete findings. Push a
PR, verify required checks, merge to main, and verify the main run/artifacts.
