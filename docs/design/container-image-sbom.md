# Container image scanning and SBOM

## Purpose and boundary

This phase scans the **built SecRAGraph runtime image**, records its OS and
language packages in a CycloneDX SBOM, and reports image vulnerabilities and
image-configuration findings through the existing SecRAGraph report model.
The scanner reads an immutable local OCI tar saved from the exact image ID
built by CI for `linux/amd64` with build provenance disabled. It does not build, run, pull, or accept an image supplied by an
API member. A Dockerfile from a submitted source snapshot remains subject to
the existing IaC scanner; arbitrary Dockerfile `RUN` commands are never
executed by the member-facing API.

The local operator command accepts a **trusted local** OCI/Docker image tar
and a locally installed pinned Trivy binary. It never calls Docker or pulls a
registry image. CI builds this repository's runtime target, saves by the exact
local image ID, and invokes the same command on that tar. The Docker image ID
may identify an OCI index, manifest or config, while Trivy's
`Metadata.ImageID` is the image **config** digest. We verify the saved tar's
OCI index/manifest/config references and blob hashes, or its Docker archive
manifest/config if the runner emits that format. The archive must contain
exactly one runnable manifest and no ambiguous platform/attestation choice.
The expected local image ID
must match a verified digest in that chain, and Trivy's JSON and CycloneDX
outputs must agree on the config digest. We record the tar SHA-256, local ID
and config digest as separate identities. None is called a registry digest.

## Engine choice

Trivy 0.76.1 is the single image inspection engine. It reads the tar once
per JSON scan and SBOM generation, covers OS and installed language packages,
supports image-config misconfiguration checks, and emits CycloneDX. A
Syft+Grype pair would add a second image parser and version/DB lifecycle.
OSV's existing lockfile audit cannot establish which OS packages ended up in
the final image. The image scan complements source SCA and IaC rather than
replacing either.

CI installs a SHA-256-verified Trivy release asset, updates the vulnerability
DB explicitly, then scans with DB updates, Java DB updates, checks updates,
telemetry, and version checks disabled. `--offline-scan` prevents advisory
lookups during analysis; it does not mean that DB acquisition is offline.
The report records the Trivy version, DB update timestamp, duration, checked
image config/package types, image config digest, tar hash, findings and
counts. DB `UpdatedAt` must be no more than 72 hours old and no more than
five minutes in the future. The tar is limited to 2 GiB; each Trivy output
is limited to 32 MiB; there may be at most 10,000 findings and 100,000 SBOM
components; each scanner process has a 10-minute deadline. A completed
image scan requires `os-pkgs`, `lang-pkgs` and image `config` result classes,
a positive SBOM component count, and a matching image identity. Empty
result sets do not pass merely because the baseline delta is zero.
Missing/stale DB metadata, malformed or truncated output, scanner
failure, timeouts, mismatched image identities, and incomplete results are
errors rather than clean reports.

## Normalized evidence

Each image finding has one validated image config digest and one bounded
logical resource (prefer a package URL; otherwise a package name/version or
`config:<rule>`). It cannot also claim a source file, HTTP endpoint, Git
commit, source line, or flow trace. `Finding` preserves the advisory or
misconfiguration rule ID, engine name, upstream severity and severity source,
package and fixed version where present, syntactically validated CWE IDs, and a small
allowlisted advisory reference. It does not copy arbitrary Trivy descriptions,
package files, image environment variables, or raw configuration evidence.
Upstream `UNKNOWN` severity is reported explicitly and assigned a conservative
SecRAGraph medium risk level; the upstream value remains visible in the
finding. Source SCA and image package findings have different categories and
locations, so duplicate advisory IDs across artifacts remain distinguishable.

`ScanExecution` has an image-specific branch with the config digest, tar
SHA-256, DB timestamp, package-result count, and SBOM SHA-256/component count.
The status and coverage cannot claim source files or HTTP endpoints.
With a configured CWE provider, LangGraph may attach official CWE references;
a caller can separately inject a RAG retriever. The CI image path disables
network evidence enrichment and the CLI does not configure Qdrant by default.
These paths preserve the image provenance fields. JSON, Markdown and SARIF render a logical
image location; SARIF does not invent a line in the source checkout. A
PostgreSQL migration supports image findings and refuses downgrade while
such rows exist. SBOM is a separate CycloneDX artifact, linked by the same
image config digest and tar SHA-256 in a small evidence manifest.

## Gate and baseline

A real scan of the pinned runtime image on 2026-10-30 with Trivy 0.76.1 and
DB `UpdatedAt=2026-10-29T13:09:46Z` reported **384 vulnerability records**:
111 low, 155 medium, 107 high, 6 critical and 5 unknown. CycloneDX 1.7
contained 386 components and 225 vulnerability entries (its representation
and deduplication differ from the JSON record count). These counts are a
point-in-time, tool-specific baseline, not a claim of 384 exploitable flaws.
Several critical records have fixed versions, so remediation remains open.

The CI gate always fails on scan/SBOM/identity incompleteness. It also fails
on any image-config misconfiguration of medium or higher severity and on any
**new** high, critical, or unknown vulnerability identity relative to a
reviewed baseline. Baseline identities contain ecosystem/type, advisory ID,
package identity and installed version; a fixed finding disappears naturally.
The baseline is explicit, versioned and limited to pre-existing records. It
is not automatically rewritten by CI. On a PR, CI compares it with the
baseline at the base commit and rejects any change to the baseline file.
The initial bootstrap PR may add the file because the base has none; after
that there is no automatic waiver or baseline-growth path. The exception is
bound to the fixed pre-feature main SHA `c8f7800ebd740298478a6c705e51f0c0e04b51f3`;
PRs read the real base SHA's baseline, not their checkout copy. An
image-config finding with `UNKNOWN` severity also fails the gate. A new advisory
must be fixed before merging, or a future separately reviewed policy change
must state its scope and rationale. A new advisory from a refreshed DB can
fail CI even when the image has not changed; that is intentional and requires
review. The job reports the full counts including baseline entries. The
baseline is not a suppression, waiver, or evidence that existing findings
are safe. The README and evidence document state the unresolved counts and
the remediation priority. Main-branch artifacts include normalized JSON,
Markdown, SARIF, CycloneDX SBOM and a manifest with tool, DB and image
provenance. A changed PR's raw scanner output is never uploaded.

## Verification

Tests use small synthetic Trivy JSON/CycloneDX documents to cover identity
binding, severity and PURL parsing, malformed/truncated reports, missing DB,
deduplication, gate growth/removal, report rendering, graph preservation,
database round trip and downgrade refusal. A local real scan uses the pinned
Trivy binary and a Docker-built runtime image. CI repeats the build, scan,
SBOM and gate on Linux. The evidence document records exact versions,
checksums, DB time, image identity, scan command and limitations. No member
API image upload or arbitrary registry scanning is claimed in this phase.

## Sources

- [Trivy container image targets](https://trivy.dev/docs/latest/guide/target/container_image/)
- [Trivy SBOM generation](https://trivy.dev/docs/latest/guide/supply-chain/sbom/)
- [Trivy vulnerability DB lifecycle](https://trivy.dev/docs/latest/guide/configuration/db/)
- [Trivy 0.76.1 release](https://github.com/aquasecurity/trivy/releases/tag/v0.76.1)
