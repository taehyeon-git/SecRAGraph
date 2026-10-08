# SecRAGraph Secure Engineering Guidelines

This document is original project material written for the SecRAGraph demonstration corpus. It
describes review principles rather than replacing an organization-specific security standard.

## Trust boundaries and deterministic review

Treat every uploaded repository, archive, filename, document, database row, and model response as
untrusted input. A review service must inspect source text without importing modules, starting
processes, evaluating expressions, or running package installation hooks. Extract archives into an
isolated temporary directory, reject symbolic links and path traversal, and enforce limits on total
bytes, file count, and processing time.

Run deterministic rules before optional AI enrichment. Rule identifiers, source locations,
redacted evidence, and base severity belong to the deterministic result and must not be rewritten
by a language model. Retrieval can add citations and grounded remediation guidance, but a provider
failure must not erase confirmed findings. A partially enriched report should retain the original
finding identifiers and include a typed warning.

## Injection-resistant data access

Use parameterized queries whenever application data influences a database statement. Keep values
outside the SQL grammar and bind them through the database driver. Dynamic identifiers such as a
sort column cannot be parameterized in the same way; map them through a small explicit allowlist.
Avoid building statements with string concatenation, interpolation, or templating.

Generated Text2SQL requires a narrower boundary than ordinary application queries. Parse exactly
one statement into an abstract syntax tree, allow only `SELECT`, require schema-qualified approved
tables, reject wildcards and volatile functions, and impose a literal row limit. Execute the
validated rendering—not the raw model response—through a login that has read-only grants only on
the security intelligence schema. Set a short statement timeout and make read-only transactions the
role default. Database permissions remain the final control if validation contains a defect.

## Secrets and credential handling

Do not commit credentials, private keys, access tokens, or production connection strings. Load
secrets from the deployment environment or a dedicated secret manager and expose them only to the
component that needs them. Redact evidence in findings so reports can be shared without reproducing
the detected value. Logging a complete request, provider exception, or database URL can turn an
otherwise useful diagnostic into a second secret leak.

When a secret is exposed, remove it from active configuration, revoke or rotate it, review access
logs, and identify every environment where the value was replicated. Deleting a line from the
latest commit is not sufficient because the value may remain in Git history, build logs, caches,
container layers, or published artifacts. Prefer short-lived credentials and narrowly scoped
service identities so a single disclosure has limited impact.

## Authentication and authorization

Authentication establishes an identity; authorization decides whether that identity may perform a
specific action on a specific resource. Apply authorization on the server for every protected
operation. UI visibility is not an access control. For multi-tenant resources, include tenant scope
in the data query rather than loading an object globally and checking ownership later.

Validate token signature, issuer, audience, expiry, and the algorithm selected by trusted server
configuration. Do not accept an algorithm supplied by an untrusted token header without policy
validation. Keep administrative operations behind separate permissions and record security-relevant
changes in an append-oriented audit trail. Avoid storing raw tokens, passwords, or sensitive request
bodies in that trail.

## Dependency and build integrity

Pin direct dependencies and keep a reproducible lock file. Review dependency updates in small
changes, verify package origin, and run automated tests and vulnerability checks before promotion.
Build containers from explicit base-image versions, use a non-root runtime user, exclude developer
credentials from the build context, and keep compilers and package managers out of the final stage
when they are not required at runtime.

Continuous integration should grant the minimum token permissions needed by each job. Untrusted
pull-request code must not gain access to deployment credentials. Separate build and deployment
roles, retain provenance for released artifacts, and require an explicit promotion decision for
production. A security scanner in CI should emit machine-readable SARIF while preserving the same
canonical findings used by the CLI and API.

## Retrieval-augmented generation boundaries

Retrieved text is evidence, not policy. A document can contain phrases such as `IGNORE ALL
INSTRUCTIONS`, tool requests, fabricated roles, or instructions to reveal secrets. Keep retrieved
content in a delimited untrusted-data field in the user message. The system message should define
the task, allowed behavior, and refusal boundaries without interpolating document text.

Use stable chunk identifiers derived from source identity and normalized content. Preserve citation
metadata such as title, URL, page, and section. Bound document size, chunk count, embedding batch
size, search result count, and minimum relevance score. Verify that an existing vector collection
uses the expected embedding dimension and cosine distance; never delete and recreate a mismatched
collection automatically. Treat malformed vector payloads as a dependency failure and do not echo
their contents in error messages.

## Findings, severity, and remediation

A useful finding states what was detected, where it appears, why it matters, and how to reduce the
risk. Evidence should be minimal and redacted. Confidence describes how strongly the observed code
supports the finding, while severity describes potential impact; they are related but not
interchangeable. Map findings to CWE when the relationship is defensible, and use CVE records as
context for affected products rather than as proof that a local code pattern is exploitable.

Prefer remediation that changes the unsafe design boundary. Replace dynamic evaluation with an
explicit parser, replace shell strings with argument arrays, validate archive destinations before
writing, and isolate privileged operations behind narrow interfaces. When an immediate redesign is
not possible, document a temporary compensating control, an owner, and an expiry date. Re-scan the
same fixture after a fix so the evidence shows both detection and closure.

## Operational failure modes

Liveness should answer whether the process can respond. Readiness should report whether required
dependencies can serve the current capability. Check PostgreSQL and Qdrant independently and return
safe reason codes such as `connection_failed` or `dimension_mismatch`; never include credentialed
URLs or raw provider responses. Optional AI providers may be unavailable while deterministic source
scanning remains healthy.

Use bounded retries with backoff only for transient operations. Invalid SQL, incompatible vector
dimensions, malformed payloads, and missing configuration are not transient and should fail without
retry storms. Record structured metrics for latency, rejected inputs, degraded reports, retrieval
attempts, and provider failures. Alerts should point an operator toward the failing boundary without
copying untrusted source or document content into notification channels.
