# Local membership, scanner, and knowledge quality design

## Intent and scope

SecRAGraph is a local-first backend/DevSecOps portfolio, not an internet-facing SaaS. The next increment lets a person sign in with an account rather than manually supplying the shared API token, keeps noninteractive automation possible, broadens two narrowly defined Python checks, and makes vetted PDF security publications usable as RAG evidence. The result must be testable without a model-provider key and must not claim general scanner accuracy or LLM factual quality from synthetic fixtures.

The user requested autonomous, uninterrupted implementation and review, so the design choices below are made as explicit defaults without waiting at a design gate. Corrections from the user override them. Work is split into independently testable membership, scanner, and PDF/corpus plans.

## Approaches considered

For member access: (1) reuse one shared token behind a login screen (rejected: no identity or report isolation); (2) external OIDC (strong for a deployed service but needs provider configuration and does not suit the keyless local demo); (3) local username/password accounts with server-side opaque sessions (chosen). The static Bearer token remains an optional, distinct *service/operator* credential for existing CLI/CI integrations; the Streamlit app no longer receives it. Member access does not remove the separate provider credential needed for live LLM/embedding calls.

For knowledge: bulk crawl and vendor arbitrary PDFs (rejected for rights, provenance, and prompt-injection risk) versus explicit, hash-verified local PDFs from a small official-source catalog (chosen). PDF support is additive to Markdown. Downloading sources is a separate opt-in step; binaries are not committed without redistribution review.

For scanner quality: maximize rule count (rejected because it inflates false positives) versus add narrow Python SQL-construction and unsafe-pickle rules with paired negative cases and an external benchmark challenge (chosen).

## Membership design

- Production API may start without `SECRAGRAPH_API_TOKEN` when its account store is configured; no `/v1` route becomes anonymously available. Existing Bearer service token is optional. It is never forwarded to Streamlit.
- A user is identified by a normalized 3–32 character ASCII username, not an asserted or verified email address. Passwords are 12–1024 UTF-8 bytes with no character-composition rules. Store only a versioned, salted scrypt verifier using OWASP's `N=2^15, r=8, p=3` equivalent setting; verify in constant time and use a dummy verifier for unknown usernames. No default account or credential is checked in.
- Self-registration is disabled by default and may be explicitly enabled only when `environment=development`; the supported Compose demo still binds host ports to `127.0.0.1`. Configuration alone cannot prove a deployment is loopback-only, so this is not a public-service security boundary. Provide password-hidden `security-review create-user`, `disable-user`, and `unlock-user` commands for local operator provisioning and recovery; no API administration endpoints are in scope. Registration and login errors must not reveal whether a username exists. Five failed attempts lock an existing account for 15 minutes; a successful login clears the counter. This account-scoped lockout can be abused for denial of login, which is acceptable only within the documented local threat model and recoverable with `unlock-user`; public deployment requires additional rate limits and abuse controls.
- A successful login creates a 256-bit unpredictable opaque session token. Only its SHA-256 digest and server-side metadata are stored; the token is returned once, never logged, and has an eight-hour absolute expiry plus a 30-minute idle expiry. Logout revokes it. Streamlit stores the token in its server-side session state and sends it as `Authorization: Session <token>`; no browser local-storage token or ambient authentication cookie is used, so cross-site request forgery does not apply to this transport. Browser-to-Streamlit and Streamlit-to-API remain local-only HTTP in Compose; TLS is required before any public deployment.
- The ASGI gate checks exactly one authorization header and resolves a typed principal before reading upload bodies. Health remains public; only registration/login routes are exempt. A service Bearer principal is not a member principal. Auth failure responses are uniform and contain no credential. Login and registration responses use `Cache-Control: no-store`.
- Each API-created scan is saved transactionally with its owner user ID. Member reads and report renders filter by owner in the repository query and return the same 404 for missing and other-user IDs. Service/operator requests may read legacy and all reports. Existing rows acquire a null owner in migration and remain operator-only. Local CLI scans do not persist reports and are unaffected.
- The local web demo shows register when enabled, login, current username, and logout; scanning and Q&A require a member session. The existing automation Bearer mode remains covered by tests but is not used by the web container.

## Scanner design

- `PY005` (CWE-89) detects clear Python dynamic SQL expressions passed to `execute`/`executemany` or `sqlalchemy.text`: f-strings, `%` formatting, `.format`, or concatenation whose static literal begins with a SQL verb. Parameterized statements with bound values, harmless comments/strings, and shadowed imports are negative controls. This is a heuristic, not taint analysis or proof of exploitability.
- `PY006` (CWE-502) detects `pickle.load`/`loads` through direct module and imported aliases, respecting local shadowing. The warning explains that risk depends on trust of serialized input. It does not claim all deserialization sinks.
- Finding evidence remains rule-owned fixed text and never includes source literals. Extend exact-line regression fixtures with paired positives and negatives, keep public `scan_path`, JSON/Markdown/SARIF compatibility, and bump the rule-set version.
- External OWASP BenchmarkPython evaluation remains opt-in and pinned by revision/hash. Extend its declared mapping only for supported CWE categories and publish full denominators, unsupported sinks, false positives, and false negatives; no invented external score.

## Knowledge/PDF design

- Add PDF extraction only for explicit local files in a verified corpus. The manifest records source URL, title, version/publication date, rights note, and SHA-256 of the original bytes. Do not crawl links or silently fetch remote content.
- Bound raw bytes, page count, extracted characters, document count, and chunks. Reject encrypted, corrupt, image-only, and otherwise unextractable PDFs with typed diagnostics; no OCR or execution of embedded content. Preserve page number in chunk metadata and citations. Deterministic chunk IDs and re-sync semantics remain stable for unchanged source bytes and extraction version.
- Existing managed-corpus identity remains `corpus_id` plus manifest-relative path/source URL (and page for PDF chunks). A revised file at that path with a new verified SHA-256 replaces the previous managed chunks through the current `sync-corpus` reconciliation; it does not silently create another corpus. The raw manifest hash and extraction-version marker make reruns auditable.
- Maintain an official-source catalog starting with NIST SSDF publications and a CISA secure-by-design reference, with final/draft status explicit. The catalog is for acquisition guidance, not a claim that all sources have been licensed, downloaded, or indexed. Downloaded PDFs and generated evidence stay Git-ignored and are reviewed before sharing.
- Keyless RAG tests must cover PDF extraction and citation metadata through the existing graph/test-double path. Actual model answer quality and semantic retrieval still require an explicitly configured provider and human review.

## Global safeguards and acceptance

- Never execute scanned source, ZIP contents, or PDF attachments. Never print password, session token, provider key, unknown source secret, or raw uploaded code in logs/test artifacts.
- Keep API/DB/Qdrant/web loopback-only in Compose. Do not publish a public service, bulk-copy unlicensed material, or assert that a passing synthetic benchmark makes this the world's best scanner.
- Authentication tests cover registration disabled/enabled, username normalization, password verifier, generic login failure, lockout, session expiry/revocation, duplicate headers, early body rejection, A/B report isolation, legacy ownership, and existing service token behavior.
- Scanner tests cover paired positive/negative source cases and all report formats. PDF tests cover bounds, corrupt/encrypted/image-only inputs, provenance hash mismatch, deterministic page citations, and prompt-injection text being treated solely as source data.
- Run Ruff, mypy, Bandit, pytest (unit and available integration), keyless RAG/scanner evidence, SARIF validation, dependency audit, and Compose smoke where local infrastructure permits. Report skipped external/LLM tests honestly.
