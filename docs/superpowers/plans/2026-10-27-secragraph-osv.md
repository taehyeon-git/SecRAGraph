# OSV.dev CVE Evidence Plan

**Goal:** Query OSV.dev by a known package ecosystem/name/version and present only returned CVE identifiers as live vulnerability evidence. Keep deterministic source-pattern findings offline and do not infer a CVE from a CWE or source pattern alone.

**API source:** [OSV POST /v1/query](https://google.github.io/osv.dev/post-v1-query/) returns vulnerabilities for a package/version and may paginate; [GET /v1/vulns/{id}](https://google.github.io/osv.dev/get-v1-vulns/) returns the full record. CVE identifiers may occur in the primary `id` or `aliases`, and some records have neither.

## Task 1: Bounded OSV adapter and normalization

- Add `src/security_review/intelligence/osv.py` with a client accepting an injected `httpx.Client`, fixed `https://api.osv.dev` origin by default, connect/read timeouts, bounded JSON body, maximum pages and records, page-token cycle detection, validated ecosystem/name/version, and no redirects.
- Normalize each returned record to `OsvAdvisory(id, cve_ids, summary, published_at, source_url)` and keep the requested ecosystem, package, and version on `OsvQueryResult`. Skip withdrawn records and reject malformed IDs or conflicting package evidence. Deduplicate by OSV ID, preserve all valid CVE primary IDs and aliases, and avoid inventing CVSS/severity when missing.
- Write offline transport tests first for valid result, no-CVE advisory, pagination, malformed body, excessive body, 429/5xx, timeout, redirect, duplicate IDs, withdrawn records, and untrusted strings. No live network in unit tests.

## Task 2: Shared API and CLI access

- Add a protected `POST /v1/vulnerabilities/query` endpoint taking ecosystem, package, version and returning bounded OSV results with provenance. Its member/operator access uses the existing early gate. Provider failure maps to a safe 503, invalid request to 422; no submitted code is sent to OSV.
- Add `security-review osv-query --ecosystem ... --package ... --version ...` using the same adapter, with JSON output and no API key. Document that it checks a specified package version rather than providing every CVE.
- Write route/CLI tests first with fake OSV adapters; verify authenticated access, no API-key need, content bounds, and that missing data is reported as missing rather than a clean bill of health.

## Task 3: Scanner integration only after evidence review

- Assess whether a pinned dependency can be obtained from supported upload types without executing code and without leaking private package names by default. If so, add opt-in package queries and canonical findings with OSV provenance; otherwise keep the explicit package/version endpoint as the supported contract and document the limitation.
- Run full unit/integration gates and a bounded live OSV smoke only if network permission remains available. Never gate offline tests on external availability.
