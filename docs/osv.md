# OSV.dev package-version CVE lookup

SecRAGraph uses the public [OSV.dev package query API](https://google.github.io/osv.dev/post-v1-query/) for live dependency vulnerability evidence. Supply an ecosystem, package, and exact version. OSV advisories retain their own IDs; `cve_ids` contains only actual `CVE-...` primary IDs or aliases returned by OSV. A record may have no CVE identifier, and an empty result is not proof that a package is safe.

Run a local query without an OSV API key:

```powershell
uv run security-review osv-query --ecosystem PyPI --package jinja2 --version 2.4.1
```

The authenticated API offers `POST /v1/vulnerabilities/query` with JSON fields `ecosystem`, `package`, and `version`. The Streamlit **Dependency CVEs** tab calls the same endpoint after member login. The lookup sends the named package and version to OSV.dev, so avoid querying private package names unless that disclosure is acceptable.

The adapter uses a fixed HTTPS origin, refuses redirects, limits response size to 1 MB, limits pages to eight and raw advisories to 500, rejects malformed or repeated pagination tokens, and returns a 503 if a complete result cannot be obtained. Tests use an offline HTTP transport; a live smoke query is a separate check. Retrieved summaries are untrusted data and are displayed as plain text.

The legacy `import-intelligence --cwe ... --cve ...` CSV command remains for the offline Text2SQL sample. Live OSV results are not inserted into that table or automatically attached to code-pattern findings: a CWE match alone cannot identify an affected CVE. Dependency scanning of local lockfiles is a future, explicit opt-in extension after package/version extraction is validated.
