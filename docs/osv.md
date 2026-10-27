# OSV.dev package-version CVE lookup

SecRAGraph uses the public [OSV.dev package query API](https://google.github.io/osv.dev/post-v1-query/) for live dependency vulnerability evidence. A normal CLI or API scan automatically reads exact versions from supported lockfiles and queries OSV.dev; users do not have to supply the ecosystem, package, or version individually. Supported inputs are public-registry Python `uv.lock` and npm `package-lock.json` v2/v3 records. Editable, Git, path, workspace, alias, private-registry, missing-version, and version-range entries are skipped. Unsupported package managers are not claimed as checked.

The scanner sends only the extracted ecosystem, package name, and exact version to OSV.dev, never source code or full lockfile bytes. These coordinates can still disclose dependency choices. Use the CLI's `--offline` option or disable the API's automatic OSV setting when the target must remain fully local. OSV needs no API key. A query failure or truncated inventory is reported as incomplete coverage; zero returned advisories is not proof of safety.

The automatic path screens coordinates with [OSV querybatch](https://google.github.io/osv.dev/post-v1-querybatch/) and fetches full advisories only for matched packages. It attaches each source-linked advisory as an informational dependency finding because OSV's returned ID alone does not establish a severity rating. The automatic finding message includes only actual `CVE-...` primary IDs or aliases returned by OSV; the explicit `osv-query` response has a `cve_ids` field. A record may have no CVE identifier; CWE labels are never used to invent a CVE.

Automatic findings use line 1 as a lockfile-level location because the bounded TOML/JSON parsers do not retain package-entry line numbers. The package name and exact version are in the finding message. SARIF results keep distinct advisory fingerprints and link to validated public OSV advisory pages.

An explicit local query remains available for a package not present in a supported lockfile:

```powershell
uv run security-review osv-query --ecosystem PyPI --package jinja2 --version 2.4.1
```

The authenticated API also offers `POST /v1/vulnerabilities/query` with JSON fields `ecosystem`, `package`, and `version`. The Streamlit **Dependency CVEs** tab calls that endpoint after member login. Avoid explicitly querying private package names unless that disclosure is acceptable.

The adapter uses a fixed HTTPS origin, refuses redirects, limits response size to 1 MB, limits pages to eight and raw advisories to 500, rejects malformed or repeated pagination tokens, and returns a 503 if a complete result cannot be obtained. Tests use an offline HTTP transport; a live smoke query is a separate check. Retrieved summaries are untrusted data and are displayed as plain text.

The legacy `import-intelligence --cwe ... --cve ...` CSV command remains for the offline Text2SQL sample. Live OSV results are not inserted into that table or attached to code-pattern findings: a CWE match alone cannot identify an affected CVE.
