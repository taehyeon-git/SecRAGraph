# Synthetic security-intelligence samples

These CSV rows were written for SecRAGraph and are intentionally synthetic. The future-dated
`CVE-2099-*` identifiers are not claims about real vulnerabilities. The files exist only to make
local imports and automated tests reproducible; do not use them as a production vulnerability
feed.

Import this documented CSV shape with:

```console
security-review import-intelligence --cwe data/samples/cwe.csv --cve data/samples/cve.csv
```

For real data, obtain it directly from its publisher, transform it into these headers, preserve
the publisher URL in `source_url`, and review that source's current license before redistribution.
Record the upstream publication date, exact release/revision, download URL, license, raw-file
SHA-256, and your import timestamp in a separate local receipt. The import timestamp means only
"loaded into this database then"; it does not prove that the upstream feed was current or
complete. These sample CSVs have no live-update mechanism or authoritative publication date.
