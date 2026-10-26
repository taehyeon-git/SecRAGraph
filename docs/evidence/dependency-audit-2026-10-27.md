# Dependency advisory check (2026-10-27)

I audited the locally installed `uv.lock` environment against OSV with `pip-audit --local -s osv --strict`. The first run examined 129 installed packages and returned 46 advisory records across three packages: `certifi 2026.7.22` (2), `filelock 4.0.12` (3), and `pillow 12.3.0` (41). Counts are advisory records from this tool, not distinct root causes or proof of exploitability in SecRAGraph.

I then updated only the affected dependency families in `uv.lock` and installed the new lock. `pillow 13.0.0` required the compatible `streamlit 1.66.1` resolution. The resulting versions were:

| Package | Before | After |
| --- | --- | --- |
| certifi | 2026.7.22 | 2026.10.23 |
| filelock | 4.0.12 | 4.2.4 |
| pillow | 12.3.0 | 13.0.0 |
| streamlit | 1.65.0 | 1.66.1 |

The second OSV audit examined 128 installed packages and returned **0 known advisory records** at the time of the check. `pip-audit` could not parse `uv.lock` directly in this environment, so these counts are for the synchronized local environment, including development dependencies. They are not a guarantee that the code or its dependency chain has no vulnerabilities; OSV entries and package releases can change after the check. For context, see the [OSV certifi advisory](https://osv.dev/vulnerability/PYSEC-2026-4320) and an [OSV Pillow advisory](https://osv.dev/vulnerability/CVE-2026-112393).

Reproduce with:

```powershell
uv sync --locked --group dev
uv run pip-audit --local -s osv --strict --progress-spinner off
```

The dependency upgrade was followed by focused web/Text2SQL/RAG tests and a full suite rerun in this change set. The isolated Compose image must be rebuilt from the updated lock for container verification; an older running image does not inherit the local environment update.
