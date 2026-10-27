# CodeQL cross-file smoke check

This local check used CodeQL CLI **2.27.0** and `codeql/python-queries` **1.8.10** on a synthetic FastAPI sample in the ignored `build/` directory. The sample was extracted but never executed. It is evidence for one built-in query, not a scanner accuracy benchmark.

The built-in `py/command-line-injection` query reported one SARIF result with two paths to the same `subprocess.run(..., shell=True)` sink:

| Source | Sink | Steps | Meaning |
| --- | --- | ---: | --- |
| `app.py:9` (`/raw/{value}`) | `sink.py:5` | 6 | True positive: input crosses `flow.py` and reaches a shell command. |
| `app.py:14` (`/checked/{value}`) | `sink.py:5` | 9 | False positive in this sample: `allowlisted` permits only `[A-Za-z0-9_]{1,32}` or an empty string before fixed `echo `. |

The built-in query recognizes FastAPI input and the shell sink across files, but does not infer that this custom allowlist is a sanitizer. The separate `codeql/FastApiCrossFileFlow.ql` fixture query models that barrier explicitly and is **not** run as a production Code Scanning rule. We did not add a broad sanitizer exemption without a verified production source/sink pair.

## Reproduction

Run from the repository root in PowerShell with a locally installed `codeql` bundle. The following source files were saved under `build/codeql-built-in-smoke/src/codeql_flow/` (plus an empty `__init__.py`). Split at each `# filename` marker and omit that marker when saving a file:

```python
# app.py
from fastapi import FastAPI

from codeql_flow.flow import unchecked, checked

app = FastAPI()


@app.get("/raw/{value}")
def raw(value: str) -> int:
    return unchecked(value)


@app.get("/checked/{value}")
def validated(value: str) -> int:
    return checked(value)


# flow.py
from codeql_flow.sanitize import allowlisted
from codeql_flow.sink import shell_echo


def unchecked(value: str) -> int:
    return shell_echo(value)


def checked(value: str) -> int:
    return shell_echo(allowlisted(value))


# sanitize.py
import re


def allowlisted(value: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9_]{1,32}", value):
        return value
    return ""


# sink.py
import subprocess


def shell_echo(value: str) -> int:
    return subprocess.run("echo " + value, shell=True, check=False).returncode
```

```powershell
New-Item -ItemType Directory -Force -Path build/codeql-built-in-smoke/src/codeql_flow | Out-Null
New-Item -ItemType File -Force -Path build/codeql-built-in-smoke/src/codeql_flow/__init__.py | Out-Null
# Save the four source listings above as app.py, flow.py, sanitize.py and sink.py.
codeql database create build/codeql-built-in-smoke/db `
  --language=python --source-root=build/codeql-built-in-smoke/src `
  --build-mode=none --overwrite
codeql database analyze build/codeql-built-in-smoke/db `
  codeql/python-queries:Security/CWE-078/CommandInjection.ql `
  --format=sarif-latest --output=build/codeql-built-in-smoke/command.sarif

$sarif = Get-Content build/codeql-built-in-smoke/command.sarif -Raw | ConvertFrom-Json
$sarif.runs[0].results[0].codeFlows | ForEach-Object {
  $locations = $_.threadFlows[0].locations
  [pscustomobject]@{
    SourceLine = $locations[0].location.physicalLocation.region.startLine
    SinkLine = $locations[-1].location.physicalLocation.region.startLine
    Steps = $locations.Count
  }
}
```

The [CodeQL Python data-flow guide](https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-python/) describes sources, sinks and barriers. The [supported framework list](https://codeql.github.com/docs/codeql-overview/supported-languages-and-frameworks/) includes FastAPI. The built-in [command-line injection query](https://codeql.github.com/codeql-query-help/python/py-command-line-injection/) belongs to `security-extended`.
