"""Bounded numeric SQLi response comparison for approved active OpenAPI seeds."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from hashlib import sha256
from typing import Any

from security_review.domain.models import Confidence, Finding, Severity

ENGINE = "dast-differential"
RULE = "DIFF/NUMERIC_SQLI"
CHECK = "numeric-sqli-differential"
MAX_SEEDS = 16
MAX_OUTPUT_BYTES = 65_536
_PARAMETER = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z")
_NUMBER = re.compile(r"[1-9][0-9]{0,5}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True, slots=True)
class NumericSeed:
    path: str
    parameter: str
    baseline: str


class DifferentialProbeError(ValueError):
    """No complete differential evidence is available."""


def numeric_query_seeds(document: bytes) -> tuple[NumericSeed, ...]:
    """Select bounded literal GET routes with one numeric-example query parameter."""

    source = json.loads(document)
    selected: list[NumericSeed] = []
    for path, operations in sorted(source["paths"].items()):
        if "{" in path:
            continue
        operation = operations.get("get", {})
        path_parameters = operations.get("parameters", [])
        operation_parameters = operation.get("parameters", [])
        if (
            not isinstance(path_parameters, list)
            or not isinstance(operation_parameters, list)
            or len(path_parameters) + len(operation_parameters) > 64
        ):
            continue
        # OpenAPI operation parameters override inherited path-item parameters.
        effective: dict[tuple[str, str], dict[str, Any]] = {}
        for parameter in (*path_parameters, *operation_parameters):
            if not isinstance(parameter, dict):
                effective = {}
                break
            name = parameter.get("name")
            location = parameter.get("in")
            if not isinstance(name, str) or not isinstance(location, str):
                effective = {}
                break
            effective[(location, name)] = parameter
        if not effective:
            continue
        for (location, name), parameter in sorted(effective.items()):
            if location != "query" or not _PARAMETER.fullmatch(name):
                continue
            # This probe supplies only one query value; other required inputs
            # would make a baseline error look like a negative result.
            if any(
                other.get("required") is True and key != (location, name)
                for key, other in effective.items()
            ):
                continue
            schema = parameter.get("schema")
            if not isinstance(schema, dict):
                continue
            examples = schema.get("examples")
            example = (
                examples[0] if isinstance(examples, list) and examples else schema.get("example")
            )
            if example is None:
                example = parameter.get("example")
            schema_type = schema.get("type")
            if (
                example is None
                and isinstance(schema_type, str)
                and schema_type in {"integer", "number"}
            ):
                example = 1
            if isinstance(example, bool) or not isinstance(example, (str, int)):
                continue
            baseline = str(example)
            if not _NUMBER.fullmatch(baseline):
                continue
            selected.append(NumericSeed(path, name, baseline))
            break
        if len(selected) >= MAX_SEEDS:
            break
    return tuple(selected)


def _samples(value: Any) -> tuple[int, str]:
    if (
        not isinstance(value, list)
        or len(value) != 2
        or any(not isinstance(item, list) or len(item) != 2 for item in value)
    ):
        raise DifferentialProbeError("invalid_differential_samples")
    first, second = value
    for status, fingerprint in (first, second):
        if (
            type(status) is not int
            or not 200 <= status <= 499
            or 300 <= status <= 399
            or not isinstance(fingerprint, str)
            or not _DIGEST.fullmatch(fingerprint)
        ):
            raise DifferentialProbeError("invalid_differential_samples")
    if first != second:
        raise DifferentialProbeError("unstable_differential_response")
    return first[0], first[1]


def parse_probe_output(raw: bytes, seeds: tuple[NumericSeed, ...]) -> tuple[Finding, ...]:
    """Accept only repeated stable response fingerprints and emit no raw HTTP material."""

    if not raw or len(raw) > MAX_OUTPUT_BYTES:
        raise DifferentialProbeError("invalid_differential_output")
    try:
        payload = json.loads(raw)
    except (ValueError, UnicodeError) as error:
        raise DifferentialProbeError("invalid_differential_output") from error
    rows = payload.get("results") if isinstance(payload, dict) else None
    if not isinstance(rows, list) or len(rows) != len(seeds):
        raise DifferentialProbeError("invalid_differential_output")
    expected = {(seed.path, seed.parameter) for seed in seeds}
    seen: set[tuple[str, str]] = set()
    findings: dict[str, Finding] = {}
    for row in rows:
        if not isinstance(row, dict) or set(row) != {
            "path",
            "parameter",
            "baseline",
            "control",
            "true",
            "false",
        }:
            raise DifferentialProbeError("invalid_differential_output")
        key = (row["path"], row["parameter"])
        if key not in expected or key in seen:
            raise DifferentialProbeError("invalid_differential_output")
        seen.add(key)
        baseline = _samples(row["baseline"])
        if baseline[0] != 200:
            raise DifferentialProbeError("non_successful_differential_baseline")
        control = _samples(row["control"])
        true = _samples(row["true"])
        false = _samples(row["false"])
        if any(sample[0] in {401, 403, 404, 429} for sample in (control, true, false)):
            raise DifferentialProbeError("non_successful_differential_variant")
        if (
            baseline[0] == control[0] == true[0] == false[0] == 200
            and baseline == control == false
            and true[1] != baseline[1]
        ):
            path = row["path"]
            identity = sha256(f"{RULE}\0GET\0{path}".encode()).hexdigest()[:24]
            findings[path] = Finding(
                id=f"DIFF-{identity}",
                rule_id=RULE,
                category="dast",
                severity=Severity.HIGH,
                http_method="GET",
                http_path=path,
                message="Stable numeric true/false SQL predicate responses differ from baseline.",
                redacted_evidence=(
                    "Repeated GET responses (all 200); normalized body HMAC-SHA256 "
                    f"prefixes: baseline/control/false={baseline[1][:12]}, "
                    f"true={true[1][:12]}. "
                    "HTTP bodies and query values omitted."
                ),
                confidence=Confidence.MEDIUM,
                cwe_ids=("CWE-89",),
                remediation="Bind numeric query parameters in SQL and validate their types.",
                engine=ENGINE,
            )
    if seen != expected:
        raise DifferentialProbeError("invalid_differential_output")
    return tuple(findings[path] for path in sorted(findings))


PROBE_SCRIPT = r"""
# NUMERIC_SQLI_PROBE_V1
import hashlib
import hmac
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

origin = sys.argv[1]
seeds = json.loads(sys.argv[2])
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
auth = os.environ.get('ZAP_AUTH_HEADER_VALUE')
fingerprint_key = bytes.fromhex(os.environ['DAST_PROBE_FINGERPRINT_KEY'])

def request(path, parameter, value):
    url = origin + path + '?' + urllib.parse.urlencode({parameter: value})
    headers = {'Authorization': auth} if auth else {}
    try:
        response = opener.open(urllib.request.Request(url, headers=headers), timeout=4)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        status = response.status
        body = response.read(4097)
    if len(body) > 4096:
        raise ValueError('response_too_large')
    try:
        normalized = json.dumps(json.loads(body), sort_keys=True, separators=(',', ':')).encode()
    except (ValueError, UnicodeError):
        normalized = b' '.join(body.split())
    return [status, hmac.new(fingerprint_key, normalized, hashlib.sha256).hexdigest()]

results = []
for path, parameter, baseline in seeds:
    samples = {}
    variants = {
        'baseline': baseline,
        'control': baseline + '+0',
        'true': baseline + ' OR 1=1',
        'false': baseline + ' OR 1=2',
    }
    for label, value in variants.items():
        samples[label] = [request(path, parameter, value) for _ in range(2)]
    results.append({'path': path, 'parameter': parameter, **samples})
sys.stdout.write(json.dumps({'results': results}, separators=(',', ':')))
""".strip()
