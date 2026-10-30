"""Numeric differential scanning accepts only complete, scoped response evidence."""

from __future__ import annotations

import json

import pytest

from security_review.dast.differential import (
    DifferentialProbeError,
    NumericSeed,
    numeric_query_seeds,
    parse_probe_output,
)
from security_review.dast.zap import sanitize_openapi


def _observation(seed: NumericSeed, *, baseline_status: int = 200) -> dict[str, object]:
    a, b = "a" * 64, "b" * 64
    return {
        "path": seed.path,
        "parameter": seed.parameter,
        "baseline": [[baseline_status, a], [baseline_status, a]],
        "control": [[422, b], [422, b]],
        "true": [[422, b], [422, b]],
        "false": [[422, b], [422, b]],
    }


@pytest.mark.parametrize("status", [401, 403, 404, 429])
def test_non_successful_baseline_is_unscored_partial(status: int) -> None:
    seed = NumericSeed("/records", "record_id", "1")
    row = _observation(seed, baseline_status=status)
    for name in ("control", "true", "false"):
        row[name] = [[status, "a" * 64], [status, "a" * 64]]

    with pytest.raises(DifferentialProbeError, match="baseline"):
        parse_probe_output(json.dumps({"results": [row]}).encode(), (seed,))


@pytest.mark.parametrize("variant", ["control", "true", "false"])
@pytest.mark.parametrize("status", [401, 403, 404, 429])
def test_expired_or_rate_limited_variant_is_unscored_partial(variant: str, status: int) -> None:
    seed = NumericSeed("/records", "record_id", "1")
    row = _observation(seed)
    row[variant] = [[status, "b" * 64], [status, "b" * 64]]

    with pytest.raises(DifferentialProbeError, match="non_successful_differential_variant"):
        parse_probe_output(json.dumps({"results": [row]}).encode(), (seed,))


def test_rejected_numeric_injections_remain_completed_clean_negative() -> None:
    seed = NumericSeed("/records", "record_id", "1")

    assert parse_probe_output(json.dumps({"results": [_observation(seed)]}).encode(), (seed,)) == ()


def test_maximum_seed_count_and_route_length_fit_bounded_output() -> None:
    seeds = tuple(
        NumericSeed("/" + "r" * 989 + str(index), "record_id", "1") for index in range(16)
    )
    raw = json.dumps({"results": [_observation(seed) for seed in seeds]}).encode()
    assert 16_384 < len(raw) < 65_536

    assert parse_probe_output(raw, seeds) == ()


def test_path_item_numeric_query_parameter_is_inherited_by_marked_get() -> None:
    document = {
        "openapi": "3.1.0",
        "info": {"title": "Fixture", "version": "1"},
        "paths": {
            "/inherited": {
                "parameters": [
                    {
                        "name": "record_id",
                        "in": "query",
                        "required": True,
                        "schema": {"type": "integer", "example": 1},
                    }
                ],
                "get": {"x-secragraph-dast-active": True},
            }
        },
    }
    safe = sanitize_openapi(
        json.dumps(document).encode(), origin="http://secragraph-target:8765", active=True
    )

    assert numeric_query_seeds(safe.document) == (NumericSeed("/inherited", "record_id", "1"),)


def test_effective_get_parameters_skip_overrides_and_other_required_queries() -> None:
    numeric = {
        "name": "record_id",
        "in": "query",
        "required": True,
        "schema": {"type": "string", "example": "1"},
    }
    document = {
        "openapi": "3.1.0",
        "info": {"title": "Fixture", "version": "1"},
        "paths": {
            "/overridden": {
                "parameters": [numeric],
                "get": {
                    "x-secragraph-dast-active": True,
                    "parameters": [
                        {
                            **numeric,
                            "schema": {"type": "string", "example": "name"},
                        }
                    ],
                },
            },
            "/needs-tenant": {
                "parameters": [numeric],
                "get": {
                    "x-secragraph-dast-active": True,
                    "parameters": [
                        {
                            "name": "tenant",
                            "in": "query",
                            "required": True,
                            "schema": {"type": "string"},
                        }
                    ],
                },
            },
            "/optional-tenant": {
                "parameters": [numeric],
                "get": {
                    "x-secragraph-dast-active": True,
                    "parameters": [
                        {
                            "name": "tenant",
                            "in": "query",
                            "required": False,
                            "schema": {"type": "string"},
                        }
                    ],
                },
            },
        },
    }
    safe = sanitize_openapi(
        json.dumps(document).encode(), origin="http://secragraph-target:8765", active=True
    )

    assert numeric_query_seeds(safe.document) == (
        NumericSeed("/optional-tenant", "record_id", "1"),
    )
