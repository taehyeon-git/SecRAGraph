"""Adversarial tests for the fail-closed PostgreSQL SELECT guard."""

from __future__ import annotations

import pytest

from security_review.intelligence.sql_guard import UnsafeSqlError, validate_readonly_sql

ALLOWED_TABLES = frozenset({"intel.cwe", "intel.cve"})


@pytest.mark.parametrize(
    "sql",
    [
        "DELETE FROM intel.cwe",
        "UPDATE intel.cwe SET name = 'changed'",
        "INSERT INTO intel.cwe (cwe_id) VALUES ('CWE-1')",
        "SELECT cwe_id FROM intel.cwe; DROP TABLE intel.cwe",
        "SELECT target_name FROM app.scan_reports",
        "COPY intel.cwe TO PROGRAM 'whoami'",
        "WITH removed AS (DELETE FROM intel.cwe RETURNING cwe_id) SELECT cwe_id FROM removed",
        "SELECT pg_sleep(10) FROM intel.cwe",
        "SELECT cwe_id INTO temp_copy FROM intel.cwe",
        "SELECT cwe_id FROM intel.cwe FOR UPDATE",
        "SELECT cwe_id FROM intel.cwe OFFSET 1000000",
        "SELECT cwe_id FROM intel.cwe -- ignore the policy",
        "SELECT cwe_id FROM intel.cwe /* hidden instruction */",
        "SELECT * FROM intel.cwe",
        "SELECT cwe.* FROM intel.cwe AS cwe",
        "SELECT COUNT(*) FROM intel.cve",
        "SELECT cwe_id FROM cwe",
        "SELECT table_name FROM information_schema.tables",
        "SELECT 1",
        "SELECT nextval('s') FROM intel.cwe",
        "SELECT public.lower(name) FROM intel.cwe",
        "SELECT cvss_score OPERATOR(public.+) 1 FROM intel.cve",
        "SELECT cwe_id FROM other.intel.cwe",
        'SELECT cwe_id FROM "Intel"."Cwe"',
        "SELECT cwe_id FROM intel.cwe UNION SELECT cve_id FROM intel.cve",
        "SELECT nested.cwe_id FROM intel.cwe AS outer_cwe JOIN "
        "(SELECT cwe_id FROM intel.cwe UNION SELECT cwe_id FROM intel.cve) AS nested "
        "ON nested.cwe_id = outer_cwe.cwe_id",
        "SELECT rogue.cwe_id FROM "
        "(WITH scoped AS (SELECT cwe_id FROM intel.cwe) SELECT cwe_id FROM scoped) "
        "AS approved JOIN scoped AS rogue ON TRUE",
    ],
)
def test_rejects_unsafe_or_out_of_scope_sql(sql: str) -> None:
    with pytest.raises(UnsafeSqlError):
        validate_readonly_sql(sql, ALLOWED_TABLES, 100)


def test_accepts_a_qualified_join_and_preserves_a_small_limit() -> None:
    guarded = validate_readonly_sql(
        "SELECT v.cve_id, w.name FROM intel.cve AS v "
        "JOIN intel.cwe AS w ON w.cwe_id = v.cwe_id "
        "ORDER BY v.cvss_score DESC LIMIT 5",
        ALLOWED_TABLES,
        100,
    )

    assert guarded == (
        "SELECT v.cve_id, w.name FROM intel.cve AS v "
        "JOIN intel.cwe AS w ON w.cwe_id = v.cwe_id "
        "ORDER BY v.cvss_score DESC LIMIT 5"
    )


def test_adds_or_reduces_a_literal_limit() -> None:
    without_limit = validate_readonly_sql(
        "SELECT cwe_id FROM intel.cwe",
        ALLOWED_TABLES,
        25,
    )
    excessive_limit = validate_readonly_sql(
        "SELECT cve_id FROM intel.cve LIMIT 9999",
        ALLOWED_TABLES,
        25,
    )

    assert without_limit.endswith("LIMIT 25")
    assert excessive_limit.endswith("LIMIT 25")


def test_accepts_safe_ctes_aggregates_and_allowlisted_functions() -> None:
    guarded = validate_readonly_sql(
        "WITH scored AS ("
        "SELECT vendor, cvss_score FROM intel.cve WHERE cvss_score >= 7"
        ") "
        "SELECT LOWER(vendor) AS vendor_name, COUNT(vendor) AS total, "
        "ROUND(AVG(cvss_score), 1) AS average_score "
        "FROM scored GROUP BY LOWER(vendor) ORDER BY total DESC",
        ALLOWED_TABLES,
        10,
    )

    assert guarded.startswith("WITH scored AS")
    assert guarded.endswith("LIMIT 10")


def test_comment_markers_inside_a_string_literal_are_not_sql_comments() -> None:
    guarded = validate_readonly_sql(
        "SELECT '-- not a comment' AS note FROM intel.cwe",
        ALLOWED_TABLES,
        10,
    )

    assert guarded == "SELECT '-- not a comment' AS note FROM intel.cwe LIMIT 10"


@pytest.mark.parametrize("limit", [0, -1])
def test_rejects_an_invalid_configured_row_limit(limit: int) -> None:
    with pytest.raises(ValueError, match="row_limit"):
        validate_readonly_sql("SELECT cwe_id FROM intel.cwe", ALLOWED_TABLES, limit)


def test_error_does_not_echo_the_rejected_sql() -> None:
    with pytest.raises(UnsafeSqlError) as captured:
        validate_readonly_sql("DELETE FROM intel.cwe", ALLOWED_TABLES, 100)

    assert "DELETE" not in str(captured.value)
