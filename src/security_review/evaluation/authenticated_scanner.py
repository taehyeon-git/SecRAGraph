"""Score the synthetic scanner corpus through real member-authenticated API routes."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from hashlib import sha256
from io import BytesIO
from pathlib import Path
from uuid import UUID
from zipfile import ZIP_DEFLATED, ZipFile

import httpx

from security_review.domain.models import ScanReport
from security_review.evaluation.scanner_benchmark import (
    CaseAssessment,
    ScannerBenchmark,
    assess_scanner_case,
    summarize_scanner_assessments,
)
from security_review.evaluation.scanner_models import ScannerCase, load_scanner_cases

_SAFE_DIAGNOSTIC_CODE = re.compile(r"[a-z][a-z0-9_]*\Z")


class AuthenticatedBenchmarkError(ValueError):
    """A content-free failure code safe to expose in evaluation logs."""


@dataclass(frozen=True, slots=True)
class AuthenticatedScannerResult:
    """Safe, stable evidence for member login, report storage, and exact scanner labels."""

    benchmark: ScannerBenchmark
    authenticated_uploads: int
    persisted_reports_verified: int
    source_paths_verified: int
    unauthenticated_rejected: bool
    foreign_member_rejected: bool
    logged_out_rejected: bool

    @property
    def has_failures(self) -> bool:
        return bool(
            self.benchmark.has_finding_mismatches
            or self.benchmark.has_coverage_failures
            or self.authenticated_uploads != self.benchmark.coverage.total
            or self.persisted_reports_verified != self.benchmark.coverage.total
            or not all(
                (
                    self.unauthenticated_rejected,
                    self.foreign_member_rejected,
                    self.logged_out_rejected,
                )
            )
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "evaluation": "member-authenticated API scan of the synthetic scanner corpus",
            "authentication": {
                "authenticated_uploads": self.authenticated_uploads,
                "persisted_reports_verified": self.persisted_reports_verified,
                "finding_locations_verified": self.source_paths_verified,
                "unauthenticated_rejected": self.unauthenticated_rejected,
                "foreign_member_rejected": self.foreign_member_rejected,
                "logged_out_rejected": self.logged_out_rejected,
            },
            "scanner": self.benchmark.to_dict(),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, indent=2, ensure_ascii=False) + "\n"

    def to_markdown(self) -> str:
        lines = [
            "# Member-authenticated scanner evaluation",
            "",
            "Every synthetic case was uploaded as a one-file ZIP through the API after member "
            "login. Each JSON report was retrieved from storage and compared with the upload "
            "response. The scanner findings use exact case, rule, and line labels.",
            "",
            "- Authenticated uploads: "
            f"{self.authenticated_uploads}/{self.benchmark.coverage.total}",
            "- Persisted reports verified: "
            f"{self.persisted_reports_verified}/{self.benchmark.coverage.total}",
            f"- Finding locations verified: {self.source_paths_verified}",
            f"- Missing session rejected (401): {self.unauthenticated_rejected}",
            f"- Other member denied the report (404): {self.foreign_member_rejected}",
            f"- Revoked session rejected (401): {self.logged_out_rejected}",
            "",
            self.benchmark.to_markdown().rstrip(),
            "",
        ]
        return "\n".join(lines)


def _request(
    client: httpx.Client,
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    json_body: dict[str, str] | None = None,
    files: dict[str, tuple[str, bytes, str]] | None = None,
) -> httpx.Response:
    try:
        return client.request(
            method,
            url,
            headers=headers,
            json=json_body,
            files=files,
        )
    except httpx.HTTPError:
        raise AuthenticatedBenchmarkError("api_unavailable") from None


def _login(client: httpx.Client, username: str, password: str) -> str:
    response = _request(
        client,
        "POST",
        "/v1/auth/login",
        json_body={"username": username, "password": password},
    )
    if response.status_code != 200:
        raise AuthenticatedBenchmarkError("member_login_failed")
    try:
        body = response.json()
    except ValueError:
        raise AuthenticatedBenchmarkError("member_login_schema_invalid") from None
    if not isinstance(body, dict):
        raise AuthenticatedBenchmarkError("member_login_schema_invalid")
    token = body.get("token")
    if not isinstance(token, str):
        raise AuthenticatedBenchmarkError("member_login_schema_invalid")
    if not token or "\r" in token or "\n" in token:
        raise AuthenticatedBenchmarkError("member_login_schema_invalid")
    returned_username = body.get("username")
    if returned_username is not None and returned_username != username:
        raise AuthenticatedBenchmarkError("member_login_identity_mismatch")
    return token


def _member_id(client: httpx.Client, header: dict[str, str], username: str) -> UUID:
    response = _request(client, "GET", "/v1/auth/me", headers=header)
    if response.status_code != 200:
        raise AuthenticatedBenchmarkError("member_identity_failed")
    try:
        body = response.json()
        if not isinstance(body, dict) or body.get("username") != username:
            raise ValueError
        user_id = UUID(body["user_id"])
    except (KeyError, TypeError, ValueError):
        raise AuthenticatedBenchmarkError("member_identity_schema_invalid") from None
    return user_id


def _report(response: httpx.Response, *, expected_target: str | None = None) -> ScanReport:
    if response.status_code != 200:
        raise AuthenticatedBenchmarkError("scan_api_failed")
    try:
        report = ScanReport.model_validate(response.json())
    except ValueError:
        raise AuthenticatedBenchmarkError("scan_report_schema_invalid") from None
    if expected_target is not None and report.target_name != expected_target:
        raise AuthenticatedBenchmarkError("scan_report_target_mismatch")
    if report.summary.total != len(report.findings):
        raise AuthenticatedBenchmarkError("scan_report_summary_mismatch")
    return report


def _one_file_archive(case: ScannerCase) -> bytes:
    buffer = BytesIO()
    with ZipFile(buffer, mode="w", compression=ZIP_DEFLATED) as archive:
        archive.writestr(case.file_path, case.source.encode("utf-8"))
    return buffer.getvalue()


def _safe_warnings(case: ScannerCase, report: ScanReport) -> tuple[str, ...]:
    safe: list[str] = []
    for warning in report.warnings:
        for prefix in (f"{case.file_path}:", f"{Path(case.file_path).name}:"):
            if warning.startswith(prefix):
                warning = warning[len(prefix) :]
                break
        if _SAFE_DIAGNOSTIC_CODE.fullmatch(warning) is None:
            raise AuthenticatedBenchmarkError("scan_diagnostic_schema_invalid")
        safe.append(warning)
    return tuple(safe)


def _expect_status(response: httpx.Response, expected: int, failure_code: str) -> None:
    if response.status_code != expected:
        raise AuthenticatedBenchmarkError(failure_code)


def run_authenticated_scanner_benchmark(
    client: httpx.Client,
    cases_path: Path,
    *,
    username: str,
    password: str,
    second_username: str,
    second_password: str,
) -> AuthenticatedScannerResult:
    """Exercise login, isolated case uploads, persisted reads, ownership, and logout."""

    try:
        # Normalize checkout newlines exactly as the local scanner benchmark does.
        corpus_sha256 = sha256(cases_path.read_text(encoding="utf-8").encode("utf-8")).hexdigest()
        cases = load_scanner_cases(cases_path)
    except (OSError, ValueError):
        raise AuthenticatedBenchmarkError("invalid_cases_manifest") from None

    if username == second_username:
        raise AuthenticatedBenchmarkError("members_must_be_distinct")
    _expect_status(
        _request(client, "GET", "/v1/auth/me"),
        401,
        "missing_session_not_rejected",
    )
    member_token = _login(client, username, password)
    second_token = _login(client, second_username, second_password)
    if member_token == second_token:
        raise AuthenticatedBenchmarkError("member_sessions_not_distinct")
    member_header = {"Authorization": f"Session {member_token}"}
    second_header = {"Authorization": f"Session {second_token}"}
    if _member_id(client, member_header, username) == _member_id(
        client, second_header, second_username
    ):
        raise AuthenticatedBenchmarkError("members_must_be_distinct")

    assessments: list[CaseAssessment] = []
    versions: set[str] = set()
    finding_locations = 0
    first_scan_id: str | None = None
    for case in cases:
        filename = f"{case.case_id}.zip"
        uploaded = _report(
            _request(
                client,
                "POST",
                "/v1/scans/archive",
                headers=member_header,
                files={"file": (filename, _one_file_archive(case), "application/zip")},
            ),
            expected_target=filename,
        )
        if first_scan_id is None:
            first_scan_id = str(uploaded.scan_id)
        for finding in uploaded.findings:
            if finding.file_path != case.file_path:
                raise AuthenticatedBenchmarkError("finding_path_mismatch")
            finding_locations += 1

        persisted = _report(
            _request(client, "GET", f"/v1/scans/{uploaded.scan_id}", headers=member_header),
            expected_target=filename,
        )
        if uploaded.model_dump(mode="json") != persisted.model_dump(mode="json"):
            raise AuthenticatedBenchmarkError("persisted_report_mismatch")

        assessment = assess_scanner_case(
            case,
            frozenset((finding.rule_id, finding.line_start) for finding in uploaded.findings),
            _safe_warnings(case, uploaded),
        )
        if (
            assessment.skipped
            or assessment.missing_diagnostics
            or assessment.unexpected_diagnostics
        ):
            raise AuthenticatedBenchmarkError("scan_coverage_failure")
        assessments.append(assessment)
        versions.add(uploaded.rule_set_version)

    if len(assessments) != len(cases) or len(versions) != 1 or first_scan_id is None:
        raise AuthenticatedBenchmarkError("scan_coverage_failure")

    report_url = f"/v1/scans/{first_scan_id}"
    _expect_status(_request(client, "GET", report_url), 401, "missing_session_not_rejected")
    _expect_status(
        _request(client, "GET", report_url, headers=second_header),
        404,
        "foreign_member_not_rejected",
    )
    _expect_status(
        _request(client, "POST", "/v1/auth/logout", headers=member_header),
        204,
        "member_logout_failed",
    )
    _expect_status(
        _request(client, "GET", report_url, headers=member_header),
        401,
        "revoked_session_not_rejected",
    )

    benchmark = summarize_scanner_assessments(
        assessments,
        corpus_sha256=corpus_sha256,
        rule_set_version=versions.pop(),
    )
    return AuthenticatedScannerResult(
        benchmark=benchmark,
        authenticated_uploads=len(assessments),
        persisted_reports_verified=len(assessments),
        source_paths_verified=finding_locations,
        unauthenticated_rejected=True,
        foreign_member_rejected=True,
        logged_out_rejected=True,
    )
