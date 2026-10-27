"""Authenticated API benchmark uses the real case labels without exposing credentials."""

from __future__ import annotations

import json
from email import policy
from email.parser import BytesParser
from io import BytesIO
from pathlib import Path
from uuid import UUID
from zipfile import ZipFile

import httpx
import pytest

from security_review.domain.models import Confidence, Finding, Severity
from security_review.evaluation.authenticated_scanner import (
    AuthenticatedBenchmarkError,
    run_authenticated_scanner_benchmark,
)
from security_review.reporting.builder import build_report


def _manifest(path: Path) -> Path:
    cases = [
        {
            "case_id": "nested-positive",
            "file_path": "nested/app.py",
            "source": "eval(user_input)\n",
            "expected": [{"rule_id": "PY001", "line_start": 1}],
            "is_benign": False,
            "expected_diagnostics": [],
            "unassessed_rules": [],
        },
        {
            "case_id": "env-negative",
            "file_path": ".env",
            "source": "SAFE=1\n",
            "expected": [],
            "is_benign": True,
            "expected_diagnostics": [],
            "unassessed_rules": [],
        },
    ]
    path.write_text(json.dumps({"schema_version": 1, "cases": cases}), encoding="utf-8")
    return path


def _multipart_zip(request: httpx.Request) -> tuple[str, str, bytes]:
    content_type = request.headers["content-type"]
    envelope = (
        f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode() + request.content
    )
    message = BytesParser(policy=policy.default).parsebytes(envelope)
    parts = list(message.iter_parts())
    assert len(parts) == 1
    filename = parts[0].get_filename()
    assert isinstance(filename, str)
    payload = parts[0].get_payload(decode=True)
    assert isinstance(payload, bytes)
    with ZipFile(BytesIO(payload)) as archive:
        names = archive.namelist()
        assert len(names) == 1
        return filename, names[0], archive.read(names[0])


class _MemberApi:
    def __init__(
        self,
        *,
        wrong_path: bool = False,
        wrong_rule: bool = False,
        foreign_status: int = 404,
        missing_status: int = 401,
        login_status: int = 200,
        ignore_logout: bool = False,
        changed_persisted_report: bool = False,
    ) -> None:
        self.wrong_path = wrong_path
        self.wrong_rule = wrong_rule
        self.foreign_status = foreign_status
        self.missing_status = missing_status
        self.login_status = login_status
        self.ignore_logout = ignore_logout
        self.changed_persisted_report = changed_persisted_report
        self.uploaded: list[tuple[str, str, bytes]] = []
        self.saved: dict[str, dict[str, object]] = {}
        self.logged_out = False

    def __call__(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        authorization = request.headers.get("authorization")
        if path == "/v1/auth/login" and request.method == "POST":
            if self.login_status != 200:
                return httpx.Response(
                    self.login_status,
                    json={"detail": "private-pass alice-session eval(user_input)"},
                )
            credentials = json.loads(request.content)
            if credentials["username"] == "alice" and credentials["password"] == "private-pass":
                return httpx.Response(200, json={"token": "alice-session", "username": "alice"})
            if credentials["username"] == "bob" and credentials["password"] == "other-pass":
                return httpx.Response(200, json={"token": "bob-session", "username": "bob"})
            return httpx.Response(401)
        if path == "/v1/auth/me" and request.method == "GET":
            if authorization == "Session alice-session" and not self.logged_out:
                return httpx.Response(
                    200,
                    json={"username": "alice", "user_id": "00000000-0000-4000-8000-000000000001"},
                )
            if authorization == "Session bob-session":
                return httpx.Response(
                    200,
                    json={"username": "bob", "user_id": "00000000-0000-4000-8000-000000000002"},
                )
            return httpx.Response(self.missing_status)
        if path == "/v1/scans/archive" and request.method == "POST":
            if authorization != "Session alice-session" or self.logged_out:
                return httpx.Response(401)
            filename, inner_path, content = _multipart_zip(request)
            self.uploaded.append((filename, inner_path, content))
            case_id = filename.removesuffix(".zip")
            findings: list[Finding] = []
            if case_id == "nested-positive":
                findings.append(
                    Finding(
                        id="synthetic-finding",
                        rule_id="PY002" if self.wrong_rule else "PY001",
                        category="code",
                        severity=Severity.HIGH,
                        file_path="wrong.py" if self.wrong_path else inner_path,
                        line_start=1,
                        message="Synthetic issue.",
                        redacted_evidence="Synthetic redaction.",
                        confidence=Confidence.HIGH,
                        remediation="Review the input.",
                    )
                )
            report = build_report(filename, findings).model_dump(mode="json")
            self.saved[report["scan_id"]] = report
            return httpx.Response(200, json=report)
        if path.startswith("/v1/scans/") and request.method == "GET":
            if authorization == "Session bob-session":
                return httpx.Response(self.foreign_status, json={"code": "scan_not_found"})
            if authorization != "Session alice-session" or self.logged_out:
                return httpx.Response(self.missing_status, json={"code": "unauthorized"})
            report = self.saved.get(path.rsplit("/", 1)[-1])
            if report and self.changed_persisted_report:
                report = {**report, "warnings": ["different"]}
            return httpx.Response(200, json=report) if report else httpx.Response(404)
        if path == "/v1/auth/logout" and request.method == "POST":
            if authorization != "Session alice-session":
                return httpx.Response(401)
            self.logged_out = not self.ignore_logout
            return httpx.Response(204)
        return httpx.Response(500)


def _run(path: Path, api: _MemberApi):
    first_password = "private-pass"
    second_member_password = "other-pass"
    with httpx.Client(base_url="http://example.test", transport=httpx.MockTransport(api)) as client:
        return run_authenticated_scanner_benchmark(
            client,
            path,
            username="alice",
            password=first_password,
            second_username="bob",
            second_password=second_member_password,
        )


def test_authenticated_cases_preserve_nested_paths_and_safe_evidence(tmp_path: Path) -> None:
    api = _MemberApi()
    result = _run(_manifest(tmp_path / "cases.json"), api)

    assert result.authenticated_uploads == 2
    assert result.persisted_reports_verified == 2
    assert result.source_paths_verified == 1
    assert (result.unauthenticated_rejected, result.foreign_member_rejected) == (True, True)
    assert result.logged_out_rejected is True
    assert result.has_failures is False
    assert result.benchmark.coverage.scanned == 2
    assert (
        result.benchmark.metrics.tp,
        result.benchmark.metrics.fp,
        result.benchmark.metrics.fn,
    ) == (
        1,
        0,
        0,
    )
    assert api.uploaded == [
        ("nested-positive.zip", "nested/app.py", b"eval(user_input)\n"),
        ("env-negative.zip", ".env", b"SAFE=1\n"),
    ]
    evidence = result.to_json() + result.to_markdown()
    assert "private-pass" not in evidence
    assert "other-pass" not in evidence
    assert "alice-session" not in evidence
    assert "eval(user_input)" not in evidence
    assert all(str(UUID(scan_id)) not in evidence for scan_id in api.saved)
    assert result.to_dict()["authentication"]["finding_locations_verified"] == 1


def test_wrong_finding_path_fails_before_scoring(tmp_path: Path) -> None:
    with pytest.raises(AuthenticatedBenchmarkError, match="finding_path_mismatch"):
        _run(_manifest(tmp_path / "cases.json"), _MemberApi(wrong_path=True))


def test_finding_mismatch_is_scored_for_safe_diagnostic_output(tmp_path: Path) -> None:
    result = _run(_manifest(tmp_path / "cases.json"), _MemberApi(wrong_rule=True))
    assert result.has_failures is True
    assert (
        result.benchmark.metrics.tp,
        result.benchmark.metrics.fp,
        result.benchmark.metrics.fn,
    ) == (
        0,
        1,
        1,
    )


@pytest.mark.parametrize(
    ("api", "code"),
    [
        (_MemberApi(missing_status=200), "missing_session_not_rejected"),
        (_MemberApi(login_status=401), "member_login_failed"),
        (_MemberApi(foreign_status=200), "foreign_member_not_rejected"),
        (_MemberApi(ignore_logout=True), "revoked_session_not_rejected"),
        (_MemberApi(changed_persisted_report=True), "persisted_report_mismatch"),
    ],
)
def test_access_or_persistence_failure_has_content_free_code(
    tmp_path: Path, api: _MemberApi, code: str
) -> None:
    with pytest.raises(AuthenticatedBenchmarkError) as caught:
        _run(_manifest(tmp_path / "cases.json"), api)
    assert str(caught.value) == code
    assert "private-pass" not in str(caught.value)
    assert "alice-session" not in str(caught.value)
    assert "eval(user_input)" not in str(caught.value)
    if code in {"missing_session_not_rejected", "member_login_failed"}:
        assert api.uploaded == []
