"""Streamlit demo that communicates with SecRAGraph only over HTTP."""

from __future__ import annotations

import json
import os
from typing import Any, Literal
from uuid import UUID

import httpx
import streamlit as st

from apps.web.client import (
    MAX_UPLOAD_BYTES,
    ApiClientError,
    SecRAGraphApiClient,
    safe_source_url,
)

API_BASE_URL = os.environ.get("SECRAGRAPH_API_BASE_URL", "http://api:8000")
_SESSION_KEY = "member_session"


def _show_client_error(error: ApiClientError) -> None:
    if error.status_code == 401 and _SESSION_KEY in st.session_state:
        st.session_state.pop(_SESSION_KEY, None)
        st.warning("Your session expired. Sign in again.")
        return
    correlation = f" (request {error.correlation_id})" if error.correlation_id else ""
    st.error("The API request failed.")
    st.text(
        _safe_text(
            f"{error.code}: {error.message}{correlation}",
            "The API request failed.",
            maximum=800,
        )
    )


def _show_scan_result(result: dict[str, Any]) -> None:
    summary = result.get("summary")
    if isinstance(summary, dict):
        total = summary.get("total")
        display_total: int | str = total if type(total) is int and total >= 0 else "Unavailable"
        st.metric("Findings", display_total)
    st.json(result)


def _show_report_downloads(api: SecRAGraphApiClient, result: dict[str, Any]) -> None:
    """Download the canonical scan and both server-rendered report formats."""

    raw_scan_id = result.get("scan_id")
    try:
        scan_id = str(UUID(raw_scan_id))
    except (TypeError, ValueError):
        st.warning("Report downloads are unavailable for this response.")
        return
    json_bytes = json.dumps(result, indent=2, ensure_ascii=False).encode("utf-8")
    st.download_button(
        "Download JSON",
        data=json_bytes,
        file_name=f"secragraph-{scan_id}.json",
        mime="application/json",
        on_click="ignore",
    )
    formats: tuple[tuple[Literal["markdown", "sarif"], str, str, str], ...] = (
        ("markdown", "Download Markdown", "md", "text/markdown"),
        ("sarif", "Download SARIF", "sarif", "application/sarif+json"),
    )
    for report_format, label, extension, mime in formats:
        try:
            body = api.get_report_format(scan_id, report_format)
        except ApiClientError as error:
            _show_client_error(error)
            continue
        st.download_button(
            label,
            data=body,
            file_name=f"secragraph-{scan_id}.{extension}",
            mime=mime,
            on_click="ignore",
        )


def _safe_text(value: object, fallback: str, *, maximum: int) -> str:
    if not isinstance(value, str):
        return fallback
    normalized = value.strip()
    if (
        not normalized
        or len(normalized) > maximum
        or any(
            (ord(character) < 32 and character not in {"\n", "\r", "\t"}) or ord(character) == 127
            for character in normalized
        )
    ):
        return fallback
    return normalized


def _show_knowledge_result(result: dict[str, Any]) -> None:
    st.subheader("Answer")
    st.text(_safe_text(result.get("answer"), "No answer returned.", maximum=20_000))
    warnings = result.get("warnings")
    if isinstance(warnings, list):
        for warning in warnings:
            st.warning("Knowledge workflow warning.")
            st.text(_safe_text(warning, "Unknown warning.", maximum=500))
    sources = result.get("sources")
    if not isinstance(sources, list) or not sources:
        return
    st.subheader("Sources")
    for index, source in enumerate(sources, start=1):
        if not isinstance(source, dict):
            continue
        title = _safe_text(source.get("title"), f"Source {index}", maximum=300)
        st.text(title)
        section = source.get("section")
        if section is not None:
            maximum = 8_192 if result.get("intent") == "text2sql" else 500
            st.text(_safe_text(section, "Section unavailable.", maximum=maximum))
        url = safe_source_url(source.get("source_url"))
        if url is not None:
            st.link_button(f"Open source {index}", url)


def _show_osv_result(result: dict[str, Any]) -> None:
    """Display only validated, version-scoped OSV records and CVE aliases."""

    advisories = result.get("advisories")
    if not isinstance(advisories, list) or not advisories:
        st.info(
            "OSV returned no advisory for this package version; this is not a safety guarantee."
        )
        return
    st.subheader(f"OSV advisories: {len(advisories)}")
    for index, advisory in enumerate(advisories, start=1):
        if not isinstance(advisory, dict):
            continue
        st.text(_safe_text(advisory.get("id"), f"Advisory {index}", maximum=128))
        st.text(_safe_text(advisory.get("summary"), "Summary unavailable.", maximum=500))
        aliases = advisory.get("cve_ids")
        if isinstance(aliases, list) and aliases:
            st.text("CVE aliases: " + ", ".join(str(item) for item in aliases[:100]))
        source = safe_source_url(advisory.get("source_url"))
        if source is not None:
            st.link_button(f"Open OSV advisory {index}", source)


def _member_client(http: httpx.Client) -> SecRAGraphApiClient | None:
    """Establish or validate a member session held only in Streamlit server state."""

    token = st.session_state.get(_SESSION_KEY)
    if not isinstance(token, str) or not token:
        st.subheader("Member sign in")
        with st.form("member-login"):
            username = st.text_input("Username", max_chars=32)
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Sign in")
        if submitted:
            try:
                anonymous = SecRAGraphApiClient(API_BASE_URL, http_client=http)
                login = anonymous.login(username, password)
            except (ApiClientError, ValueError) as error:
                if isinstance(error, ApiClientError):
                    _show_client_error(error)
                else:
                    st.error("Enter a valid username and password.")
            else:
                st.session_state[_SESSION_KEY] = login["token"]
                st.rerun()
        return None

    try:
        api = SecRAGraphApiClient(API_BASE_URL, http_client=http, session_token=token)
        identity = api.me()
    except (ApiClientError, ValueError) as error:
        if isinstance(error, ApiClientError):
            _show_client_error(error)
        else:
            st.session_state.pop(_SESSION_KEY, None)
            st.error("The saved session is invalid. Sign in again.")
        return None

    st.caption(f"Signed in as {identity['username']}")
    if st.button("Sign out"):
        try:
            api.logout()
        except ApiClientError as error:
            if error.status_code != 401:
                _show_client_error(error)
        finally:
            st.session_state.pop(_SESSION_KEY, None)
            st.rerun()
        return None
    return api


def main() -> None:
    """Render the two-tab portfolio demo."""

    st.set_page_config(page_title="SecRAGraph", page_icon="🛡️", layout="wide")
    st.title("SecRAGraph")
    st.caption("RAG- and LangGraph-powered security review platform; local demo only")
    timeout = httpx.Timeout(150.0, connect=5.0, write=5.0, pool=5.0)
    with httpx.Client(timeout=timeout, follow_redirects=False) as http:
        try:
            api = _member_client(http)
        except ValueError:
            st.error("The configured API base URL is invalid.")
            return
        if api is None:
            return

        scan_tab, knowledge_tab, osv_tab = st.tabs(["File scan", "Security Q&A", "Dependency CVEs"])
        with scan_tab:
            st.caption("Deterministic, keyless source scan. Uploaded code is never executed.")
            uploaded = st.file_uploader(
                "Choose a supported source file",
                type=["py", "js", "ts", "json", "yaml", "yml", "toml", "env", "ini"],
            )
            if st.button("Scan file", disabled=uploaded is None):
                if uploaded is not None:
                    if type(uploaded.size) is not int or uploaded.size < 0:
                        st.error("The selected file is invalid.")
                    elif uploaded.size > MAX_UPLOAD_BYTES:
                        st.error("The selected file exceeds the client upload limit.")
                    else:
                        try:
                            result = api.scan_file(
                                uploaded.name,
                                uploaded.getvalue(),
                                uploaded.type or "application/octet-stream",
                            )
                        except (ApiClientError, ValueError) as error:
                            if isinstance(error, ApiClientError):
                                _show_client_error(error)
                            else:
                                st.error("The selected file is invalid.")
                        else:
                            _show_scan_result(result)
                            _show_report_downloads(api, result)
        with knowledge_tab:
            st.caption(
                "Provider-backed Q&A requires a configured API key in the backend. "
                "Offline RAG evidence is a separate keyless evaluation, not a live answer."
            )
            question = st.text_area(
                "Ask a security question",
                max_chars=2_000,
                placeholder="How should CWE-95 be mitigated?",
            )
            if st.button("Ask SecRAGraph"):
                try:
                    result = api.query_knowledge(question)
                except ValueError:
                    st.error("Enter a non-empty security question.")
                except ApiClientError as error:
                    _show_client_error(error)
                else:
                    _show_knowledge_result(result)
        with osv_tab:
            st.caption(
                "Queries OSV.dev for a known package version. "
                "Package name and version are sent to OSV."
            )
            ecosystem = st.selectbox("Ecosystem", ["PyPI", "npm", "Go", "Maven"])
            package = st.text_input("Package name", max_chars=255)
            version = st.text_input("Package version", max_chars=100)
            if st.button("Check OSV"):
                try:
                    result = api.query_vulnerabilities(ecosystem, package, version)
                except ValueError:
                    st.error("Enter a package name and version.")
                except ApiClientError as error:
                    _show_client_error(error)
                else:
                    _show_osv_result(result)


if __name__ == "__main__":
    main()
