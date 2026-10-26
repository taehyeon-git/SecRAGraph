"""Member login state stays server-side and is cleared when invalid."""

from __future__ import annotations

from contextlib import nullcontext
from typing import Any

import pytest

from apps.web import streamlit_app
from apps.web.client import ApiClientError


class FakeStreamlit:
    def __init__(self, *, session: str | None = None, submit: bool = False, logout: bool = False):
        self.session_state: dict[str, str] = {}
        if session is not None:
            self.session_state["member_session"] = session
        self.submit = submit
        self.logout = logout
        self.warnings: list[str] = []
        self.errors: list[str] = []
        self.reruns = 0

    def subheader(self, _label: str) -> None:
        pass

    def form(self, _key: str):
        return nullcontext()

    def text_input(self, label: str, **_kwargs: Any) -> str:
        return "alice" if label == "Username" else "secure-password-123"

    def form_submit_button(self, _label: str) -> bool:
        return self.submit

    def caption(self, _message: str) -> None:
        pass

    def button(self, _label: str) -> bool:
        return self.logout

    def warning(self, message: str) -> None:
        self.warnings.append(message)

    def error(self, message: str) -> None:
        self.errors.append(message)

    def rerun(self) -> None:
        self.reruns += 1


def test_sign_in_stores_only_member_session(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeStreamlit(submit=True)
    created: list[dict[str, Any]] = []

    class Client:
        def __init__(self, _url: str, **kwargs: Any) -> None:
            created.append(kwargs)

        def login(self, _username: str, _password: str) -> dict[str, str]:
            return {"token": "member-session-secret"}

    monkeypatch.setattr(streamlit_app, "st", fake)
    monkeypatch.setattr(streamlit_app, "SecRAGraphApiClient", Client)

    assert streamlit_app._member_client(object()) is None
    assert fake.session_state == {"member_session": "member-session-secret"}
    assert fake.reruns == 1
    assert all("token" not in call and "session_token" not in call for call in created)


def test_expired_session_is_removed_before_scan_tabs(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeStreamlit(session="expired-secret")

    class Client:
        def __init__(self, _url: str, **_kwargs: Any) -> None:
            pass

        def me(self) -> None:
            raise ApiClientError(401, "unauthorized", "Authentication is required.")

    monkeypatch.setattr(streamlit_app, "st", fake)
    monkeypatch.setattr(streamlit_app, "SecRAGraphApiClient", Client)

    assert streamlit_app._member_client(object()) is None
    assert fake.session_state == {}
    assert fake.warnings == ["Your session expired. Sign in again."]


def test_logout_revokes_and_clears_session(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeStreamlit(session="member-session-secret", logout=True)
    revoked: list[bool] = []

    class Client:
        def __init__(self, _url: str, **_kwargs: Any) -> None:
            pass

        def me(self) -> dict[str, str]:
            return {"username": "alice"}

        def logout(self) -> None:
            revoked.append(True)

    monkeypatch.setattr(streamlit_app, "st", fake)
    monkeypatch.setattr(streamlit_app, "SecRAGraphApiClient", Client)

    assert streamlit_app._member_client(object()) is None
    assert revoked == [True]
    assert fake.session_state == {}
    assert fake.reruns == 1
