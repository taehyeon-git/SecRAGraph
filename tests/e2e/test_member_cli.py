"""Local account administration never accepts passwords as command arguments."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from uuid import UUID

from typer.testing import CliRunner

from security_review import cli


class FakeMembership:
    def __init__(self) -> None:
        self.created: tuple[str, str] | None = None
        self.disabled: str | None = None
        self.unlocked: str | None = None

    def register(self, username: str, password: str):
        self.created = (username, password)
        return type("Identity", (), {"username": username, "user_id": UUID(int=1)})()

    def disable(self, username: str) -> None:
        self.disabled = username

    def unlock(self, username: str) -> None:
        self.unlocked = username


def test_cli_creates_user_with_hidden_confirmed_password(monkeypatch) -> None:
    membership = FakeMembership()

    @contextmanager
    def context() -> Iterator[FakeMembership]:
        yield membership

    monkeypatch.setattr(cli, "_membership_service_context", context, raising=False)
    result = CliRunner().invoke(
        cli.app,
        ["create-user", "alice"],
        input="secure-password-123\nsecure-password-123\n",
    )

    assert result.exit_code == 0
    assert membership.created == ("alice", "secure-password-123")
    assert "secure-password-123" not in result.output


def test_cli_disable_and_unlock_use_the_same_member_store(monkeypatch) -> None:
    membership = FakeMembership()

    @contextmanager
    def context() -> Iterator[FakeMembership]:
        yield membership

    monkeypatch.setattr(cli, "_membership_service_context", context, raising=False)
    runner = CliRunner()

    disabled = runner.invoke(cli.app, ["disable-user", "alice"])
    unlocked = runner.invoke(cli.app, ["unlock-user", "alice"])

    assert disabled.exit_code == unlocked.exit_code == 0
    assert membership.disabled == membership.unlocked == "alice"
