from datetime import UTC, datetime, timedelta

import pytest

from security_review.membership.service import (
    InMemoryMembershipRepository,
    MembershipError,
    MembershipService,
    session_digest,
)

NOW = datetime(2026, 10, 27, 1, 0, tzinfo=UTC)


def service() -> MembershipService:
    return MembershipService(InMemoryMembershipRepository())


def test_register_normalizes_username_and_rejects_invalid_usernames() -> None:
    membership = service()
    identity = membership.register("  Alice_123  ", "a sufficiently long password")

    assert identity.username == "alice_123"
    for username in ("ab", "x" * 33, "naïve", "has space"):
        with pytest.raises(MembershipError) as caught:
            membership.register(username, "a sufficiently long password")
        assert caught.value.code == "invalid_input"

    with pytest.raises(MembershipError) as duplicate:
        membership.register("ALICE_123", "a sufficiently long password")
    assert duplicate.value.code == "username_taken"


@pytest.mark.parametrize("password", ["short", "x" * 1025])
def test_register_rejects_password_outside_byte_length_policy(password: str) -> None:
    with pytest.raises(MembershipError) as caught:
        service().register("alice", password)
    assert caught.value.code == "invalid_input"


def test_unknown_and_wrong_password_fail_generically() -> None:
    membership = service()
    membership.register("alice", "a sufficiently long password")

    with pytest.raises(MembershipError) as unknown:
        membership.login("nobody", "a sufficiently long password", now=NOW)
    with pytest.raises(MembershipError) as wrong:
        membership.login("alice", "a sufficiently long password!", now=NOW)

    assert unknown.value.code == wrong.value.code == "invalid_credentials"
    assert str(unknown.value) == str(wrong.value)


def test_login_rejects_out_of_policy_password_without_locking_account() -> None:
    membership = service()
    membership.register("alice", "a sufficiently long password")

    for _ in range(5):
        with pytest.raises(MembershipError) as caught:
            membership.login("alice", "x" * 1025, now=NOW)
        assert caught.value.code == "invalid_credentials"
    assert (
        membership.login("alice", "a sufficiently long password", now=NOW).identity.username
        == "alice"
    )


def test_five_failed_attempts_lock_account_until_fifteen_minutes_and_unlock() -> None:
    membership = service()
    membership.register("alice", "a sufficiently long password")
    for _ in range(5):
        with pytest.raises(MembershipError):
            membership.login("alice", "wrong password here", now=NOW)

    with pytest.raises(MembershipError) as locked:
        membership.login("alice", "a sufficiently long password", now=NOW)
    assert locked.value.code == "invalid_credentials"
    with pytest.raises(MembershipError):
        membership.login("alice", "a sufficiently long password", now=NOW + timedelta(minutes=14))
    assert (
        membership.login(
            "alice", "a sufficiently long password", now=NOW + timedelta(minutes=15)
        ).identity.username
        == "alice"
    )

    membership.disable("alice")
    with pytest.raises(MembershipError) as disabled:
        membership.login("alice", "a sufficiently long password", now=NOW + timedelta(hours=1))
    assert disabled.value.code == "invalid_credentials"
    membership.unlock("alice")


def test_session_expires_at_absolute_and_idle_deadlines_and_logout_revokes() -> None:
    membership = service()
    membership.register("alice", "a sufficiently long password")
    login = membership.login("alice", "a sufficiently long password", now=NOW)
    assert login.expires_at == NOW + timedelta(hours=8)
    assert login.token not in repr(login)
    assert membership.resolve(login.token, now=NOW + timedelta(minutes=29)) == login.identity
    assert membership.resolve(login.token, now=NOW + timedelta(minutes=60)) is None

    second = membership.login("alice", "a sufficiently long password", now=NOW)
    assert membership.resolve(second.token, now=NOW + timedelta(hours=8)) is None
    membership.logout(second.token)
    assert membership.resolve(second.token, now=NOW + timedelta(seconds=1)) is None
    assert len(session_digest(second.token)) == 64


def test_successful_login_clears_failures_and_clock_is_deterministic() -> None:
    membership = service()
    membership.register("alice", "a sufficiently long password")
    for _ in range(4):
        with pytest.raises(MembershipError):
            membership.login("alice", "wrong password here", now=NOW)
    first = membership.login("alice", "a sufficiently long password", now=NOW)
    assert first.expires_at == NOW + timedelta(hours=8)
    for _ in range(4):
        with pytest.raises(MembershipError):
            membership.login("alice", "wrong password here", now=NOW)
