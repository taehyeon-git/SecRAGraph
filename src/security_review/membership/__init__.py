"""Local member authentication and opaque session management."""

from security_review.membership.passwords import hash_password, verify_password
from security_review.membership.service import (
    InMemoryMembershipRepository,
    LoginResult,
    MemberIdentity,
    MembershipError,
    MembershipRepository,
    MembershipService,
    normalize_username,
    session_digest,
)

__all__ = [
    "InMemoryMembershipRepository",
    "LoginResult",
    "MemberIdentity",
    "MembershipError",
    "MembershipRepository",
    "MembershipService",
    "hash_password",
    "normalize_username",
    "session_digest",
    "verify_password",
]
