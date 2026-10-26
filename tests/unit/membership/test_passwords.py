import pytest

from security_review.membership.passwords import hash_password, verify_password


def test_scrypt_verifier_supports_unicode_and_does_not_store_password() -> None:
    password = "correct horse 🐴 battery staple"

    encoded = hash_password(password)

    assert encoded.startswith("scrypt$1$")
    assert password not in encoded
    assert verify_password(password, encoded)
    assert not verify_password("another password", encoded)


def test_verifier_rejects_password_outside_byte_length_policy() -> None:
    encoded = hash_password("a sufficiently long password")

    assert not verify_password("short", encoded)
    assert not verify_password("x" * 1025, encoded)


@pytest.mark.parametrize("encoded", ["", "scrypt$2$bad", "scrypt$1$32768$8$3$xx$yy", "plain"])
def test_malformed_or_unsupported_verifier_is_rejected(encoded: str) -> None:
    assert not verify_password("some password", encoded)
