import pytest

from security_review.scanner.compose_files import COMPOSE_POLICY_VERSION, is_compose_file


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("compose.yaml", True),
        ("Docker-Compose.yml", True),
        ("compose.override.yaml", True),
        ("docker-compose.test.yml", True),
        ("compose..yaml", True),
        ("nested/compose.yaml", True),
        ("nested/Docker-Compose.TEST.YML", True),
        ("other.yaml", False),
        ("compose.env", False),
        ("compose.한글.yml", False),
        ("not-compose.yaml", False),
        ("doKker-compose.yaml", False),
        ("compose/.yaml", False),
        ("compose.yaml/other.yml", False),
    ],
)
def test_is_compose_file_matches_only_recognized_posix_basenames(path: str, expected: bool) -> None:
    assert is_compose_file(path) is expected


def test_compose_policy_version_is_fixed() -> None:
    assert COMPOSE_POLICY_VERSION == "2026.10.30.1"
