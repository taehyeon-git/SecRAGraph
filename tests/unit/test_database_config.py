"""Repository defaults must never provide an authenticating database secret."""

from __future__ import annotations

import pytest
from alembic.config import Config
from sqlalchemy.engine import make_url

from security_review.config import Settings


def test_settings_default_database_url_has_no_password(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SECRAGRAPH_DATABASE_URL", raising=False)
    settings = Settings(_env_file=None)
    assert make_url(settings.database_url).password is None


def test_alembic_fallback_database_url_has_no_password() -> None:
    configuration = Config("alembic.ini")
    assert make_url(configuration.get_main_option("sqlalchemy.url")).password is None
