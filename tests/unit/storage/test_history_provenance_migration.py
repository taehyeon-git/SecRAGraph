from __future__ import annotations

import importlib
from unittest.mock import Mock

import pytest


def test_history_migration_adds_nullable_commit_with_source_location_constraint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    migration = importlib.import_module("migrations.versions.20261030_0008_git_history_provenance")
    add_column = Mock()
    create_check = Mock()
    monkeypatch.setattr(migration.op, "add_column", add_column)
    monkeypatch.setattr(migration.op, "create_check_constraint", create_check)
    monkeypatch.setattr(migration.op, "f", lambda name: name)

    migration.upgrade()

    column = add_column.call_args.args[1]
    assert column.name == "git_commit"
    assert column.nullable
    assert column.type.length == 64
    predicate = create_check.call_args.args[2]
    assert "file_path IS NOT NULL" in predicate
    assert "line_start IS NOT NULL" in predicate
    assert "http_method IS NULL" in predicate
    assert "http_path IS NULL" in predicate
    assert "[0-9a-f]{40}" in predicate


def test_history_migration_refuses_downgrade_with_provenance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    migration = importlib.import_module("migrations.versions.20261030_0008_git_history_provenance")
    connection = Mock()
    connection.scalar.return_value = True
    drop_column = Mock()
    monkeypatch.setattr(migration.op, "get_bind", lambda: connection)
    monkeypatch.setattr(migration.op, "drop_column", drop_column)

    with pytest.raises(RuntimeError, match="historical findings"):
        migration.downgrade()

    drop_column.assert_not_called()
