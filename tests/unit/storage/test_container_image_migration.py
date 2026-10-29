from __future__ import annotations

import importlib
from unittest.mock import Mock

import pytest


def test_image_migration_replaces_location_constraint_and_keeps_old_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    migration = importlib.import_module("migrations.versions.20261030_0009_container_image")
    add_column = Mock()
    drop_constraint = Mock()
    create_constraint = Mock()
    monkeypatch.setattr(migration.op, "add_column", add_column)
    monkeypatch.setattr(migration.op, "drop_constraint", drop_constraint)
    monkeypatch.setattr(migration.op, "create_check_constraint", create_constraint)
    monkeypatch.setattr(migration.op, "f", lambda name: name)

    migration.upgrade()

    names = {call.args[1].name for call in add_column.call_args_list}
    assert names == {"image_id", "image_resource", "upstream_severity", "severity_source"}
    assert drop_constraint.call_args.args[0] == "ck_findings_location_exactly_one"
    predicate = create_constraint.call_args.args[2]
    assert "file_path IS NOT NULL AND line_start IS NOT NULL" in predicate
    assert "http_method IS NOT NULL AND http_path IS NOT NULL" in predicate
    assert "image_id IS NOT NULL AND image_resource IS NOT NULL" in predicate
    assert "git_commit IS NULL" in predicate
    assert "sha256:[0-9a-f]{64}" in predicate


def test_image_migration_refuses_downgrade_with_image_findings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    migration = importlib.import_module("migrations.versions.20261030_0009_container_image")
    connection = Mock()
    connection.scalar.return_value = True
    drop_column = Mock()
    monkeypatch.setattr(migration.op, "get_bind", lambda: connection)
    monkeypatch.setattr(migration.op, "drop_column", drop_column)

    with pytest.raises(RuntimeError, match="image findings"):
        migration.downgrade()

    drop_column.assert_not_called()
