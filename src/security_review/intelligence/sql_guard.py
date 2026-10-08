"""Fail-closed AST validation for generated PostgreSQL SELECT statements."""

from __future__ import annotations

from sqlglot import exp, parse
from sqlglot.errors import OptimizeError, SqlglotError
from sqlglot.optimizer.scope import Scope, traverse_scope

_FORBIDDEN_NODES = (
    exp.Insert,
    exp.Update,
    exp.Delete,
    exp.Create,
    exp.Drop,
    exp.Alter,
    exp.Command,
    exp.Copy,
    exp.TruncateTable,
    exp.Merge,
    exp.Grant,
    exp.Revoke,
    exp.Execute,
    exp.Set,
    exp.Use,
    exp.Into,
    exp.Lock,
    exp.Offset,
    exp.Parameter,
    exp.Placeholder,
    exp.SetOperation,
    exp.Operator,
)
_ALLOWED_FUNCTION_TYPES: frozenset[type[exp.Func]] = frozenset(
    {
        exp.Avg,
        exp.Coalesce,
        exp.Count,
        exp.Extract,
        exp.Length,
        exp.Lower,
        exp.Max,
        exp.Min,
        exp.Nullif,
        exp.Round,
        exp.Sum,
        exp.TimestampTrunc,
        exp.Upper,
    }
)


class UnsafeSqlError(ValueError):
    """Generated SQL failed a safe validation rule without echoing its contents."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"unsafe_sql: {reason}")


def validate_readonly_sql(
    sql: str,
    allowed_tables: frozenset[str],
    row_limit: int,
) -> str:
    """Return normalized bounded SQL only when every AST node is read-only and scoped."""

    if row_limit < 1:
        raise ValueError("row_limit must be at least 1")
    normalized_tables = _validate_allowed_tables(allowed_tables)
    if not sql.strip():
        raise UnsafeSqlError("empty_statement")

    try:
        statements = parse(sql, read="postgres")
    except SqlglotError as error:
        raise UnsafeSqlError("parse_error") from error
    if len(statements) != 1 or statements[0] is None:
        raise UnsafeSqlError("exactly_one_statement_required")
    statement = statements[0]
    if not isinstance(statement, exp.Select):
        raise UnsafeSqlError("select_required")

    if any(node.comments for node in statement.walk()):
        raise UnsafeSqlError("comments_not_allowed")
    if any(isinstance(node, _FORBIDDEN_NODES) for node in statement.walk()):
        raise UnsafeSqlError("forbidden_operation")
    if any(isinstance(node, exp.Star) for node in statement.walk()):
        raise UnsafeSqlError("wildcards_not_allowed")

    _validate_functions(statement)
    _validate_tables(statement, normalized_tables)
    _apply_limit(statement, row_limit)
    return statement.sql(dialect="postgres")


def _validate_allowed_tables(allowed_tables: frozenset[str]) -> frozenset[str]:
    if not allowed_tables:
        raise ValueError("allowed_tables must not be empty")
    normalized: set[str] = set()
    for table in allowed_tables:
        parts = table.split(".")
        if len(parts) != 2 or any(
            not part or not part.replace("_", "").isalnum() for part in parts
        ):
            raise ValueError("allowed_tables must contain qualified schema.table names")
        normalized.add(table.casefold())
    return frozenset(normalized)


def _validate_tables(statement: exp.Select, allowed_tables: frozenset[str]) -> None:
    approved_table_seen = False
    try:
        scopes = traverse_scope(statement)
        for scope in scopes:
            for _, source in scope.selected_sources.values():
                if isinstance(source, Scope):
                    continue
                if not isinstance(source, exp.Table):
                    raise UnsafeSqlError("table_source_not_allowed")
                _validate_physical_table(source, allowed_tables)
                approved_table_seen = True
    except OptimizeError as error:
        raise UnsafeSqlError("invalid_query_scope") from error
    if not approved_table_seen:
        raise UnsafeSqlError("approved_table_required")


def _validate_physical_table(table: exp.Table, allowed_tables: frozenset[str]) -> None:
    catalog = table.args.get("catalog")
    schema = table.args.get("db")
    name = table.this
    if catalog is not None or schema is None:
        raise UnsafeSqlError("qualified_table_required")
    if not isinstance(schema, exp.Identifier) or not isinstance(name, exp.Identifier):
        raise UnsafeSqlError("table_not_allowed")
    qualified_name = f"{_normalize_identifier(schema)}.{_normalize_identifier(name)}"
    if qualified_name not in allowed_tables:
        raise UnsafeSqlError("table_not_allowed")


def _normalize_identifier(identifier: exp.Identifier) -> str:
    return identifier.name if identifier.args.get("quoted") else identifier.name.casefold()


def _validate_functions(statement: exp.Select) -> None:
    for function in statement.find_all(exp.Func):
        if type(function) not in _ALLOWED_FUNCTION_TYPES:
            raise UnsafeSqlError("function_not_allowed")


def _apply_limit(statement: exp.Select, row_limit: int) -> None:
    limit = statement.args.get("limit")
    bounded = row_limit
    if limit is not None:
        value = limit.expression
        if not isinstance(value, exp.Literal) or value.is_string:
            raise UnsafeSqlError("literal_limit_required")
        try:
            requested = int(value.this)
        except (TypeError, ValueError) as error:
            raise UnsafeSqlError("literal_limit_required") from error
        if requested < 0:
            raise UnsafeSqlError("nonnegative_limit_required")
        bounded = min(requested, row_limit)
    statement.set("limit", exp.Limit(expression=exp.Literal.number(bounded)))
