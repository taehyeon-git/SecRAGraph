"""Syntax-aware recognition of a small set of Python security-relevant calls.

This module parses source text only. It never imports or evaluates scanned code.
"""

from __future__ import annotations

import ast
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class PythonCallMatch:
    rule_id: str
    line_start: int


class PythonCallScanStopped(RuntimeError):
    """The caller's time budget expired before traversal completed."""


@dataclass(slots=True)
class _Scope:
    parent: _Scope | None = None
    kind: str = "module"
    bindings: dict[str, str | None] = field(default_factory=dict)
    local_names: frozenset[str] = frozenset()
    global_names: frozenset[str] = frozenset()
    nonlocal_names: frozenset[str] = frozenset()


_DEFAULT_BINDINGS: dict[str, str] = {
    "eval": "builtins.eval",
    "builtins": "builtins",
    "os": "os",
    "requests": "requests",
    "subprocess": "subprocess",
}
_DIRECT_IMPORTS = frozenset({"builtins", "os", "requests", "subprocess"})


class _LocalBindings(ast.NodeVisitor):
    """Collect Python's lexical local names without entering child scopes."""

    def __init__(self) -> None:
        self.names: set[str] = set()
        self.globals: set[str] = set()
        self.nonlocals: set[str] = set()

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.names.add(node.id)

    def visit_Import(self, node: ast.Import) -> None:
        self.names.update(alias.asname or alias.name.split(".")[0] for alias in node.names)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        self.names.update(alias.asname or alias.name for alias in node.names if alias.name != "*")

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.names.add(node.name)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.names.add(node.name)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.names.add(node.name)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return

    def visit_ListComp(self, node: ast.ListComp) -> None:
        return

    def visit_SetComp(self, node: ast.SetComp) -> None:
        return

    def visit_DictComp(self, node: ast.DictComp) -> None:
        return

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        return

    def visit_Global(self, node: ast.Global) -> None:
        self.globals.update(node.names)

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
        self.nonlocals.update(node.names)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.name is not None:
            self.names.add(node.name)
        self.generic_visit(node)


def _parameter_names(args: ast.arguments) -> set[str]:
    names = {arg.arg for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs)}
    if args.vararg is not None:
        names.add(args.vararg.arg)
    if args.kwarg is not None:
        names.add(args.kwarg.arg)
    return names


def _function_scope(body: Sequence[ast.stmt], args: ast.arguments, parent: _Scope) -> _Scope:
    collector = _LocalBindings()
    for statement in body:
        collector.visit(statement)
    enclosing = parent
    while enclosing.kind == "class" and enclosing.parent is not None:
        enclosing = enclosing.parent
    return _Scope(
        parent=enclosing,
        kind="function",
        local_names=frozenset(
            (collector.names | _parameter_names(args)) - collector.globals - collector.nonlocals
        ),
        global_names=frozenset(collector.globals),
        nonlocal_names=frozenset(collector.nonlocals),
    )


class _CallVisitor(ast.NodeVisitor):
    def __init__(self, should_stop: Callable[[], bool] | None) -> None:
        self._should_stop = should_stop
        self._module = _Scope(bindings=dict(_DEFAULT_BINDINGS))
        self._scope = self._module
        self.matches: list[PythonCallMatch] = []

    def visit(self, node: ast.AST) -> None:
        self._check_stop()
        super().visit(node)

    def _check_stop(self) -> None:
        if self._should_stop is not None and self._should_stop():
            raise PythonCallScanStopped

    def _binding_scope(self, name: str) -> _Scope:
        if name in self._scope.global_names:
            return self._module
        if name in self._scope.nonlocal_names:
            parent = self._scope.parent
            while parent is not None and parent is not self._module:
                if name in parent.local_names or name in parent.bindings:
                    return parent
                parent = parent.parent
        return self._scope

    def _bind(self, name: str, value: str | None = None) -> None:
        self._binding_scope(name).bindings[name] = value

    def _resolve(self, name: str) -> str | None:
        scope: _Scope | None = self._scope
        while scope is not None:
            if name in scope.global_names:
                scope = self._module
            if name in scope.bindings:
                return scope.bindings[name]
            if name in scope.local_names:
                return None
            scope = scope.parent
        return None

    def _symbol(self, node: ast.expr) -> str | None:
        if isinstance(node, ast.Name):
            return self._resolve(node.id)
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            base = self._resolve(node.value.id)
            return f"{base}.{node.attr}" if base is not None else None
        return None

    @staticmethod
    def _literal_keyword(node: ast.Call, name: str, value: bool) -> bool:
        return any(
            keyword.arg == name
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is value
            for keyword in node.keywords
        )

    def visit_Call(self, node: ast.Call) -> None:
        symbol = self._symbol(node.func)
        rule_id: str | None = None
        if symbol == "builtins.eval":
            rule_id = "PY001"
        elif symbol == "os.system":
            rule_id = "PY002"
        elif symbol in {"subprocess.run", "subprocess.call", "subprocess.Popen"}:
            if self._literal_keyword(node, "shell", True):
                rule_id = "PY002"
        elif symbol is not None and symbol.startswith("requests."):
            if self._literal_keyword(node, "verify", False):
                rule_id = "PY003"
        if rule_id is not None:
            self.matches.append(PythonCallMatch(rule_id, node.lineno))
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            bound_name = alias.asname or alias.name.split(".")[0]
            imported = alias.name if alias.asname else alias.name.split(".")[0]
            self._bind(bound_name, imported if imported in _DIRECT_IMPORTS else None)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            if alias.name == "*":
                for name in _DEFAULT_BINDINGS:
                    self._bind(name)
                continue
            imported = f"{node.module}.{alias.name}" if node.level == 0 else None
            self._bind(
                alias.asname or alias.name,
                imported if node.module in _DIRECT_IMPORTS else None,
            )

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self._bind(node.id)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.type is not None:
            self.visit(node.type)
        if node.name is not None:
            self._bind(node.name)
        for statement in node.body:
            self.visit(statement)

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        for target in node.targets:
            self.visit(target)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self.visit(node.annotation)
        if node.value is not None:
            self.visit(node.value)
        self.visit(node.target)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.visit(node.value)
        self.visit(node.target)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.visit(node.value)
        self.visit(node.target)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node, node.args, node.body, node.decorator_list, node.returns)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node, node.args, node.body, node.decorator_list, node.returns)

    def _visit_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        args: ast.arguments,
        body: Sequence[ast.stmt],
        decorators: Sequence[ast.expr],
        returns: ast.expr | None,
    ) -> None:
        for expression in (*decorators, *args.defaults, *args.kw_defaults):
            if expression is not None:
                self.visit(expression)
        for parameter in (*args.posonlyargs, *args.args, *args.kwonlyargs):
            if parameter.annotation is not None:
                self.visit(parameter.annotation)
        if returns is not None:
            self.visit(returns)
        self._bind(node.name)
        parent = self._scope
        self._scope = _function_scope(body, args, parent)
        try:
            for statement in body:
                self.visit(statement)
        finally:
            self._scope = parent

    def visit_Lambda(self, node: ast.Lambda) -> None:
        for expression in (*node.args.defaults, *node.args.kw_defaults):
            if expression is not None:
                self.visit(expression)
        parent = self._scope
        collector = _LocalBindings()
        collector.visit(node.body)
        self._scope = _Scope(
            parent=parent,
            kind="function",
            local_names=frozenset(collector.names | _parameter_names(node.args)),
        )
        try:
            self.visit(node.body)
        finally:
            self._scope = parent

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for expression in (*node.decorator_list, *node.bases):
            self.visit(expression)
        for keyword in node.keywords:
            self.visit(keyword.value)
        self._bind(node.name)
        parent = self._scope
        self._scope = _Scope(parent=parent, kind="class")
        try:
            for statement in node.body:
                self.visit(statement)
        finally:
            self._scope = parent

    def _visit_comprehension(
        self, generators: Sequence[ast.comprehension], values: Sequence[ast.expr]
    ) -> None:
        if not generators:
            return
        self.visit(generators[0].iter)
        collector = _LocalBindings()
        for generator in generators:
            collector.visit(generator.target)
        parent = self._scope
        self._scope = _Scope(parent=parent, kind="function", local_names=frozenset(collector.names))
        try:
            for index, generator in enumerate(generators):
                if index:
                    self.visit(generator.iter)
                self.visit(generator.target)
                for condition in generator.ifs:
                    self.visit(condition)
            for value in values:
                self.visit(value)
        finally:
            self._scope = parent

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self._visit_comprehension(node.generators, (node.elt,))

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self._visit_comprehension(node.generators, (node.elt,))

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        self._visit_comprehension(node.generators, (node.elt,))

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self._visit_comprehension(node.generators, (node.key, node.value))


def detect_python_calls(
    text: str, *, should_stop: Callable[[], bool] | None = None
) -> tuple[PythonCallMatch, ...]:
    """Return calls to supported APIs using syntax and simple lexical bindings."""

    if should_stop is not None and should_stop():
        raise PythonCallScanStopped
    try:
        tree = ast.parse(text)
    except (SyntaxError, RecursionError):
        if should_stop is not None and should_stop():
            raise PythonCallScanStopped from None
        raise
    if should_stop is not None and should_stop():
        raise PythonCallScanStopped
    visitor = _CallVisitor(should_stop)
    visitor.visit(tree)
    return tuple(sorted(visitor.matches, key=lambda item: (item.line_start, item.rule_id)))
