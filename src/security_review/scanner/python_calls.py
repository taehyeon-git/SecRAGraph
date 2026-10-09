"""Syntax-aware recognition of a small set of Python security-relevant calls.

This module parses source text only. It never imports or evaluates scanned code.
"""

from __future__ import annotations

import ast
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import cast


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


class _ComprehensionWalrusBindings(ast.NodeVisitor):
    """Find enclosing walrus targets, optionally excluding deferred generator bodies."""

    def __init__(self, *, eager_only: bool = False) -> None:
        self.names: set[str] = set()
        self._eager_only = eager_only

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        if isinstance(node.target, ast.Name):
            self.names.add(node.target.id)
        self.visit(node.value)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        if not self._eager_only:
            self.generic_visit(node)
        elif node.generators:
            # Only the outer iterable runs when the generator is created.
            self.visit(node.generators[0].iter)

    def visit_Starred(self, node: ast.Starred) -> None:
        if self._eager_only and isinstance(node.ctx, ast.Load):
            self.consume_iterable(node.value)
        else:
            self.visit(node.value)

    def consume_iterable(self, node: ast.expr) -> None:
        """Collect bindings from evaluating and then iterating an expression."""
        self.visit(node)
        if isinstance(node, ast.GeneratorExp):
            self.consume_generator(node)

    def consume_generator(self, node: ast.GeneratorExp) -> None:
        """Collect walruses that may run while a generator is iterated."""
        for index, generator in enumerate(node.generators):
            if index:
                self.consume_iterable(generator.iter)
            elif isinstance(generator.iter, ast.GeneratorExp):
                # Its creation was visited already; iteration runs its body.
                self.consume_generator(generator.iter)
            for condition in generator.ifs:
                self.visit(condition)
        self.visit(node.elt)

    def _visit_eager_comprehension(
        self, generators: Sequence[ast.comprehension], values: Sequence[ast.expr]
    ) -> None:
        for generator in generators:
            self.consume_iterable(generator.iter)
            for condition in generator.ifs:
                self.visit(condition)
        for value in values:
            self.visit(value)

    def visit_ListComp(self, node: ast.ListComp) -> None:
        if self._eager_only:
            self._visit_eager_comprehension(node.generators, (node.elt,))
        else:
            self.generic_visit(node)

    def visit_SetComp(self, node: ast.SetComp) -> None:
        if self._eager_only:
            self._visit_eager_comprehension(node.generators, (node.elt,))
        else:
            self.generic_visit(node)

    def visit_DictComp(self, node: ast.DictComp) -> None:
        if self._eager_only:
            self._visit_eager_comprehension(node.generators, (node.key, node.value))
        else:
            self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if not self._eager_only:
            self.generic_visit(node)
            return
        self.visit(node.func)
        for expression in (*node.args, *(keyword.value for keyword in node.keywords)):
            self.visit(expression)
            if isinstance(expression, ast.GeneratorExp):
                self.consume_generator(expression)


class _LocalBindings(ast.NodeVisitor):
    """Collect local names without entering child scopes or deferred bodies when requested."""

    def __init__(self, *, eager_only: bool = False) -> None:
        self.names: set[str] = set()
        self.globals: set[str] = set()
        self.nonlocals: set[str] = set()
        self._eager_only = eager_only

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

    def _collect_comprehension_walrus(self, node: ast.AST) -> None:
        collector = _ComprehensionWalrusBindings(eager_only=self._eager_only)
        collector.visit(node)
        self.names.update(collector.names)

    def visit_Call(self, node: ast.Call) -> None:
        if self._eager_only:
            self._collect_comprehension_walrus(node)
        else:
            self.generic_visit(node)

    def visit_Starred(self, node: ast.Starred) -> None:
        if self._eager_only and isinstance(node.ctx, ast.Load):
            self._collect_comprehension_walrus(node)
        else:
            self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        self._visit_for(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self._visit_for(node)

    def _visit_for(self, node: ast.For | ast.AsyncFor) -> None:
        if self._eager_only:
            collector = _ComprehensionWalrusBindings(eager_only=True)
            collector.consume_iterable(node.iter)
            self.names.update(collector.names)
        self.generic_visit(node)

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self._collect_comprehension_walrus(node)

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self._collect_comprehension_walrus(node)

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self._collect_comprehension_walrus(node)

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        self._collect_comprehension_walrus(node)

    def visit_Global(self, node: ast.Global) -> None:
        self.globals.update(node.names)

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
        self.nonlocals.update(node.names)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.name is not None:
            self.names.add(node.name)
        self.generic_visit(node)

    def visit_MatchAs(self, node: ast.MatchAs) -> None:
        if node.name is not None:
            self.names.add(node.name)
        self.generic_visit(node)

    def visit_MatchStar(self, node: ast.MatchStar) -> None:
        if node.name is not None:
            self.names.add(node.name)

    def visit_MatchMapping(self, node: ast.MatchMapping) -> None:
        if node.rest is not None:
            self.names.add(node.rest)
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

    @staticmethod
    def _fork_scope(scope: _Scope) -> tuple[_Scope, _Scope]:
        chain: list[_Scope] = []
        current: _Scope | None = scope
        while current is not None:
            chain.append(current)
            current = current.parent
        parent: _Scope | None = None
        module: _Scope | None = None
        for original in reversed(chain):
            parent = _Scope(
                parent=parent,
                kind=original.kind,
                bindings=dict(original.bindings),
                local_names=original.local_names,
                global_names=original.global_names,
                nonlocal_names=original.nonlocal_names,
            )
            if original.kind == "module":
                module = parent
        if parent is None or module is None:
            raise RuntimeError("invalid scanner scope")
        return parent, module

    def _active_scopes(self) -> tuple[_Scope, ...]:
        scopes: list[_Scope] = []
        current: _Scope | None = self._scope
        while current is not None:
            scopes.append(current)
            current = current.parent
        return tuple(scopes)

    @staticmethod
    def _snapshot(scopes: Sequence[_Scope]) -> tuple[dict[str, str | None], ...]:
        return tuple(dict(scope.bindings) for scope in scopes)

    @staticmethod
    def _restore(scopes: Sequence[_Scope], state: Sequence[dict[str, str | None]]) -> None:
        for scope, bindings in zip(scopes, state, strict=True):
            scope.bindings = dict(bindings)

    @staticmethod
    def _merge(scopes: Sequence[_Scope], states: Sequence[Sequence[dict[str, str | None]]]) -> None:
        missing = object()
        for index, scope in enumerate(scopes):
            merged: dict[str, str | None] = {}
            keys = set().union(*(state[index] for state in states))
            for name in keys:
                values = [state[index].get(name, missing) for state in states]
                if all(value == values[0] for value in values):
                    if values[0] is not missing:
                        merged[name] = cast("str | None", values[0])
                else:
                    merged[name] = None
            scope.bindings = merged

    def _visit_branch(
        self,
        statements: Sequence[ast.stmt],
        scopes: Sequence[_Scope],
        initial: Sequence[dict[str, str | None]],
    ) -> tuple[dict[str, str | None], ...]:
        self._restore(scopes, initial)
        for statement in statements:
            self.visit(statement)
        return self._snapshot(scopes)

    @staticmethod
    def _irrefutable_pattern(pattern: ast.pattern) -> bool:
        if isinstance(pattern, ast.MatchAs):
            return pattern.pattern is None or _CallVisitor._irrefutable_pattern(pattern.pattern)
        if isinstance(pattern, ast.MatchOr):
            return any(_CallVisitor._irrefutable_pattern(option) for option in pattern.patterns)
        return False

    @staticmethod
    def _definitely_terminates(statements: Sequence[ast.stmt]) -> bool:
        for statement in statements:
            if isinstance(statement, (ast.Return, ast.Raise)):
                return True
            if isinstance(statement, ast.If) and statement.orelse:
                if _CallVisitor._definitely_terminates(
                    statement.body
                ) and _CallVisitor._definitely_terminates(statement.orelse):
                    return True
        return False

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
        for expression in (*node.args, *(keyword.value for keyword in node.keywords)):
            if isinstance(expression, ast.GeneratorExp):
                self._bind_consumed_iterable_walrus(expression)

    def _bind_consumed_iterable_walrus(self, node: ast.expr) -> None:
        collector = _ComprehensionWalrusBindings(eager_only=True)
        collector.consume_iterable(node)
        for name in collector.names:
            self._bind(name)

    def visit_Starred(self, node: ast.Starred) -> None:
        self.visit(node.value)
        if isinstance(node.ctx, ast.Load):
            self._bind_consumed_iterable_walrus(node.value)

    def visit_For(self, node: ast.For) -> None:
        self._visit_for(node)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self._visit_for(node)

    def _visit_for(self, node: ast.For | ast.AsyncFor) -> None:
        self.visit(node.iter)
        self._bind_consumed_iterable_walrus(node.iter)
        self.visit(node.target)
        for statement in (*node.body, *node.orelse):
            self.visit(statement)

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

    def visit_MatchAs(self, node: ast.MatchAs) -> None:
        if node.pattern is not None:
            self.visit(node.pattern)
        if node.name is not None:
            self._bind(node.name)

    def visit_MatchStar(self, node: ast.MatchStar) -> None:
        if node.name is not None:
            self._bind(node.name)

    def visit_MatchMapping(self, node: ast.MatchMapping) -> None:
        self.generic_visit(node)
        if node.rest is not None:
            self._bind(node.rest)

    def visit_Match(self, node: ast.Match) -> None:
        self.visit(node.subject)
        scopes = self._active_scopes()
        initial = self._snapshot(scopes)
        exhaustive = bool(
            node.cases
            and node.cases[-1].guard is None
            and self._irrefutable_pattern(node.cases[-1].pattern)
        )
        states = [] if exhaustive else [initial]
        for case in node.cases:
            self._restore(scopes, initial)
            self.visit(case.pattern)
            if case.guard is not None:
                self.visit(case.guard)
            for statement in case.body:
                self.visit(statement)
            states.append(self._snapshot(scopes))
        self._merge(scopes, states)

    def visit_If(self, node: ast.If) -> None:
        self.visit(node.test)
        scopes = self._active_scopes()
        initial = self._snapshot(scopes)
        body_state = self._visit_branch(node.body, scopes, initial)
        else_state = self._visit_branch(node.orelse, scopes, initial)
        reachable = []
        if not self._definitely_terminates(node.body):
            reachable.append(body_state)
        if not self._definitely_terminates(node.orelse):
            reachable.append(else_state)
        self._merge(scopes, reachable or (initial,))

    def visit_Try(self, node: ast.Try) -> None:
        self._visit_try(node)

    def visit_TryStar(self, node: ast.TryStar) -> None:
        self._visit_try(node)

    def _visit_try(self, node: ast.Try | ast.TryStar) -> None:
        scopes = self._active_scopes()
        initial = self._snapshot(scopes)
        body_bindings = _LocalBindings(eager_only=True)
        for statement in node.body:
            body_bindings.visit(statement)
            self.visit(statement)
        for statement in node.orelse:
            self.visit(statement)
        states = [self._snapshot(scopes)]
        for handler in node.handlers:
            self._restore(scopes, initial)
            for name in body_bindings.names:
                self._bind(name)
            self.visit(handler)
            states.append(self._snapshot(scopes))
        self._merge(scopes, states)
        for statement in node.finalbody:
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
        if isinstance(node.target, ast.Name) and self._scope.kind == "comprehension":
            current = self._scope
            while current.kind == "comprehension" and current.parent is not None:
                current = current.parent
            inner = self._scope
            self._scope = current
            try:
                self._bind(node.target.id)
            finally:
                self._scope = inner
        else:
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
        module = self._module
        isolated_parent, self._module = self._fork_scope(parent)
        self._scope = _function_scope(body, args, isolated_parent)
        try:
            for statement in body:
                self.visit(statement)
        finally:
            self._scope = parent
            self._module = module

    def visit_Lambda(self, node: ast.Lambda) -> None:
        for expression in (*node.args.defaults, *node.args.kw_defaults):
            if expression is not None:
                self.visit(expression)
        parent = self._scope
        module = self._module
        isolated_parent, self._module = self._fork_scope(parent)
        collector = _LocalBindings()
        collector.visit(node.body)
        self._scope = _Scope(
            parent=isolated_parent,
            kind="function",
            local_names=frozenset(collector.names | _parameter_names(node.args)),
        )
        try:
            self.visit(node.body)
        finally:
            self._scope = parent
            self._module = module

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
        self,
        generators: Sequence[ast.comprehension],
        values: Sequence[ast.expr],
        *,
        lazy: bool = False,
    ) -> None:
        if not generators:
            return
        self.visit(generators[0].iter)
        collector = _LocalBindings()
        for generator in generators:
            collector.visit(generator.target)
        parent = self._scope
        module = self._module
        enclosing = parent
        if lazy:
            enclosing, self._module = self._fork_scope(parent)
        self._scope = _Scope(
            parent=enclosing,
            kind="comprehension",
            local_names=frozenset(collector.names),
        )
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
            self._module = module

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self._visit_comprehension(node.generators, (node.elt,))
        self._bind_eager_comprehension_walrus(node)

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self._visit_comprehension(node.generators, (node.elt,))
        self._bind_eager_comprehension_walrus(node)

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        self._visit_comprehension(node.generators, (node.elt,), lazy=True)

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self._visit_comprehension(node.generators, (node.key, node.value))
        self._bind_eager_comprehension_walrus(node)

    def _bind_eager_comprehension_walrus(
        self, node: ast.ListComp | ast.SetComp | ast.DictComp
    ) -> None:
        collector = _ComprehensionWalrusBindings(eager_only=True)
        collector.visit(node)
        for name in collector.names:
            self._bind(name)


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
