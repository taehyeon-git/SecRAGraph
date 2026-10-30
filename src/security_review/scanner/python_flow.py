"""Bounded AST-only Python flow analysis over a verified source snapshot.

This engine intentionally resolves only explicit local imports and simple calls. It
never imports or executes submitted Python, and reports uncertain coverage as partial.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field, replace
from hashlib import sha256
from pathlib import Path
from time import monotonic

from security_review.domain.models import Confidence, Finding, Severity, TraceLocation
from security_review.scanner.external_common import (
    ExternalExecution,
    ExternalScanResult,
    ExternalStatus,
)
from security_review.scanner.opengrep_adapter import _eligible_paths

_ENGINE = "python-flow"
_CHECK = "python-cross-file-taint"
_MAX_FINDINGS = 2_000
_MAX_CALL_DEPTH = 16
_MAX_TRACE = 64
_MAX_FLOW_CANDIDATES = 64
_MAX_ATTRIBUTE_PARTS = 64
_MAX_EXPRESSION_DEPTH = 128
_MAX_EVALUATED_NODES = 100_000
_WEB_FIELDS = frozenset(
    {"args", "form", "values", "headers", "query_params", "GET", "POST", "json", "data", "body"}
)


class _Timeout(Exception):
    pass


@dataclass(frozen=True, slots=True)
class _Flow:
    locations: tuple[TraceLocation, ...]
    alternatives: tuple[tuple[TraceLocation, ...], ...] = ()

    def step(self, path: str, line: int) -> _Flow:
        location = TraceLocation(file_path=path, line_start=line, role="step")

        def extend(trace: tuple[TraceLocation, ...]) -> tuple[TraceLocation, ...]:
            return (*trace, location) if len(trace) < _MAX_TRACE - 1 else trace

        return _Flow(extend(self.locations), tuple(extend(trace) for trace in self.alternatives))


@dataclass(slots=True)
class _Module:
    path: str
    name: str
    tree: ast.Module
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef]
    module_imports: dict[str, str] = field(default_factory=dict)
    function_imports: dict[str, tuple[str, str]] = field(default_factory=dict)
    stdlib_imports: dict[str, str] = field(default_factory=dict)
    request_names: set[str] = field(default_factory=set)
    shadowed: set[str] = field(default_factory=set)
    blocked_bindings: set[str] = field(default_factory=set)


def _module_name(path: str) -> str:
    parts = Path(path).with_suffix("").parts
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _attribute_name(node: ast.expr, warnings: set[str] | None = None) -> str | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        if len(parts) >= _MAX_ATTRIBUTE_PARTS:
            if warnings is not None:
                warnings.add("attribute_chain_unresolved")
            return None
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    return ".".join((node.id, *reversed(parts)))


def _source_call(node: ast.Call, request_names: set[str], shadowed: set[str]) -> bool:
    if isinstance(node.func, ast.Name) and node.func.id == "input" and "input" not in shadowed:
        return True
    name = _attribute_name(node.func)
    if name is None:
        return False
    parts = name.split(".")
    return (
        len(parts) == 3
        and parts[0] in request_names
        and parts[1] in _WEB_FIELDS
        and parts[2] == "get"
    )


def _source_attribute(node: ast.Attribute, request_names: set[str]) -> bool:
    name = _attribute_name(node)
    if name is None:
        return False
    parts = name.split(".")
    return len(parts) == 2 and parts[0] in request_names and parts[1] in _WEB_FIELDS


class _Analyzer:
    def __init__(self, modules: dict[str, _Module], deadline: float) -> None:
        self.modules = modules
        self.names: dict[str, list[str]] = {}
        for path, module in modules.items():
            self.names.setdefault(module.name, []).append(path)
        self.deadline = deadline
        self.findings: list[Finding] = []
        self.warnings: set[str] = set()
        self.active: set[tuple[str, str]] = set()
        self.evaluated_nodes = 0

    def check_time(self) -> None:
        if monotonic() >= self.deadline:
            raise _Timeout

    def merge(self, *flows: _Flow | None) -> _Flow | None:
        paths: list[tuple[TraceLocation, ...]] = []
        for flow in flows:
            if flow is None:
                continue
            for path in (flow.locations, *flow.alternatives):
                if path in paths:
                    continue
                if len(paths) >= _MAX_FLOW_CANDIDATES:
                    self.warnings.add("flow_candidate_limit_exceeded")
                    return _Flow(paths[0], tuple(paths[1:]))
                paths.append(path)
        return _Flow(paths[0], tuple(paths[1:])) if paths else None

    def resolve(
        self, module: _Module, name: str
    ) -> tuple[_Module, ast.FunctionDef | ast.AsyncFunctionDef] | None:
        if name.split(".", 1)[0] in module.blocked_bindings:
            return None
        if name in module.functions:
            return module, module.functions[name]
        if name in module.function_imports:
            path, symbol = module.function_imports[name]
            target = self.modules.get(path)
            if target is not None and symbol in target.functions:
                return target, target.functions[symbol]
        if "." in name:
            alias, symbol = name.rsplit(".", 1)
            module_path = module.module_imports.get(alias)
            target = self.modules.get(module_path) if module_path else None
            if target is not None and symbol in target.functions:
                return target, target.functions[symbol]
        return None

    def finding(self, rule: str, module: _Module, node: ast.Call, flow: _Flow) -> None:
        for path in (flow.locations, *flow.alternatives):
            if len(self.findings) >= _MAX_FINDINGS:
                self.warnings.add("finding_limit_exceeded")
                return
            trace = (
                *path[: _MAX_TRACE - 1],
                TraceLocation(file_path=module.path, line_start=node.lineno, role="sink"),
            )
            if len({location.file_path for location in trace}) < 2:
                continue
            identifier = sha256(
                f"{rule}\0{module.path}\0{node.lineno}\0{trace[0].file_path}\0{trace[0].line_start}".encode()
            ).hexdigest()[:20]
            if any(item.id == f"{rule}:{identifier}" for item in self.findings):
                continue
            details = {
                "PYFLOW/SHELL": (
                    "Untrusted input reaches a shell command.",
                    "CWE-78",
                    "Avoid shell interpretation of untrusted input.",
                ),
                "PYFLOW/SQL": (
                    "Untrusted input reaches SQL query text.",
                    "CWE-89",
                    "Use a constant SQL query with bound parameters.",
                ),
                "PYFLOW/CODE": (
                    "Untrusted input reaches dynamic Python code execution.",
                    "CWE-94",
                    "Avoid evaluating untrusted input as Python code.",
                ),
            }
            message, cwe, remediation = details[rule]
            self.findings.append(
                Finding(
                    id=f"{rule}:{identifier}",
                    rule_id=rule,
                    category="sast",
                    severity=Severity.HIGH,
                    file_path=module.path,
                    line_start=node.lineno,
                    line_end=getattr(node, "end_lineno", node.lineno),
                    message=message,
                    redacted_evidence="[source omitted]",
                    confidence=Confidence.MEDIUM,
                    cwe_ids=(cwe,),
                    remediation=remediation,
                    engine=_ENGINE,
                    trace=trace,
                )
            )

    def eval(
        self,
        node: ast.expr,
        module: _Module,
        env: dict[str, _Flow | None],
        request_names: set[str],
        shadowed: set[str],
        depth: int,
        expression_depth: int = 0,
    ) -> _Flow | None:
        self.check_time()
        self.evaluated_nodes += 1
        if self.evaluated_nodes > _MAX_EVALUATED_NODES:
            self.warnings.add("expression_node_limit_exceeded")
            return None
        if expression_depth > _MAX_EXPRESSION_DEPTH:
            self.warnings.add("expression_depth_exceeded")
            return None
        if isinstance(node, ast.Name):
            return env.get(node.id)
        if isinstance(node, ast.Attribute):
            if _attribute_name(node, self.warnings) is None:
                return None
            if _source_attribute(node, request_names):
                return _Flow(
                    (TraceLocation(file_path=module.path, line_start=node.lineno, role="source"),)
                )
            return self.eval(
                node.value, module, env, request_names, shadowed, depth, expression_depth + 1
            )
        if isinstance(node, ast.Constant):
            return None
        if isinstance(node, ast.JoinedStr):
            return self.merge(
                *(
                    self.eval(
                        value, module, env, request_names, shadowed, depth, expression_depth + 1
                    )
                    for value in node.values
                    if isinstance(value, ast.expr)
                )
            )
        if isinstance(node, ast.FormattedValue):
            return self.eval(
                node.value, module, env, request_names, shadowed, depth, expression_depth + 1
            )
        if isinstance(node, ast.BinOp):
            return self.merge(
                self.eval(
                    node.left, module, env, request_names, shadowed, depth, expression_depth + 1
                ),
                self.eval(
                    node.right, module, env, request_names, shadowed, depth, expression_depth + 1
                ),
            )
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            return self.merge(
                *(
                    self.eval(
                        item, module, env, request_names, shadowed, depth, expression_depth + 1
                    )
                    for item in node.elts
                )
            )
        if isinstance(node, ast.Dict):
            return self.merge(
                *(
                    self.eval(
                        item, module, env, request_names, shadowed, depth, expression_depth + 1
                    )
                    for item in (*node.keys, *node.values)
                    if item is not None
                )
            )
        if isinstance(node, ast.Subscript):
            return self.eval(
                node.value, module, env, request_names, shadowed, depth, expression_depth + 1
            )
        if isinstance(node, ast.Call):
            name = _attribute_name(node.func, self.warnings)
            if _source_call(node, request_names, shadowed):
                return _Flow(
                    (TraceLocation(file_path=module.path, line_start=node.lineno, role="source"),)
                )
            if name == "int" and "int" not in shadowed and "int" not in module.function_imports:
                return None
            args = [
                self.eval(arg, module, env, request_names, shadowed, depth, expression_depth + 1)
                for arg in node.args
            ]
            kw = {
                item.arg: self.eval(
                    item.value, module, env, request_names, shadowed, depth, expression_depth + 1
                )
                for item in node.keywords
                if item.arg is not None
            }
            if (
                name in {"eval", "exec"}
                and name not in shadowed
                and name not in module.function_imports
            ):
                if args and args[0]:
                    self.finding("PYFLOW/CODE", module, node, args[0])
                return None
            if name == "str" and "str" not in shadowed and "str" not in module.function_imports:
                return self.merge(*args, *kw.values())
            if name and name.endswith(".format"):
                return self.merge(*args, *kw.values())
            known_sink = False
            if name is not None:
                parts = name.split(".")
                canonical = (
                    module.stdlib_imports.get(parts[0]) if parts[0] not in shadowed else None
                )
                operation = ".".join((canonical, *parts[1:])) if canonical else None
                if operation == "os.system" and args and args[0]:
                    self.finding("PYFLOW/SHELL", module, node, args[0])
                if operation == "os.system":
                    known_sink = True
                if (
                    operation
                    in {
                        "subprocess.run",
                        "subprocess.Popen",
                        "subprocess.call",
                        "subprocess.check_call",
                        "subprocess.check_output",
                    }
                    and args
                    and args[0]
                ):
                    known_sink = True
                    shell = next(
                        (item.value for item in node.keywords if item.arg == "shell"), None
                    )
                    if isinstance(shell, ast.Constant) and shell.value is True:
                        self.finding("PYFLOW/SHELL", module, node, args[0])
                    elif shell is not None and not (
                        isinstance(shell, ast.Constant) and shell.value is False
                    ):
                        self.warnings.add("dynamic_shell_flag_unresolved")
                if name.endswith((".execute", ".executemany")) and args and args[0]:
                    self.finding("PYFLOW/SQL", module, node, args[0])
                if name.endswith((".execute", ".executemany")):
                    known_sink = True
                resolved = self.resolve(module, name) if parts[0] not in env else None
                if resolved is not None:
                    target, function = resolved
                    if target.path != module.path:
                        args = [
                            flow.step(target.path, function.lineno) if flow else None
                            for flow in args
                        ]
                        kw = {
                            key: flow.step(target.path, function.lineno) if flow else None
                            for key, flow in kw.items()
                        }
                    return self.call(target, function, args, kw, depth + 1)
            if not known_sink and self.merge(*args, *kw.values()) is not None:
                self.warnings.add("unresolved_tainted_call")
            return None
        if isinstance(node, ast.IfExp):
            return self.merge(
                self.eval(
                    node.body, module, env, request_names, shadowed, depth, expression_depth + 1
                ),
                self.eval(
                    node.orelse, module, env, request_names, shadowed, depth, expression_depth + 1
                ),
            )
        if isinstance(node, ast.UnaryOp):
            return self.eval(
                node.operand, module, env, request_names, shadowed, depth, expression_depth + 1
            )
        self.warnings.add("unsupported_python_flow")
        return None

    def call(
        self,
        module: _Module,
        function: ast.FunctionDef | ast.AsyncFunctionDef,
        args: list[_Flow | None],
        kw: dict[str, _Flow | None],
        depth: int,
    ) -> _Flow | None:
        self.check_time()
        key = (module.path, function.name)
        if depth > _MAX_CALL_DEPTH or key in self.active:
            self.warnings.add("recursive_call_unresolved")
            return None
        module = replace(
            module,
            tree=ast.Module(body=function.body, type_ignores=[]),
            module_imports=module.module_imports.copy(),
            function_imports=module.function_imports.copy(),
            stdlib_imports=module.stdlib_imports.copy(),
            request_names=module.request_names.copy(),
            shadowed=module.shadowed.copy(),
            blocked_bindings=module.blocked_bindings.copy(),
        )
        _imports(module, self.names, self.modules, self.warnings)
        parameters = [*function.args.posonlyargs, *function.args.args]
        env = {
            param.arg: (
                kw.get(param.arg) if param.arg in kw else args[index] if index < len(args) else None
            )
            for index, param in enumerate(parameters)
        }
        env.update({param.arg: kw.get(param.arg) for param in function.args.kwonlyargs})
        request_names = set(module.request_names)
        if "request" in env:
            request_names.add("request")
        shadowed = set(module.shadowed) | set(env)
        self.active.add(key)
        try:
            return self.statements(function.body, module, env, request_names, shadowed, depth)
        finally:
            self.active.remove(key)

    def statements(
        self,
        statements: list[ast.stmt],
        module: _Module,
        env: dict[str, _Flow | None],
        request_names: set[str],
        shadowed: set[str],
        depth: int,
    ) -> _Flow | None:
        returned: _Flow | None = None
        for stmt in statements:
            self.check_time()
            if isinstance(stmt, ast.Assign):
                value = self.eval(stmt.value, module, env, request_names, shadowed, depth)
                for target in stmt.targets:
                    if isinstance(target, ast.Name):
                        env[target.id] = value
                        shadowed.add(target.id)
            elif isinstance(stmt, ast.AnnAssign):
                value = (
                    self.eval(stmt.value, module, env, request_names, shadowed, depth)
                    if stmt.value is not None
                    else None
                )
                if isinstance(stmt.target, ast.Name):
                    env[stmt.target.id] = value
                    shadowed.add(stmt.target.id)
            elif isinstance(stmt, ast.Expr):
                self.eval(stmt.value, module, env, request_names, shadowed, depth)
            elif isinstance(stmt, ast.Return):
                value = (
                    self.eval(stmt.value, module, env, request_names, shadowed, depth)
                    if stmt.value is not None
                    else None
                )
                if value is not None:
                    returned = value.step(module.path, stmt.lineno)
                return returned
            elif isinstance(stmt, ast.If):
                left = self.statements(
                    stmt.body, module, env.copy(), request_names.copy(), shadowed.copy(), depth
                )
                right = self.statements(
                    stmt.orelse, module, env.copy(), request_names.copy(), shadowed.copy(), depth
                )
                returned = self.merge(returned, left, right)
                self.warnings.add("branch_merge_unresolved")
            elif isinstance(
                stmt,
                (
                    ast.Import,
                    ast.ImportFrom,
                    ast.FunctionDef,
                    ast.AsyncFunctionDef,
                    ast.ClassDef,
                    ast.Pass,
                ),
            ):
                continue
            else:
                self.warnings.add("unsupported_python_flow")
        return returned


def _imports(
    module: _Module, names: dict[str, list[str]], modules: dict[str, _Module], warnings: set[str]
) -> None:
    seen: set[str] = set()

    def begin_binding(bound: str) -> bool:
        # Never use an earlier recognized import after Python rebinds its name.
        module.module_imports.pop(bound, None)
        module.function_imports.pop(bound, None)
        module.stdlib_imports.pop(bound, None)
        module.request_names.discard(bound)
        if bound in seen or bound in module.shadowed:
            warnings.add("import_rebinding_unresolved")
            module.shadowed.add(bound)
            module.blocked_bindings.add(bound)
            return False
        seen.add(bound)
        return True

    package = (
        module.name if module.path.endswith("/__init__.py") else module.name.rpartition(".")[0]
    )
    for stmt in module.tree.body:
        if isinstance(stmt, ast.Import):
            for alias in stmt.names:
                bound = alias.asname or alias.name.split(".")[0]
                if not begin_binding(bound):
                    continue
                if alias.name in {"os", "subprocess"} and alias.name not in names:
                    module.stdlib_imports[bound] = alias.name
                elif alias.name in names:
                    if len(names[alias.name]) == 1:
                        module.module_imports[alias.asname or alias.name] = names[alias.name][0]
                    else:
                        warnings.add("ambiguous_local_import")
                else:
                    module.shadowed.add(bound)
        elif isinstance(stmt, ast.ImportFrom):
            base = stmt.module or ""
            if stmt.level:
                parts = package.split(".") if package else []
                if stmt.level > len(parts) + 1:
                    warnings.add("local_import_unresolved")
                    continue
                base = (
                    ".".join((*parts[: len(parts) - stmt.level + 1], base))
                    if base
                    else ".".join(parts[: len(parts) - stmt.level + 1])
                )
            for alias in stmt.names:
                bound = alias.asname or alias.name
                if alias.name == "*":
                    warnings.add("star_import_unresolved")
                    continue
                if not begin_binding(bound):
                    continue
                if base == "flask" and alias.name == "request":
                    module.request_names.add(bound)
                elif base in {"os", "subprocess"} and base not in names:
                    module.stdlib_imports[bound] = f"{base}.{alias.name}"
                elif base in names:
                    if len(names[base]) == 1:
                        target = modules[names[base][0]]
                        if alias.name in target.functions:
                            module.function_imports[bound] = (target.path, alias.name)
                        elif f"{base}.{alias.name}" in names:
                            candidates = names[f"{base}.{alias.name}"]
                            if len(candidates) == 1:
                                module.module_imports[bound] = candidates[0]
                            else:
                                warnings.add("ambiguous_local_import")
                        else:
                            warnings.add("local_import_unresolved")
                            module.shadowed.add(bound)
                    else:
                        warnings.add("ambiguous_local_import")
                elif f"{base}.{alias.name}" in names:
                    candidates = names[f"{base}.{alias.name}"]
                    if len(candidates) == 1:
                        module.module_imports[bound] = candidates[0]
                    else:
                        warnings.add("ambiguous_local_import")
                elif stmt.level:
                    warnings.add("local_import_unresolved")
                    module.shadowed.add(bound)
                else:
                    module.shadowed.add(bound)


class PythonFlowAdapter:
    """Static local Python import and simple source-to-sink flow adapter."""

    def scan_snapshot(self, root: Path, timeout: float) -> ExternalScanResult:
        started = monotonic()
        eligible = tuple(path for path in _eligible_paths(root) if path.endswith(".py"))
        warnings: set[str] = set()
        inspected: list[str] = []
        findings: tuple[Finding, ...] = ()
        if timeout <= 0:
            warnings.add("scanner_timeout")
        elif eligible:
            deadline = started + timeout
            modules: dict[str, _Module] = {}
            names: dict[str, list[str]] = {}
            try:
                for path in eligible:
                    if monotonic() >= deadline:
                        raise _Timeout
                    try:
                        source = root.joinpath(*path.split("/")).read_text(encoding="utf-8")
                        tree = ast.parse(source, filename=path)
                    except (OSError, UnicodeError, SyntaxError, ValueError):
                        warnings.add("python_parse_failed")
                        continue
                    functions = {
                        stmt.name: stmt
                        for stmt in tree.body
                        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef))
                    }
                    shadowed = {
                        stmt.name
                        for stmt in tree.body
                        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                    }
                    shadowed.update(
                        target.id
                        for stmt in tree.body
                        if isinstance(stmt, ast.Assign)
                        for target in stmt.targets
                        if isinstance(target, ast.Name)
                    )
                    name = _module_name(path)
                    modules[path] = _Module(path, name, tree, functions, shadowed=shadowed)
                    names.setdefault(name, []).append(path)
                    inspected.append(path)
                    for node in ast.walk(tree):
                        if isinstance(node, ast.Call) and _attribute_name(node.func, warnings) in {
                            "__import__",
                            "importlib.import_module",
                        }:
                            warnings.add("dynamic_import_unresolved")
                for module in modules.values():
                    _imports(module, names, modules, warnings)
                analyzer = _Analyzer(modules, deadline)
                for module in modules.values():
                    analyzer.check_time()
                    analyzer.statements(
                        module.tree.body,
                        module,
                        {},
                        set(module.request_names),
                        set(module.shadowed),
                        0,
                    )
                    for function in module.functions.values():
                        analyzer.call(module, function, [], {}, 0)
                warnings.update(analyzer.warnings)
                findings = tuple(analyzer.findings)
            except _Timeout:
                warnings.add("scanner_timeout")
                if "analyzer" in locals():
                    warnings.update(analyzer.warnings)
                    findings = tuple(analyzer.findings)
            except RecursionError:
                warnings.add("expression_depth_exceeded")
                if "analyzer" in locals():
                    warnings.update(analyzer.warnings)
                    findings = tuple(analyzer.findings)
        status: ExternalStatus
        if not eligible:
            status = "skipped"
            warnings.add("no_eligible_files")
        elif warnings == {"scanner_timeout"} and not inspected:
            status = "not_run"
        else:
            status = "partial" if warnings else "completed"
        return ExternalScanResult(
            findings=findings,
            execution=ExternalExecution(
                scanner=_ENGINE,
                version="1",
                status=status,
                eligible_files=eligible,
                inspected_files=tuple(inspected),
                checks=(_CHECK,) if inspected else (),
                duration_ms=max(0, int((monotonic() - started) * 1000)),
                warnings=tuple(sorted(warnings)),
            ),
        )
