"""Behavioral tests for the bounded, static Python cross-file flow engine."""

from pathlib import Path

from security_review.scanner.python_flow import PythonFlowAdapter


def scan(tmp_path: Path, files: dict[str, str], timeout: float = 5.0):
    for name, source in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
    return PythonFlowAdapter().scan_snapshot(tmp_path, timeout)


def test_static_import_relay_to_shell_has_cross_file_source_step_sink(tmp_path: Path) -> None:
    result = scan(
        tmp_path,
        {
            "app.py": (
                "from relay import command\nimport subprocess\n\n"
                "def route(request):\n"
                "    value = request.query_params.get('cmd')\n"
                "    subprocess.run(command(value), shell=True)\n"
            ),
            "relay.py": "def command(value):\n    return 'echo ' + value\n",
        },
    )

    assert [(f.engine, f.rule_id, f.file_path, f.line_start) for f in result.findings] == [
        ("python-flow", "PYFLOW/SHELL", "app.py", 6)
    ]
    assert [(t.file_path, t.line_start, t.role) for t in result.findings[0].trace] == [
        ("app.py", 5, "source"),
        ("relay.py", 1, "step"),
        ("relay.py", 2, "step"),
        ("app.py", 6, "sink"),
    ]
    assert result.execution.status == "completed"
    assert result.execution.inspected_files == ("app.py", "relay.py")
    assert result.execution.checks == ("python-cross-file-taint",)


def test_two_hop_import_relay_to_sql_query_text(tmp_path: Path) -> None:
    result = scan(
        tmp_path,
        {
            "app.py": (
                "from first import relay\n\n"
                "def route(request, cursor):\n"
                "    user = request.args.get('user')\n"
                "    cursor.execute(relay(user))\n"
            ),
            "first.py": "from second import query\n\ndef relay(value):\n    return query(value)\n",
            "second.py": "def query(value):\n    return f'SELECT * FROM users WHERE id={value}'\n",
        },
    )

    assert [(f.rule_id, f.file_path, f.line_start) for f in result.findings] == [
        ("PYFLOW/SQL", "app.py", 5)
    ]
    trace = [(t.file_path, t.line_start, t.role) for t in result.findings[0].trace]
    assert trace[0] == ("app.py", 4, "source")
    assert ("first.py", 4, "step") in trace
    assert ("second.py", 2, "step") in trace
    assert trace[-1] == ("app.py", 5, "sink")


def test_safe_paths_and_unused_import_do_not_report(tmp_path: Path) -> None:
    result = scan(
        tmp_path,
        {
            "app.py": (
                "from relay import command\nimport subprocess\n\n"
                "def safe(request, cursor):\n"
                "    raw = request.query_params.get('id')\n"
                "    cursor.execute('SELECT * FROM users WHERE id=?', (raw,))\n"
                "    subprocess.run(f'echo {int(raw)}', shell=True)\n"
                "    subprocess.run(['echo', raw], shell=False)\n"
                "    return command('constant')\n"
            ),
            "relay.py": "def command(value):\n    return 'echo ' + value\n",
        },
    )

    assert result.findings == ()
    assert result.execution.status == "completed"


def test_input_through_imported_helper_to_os_system(tmp_path: Path) -> None:
    result = scan(
        tmp_path,
        {
            "app.py": "from worker import run\nrun(input())\n",
            "worker.py": "import os\n\ndef run(value):\n    os.system(value)\n",
        },
    )

    assert [(f.rule_id, f.file_path, f.line_start) for f in result.findings] == [
        ("PYFLOW/SHELL", "worker.py", 4)
    ]
    assert [(t.file_path, t.line_start, t.role) for t in result.findings[0].trace] == [
        ("app.py", 2, "source"),
        ("worker.py", 3, "step"),
        ("worker.py", 4, "sink"),
    ]


def test_dynamic_import_and_parse_failure_are_partial_without_source_disclosure(
    tmp_path: Path,
) -> None:
    secret = "super-secret-customer-token"
    result = scan(
        tmp_path,
        {
            "dynamic.py": "module = __import__('worker')\n",
            "broken.py": f"token = '{secret}'\ndef broken(:\n",
        },
    )

    assert result.findings == ()
    assert result.execution.status == "partial"
    assert set(result.execution.warnings) == {"dynamic_import_unresolved", "python_parse_failed"}
    assert result.execution.inspected_files == ("dynamic.py",)
    assert secret not in repr(result)


def test_ambiguous_local_resolution_is_partial_and_does_not_invent_flow(
    tmp_path: Path,
) -> None:
    result = scan(
        tmp_path,
        {
            "app.py": "from helper import run\nrun(input())\n",
            "helper.py": "import os\ndef run(value):\n    os.system(value)\n",
            "helper/__init__.py": "def run(value):\n    return value\n",
        },
    )

    assert result.findings == ()
    assert result.execution.status == "partial"
    assert "ambiguous_local_import" in result.execution.warnings


def test_zero_timeout_reports_unscanned_coverage(tmp_path: Path) -> None:
    result = scan(tmp_path, {"app.py": "x = input()\n"}, timeout=0.0)

    assert result.findings == ()
    assert result.execution.status == "not_run"
    assert result.execution.eligible_files == ("app.py",)
    assert result.execution.inspected_files == ()
    assert result.execution.warnings == ("scanner_timeout",)


def test_shadowed_builtin_and_subprocess_name_are_not_sources_or_sinks(tmp_path: Path) -> None:
    result = scan(
        tmp_path,
        {
            "app.py": (
                "def input():\n    return 'fixed'\n\n"
                "class Fake:\n"
                "    def run(self, value, shell):\n"
                "        return value\n\n"
                "subprocess = Fake()\n"
                "subprocess.run(input(), shell=True)\n"
            )
        },
    )

    assert result.findings == ()


def test_package_relative_module_import_resolves_relay(tmp_path: Path) -> None:
    result = scan(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/app.py": "from . import relay\nimport os\nos.system(relay.command(input()))\n",
            "pkg/relay.py": "def command(value):\n    return 'echo ' + value\n",
        },
    )

    assert [
        (finding.rule_id, finding.file_path, finding.line_start) for finding in result.findings
    ] == [("PYFLOW/SHELL", "pkg/app.py", 3)]
    assert result.execution.status == "completed"


def test_dotted_local_module_import_resolves_relay(tmp_path: Path) -> None:
    result = scan(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/relay.py": "def command(value):\n    return value\n",
            "app.py": "import pkg.relay\nimport os\nos.system(pkg.relay.command(input()))\n",
        },
    )

    assert [
        (finding.rule_id, finding.file_path, finding.line_start) for finding in result.findings
    ] == [("PYFLOW/SHELL", "app.py", 3)]


def test_same_file_source_to_sink_stays_with_opengrep(tmp_path: Path) -> None:
    result = scan(
        tmp_path,
        {
            "app.py": (
                "import os\n"
                "import subprocess\n"
                "value = input()\n"
                "os.system(value)\n"
                "subprocess.run(value, shell=True)\n"
                "cursor.execute(f'SELECT {value}')\n"
            )
        },
    )

    assert result.findings == ()
    assert result.execution.status == "completed"


def test_keyword_only_relay_argument_reaches_other_file_sink(tmp_path: Path) -> None:
    result = scan(
        tmp_path,
        {
            "app.py": "from worker import run\nrun(value=input())\n",
            "worker.py": "import os\ndef run(*, value):\n    os.system(value)\n",
        },
    )

    assert [
        (finding.rule_id, finding.file_path, finding.line_start) for finding in result.findings
    ] == [("PYFLOW/SHELL", "worker.py", 3)]


def test_cross_file_source_is_not_hidden_by_same_file_source(tmp_path: Path) -> None:
    result = scan(
        tmp_path,
        {
            "app.py": "from helper import get\nimport os\nos.system(input() + get())\n",
            "helper.py": "def get():\n    return input()\n",
        },
    )

    assert [
        (finding.rule_id, finding.file_path, finding.line_start) for finding in result.findings
    ] == [("PYFLOW/SHELL", "app.py", 3)]
    assert result.findings[0].trace[0].file_path == "helper.py"


def test_local_os_module_is_not_stdlib_shell_sink(tmp_path: Path) -> None:
    result = scan(
        tmp_path,
        {
            "app.py": "import os\nfrom helper import command\nos.system(command(input()))\n",
            "helper.py": "def command(value):\n    return value\n",
            "os.py": "def system(value):\n    return None\n",
        },
    )

    assert result.findings == ()
    assert result.execution.status == "completed"


def test_return_stops_before_unreachable_other_file_sink(tmp_path: Path) -> None:
    result = scan(
        tmp_path,
        {
            "app.py": "from worker import run\nrun(input())\n",
            "worker.py": "import os\ndef run(value):\n    return None\n    os.system(value)\n",
        },
    )

    assert result.findings == ()
    assert result.execution.status == "completed"


def test_excessive_attribute_chain_is_partial_instead_of_crashing(tmp_path: Path) -> None:
    result = scan(tmp_path, {"app.py": "root" + ".attr" * 1500 + "()\n"})

    assert result.findings == ()
    assert result.execution.status == "partial"
    assert "attribute_chain_unresolved" in result.execution.warnings


def test_function_local_os_shadow_is_not_stdlib_sink(tmp_path: Path) -> None:
    result = scan(
        tmp_path,
        {
            "app.py": (
                "import os\nfrom helper import get\n"
                "class Fake:\n"
                "    def system(self, value):\n        return None\n"
                "def route():\n"
                "    os = Fake()\n"
                "    os.system(get())\n"
            ),
            "helper.py": "def get():\n    return input()\n",
        },
    )

    assert result.findings == ()
    assert result.execution.status == "partial"
    assert "unresolved_tainted_call" in result.execution.warnings


def test_deep_binary_expression_is_partial_instead_of_crashing(tmp_path: Path) -> None:
    result = scan(
        tmp_path,
        {"app.py": "import os\nos.system(" + " + ".join(["'x'"] * 1500) + ")\n"},
    )

    assert result.findings == ()
    assert result.execution.status == "partial"
    assert "expression_depth_exceeded" in result.execution.warnings


def test_local_function_rebind_does_not_call_stale_import(tmp_path: Path) -> None:
    result = scan(
        tmp_path,
        {
            "app.py": (
                "from worker import run\n"
                "def safe(value):\n    return None\n"
                "def route():\n"
                "    run = safe\n"
                "    run(input())\n"
            ),
            "worker.py": "import os\ndef run(value):\n    os.system(value)\n",
        },
    )

    assert result.findings == ()
    assert result.execution.status == "partial"
    assert "unresolved_tainted_call" in result.execution.warnings


def test_imported_int_function_is_not_builtin_sanitizer(tmp_path: Path) -> None:
    result = scan(
        tmp_path,
        {
            "app.py": "from worker import int\nimport os\nos.system(int(input()))\n",
            "worker.py": "def int(value):\n    return value\n",
        },
    )

    assert [
        (finding.rule_id, finding.file_path, finding.line_start) for finding in result.findings
    ] == [("PYFLOW/SHELL", "app.py", 3)]


def test_builtin_str_preserves_taint_across_files(tmp_path: Path) -> None:
    result = scan(
        tmp_path,
        {
            "app.py": (
                "from worker import run\n"
                "def route(request):\n"
                "    run(str(request.args.get('cmd')))\n"
            ),
            "worker.py": "import os\ndef run(value):\n    os.system(value)\n",
        },
    )

    assert [(item.rule_id, item.file_path) for item in result.findings] == [
        ("PYFLOW/SHELL", "worker.py")
    ]
    assert result.execution.status == "completed"


def test_unknown_external_int_is_not_trusted_sanitizer(tmp_path: Path) -> None:
    result = scan(
        tmp_path,
        {
            "app.py": (
                "from external_pkg import int\n"
                "from worker import run\n"
                "def route(request):\n"
                "    run(int(request.args.get('cmd')))\n"
            ),
            "worker.py": "import os\ndef run(value):\n    os.system(value)\n",
        },
    )

    assert result.execution.status == "partial"
    assert "unresolved_tainted_call" in result.execution.warnings


def test_function_local_import_relay_is_traced_across_files(tmp_path: Path) -> None:
    result = scan(
        tmp_path,
        {
            "app.py": (
                "def route(request):\n"
                "    from worker import run\n"
                "    run(request.args.get('cmd'))\n"
            ),
            "worker.py": "import os\ndef run(value):\n    os.system(value)\n",
        },
    )

    assert [(item.rule_id, item.file_path) for item in result.findings] == [
        ("PYFLOW/SHELL", "worker.py")
    ]
    assert result.execution.status == "completed"


def test_rebound_import_does_not_follow_stale_local_helper(tmp_path: Path) -> None:
    result = scan(
        tmp_path,
        {
            "app.py": ("from worker import run\nfrom extlib import run\nrun(input())\n"),
            "worker.py": "import os\ndef run(value):\n    os.system(value)\n",
        },
    )

    assert result.findings == ()
    assert result.execution.status == "partial"
    assert "import_rebinding_unresolved" in result.execution.warnings


def test_rebound_os_alias_does_not_emit_stale_stdlib_sink(tmp_path: Path) -> None:
    result = scan(
        tmp_path,
        {
            "app.py": ("from worker import get\nimport os\nimport fake as os\nos.system(get())\n"),
            "worker.py": "def get():\n    return input()\n",
        },
    )

    assert result.findings == ()
    assert result.execution.status == "partial"
    assert "import_rebinding_unresolved" in result.execution.warnings


def test_import_after_function_definition_blocks_stale_local_function(tmp_path: Path) -> None:
    result = scan(
        tmp_path,
        {
            "app.py": (
                "from worker import dispatch\n"
                "def run(value):\n    dispatch(value)\n"
                "from extlib import run\n"
                "run(input())\n"
            ),
            "worker.py": "import os\ndef dispatch(value):\n    os.system(value)\n",
        },
    )

    assert result.findings == ()
    assert result.execution.status == "partial"
    assert "import_rebinding_unresolved" in result.execution.warnings


def test_expression_budget_carries_across_nested_function_calls(tmp_path: Path) -> None:
    functions = []
    for index in range(16):
        next_value = f"f{index + 1}(value)" if index < 15 else "value"
        functions.append(f"def f{index}(value):\n    return " + next_value + " + 'x'" * 119)
    result = scan(
        tmp_path,
        {
            "app.py": "from worker import f0\nimport os\nos.system(f0(input()))\n",
            "worker.py": "\n".join(functions) + "\n",
        },
    )

    assert result.execution.status == "partial"
    assert "expression_depth_exceeded" in result.execution.warnings
