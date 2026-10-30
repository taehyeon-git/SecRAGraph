"""Verify the pinned vendor rules and conservative adapter normalization."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_ROOT = Path(__file__).resolve().parents[3]
_BINARY = os.environ.get("SECRAGRAPH_OPENGREP_BINARY", "opengrep")


class OpengrepRuleQualityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        executable = shutil.which(_BINARY)
        if executable is None:
            raise unittest.SkipTest("Opengrep binary is unavailable")
        version = subprocess.run(  # noqa: S603  # nosec B603
            [executable, "--version"], capture_output=True, text=True, check=False
        )
        if version.returncode != 0 or version.stdout.strip() != "1.32.0":
            raise unittest.SkipTest("pinned Opengrep 1.32.0 is unavailable")
        cls.executable = executable

    def _findings(self, rule: Path, files: dict[str, str]) -> dict[str, list[int]]:
        with tempfile.TemporaryDirectory(prefix="secragraph-rule-quality-") as directory:
            target = Path(directory)
            for name, source in files.items():
                (target / name).write_text(source, encoding="utf-8")
            report = target / "report.json"
            completed = subprocess.run(  # noqa: S603  # nosec B603
                [
                    self.executable,
                    "scan",
                    "--config",
                    str(rule),
                    "--json-output",
                    str(report),
                    "--quiet",
                    "--disable-version-check",
                    "--no-git-ignore",
                    "--disable-nosem",
                    "--jobs",
                    "1",
                    ".",
                ],
                cwd=target,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            payload = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(payload["errors"], [])
            return {
                name: sorted(
                    item["start"]["line"]
                    for item in payload["results"]
                    if Path(item["path"]).name == name
                )
                for name in files
            }

    def test_adapter_suppresses_only_proven_numeric_shell_arguments(self) -> None:
        from security_review.scanner.opengrep_adapter import _normalize_report

        files = {
            "numeric.py": (
                "import subprocess\n"
                "def run(request):\n"
                "    value = int(request.query_params.get('id'))\n"
                "    subprocess.run(f'echo {value}', shell=True)\n"
            ),
            "two_numeric.py": (
                "import subprocess\n"
                "def run(request):\n"
                "    x = int(request.args['first'])\n"
                "    y = int(request.args['second'])\n"
                "    subprocess.run(f'echo {x} {y}', shell=True)\n"
            ),
            "positive.py": (
                "import subprocess\ncommand = input()\nsubprocess.run(command, shell=True)\n"
            ),
            "subscription.py": (
                "import subprocess\n"
                "def run(request):\n"
                "    command = request.args['cmd']\n"
                "    subprocess.run(command, shell=True)\n"
            ),
            "shadowed.py": (
                "import subprocess\n"
                "def int(value):\n"
                "    return value\n"
                "def run(request):\n"
                "    command = int(request.query_params.get('cmd'))\n"
                "    subprocess.run(f'echo {command}', shell=True)\n"
            ),
            "conditional.py": (
                "import subprocess\n"
                "def run(request):\n"
                "    value = request.args['cmd']\n"
                "    if False:\n"
                "        value = int(request.args['id'])\n"
                "    subprocess.run(f'echo {value}', shell=True)\n"
            ),
            "tuple.py": (
                "import subprocess\n"
                "def run(request):\n"
                "    value = int(request.args['id'])\n"
                "    value, other = input(), None\n"
                "    subprocess.run(f'echo {value}', shell=True)\n"
            ),
            "unknown.py": (
                "import subprocess\ndef run():\n    subprocess.run(f'echo {value}', shell=True)\n"
            ),
            "producer.py": "def command(request):\n    return request.args['cmd']\n",
            "consumer.py": (
                "import subprocess\n"
                "from producer import command\n"
                "def run(request):\n"
                "    subprocess.run(f'echo {command(request)}', shell=True)\n"
            ),
        }
        reported_lines = {
            "numeric.py": 4,
            "two_numeric.py": 5,
            "positive.py": 3,
            "subscription.py": 4,
            "shadowed.py": 6,
            "conditional.py": 6,
            "tuple.py": 5,
            "unknown.py": 3,
            "consumer.py": 4,
        }
        with tempfile.TemporaryDirectory(prefix="og-") as directory:
            target = Path(directory)
            for name, source in files.items():
                (target / name).write_text(source, encoding="utf-8")
            payload = {
                "results": [
                    {
                        "check_id": "python.exec.python_exec_rule-subprocess-popen-shell-true",
                        "path": name,
                        "start": {"line": line},
                        "end": {"line": line},
                        "extra": {"severity": "ERROR", "metadata": {"cwe": "CWE-78"}},
                    }
                    for name, line in reported_lines.items()
                ],
                "errors": [],
                "paths": {"scanned": sorted(files), "skipped": []},
            }
            normalized, inspected, partial = _normalize_report(
                payload, target, tuple(sorted(files))
            )
        self.assertFalse(partial)
        self.assertEqual(set(inspected), set(files))
        findings = {
            name: sorted(item.line_start for item in normalized if item.file_path == name)
            for name in files
        }
        self.assertEqual(
            findings,
            {
                "numeric.py": [],
                "two_numeric.py": [],
                "positive.py": [3],
                "subscription.py": [4],
                "shadowed.py": [6],
                "conditional.py": [6],
                "tuple.py": [5],
                "unknown.py": [3],
                "producer.py": [],
                "consumer.py": [4],
            },
        )

    def test_vendor_shell_rule_retains_numeric_and_untrusted_commands(self) -> None:
        findings = self._findings(
            _ROOT / "data/engines/opengrep/python/exec/rule-subprocess-popen-shell-true.yml",
            {
                "numeric.py": (
                    "import subprocess\n"
                    "def run(request):\n"
                    "    value = int(request.query_params.get('id'))\n"
                    "    subprocess.run(f'echo {value}', shell=True)\n"
                ),
                "command.py": (
                    "import subprocess\ncommand = input()\nsubprocess.run(command, shell=True)\n"
                ),
                "mixed.py": (
                    "import subprocess\n"
                    "def run(request):\n"
                    "    value = int(request.query_params.get('id'))\n"
                    "    command = request.query_params.get('cmd')\n"
                    "    subprocess.run(f'echo {value} {command}', shell=True)\n"
                ),
                "reassigned.py": (
                    "import subprocess\n"
                    "def run(request):\n"
                    "    value = int(request.query_params.get('id'))\n"
                    "    value = request.query_params.get('cmd')\n"
                    "    subprocess.run(f'echo {value}', shell=True)\n"
                ),
            },
        )
        self.assertEqual(
            findings,
            {"numeric.py": [4], "command.py": [3], "mixed.py": [5], "reassigned.py": [5]},
        )

    def test_input_fstring_sql_is_reported_but_parameterized_sql_is_clean(self) -> None:
        findings = self._findings(
            _ROOT / "data/engines/opengrep/python/sql/rule-hardcoded-sql-expression.yml",
            {
                "fstring.py": (
                    "name = input()\n"
                    "cursor.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n"
                ),
                "parameterized.py": (
                    "name = input()\n"
                    "cursor.execute('SELECT * FROM users WHERE name = ?', (name,))\n"
                ),
            },
        )
        self.assertEqual(findings, {"fstring.py": [2], "parameterized.py": []})

    def test_vendor_shell_rule_keeps_conditional_tuple_and_two_numeric_findings(self) -> None:
        findings = self._findings(
            _ROOT / "data/engines/opengrep/python/exec/rule-subprocess-popen-shell-true.yml",
            {
                "branch.py": (
                    "import subprocess\n"
                    "def run(request, enabled):\n"
                    "    value = request.query_params.get('cmd')\n"
                    "    if enabled:\n"
                    "        value = int(request.query_params.get('id'))\n"
                    "    subprocess.run(f'echo {value}', shell=True)\n"
                ),
                "tuple.py": (
                    "import subprocess\n"
                    "def run(request):\n"
                    "    value = int(request.query_params.get('id'))\n"
                    "    value, other = request.query_params.get('cmd'), None\n"
                    "    subprocess.run(f'echo {value}', shell=True)\n"
                ),
                "two_numeric.py": (
                    "import subprocess\n"
                    "def run(request):\n"
                    "    x = int(request.query_params.get('first'))\n"
                    "    y = int(request.query_params.get('second'))\n"
                    "    subprocess.run(f'echo {x} {y}', shell=True)\n"
                ),
            },
        )
        self.assertEqual(findings, {"branch.py": [6], "tuple.py": [5], "two_numeric.py": [5]})

    def test_shadowed_int_does_not_sanitize_untrusted_shell_input(self) -> None:
        findings = self._findings(
            _ROOT / "data/engines/opengrep/python/exec/rule-subprocess-popen-shell-true.yml",
            {
                "shadowed.py": (
                    "import subprocess\n"
                    "def int(value):\n"
                    "    return value\n"
                    "def run(request):\n"
                    "    command = int(request.query_params.get('cmd'))\n"
                    "    subprocess.run(command, shell=True)\n"
                ),
            },
        )
        self.assertEqual(findings, {"shadowed.py": [6]})

    def test_vendor_shell_rule_keeps_flask_subscription_findings(self) -> None:
        sources = {
            "args.py": "request.args['cmd']",
            "form.py": "request.form['cmd']",
            "values.py": "request.values['cmd']",
            "headers.py": "request.headers['X-Command']",
            "numeric.py": "int(request.args['id'])",
        }
        files = {
            name: (
                "import subprocess\n"
                "def run(request):\n"
                f"    command = {expression}\n"
                "    subprocess.run(command, shell=True)\n"
            )
            for name, expression in sources.items()
        }
        expected = {name: [4] for name in sources}
        vendor = _ROOT / "data/engines/opengrep/python/exec/rule-subprocess-popen-shell-true.yml"
        self.assertEqual(self._findings(vendor, files), expected)

    def test_vendor_shell_rule_keeps_flask_collection_and_skips_literal(self) -> None:
        findings = self._findings(
            _ROOT / "data/engines/opengrep/python/exec/rule-subprocess-popen-shell-true.yml",
            {
                "form_keys.py": (
                    "import subprocess\n"
                    "def run(request):\n"
                    "    for name in request.form.keys():\n"
                    "        command = name\n"
                    "        break\n"
                    "    subprocess.run(f'echo {command}', shell=True)\n"
                ),
                "header_list.py": (
                    "import subprocess\n"
                    "def run(request):\n"
                    "    headers = request.headers.getlist('X-Command')\n"
                    "    command = headers[0]\n"
                    "    subprocess.run(f'echo {command}', shell=True)\n"
                ),
                "header_plus.py": (
                    "import subprocess\n"
                    "def run(request):\n"
                    "    headers = request.headers.getlist('X-Command')\n"
                    "    piece = 'help'\n"
                    "    piece += headers[0]\n"
                    "    subprocess.run(f'echo {piece}', shell=True)\n"
                ),
                "literal.py": (
                    "import subprocess\n"
                    "def run(request):\n"
                    "    names = request.form.keys()\n"
                    "    command = 'echo safe'\n"
                    "    subprocess.run(command, shell=True)\n"
                ),
            },
        )
        self.assertEqual(
            findings,
            {
                "form_keys.py": [6],
                "header_list.py": [5],
                "header_plus.py": [6],
                "literal.py": [],
            },
        )


class AdapterNumericGuardTests(unittest.TestCase):
    def _normalize(self, source: str, line: int, finding_count: int = 1) -> int:
        from security_review.scanner.opengrep_adapter import _normalize_report

        with tempfile.TemporaryDirectory(prefix="og-guard-") as directory:
            root = Path(directory)
            (root / "app.py").write_text(source, encoding="utf-8")
            payload = {
                "results": [
                    {
                        "check_id": "python.exec.python_exec_rule-subprocess-popen-shell-true",
                        "path": "app.py",
                        "start": {"line": line},
                        "end": {"line": line},
                        "extra": {"severity": "ERROR", "metadata": {"cwe": "CWE-78"}},
                    }
                    for _ in range(finding_count)
                ],
                "errors": [],
                "paths": {"scanned": ["app.py"], "skipped": []},
            }
            findings, inspected, partial = _normalize_report(payload, root, ("app.py",))
        self.assertEqual(inspected, ("app.py",))
        self.assertFalse(partial)
        return len(findings)

    def test_parser_resource_failures_keep_original_finding(self) -> None:
        source = (
            "import subprocess\nvalue = int(input())\nsubprocess.run(f'echo {value}', shell=True)\n"
        )
        for error in (RecursionError, MemoryError):
            with self.subTest(error=error.__name__):
                with patch("security_review.scanner.opengrep_adapter.ast.parse", side_effect=error):
                    self.assertEqual(self._normalize(source, 3), 1)

    def test_large_ast_keeps_original_finding(self) -> None:
        source = (
            "import subprocess\n"
            "def run():\n"
            + "    pass\n" * 10_000
            + "    value = int(input())\n"
            + "    subprocess.run(f'echo {value}', shell=True)\n"
        )
        self.assertEqual(self._normalize(source, 10_004), 1)

    def test_two_subprocess_calls_on_one_line_keep_both_findings(self) -> None:
        source = (
            "import subprocess\n"
            "value = int(input())\n"
            "subprocess.run(f'echo {value}', shell=True); "
            "subprocess.run(input(), shell=1)\n"
        )
        self.assertEqual(self._normalize(source, 3, finding_count=2), 2)
