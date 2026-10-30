"""Real pinned Opengrep checks for Flask request-header SQL flows."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from security_review.scanner.opengrep_adapter import OpengrepAdapter

_REPO_ROOT = Path(__file__).resolve().parents[3]
_RULE_ID = "OG/python-web-sql-taint"


class FlaskHeaderTaintTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        executable = shutil.which("opengrep")
        if executable is None:
            raise unittest.SkipTest("pinned Opengrep binary is unavailable")
        version = subprocess.run(  # noqa: S603  # nosec B603
            [executable, "--version"], capture_output=True, text=True, check=False
        )
        if version.returncode != 0 or version.stdout.strip() != "1.32.0":
            raise unittest.SkipTest("pinned Opengrep 1.32.0 is unavailable")

    def _scan(self, source: str):
        with tempfile.TemporaryDirectory(prefix="secragraph-header-test-") as directory:
            root = Path(directory)
            (root / "app.py").write_text(source, encoding="utf-8")
            result = OpengrepAdapter(
                rules_root=_REPO_ROOT / "data" / "engines" / "opengrep",
                taint_rules_root=_REPO_ROOT / "data" / "engines" / "secragraph-taint",
            ).scan_snapshot(root, timeout=60)
            self.assertEqual(result.execution.version, "1.32.0")
            self.assertEqual(result.execution.status, "completed")
            self.assertEqual(result.execution.inspected_files, ("app.py",))
            return tuple(finding for finding in result.findings if finding.rule_id == _RULE_ID)

    def test_header_value_reaching_sql_query_is_reported(self) -> None:
        findings = self._scan(
            "from flask import request\n"
            "def view(cursor):\n"
            "    value = request.headers.get('X-User')\n"
            "    cursor.execute(f\"SELECT * FROM users WHERE name = '{value}'\")\n"
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].line_start, 4)
        self.assertEqual(findings[0].trace[0].role, "source")
        self.assertEqual(findings[0].trace[-1].role, "sink")

    def test_header_value_as_parameter_is_not_reported(self) -> None:
        findings = self._scan(
            "from flask import request\n"
            "def view(cursor):\n"
            "    value = request.headers.get('X-User')\n"
            "    cursor.execute('SELECT * FROM users WHERE name = ?', (value,))\n"
        )
        self.assertEqual(findings, ())
