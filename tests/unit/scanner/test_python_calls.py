"""Behavioral cases for non-executing Python call recognition."""

import pytest


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("eval(user_input)\n", [("PY001", 1)]),
        ("from builtins import eval as evaluate\nevaluate(user_input)\n", [("PY001", 2)]),
        ("import subprocess as sp\nsp.run(command, shell=True)\n", [("PY002", 2)]),
        ("from subprocess import call as launch\nlaunch(command, shell=True)\n", [("PY002", 2)]),
        ("import subprocess\nsubprocess.Popen(command, shell=True)\n", [("PY002", 2)]),
        ("from os import system as execute\nexecute(command)\n", [("PY002", 2)]),
        ("import os as operating_system\noperating_system.system(command)\n", [("PY002", 2)]),
        ("import requests as http\nhttp.post(url, verify=False)\n", [("PY003", 2)]),
        ("from requests import get as fetch\nfetch(url, verify=False)\n", [("PY003", 2)]),
        (
            "import subprocess\nsubprocess.run(\n    command,\n    shell=True,\n)\n",
            [("PY002", 2)],
        ),
        (
            "import requests\nrequests.get(\n    url,\n    verify=False,\n)\n",
            [("PY003", 2)],
        ),
    ],
)
def test_detects_supported_calls_at_call_start(
    source: str, expected: list[tuple[str, int]]
) -> None:
    from security_review.scanner.python_calls import detect_python_calls

    assert [(item.rule_id, item.line_start) for item in detect_python_calls(source)] == expected


@pytest.mark.parametrize(
    "source",
    [
        "# eval(user_input)\n",
        "example = 'eval(user_input)'\n",
        "example = 'requests.get(url, verify=False)'\n",
        "import subprocess\nsubprocess.run(command, shell=False)\n",
        "import requests\nrequests.get(url, verify=True)\n",
        "import subprocess as sp\nsp = object()\nsp.run(command, shell=True)\n",
        "import subprocess as sp\ndef work(sp):\n    sp.run(command, shell=True)\n",
        (
            "import requests as http\ndef outer():\n"
            "    def inner(http):\n        http.get(url, verify=False)\n"
        ),
        (
            "def outer():\n    requests = object()\n"
            "    def inner():\n        requests.get(url, verify=False)\n"
        ),
        (
            "def outer():\n    def inner():\n"
            "        requests.get(url, verify=False)\n    requests = object()\n"
        ),
        ("try:\n    pass\nexcept Exception as requests:\n    requests.get(url, verify=False)\n"),
        "def eval(value):\n    return value\neval(user_input)\n",
        "import other_module as subprocess\nsubprocess.run(command, shell=True)\n",
    ],
)
def test_rejects_non_calls_safe_arguments_and_shadowed_bindings(source: str) -> None:
    from security_review.scanner.python_calls import detect_python_calls

    assert detect_python_calls(source) == ()


def test_reimport_restores_an_explicit_alias() -> None:
    from security_review.scanner.python_calls import detect_python_calls

    source = "sp = object()\nimport subprocess as sp\nsp.run(command, shell=True)\n"

    assert [(item.rule_id, item.line_start) for item in detect_python_calls(source)] == [
        ("PY002", 3)
    ]
