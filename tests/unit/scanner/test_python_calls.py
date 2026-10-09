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


def test_uncalled_global_assignment_does_not_invalidate_module_alias() -> None:
    from security_review.scanner.python_calls import detect_python_calls

    source = (
        "import subprocess as sp\n"
        "def change():\n    global sp\n    sp = object()\n"
        "sp.run(command, shell=True)\n"
    )

    assert [(item.rule_id, item.line_start) for item in detect_python_calls(source)] == [
        ("PY002", 5)
    ]


def test_uncalled_global_import_does_not_establish_module_alias() -> None:
    from security_review.scanner.python_calls import detect_python_calls

    source = (
        "sp = object()\n"
        "def change():\n    global sp\n    import subprocess as sp\n"
        "sp.run(command, shell=True)\n"
    )

    assert detect_python_calls(source) == ()


def test_match_capture_shadows_import_alias() -> None:
    from security_review.scanner.python_calls import detect_python_calls

    source = "\n".join(
        (
            "import subprocess as sp",
            "match item:",
            "    case sp:",
            "        sp.run(command, shell=True)",
            "",
        )
    )

    assert detect_python_calls(source) == ()


def test_comprehension_walrus_invalidates_enclosing_alias() -> None:
    from security_review.scanner.python_calls import detect_python_calls

    source = "\n".join(
        (
            "import subprocess as sp",
            "[(sp := object()) for _ in [1]]",
            "sp.run(command, shell=True)",
            "",
        )
    )

    assert detect_python_calls(source) == ()


def test_comprehension_walrus_is_a_function_local_before_assignment() -> None:
    from security_review.scanner.python_calls import detect_python_calls

    source = (
        "import subprocess as sp\n"
        "def work():\n    sp.run(command, shell=True)\n"
        "    [(sp := object()) for _ in [1]]\n"
    )

    assert detect_python_calls(source) == ()


def test_conditional_branches_merge_alias_certainty() -> None:
    from security_review.scanner.python_calls import detect_python_calls

    source = (
        "import subprocess as sp\n"
        "if condition:\n    sp = object()\n"
        "else:\n    import subprocess as sp\n"
        "sp.run(command, shell=True)\n"
    )

    assert detect_python_calls(source) == ()


def test_uniterated_generator_does_not_apply_walrus_to_module_alias() -> None:
    from security_review.scanner.python_calls import detect_python_calls

    source = (
        "import subprocess as sp\n"
        "generator = ((sp := object()) for _ in [1])\n"
        "sp.run(command, shell=True)\n"
    )

    assert [(item.rule_id, item.line_start) for item in detect_python_calls(source)] == [
        ("PY002", 3)
    ]


def test_exhaustive_match_with_same_import_keeps_alias_certain() -> None:
    from security_review.scanner.python_calls import detect_python_calls

    source = (
        "match value:\n"
        "    case 0:\n        import subprocess as sp\n"
        "    case _:\n        import subprocess as sp\n"
        "sp.run(command, shell=True)\n"
    )

    assert [(item.rule_id, item.line_start) for item in detect_python_calls(source)] == [
        ("PY002", 6)
    ]


def test_returning_if_branch_does_not_weaken_reachable_import() -> None:
    from security_review.scanner.python_calls import detect_python_calls

    source = (
        "def work(flag):\n"
        "    if flag:\n        return\n"
        "    else:\n        import subprocess as sp\n"
        "    sp.run(command, shell=True)\n"
    )

    assert [(item.rule_id, item.line_start) for item in detect_python_calls(source)] == [
        ("PY002", 6)
    ]


def test_caught_raise_path_keeps_reassigned_alias_uncertain() -> None:
    from security_review.scanner.python_calls import detect_python_calls

    source = (
        "import subprocess as sp\n"
        "try:\n"
        "    if flag:\n        sp = object()\n        raise ValueError()\n"
        "    else:\n        import subprocess as sp\n"
        "except ValueError:\n    pass\n"
        "sp.run(command, shell=True)\n"
    )

    assert detect_python_calls(source) == ()


def test_generator_passed_to_call_may_reassign_alias() -> None:
    from security_review.scanner.python_calls import detect_python_calls

    source = (
        "import subprocess as sp\n"
        "list((sp := object()) for _ in [1])\n"
        "sp.run(command, shell=True)\n"
    )

    assert detect_python_calls(source) == ()


def test_caught_raise_after_uniterated_generator_keeps_import_alias() -> None:
    from security_review.scanner.python_calls import detect_python_calls

    source = (
        "import subprocess as sp\n"
        "try:\n"
        "    gen = ((sp := object()) for _ in [1])\n"
        "    raise ValueError()\n"
        "except ValueError:\n"
        "    sp.run(command, shell=True)\n"
    )

    assert [(item.rule_id, item.line_start) for item in detect_python_calls(source)] == [
        ("PY002", 6)
    ]


def test_consuming_outer_generator_leaves_nested_generators_uniterated() -> None:
    from security_review.scanner.python_calls import detect_python_calls

    source = (
        "import subprocess as sp\n"
        "list(((sp := object()) for _ in [1]) for x in [1])\n"
        "sp.run(command, shell=True)\n"
    )

    assert [(item.rule_id, item.line_start) for item in detect_python_calls(source)] == [
        ("PY002", 3)
    ]


def test_consuming_generator_also_iterates_its_generator_iterable() -> None:
    from security_review.scanner.python_calls import detect_python_calls

    source = (
        "import subprocess as sp\n"
        "list(value for value in ((sp := object()) for _ in [1]))\n"
        "sp.run(command, shell=True)\n"
    )

    assert detect_python_calls(source) == ()


def test_eager_comprehension_iterates_its_generator_iterable() -> None:
    from security_review.scanner.python_calls import detect_python_calls

    source = (
        "import subprocess as sp\n"
        "[value for value in ((sp := object()) for _ in [1])]\n"
        "sp.run(command, shell=True)\n"
    )

    assert detect_python_calls(source) == ()
