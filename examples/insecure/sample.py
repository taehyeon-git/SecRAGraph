"""Deliberately insecure, non-executed scanner fixture with fake values only."""

import subprocess

DEMO_API_KEY = "demo-not-a-real-secret-12345"


def run_user_command(command: str) -> None:
    """Demonstrate a shell-injection finding without invoking this fixture."""

    subprocess.run(command, shell=True, check=False)


def calculate(expression: str) -> object:
    """Demonstrate a dynamic-evaluation finding without invoking this fixture."""

    return eval(expression)
