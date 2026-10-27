"""Harmless stand-in sink; the CodeQL demo query treats its argument as a sink."""


def observe(value: str) -> str:
    return value
