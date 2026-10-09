"""Bounded lexical recognition of explicit Node TLS-disable assignments.

This is not a JavaScript parser. Template literals, including executable
interpolations, are deliberately unassessed and can contain false negatives.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_JS_ASSIGNMENT = re.compile(
    r"process[ \t]*\.[ \t]*env[ \t]*\.[ \t]*NODE_TLS_REJECT_UNAUTHORIZED"
    r"[ \t]*=[ \t]*(?:\"0\"|'0'|0)"
)
_ENV_ASSIGNMENT = re.compile(
    r"[ \t]*NODE_TLS_REJECT_UNAUTHORIZED[ \t]*=[ \t]*(?:0|\"0\"|'0')"
    r"[ \t]*(?:\#.*)?"
)
_REGEX_PREFIX_WORDS = frozenset(
    {
        "return",
        "throw",
        "case",
        "delete",
        "void",
        "typeof",
        "instanceof",
        "in",
        "of",
        "yield",
        "await",
    }
)
_CONTROL_PAREN_WORDS = frozenset({"if", "while", "for", "switch", "catch", "with"})
_PRECEDING_NON_BOUNDARY = frozenset("._$'\"`])")
_LINE_CONTINUATION_START = frozenset("+-*/%&|^?=.([`<>!")


@dataclass(slots=True)
class _CodeContext:
    """A source-code frame, optionally nested inside a template interpolation."""

    interpolation_depth: int = 0
    regex_allowed: bool = True
    control_before_paren: bool = False
    control_parens: list[bool] = field(default_factory=list)


def _skip_quoted(text: str, start: int) -> int:
    quote = text[start]
    index = start + 1
    while index < len(text):
        if text[index] == "\\":
            index += 2
        elif text[index] == quote:
            return index + 1
        else:
            index += 1
    return len(text)


def _skip_regex(text: str, start: int) -> int:
    index = start + 1
    in_class = False
    while index < len(text):
        char = text[index]
        if char == "\\":
            index += 2
            continue
        if char in "\r\n":
            return index
        if char == "[":
            in_class = True
        elif char == "]":
            in_class = False
        elif char == "/" and not in_class:
            index += 1
            while index < len(text) and text[index].isalpha():
                index += 1
            return index
        index += 1
    return len(text)


def _ends_literal_assignment(text: str, start: int) -> bool:
    """Check past comments and line breaks for a continued RHS expression."""

    index = start
    saw_line_break = False
    while index < len(text):
        if text[index] in " \t":
            index += 1
        elif text[index] in "\r\n":
            saw_line_break = True
            index += 1
        elif text.startswith("/*", index):
            close = text.find("*/", index + 2)
            if close < 0:
                return False
            saw_line_break |= "\n" in text[index : close + 2]
            index = close + 2
        elif text.startswith("//", index):
            newline = text.find("\n", index + 2)
            if newline < 0:
                return True
            saw_line_break = True
            index = newline + 1
        else:
            break
    if index == len(text):
        return True
    if saw_line_break:
        return text[index] not in _LINE_CONTINUATION_START
    return text[index] in ";,)]}"


def _detect_js_assignments(text: str) -> tuple[int, ...]:
    matches: set[int] = set()
    frames: list[_CodeContext | None] = [_CodeContext()]
    index = 0
    line = 1

    while index < len(text):
        char = text[index]
        context = frames[-1]
        if context is None:
            # Skip all template content, including ${...} code and nested templates.
            if char == "\\":
                end = min(index + 2, len(text))
            elif char == "`":
                frames.pop()
                end = index + 1
                parent = frames[-1]
                if parent is not None:
                    parent.regex_allowed = False
            elif text.startswith("${", index):
                frames.append(_CodeContext(interpolation_depth=1))
                end = index + 2
            else:
                end = index + 1
        elif context.interpolation_depth and char == "}":
            context.interpolation_depth -= 1
            if context.interpolation_depth == 0:
                frames.pop()
            end = index + 1
        elif char == "(":
            context.control_parens.append(context.control_before_paren)
            context.control_before_paren = False
            context.regex_allowed = True
            end = index + 1
        elif char == ")":
            context.regex_allowed = (
                context.control_parens.pop() if context.control_parens else False
            )
            context.control_before_paren = False
            end = index + 1
        elif char == "{":
            if context.interpolation_depth:
                context.interpolation_depth += 1
            context.regex_allowed = True
            context.control_before_paren = False
            end = index + 1
        elif char in "'\"":
            end = _skip_quoted(text, index)
            context.regex_allowed = False
        elif char == "`":
            frames.append(None)
            end = index + 1
        elif text.startswith("//", index):
            next_newline = text.find("\n", index + 2)
            end = len(text) if next_newline < 0 else next_newline
        elif text.startswith("/*", index):
            close = text.find("*/", index + 2)
            end = len(text) if close < 0 else close + 2
        elif char == "/":
            if context.regex_allowed:
                end = _skip_regex(text, index)
                context.regex_allowed = False
            else:
                end = index + 1
                context.regex_allowed = True
        elif char.isalpha() or char in "_$":
            if not context.interpolation_depth and char == "p":
                assignment = _JS_ASSIGNMENT.match(text, index)
                preceding = text[index - 1] if index else ""
                if (
                    assignment is not None
                    and _ends_literal_assignment(text, assignment.end())
                    and not (preceding.isalnum() or preceding in _PRECEDING_NON_BOUNDARY)
                ):
                    matches.add(line)
            end = index + 1
            while end < len(text) and (text[end].isalnum() or text[end] in "_$"):
                end += 1
            word = text[index:end]
            context.control_before_paren = word in _CONTROL_PAREN_WORDS and context.regex_allowed
            context.regex_allowed = word in _REGEX_PREFIX_WORDS
        elif char.isdigit():
            end = index + 1
            while end < len(text) and (text[end].isalnum() or text[end] in "._"):
                end += 1
            context.regex_allowed = False
        elif char in "+-" and text[index : index + 2] == char * 2:
            # Postfix ++/-- leaves a complete expression before a division slash.
            end = index + 2
            context.control_before_paren = False
        else:
            end = index + 1
            if not char.isspace():
                context.regex_allowed = char not in ".)]}"
                context.control_before_paren = False

        line += text.count("\n", index, end)
        index = end

    return tuple(sorted(matches))


def detect_node_tls_assignments(text: str, extension: str) -> tuple[int, ...]:
    """Return lines assigning literal zero to the supported Node TLS setting.

    Template interpolation is intentionally skipped with its enclosing literal;
    this narrow check does not prove such code safe.
    """

    if extension == ".env":
        return tuple(
            line_number
            for line_number, line in enumerate(text.splitlines(), start=1)
            if _ENV_ASSIGNMENT.fullmatch(line) is not None
        )
    if extension in {".js", ".ts"}:
        return _detect_js_assignments(text)
    return ()
