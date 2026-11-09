"""Blank comment text before repository source is scanned for structure.

A comment cannot create an import, a module edge, or a build path, so a scanner
that matches raw text reports prose as structure. Each helper replaces comment
characters with spaces and preserves every whitespace character, so offsets,
line numbers, and line counts are identical to the original text.

String and character literals are preserved: a ``//`` inside ``"https://host"``
opens no comment. Unterminated literals recover at the end of their line, and
C-style block comments do not nest, so both recoveries under-blank rather than
hide real source from the scanners that consume this text.
"""

from __future__ import annotations


def strip_zig(text: str) -> str:
    """Return ``text`` with Zig ``//``, ``///``, and ``//!`` comments blanked."""
    return _strip(text, block_comments=False)


def strip_c(text: str) -> str:
    """Return ``text`` with C-family ``//`` and ``/* ... */`` comments blanked."""
    return _strip(text, block_comments=True)


def _strip(text: str, block_comments: bool) -> str:
    rendered = list(text)
    index = 0
    while index < len(text):
        char = text[index]
        if char in {'"', "'"}:
            index = _skip_literal(text, index)
        elif not block_comments and text.startswith("\\\\", index):
            index = _line_end(text, index)
        elif text.startswith("//", index):
            index = _blank(rendered, text, index, _line_end(text, index))
        elif block_comments and text.startswith("/*", index):
            end = text.find("*/", index + 2)
            index = _blank(rendered, text, index, len(text) if end < 0 else end + 2)
        else:
            index += 1
    return "".join(rendered)


def _skip_literal(text: str, start: int) -> int:
    """Return the index after the string or character literal opened at ``start``."""
    quote = text[start]
    index = start + 1
    while index < len(text):
        char = text[index]
        if char == "\\":
            index += 2
        elif char == quote:
            return index + 1
        elif char == "\n":
            return index
        else:
            index += 1
    return len(text)


def _line_end(text: str, start: int) -> int:
    end = text.find("\n", start)
    return len(text) if end < 0 else end


def _blank(rendered: list[str], text: str, start: int, end: int) -> int:
    for index in range(start, end):
        if not text[index].isspace():
            rendered[index] = " "
    return end
