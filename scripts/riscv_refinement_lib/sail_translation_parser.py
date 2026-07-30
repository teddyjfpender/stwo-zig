"""Fail-closed parser for the generated-Sail Lean subset."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn, Sequence

from .sail_translation_model import (
    _EFFECT_FUNCTIONS,
    _RESERVED,
    Alt,
    App,
    BinOp,
    Bind,
    Binder,
    Ctor,
    Definition,
    Do,
    ExprStmt,
    HexLit,
    Ident,
    Let,
    Match,
    MatchedEffect,
    NamedArg,
    NumLit,
    SailTranslationError,
    UnitLit,
)

# --------------------------------------------------------------------------
# lexer
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class _Token:
    kind: str
    text: str
    line: int
    column: int


_TOKEN_RE = re.compile(
    "|".join(
        f"(?P<{name}>{pattern})"
        for name, pattern in (
            ("ASSIGN", r":="),
            ("ARROW", r"=>"),
            ("BIND", r"←|<-"),
            (
                "OP",
                r"\+\+\+|&&&|\|\|\||\^\^\^|<<<|>>>|[+\-*]i|\+|-|\*",
            ),
            ("LPAREN", r"\("),
            ("RPAREN", r"\)"),
            ("COLON", r":"),
            ("BAR", r"\|"),
            ("HEX", r"0x[0-9a-fA-F]+(?:#[0-9]+)?"),
            ("NUM", r"[0-9]+"),
            ("IDENT", r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*"),
            ("CTOR", r"\.[A-Za-z_][A-Za-z0-9_']*"),
        )
    )
)


def _tokenize(text: str, line: int) -> list[_Token]:
    tokens: list[_Token] = []
    position = 0
    while position < len(text):
        if text[position] == " ":
            position += 1
            continue
        match = _TOKEN_RE.match(text, position)
        if match is None or match.lastgroup is None:
            raise SailTranslationError(
                f"line {line} column {position + 1}: unsupported syntax "
                f"{text[position:position + 16]!r}"
            )
        tokens.append(_Token(match.lastgroup, match.group(), line, position + 1))
        position = match.end()
    return tokens


class _Cursor:
    def __init__(self, tokens: Sequence[_Token], line: int) -> None:
        self._tokens = list(tokens)
        self._index = 0
        self._line = line

    def kind(self, offset: int = 0) -> str | None:
        position = self._index + offset
        if position >= len(self._tokens):
            return None
        return self._tokens[position].kind

    def take(self, kind: str | None = None) -> _Token:
        if self._index >= len(self._tokens):
            self.fail(f"unexpected end of expression, wanted {kind or 'a token'}")
        token = self._tokens[self._index]
        if kind is not None and token.kind != kind:
            self.fail(f"expected {kind} but found {token.text!r}")
        self._index += 1
        return token

    def done(self) -> bool:
        return self._index >= len(self._tokens)

    def fail(self, message: str) -> NoReturn:
        raise SailTranslationError(f"line {self._line}: {message}")


_ATOM_START = frozenset({"LPAREN", "BIND", "CTOR", "IDENT", "HEX", "NUM"})


def _parse_atom(cursor: _Cursor) -> Any:
    kind = cursor.kind()
    if kind == "LPAREN":
        cursor.take("LPAREN")
        if cursor.kind() == "RPAREN":
            cursor.take("RPAREN")
            return UnitLit()
        if cursor.kind() == "IDENT" and cursor.kind(1) == "ASSIGN":
            name = cursor.take("IDENT").text
            cursor.take("ASSIGN")
            value = _parse_expression(cursor)
            cursor.take("RPAREN")
            return NamedArg(name, value)
        value = _parse_expression(cursor)
        cursor.take("RPAREN")
        return value
    if kind == "BIND":
        cursor.take("BIND")
        return Bind(_parse_atom(cursor))
    if kind == "CTOR":
        return Ctor(cursor.take("CTOR").text[1:])
    if kind == "IDENT":
        token = cursor.take("IDENT")
        if token.text in _RESERVED:
            cursor.fail(f"unsupported keyword {token.text!r} in expression position")
        return Ident(token.text)
    if kind == "HEX":
        token = cursor.take("HEX")
        text, _, width = token.text.partition("#")
        return HexLit(token.text, int(width) if width else None)
    if kind == "NUM":
        return NumLit(int(cursor.take("NUM").text))
    cursor.fail("expected an expression")


def _parse_application(cursor: _Cursor) -> Any:
    parts = [_parse_atom(cursor)]
    while cursor.kind() in _ATOM_START:
        parts.append(_parse_atom(cursor))
    if len(parts) == 1:
        return parts[0]
    if not isinstance(parts[0], (Ident, Ctor)):
        cursor.fail("application head must be a name")
    return App(parts[0], tuple(parts[1:]))


def _parse_expression(cursor: _Cursor) -> Any:
    args = [_parse_application(cursor)]
    operators: list[str] = []
    while cursor.kind() == "OP":
        operators.append(cursor.take("OP").text)
        args.append(_parse_application(cursor))
    if not operators:
        return args[0]
    if len(set(operators)) > 1:
        cursor.fail(
            f"mixed operators {sorted(set(operators))} without parentheses; "
            "the receipt refuses to guess a precedence"
        )
    return BinOp(operators[0], tuple(args))


def _parse_expression_tokens(tokens: Sequence[_Token], line: int) -> Any:
    if not tokens:
        raise SailTranslationError(f"line {line}: expected an expression")
    cursor = _Cursor(tokens, line)
    value = _parse_expression(cursor)
    if not cursor.done():
        cursor.fail("trailing tokens after expression")
    return value


# --------------------------------------------------------------------------
# indentation-structured statement parser
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class _Line:
    number: int
    indent: int
    text: str


@dataclass(frozen=True)
class _Item:
    line: _Line
    children: tuple


def _source_lines(text: str) -> list[_Line]:
    lines: list[_Line] = []
    for number, raw in enumerate(text.splitlines(), start=1):
        if "\t" in raw:
            raise SailTranslationError(f"line {number}: tabs are not permitted")
        if "/-" in raw or "-/" in raw:
            raise SailTranslationError(
                f"line {number}: block comments are not supported"
            )
        stripped = raw.strip()
        if not stripped:
            continue
        if stripped.startswith("--"):
            continue
        if "--" in stripped:
            raise SailTranslationError(
                f"line {number}: inline comments are not supported"
            )
        lines.append(_Line(number, len(raw) - len(raw.lstrip(" ")), stripped))
    return lines


def _build_items(lines: Sequence[_Line], position: int) -> tuple[tuple, int]:
    indent = lines[position].indent
    items: list[_Item] = []
    while position < len(lines) and lines[position].indent >= indent:
        if lines[position].indent > indent:
            raise SailTranslationError(
                f"line {lines[position].number}: inconsistent indentation"
            )
        head = lines[position]
        position += 1
        children: tuple = ()
        if position < len(lines) and lines[position].indent > indent:
            children, position = _build_items(lines, position)
        items.append(_Item(head, children))
    return tuple(items), position


def _matching_paren(tokens: Sequence[_Token], start: int) -> int:
    depth = 0
    for index in range(start, len(tokens)):
        if tokens[index].kind == "LPAREN":
            depth += 1
        elif tokens[index].kind == "RPAREN":
            depth -= 1
            if depth == 0:
                return index
    raise SailTranslationError(f"line {tokens[start].line}: unbalanced parentheses")


def _top_level_index(tokens: Sequence[_Token], kinds: frozenset) -> int:
    depth = 0
    for index, token in enumerate(tokens):
        if token.kind == "LPAREN":
            depth += 1
        elif token.kind == "RPAREN":
            depth -= 1
        elif depth == 0 and token.kind in kinds:
            return index
    return -1


def _is_word(token: _Token, word: str) -> bool:
    return token.kind == "IDENT" and token.text == word


def _parse_body(rest: Sequence[_Token], item: _Item) -> Any:
    if len(rest) == 1 and _is_word(rest[0], "do"):
        if not item.children:
            raise SailTranslationError(
                f"line {item.line.number}: expected an indented do-block"
            )
        return Do(_parse_block(item.children))
    continuation = [
        token
        for child in item.children
        for token in _flatten_item_tokens(child)
    ]
    expression = [*rest, *continuation]
    if not expression:
        raise SailTranslationError(
            f"line {item.line.number}: expected an expression"
        )
    return _parse_expression_tokens(expression, item.line.number)


def _flatten_item_tokens(item: _Item) -> list[_Token]:
    """Flatten one generated expression continuation in source order."""
    return [
        *_tokenize(item.line.text, item.line.number),
        *(
            token
            for child in item.children
            for token in _flatten_item_tokens(child)
        ),
    ]


def _strip_final_suffix(item: _Item, suffix: str) -> _Item:
    """Remove a wrapper suffix from the final continuation leaf exactly."""
    if item.children:
        children = list(item.children)
        children[-1] = _strip_final_suffix(children[-1], suffix)
        return _Item(item.line, tuple(children))
    if not item.line.text.endswith(suffix):
        raise SailTranslationError(
            f"line {item.line.number}: final alternative must close exactly "
            "the inline monad and effect wrappers"
        )
    return _Item(
        _Line(
            item.line.number,
            item.line.indent,
            item.line.text[: -len(suffix)],
        ),
        (),
    )


def _parse_let(item: _Item, tokens: Sequence[_Token]) -> Let:
    line = item.line.number
    if len(tokens) < 3 or tokens[1].kind != "IDENT" or "." in tokens[1].text:
        raise SailTranslationError(f"line {line}: expected 'let <name>'")
    separator = _top_level_index(tokens, frozenset({"ASSIGN", "BIND"}))
    if separator < 0:
        raise SailTranslationError(f"line {line}: let binding has no ':=' or '<-'")
    declared: Any | None = None
    if tokens[2].kind == "COLON":
        declared = _parse_expression_tokens(tokens[3:separator], line)
    elif separator != 2:
        raise SailTranslationError(f"line {line}: unsupported let binder syntax")
    return Let(
        name=tokens[1].text,
        declared_type=declared,
        monadic=tokens[separator].kind == "BIND",
        value=_parse_body(tokens[separator + 1 :], item),
    )


def _parse_alternative(item: _Item) -> Alt:
    line = item.line.number
    tokens = _tokenize(item.line.text, line)
    if len(tokens) < 3 or tokens[0].kind != "BAR":
        raise SailTranslationError(f"line {line}: expected a match alternative")
    if tokens[1].kind != "CTOR" or tokens[2].kind != "ARROW":
        raise SailTranslationError(
            f"line {line}: only single-constructor patterns are supported"
        )
    return Alt(tokens[1].text[1:], _parse_body(tokens[3:], item))


def _parse_match(items: Sequence[_Item], index: int) -> tuple[Match, int]:
    item = items[index]
    line = item.line.number
    tokens = _tokenize(item.line.text, line)
    if not _is_word(tokens[-1], "with"):
        raise SailTranslationError(f"line {line}: match head must end in 'with'")
    scrutinee = _parse_expression_tokens(tokens[1:-1], line)
    index += 1
    if item.children:
        alternatives = [_parse_alternative(child) for child in item.children]
        following = items[index] if index < len(items) else None
        if following is not None and _tokenize(
            following.line.text, following.line.number
        )[0].kind == "BAR":
            raise SailTranslationError(
                f"line {items[index].line.number}: match alternatives are split "
                "across two indentation levels"
            )
    else:
        alternatives = []
        while index < len(items):
            head = _tokenize(items[index].line.text, items[index].line.number)
            if not head or head[0].kind != "BAR":
                break
            alternatives.append(_parse_alternative(items[index]))
            index += 1
    if not alternatives:
        raise SailTranslationError(f"line {line}: match has no alternatives")
    seen = [alt.ctor for alt in alternatives]
    if len(set(seen)) != len(seen):
        raise SailTranslationError(f"line {line}: duplicate match alternative")
    return Match(scrutinee, tuple(alternatives)), index


def _paren_balance(tokens: Sequence[_Token]) -> int:
    return sum(
        1 if token.kind == "LPAREN" else -1 if token.kind == "RPAREN" else 0
        for token in tokens
    )


def _parse_matched_effect(item: _Item) -> MatchedEffect:
    """Parse the exact nested shape emitted by Sail 0.20.2.

    The theorem backend emits `wX_bits rd (← do match op with ...)` as one
    multiline statement rather than first binding the selected value. Only
    that fully-accounted shape is accepted here: two opening wrapper
    parentheses, one selector match, and exactly two closing wrapper
    parentheses on the final alternative.
    """
    line = item.line.number
    head = _tokenize(item.line.text, line)
    if (
        len(head) != 3
        or head[0].kind != "LPAREN"
        or head[1].kind != "IDENT"
        or head[1].text not in _EFFECT_FUNCTIONS
    ):
        raise SailTranslationError(
            f"line {line}: unsupported multiline effect head"
        )
    argument = _parse_expression_tokens(head[2:], line)
    if len(item.children) != 1:
        raise SailTranslationError(
            f"line {line}: multiline effect needs one inline monadic value"
        )
    wrapper = item.children[0]
    wrapper_tokens = _tokenize(wrapper.line.text, wrapper.line.number)
    if (
        len(wrapper_tokens) != 3
        or wrapper_tokens[0].kind != "LPAREN"
        or wrapper_tokens[1].kind != "BIND"
        or not _is_word(wrapper_tokens[2], "do")
    ):
        raise SailTranslationError(
            f"line {wrapper.line.number}: expected '(← do' effect value"
        )
    nested = list(wrapper.children)
    if len(nested) < 2:
        raise SailTranslationError(
            f"line {wrapper.line.number}: inline monadic value has no match"
        )
    match_item = nested[0]
    match_tokens = _tokenize(match_item.line.text, match_item.line.number)
    if (
        match_item.children
        or len(match_tokens) < 3
        or not _is_word(match_tokens[0], "match")
        or not _is_word(match_tokens[-1], "with")
    ):
        raise SailTranslationError(
            f"line {match_item.line.number}: inline effect value must be a match"
        )
    scrutinee = _parse_expression_tokens(
        match_tokens[1:-1], match_item.line.number
    )
    alternatives = nested[1:]
    for alternative in alternatives[:-1]:
        tokens = _flatten_item_tokens(alternative)
        if _paren_balance(tokens) != 0:
            raise SailTranslationError(
                f"line {alternative.line.number}: non-final match alternative "
                "has unbalanced parentheses"
            )
    final = alternatives[-1]
    stripped = _strip_final_suffix(final, "))")
    if _paren_balance(_flatten_item_tokens(stripped)) != 0:
        raise SailTranslationError(
            f"line {final.line.number}: wrapper closure is not exact"
        )
    parsed = [
        _parse_alternative(alternative) for alternative in alternatives[:-1]
    ]
    parsed.append(_parse_alternative(stripped))
    constructors = [alternative.ctor for alternative in parsed]
    if len(set(constructors)) != len(constructors):
        raise SailTranslationError(
            f"line {match_item.line.number}: duplicate match alternative"
        )
    return MatchedEffect(
        Ident(head[1].text),
        (argument,),
        Match(scrutinee, tuple(parsed)),
    )


def _parse_block(items: Sequence[_Item]) -> tuple:
    statements: list[Any] = []
    index = 0
    while index < len(items):
        item = items[index]
        tokens = _tokenize(item.line.text, item.line.number)
        if not tokens:
            raise SailTranslationError(f"line {item.line.number}: empty statement")
        if tokens[0].kind == "BAR":
            raise SailTranslationError(
                f"line {item.line.number}: match alternative outside a match"
            )
        if _is_word(tokens[0], "let"):
            statements.append(_parse_let(item, tokens))
            index += 1
        elif _is_word(tokens[0], "match"):
            if item.children and any(
                _tokenize(child.line.text, child.line.number)[0].kind != "BAR"
                for child in item.children
            ):
                raise SailTranslationError(
                    f"line {item.line.number}: match body must be alternatives only"
                )
            node, index = _parse_match(items, index)
            statements.append(ExprStmt(node))
        else:
            if item.children:
                statements.append(_parse_matched_effect(item))
            else:
                statements.append(
                    ExprStmt(_parse_expression_tokens(tokens, item.line.number))
                )
            index += 1
    return tuple(statements)


def _parse_header(tokens: Sequence[_Token], line: int) -> tuple[str, tuple, Any]:
    if len(tokens) < 4 or not _is_word(tokens[0], "def") or tokens[1].kind != "IDENT":
        raise SailTranslationError(f"line {line}: expected 'def <name>'")
    name = tokens[1].text
    index = 2
    binders: list[Binder] = []
    while index < len(tokens) and tokens[index].kind == "LPAREN":
        close = _matching_paren(tokens, index)
        inner = tokens[index + 1 : close]
        colon = _top_level_index(inner, frozenset({"COLON"}))
        if colon < 0:
            break
        names = tuple(token.text for token in inner[:colon])
        if not names or any(token.kind != "IDENT" for token in inner[:colon]):
            raise SailTranslationError(f"line {line}: unsupported binder syntax")
        binders.append(
            Binder(names, _parse_expression_tokens(inner[colon + 1 :], line))
        )
        index = close + 1
    if index >= len(tokens) or tokens[index].kind != "COLON":
        raise SailTranslationError(f"line {line}: definition has no result type")
    rest = tokens[index + 1 :]
    assign = _top_level_index(rest, frozenset({"ASSIGN"}))
    if assign < 0:
        raise SailTranslationError(f"line {line}: definition header has no ':='")
    result_type = _parse_expression_tokens(rest[:assign], line)
    tail = rest[assign + 1 :]
    if len(tail) != 1 or not _is_word(tail[0], "do"):
        raise SailTranslationError(
            f"line {line}: only monadic 'do' definitions are supported"
        )
    return name, tuple(binders), result_type


def parse_definition(text: str, *, expected_name: str | None = None) -> Definition:
    """Parse one generated theorem-backend definition into a typed AST."""
    lines = _source_lines(text)
    if not lines:
        raise SailTranslationError("definition is empty")
    if lines[0].indent != 0:
        raise SailTranslationError("definition must start at column 1")
    header = [lines[0].text]
    index = 1
    while not " ".join(header).endswith(":= do"):
        if index >= len(lines) or lines[index].indent == 0:
            raise SailTranslationError(
                "definition header must end in ':= do'; the receipt only "
                "covers monadic generated definitions"
            )
        header.append(lines[index].text)
        index += 1
    name, binders, result_type = _parse_header(
        _tokenize(" ".join(header), lines[0].number),
        lines[0].number,
    )
    if expected_name is not None and name != expected_name:
        raise SailTranslationError(
            f"definition is {name!r} but {expected_name!r} was expected"
        )
    body_lines = lines[index:]
    if not body_lines:
        raise SailTranslationError(f"{name}: definition has an empty body")
    if any(body.indent == 0 for body in body_lines):
        raise SailTranslationError(
            f"{name}: the slice carries more than one top-level declaration"
        )
    items, consumed = _build_items(body_lines, 0)
    if consumed != len(body_lines):
        raise SailTranslationError(f"{name}: inconsistent body indentation")
    return Definition(name, binders, result_type, _parse_block(items))


def parse_definition_file(
    path: Path,
    *,
    expected_name: str | None = None,
) -> Definition:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise SailTranslationError(f"{path}: unreadable definition") from exc
    return parse_definition(text, expected_name=expected_name)
