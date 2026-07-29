"""Checked translation receipts for generated Sail theorem-backend Lean.

`sail.py` currently binds the pinned Sail model to Lean by slicing a definition
out of the generated theorem-backend file, hashing the slice, and grepping it
for a handful of expected substrings.  Issue #137 states plainly that this is
not sufficient evidence for the translation obligation.  Section 7.2 of
`soundness/UNIVERSAL_AIR_SAIL_REFINEMENT.md` sanctions exactly one fallback: a
generated normalized semantics capsule plus a *checked translation receipt from
the Sail AST*.

This module is that receipt machinery.  It parses the subset of generated-Sail
Lean syntax the backend emits into a typed AST, normalizes the AST into the
observable effects of each instruction selector, and emits a canonical JSON
receipt binding source digest, AST digest, normalized effects, and the identity
of the normalization rules applied.  Every construct it does not understand is
an error; nothing is ever skipped silently.

The module is deliberately standalone: it imports nothing from its siblings so
that a later integration step can wire it into `sail.py` without a cycle.  The
canonical digest is computed exactly the way `codec.content_digest` computes
it, reimplemented locally for that reason.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, is_dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, NoReturn, Sequence

SCHEMA_VERSION = "stwo-sail-translation-receipt-v1"
PARSER_VERSION = "sail-lean-subset-parser-v1"

#: Normalization rules the pass may apply.  The catalogue is part of the
#: receipt payload, so editing a description changes the canonical digest.
NORMALIZATION_RULES: dict[str, str] = {
    "collapse-single-statement-do": (
        "a do-block holding exactly one expression statement denotes that "
        "expression"
    ),
    "inline-pure-let-bindings": (
        "let-bound expression names are inlined into the expressions that use "
        "them"
    ),
    "selector-match-is-total": (
        "the single match on the instruction selector supplies one alternative "
        "per selector and no wildcard"
    ),
    "monadic-bind-is-observation": (
        "a monadic bind of a whitelisted reader denotes an observation of "
        "pre-state, never a state change"
    ),
    "register-write-via-wX_bits": (
        "wX_bits target value denotes the single architectural register write"
    ),
    "next-pc-sequential-unless-set": (
        "absence of a next-pc effect denotes the sequential pc + 4 retirement"
    ),
    "retirement-from-terminal-pure": (
        "the terminal pure expression carries the retirement classification"
    ),
}

SEQUENTIAL_NEXT_PC = "sequential-pc-plus-4"

#: Recorded inside every receipt so the artifact carries its own boundary.
RECEIPT_CLAIM = (
    "binds each generated Sail definition text to its parsed AST and to the "
    "normalized observable effect of every instruction selector; it is "
    "evidence about the translation only, it is not a proof about the pinned "
    "Sail model, and it must be re-derived from the generated InstsEnd.lean on "
    "a host carrying the pinned Sail compiler before it counts as Sail evidence"
)

_RETIREMENTS = frozenset({"RETIRE_SUCCESS", "RETIRE_FAIL"})
#: Functions allowed in value position that observe pre-state.
_READER_FUNCTIONS = {
    "rX_bits": "register_read",
    "get_arch_pc": "program_counter_read",
    "mem_read": "memory_read",
}
#: Pure combinators allowed in value position.
_PURE_FUNCTIONS = frozenset(
    {
        "sign_extend",
        "zero_extend",
        "truncate",
        "bool_to_bits",
        "BitVec.slt",
        "BitVec.sle",
        "BitVec.ult",
        "BitVec.ule",
        "BitVec.append",
        "BitVec.extractLsb",
    }
)
#: Functions allowed in statement position, each with its effect slot.
_EFFECT_FUNCTIONS = {
    "wX_bits": "register_write",
    "set_next_pc": "next_pc",
    "mem_write_value": "memory_write",
}
_RESERVED = frozenset(
    {"def", "do", "let", "match", "with", "if", "then", "else", "fun", "λ"}
)


class SailTranslationError(Exception):
    """Raised for any construct the receipt pipeline cannot account for."""


# --------------------------------------------------------------------------
# typed AST
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Ident:
    name: str


@dataclass(frozen=True)
class Ctor:
    name: str


@dataclass(frozen=True)
class HexLit:
    text: str
    width: int | None


@dataclass(frozen=True)
class NumLit:
    value: int


@dataclass(frozen=True)
class UnitLit:
    pass


@dataclass(frozen=True)
class NamedArg:
    name: str
    value: Any


@dataclass(frozen=True)
class Bind:
    value: Any


@dataclass(frozen=True)
class App:
    head: Any
    args: tuple


@dataclass(frozen=True)
class BinOp:
    op: str
    args: tuple


@dataclass(frozen=True)
class Do:
    statements: tuple


@dataclass(frozen=True)
class Alt:
    ctor: str
    body: Any


@dataclass(frozen=True)
class Match:
    scrutinee: Any
    alts: tuple


@dataclass(frozen=True)
class Let:
    name: str
    declared_type: Any | None
    monadic: bool
    value: Any


@dataclass(frozen=True)
class ExprStmt:
    value: Any


@dataclass(frozen=True)
class Binder:
    names: tuple
    declared_type: Any


@dataclass(frozen=True)
class Definition:
    name: str
    binders: tuple
    result_type: Any
    body: tuple


def _is_ast_node(node: Any) -> bool:
    """Every public dataclass in this module is an AST node."""
    return (
        is_dataclass(node)
        and not isinstance(node, type)
        and type(node).__module__ == __name__
        and not type(node).__name__.startswith("_")
    )


def ast_json(node: Any) -> Any:
    """Total JSON view of the AST; the digest is taken over this view."""
    if node is None or isinstance(node, (bool, int, str)):
        return node
    if isinstance(node, tuple):
        return [ast_json(item) for item in node]
    if _is_ast_node(node):
        return {
            "kind": type(node).__name__,
            **{name: ast_json(value) for name, value in vars(node).items()},
        }
    raise SailTranslationError(f"no JSON view for AST node {node!r}")


def render(node: Any) -> str:
    """Canonical, fully parenthesized text form of a value expression."""
    if isinstance(node, Ident):
        return node.name
    if isinstance(node, Ctor):
        return f".{node.name}"
    if isinstance(node, HexLit):
        return node.text
    if isinstance(node, NumLit):
        return str(node.value)
    if isinstance(node, UnitLit):
        return "()"
    if isinstance(node, NamedArg):
        return f"({node.name} := {render(node.value)})"
    if isinstance(node, Bind):
        return f"(← {render(node.value)})"
    if isinstance(node, App):
        return "(" + " ".join(render(p) for p in (node.head, *node.args)) + ")"
    if isinstance(node, BinOp):
        return "(" + f" {node.op} ".join(render(arg) for arg in node.args) + ")"
    raise SailTranslationError(
        f"{type(node).__name__} is not a value expression and cannot be rendered"
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
                r"\+\+\+|&&&|\|\|\||\^\^\^|<<<|>>>|\+|-|\*",
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
    if not rest or (len(rest) == 1 and _is_word(rest[0], "do")):
        if not item.children:
            raise SailTranslationError(
                f"line {item.line.number}: expected an indented do-block"
            )
        return Do(_parse_block(item.children))
    if item.children:
        raise SailTranslationError(
            f"line {item.line.number}: unsupported continuation lines"
        )
    return _parse_expression_tokens(rest, item.line.number)


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
                raise SailTranslationError(
                    f"line {item.line.number}: unsupported continuation lines"
                )
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


# --------------------------------------------------------------------------
# normalization
# --------------------------------------------------------------------------


def _substitute(node: Any, env: Mapping[str, Any]) -> Any:
    if isinstance(node, Ident):
        return env.get(node.name, node)
    if isinstance(node, (Ctor, HexLit, NumLit, UnitLit)):
        return node
    if isinstance(node, NamedArg):
        return NamedArg(node.name, _substitute(node.value, env))
    if isinstance(node, Bind):
        return Bind(_substitute(node.value, env))
    if isinstance(node, App):
        return App(node.head, tuple(_substitute(a, env) for a in node.args))
    if isinstance(node, BinOp):
        return BinOp(node.op, tuple(_substitute(a, env) for a in node.args))
    raise SailTranslationError(
        f"{type(node).__name__} cannot appear inside a value expression"
    )


def _unwrap(node: Any) -> Any:
    """Collapse a do-block that holds exactly one expression statement."""
    while isinstance(node, Do):
        if len(node.statements) != 1 or not isinstance(node.statements[0], ExprStmt):
            raise SailTranslationError(
                "only single-expression do-blocks are supported in value position"
            )
        node = node.statements[0].value
    return node


def _classify_value(node: Any, names: frozenset, observations: dict) -> None:
    if isinstance(node, Ident):
        if node.name not in names:
            raise SailTranslationError(f"unbound identifier {node.name!r}")
        return
    if isinstance(node, (Ctor, HexLit, NumLit, UnitLit)):
        return
    if isinstance(node, NamedArg):
        _classify_value(node.value, names, observations)
        return
    if isinstance(node, Bind):
        _classify_value(node.value, names, observations)
        return
    if isinstance(node, BinOp):
        for argument in node.args:
            _classify_value(argument, names, observations)
        return
    if isinstance(node, App) and isinstance(node.head, Ident):
        head = node.head.name
        if head in _READER_FUNCTIONS:
            slot = _READER_FUNCTIONS[head]
            observations.setdefault(slot, []).append(
                render(node.args[0]) if len(node.args) == 1 else render(node)
            )
        elif head not in _PURE_FUNCTIONS:
            raise SailTranslationError(
                f"unknown function {head!r} in value position; the receipt "
                "refuses to classify it"
            )
        for argument in node.args:
            _classify_value(argument, names, observations)
        return
    raise SailTranslationError(
        f"{type(node).__name__} is not a supported value expression"
    )


def _effects(
    tail: Sequence[Any],
    env: Mapping[str, Any],
    names: frozenset,
    applied: set,
) -> dict:
    observations: dict[str, list[str]] = {}
    write: dict | None = None
    next_pc: str = SEQUENTIAL_NEXT_PC
    next_pc_was_set = False
    memory_write: str | None = None
    retirement: str | None = None
    for statement in tail:
        if not isinstance(statement, ExprStmt):
            raise SailTranslationError(
                "only expression statements may follow the selector match"
            )
        if retirement is not None:
            raise SailTranslationError("statement after the retirement expression")
        node = _substitute(_unwrap(statement.value), env)
        if not isinstance(node, App) or not isinstance(node.head, Ident):
            raise SailTranslationError(
                f"unsupported effect statement {render(node)!r}"
            )
        head = node.head.name
        if head == "pure":
            if len(node.args) != 1 or not isinstance(node.args[0], Ident):
                raise SailTranslationError("terminal pure must carry one name")
            if node.args[0].name not in _RETIREMENTS:
                raise SailTranslationError(
                    f"unknown retirement {node.args[0].name!r}"
                )
            retirement = node.args[0].name
            applied.add("retirement-from-terminal-pure")
        elif head == "wX_bits":
            if write is not None:
                raise SailTranslationError("more than one register write")
            if len(node.args) != 2 or not isinstance(node.args[0], Ident):
                raise SailTranslationError("wX_bits needs a name and a value")
            if node.args[0].name not in names:
                raise SailTranslationError(
                    f"register write target {node.args[0].name!r} is unbound"
                )
            _classify_value(node.args[1], names, observations)
            write = {
                "target": node.args[0].name,
                "value": render(node.args[1]),
            }
            applied.add("register-write-via-wX_bits")
        elif head == "set_next_pc":
            if next_pc_was_set:
                raise SailTranslationError("more than one next-pc effect")
            if len(node.args) != 1:
                raise SailTranslationError("set_next_pc takes one value")
            _classify_value(node.args[0], names, observations)
            next_pc = render(node.args[0])
            next_pc_was_set = True
        elif head == "mem_write_value":
            if memory_write is not None:
                raise SailTranslationError("more than one memory write")
            for argument in node.args:
                _classify_value(argument, names, observations)
            memory_write = render(node)
        else:
            raise SailTranslationError(
                f"unknown effect function {head!r}; the receipt accounts only "
                f"for 'pure' and {sorted(_EFFECT_FUNCTIONS)}, and refuses to "
                "treat anything else as observation-free"
            )
    if retirement is None:
        raise SailTranslationError("no terminal retirement expression")
    if not next_pc_was_set:
        applied.add("next-pc-sequential-unless-set")
    reads = observations.get("register_read", [])
    # Identical rendered observations are one observation: the same read may be
    # inlined into several effect arguments. Distinct ones are refused.
    memory_read = sorted(set(observations.get("memory_read", [])))
    if len(memory_read) > 1:
        raise SailTranslationError(
            f"more than one distinct memory read observation: {memory_read}"
        )
    if reads or memory_read or observations.get("program_counter_read"):
        applied.add("monadic-bind-is-observation")
    return {
        "memory_read": memory_read[0] if memory_read else None,
        "memory_write": memory_write,
        "next_pc": next_pc,
        "reads_program_counter": bool(observations.get("program_counter_read")),
        "register_reads": sorted(set(reads)),
        "register_write": write,
        "retirement": retirement,
    }


def normalize_definition(definition: Definition) -> dict:
    """Extract the observable effect of every selector alternative."""
    applied: set[str] = set()
    names = {name for binder in definition.binders for name in binder.names}
    env: dict[str, Any] = {}
    selector: tuple[str, Match] | None = None
    tail: list[Any] = []
    for statement in definition.body:
        if selector is not None:
            tail.append(statement)
            continue
        if isinstance(statement, Let):
            value = _unwrap(statement.value)
            if isinstance(value, Match):
                selector = (statement.name, value)
                continue
            if statement.name in env or statement.name in names:
                raise SailTranslationError(f"shadowed binding {statement.name!r}")
            env[statement.name] = _substitute(value, env)
            applied.add("inline-pure-let-bindings")
            if statement.monadic:
                applied.add("monadic-bind-is-observation")
            continue
        raise SailTranslationError(
            "the selector match must precede every observable effect"
        )
    if selector is None:
        raise SailTranslationError("definition has no instruction-selector match")
    if not tail:
        raise SailTranslationError("selector match is followed by no effect")
    binding, match = selector
    if not isinstance(match.scrutinee, Ident) or match.scrutinee.name not in names:
        raise SailTranslationError("selector match must scrutinize a definition binder")
    applied.add("selector-match-is-total")
    applied.add("collapse-single-statement-do")
    # Inlining is total, so after substitution only definition binders may
    # remain free; a surviving let name or selector binding is a bug, not a
    # thing to tolerate.
    known = frozenset(names)
    selectors: dict[str, dict] = {}
    for alternative in match.alts:
        body = _unwrap(alternative.body)
        if (
            not isinstance(body, App)
            or not isinstance(body.head, Ident)
            or body.head.name != "pure"
            or len(body.args) != 1
        ):
            raise SailTranslationError(
                f"alternative .{alternative.ctor} must produce '(pure <value>)'"
            )
        value = _substitute(body.args[0], env)
        _classify_value(value, known, {})
        selectors[alternative.ctor] = _effects(
            tail,
            {**env, binding: value},
            known,
            applied,
        )
    return {
        "applied_rules": sorted(applied),
        "selector_binder": match.scrutinee.name,
        "selectors": selectors,
    }


# --------------------------------------------------------------------------
# receipt
# --------------------------------------------------------------------------


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def content_digest(value: Mapping[str, Any]) -> str:
    """Local mirror of codec.content_digest; the module stays standalone."""
    unsigned = dict(value)
    unsigned.pop("canonical_digest", None)
    return hashlib.sha256(canonical_bytes(unsigned)).hexdigest()


def translate(name: str, text: str) -> dict:
    """Parse, normalize, and digest a single generated definition."""
    definition = parse_definition(text, expected_name=name)
    normalized = normalize_definition(definition)
    tree = ast_json(definition)
    return {
        "applied_rules": normalized["applied_rules"],
        "ast_sha256": hashlib.sha256(canonical_bytes(tree)).hexdigest(),
        "binders": [
            {"names": list(binder.names), "type": render(binder.declared_type)}
            for binder in definition.binders
        ],
        "result_type": render(definition.result_type),
        "selector_binder": normalized["selector_binder"],
        "selectors": normalized["selectors"],
        "source_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
    }


def build_receipt(definitions: Mapping[str, str]) -> dict:
    """Canonical translation receipt for the given generated definitions."""
    if not definitions:
        raise SailTranslationError(
            "a translation receipt needs at least one definition"
        )
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "parser_version": PARSER_VERSION,
        "claim": RECEIPT_CLAIM,
        "normalization_rules": dict(NORMALIZATION_RULES),
        "sequential_next_pc": SEQUENTIAL_NEXT_PC,
        "definitions": {
            name: translate(name, definitions[name]) for name in sorted(definitions)
        },
    }
    payload["canonical_digest"] = content_digest(payload)
    return payload


def _difference(expected: Any, actual: Any, path: str = "$") -> str | None:
    if isinstance(expected, dict) and isinstance(actual, dict):
        for key in sorted(set(expected) | set(actual)):
            if key not in actual:
                return f"{path}.{key} is missing"
            if key not in expected:
                return f"{path}.{key} is unexpected"
            found = _difference(expected[key], actual[key], f"{path}.{key}")
            if found is not None:
                return found
        return None
    if isinstance(expected, list) and isinstance(actual, list):
        if len(expected) != len(actual):
            return f"{path} has {len(actual)} entries, expected {len(expected)}"
        for index, (left, right) in enumerate(zip(expected, actual)):
            found = _difference(left, right, f"{path}[{index}]")
            if found is not None:
                return found
        return None
    if expected != actual:
        return f"{path} is {actual!r}, expected {expected!r}"
    return None


def verify_receipt(receipt: Any, definitions: Mapping[str, str]) -> dict:
    """Re-derive the receipt from the definitions and fail closed on drift."""
    if not isinstance(receipt, dict):
        raise SailTranslationError("translation receipt must be a JSON object")
    claimed = receipt.get("canonical_digest")
    if not isinstance(claimed, str):
        raise SailTranslationError("translation receipt has no canonical digest")
    if claimed != content_digest(receipt):
        raise SailTranslationError("translation receipt digest does not cover its body")
    rederived = build_receipt(definitions)
    drift = _difference(
        {key: value for key, value in rederived.items() if key != "canonical_digest"},
        {key: value for key, value in receipt.items() if key != "canonical_digest"},
    )
    if drift is not None:
        raise SailTranslationError(f"translation receipt drifted: {drift}")
    if claimed != rederived["canonical_digest"]:
        raise SailTranslationError(
            "translation receipt digest does not match the re-derived receipt"
        )
    return rederived


def load_definitions(directory: Path, names: Iterable[str]) -> dict[str, str]:
    """Read `<name>.lean` definition slices out of one directory."""
    result: dict[str, str] = {}
    for name in names:
        path = Path(directory) / f"{name}.lean"
        try:
            result[name] = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise SailTranslationError(f"{path}: unreadable definition") from exc
    return result
