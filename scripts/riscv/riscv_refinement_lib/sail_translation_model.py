"""Constants and typed AST for checked Sail translation receipts."""

from __future__ import annotations

from dataclasses import dataclass, is_dataclass
from typing import Any

SCHEMA_VERSION = "stwo-sail-translation-receipt-v1"
PARSER_VERSION = "sail-lean-subset-parser-v2"

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
    "selector-match-feeds-effect": (
        "a generated effect whose value is selected by an inline monadic "
        "match is normalized by feeding each alternative directly to that "
        "effect"
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
        "bool_to_bit",
        "zopz0zI_s",
        "zopz0zI_u",
        "BitVec.slt",
        "BitVec.sle",
        "BitVec.ult",
        "BitVec.ule",
        "BitVec.append",
        "BitVec.extractLsb",
        "Sail.BitVec.extractLsb",
        "shift_bits_left",
        "shift_bits_right",
        "shift_bits_right_arith",
    }
)
# Generated shift alternatives refer to this pinned architectural constant.
# It is accepted as a value atom, not as an unconstrained local.
_PURE_CONSTANTS = frozenset({"log2_xlen"})
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
class MatchedEffect:
    """An effect whose final value is supplied by an inline monadic match."""

    head: Ident
    args: tuple
    match: Match


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


_AST_NODE_TYPES = (
    Ident,
    Ctor,
    HexLit,
    NumLit,
    UnitLit,
    NamedArg,
    Bind,
    App,
    BinOp,
    Do,
    Alt,
    Match,
    Let,
    ExprStmt,
    MatchedEffect,
    Binder,
    Definition,
)


def _is_ast_node(node: Any) -> bool:
    """Every public dataclass in this module is an AST node."""
    return (
        is_dataclass(node)
        and not isinstance(node, type)
        and type(node) in _AST_NODE_TYPES
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
