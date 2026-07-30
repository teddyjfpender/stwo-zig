"""Checked translation receipts for generated Sail theorem-backend Lean.

`sail.py` binds the pinned Sail model to Lean by slicing definitions out of the
generated theorem-backend file. Issue #137 states plainly that hashes and
substring checks alone are not sufficient evidence for the translation
obligation. Section 7.2 of `soundness/UNIVERSAL_AIR_SAIL_REFINEMENT.md`
sanctions exactly one fallback: a generated normalized semantics capsule plus a
*checked translation receipt from the Sail AST*.

This module is that receipt machinery.  It parses the subset of generated-Sail
Lean syntax the backend emits into a typed AST, normalizes the AST into the
observable effects of each instruction selector, and emits a canonical JSON
receipt binding source digest, AST digest, normalized effects, and the identity
of the normalization rules applied.  Every construct it does not understand is
an error; nothing is ever skipped silently.

The translation subsystem is deliberately standalone from the other refinement
libraries, so `sail.py` can use its small helper modules without an import
cycle. The canonical digest is computed exactly the way
`codec.content_digest` computes it, reimplemented locally for that reason.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, is_dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, NoReturn, Sequence

from .sail_translation_model import (
    NORMALIZATION_RULES,
    PARSER_VERSION,
    RECEIPT_CLAIM,
    SCHEMA_VERSION,
    SEQUENTIAL_NEXT_PC,
    _EFFECT_FUNCTIONS,
    _PURE_CONSTANTS,
    _PURE_FUNCTIONS,
    _READER_FUNCTIONS,
    _RESERVED,
    _RETIREMENTS,
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
    _is_ast_node,
    ast_json,
    render,
)
from .sail_translation_normalization import (
    _classify_value,
    _effects,
    _substitute,
    _unwrap,
    normalize_definition,
)
from .sail_translation_parser import (
    _ATOM_START,
    _TOKEN_RE,
    _Cursor,
    _Item,
    _Line,
    _Token,
    _build_items,
    _flatten_item_tokens,
    _is_word,
    _matching_paren,
    _paren_balance,
    _parse_alternative,
    _parse_application,
    _parse_atom,
    _parse_block,
    _parse_body,
    _parse_expression,
    _parse_expression_tokens,
    _parse_header,
    _parse_let,
    _parse_match,
    _parse_matched_effect,
    _source_lines,
    _strip_final_suffix,
    _tokenize,
    _top_level_index,
    parse_definition,
    parse_definition_file,
)
from .sail_translation_receipt import (
    _difference,
    build_receipt,
    canonical_bytes,
    content_digest,
    load_definitions,
    translate,
    verify_receipt,
)

for _exported_object in (
    SailTranslationError,
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
    _Token,
    _Cursor,
    _Line,
    _Item,
    _is_ast_node,
    ast_json,
    render,
    _tokenize,
    _parse_atom,
    _parse_application,
    _parse_expression,
    _parse_expression_tokens,
    _source_lines,
    _build_items,
    _matching_paren,
    _top_level_index,
    _is_word,
    _parse_body,
    _flatten_item_tokens,
    _strip_final_suffix,
    _parse_let,
    _parse_alternative,
    _parse_match,
    _paren_balance,
    _parse_matched_effect,
    _parse_block,
    _parse_header,
    parse_definition,
    parse_definition_file,
    _substitute,
    _unwrap,
    _classify_value,
    _effects,
    normalize_definition,
    canonical_bytes,
    content_digest,
    translate,
    build_receipt,
    _difference,
    verify_receipt,
    load_definitions,
):
    _exported_object.__module__ = __name__
del _exported_object
