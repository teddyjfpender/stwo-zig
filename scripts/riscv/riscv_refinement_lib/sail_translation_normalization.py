"""Observable-effect normalization for parsed Sail definitions."""

from __future__ import annotations

from typing import Any, Mapping, Sequence

from .sail_translation_model import (
    _EFFECT_FUNCTIONS,
    _PURE_CONSTANTS,
    _PURE_FUNCTIONS,
    _READER_FUNCTIONS,
    _RETIREMENTS,
    SEQUENTIAL_NEXT_PC,
    Alt,
    App,
    BinOp,
    Bind,
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
    render,
)

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
        if node.name not in names and node.name not in _PURE_CONSTANTS:
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
    selector: tuple[str | None, Match] | None = None
    matched_effect: MatchedEffect | None = None
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
        if isinstance(statement, MatchedEffect):
            selector = (None, statement.match)
            matched_effect = statement
            applied.add("selector-match-feeds-effect")
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
        effect_tail = tail
        effect_env = dict(env)
        if matched_effect is not None:
            effect_tail = [
                ExprStmt(
                    App(
                        matched_effect.head,
                        (*matched_effect.args, value),
                    )
                ),
                *tail,
            ]
        elif binding is not None:
            effect_env[binding] = value
        selectors[alternative.ctor] = _effects(
            effect_tail,
            effect_env,
            known,
            applied,
        )
    return {
        "applied_rules": sorted(applied),
        "selector_binder": match.scrutinee.name,
        "selectors": selectors,
    }
