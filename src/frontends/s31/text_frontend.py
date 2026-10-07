"""Deliberately small, typed S31 text frontend for normalized relation v1.

There is no witness-dependent control flow or runtime function value. Functions
are specialized at calls; iterate recognizes a static step program before node
emission, preserving the current four-lane chip shape.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import s31_mathlib as mathlib
from s31_stdlib import Builder, StaticGroup, StepState, Type, TypeErrorS31, Value, P, STDLIB_ABI_VERSION


TOKEN_RE = re.compile(
    r"(?P<space>\s+)|(?P<comment>//[^\n]*)|(?P<field>[0-9]+_m31\b)|"
    r"(?P<number>[0-9]+)|(?P<ident>[A-Za-z_][A-Za-z_0-9]*)|"
    r"(?P<symbol>->|::|\.\*|==|[\[\]{}();,:<>+=*@])"
)
MAX_TOKENS = 100_000
MAX_CALL_DEPTH = 32
BUILTINS = {
    "splat", "iterate", "m31_from_u16", "select", "poseidon2_leaf",
    "std::array::get", "std::array::concat",
    "poseidon2_pair", "blake2s_leaf", "blake2s_pair",
    "merkle_path_poseidon2", "merkle_path_blake2s",
    "std::bytes::to_u256_le", "std::bytes::from_u256_le", "std::bytes::limbs_m31",
    "sha256d_header", "is_zero",
    "target_mainnet",
    "prev_hash", "header_bits", "header_time", "genesis_hash_mainnet", "lt_u32",
} | mathlib.BUILTINS
STANDARD_ALIASES = {
    "std::field::from_u16": "m31_from_u16",
    "std::field::select": "select",
    "std::field::is_zero": "is_zero",
    "std::hash::poseidon2_leaf": "poseidon2_leaf",
    "std::hash::poseidon2_pair": "poseidon2_pair",
    "std::hash::blake2s_leaf": "blake2s_leaf",
    "std::hash::blake2s_pair": "blake2s_pair",
    "std::hash::sha256d_header": "sha256d_header",
    "std::bitcoin::block_hash": "block_hash",
    "std::bitcoin::hash_bytes": "hash_bytes",
    "std::bitcoin::parent_hash": "parent_hash",
    "std::bitcoin::genesis_block_hash_mainnet": "genesis_block_hash_mainnet",
    "std::bitcoin::target_mainnet": "target_mainnet",
    "std::bitcoin::prev_hash": "prev_hash",
    "std::bitcoin::header_bits": "header_bits",
    "std::bitcoin::header_time": "header_time",
    "std::math::lt_u32": "lt_u32",
    "std::bitcoin::genesis_hash_mainnet": "genesis_hash_mainnet",
    "std::merkle::path_poseidon2": "merkle_path_poseidon2",
    "std::merkle::path_blake2s": "merkle_path_blake2s",
}
BUILTINS |= STANDARD_ALIASES.keys()


class SourceError(ValueError):
    pass


@dataclass(frozen=True)
class Token:
    kind: str
    text: str
    line: int
    column: int


@dataclass(frozen=True)
class Expr:
    kind: str
    value: str
    args: tuple[Expr, ...]
    token: Token
    generic: int | None = None


@dataclass(frozen=True)
class Statement:
    kind: str
    name: str
    args: tuple[Expr, ...]
    token: Token


@dataclass(frozen=True)
class Function:
    name: str
    params: tuple[tuple[str, Type], ...]
    result: Type
    statements: tuple[Statement, ...]
    body: Expr


@dataclass(frozen=True)
class Circuit:
    name: str
    params: tuple[tuple[str, Type, str], ...]
    result: Type
    statements: tuple[Statement, ...]
    body: Expr


def lex(source: str, filename: str = "<source>") -> list[Token]:
    tokens: list[Token] = []
    position, line, column = 0, 1, 1
    while position < len(source):
        match = TOKEN_RE.match(source, position)
        if match is None:
            raise SourceError(f"{filename}:{line}:{column}: unexpected character {source[position]!r}")
        kind = match.lastgroup or ""
        chunk = match.group()
        if kind not in {"space", "comment"}:
            tokens.append(Token(kind, chunk, line, column))
            if len(tokens) > MAX_TOKENS:
                raise SourceError(f"{filename}:{line}:{column}: token limit exceeded")
        if "\n" in chunk:
            line += chunk.count("\n")
            column = len(chunk.rsplit("\n", 1)[1]) + 1
        else:
            column += len(chunk)
        position = match.end()
    tokens.append(Token("eof", "<eof>", line, column))
    return tokens


class Parser:
    def __init__(self, source: str, filename: str) -> None:
        self.tokens = lex(source, filename)
        self.filename = filename
        self.at = 0
        self.stdlib_explicit = False

    def peek(self) -> Token:
        return self.tokens[self.at]

    def accept(self, text: str) -> Token | None:
        if self.peek().text == text:
            token = self.peek()
            self.at += 1
            return token
        return None

    def error(self, message: str, token: Token | None = None) -> SourceError:
        token = token or self.peek()
        return SourceError(f"{self.filename}:{token.line}:{token.column}: {message}")

    def expect(self, text: str) -> Token:
        found = self.accept(text)
        if found is None:
            raise self.error(f"expected {text!r}, found {self.peek().text!r}")
        return found

    def identifier(self) -> str:
        token = self.peek()
        if token.kind != "ident" or token.text in {"use", "let", "fn", "circuit", "public", "private", "assert_eq"}:
            raise self.error("expected identifier")
        self.at += 1
        return token.text

    def number(self) -> int:
        token = self.peek()
        if token.kind != "number":
            raise self.error("expected a compile-time natural number")
        self.at += 1
        return int(token.text)

    def parse_type(self) -> Type:
        token = self.peek()
        if self.accept("["):
            kind = self.identifier()
            if kind not in {"m31", "u16"}:
                raise self.error("array element type must be m31 or u16", token)
            self.expect(";")
            length = self.number()
            self.expect("]")
            try:
                return Type(kind, length)
            except TypeErrorS31 as exc:
                raise self.error(str(exc), token) from exc
        if self.accept("bit"):
            return Type("bit", 1)
        if self.accept("UInt256"):
            return Type("uint256", 16)
        if self.accept("Bytes32"):
            return Type("bytes32", 16)
        if self.accept("BlockHash"):
            return Type("blockhash", 16)
        if self.accept("Bytes80"):
            return Type("bytes80", 40)
        if self.accept("Digest"):
            self.expect("<")
            family = self.identifier()
            self.expect(">")
            normalized = {"Poseidon2": "poseidon2", "Blake2sReduced": "blake2s_reduced"}.get(family)
            if normalized is None:
                raise self.error("digest family must be Poseidon2 or Blake2sReduced", token)
            return Type("digest", 8, normalized)
        raise self.error("expected [m31; N], [u16; N], bit, UInt256, Bytes32, BlockHash, Bytes80, or Digest<Family>")

    def parameters(self, circuit: bool) -> tuple[Any, ...]:
        self.expect("(")
        params: list[Any] = []
        if not self.accept(")"):
            while True:
                visibility = None
                if circuit:
                    token = self.peek()
                    if token.text not in {"public", "private"}:
                        raise self.error("circuit input must be public or private")
                    visibility = token.text
                    self.at += 1
                name = self.identifier()
                self.expect(":")
                typ = self.parse_type()
                params.append((name, typ, visibility) if circuit else (name, typ))
                if self.accept(")"):
                    break
                self.expect(",")
        names = [item[0] for item in params]
        if len(names) != len(set(names)):
            raise self.error("duplicate parameter name")
        return tuple(params)

    def block(self) -> tuple[tuple[Statement, ...], Expr]:
        self.expect("{")
        statements: list[Statement] = []
        while self.peek().text in {"let", "assert_eq"}:
            token = self.peek()
            if self.accept("let"):
                name = self.identifier()
                self.expect("=")
                expression = self.expression()
                self.expect(";")
                statements.append(Statement("let", name, (expression,), token))
            else:
                self.expect("assert_eq")
                self.expect("(")
                lhs = self.expression()
                self.expect(",")
                rhs = self.expression()
                self.expect(")")
                self.expect(";")
                statements.append(Statement("assert", "", (lhs, rhs), token))
        result = self.expression()
        self.accept(";")
        self.expect("}")
        return tuple(statements), result

    def declaration(self) -> Function | Circuit:
        if self.accept("fn"):
            name = self.identifier()
            params = self.parameters(False)
            self.expect("->")
            result = self.parse_type()
            statements, body = self.block()
            return Function(name, params, result, statements, body)
        self.expect("circuit")
        name = self.identifier()
        params = self.parameters(True)
        self.expect("->")
        self.expect("public")
        result = self.parse_type()
        statements, body = self.block()
        return Circuit(name, params, result, statements, body)

    def expression(self, min_power: int = 0) -> Expr:
        token = self.peek()
        if self.accept("("):
            lhs = self.expression()
            self.expect(")")
        elif self.accept("["):
            elements: list[Expr] = []
            if not self.accept("]"):
                while True:
                    elements.append(self.expression())
                    if self.accept("]"):
                        break
                    self.expect(",")
            lhs = Expr("array", "", tuple(elements), token)
        elif token.kind in {"field", "number"}:
            self.at += 1
            lhs = Expr("field" if token.kind == "field" else "number", token.text, (), token)
        elif token.kind == "ident":
            self.at += 1
            name = token.text
            while self.accept("::"):
                name += "::" + self.identifier()
            generic = None
            if self.accept("<"):
                generic = self.number()
                self.expect(">")
            if self.accept("("):
                args: list[Expr] = []
                if not self.accept(")"):
                    while True:
                        args.append(self.expression())
                        if self.accept(")"):
                            break
                        self.expect(",")
                lhs = Expr("call", name, tuple(args), token, generic)
            elif generic is None:
                lhs = Expr("name", name, (), token)
            else:
                raise self.error("type argument requires a call")
        else:
            raise self.error(f"expected expression, found {token.text!r}")
        while True:
            operator = self.peek()
            power = {"+": 10, ".*": 20}.get(operator.text)
            if power is None or power < min_power:
                break
            self.at += 1
            rhs = self.expression(power + 1)
            lhs = Expr("binary", operator.text, (lhs, rhs), operator)
        return lhs

    def parse(self) -> tuple[dict[str, Function], Circuit]:
        if self.accept("use"):
            package = self.identifier()
            self.expect("@")
            version = self.number()
            self.expect(";")
            if package != "std" or version != STDLIB_ABI_VERSION:
                raise self.error("only the compiler-owned standard library std@1 is supported")
            self.stdlib_explicit = True
        functions: dict[str, Function] = {}
        while self.peek().text == "fn":
            fn = self.declaration()
            assert isinstance(fn, Function)
            if fn.name in functions or fn.name in BUILTINS:
                raise self.error(f"duplicate or reserved function {fn.name}")
            functions[fn.name] = fn
        circuit = self.declaration()
        if not isinstance(circuit, Circuit):
            raise self.error("expected one circuit")
        if self.peek().kind != "eof":
            raise self.error("expected end of file after circuit")
        return functions, circuit


class Compiler:
    def __init__(self, functions: dict[str, Function], circuit: Circuit, filename: str) -> None:
        self.functions = functions
        self.circuit = circuit
        self.filename = filename
        self.builder = Builder(circuit.name)
        self.call_stack: list[str] = []
        self.inline_count = 0
        self.source_names = {name for name, _, _ in circuit.params}
        self.source_names.update(statement.name for statement in circuit.statements
                                 if statement.kind == "let")
        self.builder.reserved_names = self.source_names

    def located(self, expr: Expr, exc: Exception) -> SourceError:
        return SourceError(f"{self.filename}:{expr.token.line}:{expr.token.column}: {exc}")

    @staticmethod
    def span(expr: Expr) -> dict[str, int]:
        return {"line": expr.token.line, "column": expr.token.column}

    def expect_value(self, thing: Any, expr: Expr) -> Value:
        if not isinstance(thing, Value):
            raise self.located(expr, "expected a circuit value")
        return thing

    def eval_block(self, statements: tuple[Statement, ...], body: Expr,
                   env: dict[str, Any], wanted: str | None = None,
                   inline_prefix: str = "", allow_assert: bool = True) -> Value:
        local = env.copy()
        for statement_index, statement in enumerate(statements):
            if statement.kind == "let":
                if statement.name in local:
                    raise self.located(statement.args[0], f"duplicate local name {statement.name}")
                if inline_prefix and wanted is not None and body.kind == "name" and body.value == statement.name:
                    target = wanted
                elif inline_prefix:
                    target = f"{inline_prefix}{statement_index}"
                else:
                    target = statement.name
                value = self.eval_expr(statement.args[0], local, wanted=target)
                if not isinstance(value, (Value, StaticGroup)):
                    raise self.located(statement.args[0], "let requires a circuit value or static array")
                local[statement.name] = value
            else:
                if not allow_assert:
                    raise self.located(statement.args[0], "pure functions cannot contain assertions")
                lhs = self.expect_value(self.eval_expr(statement.args[0], local), statement.args[0])
                rhs = self.expect_value(self.eval_expr(statement.args[1], local), statement.args[1])
                self.builder.assert_equal(lhs, rhs)
        return self.expect_value(self.eval_expr(body, local, wanted=wanted), body)

    def call_function(self, name: str, args: tuple[Any, ...], wanted: str | None, expr: Expr) -> Value:
        fn = self.functions[name]
        if len(args) != len(fn.params):
            raise self.located(expr, f"{name} expects {len(fn.params)} arguments")
        if name in self.call_stack or len(self.call_stack) >= MAX_CALL_DEPTH:
            raise self.located(expr, "recursive or excessively deep function expansion")
        env: dict[str, Value] = {}
        for (parameter, typ), arg in zip(fn.params, args):
            value = self.expect_value(arg, expr)
            if value.typ != typ:
                raise self.located(expr, f"{name} argument {parameter} expects {typ}")
            env[parameter] = value
        self.call_stack.append(name)
        while True:
            self.inline_count += 1
            prefix = f"_s31_i{self.inline_count}_"
            generated = {f"{prefix}{index}" for index, statement in enumerate(fn.statements)
                         if statement.kind == "let"}
            if not generated.intersection(self.source_names | self.builder.used_names):
                break
        try:
            result = self.eval_block(fn.statements, fn.body, env, wanted=wanted,
                                     inline_prefix=prefix, allow_assert=False)
        finally:
            self.call_stack.pop()
        if result.typ != fn.result:
            raise self.located(expr, f"{name} result does not match its declared type")
        return result

    def eval_expr(self, expr: Expr, env: dict[str, Any], wanted: str | None = None) -> Any:
        try:
            if expr.kind == "name":
                if expr.value not in env:
                    raise TypeErrorS31(f"unknown value {expr.value}")
                return env[expr.value]
            if expr.kind == "number":
                raise TypeErrorS31("field literals require the _m31 suffix")
            if expr.kind == "field":
                number = int(expr.value[:-4])
                if not 0 <= number < P:
                    raise TypeErrorS31("m31 literal must be canonical")
                return number
            if expr.kind == "array":
                values = tuple(self.eval_expr(item, env) for item in expr.args)
                if not values:
                    raise TypeErrorS31("static array cannot be empty")
                if not all(isinstance(value, (Value, StaticGroup)) for value in values):
                    raise TypeErrorS31("static array elements must be circuit values or static arrays")
                return StaticGroup(values)
            if expr.kind == "binary":
                lhs = self.expect_value(self.eval_expr(expr.args[0], env), expr.args[0])
                rhs = self.expect_value(self.eval_expr(expr.args[1], env), expr.args[1])
                return self.builder.binary("add" if expr.value == "+" else "mul", lhs, rhs,
                                           wanted=wanted, span=self.span(expr))
            if expr.kind != "call":
                raise TypeErrorS31("invalid expression")
            name = STANDARD_ALIASES.get(expr.value, expr.value)
            if name == "std::array::get":
                if expr.generic is None or len(expr.args) != 1:
                    raise TypeErrorS31("std::array::get<K>(array) expected")
                value = self.eval_expr(expr.args[0], env)
                if not isinstance(value, (Value, StaticGroup)):
                    raise TypeErrorS31("std::array::get requires an array")
                return self.builder.array_get(value, expr.generic, wanted=wanted, span=self.span(expr))
            if name == "std::array::concat":
                if expr.generic is not None or len(expr.args) != 2:
                    raise TypeErrorS31("std::array::concat(a,b) expected")
                values = tuple(self.eval_expr(arg, env) for arg in expr.args)
                if not all(isinstance(value, (Value, StaticGroup)) for value in values):
                    raise TypeErrorS31("std::array::concat requires arrays")
                return self.builder.array_concat(*values, wanted=wanted, span=self.span(expr))
            if name in mathlib.BUILTINS:
                if name == "std::math::pow":
                    if expr.generic is None or len(expr.args) != 1:
                        raise TypeErrorS31("std::math::pow<N>(value) expected")
                    value = self.expect_value(self.eval_expr(expr.args[0], env), expr.args[0])
                    return mathlib.pow_static(self.builder, value, expr.generic,
                                              wanted=wanted, span=self.span(expr))
                if expr.generic is not None:
                    raise TypeErrorS31(f"{name} does not accept a static parameter")
                if name == "std::math::matvec":
                    if len(expr.args) != 2:
                        raise TypeErrorS31("std::math::matvec expects a matrix and vector")
                    matrix, vector = (self.eval_expr(arg, env) for arg in expr.args)
                    return mathlib.matvec(self.builder, matrix, vector, span=self.span(expr))
                if name in {"std::math::sum", "std::math::dot", "std::math::poly_eval"}:
                    args = tuple(self.eval_expr(arg, env) for arg in expr.args)
                    arity = 1 if name == "std::math::sum" else 2
                    if len(args) != arity:
                        raise TypeErrorS31(f"{name} expects {arity} arguments")
                    if name == "std::math::sum":
                        return mathlib.sum_static(self.builder, args[0], wanted=wanted,
                                                  span=self.span(expr))
                    if name == "std::math::dot":
                        return mathlib.dot_static(self.builder, args[0], args[1],
                                                  wanted=wanted, span=self.span(expr))
                    return mathlib.poly_eval(self.builder, self.expect_value(args[0], expr), args[1],
                                             wanted=wanted, span=self.span(expr))
                if name in {"std::math::sum_lanes", "std::math::dot_lanes"}:
                    arity = 1 if name == "std::math::sum_lanes" else 2
                    if len(expr.args) != arity:
                        raise TypeErrorS31(f"{name} expects {arity} arguments")
                    values = tuple(self.expect_value(self.eval_expr(arg, env), arg)
                                   for arg in expr.args)
                    operation = (mathlib.sum_lanes if arity == 1 else mathlib.dot_lanes)
                    return operation(self.builder, *values, wanted=wanted, span=self.span(expr))
                values = tuple(self.expect_value(self.eval_expr(arg, env), arg) for arg in expr.args)
                arity = 2 if name in {"std::math::sub", "std::math::div", "std::math::add_u256", "std::math::add_u256_checked", "std::math::sub_u256", "std::math::sub_u256_checked", "std::math::le_u256"} else 1
                if len(values) != arity:
                    raise TypeErrorS31(f"{name} expects {arity} arguments")
                operation = {"std::math::neg": mathlib.neg, "std::math::sub": mathlib.sub,
                             "std::math::square": mathlib.square, "std::math::inv": mathlib.inv,
                             "std::math::div": mathlib.div,
                             "std::math::add_u256": mathlib.add_u256,
                             "std::math::add_u256_checked": mathlib.add_u256_checked,
                             "std::math::sub_u256": mathlib.sub_u256,
                             "std::math::sub_u256_checked": mathlib.sub_u256_checked,
                             "std::math::le_u256": mathlib.le_u256}[name]
                return operation(self.builder, *values, wanted=wanted, span=self.span(expr))
            if name == "iterate":
                if expr.generic is None or len(expr.args) != 2 or expr.args[0].kind != "name":
                    raise TypeErrorS31("iterate<N>(step_function, initial_value) expected")
                fn_name = expr.args[0].value
                if fn_name not in self.functions:
                    raise TypeErrorS31(f"unknown step function {fn_name}")
                start = self.expect_value(self.eval_expr(expr.args[1], env), expr.args[1])
                steps = self.step_function(fn_name, start.typ, expr)
                return self.builder.repeat(expr.generic, start, steps, wanted=wanted, span=self.span(expr))
            if expr.generic is not None and name != "splat":
                raise TypeErrorS31(f"{name} does not accept a static parameter")
            args = tuple(self.eval_expr(item, env) for item in expr.args)
            if name == "splat":
                if expr.generic is None or len(args) != 1 or not isinstance(args[0], int):
                    raise TypeErrorS31("splat<N>(constant_m31) expected")
                return self.builder.splat(args[0], expr.generic)
            if name == "m31_from_u16" and len(args) == 1:
                value = self.expect_value(args[0], expr)
                if value.typ.kind != "u16":
                    raise TypeErrorS31("m31_from_u16 requires a [u16; N] value; use std::bytes::limbs_m31 for wide values")
                return self.builder.cast_m31(value, wanted=wanted, span=self.span(expr))
            if name in {"std::bytes::to_u256_le", "std::bytes::from_u256_le"} and len(args) == 1:
                target = "uint256" if name.endswith("to_u256_le") else "bytes32"
                return self.builder.bytes32_reinterpret(self.expect_value(args[0], expr), target)
            if name == "std::bytes::limbs_m31" and len(args) == 1:
                value = self.expect_value(args[0], expr)
                if value.typ.kind not in {"uint256", "bytes32"}:
                    raise TypeErrorS31("limbs_m31 requires UInt256 or Bytes32")
                return self.builder.cast_m31(value, wanted=wanted, span=self.span(expr))
            if name in {"poseidon2_leaf", "blake2s_leaf"} and len(args) == 1:
                family = "poseidon2" if name.startswith("poseidon2") else "blake2s_reduced"
                return self.builder.hash_leaf(family, self.expect_value(args[0], expr), wanted=wanted, span=self.span(expr))
            if name == "sha256d_header" and len(args) == 1:
                return self.builder.sha256d_header(self.expect_value(args[0], expr), wanted=wanted, span=self.span(expr))
            if name == "block_hash" and len(args) == 1:
                return self.builder.bitcoin_block_hash(self.expect_value(args[0], expr), wanted=wanted, span=self.span(expr))
            if name == "hash_bytes" and len(args) == 1:
                return self.builder.bitcoin_hash_bytes(self.expect_value(args[0], expr))
            if name == "parent_hash" and len(args) == 1:
                return self.builder.bitcoin_parent_hash(self.expect_value(args[0], expr), wanted=wanted, span=self.span(expr))
            if name == "target_mainnet" and len(args) == 1:
                return self.builder.bitcoin_target_mainnet(self.expect_value(args[0], expr), wanted=wanted, span=self.span(expr))
            if name == "prev_hash" and len(args) == 1:
                return self.builder.header_prev_hash(self.expect_value(args[0], expr), wanted=wanted, span=self.span(expr))
            if name == "header_bits" and len(args) == 1:
                return self.builder.header_bits(self.expect_value(args[0], expr), wanted=wanted, span=self.span(expr))
            if name == "header_time" and len(args) == 1:
                return self.builder.header_time(self.expect_value(args[0], expr), wanted=wanted, span=self.span(expr))
            if name == "lt_u32" and len(args) == 2:
                return self.builder.lt_u32(*(self.expect_value(arg, expr) for arg in args), wanted=wanted, span=self.span(expr))
            if name == "genesis_hash_mainnet" and len(args) == 0:
                return self.builder.genesis_hash_mainnet(wanted=wanted, span=self.span(expr))
            if name == "genesis_block_hash_mainnet" and len(args) == 0:
                return self.builder.genesis_block_hash_mainnet(wanted=wanted, span=self.span(expr))
            if name in {"poseidon2_pair", "blake2s_pair"} and len(args) == 2:
                family = "poseidon2" if name.startswith("poseidon2") else "blake2s_reduced"
                return self.builder.hash_pair(family, *(self.expect_value(arg, expr) for arg in args),
                                              wanted=wanted, span=self.span(expr))
            if name == "select" and len(args) == 3:
                return self.builder.select(*(self.expect_value(arg, expr) for arg in args),
                                           wanted=wanted, span=self.span(expr))
            if name == "is_zero" and len(args) == 1:
                return self.builder.is_zero(self.expect_value(args[0], expr),
                                            wanted=wanted, span=self.span(expr))
            if name in {"merkle_path_poseidon2", "merkle_path_blake2s"} and len(args) == 3:
                family = "poseidon2" if name.endswith("poseidon2") else "blake2s_reduced"
                if not isinstance(args[1], StaticGroup) or not isinstance(args[2], StaticGroup):
                    raise TypeErrorS31("merkle_path sibling and direction lists must be static arrays")
                return self.builder.merkle_path(family, self.expect_value(args[0], expr), args[1], args[2],
                                                wanted=wanted, span=self.span(expr))
            if name in self.functions and expr.generic is None:
                return self.call_function(name, args, wanted, expr)
            raise TypeErrorS31(f"unknown builtin or wrong arity: {name}")
        except TypeErrorS31 as exc:
            raise self.located(expr, exc) from exc

    def step_function(self, name: str, typ: Type, site: Expr) -> tuple[dict[str, Any], ...]:
        fn = self.functions[name]
        if len(fn.params) != 1 or fn.params[0][1] != typ or fn.result != typ or typ.kind != "m31":
            raise self.located(site, "iterate step must have type [m31; N] -> [m31; N]")
        state = self.step_block(fn, {fn.params[0][0]: StepState(typ, ())}, site)
        if not isinstance(state, StepState) or not state.steps:
            raise self.located(site, "iterate step must transform its input")
        return state.steps

    def step_block(self, fn: Function, env: dict[str, Any], site: Expr) -> Any:
        if fn.name in self.call_stack or len(self.call_stack) >= MAX_CALL_DEPTH:
            raise self.located(site, "recursive step function")
        self.call_stack.append(fn.name)
        try:
            local = env.copy()
            for statement in fn.statements:
                if statement.kind != "let":
                    raise self.located(site, "iterate step cannot contain assertions")
                if statement.name in local:
                    raise self.located(site, f"duplicate local name {statement.name}")
                local[statement.name] = self.step_expr(statement.args[0], local)
            return self.step_expr(fn.body, local)
        finally:
            self.call_stack.pop()

    def step_expr(self, expr: Expr, env: dict[str, Any]) -> Any:
        if expr.kind == "name":
            if expr.value not in env:
                raise self.located(expr, f"unknown step value {expr.value}")
            return env[expr.value]
        if expr.kind == "field":
            number = int(expr.value[:-4])
            if not 0 <= number < P:
                raise self.located(expr, "m31 literal must be canonical")
            return number
        if expr.kind == "call" and expr.value == "splat":
            if expr.generic is None or len(expr.args) != 1:
                raise self.located(expr, "splat<N>(constant_m31) expected")
            constant = self.step_expr(expr.args[0], env)
            if not isinstance(constant, int):
                raise self.located(expr, "step splat requires a static constant")
            return self.builder.splat(constant, expr.generic)
        if expr.kind == "call" and expr.value == "std::math::square":
            if expr.generic is not None or len(expr.args) != 1:
                raise self.located(expr, "std::math::square(step_state) expected")
            value = self.step_expr(expr.args[0], env)
            if not isinstance(value, StepState):
                raise self.located(expr, "iterate can square only its current state")
            if len(value.steps) >= 16:
                raise self.located(expr, "iterate body exceeds sixteen steps")
            return StepState(value.typ, value.steps + ({"op": "square"},))
        if expr.kind == "call" and expr.value == "std::math::mix4":
            if expr.generic is not None or len(expr.args) != 1:
                raise self.located(expr, "std::math::mix4(step_state) expected")
            value = self.step_expr(expr.args[0], env)
            if not isinstance(value, StepState) or value.typ != Type("m31", 4):
                raise self.located(expr, "std::math::mix4 requires the current [m31; 4] state")
            if len(value.steps) >= 16:
                raise self.located(expr, "iterate body exceeds sixteen steps")
            return StepState(value.typ, value.steps + ({"op": "mix4"},))
        if expr.kind == "call" and expr.value in self.functions and expr.generic is None:
            fn = self.functions[expr.value]
            if len(fn.params) != len(expr.args):
                raise self.located(expr, "wrong step function arity")
            args = [self.step_expr(arg, env) for arg in expr.args]
            for (_, typ), value in zip(fn.params, args):
                if not isinstance(value, (StepState, Value)) or value.typ != typ:
                    raise self.located(expr, "step helper argument type mismatch")
            result = self.step_block(fn, {param: value for (param, _), value in zip(fn.params, args)}, expr)
            if not isinstance(result, (StepState, Value)) or result.typ != fn.result:
                raise self.located(expr, "step helper result type mismatch")
            return result
        if expr.kind == "binary":
            lhs, rhs = (self.step_expr(arg, env) for arg in expr.args)
            if isinstance(lhs, StepState) and isinstance(rhs, StepState):
                if expr.value == ".*" and lhs == rhs:
                    if len(lhs.steps) >= 16:
                        raise self.located(expr, "iterate body exceeds sixteen steps")
                    return StepState(lhs.typ, lhs.steps + ({"op": "square"},))
                raise self.located(expr, "iterate supports squaring the same state, not two different states")
            if isinstance(lhs, Value) and lhs.constant is not None:
                lhs, rhs = rhs, lhs
            if isinstance(lhs, StepState) and isinstance(rhs, Value) and rhs.constant is not None:
                if lhs.typ != rhs.typ:
                    raise self.located(expr, "step constant and state shapes differ")
                if len(lhs.steps) >= 16:
                    raise self.located(expr, "iterate body exceeds sixteen steps")
                op = "add_const" if expr.value == "+" else "mul_const"
                return StepState(lhs.typ, lhs.steps + ({"op": op, "constant": rhs.constant},))
        raise self.located(expr, "iterate step must use square, add_const, mul_const, or mix4 operations")

    def compile(self) -> tuple[dict[str, Any], dict[str, dict[str, int]]]:
        env = {name: self.builder.input(name, typ, visibility)
               for name, typ, visibility in self.circuit.params}
        result = self.eval_block(self.circuit.statements, self.circuit.body, env)
        return self.builder.finish(result, self.circuit.result,
                                   span=self.span(self.circuit.body)), self.builder.source_map


def compile_text(source: str, filename: str = "<source>") -> tuple[dict[str, Any], dict[str, dict[str, int]]]:
    try:
        functions, circuit = Parser(source, filename).parse()
        if circuit.name in functions:
            raise SourceError(f"{filename}: circuit name conflicts with a function")
        return Compiler(functions, circuit, filename).compile()
    except RecursionError as exc:
        raise SourceError(f"{filename}: expression nesting limit exceeded") from exc


def compile_file(path: Path) -> tuple[dict[str, Any], dict[str, dict[str, int]]]:
    return compile_text(path.read_text(), str(path))
