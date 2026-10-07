"""Typed, proof-aware primitives for the first S31 text frontend.

This module only constructs the existing normalized relation. The Zig validator,
witness evaluator, AIR compiler, and generated native verifier remain authoritative.
Types erased by that relation (bit, digest families, and 256-bit values) are
checked here first. UInt256 and Bytes32 use sixteen little-endian u16 limbs.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Any


P = (1 << 31) - 1
STDLIB_ABI_VERSION = 1
MAX_NODES = 100_000


class TypeErrorS31(ValueError):
    pass


@dataclass(frozen=True)
class Type:
    kind: str
    length: int
    family: str = ""

    def __post_init__(self) -> None:
        if self.length < 1 or self.length > 4096:
            raise TypeErrorS31("array length must be 1..4096")
        if self.kind not in {"m31", "u16", "bit", "digest", "uint256", "bytes32", "bytes80", "blockhash"}:
            raise TypeErrorS31(f"unsupported type {self.kind}")
        if self.kind == "bit" and self.length != 1:
            raise TypeErrorS31("bit is a single constrained field value")
        if self.kind == "digest" and (self.length != 8 or self.family not in {"poseidon2", "blake2s_reduced"}):
            raise TypeErrorS31("digest must name a supported eight-word hash family")
        if self.kind in {"uint256", "bytes32", "blockhash"} and (self.length != 16 or self.family):
            raise TypeErrorS31("256-bit values require sixteen little-endian u16 limbs")
        if self.kind == "bytes80" and (self.length != 40 or self.family):
            raise TypeErrorS31("Bytes80 requires forty little-endian u16 limbs")

    def relation_shape(self) -> tuple[str, int]:
        return ("u16" if self.kind in {"u16", "uint256", "bytes32", "bytes80", "blockhash"} else "m31", self.length)


@dataclass(frozen=True)
class Value:
    typ: Type
    ref: str | None = None
    constant: int | None = None


@dataclass(frozen=True)
class StaticGroup:
    # A compile-time list of references. Nested groups describe fixed matrices.
    elements: tuple[Value | StaticGroup, ...]


@dataclass(frozen=True)
class StepState:
    typ: Type
    steps: tuple[dict[str, Any], ...]


class Builder:
    def __init__(self, name: str) -> None:
        self.name = name
        self.inputs: list[dict[str, Any]] = []
        self.nodes: list[dict[str, Any]] = []
        self.assertions: list[dict[str, str]] = []
        self.used_names: set[str] = set()
        self.reserved_names: set[str] = set()
        self.source_map: dict[str, dict[str, int]] = {}
        self.bit_inputs: set[str] = set()
        self.constrained_bits: set[str] = set()
        self.computed_bits: set[str] = set()
        self.inverse_cache: dict[str, Value] = {}
        self.next_temp = 0

    def unique(self, wanted: str | None = None) -> str:
        if wanted is not None:
            if wanted in self.used_names:
                raise TypeErrorS31(f"duplicate relation name {wanted}")
            name = wanted
        else:
            while (f"_s31_{self.next_temp}" in self.used_names or
                   f"_s31_{self.next_temp}" in self.reserved_names):
                self.next_temp += 1
            name = f"_s31_{self.next_temp}"
            self.next_temp += 1
        if len(name) > 128:
            raise TypeErrorS31("relation names may contain at most 128 characters")
        self.used_names.add(name)
        return name

    def input(self, name: str, typ: Type, visibility: str) -> Value:
        self.unique(name)
        kind, length = typ.relation_shape()
        self.inputs.append({"name": name, "kind": kind, "length": length, "visibility": visibility})
        if typ.kind == "bit":
            self.bit_inputs.add(name)
        return Value(typ, ref=name)

    def emit(self, op: str, typ: Type, *, wanted: str | None = None,
             span: dict[str, int] | None = None, **fields: Any) -> Value:
        if len(self.nodes) >= MAX_NODES:
            raise TypeErrorS31("node expansion limit exceeded")
        name = self.unique(wanted)
        self.nodes.append({"name": name, "op": op, **fields})
        if span is not None:
            self.source_map[name] = span
        return Value(typ, ref=name)

    def splat(self, number: int, length: int) -> Value:
        if not 0 <= number < P:
            raise TypeErrorS31("m31 literal must be canonical")
        return Value(Type("m31", length), constant=number)

    def realize(self, value: Value, wanted: str | None = None,
                span: dict[str, int] | None = None) -> Value:
        if value.ref is not None:
            return value
        if value.constant is not None:
            return self.emit("constant", value.typ, wanted=wanted, span=span,
                             constant=value.constant, length=value.typ.length)
        raise TypeErrorS31("an array of references cannot be used as a relation value")

    def binary(self, op: str, lhs: Value, rhs: Value, *, wanted: str | None = None,
               span: dict[str, int] | None = None) -> Value:
        if lhs.typ != rhs.typ or lhs.typ.kind != "m31":
            raise TypeErrorS31("arithmetic requires equally shaped m31 arrays")
        if op not in {"add", "mul"}:
            raise TypeErrorS31(f"unsupported arithmetic operation {op}")
        if lhs.constant is not None and rhs.constant is not None:
            result = (lhs.constant + rhs.constant) if op == "add" else (lhs.constant * rhs.constant)
            return self.splat(result % P, lhs.typ.length)
        if lhs.constant is not None:
            lhs, rhs = rhs, lhs
        if rhs.constant is not None:
            return self.emit(f"{op}_const", lhs.typ, wanted=wanted, span=span,
                             lhs=self.realize(lhs).ref, constant=rhs.constant)
        return self.emit(op, lhs.typ, wanted=wanted, span=span,
                         lhs=self.realize(lhs).ref, rhs=self.realize(rhs).ref)

    def sum_lanes(self, value: Value, *, wanted: str | None = None,
                  span: dict[str, int] | None = None) -> Value:
        if value.typ.kind != "m31":
            raise TypeErrorS31("sum_lanes requires a [m31; N] value")
        if value.constant is not None:
            return self.splat(value.constant * value.typ.length % P, 1)
        if value.typ.length == 1:
            return value
        return self.emit("sum_lanes", Type("m31", 1), wanted=wanted,
                         span=span, lhs=self.realize(value).ref)

    def inverse(self, value: Value, *, wanted: str | None = None,
                span: dict[str, int] | None = None) -> Value:
        if value.typ.kind != "m31":
            raise TypeErrorS31("inverse requires an [m31; N] value")
        if value.constant is not None:
            if value.constant == 0:
                raise TypeErrorS31("inverse of zero is undefined")
            return self.splat(pow(value.constant, P - 2, P), value.typ.length)
        source = self.realize(value).ref
        if source in self.inverse_cache:
            return self.inverse_cache[source]
        result = self.emit("inv", value.typ, wanted=wanted, span=span, lhs=source)
        self.inverse_cache[source] = result
        return result

    def divide(self, lhs: Value, rhs: Value, *, wanted: str | None = None,
               span: dict[str, int] | None = None) -> Value:
        if lhs.typ != rhs.typ or lhs.typ.kind != "m31":
            raise TypeErrorS31("division requires equally shaped [m31; N] values")
        if rhs.constant is not None:
            return self.binary("mul", lhs, self.inverse(rhs), wanted=wanted, span=span)
        return self.binary("mul", lhs, self.inverse(rhs), wanted=wanted, span=span)

    def is_zero(self, value: Value, *, wanted: str | None = None,
                span: dict[str, int] | None = None) -> Value:
        if value.typ != Type("m31", 1):
            raise TypeErrorS31("is_zero requires one [m31; 1] value")
        if value.constant is not None:
            result = self.emit("constant", Type("bit", 1), wanted=wanted,
                               span=span, constant=int(value.constant == 0), length=1)
        else:
            result = self.emit("is_zero", Type("bit", 1), wanted=wanted,
                               span=span, lhs=self.realize(value).ref)
        self.computed_bits.add(result.ref)
        return result

    def cast_m31(self, value: Value, *, wanted: str | None = None,
                 span: dict[str, int] | None = None) -> Value:
        if value.typ.kind not in {"u16", "uint256", "bytes32"}:
            raise TypeErrorS31("m31 limb conversion requires u16-backed values")
        return self.emit("cast_m31", Type("m31", value.typ.length), wanted=wanted,
                         span=span, lhs=self.realize(value).ref)

    def array_get(self, value: Value | StaticGroup, index: int, *,
                  wanted: str | None = None,
                  span: dict[str, int] | None = None) -> Value | StaticGroup:
        if isinstance(value, StaticGroup):
            if not 0 <= index < len(value.elements):
                raise TypeErrorS31("std::array::get index is outside the static array")
            return value.elements[index]
        if value.typ.kind not in {"m31", "u16"}:
            raise TypeErrorS31("std::array::get requires [m31; N] or [u16; N]")
        if not 0 <= index < value.typ.length:
            raise TypeErrorS31("std::array::get index is outside the runtime array")
        if value.constant is not None:
            return self.splat(value.constant, 1)
        return self.emit("array_get", Type(value.typ.kind, 1), wanted=wanted,
                         span=span, lhs=self.realize(value).ref, index=index)

    def array_concat(self, lhs: Value | StaticGroup, rhs: Value | StaticGroup, *,
                     wanted: str | None = None,
                     span: dict[str, int] | None = None) -> Value | StaticGroup:
        if isinstance(lhs, StaticGroup) and isinstance(rhs, StaticGroup):
            if len(lhs.elements) + len(rhs.elements) > 64:
                raise TypeErrorS31("std::array::concat static result exceeds 64 terms")
            return StaticGroup(lhs.elements + rhs.elements)
        if not isinstance(lhs, Value) or not isinstance(rhs, Value):
            raise TypeErrorS31("std::array::concat requires two static groups or two runtime arrays")
        if lhs.typ.kind != rhs.typ.kind or lhs.typ.kind not in {"m31", "u16"}:
            raise TypeErrorS31("std::array::concat requires arrays with the same m31 or u16 element type")
        length = lhs.typ.length + rhs.typ.length
        if length > 4096:
            raise TypeErrorS31("std::array::concat result exceeds 4096 elements")
        return self.emit("array_concat", Type(lhs.typ.kind, length), wanted=wanted,
                         span=span, lhs=self.realize(lhs).ref, rhs=self.realize(rhs).ref)

    def u256_binary(self, op: str, lhs: Value, rhs: Value, *, wanted: str | None = None,
                    span: dict[str, int] | None = None) -> Value:
        if op not in {"u256_add", "u256_add_checked", "u256_sub", "u256_sub_checked", "u256_le"}:
            raise TypeErrorS31(f"unsupported UInt256 operation {op}")
        if lhs.typ != Type("uint256", 16) or rhs.typ != lhs.typ:
            raise TypeErrorS31(f"{op} requires two UInt256 values")
        result = Type("uint256", 16) if op in {
            "u256_add", "u256_add_checked", "u256_sub", "u256_sub_checked"
        } else Type("m31", 1)
        return self.emit(op, result, wanted=wanted, span=span,
                         lhs=self.realize(lhs).ref, rhs=self.realize(rhs).ref)

    def bytes32_reinterpret(self, value: Value, target: str) -> Value:
        expected = "bytes32" if target == "uint256" else "uint256"
        if value.typ != Type(expected, 16):
            raise TypeErrorS31(f"explicit little-endian conversion requires {expected}")
        return Value(Type(target, 16), ref=self.realize(value).ref)

    def hash_leaf(self, family: str, value: Value, *, wanted: str | None = None,
                  span: dict[str, int] | None = None) -> Value:
        if value.typ.kind != "m31" or value.typ.length not in {4, 8, 12, 16}:
            raise TypeErrorS31("hash leaf requires 4, 8, 12, or 16 m31 words")
        op = {"poseidon2": "hash_poseidon2_leaf", "blake2s_reduced": "hash_blake2s_leaf"}[family]
        return self.emit(op, Type("digest", 8, family), wanted=wanted, span=span,
                         lhs=self.realize(value).ref)

    def sha256d_header(self, value: Value, *, wanted: str | None = None,
                       span: dict[str, int] | None = None) -> Value:
        if value.typ != Type("bytes80", 40):
            raise TypeErrorS31("sha256d_header requires a serialized Bytes80 header")
        return self.emit("hash_sha256d_header", Type("bytes32", 16),
                         wanted=wanted, span=span, lhs=self.realize(value).ref)

    def bitcoin_block_hash(self, header: Value, *, wanted: str | None = None,
                           span: dict[str, int] | None = None) -> Value:
        digest = self.sha256d_header(header, wanted=wanted, span=span)
        return Value(Type("blockhash", 16), ref=digest.ref)

    def bitcoin_hash_bytes(self, value: Value) -> Value:
        if value.typ != Type("blockhash", 16):
            raise TypeErrorS31("hash_bytes requires a BlockHash")
        return Value(Type("bytes32", 16), ref=self.realize(value).ref)

    def bitcoin_target_mainnet(self, value: Value, *, wanted: str | None = None,
                               span: dict[str, int] | None = None) -> Value:
        if value.typ != Type("bytes80", 40):
            raise TypeErrorS31("target_mainnet requires a serialized Bytes80 header")
        return self.emit("bitcoin_target_mainnet", Type("uint256", 16),
                         wanted=wanted, span=span, lhs=self.realize(value).ref)

    def header_prev_hash(self, value: Value, *, wanted: str | None = None,
                         span: dict[str, int] | None = None) -> Value:
        if value.typ != Type("bytes80", 40):
            raise TypeErrorS31("prev_hash requires a serialized Bytes80 header")
        return self.emit("bitcoin_prev_hash", Type("bytes32", 16),
                         wanted=wanted, span=span, lhs=self.realize(value).ref)

    def bitcoin_parent_hash(self, header: Value, *, wanted: str | None = None,
                            span: dict[str, int] | None = None) -> Value:
        digest = self.header_prev_hash(header, wanted=wanted, span=span)
        return Value(Type("blockhash", 16), ref=digest.ref)

    def header_bits(self, value: Value, *, wanted: str | None = None,
                    span: dict[str, int] | None = None) -> Value:
        if value.typ != Type("bytes80", 40):
            raise TypeErrorS31("header_bits requires a serialized Bytes80 header")
        return self.emit("bitcoin_header_bits", Type("u16", 2),
                         wanted=wanted, span=span, lhs=self.realize(value).ref)

    def header_time(self, value: Value, *, wanted: str | None = None,
                    span: dict[str, int] | None = None) -> Value:
        if value.typ != Type("bytes80", 40):
            raise TypeErrorS31("header_time requires a serialized Bytes80 header")
        return self.emit("bitcoin_header_time", Type("u16", 2),
                         wanted=wanted, span=span, lhs=self.realize(value).ref)

    def lt_u32(self, lhs: Value, rhs: Value, *, wanted: str | None = None,
               span: dict[str, int] | None = None) -> Value:
        if lhs.typ != Type("u16", 2) or rhs.typ != lhs.typ:
            raise TypeErrorS31("lt_u32 requires two little-endian [u16; 2] values")
        return self.emit("u32_lt", Type("m31", 1), wanted=wanted, span=span,
                         lhs=self.realize(lhs).ref, rhs=self.realize(rhs).ref)

    def genesis_hash_mainnet(self, *, wanted: str | None = None,
                             span: dict[str, int] | None = None) -> Value:
        return self.emit("bitcoin_genesis_hash_mainnet", Type("bytes32", 16),
                         wanted=wanted, span=span)

    def genesis_block_hash_mainnet(self, *, wanted: str | None = None,
                                   span: dict[str, int] | None = None) -> Value:
        digest = self.genesis_hash_mainnet(wanted=wanted, span=span)
        return Value(Type("blockhash", 16), ref=digest.ref)

    def hash_pair(self, family: str, lhs: Value, rhs: Value, *, wanted: str | None = None,
                  span: dict[str, int] | None = None) -> Value:
        expected = Type("digest", 8, family)
        if lhs.typ != expected or rhs.typ != expected:
            raise TypeErrorS31("hash pair requires two digests of the same family")
        op = {"poseidon2": "hash_poseidon2_pair", "blake2s_reduced": "hash_blake2s_pair"}[family]
        return self.emit(op, expected, wanted=wanted, span=span,
                         lhs=self.realize(lhs).ref, rhs=self.realize(rhs).ref)

    def select(self, bit: Value, lhs: Value, rhs: Value, *, wanted: str | None = None,
               span: dict[str, int] | None = None) -> Value:
        if bit.typ != Type("bit", 1) or lhs.typ != rhs.typ or lhs.typ.kind not in {"m31", "digest"}:
            raise TypeErrorS31("select requires a bit and two equally typed m31 values")
        if bit.ref not in self.bit_inputs and bit.ref not in self.computed_bits:
            raise TypeErrorS31("select requires a constrained bit value")
        if bit.ref in self.bit_inputs:
            self.constrained_bits.add(bit.ref)
        return self.emit("select", lhs.typ, wanted=wanted, span=span,
                         lhs=self.realize(lhs).ref, rhs=self.realize(rhs).ref, selector=bit.ref)

    def repeat(self, rounds: int, start: Value, steps: tuple[dict[str, Any], ...],
               *, wanted: str | None = None, span: dict[str, int] | None = None) -> Value:
        if start.typ.kind != "m31" or not 1 <= rounds <= 32768 or not 1 <= len(steps) <= 16:
            raise TypeErrorS31("iterate requires an m31 array, 1..32768 rounds, and 1..16 static steps")
        if any(step.get("op") == "mix4" for step in steps) and start.typ != Type("m31", 4):
            raise TypeErrorS31("mix4 requires an [m31; 4] iterate state")
        return self.emit("repeat", start.typ, wanted=wanted, span=span,
                         lhs=self.realize(start).ref, rounds=rounds, body=list(steps))

    def assert_equal(self, lhs: Value, rhs: Value) -> None:
        if lhs.typ != rhs.typ:
            raise TypeErrorS31("assert_eq requires two values of the same relation type")
        self.assertions.append({"lhs": self.realize(lhs).ref, "rhs": self.realize(rhs).ref})

    def merkle_path(self, family: str, leaf: Value, siblings: StaticGroup, directions: StaticGroup,
                    *, wanted: str | None = None, span: dict[str, int] | None = None) -> Value:
        if len(siblings.elements) != len(directions.elements):
            raise TypeErrorS31("merkle_path requires equal static arrays of siblings and bits")
        if not 1 <= len(siblings.elements) <= 16:
            raise TypeErrorS31("merkle_path depth must be 1..16")
        digest_type = Type("digest", 8, family)
        current = self.hash_leaf(family, leaf, span=span) if leaf.typ.kind == "m31" else leaf
        if current.typ != digest_type:
            raise TypeErrorS31("merkle_path leaf has the wrong hash family")
        for level, (sibling, direction) in enumerate(zip(siblings.elements, directions.elements)):
            if sibling.typ != digest_type:
                raise TypeErrorS31("merkle_path sibling has the wrong hash family")
            left = self.select(direction, current, sibling, span=span)
            right = self.select(direction, sibling, current, span=span)
            current = self.hash_pair(family, left, right,
                                     wanted=wanted if level == len(siblings.elements) - 1 else None,
                                     span=span)
        return current

    def finish(self, result: Value, output_type: Type,
               span: dict[str, int] | None = None) -> dict[str, Any]:
        if result.typ != output_type:
            raise TypeErrorS31("circuit result does not match declared public output type")
        if self.bit_inputs != self.constrained_bits:
            raise TypeErrorS31("every bit input must be constrained by a select")
        if sum(item["length"] for item in self.inputs if item["visibility"] == "public") + result.typ.length > 8:
            raise TypeErrorS31("current public ABI allows at most eight words")
        value = self.realize(result, span=span)
        return {"version": 1, "name": self.name, "inputs": self.inputs, "nodes": self.nodes,
                "assertions": self.assertions, "public_outputs": [value.ref]}


# Independent value semantics used by library tests; no relation nodes are involved.
def encode_m31_words_le(words: list[int]) -> bytes:
    if any(not 0 <= word < P for word in words):
        raise ValueError("M31 word encoding requires canonical values")
    return b"".join(struct.pack("<I", word) for word in words)


def decode_m31_words_le(encoded: bytes) -> list[int]:
    if len(encoded) % 4:
        raise ValueError("M31 word encoding must be four-byte aligned")
    words = list(struct.unpack(f"<{len(encoded) // 4}I", encoded))
    if any(word >= P for word in words):
        raise ValueError("noncanonical M31 word encoding")
    return words


def decode_u256_le(encoded: bytes) -> list[int]:
    """Convert exactly 32 bytes to the source language's sixteen u16 limbs."""
    if len(encoded) != 32:
        raise ValueError("UInt256/Bytes32 requires exactly 32 bytes")
    return list(struct.unpack("<16H", encoded))


def encode_u256_le(limbs: list[int]) -> bytes:
    if len(limbs) != 16 or any(type(word) is not int or not 0 <= word < 65536 for word in limbs):
        raise ValueError("UInt256/Bytes32 requires sixteen canonical u16 limbs")
    return struct.pack("<16H", *limbs)


def decode_header80(encoded: bytes) -> list[int]:
    """Turn exactly 80 serialized header bytes into S31 `Bytes80` limbs."""
    if len(encoded) != 80:
        raise ValueError("Bytes80 requires exactly 80 serialized bytes")
    return list(struct.unpack("<40H", encoded))


def encode_header80(limbs: list[int]) -> bytes:
    if len(limbs) != 40 or any(type(word) is not int or not 0 <= word < 65536 for word in limbs):
        raise ValueError("Bytes80 requires forty canonical u16 limbs")
    return struct.pack("<40H", *limbs)


def reference_m31_binary(op: str, lhs: list[int], rhs: list[int]) -> list[int]:
    if len(lhs) != len(rhs) or not lhs or any(not 0 <= word < P for word in lhs + rhs):
        raise ValueError("arithmetic needs equally shaped canonical M31 arrays")
    if op == "add":
        return [(a + b) % P for a, b in zip(lhs, rhs)]
    if op == "mul":
        return [(a * b) % P for a, b in zip(lhs, rhs)]
    raise ValueError("unknown M31 arithmetic operation")


def reference_m31_from_u16(words: list[int]) -> list[int]:
    if not words or any(not 0 <= word < 65536 for word in words):
        raise ValueError("cast requires canonical u16 words")
    return words[:]


def reference_select(bit: int, lhs: list[int], rhs: list[int]) -> list[int]:
    if bit not in {0, 1} or len(lhs) != len(rhs) or not lhs:
        raise ValueError("select requires a bit and equally shaped arrays")
    return rhs[:] if bit else lhs[:]


def reference_iterate(words: list[int], rounds: int, steps: tuple[dict[str, Any], ...]) -> list[int]:
    if not words or any(not 0 <= x < P for x in words):
        raise ValueError("expected canonical M31 words")
    state = words[:]
    for _ in range(rounds):
        for step in steps:
            op = step["op"]
            if op == "square":
                state = [x * x % P for x in state]
            elif op == "add_const":
                state = [(x + step["constant"]) % P for x in state]
            elif op == "mul_const":
                state = [x * step["constant"] % P for x in state]
            elif op == "mix4" and len(state) == 4 and step.get("constant") is None:
                total = sum(state) % P
                state = [(x + total) % P for x in state]
            else:
                raise ValueError(f"unknown step {op}")
    return state


def reference_digest(family: str, operation: str, *values: list[int]) -> list[int]:
    if operation == "leaf":
        if len(values) != 1 or len(values[0]) not in {4, 8, 12, 16}:
            raise ValueError("leaf needs 4, 8, 12, or 16 M31 words")
    elif operation == "pair":
        if len(values) != 2 or any(len(value) != 8 for value in values):
            raise ValueError("pair needs two eight-word digests")
    else:
        raise ValueError("digest operation must be leaf or pair")
    if any(not 0 <= word < P for value in values for word in value):
        raise ValueError("digest input must be canonical M31")
    if family == "poseidon2":
        import poseidon2_oracle
        return poseidon2_oracle.leaf(values[0]) if operation == "leaf" else poseidon2_oracle.pair(*values)
    if family != "blake2s_reduced":
        raise ValueError("unknown digest family")
    words = values[0] if operation == "leaf" else values[0] + values[1]
    domain = b"S31LEAF1" if operation == "leaf" else b"S31PAIR1"
    raw = hashlib.blake2s(encode_m31_words_le(words), person=domain).digest()
    return [x % P for x in struct.unpack("<8I", raw)]


def reference_merkle_path(family: str, leaf: list[int], siblings: list[list[int]],
                          directions: list[int], *, prehashed: bool = False) -> list[int]:
    if len(siblings) != len(directions):
        raise ValueError("sibling/direction length mismatch")
    if prehashed:
        if len(leaf) != 8 or any(not 0 <= word < P for word in leaf):
            raise ValueError("prehashed leaf must be an eight-word canonical digest")
        current = leaf[:]
    else:
        current = reference_digest(family, "leaf", leaf)
    for sibling, bit in zip(siblings, directions):
        left = reference_select(bit, current, sibling)
        right = reference_select(bit, sibling, current)
        current = reference_digest(family, "pair", left, right)
    return current
