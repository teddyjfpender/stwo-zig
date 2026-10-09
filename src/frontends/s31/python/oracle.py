"""Independent value oracle for S31 relation IR v1.

This module deliberately does not import the S31 compiler, runtime, or standard
library. It checks the author's normalized relation against an assignment using
ordinary Python integer arithmetic. Passing this check is useful evidence that
the claimed values match the relation, but it does not establish that the
compiled circuit constrains the same relation or that a proof is sound.

Poseidon2 uses a separate Python permutation implementation with the pinned
constants from the repository; BLAKE2s uses Python's standard library.
Unknown future operations raise UnsupportedOperation, never a success result.
"""

from __future__ import annotations

import sys
from pathlib import Path
S31_SOURCE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(S31_SOURCE_ROOT / "python"))

import hashlib
import re
import struct
from collections.abc import Mapping
from typing import Any


P = 2**31 - 1
_NAME = re.compile(r"[A-Za-z0-9_]{1,128}\Z")
_HASH_OPS = frozenset({
    "hash_blake2s", "hash_blake2s_leaf", "hash_blake2s_pair",
    "hash_poseidon2_leaf", "hash_poseidon2_pair",
})
_OPS = frozenset({"constant", "cast_m31", "array_get", "array_concat", "array_slice", "add", "mul", "inv", "is_zero", "bool_not", "bool_and", "bool_or", "bool_xor", "bool_select", "add_const",
                  "mul_const", "sum_lanes", "select", "repeat",
                  "u256_add", "u256_le", "u256_add_checked", "u256_sub", "u256_sub_checked",
                  "int_view", "int_add_checked", "int_add_wrapping", "int_sub_checked", "int_sub_wrapping", "int_le",
                  "hash_sha256d_header", "bitcoin_target_mainnet", "bitcoin_block_work",
                  "bitcoin_prev_hash", "bitcoin_header_bits", "bitcoin_header_time", "u32_lt",
                  "bitcoin_genesis_hash_mainnet"}) | _HASH_OPS
_NODE_FIELDS = frozenset({"name", "op", "lhs", "rhs", "selector",
                          "constant", "length", "rounds", "body", "index"})


class OracleError(ValueError):
    """The relation, assignment, or claimed result fails the oracle check."""


class UnsupportedOperation(OracleError):
    """The relation contains an operation not independently evaluated here."""


def _object(value: Any, path: str, allowed: set[str] | frozenset[str] | None) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise OracleError(f"{path} must be an object")
    if allowed is not None:
        extra = set(value) - allowed
        if extra:
            raise OracleError(f"{path} has unknown fields: {sorted(map(str, extra))}")
    return value


def _array(value: Any, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise OracleError(f"{path} must be an array")
    return value


def _uint(value: Any, path: str, limit: int) -> int:
    # bool is a subclass of int in Python; it is not a JSON integer in Zig.
    if type(value) is not int or not 0 <= value < limit:
        raise OracleError(f"{path} must be an integer in 0..{limit - 1}")
    return value


def _name(value: Any, path: str) -> str:
    if not isinstance(value, str) or _NAME.fullmatch(value) is None:
        raise OracleError(f"{path} must be a 1..128 character ASCII identifier")
    return value


def _operand(node: Mapping[str, Any], field: str, shapes: Mapping[str, tuple[str, int]]) -> tuple[str, int] | None:
    value = node.get(field)
    if value is None:
        return None
    name = _name(value, f"node.{field}")
    if name not in shapes:
        raise OracleError(f"node.{field} refers to unknown or forward value {name!r}")
    return shapes[name]


def _absent(node: Mapping[str, Any], *fields: str) -> None:
    for field in fields:
        if node.get(field) is not None:
            raise OracleError(f"{node['name']}: unexpected {field} for {node['op']}")


def _same_m31(node: Mapping[str, Any], lhs: tuple[str, int] | None,
              rhs: tuple[str, int] | None = None) -> tuple[str, int]:
    if lhs is None or lhs[0] != "m31" or (rhs is not None and rhs != lhs):
        raise OracleError(f"{node['name']}: {node['op']} requires equally shaped m31 operands")
    return lhs


def _int_spec(node: Mapping[str, Any]) -> tuple[int, bool, int]:
    spec = _uint(node.get("constant"), f"{node['name']}.constant", 385)
    width, signed = spec & 255, bool(spec & 256)
    if width not in (8, 16, 32, 64, 128) or spec != width | (256 if signed else 0):
        raise OracleError(f"{node['name']}: invalid fixed-width integer spec")
    return width, signed, max(1, width // 16)


def _validated_shapes(relation: Mapping[str, Any]) -> tuple[dict[str, tuple[str, int]], int]:
    _object(relation, "relation", {"version", "name", "proof_mode", "inputs", "nodes", "assertions", "public_outputs"})
    if relation.get("proof_mode", "transparent") not in ("transparent", "blinded"):
        raise OracleError("relation.proof_mode must be transparent or blinded")
    if relation.get("version") != 1 or type(relation.get("version")) is not int:
        raise OracleError("relation.version must be 1")
    _name(relation.get("name"), "relation.name")
    shapes: dict[str, tuple[str, int]] = {}
    public_words = 0
    for index, raw in enumerate(_array(relation.get("inputs"), "relation.inputs")):
        item = _object(raw, f"inputs[{index}]", {"name", "kind", "length", "visibility"})
        name = _name(item.get("name"), f"inputs[{index}].name")
        if name in shapes:
            raise OracleError(f"duplicate value name {name!r}")
        kind = item.get("kind")
        visibility = item.get("visibility")
        if kind not in ("u16", "m31") or visibility not in ("public", "private"):
            raise OracleError(f"inputs[{index}] has invalid kind or visibility")
        length = _uint(item.get("length"), f"inputs[{index}].length", 4097)
        if length == 0:
            raise OracleError(f"inputs[{index}].length must be positive")
        shapes[name] = (kind, length)
        if visibility == "public":
            public_words += length

    for index, raw in enumerate(_array(relation.get("nodes"), "relation.nodes")):
        node = _object(raw, f"nodes[{index}]", _NODE_FIELDS)
        name = _name(node.get("name"), f"nodes[{index}].name")
        if name in shapes:
            raise OracleError(f"duplicate value name {name!r}")
        op = node.get("op")
        if not isinstance(op, str) or op not in _OPS:
            raise UnsupportedOperation(f"{name}: unsupported relation operation {op!r}")
        lhs = _operand(node, "lhs", shapes)
        rhs = _operand(node, "rhs", shapes)
        selector = _operand(node, "selector", shapes)
        if op not in {"select", "bool_select"}:
            _absent(node, "selector")
        if op not in {"array_get", "array_slice"}:
            _absent(node, "index")
        if op == "constant":
            _absent(node, "lhs", "rhs", "rounds", "body")
            _uint(node.get("constant"), f"{name}.constant", P)
            length = _uint(node.get("length"), f"{name}.length", 4097)
            if length == 0:
                raise OracleError(f"{name}.length must be positive")
            shape = ("m31", length)
        elif op == "cast_m31":
            _absent(node, "rhs", "constant", "length", "rounds", "body")
            if lhs is None or lhs[0] != "u16":
                raise OracleError(f"{name}: cast_m31 requires a u16 operand")
            shape = ("m31", lhs[1])
        elif op == "array_get":
            _absent(node, "rhs", "constant", "length", "rounds", "body")
            if lhs is None or lhs[0] not in {"m31", "u16"}:
                raise OracleError(f"{name}: array_get requires an m31 or u16 array")
            _uint(node.get("index"), f"{name}.index", lhs[1])
            shape = (lhs[0], 1)
        elif op == "array_slice":
            _absent(node, "rhs", "constant", "rounds", "body")
            if lhs is None or lhs[0] not in {"m31", "u16"}:
                raise OracleError(f"{name}: array_slice requires an m31 or u16 array")
            start = _uint(node.get("index"), f"{name}.index", lhs[1])
            length = _uint(node.get("length"), f"{name}.length", lhs[1] + 1)
            if length == 0 or start + length > lhs[1]:
                raise OracleError(f"{name}: array_slice must be nonempty and inside the source")
            shape = (lhs[0], length)
        elif op == "array_concat":
            _absent(node, "constant", "length", "rounds", "body")
            if lhs is None or rhs is None or lhs[0] != rhs[0] or lhs[0] not in {"m31", "u16"}:
                raise OracleError(f"{name}: array_concat requires equal m31 or u16 element types")
            if lhs[1] + rhs[1] > 4096:
                raise OracleError(f"{name}: array_concat exceeds 4096 elements")
            shape = (lhs[0], lhs[1] + rhs[1])
        elif op in ("add", "mul"):
            _absent(node, "constant", "length", "rounds", "body")
            if rhs is None:
                raise OracleError(f"{name}: missing rhs")
            shape = _same_m31(node, lhs, rhs)
        elif op == "inv":
            _absent(node, "rhs", "constant", "length", "rounds", "body")
            shape = _same_m31(node, lhs)
        elif op == "is_zero":
            _absent(node, "rhs", "constant", "length", "rounds", "body")
            if lhs != ("m31", 1):
                raise OracleError(f"{name}: is_zero requires scalar m31")
            shape = ("m31", 1)
        elif op == "bool_not":
            _absent(node, "rhs", "constant", "length", "rounds", "body")
            if lhs != ("m31", 1):
                raise OracleError(f"{name}: bool_not requires scalar m31")
            shape = ("m31", 1)
        elif op in {"bool_and", "bool_or", "bool_xor", "bool_select"}:
            _absent(node, "constant", "length", "rounds", "body")
            if lhs != ("m31", 1) or rhs != ("m31", 1):
                raise OracleError(f"{name}: {op} requires two scalar m31 operands")
            if op == "bool_select" and selector != ("m31", 1):
                raise OracleError(f"{name}: bool_select requires a scalar m31 selector")
            shape = ("m31", 1)
        elif op in ("add_const", "mul_const"):
            _absent(node, "rhs", "length", "rounds", "body")
            _uint(node.get("constant"), f"{name}.constant", P)
            shape = _same_m31(node, lhs)
        elif op == "sum_lanes":
            _absent(node, "rhs", "constant", "length", "rounds", "body")
            _same_m31(node, lhs)
            shape = ("m31", 1)
        elif op in ("u256_add", "u256_le", "u256_add_checked", "u256_sub", "u256_sub_checked"):
            _absent(node, "constant", "length", "rounds", "body")
            if lhs != ("u16", 16) or rhs != ("u16", 16):
                raise OracleError(f"{name}: {op} requires two 16-limb u256 operands")
            shape = ("u16", 16) if op in {"u256_add", "u256_add_checked", "u256_sub", "u256_sub_checked"} else ("m31", 1)
        elif op in {"int_view", "int_add_checked", "int_add_wrapping", "int_sub_checked", "int_sub_wrapping", "int_le"}:
            _absent(node, "length", "rounds", "body")
            width, _, limb_count = _int_spec(node)
            if lhs != ("u16", limb_count) or (rhs is not None if op == "int_view" else rhs != lhs):
                raise OracleError(f"{name}: {op} requires {limb_count} u16 limb(s) for {width} bits")
            shape = ("m31", 1) if op == "int_le" else lhs
        elif op == "bitcoin_block_work":
            _absent(node, "rhs", "selector", "constant", "length", "rounds", "body")
            if lhs != ("u16", 16):
                raise OracleError(f"{name}: block_work requires a 16-limb u256 target")
            shape = ("u16", 16)
        elif op == "u32_lt":
            _absent(node, "constant", "length", "rounds", "body")
            if lhs != ("u16", 2) or rhs != ("u16", 2):
                raise OracleError(f"{name}: u32_lt requires two 2-limb u16 operands")
            shape = ("m31", 1)
        elif op in ("hash_sha256d_header", "bitcoin_target_mainnet", "bitcoin_prev_hash", "bitcoin_header_bits", "bitcoin_header_time"):
            _absent(node, "rhs", "constant", "length", "rounds", "body")
            if lhs != ("u16", 40):
                raise OracleError(f"{name}: {op} requires forty u16 limbs")
            shape = ("u16", 2 if op in {"bitcoin_header_bits", "bitcoin_header_time"} else 16)
        elif op == "bitcoin_genesis_hash_mainnet":
            _absent(node, "lhs", "rhs", "selector", "constant", "length", "rounds", "body")
            shape = ("u16", 16)
        elif op == "select":
            _absent(node, "constant", "length", "rounds", "body")
            if rhs is None:
                raise OracleError(f"{name}: missing rhs")
            if lhs is None or rhs != lhs or lhs[0] not in {"m31", "u16"}:
                raise OracleError(f"{name}: select requires equally shaped m31 or u16 operands")
            shape = lhs
            if selector != ("m31", 1):
                raise OracleError(f"{name}: selector must be scalar m31")
        elif op in _HASH_OPS:
            _absent(node, "constant", "length", "rounds", "body")
            if lhs is None or lhs[0] != "m31":
                raise OracleError(f"{name}: {op} requires m31 words")
            if op in ("hash_blake2s_pair", "hash_poseidon2_pair"):
                if lhs[1] != 8 or rhs != ("m31", 8):
                    raise OracleError(f"{name}: ordered pair hash requires two m31[8] digests")
            elif rhs is not None or lhs[1] not in (4, 8, 12, 16):
                raise OracleError(f"{name}: leaf hash requires 4, 8, 12, or 16 m31 words")
            shape = ("m31", 8)
        else:  # repeat
            _absent(node, "rhs", "constant", "length")
            shape = _same_m31(node, lhs)
            rounds = _uint(node.get("rounds"), f"{name}.rounds", 32769)
            if rounds == 0:
                raise OracleError(f"{name}.rounds must be positive")
            body = _array(node.get("body"), f"{name}.body")
            if not 1 <= len(body) <= 16:
                raise OracleError(f"{name}.body needs 1..16 steps")
            for step_index, raw_step in enumerate(body):
                step = _object(raw_step, f"{name}.body[{step_index}]", {"op", "constant"})
                step_op = step.get("op")
                if step_op == "square":
                    if step.get("constant") is not None:
                        raise OracleError(f"{name}.body[{step_index}]: square has no constant")
                elif step_op == "mix4":
                    if step.get("constant") is not None or shape[1] != 4:
                        raise OracleError(f"{name}.body[{step_index}]: mix4 requires four lanes and no constant")
                elif step_op in ("add_const", "mul_const"):
                    _uint(step.get("constant"), f"{name}.body[{step_index}].constant", P)
                else:
                    raise UnsupportedOperation(f"{name}.body[{step_index}]: unsupported step {step_op!r}")
        shapes[name] = shape

    for index, raw in enumerate(_array(relation.get("assertions"), "relation.assertions")):
        assertion = _object(raw, f"assertions[{index}]", {"lhs", "rhs"})
        lhs_name = _name(assertion.get("lhs"), f"assertions[{index}].lhs")
        rhs_name = _name(assertion.get("rhs"), f"assertions[{index}].rhs")
        if lhs_name not in shapes or rhs_name not in shapes:
            raise OracleError(f"assertions[{index}] has unknown operand")
        if shapes[lhs_name] != shapes[rhs_name]:
            raise OracleError(f"assertions[{index}] has mismatched shapes")
    outputs = _array(relation.get("public_outputs"), "relation.public_outputs")
    output_names: set[str] = set()
    for index, raw in enumerate(outputs):
        name = _name(raw, f"public_outputs[{index}]")
        if name not in shapes:
            raise OracleError(f"public_outputs[{index}] has unknown value")
        if name in output_names:
            raise OracleError(f"duplicate public output {name!r}")
        output_names.add(name)
        public_words += shapes[name][1]
    if not 1 <= public_words <= 8:
        raise OracleError("public ABI must contain 1..8 field words")
    return shapes, public_words


def _assigned(values: Mapping[str, Any], name: str, shape: tuple[str, int], path: str) -> list[int]:
    raw = _array(values.get(name), f"{path}.{name}")
    if len(raw) != shape[1]:
        raise OracleError(f"{path}.{name} must have {shape[1]} words")
    bound = 65536 if shape[0] == "u16" else P
    return [_uint(word, f"{path}.{name}[{index}]", bound) for index, word in enumerate(raw)]


def _blake_words(words: list[int], personalization: bytes | None) -> list[int]:
    message = b"".join(word.to_bytes(4, "little") for word in words)
    options = {"person": personalization} if personalization is not None else {}
    digest = hashlib.blake2s(message, digest_size=32, **options).digest()
    return [int.from_bytes(digest[index:index + 4], "little") % P
            for index in range(0, 32, 4)]


def evaluate_relation(relation: Mapping[str, Any], assignment: Mapping[str, Any]) -> dict[str, list[int]]:
    """Check a relation and full assignment; return its computed public outputs.

    This is a value check, independent of the compiler. It requires an exact
    assignment (including claimed public outputs), and raises OracleError on
    malformed values, failed assertions, or a claim that differs from the
    evaluated arithmetic relation.
    """
    shapes, _ = _validated_shapes(relation)
    _object(assignment, "assignment", {"public_inputs", "private_inputs", "public_outputs"})
    public = _object(assignment.get("public_inputs"), "assignment.public_inputs", None)
    private = _object(assignment.get("private_inputs", {}), "assignment.private_inputs", None)
    claimed = _object(assignment.get("public_outputs"), "assignment.public_outputs", None)
    expected_public = {item["name"] for item in relation["inputs"] if item["visibility"] == "public"}
    expected_private = {item["name"] for item in relation["inputs"] if item["visibility"] == "private"}
    expected_outputs = set(relation["public_outputs"])
    for path, actual, expected in (("public_inputs", public, expected_public),
                                   ("private_inputs", private, expected_private),
                                   ("public_outputs", claimed, expected_outputs)):
        if set(actual) != expected:
            raise OracleError(f"assignment.{path} fields must be exactly {sorted(expected)}")
    values: dict[str, list[int]] = {}
    for item in relation["inputs"]:
        name = item["name"]
        source = public if item["visibility"] == "public" else private
        values[name] = _assigned(source, name, shapes[name], item["visibility"] + "_inputs")
    for node in relation["nodes"]:
        name, op = node["name"], node["op"]
        lhs = values[node["lhs"]] if node.get("lhs") is not None else None
        rhs = values[node["rhs"]] if node.get("rhs") is not None else None
        if op == "constant":
            result = [node["constant"]] * node["length"]
        elif op == "cast_m31":
            result = lhs.copy()
        elif op == "array_get":
            result = [lhs[node["index"]]]
        elif op == "array_slice":
            result = lhs[node["index"]:node["index"] + node["length"]]
        elif op == "array_concat":
            result = lhs + rhs
        elif op == "add":
            result = [(a + b) % P for a, b in zip(lhs, rhs)]
        elif op == "mul":
            result = [(a * b) % P for a, b in zip(lhs, rhs)]
        elif op == "inv":
            if 0 in lhs:
                raise OracleError(f"{name}: division by zero")
            result = [pow(x, P - 2, P) for x in lhs]
        elif op == "is_zero":
            result = [int(lhs[0] == 0)]
        elif op in {"bool_not", "bool_and", "bool_or", "bool_xor", "bool_select"}:
            bits = [lhs[0]] + ([] if op == "bool_not" else [rhs[0]])
            if op == "bool_select":
                bits.append(values[node["selector"]][0])
            if any(bit not in (0, 1) for bit in bits):
                raise OracleError(f"{name}: Boolean operands must be 0 or 1")
            a = bits[0]
            b = bits[1] if len(bits) > 1 else 0
            result = [{"bool_not": 1 - a, "bool_and": a & b, "bool_or": a | b,
                       "bool_xor": a ^ b, "bool_select": (a if bits[-1] == 0 else b)}[op]]
        elif op == "add_const":
            result = [(a + node["constant"]) % P for a in lhs]
        elif op == "mul_const":
            result = [(a * node["constant"]) % P for a in lhs]
        elif op == "sum_lanes":
            result = [sum(lhs) % P]
        elif op in ("u256_add", "u256_le", "u256_add_checked", "u256_sub", "u256_sub_checked"):
            a = sum(word << (16 * index) for index, word in enumerate(lhs))
            b = sum(word << (16 * index) for index, word in enumerate(rhs))
            if op == "u256_add_checked" and a + b >= 1 << 256:
                raise OracleError(f"{name}: 256-bit addition overflow")
            if op == "u256_sub_checked" and a < b:
                raise OracleError(f"{name}: 256-bit subtraction underflow")
            result = ([int(a <= b)] if op == "u256_le" else
                      [(((a - b) if op in {"u256_sub", "u256_sub_checked"} else (a + b)) >> (16 * index)) & 0xffff
                       for index in range(16)])
        elif op in {"int_view", "int_add_checked", "int_add_wrapping", "int_sub_checked", "int_sub_wrapping", "int_le"}:
            width, signed, count = _int_spec(node)
            limit = 1 << width
            a = sum(word << (16 * index) for index, word in enumerate(lhs))
            b = sum(word << (16 * index) for index, word in enumerate(rhs)) if rhs is not None else None
            if a >= limit or (b is not None and b >= limit):
                raise OracleError(f"{name}: integer operand exceeds {width} bits")
            def interpreted(pattern: int) -> int:
                return pattern - limit if signed and pattern >= (limit >> 1) else pattern
            if op == "int_view":
                result = lhs.copy()
            elif op == "int_le":
                result = [int(interpreted(a) <= interpreted(b))]
            else:
                mathematical = interpreted(a) + interpreted(b) if "add" in op else interpreted(a) - interpreted(b)
                if op.endswith("checked"):
                    low = -(limit >> 1) if signed else 0
                    high = (limit >> 1) - 1 if signed else limit - 1
                    if not low <= mathematical <= high:
                        raise OracleError(f"{name}: checked integer arithmetic overflow")
                bits = mathematical % limit
                result = [(bits >> (16 * index)) & 0xffff for index in range(count)]
        elif op == "hash_sha256d_header":
            header = struct.pack("<40H", *lhs)
            first = hashlib.sha256(header).digest()
            result = list(struct.unpack("<16H", hashlib.sha256(first).digest()))
        elif op == "bitcoin_target_mainnet":
            header = struct.pack("<40H", *lhs)
            compact = int.from_bytes(header[72:76], "little")
            exponent, mantissa = compact >> 24, compact & 0x7fffff
            if compact & 0x800000 or not 1 <= exponent <= 32 or not mantissa:
                raise OracleError(f"{name}: invalid mainnet compact target")
            target = (mantissa >> (8 * (3 - exponent)) if exponent <= 3
                      else mantissa << (8 * (exponent - 3)))
            if not 0 < target <= 0xffff << 208:
                raise OracleError(f"{name}: target exceeds mainnet powLimit or is zero")
            result = [(target >> (16 * index)) & 0xffff for index in range(16)]
        elif op == "bitcoin_block_work":
            target = sum(word << (16 * index) for index, word in enumerate(lhs))
            if not 0 < target < (1 << 256) - 1:
                raise OracleError(f"{name}: block_work target must be in 1..2^256-2")
            work = (1 << 256) // (target + 1)
            result = [(work >> (16 * index)) & 0xffff for index in range(16)]
        elif op == "u32_lt":
            result = [int(lhs[0] + (lhs[1] << 16) < rhs[0] + (rhs[1] << 16))]
        elif op in ("bitcoin_prev_hash", "bitcoin_header_bits", "bitcoin_header_time"):
            start = 2 if op == "bitcoin_prev_hash" else 34 if op == "bitcoin_header_time" else 36
            result = lhs[start:start + (16 if op == "bitcoin_prev_hash" else 2)]
        elif op == "bitcoin_genesis_hash_mainnet":
            result = list(struct.unpack("<16H", bytes.fromhex(
                "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000")))
        elif op == "select":
            bit = values[node["selector"]][0]
            if bit not in (0, 1):
                raise OracleError(f"{name}: selector must be 0 or 1")
            result = (lhs if bit == 0 else rhs).copy()
        elif op == "hash_blake2s":
            result = _blake_words(lhs, None)
        elif op == "hash_blake2s_leaf":
            result = _blake_words(lhs, b"S31LEAF1")
        elif op == "hash_blake2s_pair":
            result = _blake_words(lhs + rhs, b"S31PAIR1")
        elif op == "hash_poseidon2_leaf":
            from poseidon2_oracle import leaf

            result = leaf(lhs)
        elif op == "hash_poseidon2_pair":
            from poseidon2_oracle import pair

            result = pair(lhs, rhs)
        else:  # repeat
            result = lhs.copy()
            for _ in range(node["rounds"]):
                for step in node["body"]:
                    if step["op"] == "square":
                        result = [(v * v) % P for v in result]
                    elif step["op"] == "add_const":
                        result = [(v + step["constant"]) % P for v in result]
                    elif step["op"] == "mix4":
                        total = sum(result) % P
                        result = [(v + total) % P for v in result]
                    else:
                        result = [(v * step["constant"]) % P for v in result]
        values[name] = result
    for index, assertion in enumerate(relation["assertions"]):
        if values[assertion["lhs"]] != values[assertion["rhs"]]:
            raise OracleError(f"assertions[{index}] failed")
    computed: dict[str, list[int]] = {}
    for name in relation["public_outputs"]:
        actual = values[name]
        expected = _assigned(claimed, name, shapes[name], "public_outputs")
        if actual != expected:
            raise OracleError(f"public_outputs.{name} does not match computed relation value")
        computed[name] = actual.copy()
    return computed
