"""Independent normalized-IR regression corpus for the executable Lean model.

Expected values use Python integers/hashlib and the existing independent oracle.
These checks are not a substitute for the Lean constraint proofs.
"""
from __future__ import annotations

import copy
import hashlib
import json
import struct
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src/frontends/s31/python"))
from oracle import OracleError, evaluate_relation  # noqa: E402
from poseidon2_oracle import leaf, pair  # noqa: E402

P = 2**31 - 1
GENESIS = bytes.fromhex("6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000")


def limbs(value: int, count: int) -> list[int]:
    return [(value >> (16 * i)) & 65535 for i in range(count)]


def number(words: list[int]) -> int:
    return sum(x << (16 * i) for i, x in enumerate(words))


def expected(node: dict, args: list[tuple[str, list[int]]]) -> list[int]:
    op = node["op"]
    a = args[0][1] if args else []
    b = args[1][1] if len(args) > 1 else []
    s = args[2][1][0] if len(args) > 2 else 0
    c = node.get("constant", 0)
    if op == "constant":
        return [c] * node["length"]
    if op == "cast_m31":
        return a.copy()
    if op == "add":
        return [(x + y) % P for x, y in zip(a, b)]
    if op == "mul":
        return [(x * y) % P for x, y in zip(a, b)]
    if op == "add_const":
        return [(x + c) % P for x in a]
    if op == "mul_const":
        return [(x * c) % P for x in a]
    if op == "inv":
        if 0 in a:
            raise ValueError("zero inverse")
        return [pow(x, P - 2, P) for x in a]
    if op == "is_zero":
        return [int(a[0] == 0)]
    if op == "sum_lanes":
        return [sum(a) % P]
    if op in {"select", "bool_select"}:
        return b.copy() if s else a.copy()
    if op == "bool_not":
        return [1 - a[0]]
    if op == "bool_and":
        return [a[0] & b[0]]
    if op == "bool_or":
        return [a[0] | b[0]]
    if op == "bool_xor":
        return [a[0] ^ b[0]]
    if op == "array_get":
        return [a[node["index"]]]
    if op == "array_concat":
        return a + b
    if op == "array_slice":
        return a[node["index"]:node["index"] + node["length"]]
    if op == "repeat":
        a = a.copy()
        for _ in range(node["rounds"]):
            for step in node["body"]:
                if step["op"] == "square":
                    a = [x * x % P for x in a]
                elif step["op"] == "add_const":
                    a = [(x + step["constant"]) % P for x in a]
                elif step["op"] == "mul_const":
                    a = [x * step["constant"] % P for x in a]
                else:
                    total = sum(a)
                    a = [(x + total) % P for x in a]
        return a
    if op.startswith("hash_blake2s"):
        personal = b"S31LEAF1" if op.endswith("leaf") else b"S31PAIR1" if op.endswith("pair") else b""
        message = b"".join(struct.pack("<I", x) for x in a + (b if op.endswith("pair") else []))
        digest = hashlib.blake2s(message, person=personal).digest()
        return [x % P for x in struct.unpack("<8I", digest)]
    if op == "hash_poseidon2_leaf":
        return leaf(a)
    if op == "hash_poseidon2_pair":
        return pair(a, b)
    if op.startswith("u256_"):
        x, y = number(a), number(b)
        if op == "u256_le":
            return [int(x <= y)]
        value = x - y if "sub" in op else x + y
        if op.endswith("checked") and not 0 <= value < 2**256:
            raise ValueError("u256 overflow")
        return limbs(value % 2**256, 16)
    if op == "u32_lt":
        return [int(number(a) < number(b))]
    if op.startswith("int_"):
        width, signed = c % 256, c >= 256
        limit = 2**width
        if number(a) >= limit or (b and number(b) >= limit):
            raise ValueError("integer range")
        def interpret(x):
            return x - limit if signed and x >= limit // 2 else x
        x, y = interpret(number(a)), interpret(number(b))
        if op == "int_view":
            return a.copy()
        if op == "int_le":
            return [int(x <= y)]
        value = x - y if "sub" in op else x + y
        lo, hi = (-limit // 2, limit // 2 - 1) if signed else (0, limit - 1)
        if op.endswith("checked") and not lo <= value <= hi:
            raise ValueError("integer overflow")
        return limbs(value % limit, max(1, width // 16))
    if op == "hash_sha256d_header":
        message = b"".join(struct.pack("<H", x) for x in a)
        return list(struct.unpack("<16H", hashlib.sha256(hashlib.sha256(message).digest()).digest()))
    if op == "bitcoin_genesis_hash_mainnet":
        return list(struct.unpack("<16H", GENESIS))
    if op == "bitcoin_prev_hash":
        return a[2:18]
    if op == "bitcoin_header_time":
        return a[34:36]
    if op == "bitcoin_header_bits":
        return a[36:38]
    if op == "bitcoin_block_work":
        target = number(a)
        if not 0 < target < 2**256 - 1:
            raise ValueError("work target")
        return limbs(2**256 // (target + 1), 16)
    if op == "bitcoin_target_mainnet":
        compact = number(a[36:38])
        exp, mantissa = compact >> 24, compact & 0x7fffff
        if compact & 0x800000 or not 1 <= exp <= 32 or not mantissa:
            raise ValueError("compact target")
        target = mantissa >> (8 * (3 - exp)) if exp <= 3 else mantissa << (8 * (exp - 3))
        if not 0 < target <= 2**224 - 1:
            raise ValueError("target bound")
        return limbs(target, 16)
    raise AssertionError(f"missing fixture semantics: {op}")


@dataclass
class Case:
    name: str
    request: dict
    words: list[int] | None


def operation_case(op: str, args: list[tuple[str, list[int]]], **metadata) -> Case:
    node = {"name": "y", "op": op, **metadata}
    inputs, private = [], {}
    for (name, operand), (kind, words) in zip([("a", "lhs"), ("b", "rhs"), ("s", "selector")], args):
        node[operand] = name
        inputs.append({"name": name, "kind": kind, "length": len(words), "visibility": "private"})
        private[name] = words
    try:
        result = expected(node, args)
    except ValueError:
        result = None
    length = len(result) if result is not None else (16 if op.startswith("u256") or op.startswith("bitcoin") else len(args[0][1]))
    # A sixteen-word operation is private; expose a legal eight-word projection.
    nodes, output = [node], "y"
    if length > 8:
        nodes.append({"name": "out", "op": "array_slice", "lhs": "y", "index": 0, "length": 8})
        output = "out"
        result = result[:8] if result is not None else None
        length = 8
    program = {"version": 1, "name": "formal_parity", "inputs": inputs, "nodes": nodes,
               "assertions": [], "public_outputs": [output]}
    assignment = {"public_inputs": {}, "private_inputs": private,
                  "public_outputs": {output: result if result is not None else [0] * length}}
    return Case(op, {"program": program, "assignment": assignment},
                result + [0] * (8 - length) if result is not None else None)


def corpus() -> list[Case]:
    a, b = [0, 1, P - 1, 123456789], [P - 1, 2, 7, 9876]
    m31 = lambda x: ("m31", x)
    u16 = lambda x: ("u16", x)
    cases = [operation_case("constant", [], constant=P - 1, length=8),
             operation_case("cast_m31", [u16([0, 1, 65535])])]
    for op in ["add", "mul"]:
        cases.append(operation_case(op, [m31(a), m31(b)]))
    for op in ["add_const", "mul_const"]:
        cases.append(operation_case(op, [m31(a)], constant=P - 1))
    for op in ["inv", "sum_lanes"]:
        cases.append(operation_case(op, [m31([1, 2, P - 1, 123456789])]))
    for x in [0, 1, P - 1]:
        cases.append(operation_case("is_zero", [m31([x])]))
    cases.append(operation_case("inv", [m31([1, 0, P - 1])]))
    for bit in [0, 1]:
        for kind in [m31, u16]:
            cases.append(operation_case("select", [kind([7, 65535]), kind([9, 0]), m31([bit])]))
        cases.append(operation_case("bool_not", [m31([bit])]))
        for other in [0, 1]:
            for op in ["bool_and", "bool_or", "bool_xor"]:
                cases.append(operation_case(op, [m31([bit]), m31([other])]))
            for selector in [0, 1]:
                cases.append(operation_case("bool_select", [m31([bit]), m31([other]), m31([selector])]))
    cases.extend([operation_case("array_get", [u16([1, 2, 3, 4])], index=3),
                  operation_case("array_slice", [u16([1, 2, 3, 4])], index=1, length=2),
                  operation_case("array_concat", [u16([1, 2]), u16([3, 4])]),
                  operation_case("repeat", [m31(a)], rounds=3, body=[{"op": "square"},
                      {"op": "add_const", "constant": 5}, {"op": "mul_const", "constant": 3}, {"op": "mix4"}])])
    for length in [4, 8, 12, 16]:
        words = [P - 1, 0] + list(range(2, length))
        for op in ["hash_blake2s", "hash_blake2s_leaf", "hash_poseidon2_leaf"]:
            cases.append(operation_case(op, [m31(words)]))
    for op in ["hash_blake2s_pair", "hash_poseidon2_pair"]:
        cases.append(operation_case(op, [m31(list(range(8))), m31(list(range(8, 16)))]))
    for op in ["u256_add", "u256_add_checked", "u256_sub", "u256_sub_checked", "u256_le"]:
        for x, y in [(65535, 1), (2**256 - 1, 1), (0, 1), (2**255, 2**255)]:
            cases.append(operation_case(op, [u16(limbs(x, 16)), u16(limbs(y, 16))]))
    for x, y in [(65535, 65536), (2**32 - 1, 0), (42, 42)]:
        cases.append(operation_case("u32_lt", [u16(limbs(x, 2)), u16(limbs(y, 2))]))
    for width in [8, 16, 32, 64, 128]:
        count, limit = max(1, width // 16), 2**width
        for signed in [False, True]:
            spec = width + 256 * signed
            for op in ["int_view", "int_add_checked", "int_add_wrapping", "int_sub_checked", "int_sub_wrapping", "int_le"]:
                for x, y in [(0, 1), (limit - 1, 1), (limit // 2 - 1, 1), (limit // 2, limit - 1)]:
                    args = [u16(limbs(x, count))] + ([] if op == "int_view" else [u16(limbs(y, count))])
                    cases.append(operation_case(op, args, constant=spec))
    cases.append(operation_case("int_view", [u16([256])], constant=8))
    header = list(range(40))
    header[36:38] = limbs(0x1d00ffff, 2)
    for op in ["hash_sha256d_header", "bitcoin_target_mainnet", "bitcoin_prev_hash", "bitcoin_header_bits", "bitcoin_header_time"]:
        cases.append(operation_case(op, [u16(header)]))
    cases.append(operation_case("bitcoin_genesis_hash_mainnet", []))
    for compact in [0x01010000, 0x02000100, 0x03000001, 0x1c7fffff, 0x1e000001,
                    0, 0x1d80ffff, 0x2100ffff, 0x01000001, 0x1d010000]:
        h = header.copy(); h[36:38] = limbs(compact, 2)
        cases.append(operation_case("bitcoin_target_mainnet", [u16(h)]))
    for target in [1, 2**224 - 1, 2**256 - 2, 0, 2**256 - 1]:
        cases.append(operation_case("bitcoin_block_work", [u16(limbs(target, 16))]))
    # Assignment, type, shape, topology, static-repeat and public-ABI failures.
    seed = operation_case("add_const", [m31([7])], constant=5)
    mutations = [
        lambda q: q["assignment"]["private_inputs"].update({"extra": [0]}),
        lambda q: q["assignment"]["public_inputs"].update({"extra": [0]}),
        lambda q: q["assignment"]["public_outputs"].update({"y": [13]}),
        lambda q: q["assignment"]["private_inputs"].update({"a": [P]}),
        lambda q: q["assignment"]["private_inputs"].update({"a": [-1]}),
        lambda q: q["assignment"]["private_inputs"].update({"a": [7.0]}),
        lambda q: q["program"].update({"proof_mode": "zk"}),
        lambda q: q["program"].update({"version": 2}),
        lambda q: q["program"]["nodes"][0].update({"lhs": "later"}),
        lambda q: q["program"]["nodes"][0].update({"selector": "a"}),
        lambda q: q["program"]["nodes"][0].update({"ignored": 0}),
        lambda q: q["program"]["nodes"][0].update({"constant": P}),
        lambda q: q["program"].update({"assertions": [{"lhs": "a", "rhs": "y"}]}),
        lambda q: q["program"]["inputs"][0].update({"length": 0}),
        lambda q: q["program"].update({"public_outputs": []}),
    ]
    for i, mutate in enumerate(mutations):
        request = copy.deepcopy(seed.request); mutate(request)
        cases.append(Case(f"malformed_{i}", request, None))
    for op, args, metadata in [
        ("bool_not", [m31([2])], {}), ("select", [m31([1]), m31([2]), m31([2])], {}),
        ("repeat", [m31([1])], {"rounds": 0, "body": [{"op": "square"}]}),
        ("repeat", [m31([1])], {"rounds": 1, "body": [{"op": "mix4"}]}),
        ("array_get", [m31([1])], {"index": 1}),
    ]:
        # Construct manually because expected() intentionally assumes valid shape.
        request = copy.deepcopy(seed.request)
        node = {"name": "y", "op": op, **metadata}
        request["program"]["inputs"] = []
        request["assignment"]["private_inputs"] = {}
        for (name, operand), (kind, words) in zip([("a", "lhs"), ("b", "rhs"), ("s", "selector")], args):
            node[operand] = name
            request["program"]["inputs"].append({"name": name, "kind": kind, "length": len(words), "visibility": "private"})
            request["assignment"]["private_inputs"][name] = words
        request["program"]["nodes"] = [node]
        cases.append(Case("invalid_" + op, request, None))
    blinded = copy.deepcopy(seed.request); blinded["program"]["proof_mode"] = "blinded"
    cases.append(Case("blinded_semantics", blinded, seed.words))
    public = copy.deepcopy(seed.request)
    public["program"]["inputs"][0]["visibility"] = "public"
    public["assignment"]["public_inputs"] = public["assignment"].pop("private_inputs")
    cases.append(Case("public_order", public, [7, 12] + [0] * 6))
    return cases


def run(binary: Path) -> dict:
    cases = corpus()
    ops = set(json.loads((ROOT / "formal/s31/source-bindings.json").read_text())["ops"])
    seen = {n["op"] for c in cases for n in c.request["program"]["nodes"]}
    if seen != ops:
        raise AssertionError(f"parity inventory mismatch: missing={ops - seen}, extra={seen - ops}")
    for i, c in enumerate(cases):
        try:
            evaluate_relation(c.request["program"], c.request["assignment"])
            accepted = True
        except OracleError:
            accepted = False
        if accepted != (c.words is not None):
            raise AssertionError(f"Python oracle disagrees with fixture {i}: {c.name}")
    data = "".join(json.dumps(c.request, separators=(",", ":")) + "\n" for c in cases)
    process = subprocess.run([str(binary.resolve())], input=data, text=True, capture_output=True, timeout=240)
    if process.returncode:
        raise AssertionError(f"Lean adapter failed: {process.stderr[:1000]}")
    responses = process.stdout.splitlines()
    if len(responses) != len(cases):
        raise AssertionError(f"Lean adapter returned {len(responses)} of {len(cases)} results")
    for i, (c, line) in enumerate(zip(cases, responses)):
        response = json.loads(line)
        if (c.words is None and "error" not in response) or (c.words is not None and response.get("ok") != c.words):
            raise AssertionError(f"Lean parity failure {i} {c.name}: expected {c.words}, got {response}")
    return {"operations": len(ops), "cases": len(cases), "accepted": sum(c.words is not None for c in cases),
            "rejected": sum(c.words is None for c in cases),
            "corpus_sha256": hashlib.sha256(data.encode()).hexdigest()}
