#!/usr/bin/env python3
"""Exact fixed-KMX test-vector generation and independent CX/CCX simulator.

This is a diagnostic oracle, not the proof-bearing implementation. It uses the
same raw-byte SHAKE256 stream, little-endian U256 limbs, 64-shot bit slices,
and operation order as the public upstream SP1 example_zkp_fuzzer.
"""

import argparse
import hashlib
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
EXPECTED_SHA256 = "eb85f1e61b235e2f598d910c93208b813f974aa02b43497b859dac02d4b2143d"
MASK256 = (1 << 256) - 1


def fixture() -> bytes:
    circuit = (HERE / "iadd256.kmx").read_bytes()
    if hashlib.sha256(circuit).hexdigest() != EXPECTED_SHA256:
        raise ValueError("public KMX fixture hash changed")
    return circuit


def parse(circuit: bytes) -> list[tuple[str, tuple[int, ...]]]:
    gates = []
    registers: list[list[int]] = [[], []]
    counts = {"CX": 0, "CCX": 0, "REGISTER": 0, "APPEND_TO_REGISTER": 0}
    for line in circuit.decode("utf-8").splitlines():
        words = line.split()
        if not words:
            continue
        op = words[0]
        if op not in counts:
            raise ValueError(f"unsupported fixed-fixture operation: {op}")
        counts[op] += 1
        if op == "REGISTER":
            assert len(words) == 2 and int(words[1][1:]) == counts[op] - 1
        elif op == "APPEND_TO_REGISTER":
            q, r = int(words[1][1:]), int(words[2][1:])
            assert len(words) == 3 and q == counts[op] - 1 and r == q // 256
            registers[r].append(q)
        else:
            qs = tuple(int(word[1:]) for word in words[1:])
            assert len(qs) == (2 if op == "CX" else 3)
            assert len(qs) == len(set(qs)) and all(0 <= q < 512 for q in qs)
            gates.append((op, qs))
    assert counts == {"CX": 2038, "CCX": 509, "REGISTER": 2, "APPEND_TO_REGISTER": 512}
    assert registers == [list(range(256)), list(range(256, 512))]
    assert len(gates) == 2547
    return gates


def test_vectors(circuit: bytes, total_shots: int) -> list[tuple[int, int]]:
    if not 1 <= total_shots <= 9024 or total_shots % 64:
        raise ValueError("shot count must be complete 64-shot batches within the benchmark contract")
    stream = hashlib.shake_256(circuit).digest(64 * total_shots)
    return [
        (int.from_bytes(stream[64*i:64*i+32], "little"),
         int.from_bytes(stream[64*i+32:64*i+64], "little"))
        for i in range(total_shots)
    ]


def check_batch(gates, vectors, repetitions: int, batch: int) -> dict:
    if not 1 <= repetitions <= 8000:
        raise ValueError("repetition count outside benchmark contract")
    if not 0 <= batch < (len(vectors) + 63) // 64:
        raise ValueError("invalid batch index")
    chosen = vectors[64*batch:64*(batch+1)]
    qubits = [0] * 512
    for shot, (target, offset) in enumerate(chosen):
        for bit in range(256):
            qubits[bit] |= ((target >> bit) & 1) << shot
            qubits[256 + bit] |= ((offset >> bit) & 1) << shot
    for _ in range(repetitions):
        for op, qs in gates:
            if op == "CX":
                c, t = qs
                qubits[t] ^= qubits[c]
            else:
                a, b, t = qs
                qubits[t] ^= qubits[a] & qubits[b]
    for shot, (target, offset) in enumerate(chosen):
        output = sum(((qubits[bit] >> shot) & 1) << bit for bit in range(256))
        offset_out = sum(((qubits[256 + bit] >> shot) & 1) << bit for bit in range(256))
        expected = (target + repetitions * offset) & MASK256
        if output != expected or offset_out != offset:
            raise AssertionError(f"batch={batch}, shot={shot}: output or offset mismatch")
    # The public fixture has exactly the 512 register qubits and no phase ops.
    assert len(qubits) == 512
    return {
        "batch": batch, "shot_count": len(chosen), "repetitions": repetitions,
        "total_parsed_ops": 3061 * repetitions,
        "per_shot_non_clifford": 509 * repetitions,
        "per_shot_clifford": 2038 * repetitions,
        "first_target_le_hex": chosen[0][0].to_bytes(32, "little").hex(),
        "first_offset_le_hex": chosen[0][1].to_bytes(32, "little").hex(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repetitions", type=int, default=1)
    parser.add_argument("--total-shots", type=int, default=64)
    parser.add_argument("--batch", type=int, default=0)
    parser.add_argument("--input-out", type=Path)
    args = parser.parse_args()
    circuit = fixture()
    result = check_batch(parse(circuit), test_vectors(circuit, args.total_shots),
                         args.repetitions, args.batch)
    result["circuit_sha256"] = EXPECTED_SHA256
    if args.input_out:
        header = struct.pack("<7I", args.repetitions, args.total_shots, args.batch,
                             512, 509 * args.repetitions, 3061 * args.repetitions,
                             len(circuit))
        args.input_out.write_bytes(header + circuit)
        result["input_bytes"] = len(header) + len(circuit)
        result["input_sha256"] = hashlib.sha256(header + circuit).hexdigest()
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
