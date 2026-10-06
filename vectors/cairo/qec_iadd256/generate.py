#!/usr/bin/env python3
"""Generate a fixed-iadd256 Cairo diagnostic from the public KMX fixture.

This emits a Cairo executable and one 64-shot argument set. The guest proves
gate execution and result checks. SHAKE input derivation is performed here,
outside that Cairo proof, so this is not the full upstream statement.
"""

import argparse
import hashlib
import json
from pathlib import Path


FIXTURE = Path(__file__).resolve().parents[2] / "riscv_guests/iadd256_kmx/iadd256.kmx"
FIXTURE_SHA256 = "eb85f1e61b235e2f598d910c93208b813f974aa02b43497b859dac02d4b2143d"
MASK256 = (1 << 256) - 1
LEAF_DOMAIN = b"stwo-zig/qec/iadd256/fixed-leaf/v1\0"

HEADER = """use core::dict::Felt252Dict;

#[executable]
fn main(inputs: Span<u64>, repetitions: u32) -> Array<u64> {
    assert!(inputs.len() == 512, "bad input count");
    let mut state: Felt252Dict<u64> = Default::default();
    let mut i: u32 = 0;
    while i < inputs.len() {
        state.insert(i.into(), *inputs.at(i));
        i += 1;
    };
    let gates: Array<(u32,u32,u32,u32)> = array![
"""

TAIL = """    ];
    let gate_span = gates.span();
    let mut rep: u32 = 0;
    while rep < repetitions {
        let mut j: u32 = 0;
        while j < gate_span.len() {
            let (kind, c1, c2, target) = *gate_span.at(j);
            let value = state.get(target.into());
            let control = state.get(c1.into());
            if kind == 1 {
                state.insert(target.into(), value ^ control);
            } else {
                let control2 = state.get(c2.into());
                state.insert(target.into(), value ^ (control & control2));
            };
            j += 1;
        };
        rep += 1;
    };
    let mut expected: Felt252Dict<u64> = Default::default();
    let mut bit: u32 = 0;
    while bit < 256 {
        expected.insert(bit.into(), *inputs.at(bit));
        bit += 1;
    };
    let mut add_rep: u32 = 0;
    while add_rep < repetitions {
        let mut carry: u64 = 0;
        let mut add_bit: u32 = 0;
        while add_bit < 256 {
            let a = expected.get(add_bit.into());
            let b = *inputs.at(add_bit + 256);
            let axb = a ^ b;
            expected.insert(add_bit.into(), axb ^ carry);
            carry = (a & b) | (axb & carry);
            add_bit += 1;
        };
        add_rep += 1;
    };
    let mut check_bit: u32 = 0;
    while check_bit < 256 {
        assert!(state.get(check_bit.into()) == expected.get(check_bit.into()), "wrong target");
        assert!(state.get((check_bit + 256).into()) == *inputs.at(check_bit + 256), "changed offset");
        check_bit += 1;
    };
    let mut outputs: Array<u64> = array![];
    let mut k: u32 = 0;
    while k < 512 {
        outputs.append(state.get(k.into()));
        k += 1;
    };
    outputs
}
"""

MANIFEST = """[package]
name = "qec_iadd256"
version = "0.1.0"
edition = "2025_12"

[executable]

[cairo]
enable-gas = false

[dependencies]
cairo_execute = "2.18.0"
"""


def gates_from_fixture(raw: bytes) -> list[tuple[int, int, int, int]]:
    counts = {"CX": 0, "CCX": 0, "APPEND_TO_REGISTER": 0, "REGISTER": 0}
    gates = []
    for line in raw.decode("utf-8").splitlines():
        parts = line.split()
        if not parts:
            continue
        kind = parts[0]
        if kind not in counts:
            raise ValueError(f"unsupported operation {kind}")
        counts[kind] += 1
        if kind == "REGISTER":
            assert len(parts) == 2 and parts[1] == f"r{counts[kind] - 1}"
        elif kind == "APPEND_TO_REGISTER":
            q = counts[kind] - 1
            assert len(parts) == 3 and parts[1:] == [f"q{q}", f"r{q // 256}"]
        else:
            qubits = [int(word.removeprefix("q")) for word in parts[1:]]
            assert len(qubits) == (2 if kind == "CX" else 3)
            assert len(set(qubits)) == len(qubits) and all(0 <= q < 512 for q in qubits)
            gates.append((1, qubits[0], 0, qubits[1]) if kind == "CX" else (2, *qubits))
    assert counts == {"CX": 2038, "CCX": 509, "APPEND_TO_REGISTER": 512, "REGISTER": 2}
    assert len(gates) == 2547
    return gates


def inputs_and_expected(raw: bytes, gates: list[tuple[int, int, int, int]],
                        total_shots: int, batch: int, repetitions: int) -> tuple[list[int], list[int]]:
    if total_shots < 64 or total_shots > 9024 or total_shots % 64:
        raise ValueError("total shots must be 64..9024 in complete 64-shot batches")
    if not 0 <= batch < total_shots // 64 or not 1 <= repetitions <= 8000:
        raise ValueError("batch or repetitions outside the fixed benchmark")
    stream = hashlib.shake_256(raw).digest(64 * total_shots)
    values = [0] * 512
    for local_shot in range(64):
        shot = 64 * batch + local_shot
        target = int.from_bytes(stream[64 * shot:64 * shot + 32], "little")
        offset = int.from_bytes(stream[64 * shot + 32:64 * shot + 64], "little")
        for bit in range(256):
            values[bit] |= ((target >> bit) & 1) << local_shot
            values[256 + bit] |= ((offset >> bit) & 1) << local_shot
    state = values.copy()
    for _ in range(repetitions):
        for kind, c1, c2, target in gates:
            state[target] ^= state[c1] if kind == 1 else state[c1] & state[c2]
    for local_shot in range(64):
        shot = 64 * batch + local_shot
        target = int.from_bytes(stream[64 * shot:64 * shot + 32], "little")
        offset = int.from_bytes(stream[64 * shot + 32:64 * shot + 64], "little")
        got = sum(((state[bit] >> local_shot) & 1) << bit for bit in range(256))
        got_offset = sum(((state[256 + bit] >> local_shot) & 1) << bit for bit in range(256))
        assert got == (target + repetitions * offset) & MASK256 and got_offset == offset
    return values, state


def leaf_digest(raw: bytes, total_shots: int, batch: int, repetitions: int,
                inputs: list[int], outputs: list[int]) -> bytes:
    """Commit the entire fixed-fixture statement, including every shot word."""
    assert len(inputs) == len(outputs) == 512
    preimage = bytearray(LEAF_DOMAIN)
    preimage.extend(hashlib.sha256(raw).digest())
    for value in (total_shots, batch, repetitions):
        preimage.extend(value.to_bytes(4, "little"))
    for value in (*inputs, *outputs):
        preimage.extend(value.to_bytes(8, "little"))
    return hashlib.sha256(preimage).digest()


def fixed_leaf_source(source: str, inputs: list[int], outputs: list[int],
                      digest: bytes) -> str:
    """Constrain the public arguments and all 512 results in Cairo itself."""
    source = source.replace(
        "fn main(inputs: Span<u64>, repetitions: u32) -> Array<u64> {",
        "fn main(inputs: Span<u64>, repetitions: u32) -> (u128, u128) {",
        1,
    )
    input_check = (
        "    assert!(repetitions == FIXED_REPETITIONS, \"wrong repetitions\");\n"
        "    let fixed_inputs: Array<u64> = array![\n"
        + "".join(f"        {value},\n" for value in inputs)
        + "    ];\n"
        "    let mut input_index: u32 = 0;\n"
        "    while input_index < 512 {\n"
        "        assert!(*inputs.at(input_index) == *fixed_inputs.at(input_index), \"wrong input\");\n"
        "        input_index += 1;\n"
        "    };\n"
    )
    source = source.replace("    let mut state: Felt252Dict<u64>",
                            input_check + "    let mut state: Felt252Dict<u64>", 1)
    output_check = (
        "    let fixed_outputs: Array<u64> = array![\n"
        + "".join(f"        {value},\n" for value in outputs)
        + "    ];\n"
        "    let mut output_index: u32 = 0;\n"
        "    while output_index < 512 {\n"
        "        assert!(state.get(output_index.into()) == *fixed_outputs.at(output_index), \"wrong output\");\n"
        "        output_index += 1;\n"
        "    };\n"
        f"    ({int.from_bytes(digest[:16], 'little')}, {int.from_bytes(digest[16:], 'little')})\n"
        "}\n"
    )
    source = source.replace(
        "    let mut outputs: Array<u64> = array![];\n"
        "    let mut k: u32 = 0;\n"
        "    while k < 512 {\n"
        "        outputs.append(state.get(k.into()));\n"
        "        k += 1;\n"
        "    };\n"
        "    outputs\n}\n",
        output_check,
        1,
    )
    if not source.endswith(output_check):
        raise AssertionError("fixed leaf source template drift")
    return source


def render_source(gates: list[tuple[int, int, int, int]], inputs: list[int],
                  outputs: list[int], repetitions: int, digest: bytes | None) -> str:
    source = HEADER + "".join(f"        ({a},{b},{c},{d}),\n" for a, b, c, d in gates) + TAIL
    if digest is not None:
        source = (f"const FIXED_REPETITIONS: u32 = {repetitions};\n" +
                  fixed_leaf_source(source, inputs, outputs, digest))
    return source


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--total-shots", type=int, default=64)
    parser.add_argument("--batch", type=int, default=0)
    parser.add_argument("--repetitions", type=int, default=1)
    parser.add_argument("--leaf", action="store_true",
                        help="emit a two-cell circuit-recursion leaf for this exact batch")
    args = parser.parse_args()
    raw = FIXTURE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != FIXTURE_SHA256:
        raise ValueError("public KMX fixture hash changed")
    gates = gates_from_fixture(raw)
    inputs, expected = inputs_and_expected(raw, gates, args.total_shots,
                                           args.batch, args.repetitions)
    digest = leaf_digest(raw, args.total_shots, args.batch, args.repetitions,
                         inputs, expected) if args.leaf else None
    source = render_source(gates, inputs, expected, args.repetitions, digest)
    (args.out / "src").mkdir(parents=True, exist_ok=True)
    (args.out / "src/lib.cairo").write_text(source)
    (args.out / "Scarb.toml").write_text(MANIFEST)
    (args.out / "args.json").write_text(json.dumps([hex(v) for v in [512, *inputs, args.repetitions]]))
    (args.out / "expected.json").write_text(json.dumps(expected))
    if digest is not None:
        (args.out / "leaf-statement.json").write_text(json.dumps({
            "schema": "qec-iadd256-fixed-leaf-v1",
            "fixture_sha256": FIXTURE_SHA256,
            "total_shots": args.total_shots,
            "batch": args.batch,
            "repetitions": args.repetitions,
            "digest_sha256": digest.hex(),
            "output_cells_le_u128": [hex(int.from_bytes(digest[i:i + 16], "little"))
                                      for i in (0, 16)],
        }, indent=2, sort_keys=True) + "\n")
    receipt = {
        "fixture_sha256": FIXTURE_SHA256,
        "generated_source_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "total_shots": args.total_shots, "batch": args.batch,
        "repetitions": args.repetitions, "gates": len(gates),
        "input_argument_sha256": hashlib.sha256((args.out / "args.json").read_bytes()).hexdigest(),
        "leaf_digest_sha256": digest.hex() if digest is not None else None,
    }
    (args.out / "generation.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    print(json.dumps(receipt, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
