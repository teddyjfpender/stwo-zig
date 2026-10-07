#!/usr/bin/env python3
"""Diagnostic fixed-fixture CX/CCX equivalence check (requires z3-solver).

This is a build-time audit, not a STARK proof or a proof certificate. It only
applies to the pinned public iadd256.kmx bytes and makes no generic QEC claim.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import z3


FIXTURE = Path(__file__).with_name("fixtures") / "iadd256.kmx"
EXPECTED_SHA256 = "eb85f1e61b235e2f598d910c93208b813f974aa02b43497b859dac02d4b2143d"


def main() -> None:
    source = FIXTURE.read_bytes()
    digest = hashlib.sha256(source).hexdigest()
    if digest != EXPECTED_SHA256:
        raise ValueError("The circuit bytes differ from the pinned public fixture")

    registers: list[list[int]] = [[], []]
    declared: set[int] = set()
    gates: list[tuple[str, tuple[int, ...]]] = []
    for line_number, line in enumerate(source.decode("utf-8").splitlines(), 1):
        words = line.split("#", 1)[0].split()
        if not words:
            continue
        kind, *args = words
        if kind == "APPEND_TO_REGISTER" and len(args) == 2:
            qubit, register = args
            if not qubit.startswith("q") or not register.startswith("r"):
                raise ValueError(f"invalid register annotation on line {line_number}")
            index, reg = int(qubit[1:]), int(register[1:])
            if reg not in (0, 1):
                raise ValueError(f"invalid register on line {line_number}")
            registers[reg].append(index)
        elif kind == "REGISTER" and len(args) == 1:
            register = args[0]
            if not register.startswith("r") or int(register[1:]) not in (0, 1):
                raise ValueError(f"invalid register declaration on line {line_number}")
            declared.add(int(register[1:]))
        elif kind in ("CX", "CCX") and len(args) == (2 if kind == "CX" else 3):
            if not all(arg.startswith("q") for arg in args):
                raise ValueError(f"invalid gate operand on line {line_number}")
            operands = tuple(int(arg[1:]) for arg in args)
            if len(set(operands)) != len(operands):
                raise ValueError(f"aliased gate operand on line {line_number}")
            gates.append((kind, operands))
        else:
            raise ValueError(f"unsupported operation on line {line_number}: {kind}")

    if declared != {0, 1} or registers != [list(range(256)), list(range(256, 512))]:
        raise ValueError("fixture no longer has exactly two 256-qubit registers")
    if len(gates) != 2547 or sum(kind == "CCX" for kind, _ in gates) != 509:
        raise ValueError("unexpected CX/CCX composition")

    target, offset = z3.BitVecs("target offset", 256)
    qubits = [z3.Extract(index, index, target) == 1 for index in range(256)]
    qubits += [z3.Extract(index, index, offset) == 1 for index in range(256)]
    for kind, operands in gates:
        if kind == "CX":
            control, dest = operands
            qubits[dest] = z3.Xor(qubits[dest], qubits[control])
        else:
            control1, control2, dest = operands
            qubits[dest] = z3.Xor(qubits[dest], z3.And(qubits[control1], qubits[control2]))

    def bits_to_word(indices: list[int]) -> z3.BitVecRef:
        return z3.Concat(
            *(
                z3.If(qubits[index], z3.BitVecVal(1, 1), z3.BitVecVal(0, 1))
                for index in reversed(indices)
            )
        )

    target_out = bits_to_word(registers[0])
    offset_out = bits_to_word(registers[1])
    solver = z3.Solver()
    solver.set(timeout=60_000)
    solver.add(z3.Or(target_out != target + offset, offset_out != offset))
    result = solver.check()
    if result != z3.unsat:
        raise AssertionError(f"fixed-fixture equivalence did not close: {result}")
    print(
        json.dumps(
            {
                "fixture_sha256": digest,
                "z3_version": z3.get_version_string(),
                "result": "unsat",
                "proved_symbolic_relation": "target_out = target + offset mod 2^256; offset_out = offset",
                "scope": "one application of the pinned, CX/CCX-only fixture",
                "cx": 2038,
                "ccx": 509,
                "phase_gates": 0,
                "ancilla_qubits": 0,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
