"""Render the reviewed load/store circuit bridge from canonical AIR IR v2.

Concrete load/store fixtures are independent reviewed inputs. Circuit nodes,
roots, lookup order and identity always come from the production export.
"""
from __future__ import annotations

import json
from typing import Any

DOMAINS = {
    "program_access": "programAccess", "registers_state": "registersState",
    "memory_access": "memoryAccess", "range_check_20": "rangeCheck20",
    "range_check_m31": "rangeCheckM31", "range_check_8_8": "rangeCheck88",
}
ROLES = {"request": "request", "consume": "consumed", "emit": "emitted"}


def render(payload: dict[str, Any]) -> bytes:
    if payload["family"] != "load_store" or payload["opcode_selector"]["mnemonic"] != "lb":
        raise ValueError("load/store bridge requires the canonical LB program")
    nodes = payload["nodes"]
    constraints = [event["root"] for event in payload["events"] if event["kind"] == "constraint"]
    lookups = [event for event in payload["events"] if event["kind"] == "lookup"]
    lines = [
        "-- GENERATED FILE. DO NOT EDIT.",
        "-- Generator: scripts/riscv_refinement.py",
        "-- Source: generated/air/lb.air-ir-v2.json",
        "import RiscvRefinement.Air.Bridge.MulhProgram",
        "namespace RiscvRefinement.Air.Bridge",
        'def loadStoreProgramIrDigest : String := ' + json.dumps(payload["content_digest"]),
    ]
    for local in (False, True):
        name = "loadStoreCircuitCompiled" if local else "loadStoreCircuit"
        lines += [f"def {name} : MulhCircuit where", '  family := "load_store"',
                  "  modulus := " + str(payload["field"]["modulus"]),
                  "  columns := " + ("loadStoreCircuit.columns" if local else
                    json.dumps([column["name"] for column in payload["columns"]])), "  nodes := ["]
        for index, node in enumerate(nodes):
            operation = node["op"]
            if operation in ("col", "const"):
                arguments = [node["column"] if operation == "col" else node["value"]]
            elif operation in ("neg", "add", "sub", "mul"):
                arguments = [index - argument - 1 if local else argument for argument in node["args"]]
                if any(argument < 0 for argument in arguments):
                    raise ValueError("load/store bridge has a forward node reference")
            else:
                raise ValueError(f"unsupported load/store node: {operation}")
            comma = "," if index + 1 < len(nodes) else ""
            lines.append(f"    .{operation} " + " ".join(map(str, arguments)) + comma + f" -- {index}")
        lines += ["  ]", f"  nodeCount := {len(nodes)}"]
        if local:
            lines += ["  constraints := loadStoreCircuit.constraints", "  lookups := loadStoreCircuit.lookups"]
        else:
            lines += ["  constraints := " + str(constraints), "  lookups := ["]
            for index, event in enumerate(lookups):
                comma = "," if index + 1 < len(lookups) else ""
                lines += ["    { domain := ." + DOMAINS[event["domain"]] + ", role := ." + ROLES[event["role"]] + ",",
                          f"      numerator := {event['numerator']}, tuple := {event['tuple']} }}{comma}"]
            lines.append("  ]")
    lines += ["#guard loadStoreCircuitCompiled == loadStoreCircuit.localise",
              "#guard loadStoreCircuit.wellFormed"]
    for field, expected in (("columns", 50), ("nodes", 308), ("constraints", 63), ("lookups", 17)):
        lines.append(f"#guard loadStoreCircuit.{field}.length == {expected}")
    return ("\n".join(lines) + "\n\n" + WITNESSES + "\nend RiscvRefinement.Air.Bridge\n").encode()


# These fixtures stay independent of the emitter; geometry changes require review.
WITNESSES = r"""-- Independent concrete LW and SB witnesses retained as evaluator differential tests.
def loadStoreLoadWitnessColumns : List M31 := [
    M31.reduce 5, M31.reduce 100, M31.reduce 0, M31.reduce 0,
    M31.reduce 0, M31.reduce 0, M31.reduce 0, M31.reduce 3,
    M31.reduce 145, M31.reduce 34, M31.reduce 51, M31.reduce 68,
    M31.reduce 1, M31.reduce 64, M31.reduce 0, M31.reduce 0,
    M31.reduce 0, M31.reduce 3, M31.reduce 0, M31.reduce 145,
    M31.reduce 34, M31.reduce 51, M31.reduce 68, M31.reduce 3,
    M31.reduce 7, M31.reduce 0, M31.reduce 0, M31.reduce 0,
    M31.reduce 64, M31.reduce 7, M31.reduce 0, M31.reduce 0,
    M31.reduce 0, M31.reduce 0, M31.reduce 0, M31.reduce 0,
    M31.reduce 0, M31.reduce 0, M31.reduce 1, M31.reduce 0,
    M31.reduce 0, M31.reduce 0, M31.reduce 145, M31.reduce 34,
    M31.reduce 51, M31.reduce 68, M31.reduce 1, M31.reduce 1840700269, M31.reduce 16, M31.reduce 16
  ]

#guard loadStoreCircuitCompiled.constraintValues loadStoreLoadWitnessColumns ==
  List.replicate 63 0

#guard loadStoreCircuitCompiled.fixedRequestsHold loadStoreLoadWitnessColumns

#guard (loadStoreCircuitCompiled.lookups.map fun entry =>
    (loadStoreCircuitCompiled.lookupTuple loadStoreLoadWitnessColumns entry).map M31.toNat) ==
  [
    [100, 21, 1, 7, 0],
    [100, 5],
    [104, 6],
    [0, 1, 3, 64, 0, 0, 0],
    [0, 1, 17, 64, 0, 0, 0],
    [13],
    [16],
    [64, 0],
    [1, 64, 3, 145, 34, 51, 68],
    [1, 64, 19, 145, 34, 51, 68],
    [15],
    [0, 7, 3, 0, 0, 0, 0],
    [0, 7, 18, 145, 34, 51, 68],
    [14],
    [0, 145],
    [0, 34],
    [0, 0]
  ]

#guard (loadStoreCircuitCompiled.lookups.map fun entry =>
    (loadStoreCircuitCompiled.lookupNumerator loadStoreLoadWitnessColumns entry).toNat) ==
  [2147483646, 2147483646, 1, 2147483646, 1, 2147483646, 2147483646, 2147483646, 2147483646, 1, 2147483646, 2147483646, 1, 2147483646, 0, 0, 2147483646]

def loadStoreStoreWitnessColumns : List M31 := [
    M31.reduce 5, M31.reduce 200, M31.reduce 0, M31.reduce 17,
    M31.reduce 34, M31.reduce 51, M31.reduce 68, M31.reduce 3,
    M31.reduce 17, M31.reduce 171, M31.reduce 51, M31.reduce 68,
    M31.reduce 1, M31.reduce 65, M31.reduce 0, M31.reduce 0,
    M31.reduce 0, M31.reduce 3, M31.reduce 0, M31.reduce 171,
    M31.reduce 0, M31.reduce 0, M31.reduce 0, M31.reduce 3,
    M31.reduce 2, M31.reduce 0, M31.reduce 0, M31.reduce 1,
    M31.reduce 2, M31.reduce 64, M31.reduce 0, M31.reduce 1,
    M31.reduce 0, M31.reduce 0, M31.reduce 0, M31.reduce 0,
    M31.reduce 0, M31.reduce 0, M31.reduce 0, M31.reduce 1,
    M31.reduce 0, M31.reduce 0, M31.reduce 0, M31.reduce 0,
    M31.reduce 0, M31.reduce 0, M31.reduce 1, M31.reduce 1073741824, M31.reduce 16, M31.reduce 16
  ]

#guard loadStoreCircuitCompiled.constraintValues loadStoreStoreWitnessColumns ==
  List.replicate 63 0

#guard loadStoreCircuitCompiled.fixedRequestsHold loadStoreStoreWitnessColumns

#guard (loadStoreCircuitCompiled.lookups.map fun entry =>
    (loadStoreCircuitCompiled.lookupTuple loadStoreStoreWitnessColumns entry).map M31.toNat) ==
  [
    [200, 24, 1, 2, 0],
    [200, 5],
    [204, 6],
    [0, 1, 3, 65, 0, 0, 0],
    [0, 1, 17, 65, 0, 0, 0],
    [13],
    [16],
    [65, 0],
    [0, 2, 3, 171, 0, 0, 0],
    [0, 2, 18, 171, 0, 0, 0],
    [14],
    [1, 64, 3, 17, 34, 51, 68],
    [1, 64, 19, 17, 171, 51, 68],
    [15],
    [0, 0],
    [0, 0],
    [0, 0]
  ]

#guard (loadStoreCircuitCompiled.lookups.map fun entry =>
    (loadStoreCircuitCompiled.lookupNumerator loadStoreStoreWitnessColumns entry).toNat) ==
  [2147483646, 2147483646, 1, 2147483646, 1, 2147483646, 2147483646, 2147483646, 2147483646, 1, 2147483646, 2147483646, 1, 2147483646, 0, 0, 2147483646]

-- Gating is load-bearing: inactive range_check_m31 requests need not be members.
#guard !loadStoreCircuitCompiled.fixedRequestsHoldUnconditional
    loadStoreLoadWitnessColumns

"""
