"""Checked mutation controls for the LUI/ADDI refinement bridge."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

from . import air, codec
from .model import M31_MODULUS, RefinementError


def _evaluate(payload: dict[str, Any], assignment: dict[str, int]) -> list[int]:
    values: list[int] = []
    for raw in payload["nodes"]:
        op = raw["op"]
        if op == "const":
            value = int(raw["value"])
        elif op == "col":
            value = assignment[str(raw["name"])]
        elif op == "neg":
            value = -values[int(raw["args"][0])]
        else:
            lhs, rhs = (values[int(index)] for index in raw["args"])
            if op == "add":
                value = lhs + rhs
            elif op == "sub":
                value = lhs - rhs
            elif op == "mul":
                value = lhs * rhs
            else:
                raise RefinementError(f"negative control saw unknown node {op}")
        values.append(value % M31_MODULUS)
    return values


def _assert_constraints(
    payload: dict[str, Any],
    assignment: dict[str, int],
) -> None:
    values = _evaluate(payload, assignment)
    failed = [
        index
        for index, root in enumerate(payload["constraints"])
        if values[int(root)] != 0
    ]
    if failed:
        raise RefinementError(f"mutation witness fails constraints {failed}")


def _assert_ranges(
    payload: dict[str, Any],
    assignment: dict[str, int],
) -> None:
    values = _evaluate(payload, assignment)
    widths = {
        "range_check_20": (20,),
        "range_check_8_11": (8, 11),
        "range_check_8_8_4": (8, 8, 4),
        "range_check_8_8": (8, 8),
    }
    for lookup in payload["lookups"]:
        domain = lookup["domain"]
        if domain not in widths:
            continue
        numerator = values[int(lookup["numerator"])]
        if numerator == 0:
            continue
        tuple_values = [values[int(index)] for index in lookup["tuple"]]
        bounds = widths[domain]
        if len(tuple_values) != len(bounds):
            raise RefinementError(f"{domain}: mutation lookup arity drifted")
        for value, width in zip(tuple_values, bounds, strict=True):
            if not 0 <= value < 1 << width:
                raise RefinementError(
                    f"{domain}: mutation witness value {value} is not {width}-bit"
                )


def _expect_bridge_rejection(payload: dict[str, Any], family: str) -> None:
    try:
        air.validate_family(payload, family)
    except RefinementError:
        return
    raise RefinementError(f"{family}: mutation did not invalidate the bridge")


def _lui_control(path: Path) -> dict[str, Any]:
    payload = codec.load_json(path)
    mutated = copy.deepcopy(payload)
    del mutated["constraints"][4]
    assignment = {
        "enabler": 1,
        "clock": 1,
        "pc": 0,
        "rd_addr": 1,
        "rd_previous_0": 0,
        "rd_previous_1": 0,
        "rd_previous_2": 0,
        "rd_previous_3": 0,
        "rd_previous_clock": 0,
        "rd_next_0": 1,
        "rd_next_1": 0,
        "rd_next_2": 0,
        "rd_next_3": 0,
        "imm_0": 0,
        "imm_1": 0,
        "imm_2": 0,
        "destination_nonzero": 1,
        "destination_inverse": 1,
        "bus_value_18": 0,
        "bus_value_19": 4,
        "bus_value_20": 2,
        "bus_value_21": 1,
    }
    _assert_constraints(mutated, assignment)
    _assert_ranges(mutated, assignment)
    if assignment["rd_next_0"] == 0:
        raise RefinementError("LUI mutation witness does not diverge from Sail")
    _expect_bridge_rejection(mutated, "lui")
    return {
        "name": "lui-free-low-limb",
        "removed_constraint_index": 4,
        "counterexample": assignment,
        "sail_result": "0x00000000",
        "mutated_air_result": "0x00000001",
        "status": "passed",
    }


def _addi_control(path: Path) -> dict[str, Any]:
    payload = codec.load_json(path)
    mutated = copy.deepcopy(payload)
    del mutated["constraints"][9]
    assignment = {
        "clk": 1,
        "pc": 0,
        "rd_addr": 1,
        "rd_previous_0": 0,
        "rd_previous_1": 0,
        "rd_previous_2": 0,
        "rd_previous_3": 0,
        "rd_previous_clock": 0,
        "rd_next_0": 0,
        "rd_next_1": 0,
        "rd_next_2": 0,
        "rd_next_3": 1,
        "rs1_addr": 2,
        "rs1_previous_0": 0,
        "rs1_previous_1": 0,
        "rs1_previous_2": 0,
        "rs1_previous_3": 0,
        "rs1_previous_clock": 0,
        "rs1_next_0": 0,
        "rs1_next_1": 0,
        "rs1_next_2": 0,
        "rs1_next_3": 0,
        "imm_0": 0,
        "imm_1": 0,
        "imm_msb": 0,
        "is_addi": 1,
        "is_xori": 0,
        "is_ori": 0,
        "is_andi": 0,
        "result_0": 0,
        "result_1": 0,
        "result_2": 0,
        "result_3": 1,
        "destination_nonzero": 1,
        "destination_inverse": 1,
        "bus_value_35": 10,
        "bus_value_36": 0,
        "bus_value_37": 4,
        "bus_value_38": 2,
        "bus_value_39": 1,
        "bus_value_40": 2,
    }
    _assert_constraints(mutated, assignment)
    _assert_ranges(mutated, assignment)
    if assignment["result_3"] == 0:
        raise RefinementError("ADDI mutation witness does not diverge from Sail")
    _expect_bridge_rejection(mutated, "base_alu_imm")
    return {
        "name": "addi-free-high-carry",
        "removed_constraint_index": 9,
        "counterexample": assignment,
        "sail_result": "0x00000000",
        "mutated_air_result": "0x01000000",
        "status": "passed",
    }


def run(ir_directory: Path) -> list[dict[str, Any]]:
    addi = ir_directory / "base_alu_imm.json"
    if not addi.is_file():
        addi = ir_directory / "addi.json"
    return [
        _lui_control(ir_directory / "lui.json"),
        _addi_control(addi),
    ]
