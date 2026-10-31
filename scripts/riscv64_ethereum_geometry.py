#!/usr/bin/env python3
"""Model independent component geometry from an exact completed access census.

This is a source-cell/padding model, not a proving-time or peak-RSS benchmark.
CPU width must come from the expected immutable ROM, never observed opcodes.
RAM costs exclude the private caller, permissions and initialization proof.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

MODULUS = 2147483647
MULTIPLICATION = {"MUL", "MULH", "MULHSU", "MULHU", "MULW"}
DIVISION = {"DIV", "DIVU", "REM", "REMU", "DIVW", "DIVUW", "REMW", "REMUW"}
ROOT = Path(__file__).resolve().parents[1]
SOURCE_FILES = (
    "src/frontends/riscv/rv64/air/crypto/keccak/layout.zig",
    "src/frontends/riscv/rv64/air/crypto/keccak/bridge/layout.zig",
    "src/frontends/riscv/rv64/air/arithmetic/division/layout.zig",
    "src/frontends/riscv/rv64/air/arithmetic/multiplication/layout.zig",
    "src/frontends/riscv/rv64/air/crypto/secp256k1/layout.zig",
    "src/frontends/riscv/rv64/air/crypto/secp256k1/bridge/layout.zig",
)


def domain_rows(live):
    if type(live) is not int or live < 0:
        raise ValueError("Nonnegative integer component rows required")
    return 1 << (max(32, live) - 1).bit_length()


def component(live, fixed, main, interaction):
    rows = domain_rows(live)
    cells = rows * (fixed + main + interaction)
    return dict(live_rows=live, rows=rows, fixed_columns=fixed, main_columns=main,
                interaction_columns=interaction, source_cells=cells,
                source_bytes=4 * cells)


def validated_batches(census):
    if census.get("status") != "completed" or census.get("verified_output") is not True:
        raise ValueError("Requires a completed, output-checked execution census")
    names = census["opcode_names"]
    if len(names) != len(set(names)) or not DIVISION <= set(names) or "ECALL" not in names:
        raise ValueError("Invalid opcode schema")
    sizes = census["access_census_chunk_bytes"]
    if not sizes or len(sizes) != len(set(sizes)) or any(type(s) is not int or s < 8 or s & (s - 1) for s in sizes):
        raise ValueError("Distinct power-of-two chunk sizes required")
    batches = census["access_batches"]
    end = calls = divisions = 0
    typed_totals = dict(keccak_calls=0, secp_add_calls=0, secp_double_calls=0)
    typed = census["execution_profile"] in {"ethereum_services_v1", "ethereum_services_v2"}
    for batch in batches:
        counts = batch["opcode_counts"]
        if len(counts) != len(names) or any(type(n) is not int or n < 0 for n in counts):
            raise ValueError("Invalid opcode counters")
        if (batch["first_step"] != end or batch["end_step"] <= end or
                batch["instructions"] != batch["end_step"] - end or
                batch.get("unclassified_instructions") != 0 or sum(counts) != batch["instructions"]):
            raise ValueError("Incomplete or non-adjacent instruction census")
        for key in ("touched_chunks", "net_changed_chunks", "touched_internal_nodes", "net_changed_internal_nodes"):
            if len(batch[key]) != len(sizes) or any(type(n) is not int or n < 0 for n in batch[key]):
                raise ValueError("Invalid chunk/node census")
        for before, after in zip(batch["touched_chunks"], batch["net_changed_chunks"]):
            if after > before:
                raise ValueError("Changed chunks must be touched")
        histogram = dict(zip(names, counts))
        if typed:
            for key in typed_totals:
                value = batch.get(key)
                if type(value) is not int or value < 0:
                    raise ValueError("Missing typed service census")
                typed_totals[key] += value
            if sum(batch[key] for key in typed_totals) != histogram["ECALL"]:
                raise ValueError("Typed service counts do not conserve ECALLs")
        calls += histogram["ECALL"]
        divisions += sum(histogram[op] for op in DIVISION)
        end = batch["end_step"]
    if not batches or end != census["instructions"] or (typed and calls != sum(typed_totals.values())):
        raise ValueError("Whole-execution census does not conserve steps/calls")
    if typed and any(typed_totals[key] != census.get(key) for key in typed_totals):
        raise ValueError("Whole-execution typed service census differs")
    if not typed and calls != census["keccak_calls"]:
        raise ValueError("Whole-execution census does not conserve steps/calls")
    return batches, sizes, names, calls, divisions


def model(census, cpu=None, arithmetic_policy="division_service_v2"):
    if arithmetic_policy not in {"division_service_v2", "division_multiplication_services_v3"}:
        raise ValueError("Unknown arithmetic provider policy")
    batches, sizes, names, calls, divisions = validated_batches(census)
    if cpu is not None:
        if (cpu.get("opcodes_from_immutable_rom") is not True or
                cpu.get("execution_profile") != census["execution_profile"] or
                cpu.get("elf_sha256") != census["elf_sha256"]):
            raise ValueError("CPU geometry requires the exact expected ELF and immutable opcode policy")
        for key in ("fixed_columns", "main_columns", "interaction_columns", "range_queries_per_row"):
            if type(cpu.get(key)) is not int or cpu[key] < 0:
                raise ValueError("Invalid independently derived CPU geometry")
    output = []
    for batch in batches:
        histogram = dict(zip(names, batch["opcode_counts"]))
        count = batch.get("keccak_calls", histogram["ECALL"])
        adds = batch.get("secp_add_calls", 0)
        doubles = batch.get("secp_double_calls", 0)
        muls = sum(histogram.get(op, 0) for op in MULTIPLICATION)
        divs = sum(histogram[op] for op in DIVISION)
        pairs = (count + 1) // 2
        parts = {
            "keccak": component(29 * pairs, 32, 1923, 2596),
            "keccak_bridge": component(25 * count, 5, 57, 60),
            "division": component(divs, 3, 1135, 8),
            "chi_table": component(8192, 7, 1, 4),
            "xor5_table": component(1024, 7, 1, 4),
        }
        if arithmetic_policy == "division_multiplication_services_v3":
            parts["multiplication"] = component(muls, 3, 87, 132)
        if census["execution_profile"] in {"ethereum_services_v1", "ethereum_services_v2"}:
            for label, number, products, linear, bridge in [("add", adds, 16, 23, 6), ("double", doubles, 13, 6, 3)]:
                # Qualified v1 topology requires one trailing inactive row.
                parts[f"secp_{label}_product"] = component(products * number + 1, 15, 319, 384)
                parts[f"secp_{label}_linear"] = component(linear * number + 1, 15, 200, 176)
                parts[f"secp_{label}_bridge"] = component(bridge * number + 1, 7, 128, 72)
        cpu_rows = domain_rows(batch["instructions"])
        byte_mass = 40 * parts["keccak_bridge"]["rows"]
        if arithmetic_policy == "division_multiplication_services_v3":
            byte_mass += 96 * parts["multiplication"]["rows"]
        for label in ("add", "double"):
            if f"secp_{label}_product" in parts:
                byte_mass += (284 * parts[f"secp_{label}_product"]["rows"] +
                              128 * parts[f"secp_{label}_linear"]["rows"] +
                              42 * parts[f"secp_{label}_bridge"]["rows"])
        if cpu is not None:
            parts["cpu"] = component(batch["instructions"], cpu["fixed_columns"], cpu["main_columns"], cpu["interaction_columns"])
            byte_mass += cpu_rows * cpu["range_queries_per_row"]
        masses = dict(chi=pairs * 24 * 1600, xor5=pairs * 24 * 320,
                      keccak_io=2 * 25 * count, bytes=byte_mass)
        if any(mass >= MODULUS for mass in masses.values()):
            raise ValueError("Shared lookup mass reaches the characteristic")
        ram = []
        for i, size in enumerate(sizes):
            chunks = batch["touched_chunks"][i] + batch["net_changed_chunks"][i]
            nodes = batch["touched_internal_nodes"][i] + batch["net_changed_internal_nodes"][i]
            # Value-only RAMV: domain framing in capacity, four u16/value, rate7,
            # one explicit final delimiter block. No permission lanes in values.
            per_chunk = (4 * (size // 8) + 6) // 7 + 1
            permutations = chunks * per_chunk + nodes * 4
            provider = component(permutations, 1, 303, 8)
            ram.append(dict(chunk_bytes=size, chunk_permutations=chunks * per_chunk,
                            node_permutations=nodes * 4, total_permutations=permutations,
                            hash_provider_counterfactual=provider))
        output.append(dict(first_step=batch["first_step"], end_step=batch["end_step"],
                           cpu_rows=cpu_rows, cpu_local_clock_admissible=batch["instructions"] < 1 << 22,
                           keccak_calls=count, secp_add_calls=adds, secp_double_calls=doubles,
                           multiplication_calls=muls, division_calls=divs, components=parts,
                           shared_lookup_mass=masses, ram_candidates=ram,
                           modeled_source_bytes_without_ram=sum(p["source_bytes"] for p in parts.values())))
    summaries = []
    for i, size in enumerate(sizes):
        summaries.append(dict(chunk_bytes=size,
                              total_permutations=sum(row["ram_candidates"][i]["total_permutations"] for row in output),
                              peak_batch_permutations=max(row["ram_candidates"][i]["total_permutations"] for row in output),
                              total_padded_hash_rows=sum(row["ram_candidates"][i]["hash_provider_counterfactual"]["rows"] for row in output),
                              peak_hash_source_bytes=max(row["ram_candidates"][i]["hash_provider_counterfactual"]["source_bytes"] for row in output)))
    return dict(schema="rv64-independent-component-geometry-v1", full_block_proof_verified=False,
                shared_lookup_mass_admission_complete=False, cpu_width_included=cpu is not None, instructions=census["instructions"],
                batch_count=len(output), keccak_calls=census["keccak_calls"], division_calls=divisions,
                secp_add_calls=census.get("secp_add_calls", 0), secp_double_calls=census.get("secp_double_calls", 0),
                arithmetic_policy=arithmetic_policy,
                cpu_padded_rows=sum(row["cpu_rows"] for row in output),
                all_batches_local_clock_admissible=all(row["cpu_local_clock_admissible"] for row in output),
                max_keccak_calls=max(row["keccak_calls"] for row in output),
                max_division_calls=max(row["division_calls"] for row in output),
                ram_candidates=summaries, batches=output,
                scope=["Geometry model only; not a time or RSS benchmark.",
                       "Lookup masses cover modeled CPU/crypto BYTE and Keccak families only; RAM/policy/other admission belongs to the concrete proof coordinator.",
                       "Diagnostic 2^22-step census intervals fail strict 24-bit clock admission; recapture smaller proving batches.",
                       "RAM hash provider is a source-cost counterfactual, not qualified private continuation.",
                       "Excludes private RAM caller, permits, initialization, CPU unless supplied, ROM, BYTE/AND/SHIFT providers, PCS/FFT, masks and receiver/checkpoint cost.",
                       "The PCS hashes low-height column prefixes once before lifting hasher states; do not multiply every provider width by CPU height."])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("census", type=Path)
    parser.add_argument("--cpu-geometry", type=Path)
    parser.add_argument("--arithmetic-policy", choices=["division_service_v2", "division_multiplication_services_v3"], default="division_service_v2")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    raw = args.census.read_bytes()
    result = model(json.loads(raw), json.loads(args.cpu_geometry.read_bytes()) if args.cpu_geometry else None, args.arithmetic_policy)
    result["census_sha256"] = hashlib.sha256(raw).hexdigest()
    result["source_sha256"] = {path: hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in SOURCE_FILES}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")


if __name__ == "__main__":
    main()
