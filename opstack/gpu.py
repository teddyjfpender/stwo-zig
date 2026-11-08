#!/usr/bin/env python3
"""Measure a complete OP Mainnet native CUDA proof with fresh CPU acceptance."""

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
import rv64_ethereum_basket as basket
import rv64_resident_basket as resident

from opstack.cpu import PROFILE, accept, batch_steps, measured

CORPUS = ROOT / "vectors/reports/rv64-opstack-mainnet-20261106/mainnet-corpus.json"


def request_for(block, benchmark, workers, steps, output):
    fixture = next(
        (row for row in basket.load(CORPUS)["fixtures"] if row["block"] == block), None
    )
    if fixture is None:
        raise ValueError("block is not in the pinned OP Mainnet corpus")
    config = basket.load(benchmark / f"{block}-proof-config.json")
    execution = basket.load(benchmark / f"{block}-rv64.json")
    oracle = basket.load(benchmark / f"{block}-oracle.json")
    expected = fixture["native"]["output"]
    if (
        execution["status"] != "completed"
        or execution["verified_output"] is not True
        or oracle["schema"] != "stwo.opstack.unicorn.v1"
        or oracle["completed"] is not True
        or oracle["exact_steps_verified"] != execution["instructions"]
        or oracle["elf_sha256"] != config["elf_sha256"]
        or oracle["input_sha256"] != config["input_sha256"]
        or config["execution_profile"] != "ethereum_services_v3"
        or config["expected_output"] != expected
        or execution["output"] != expected
        or oracle["output"] != expected
        or execution["pc"] != config["terminal_pc"]
        or oracle["post_store_pc"] != execution["pc"]
        or oracle["final_registers"] != execution["final_registers"]
        or any(execution[key] != count for key, count in oracle["services"].items())
    ):
        raise ValueError(
            "request, pinned mainnet output and independent oracle disagree"
        )
    instructions = resident.positive(execution["instructions"], "guest instructions")
    for key in ("elf", "input"):
        source = basket.absolute(config[key], benchmark)
        if basket.sha(source) != config[key + "_sha256"]:
            raise ValueError(key + " identity mismatch")
        config[key] = str(source)
    config.update(
        batch_steps=batch_steps(config, steps),
        max_steps=instructions + 1,
        max_batches=0,
        workers=workers,
        output_directory=str(output),
    )
    return config, instructions, fixture


def resources_for(source, count):
    resources = basket.load(source)
    if resources.get("park_main") is not False or resources.get("disk_bytes") != 0:
        raise ValueError("resident CUDA requires park_main=false and disk_bytes=0")
    if resources.get("keccak_uniform_throughput") is not True:
        raise ValueError(
            "explicit keccak_uniform_throughput=true required for resident CUDA"
        )
    for key in (
        "gkr_bytes",
        "global_bytes",
        "retained_frontend_bytes",
        "fixed_setup_bytes",
    ):
        resident.positive(resources[key], key)
    resources = resident.device_resources(resources, count)
    return resources


def census_coverage(plan, instructions, terminal_pc, devices):
    if (
        plan.get("schema") != "rv64-native-plan-cost/v1"
        or plan.get("proof_generated") is not False
        or plan.get("prefix_count") != 0
        or plan.get("total_steps") != instructions
        or plan.get("final_pc") != terminal_pc
        or not plan.get("cpu")
    ):
        raise ValueError("CPU census did not cover complete independent execution")
    return len(plan["cpu"]), len(plan["cpu"]) <= len(devices) * 64


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--block", type=int, required=True)
    parser.add_argument("--benchmark", type=Path, required=True)
    parser.add_argument("--receiver", type=Path, required=True)
    parser.add_argument("--driver", type=Path)
    parser.add_argument("--runtime", type=Path)
    parser.add_argument("--runtime-sha256")
    parser.add_argument("--resources", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--devices", type=int, nargs="+", default=[0])
    parser.add_argument("--device-cap-bytes", type=int, default=28 << 30)
    parser.add_argument("--workers", type=int, choices=range(1, 33), default=8)
    parser.add_argument("--batch-steps", type=int)
    parser.add_argument("--plan-timeout", type=int, default=3600)
    parser.add_argument(
        "--prepare-only",
        action="store_true",
        help="run the CPU census without requiring CUDA",
    )
    args = parser.parse_args()
    if not (
        len(args.devices) in (1, 2, 4)
        and len(set(args.devices)) == len(args.devices)
        and min(args.devices) >= 0
    ):
        parser.error("specify one, two or four distinct physical CUDA device indices")
    if args.device_cap_bytes < 512 << 20 or args.plan_timeout < 1:
        parser.error(
            "device cap must fit 512 MiB immutable budget; timeout must be positive"
        )
    if any(key.startswith(("STWO_", "CUDA_")) for key in os.environ):
        parser.error(
            "clear ambient STWO_* and CUDA_* variables before a controlled run"
        )
    driver = runtime = None
    receiver = args.receiver.resolve(strict=True)
    if not args.prepare_only:
        if not all((args.driver, args.runtime, args.runtime_sha256)):
            parser.error(
                "CUDA production requires --driver, --runtime and --runtime-sha256"
            )
        driver = args.driver.resolve(strict=True)
        runtime = args.runtime.resolve(strict=True)
        if driver == receiver or basket.sha(driver) == basket.sha(receiver):
            parser.error("the receiver must be a separate CPU-only binary")
        if basket.sha(runtime) != args.runtime_sha256:
            parser.error("CUDA runtime differs from the pinned SHA-256")
    root = args.artifacts.resolve()
    config, instructions, fixture = request_for(
        args.block,
        args.benchmark.resolve(),
        args.workers,
        args.batch_steps,
        root / "case",
    )
    resources = resources_for(args.resources, len(args.devices))
    root.mkdir(parents=True)
    request, resource_path = root / "request.json", root / "resources.json"
    basket.atomic_json(request, config)
    basket.atomic_json(resource_path, resources)
    assets = {"receiver": str(receiver)}
    if driver is not None:
        assets.update(driver=str(driver), library=str(runtime))
    pins = {key: basket.sha(path) for key, path in assets.items()}
    receipt = {
        "schema": "stwo.opstack.native-cuda.v1",
        "block": args.block,
        "expected_block_hash": fixture["expected_block_hash"],
        "expected_output": config["expected_output"],
        "elf_sha256": config["elf_sha256"],
        "input_sha256": config["input_sha256"],
        "request_sha256": basket.sha(request),
        "resources_sha256": basket.sha(resource_path),
        "asset_sha256": pins,
        "profile": PROFILE,
        "harness_sha256": basket.sha(__file__),
        "execution_receipt_sha256": basket.sha(
            args.benchmark / f"{args.block}-rv64.json"
        ),
        "oracle_receipt_sha256": basket.sha(
            args.benchmark / f"{args.block}-oracle.json"
        ),
        "security_qualified": False,
        "proof_verified": False,
        "guest_instructions": instructions,
        "devices": args.devices,
        "device_cap_bytes": args.device_cap_bytes,
        "batch_steps": config["batch_steps"],
        "status": "planning",
    }
    summary = root / "summary.json"
    basket.atomic_json(summary, receipt)
    try:
        if not args.prepare_only:
            receipt["gpu_inventory"] = resident.gpu_inventory(
                args.devices, require_name=None
            )
            if any(
                args.device_cap_bytes > device["memory_bytes"]
                for device in receipt["gpu_inventory"].values()
            ):
                raise ValueError("logical GPU cap exceeds device memory")
        tool = [receiver, "--security-profile", PROFILE]
        receipt["cpu_plan"] = measured(
            [*tool, "plan-candidate", request, "-", "0", resource_path],
            root / "plan",
            args.plan_timeout,
            dict(os.environ, CUDA_VISIBLE_DEVICES=""),
            allow_failure=True,
        )
        if receipt["cpu_plan"]["returncode"]:
            raise ValueError("CPU census failed; see plan.stderr")
        census_path = root / "plan.stdout"
        census = basket.load(census_path)
        segments, scopes_fit = census_coverage(
            census, instructions, config["terminal_pc"], args.devices
        )
        receipt.update(
            status="prepared",
            census_sha256=basket.sha(census_path),
            cpu_segments=segments,
            truth_declarations=len(census["truths"]),
            raw_padded_main_bytes=4 * census["native_trace_cells"][1],
            cpu_scope_count_fits=scopes_fit,
        )
        basket.atomic_json(summary, receipt)
        if args.prepare_only:
            print(summary)
            return
        if not scopes_fit:
            raise ValueError(
                "complete CPU scope count exceeds 64 per GPU; choose more devices"
            )
        job = {
            "block": args.block,
            "devices": args.devices,
            "device_count": len(args.devices),
            "request": str(request),
            "request_sha256": receipt["request_sha256"],
            "expected_output": config["expected_output"],
            "input_sha256": config["input_sha256"],
            "segments": segments,
            "target": str(root / "case"),
            "resources": resources,
            "missing": [],
        }
        plan = {
            "schema": resident.SCHEMA,
            "profile": PROFILE,
            "repeat": 1,
            "assets": assets,
            "asset_sha256": pins,
            "device_cap_bytes": args.device_cap_bytes,
            # Compact CPU replay is the existing production resident setting.
            # Empty setup cache value gives process-local setup, never disk reuse.
            "resident_environment": {
                "STWO_RV64_GPU_CPU_REPLAY": "1",
                "STWO_ZIG_RV64_SETUP_CACHE": "",
            },
            "jobs": [job],
        }
        basket.atomic_json(root / "cuda-plan.json", plan)
        pending = resident.produce_job(plan, job)
        # Qualification reconstructs authority in a separate CUDA-disabled process.
        result = resident.qualify_job(plan, job, pending)
        report = basket.load(root / "case" / "receiver-0.stdout")
        accept(report, config["expected_output"])
        trial = result["trials"][0]
        if (
            trial["instructions"] != instructions
            or report["cpu_proofs"] != segments
            or report["truth_proofs"] != trial["truths"]
        ):
            raise ValueError(
                "CUDA producer and fresh receiver coverage disagree with the complete execution"
            )
        basket.atomic_json(root / "case" / "result.json", result)
        receipt.update(
            status="accepted",
            proof_verified=True,
            result_sha256=basket.sha(root / "case" / "result.json"),
        )
    except (OSError, RuntimeError, ValueError) as error:
        receipt.update(status="failed", error=str(error))
        if hasattr(error, "measurement"):
            receipt["failed_stage_measurement"] = error.measurement
        raise
    finally:
        basket.atomic_json(summary, receipt)
    print(summary)


if __name__ == "__main__":
    main()
