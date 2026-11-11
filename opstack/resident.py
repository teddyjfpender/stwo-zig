#!/usr/bin/env python3
"""Package measured OP cases for the existing bounded resident GPU producer.

Run the producer from the output directory: request asset paths are relative to
that directory so the package can be copied to a GPU host without editing pins.
The qualified host's template supplies every resource/security/format decision.
This prepares inputs; it does not claim GPU fit or proof acceptance.
"""

import argparse
import copy
import hashlib
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.rv64 import rv64_resident_basket as resident_policy


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def validate_case(request, execution, oracle):
    output = bytes.fromhex(request["expected_output"])
    if len(output) != 43 or output[32] != 1 or output[41:] != b"OP":
        raise ValueError("requires OP execution schema")
    if (
        request.get("execution_profile") != "ethereum_services_v3"
        or execution.get("status") != "completed"
        or execution.get("verified_output") is not True
        or execution.get("proof_verified") is not False
        or execution["output"] != request["expected_output"]
        or execution["pc"] != request["terminal_pc"]
        or request.get("max_batches", 0) != 0
    ):
        raise ValueError("requires complete measured v3 execution")
    if (
        oracle.get("oracle") != "Unicorn2.1.4"
        or oracle.get("completed") is not True
        or oracle.get("proof_verified") is not False
        or oracle["exact_steps_verified"] != execution["instructions"]
        or oracle["output"] != execution["output"]
        or oracle["post_store_pc"] != execution["pc"]
        or oracle["final_registers"] != execution["final_registers"]
        or any(oracle[k] != request[k] for k in ("elf_sha256", "input_sha256"))
        or any(execution[k] != v for k, v in oracle["services"].items())
    ):
        raise ValueError("independent execution receipt differs")
    return int.from_bytes(output[33:41], "little")


def prepare(benchmark, template, cases, output, batch_steps, workers, devices):
    if not 1 <= batch_steps < 1 << 23 or not 1 <= workers <= 32:
        raise ValueError("invalid native geometry/workers")
    if not 1 <= len(cases) <= 256 or len(set(cases)) != len(cases):
        raise ValueError("distinct cases, 1..256")
    if devices not in (1, 2, 4):
        raise ValueError("device count 1, 2 or 4")
    # Reuse the production harness's admission policy rather than defining an
    # OP-specific scheduler or changing its resource defaults.
    recursion = resident_policy.recursion_options(template, True, [devices], True)
    if recursion.get("recursion_worker_budget", 0) > workers:
        raise ValueError("recursion worker budget exceeds native workers")
    resources = resident_policy.device_resources(template["resources"], devices)
    if resources.get("park_main") is not False:
        raise ValueError("resident requests require park_main=false")
    for key in ("fixed_setup_bytes", "retained_frontend_bytes"):
        resident_policy.positive(resources.get(key), key)
    if template.get("schema") != "rv64-ethereum-basket-inputs/v1":
        raise ValueError("requires a qualified resident manifest template")
    if template.get("profile", resident_policy.PROFILE) != resident_policy.PROFILE:
        raise ValueError("requires the existing resident security profile")
    manifest = copy.deepcopy(template)
    manifest.update(
        blocks={}, execution_order=[], warm_order=[], repeat=1, resources=resources
    )
    checked, guest_hash, chain_id = [], None, None
    for ordinal, case in enumerate(cases):
        if Path(case).name != case or case in (".", ".."):
            raise ValueError("case must be a basename")
        request = json.loads((benchmark / f"{case}-proof-config.json").read_text())
        execution = json.loads((benchmark / f"{case}-rv64.json").read_text())
        oracle = json.loads((benchmark / f"{case}-oracle.json").read_text())
        chain = validate_case(request, execution, oracle)
        if chain_id is not None and chain_id != chain:
            raise ValueError("chain identity changes within resident session")
        chain_id = chain
        if guest_hash is not None and guest_hash != request["elf_sha256"]:
            raise ValueError("guest identity changes within resident session")
        guest_hash = request["elf_sha256"]
        for key in ("elf", "input"):
            if sha(request[key]) != request[key + "_sha256"]:
                raise ValueError(key + " identity mismatch")
        request.update(
            elf="assets/guest.elf",
            input=f"inputs/{ordinal}.opx",
            workers=workers,
            batch_steps=batch_steps,
            max_steps=execution["instructions"] + 1,
            output_directory=f"capture/{ordinal}",
        )
        segments = (execution["instructions"] + batch_steps - 1) // batch_steps
        manifest["blocks"][str(ordinal)] = {
            "request": f"requests/{ordinal}.json",
            "jobs": "-",
            "prefix_count": 0,
            "expected_cpu_segments": segments,
        }
        manifest["execution_order"].append(ordinal)
        checked.append((case, request, execution, oracle))
    output.mkdir(parents=True, exist_ok=False)
    for directory in ("assets", "inputs", "requests", "evidence"):
        (output / directory).mkdir()
    for ordinal, (case, request, execution, oracle) in enumerate(checked):
        original = json.loads((benchmark / f"{case}-proof-config.json").read_text())
        if ordinal == 0:
            shutil.copyfile(original["elf"], output / "assets/guest.elf")
        shutil.copyfile(original["input"], output / request["input"])
        # Recheck copied bytes; source modification between planning and copy fails.
        for key in ("elf", "input"):
            if sha(output / request[key]) != request[key + "_sha256"]:
                raise ValueError("copied " + key + " identity mismatch")
        write(output / f"requests/{ordinal}.json", request)
        write(
            output / f"evidence/{ordinal}.json",
            {"case": case, "execution": execution, "oracle": oracle},
        )
    write(output / "manifest.json", manifest)
    package = {
        str(p.relative_to(output)): sha(p)
        for p in sorted(output.rglob("*"))
        if p.is_file()
    }
    write(
        output / "package.json",
        {
            "schema": "stwo.opstack.resident-inputs.v1",
            "proof_verified": False,
            "scope": "OP execution only; no L1 derivation or settlement",
            "template_canonical_sha256": hashlib.sha256(
                json.dumps(template, sort_keys=True).encode()
            ).hexdigest(),
            "chain_id": chain_id,
            "cases": cases,
            "files": package,
            "run_cwd": "package directory",
            "device_count": devices,
            "capacity_qualified": False,
            "producer_arguments": ["combined-batch", "manifest.json", "proofs"],
        },
    )
    return manifest


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--benchmark", type=Path, required=True)
    p.add_argument("--template", type=Path, required=True)
    p.add_argument("--cases", nargs="+", required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--batch-steps", type=int, default=4_194_303)
    p.add_argument("--workers", type=int, default=2)
    p.add_argument("--devices", type=int, choices=(1, 2, 4), default=1)
    args = p.parse_args()
    prepare(
        args.benchmark,
        json.loads(args.template.read_text()),
        args.cases,
        args.output,
        args.batch_steps,
        args.workers,
        args.devices,
    )
    print(args.output / "manifest.json")


if __name__ == "__main__":
    main()
