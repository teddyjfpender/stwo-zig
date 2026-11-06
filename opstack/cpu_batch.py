#!/usr/bin/env python3
"""Measure bounded CPU setup reuse and independently receive every durable proof."""

import argparse
import json
import os
import platform
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from opstack.cpu import PROFILE, accept, batch_steps, corruption_trials, measured, sha
from opstack.resident import validate_case


def validate_index(index, names, repeat):
    rows = index.get("requests")
    if (
        index.get("schema") != "rv64-cpu-resident-batch/v1"
        or index.get("security_profile") != PROFILE
        or index.get("security_qualified") is not False
        or index.get("independent_reception") is not False
        or not isinstance(rows, list)
        or len(rows) != repeat * len(names)
    ):
        raise ValueError("invalid resident production index")
    for ordinal, row in enumerate(rows):
        if (
            row.get("ordinal") != ordinal
            or row.get("repeat") != ordinal // len(names)
            or row.get("name") != names[ordinal % len(names)]
            or type(row.get("wall_ns")) is not int
            or row["wall_ns"] <= 0
        ):
            raise ValueError("resident production order or timing mismatch")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--benchmark", type=Path, required=True)
    p.add_argument("--runner", type=Path, required=True)
    p.add_argument("--resources", type=Path, required=True)
    p.add_argument("--artifacts", type=Path, required=True)
    p.add_argument("--cases", nargs="+", default=["120794432", "121057303"])
    p.add_argument("--repeat", type=int, default=2)
    p.add_argument("--workers", type=int, default=4)
    p.add_argument("--setup-workers", type=int, default=1)
    p.add_argument("--batch-steps", type=int)
    p.add_argument("--key-bytes", type=int, default=1 << 30)
    p.add_argument("--timeout", type=int, default=7200)
    p.add_argument(
        "--receiver-setup", choices=("committed", "identity-only"), default="committed"
    )
    args = p.parse_args()
    if (
        not 1 <= args.repeat <= 4
        or not 1 <= len(args.cases) <= 32
        or len(set(args.cases)) != len(args.cases)
    ):
        p.error("repeat 1..4, distinct cases 1..32")
    if (
        not 1 <= args.workers <= 8
        or not 1 <= args.setup_workers <= 8
        or not 1 <= args.key_bytes <= 4 << 30
        or not 1 <= args.timeout <= 21600
    ):
        p.error("workers 1..8, positive key budget up to 4 GiB, timeout 1..21600")
    if any(key.startswith("STWO_") for key in os.environ):
        raise ValueError("unset ambient STWO_* selections")
    resources = json.loads(args.resources.read_text())
    cases = []
    guest = None
    for case in args.cases:
        if not case.isdecimal():
            p.error("case must be a mainnet block number")
        request = json.loads((args.benchmark / f"{case}-proof-config.json").read_text())
        execution = json.loads((args.benchmark / f"{case}-rv64.json").read_text())
        oracle = json.loads((args.benchmark / f"{case}-oracle.json").read_text())
        if validate_case(request, execution, oracle) != 10:
            raise ValueError("requires OP Mainnet")
        if guest is not None and request["elf_sha256"] != guest:
            raise ValueError("guest changes within batch")
        guest = request["elf_sha256"]
        for key in ("elf", "input"):
            if sha(request[key]) != request[key + "_sha256"]:
                raise ValueError(key + " identity mismatch")
        request.update(
            batch_steps=batch_steps(request, args.batch_steps),
            workers=args.workers,
            max_batches=0,
            max_steps=execution["instructions"] + 1,
        )
        cases.append((case, request))
    args.artifacts.mkdir(parents=True, exist_ok=False)
    root = args.artifacts.resolve()
    resources_path = root / "resources.json"
    resources_path.write_text(json.dumps(resources, indent=2) + "\n")
    items = []
    for case, request in cases:
        path = root / f"request-{case}.json"
        path.write_text(json.dumps(request, indent=2) + "\n")
        items.append(
            {"name": case, "request": str(path), "resources": str(resources_path)}
        )
    manifest = {
        "schema": "rv64-cpu-resident-inputs/v1",
        "immutable_host_key_bytes": args.key_bytes,
        "repeat": args.repeat,
        "requests": items,
    }
    manifest_path = root / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    receipt = {
        "schema": "stwo.opstack.cpu-resident.v1",
        "scope": "complete native STARK production and separate fresh durable reception; no recursive root or L1 derivation",
        "security_qualified": False,
        "profile": PROFILE,
        "platform": platform.platform(),
        "logical_cpus": os.cpu_count(),
        "setup_build_workers": args.setup_workers,
        "native_pool_workers": args.workers,
        "receiver_source_keys": args.receiver_setup,
        "runner_sha256": sha(args.runner),
        "harness_sha256": sha(__file__),
        "manifest": manifest,
        "proof_verified": False,
        "receivers": [],
    }

    def checkpoint():
        (root / "summary.json").write_text(json.dumps(receipt, indent=2) + "\n")

    checkpoint()
    tool = [args.runner.resolve(), "--security-profile", PROFILE]
    env = dict(os.environ, STWO_ZIG_RV64_SETUP_BUILD_THREADS=str(args.setup_workers))
    producer_env = dict(env, STWO_ZIG_RV64_SETUP_CACHE="")
    receiver_env = dict(env)
    if args.receiver_setup == "identity-only":
        receiver_env["STWO_ZIG_RV64_RECEIVER_IDENTITY_ONLY_CPU"] = "1"
    output = root / "proofs"
    receipt["produce"] = measured(
        [*tool, "batch-candidate", manifest_path, output],
        root / "produce",
        args.timeout,
        producer_env,
        True,
    )
    checkpoint()
    if receipt["produce"]["returncode"]:
        raise RuntimeError("resident producer failed; see produce.stderr")
    index = json.loads((output / "index.json").read_text())
    validate_index(index, args.cases, args.repeat)
    receipt["production_index"] = index
    for ordinal in range(args.repeat * len(cases)):
        case, request = cases[ordinal % len(cases)]
        # Receiver authority and paths come from this harness's own plan.
        # A producer index never supplies configuration or trusted proof paths.
        proof = output / f"{ordinal:06d}-{case}"
        verifier = [
            *tool,
            "verify-candidate",
            root / f"request-{case}.json",
            proof,
            resources["fixed_setup_bytes"],
            6 << 30,
        ]
        prefix = root / f"receive-{ordinal:06d}"
        row = measured(verifier, prefix, args.timeout, receiver_env, True)
        receipt["receivers"].append(row)
        checkpoint()
        if row["returncode"]:
            raise RuntimeError("fresh resident-bundle reception failed")
        report = json.loads(prefix.with_suffix(".stdout").read_text())
        accept(report, request["expected_output"])
        row["report"] = report
    receipt["corruption"] = corruption_trials(
        proof, verifier, root, args.timeout, receiver_env
    )
    receipt["artifacts"] = {
        str(path.relative_to(output)): {
            "bytes": path.stat().st_size,
            "sha256": sha(path),
        }
        for path in sorted(output.rglob("*"))
        if path.is_file()
    }
    receipt["proof_verified"] = True
    receipt["tampered_proof_rejected"] = True
    checkpoint()
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
