#!/usr/bin/env python3
"""Prove a complete admitted OP execution and freshly receive its durable proof.

Uses the current native GPU-compatible service roster on CPU. No recursion,
SNARK wrapping, or whole-protocol security qualification is implied.
"""

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from opstack.process_metrics import peak_rss_bytes
from opstack.native_profiles import DEFAULT_NATIVE_PROFILE, NATIVE_PROFILES

PROFILE = DEFAULT_NATIVE_PROFILE


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def batch_steps(config, override=None):
    """Preserve declared geometry unless the operator explicitly changes it."""
    selected = config.get("batch_steps", 1048575) if override is None else override
    if type(selected) is not int or not 1 <= selected < 1 << 23:
        raise ValueError("batch steps must be an integer in 1..2^23-1")
    return selected


def measured(command, prefix, timeout, env, allow_failure=False):
    start = time.monotonic_ns()
    timed_out = False
    heartbeat = prefix.with_suffix(".heartbeat.json")
    heartbeat_tmp = prefix.with_suffix(".heartbeat.tmp")
    with (
        prefix.with_suffix(".stdout").open("wb") as out,
        prefix.with_suffix(".stderr").open("wb") as err,
    ):
        process = subprocess.Popen(
            [str(x) for x in command], stdout=out, stderr=err, env=env
        )
        try:
            deadline = time.monotonic() + timeout
            last_update = 0.0
            last_message = start
            while True:
                pid, status, usage = os.wait4(process.pid, os.WNOHANG)
                if pid:
                    process.returncode = os.waitstatus_to_exitcode(status)
                    break
                if time.monotonic() >= deadline:
                    timed_out = True
                    process.kill()
                    _, status, usage = os.wait4(process.pid, 0)
                    process.returncode = os.waitstatus_to_exitcode(status)
                    break
                now = time.monotonic()
                now_ns = time.monotonic_ns()
                if now_ns - last_message >= 30_000_000_000:
                    print(
                        f"CPU_STAGE {prefix.name} elapsed_s={(now_ns - start) / 1e9:.1f}",
                        file=sys.stderr,
                        flush=True,
                    )
                    last_message = now_ns
                if now - last_update >= 1:
                    heartbeat_tmp.write_text(
                        json.dumps(
                            {
                                "schema": "stwo.opstack.cpu-supervisor.v1",
                                "child_pid_in_namespace": process.pid,
                                "last_observed_unix_ns": time.time_ns(),
                                "elapsed_ns": time.monotonic_ns() - start,
                                "remaining_s": max(0, deadline - now),
                            }
                        )
                        + "\n"
                    )
                    heartbeat_tmp.replace(heartbeat)
                    last_update = now
                time.sleep(0.05)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            heartbeat.unlink(missing_ok=True)
            heartbeat_tmp.unlink(missing_ok=True)
    receipt = {
        "command": [str(x) for x in command],
        "wall_ns": time.monotonic_ns() - start,
        "peak_rss_bytes": peak_rss_bytes(usage),
        "peak_rss_scope": "wait4 per child; measured high-water RSS, not a memory cap",
        "user_cpu_s": usage.ru_utime,
        "system_cpu_s": usage.ru_stime,
        "returncode": process.returncode,
        "timed_out": timed_out,
    }
    prefix.with_suffix(".json").write_text(json.dumps(receipt, indent=2) + "\n")
    if process.returncode and not allow_failure:
        raise RuntimeError(f"CPU stage failed; see {prefix}.stderr")
    return receipt


def accept(report, expected, profile=None):
    if (
        report.get("accepted") is not True
        or report.get("completed_ethereum_block") is not True
    ):
        raise ValueError("fresh receiver did not accept complete execution")
    if report.get("security_qualified") is not False:
        raise ValueError("unexpected security qualification")
    if profile is not None and (
        profile not in NATIVE_PROFILES or report.get("security_profile") != profile
    ):
        raise ValueError("fresh receiver native profile mismatch")
    output = report.get("output")
    if isinstance(output, str):
        output = list(output.encode("utf-8"))
    if output != list(bytes.fromhex(expected)):
        raise ValueError("fresh receiver terminal output mismatch")


def corruption_trials(proof_directory, verifier, artifacts, timeout, env, record=None):
    """Exercise transport and verifier rejection, restoring exact durable bytes."""
    proof = proof_directory / "cpu-0.bin"
    data = proof.read_bytes()
    if not data:
        raise ValueError("missing CPU proof bytes")
    mutated = bytearray(data)
    mutated[len(mutated) // 2] ^= 1
    metadata_path = proof_directory / "bundle.json"
    metadata_bytes = metadata_path.read_bytes()
    results = {}
    try:
        proof.write_bytes(mutated)
        for name, rehash in (("tamper", False), ("tamper-rehashed", True)):
            if rehash:
                metadata = json.loads(metadata_bytes)
                metadata["cpus"][0]["proof"]["sha256"] = list(
                    hashlib.sha256(mutated).digest()
                )
                metadata_path.write_text(json.dumps(metadata) + "\n")
            row = measured(verifier, artifacts / name, timeout, env, True)
            results[name] = row
            if record is not None:
                record(name, row)
            expected = "RootMismatch" if rehash else "WideBundleFileChanged"
            error = (artifacts / (name + ".stderr")).read_text().strip()
            if row["returncode"] <= 0 or error != "error: " + expected:
                raise ValueError(
                    f"corruption did not reach expected rejection {expected}: {error}"
                )
    finally:
        proof.write_bytes(data)
        metadata_path.write_bytes(metadata_bytes)
    return results


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--request", type=Path, required=True)
    p.add_argument("--execution", type=Path, required=True)
    p.add_argument("--runner", type=Path, required=True)
    p.add_argument(
        "--transition-statement",
        type=Path,
        help="independently pinned anchored OP Mainnet statement for an OD guest",
    )
    p.add_argument("--artifacts", type=Path, required=True)
    p.add_argument(
        "--batch-steps",
        type=int,
        help="explicit geometry override; otherwise preserve request (fallback 1048575)",
    )
    p.add_argument(
        "--workers", type=int, default=1, help="native proof pool budget, 1..32"
    )
    p.add_argument("--native-profile", choices=NATIVE_PROFILES, default=PROFILE)
    p.add_argument(
        "--plan-first",
        action="store_true",
        help="also replay a standalone source-cost plan before production (extra capture)",
    )
    p.add_argument(
        "--gkr-storage",
        choices=("default", "streamed-dense", "materialized-checkpointed"),
        default="default",
        help="producer storage strategy; proof and transcript stay identical",
    )
    p.add_argument(
        "--receiver-setup",
        choices=("committed", "identity-only"),
        default="committed",
        help="fresh source-key construction; neither choice loads producer setup files",
    )
    p.add_argument(
        "--setup-workers",
        type=int,
        default=1,
        help="independent setup-build concurrency; keep bounded separately from proof FFT workers",
    )
    p.add_argument("--receiver-setup-workers", type=int, choices=range(1, 9), default=1)
    p.add_argument(
        "--receiver-bytes",
        type=int,
        default=6 << 30,
        help="requested-live receiver admission in bytes; not an RSS cap",
    )
    p.add_argument(
        "--setup",
        choices=("ephemeral", "uncached"),
        default="ephemeral",
        help="producer-only in-memory GPU-compatible setup sharing; fresh receivers never use it",
    )
    p.add_argument(
        "--timeout", type=int, default=3600, help="per-stage wall time limit in seconds"
    )
    p.add_argument(
        "--resources",
        type=Path,
        help="explicit native admission JSON; defaults are written to the receipt directory",
    )
    args = p.parse_args()
    if (
        not 1 <= args.workers <= 32
        or not 1 <= args.setup_workers <= 8
        or not 1 <= args.timeout <= 21600
        or not 1 <= args.receiver_bytes <= 64 << 30
    ):
        p.error(
            "proof workers 1..32, setup workers 1..8, timeout 1..21600, receiver bytes 1..64 GiB"
        )
    if args.receiver_setup_workers > 1 and args.receiver_setup == "committed":
        p.error("parallel receiver setup requires --receiver-setup identity-only")
    config = json.loads(args.request.read_text())
    execution = json.loads(args.execution.read_text())
    selected_batch_steps = batch_steps(config, args.batch_steps)
    if (
        execution.get("status") != "completed"
        or execution.get("verified_output") is not True
    ):
        raise ValueError("requires completed expected execution")
    if (
        config["expected_output"] != execution["output"]
        or config["terminal_pc"] != execution["pc"]
    ):
        raise ValueError("request/execution mismatch")
    for key in ("elf", "input"):
        if sha(config[key]) != config[key + "_sha256"]:
            raise ValueError(key + " identity mismatch")
    if config["execution_profile"] != "ethereum_services_v3":
        raise ValueError("requires current admitted v3 services")
    public = bytes.fromhex(config["expected_output"])
    transition_preflight = None
    if args.transition_statement is not None:
        from opstack.recursive_transition import read_object, statement_outputs

        raw, statement = read_object(args.transition_statement, 16384)
        derivation, _ = statement_outputs(statement)
        if public != derivation:
            raise ValueError("request does not bind the pinned anchored transition")
        instructions = execution["instructions"]
        if type(instructions) is not int or instructions <= 0:
            raise ValueError("expected a positive retired instruction count")
        # The current native candidate requires a padding row and admits at
        # most 2^22 CPU trace rows and 256 proofs including service workers.
        max_steps_per_shard = min(selected_batch_steps, (1 << 22) - 1)
        cpu_shards = (instructions + max_steps_per_shard - 1) // max_steps_per_shard
        transition_preflight = {
            "statement_sha256": hashlib.sha256(raw).hexdigest(),
            "max_steps_per_shard": max_steps_per_shard,
            "minimum_cpu_shards": cpu_shards,
            "native_proof_cap": 256,
            "blocked": cpu_shards > 256,
        }
    elif (
        len(public) != 43
        or public[32] != 1
        or int.from_bytes(public[33:41], "little") != 10
        or public[41:] != b"OP"
    ):
        raise ValueError("requires successful OP Mainnet chain 10 public output")
    args.artifacts.mkdir(parents=True, exist_ok=False)
    root = args.artifacts.resolve()
    config.update(
        batch_steps=selected_batch_steps,
        workers=args.workers,
        max_batches=0,
        max_steps=execution["instructions"] + 1,
        output_directory=str(root / "proof"),
    )
    request = root / "request.json"
    request.write_text(json.dumps(config, indent=2) + "\n")
    resources = {
        "gkr_bytes": 2 << 30,
        "global_bytes": 1 << 30,
        "retained_frontend_bytes": 2 << 30,
        "disk_bytes": 8 << 30,
        "fixed_setup_bytes": 1 << 30,
        "park_main": True,
        "recycler_cache_bytes": 64 << 20,
        "keccak_max_log": 16,
        "capture_options": {"execution_workers": 0},
        "schedule": {
            "lanes": 1,
            "workers_per_lane": args.workers,
            "memory_cap_bytes": 2 << 30,
        },
    }
    if args.resources:
        resources = json.loads(args.resources.read_text())
    resource_path = root / "resources.json"
    resource_path.write_text(json.dumps(resources, indent=2) + "\n")
    # These environment variables select semantic/operational variants. Require
    # a clean explicit benchmark instead of accidentally inheriting a warm cache.
    if any(key.startswith("STWO_") for key in os.environ):
        raise ValueError("unset STWO_* variables for a cold independent CPU benchmark")
    env = dict(os.environ, STWO_ZIG_RV64_SETUP_BUILD_THREADS=str(args.setup_workers))
    producer_env = dict(env)
    receiver_env = dict(env)
    if args.gkr_storage == "streamed-dense":
        producer_env["STWO_ZIG_GKR_TREE_CHECKPOINTS"] = "1"
    elif args.gkr_storage == "materialized-checkpointed":
        producer_env["STWO_ZIG_GKR_STREAM_BOTTOM"] = "0"
        producer_env["STWO_ZIG_GKR_TREE_CHECKPOINTS"] = "2"
    if args.receiver_setup == "identity-only":
        receiver_env["STWO_ZIG_RV64_RECEIVER_IDENTITY_ONLY_CPU"] = "1"
        receiver_env["STWO_ZIG_RV64_RECEIVER_SETUP_THREADS"] = str(
            args.receiver_setup_workers
        )
    if args.setup == "ephemeral":
        # An empty directory enables the existing identity-only/shared setup
        # path without loading or persisting any setup files. Receiver env is
        # deliberately separate and the cache owner dies with this process.
        producer_env["STWO_ZIG_RV64_SETUP_CACHE"] = ""
    tool = [args.runner.resolve(), "--security-profile", args.native_profile]
    receipt = {
        "schema": "stwo.opstack.cpu-proof.v1",
        "security_qualified": False,
        "scope": "native execution/service STARK bundle; no recursive root or L1 derivation",
        "profile": args.native_profile,
        "producer_setup": args.setup,
        "gkr_storage": args.gkr_storage,
        "setup_build_workers": args.setup_workers,
        "native_pool_workers": args.workers,
        "batch_steps": selected_batch_steps,
        "batch_steps_source": "explicit override"
        if args.batch_steps is not None
        else "request or fallback",
        "guest_instructions": execution["instructions"],
        "standalone_plan_requested": args.plan_first,
        "service_schedule": resources["schedule"],
        "receiver_setup": "independently rebuilt; no producer cache",
        "receiver_source_keys": args.receiver_setup,
        "receiver_setup_workers": args.receiver_setup_workers,
        "receiver_requested_live_bytes": args.receiver_bytes,
        "runner_sha256": sha(args.runner),
        "harness_sha256": sha(__file__),
        "platform": platform.platform(),
        "logical_cpus": os.cpu_count(),
        "request_sha256": sha(request),
        "elf_sha256": config["elf_sha256"],
        "input_sha256": config["input_sha256"],
        "proof_verified": False,
        "stages": {},
    }
    if transition_preflight is not None:
        receipt["scope"] = "native anchored derivation and execution STARK bundle"
        receipt["transition_preflight"] = transition_preflight
    summary = root / "summary.json"

    def checkpoint():
        summary.write_text(json.dumps(receipt, indent=2) + "\n")

    checkpoint()
    if transition_preflight is not None and transition_preflight["blocked"]:
        raise ValueError(
            f"anchored transition exceeds the native proof cap before services; see {summary}"
        )
    stages = [
        (
            "produce",
            [
                *tool,
                "produce-candidate",
                request,
                "-",
                root / "proof",
                "0",
                resource_path,
            ],
        ),
        (
            "receive",
            [
                *tool,
                "verify-candidate",
                request,
                root / "proof",
                resources["fixed_setup_bytes"],
                args.receiver_bytes,
            ],
        ),
    ]
    # Native production performs source/geometry/resource admission itself.
    # A separate cost census repeats execution and capture; make that explicit
    # rather than charging every complete proof request for it twice.
    if args.plan_first:
        stages.insert(
            0, ("plan", [*tool, "plan-candidate", request, "-", "0", resource_path])
        )
    for mode, command in stages:
        receipt["stages"][mode] = measured(
            command,
            root / mode,
            args.timeout,
            producer_env
            if mode == "produce"
            else receiver_env
            if mode == "receive"
            else env,
            True,
        )
        checkpoint()
        if receipt["stages"][mode]["returncode"]:
            raise RuntimeError(f"CPU {mode} failed; see {root / mode}.stderr")
    received = json.loads((root / "receive.stdout").read_text())
    accept(received, config["expected_output"], args.native_profile)
    receipt["receiver"] = received
    files = sorted((root / "proof").rglob("*"))
    receipt["artifacts"] = {
        str(f.relative_to(root)): {"bytes": f.stat().st_size, "sha256": sha(f)}
        for f in files
        if f.is_file()
    }
    verifier = [
        *tool,
        "verify-candidate",
        request,
        root / "proof",
        resources["fixed_setup_bytes"],
        args.receiver_bytes,
    ]

    def record_rejection(name, row):
        receipt["stages"][name] = row
        checkpoint()

    corruption_trials(
        root / "proof", verifier, root, args.timeout, receiver_env, record_rejection
    )
    receipt["proof_verified"] = True
    receipt["tampered_proof_rejected"] = True
    checkpoint()
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
