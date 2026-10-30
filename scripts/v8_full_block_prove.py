#!/usr/bin/env python3
"""Pinned retained Ethereum execution -> one freshly verified recursive root.

Consumes a one-pass checkpoint catalog. It never captures execution or repeats
prefixes. A complete result exists only after the binary's fresh final receiver
and the artifact audit below both pass.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

from v7_real_window_corpus import ROOT, PINS
from v8_full_block_campaign import validate_plan


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def bounded(path: Path, maximum: int) -> bytes:
    if path.stat().st_size > maximum:
        raise ValueError(f"input exceeds bounded size: {path}")
    return path.read_bytes()


def pinned(path: Path, expected: str, maximum: int) -> bytes:
    data = bounded(path, maximum)
    if len(expected) != 64 or sha(data) != expected:
        raise ValueError(f"input differs from independently selected pin: {path}")
    return data


def validate_inputs(assembly: Path, source: Path, plan_pin: str, manifest_pin: str):
    plan_bytes = pinned(assembly / "plan.json", plan_pin, 4 << 20)
    plan = json.loads(plan_bytes)
    validate_plan(plan)
    if plan["total_cycles"] != 139214856 or plan["security"] != {"queries": 70, "pow_bits": 26}:
        raise ValueError("wrong retained execution/security boundary")
    for filename, field, maximum in (("guest.elf", "elf_sha256", 32 << 20), ("input.bin", "input_sha256", 4 << 20), ("expected-output.bin", "output_sha256", 44)):
        pinned(source / filename, PINS[filename][0], maximum)
        if plan[field] != PINS[filename][0]:
            raise ValueError(f"plan/source disagreement: {field}")
    manifest_path = assembly / "execution" / "checkpoints" / "snapshots.jsonl"
    manifest_bytes = pinned(manifest_path, manifest_pin, 4 << 20)
    checkpoints = [json.loads(line) for line in manifest_bytes.splitlines() if line]
    boundaries = [0] + [w["skip_cycles"] + w["cycles"] for w in plan["windows"]]
    if len(checkpoints) != len(boundaries):
        raise ValueError("missing or extra shared checkpoints")
    checkpoint_dir = manifest_path.parent
    for row, cycle in zip(checkpoints, boundaries):
        name = f"state-{cycle}.b7win"
        if row["schema"] != "stwo-b8-execution-checkpoint-input-v1" or row["proof_verified"] is not False or row["completed_cycles"] != cycle or row["file"] != name or not 148 <= row["bytes"] <= 256 << 20:
            raise ValueError("checkpoint catalog coverage/framing mismatch")
        if (checkpoint_dir / name).stat().st_size != row["bytes"]:
            raise ValueError("checkpoint length changed")
        if any(len(row[field]) != 64 or any(c not in "0123456789abcdef" for c in row[field]) for field in ("snapshot_id", "transport_sha256")):
            raise ValueError("noncanonical checkpoint digest")
    # The binary hashes and decodes each raw checkpoint exactly once. Python
    # validates catalog pins and sizes without another multi-GB snapshot scan.
    return plan, manifest_path


def digest_text(value, length: int) -> str:
    if isinstance(value, str):
        text = value
    elif isinstance(value, list):
        raw = bytes(value)
        text = raw.decode("ascii") if len(raw) == length else raw.hex()
    else:
        raise ValueError("incorrect digest representation")
    if len(text) != length or any(c not in "0123456789abcdef" for c in text):
        raise ValueError("noncanonical published digest")
    return text


def validate_result(proof_dir: Path, plan: dict, *, resume_allowed: bool = False, native_cohort_cycles: int | None = None, immutable_admission_cache: bool = False):
    report = json.loads(bounded(proof_dir / "report.json", 1 << 20))
    benchmark = json.loads(bounded(proof_dir / "benchmark-report.json", 1 << 20))
    count = len(plan["windows"])
    if report.get("schema") != "stwo-b8-complete-execution-root-v1" or report.get("proof_verified") is not True or report.get("cycles") != plan["total_cycles"] or report.get("windows") != count or report.get("folds") != count - 1:
        raise ValueError("missing complete independently verified block result")
    if benchmark.get("schema") != "stwo-b8-full-block-one-root-benchmark-v1" or benchmark.get("independent_root_verified") is not True or (benchmark.get("queries"), benchmark.get("pow_bits")) != (70, 26) or benchmark.get("pipeline") != report or benchmark.get("unique_snapshot_decodes") != count + 1:
        raise ValueError("benchmark/core verification boundary disagreement")
    resumed = report.get("resumed_windows", 0) + report.get("resumed_original_bundles", 0) + report.get("resumed_folds", 0)
    if resumed and (not resume_allowed or report.get("fresh_complete_run") is not False or "excluded" not in report.get("timing_scope", "")):
        raise ValueError("resumed work presented as a fresh complete-run timing")
    if native_cohort_cycles is not None and benchmark.get("native_cohort_cycles") != native_cohort_cycles:
        raise ValueError("native cohort resource option mismatch")
    if bool(benchmark.get("immutable_admission_cache", False)) != immutable_admission_cache:
        raise ValueError("immutable admission-cache option mismatch")
    cache = report.get("admission_cache")
    if immutable_admission_cache:
        if not isinstance(cache, dict) or cache.get("unique_nodes") != 2 * count - 1 or cache.get("independent_derivations") != 2 * count - 1:
            raise ValueError("missing complete independently derived admission cache")
        if cache.get("temporary_fold_derivations") != report.get("resumed_folds", 0):
            raise ValueError("saved-fold independent derivation census mismatch")
        if not cache.get("key_derivation_peak_bytes", 0) >= cache.get("retained_profile_peak_bytes", 0) >= cache.get("profile_live_bytes", 0):
            raise ValueError("inconsistent cache memory accounting")
    elif cache is not None:
        raise ValueError("unexpected admission cache in baseline report")
    for field, expected in (("elf_sha256", plan["elf_sha256"]), ("input_sha256", plan["input_sha256"]), ("expected_output_sha256", plan["output_sha256"])):
        if digest_text(report[field], 64) != expected:
            raise ValueError(f"final root source mismatch: {field}")
    root = bounded(proof_dir / "root.proof", 64 << 20)
    if len(root) != report["root_bytes"] or sha(root) != digest_text(report["root_sha256"], 64):
        raise ValueError("published recursive proof changed")
    for field in ("initial_policy_id", "terminal_policy_id"):
        if digest_text(report[field], 64) == "0" * 64:
            raise ValueError("missing initial/terminal output policy binding")
    catalog = json.loads(bounded(proof_dir / "catalog.json", 16 << 20))
    nodes = catalog["nodes"]
    if catalog["window_count"] != count or len(nodes) != 2 * count - 1 or catalog["root_index"] != len(nodes) - 1:
        raise ValueError("incorrect unpadded reduction tree")
    uses = [0] * len(nodes)
    coverage = []
    for index, node in enumerate(nodes):
        if node["index"] != index:
            raise ValueError("node catalog reordering")
        if index < count:
            window = plan["windows"][index]
            if node["kind"] != (0 if window["kind"] == "native" else 1) or node["children"]:
                raise ValueError("leaf/job disagreement")
            coverage.append((window["skip_cycles"], window["cycles"]))
        else:
            children = node["children"]
            if node["kind"] != 2 or len(children) != 2 or len(set(children)) != 2 or any(child >= index for child in children):
                raise ValueError("invalid bounded fold")
            left, right = (coverage[child] for child in children)
            if left[0] + left[1] != right[0]:
                raise ValueError("nonadjacent fold coverage")
            coverage.append((left[0], left[1] + right[1]))
        for child in node["children"]:
            uses[child] += 1
    if uses != [1] * (len(nodes) - 1) + [0] or coverage[-1] != (0, plan["total_cycles"]):
        raise ValueError("reused/orphan/missing window in final tree")
    return report


def run(args) -> int:
    if not 0 < args.native_cohort_cycles <= 1 << 23:
        raise ValueError("native cohort exceeds qualified bounded geometry")
    plan, manifest = validate_inputs(args.assembly, args.source, args.plan_sha256, args.checkpoint_manifest_sha256)
    if any((w["cycles"] + args.native_cohort_cycles - 1) // args.native_cohort_cycles > 62 for w in plan["windows"] if w["kind"] == "native"):
        raise ValueError("native cohort split exceeds bounded source roster")
    binary = pinned(args.binary, args.binary_sha256, 128 << 20)
    if args.destination.exists() and not args.resume:
        raise ValueError("destination exists; preserving prior proof evidence")
    if args.destination.exists():
        previous_path = args.destination / "invocation.json"
        previous = json.loads(bounded(previous_path, 1 << 20))
        if previous.get("plan_sha256") != args.plan_sha256 or previous.get("checkpoint_manifest_sha256") != args.checkpoint_manifest_sha256:
            raise ValueError("resume selected different execution inputs")
        generation = 0
        while (args.destination / f"invocation-previous-{generation}.json").exists():
            generation += 1
        for filename in ("qualification.log", "benchmark", "build.json"):
            candidate = args.destination / filename
            if candidate.exists():
                shutil.copy2(candidate, args.destination / f"{filename}-previous-{generation}")
        shutil.copy2(previous_path, args.destination / f"invocation-previous-{generation}.json")
    else:
        args.destination.mkdir(parents=True)
    proof_dir = args.destination / "proof"
    proof_dir.mkdir(exist_ok=args.resume)
    if args.binary.resolve() != (args.destination / "benchmark").resolve():
        shutil.copy2(args.binary, args.destination / "benchmark")
    (args.destination / "selected-plan.json").write_bytes((args.assembly / "plan.json").read_bytes())
    (args.destination / "selected-checkpoints.jsonl").write_bytes(manifest.read_bytes())
    if args.build_manifest:
        build = json.loads(bounded(args.build_manifest, 16 << 20))
        if build.get("binary_sha256") != sha(binary):
            raise ValueError("build manifest binary disagreement")
        if args.build_manifest.resolve() != (args.destination / "build.json").resolve():
            shutil.copy2(args.build_manifest, args.destination / "build.json")
    env = {k: v for k, v in os.environ.items() if not k.startswith("STWO_")}
    env.update({
        "STWO_B8_BLOCK_ENABLE": "1", "STWO_B8_BLOCK_ELF": str((args.source / "guest.elf").resolve()),
        "STWO_B8_BLOCK_ELF_SHA256": PINS["guest.elf"][0], "STWO_B8_BLOCK_INPUT": str((args.source / "input.bin").resolve()),
        "STWO_B8_BLOCK_INPUT_SHA256": PINS["input.bin"][0], "STWO_B8_BLOCK_EXPECTED_OUTPUT": str((args.source / "expected-output.bin").resolve()),
        "STWO_B8_BLOCK_EXPECTED_OUTPUT_SHA256": PINS["expected-output.bin"][0], "STWO_B8_BLOCK_PLAN": str((args.assembly / "plan.json").resolve()),
        "STWO_B8_BLOCK_PLAN_SHA256": args.plan_sha256, "STWO_B8_BLOCK_CHECKPOINT_MANIFEST": str(manifest.resolve()),
        "STWO_B8_BLOCK_CHECKPOINT_MANIFEST_SHA256": args.checkpoint_manifest_sha256, "STWO_B8_BLOCK_CHECKPOINT_DIR": str(manifest.parent.resolve()),
        "STWO_B8_FULL_NATIVE_COHORT_CYCLES": str(args.native_cohort_cycles), "STWO_B8_BLOCK_OUTPUT": str(proof_dir.resolve()), "STWO_B8_BLOCK_WORKERS": str(args.workers), "STWO_B8_BLOCK_BUDGET_GIB": str(args.budget_gib),
    })
    env["STWO_B8_BLOCK_IMMUTABLE_ADMISSION_CACHE"] = "1" if args.immutable_admission_cache else "0"
    if args.resume:
        env["STWO_B8_BLOCK_RESUME"] = "1"
    command = ["/usr/bin/time", "-l", str(args.binary.resolve())]
    invocation = {"schema": "stwo-b8-full-block-proving-invocation-v1", "binary_sha256": sha(binary), "plan_sha256": args.plan_sha256,
                  "checkpoint_manifest_sha256": args.checkpoint_manifest_sha256, "cpu_only": True, "workers": args.workers,
                  "resume_requested": args.resume, "immutable_admission_cache": args.immutable_admission_cache, "budget_bytes": args.budget_gib << 30, "native_cohort_cycles": args.native_cohort_cycles, "command": command, "started_unix_ns": time.time_ns(), "report_checked": False}
    record = args.destination / "invocation.json"
    record.write_text(json.dumps(invocation, indent=2) + "\n")
    with (args.destination / "qualification.log").open("w") as output:
        result = subprocess.run(command, cwd=ROOT, env=env, stdout=output, stderr=subprocess.STDOUT, check=False)
    invocation.update(returncode=result.returncode, finished_unix_ns=time.time_ns())
    try:
        if result.returncode == 0:
            report = validate_result(proof_dir, plan, resume_allowed=args.resume, native_cohort_cycles=args.native_cohort_cycles, immutable_admission_cache=args.immutable_admission_cache)
            invocation.update(report_checked=True, root_sha256=digest_text(report["root_sha256"], 64), root_bytes=report["root_bytes"], fresh_complete_run=report.get("fresh_complete_run", True), timing_scope=report.get("timing_scope", "fresh execution-to-root invocation"))
    except Exception as error:
        invocation["artifact_audit_error"] = str(error)
        raise
    finally:
        record.write_text(json.dumps(invocation, indent=2) + "\n")
    print(f"complete block proof {'verified' if invocation['report_checked'] else 'failed'}: {args.destination}")
    return result.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("assembly", "source", "binary", "destination"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("binary-sha256", "plan-sha256", "checkpoint-manifest-sha256"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--resume", action="store_true", help="freshly verify and reuse saved stages; timings exclude prior proving")
    parser.add_argument("--immutable-admission-cache", action="store_true", help="opt in to owned independently derived admissions; saved folds freshly verified; final receiving uncached")
    parser.add_argument("--build-manifest", type=Path)
    parser.add_argument("--native-cohort-cycles", type=int, default=1 << 23)
    parser.add_argument("--workers", type=int, default=8, choices=range(1, 17))
    parser.add_argument("--budget-gib", type=int, default=60, choices=range(32, 61))
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
