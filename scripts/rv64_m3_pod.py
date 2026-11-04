#!/usr/bin/env python3
"""One-command RV64 M3 pod harness: build | inputs | prove | receive | bench | parity.

Runs ON the 2x RTX 5090 pod. Every stream builds from /workspace/m3/src/<stream>
into /workspace/m3/build/<stream>, proves into /workspace/m3/runs/<stream>, and
gets one receipt JSON per run with request wall, stage breakdown, recursion
counters, proof hashes, byte parity against the accepted-v7 controls and the
verdict of a fresh, separate, cache-disabled CPU-only receiver process.

  python3 rv64_m3_pod.py build   [--stream S] [--only zig|cuda] [--jobs N]
  python3 rv64_m3_pod.py inputs                        # once per pod (copies full15 inputs)
  python3 rv64_m3_pod.py prove   BLOCK [--gpus 2] [--stream S] [--tag T] [--env K=V] [--nsys]
  python3 rv64_m3_pod.py receive BLOCK --run DIR [--receiver PATH]
  python3 rv64_m3_pod.py bench   BLOCK [--gpus 2] ...  # prove, then receive, one receipt
  python3 rv64_m3_pod.py parity  --run DIR             # recompute parity vs accepted controls

GPU jobs take /workspace/m3/locks/gpu.lock (flock -w 7200) for the producer only;
the receiver is CPU-only and never holds the GPU lock.  Owner rule: develop and
measure only on 26235156 and 24628607; this harness refuses other blocks unless
--allow-scale-up is passed (final integration scale-up only).
"""
import argparse
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

M3 = Path(os.environ.get("RV64_M3_ROOT", "/workspace/m3"))
FULL15 = Path("/workspace/rv64-gpu-session/two-gpu-ready-fixed-full15")
SESSION_INPUTS = Path("/workspace/rv64-gpu-session/inputs")
ZIG = os.environ.get("RV64_M3_ZIG", "/workspace/zig/zig")
NVCC = "/usr/local/cuda/bin/nvcc"
DEV_BLOCKS = {26235156, 24628607}
GPU_LOCK = M3 / "locks/gpu.lock"
GPU_LOCK_WAIT = 7200
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import rv64_resident_basket as R  # noqa: E402
B = R.B


def sha(path):
    return B.sha(Path(path))


def now():
    return time.strftime("%Y%m%dT%H%M%S")


def src_root(stream):
    root = M3 / "src" / stream
    if not (root / "src/integrations/riscv_cuda/build.zig").is_file():
        raise SystemExit(f"no synced source tree at {root}; run podsync <worktree> {stream}")
    return root


def source_commit(root):
    marker = root / ".m3-commit"
    return marker.read_text().strip() if marker.is_file() else None


def build_paths(stream):
    base = M3 / "build" / stream
    return {"base": base, "driver": base / "zig-out/bin/rv64-word16-ethereum-gpu-combined",
            "receiver": base / "zig-out/bin/rv64-word16-ethereum-recursion-receiver",
            "library": base / "cuda/native/libstwo-rv64-native.so", "receipt": base / "build.json"}


# ----------------------------------------------------------------------------- build

def run_logged(argv, log, cwd=None, env=None):
    started = time.monotonic()
    with open(log, "w") as handle:
        code = subprocess.run(argv, cwd=cwd, env=env, stdout=handle, stderr=subprocess.STDOUT).returncode
    if code:
        sys.stderr.write(Path(log).read_text()[-4000:])
        raise SystemExit(f"command failed ({code}): {' '.join(map(str, argv))}; log {log}")
    return round(time.monotonic() - started, 2)


def build(args):
    root = src_root(args.stream)
    paths = build_paths(args.stream)
    paths["base"].mkdir(parents=True, exist_ok=True)
    logs = paths["base"] / "logs"
    logs.mkdir(exist_ok=True)
    receipt = B.load(paths["receipt"]) if paths["receipt"].is_file() else {}
    receipt.update({"schema": "rv64-m3-build/v1", "stream": args.stream, "source_root": str(root),
                    "source_commit": source_commit(root), "host": os.uname().nodename})
    if args.only in (None, "zig"):
        env = dict(os.environ, ZIG_GLOBAL_CACHE_DIR=str(M3 / "cache/zig-global"))
        steps = {}
        for step in ("build-rv64-ethereum-gpu-combined", "build-rv64-ethereum-recursion-receiver"):
            # The production driver is GNU x86_64_v4+sha ReleaseFast (matches the
            # accepted d5766d83 driver's AVX-512/SHA code; -Dtarget alone is baseline).
            steps[step] = run_logged([ZIG, "build", step, "-Dtarget=x86_64-linux-gnu", "-Dcpu=x86_64_v4+sha",
                                      "-Doptimize=ReleaseFast", "--cache-dir", str(root / ".zig-cache"),
                                      "--prefix", str(paths["base"] / "zig-out")],
                                     logs / f"{step}.log", cwd=root / "src/integrations/riscv_cuda", env=env)
        receipt["zig_seconds"] = steps
        receipt["driver_sha256"] = sha(paths["driver"])
        receipt["receiver_sha256"] = sha(paths["receiver"])
    if args.only in (None, "cuda"):
        cat = Path(args.catalogues)
        command = [sys.executable, str(root / "scripts/rv64_cuda_resident_image_build.py"), "--source-root", str(root),
                   "--core-domain", str(cat / "core"), "--core-projection", str(cat / "projection"),
                   "--global-projection", str(cat / "global"), "--truth-domain", str(cat / "truth"),
                   "--truth-partitions", str(cat / "truth-parts"), "--truth-rational", str(cat / "rational"),
                   "--outer-circuit-dir", str(cat / "outer"), "--build", str(paths["base"] / "cuda"),
                   "--object-store", str(M3 / "cache/cuda-objects"), "--catalogue-root", str(cat),
                   "--nvcc", NVCC, "--jobs", str(args.jobs), "--compile-timeout", "2400", "--link-timeout", "1800",
                   "--split-core-role", "8", "--split-core-role", "41", "--split-core-role", "43", "--split-core-role", "44",
                   "--core-module-max-bytes", "32768"]
        receipt["cuda_seconds"] = run_logged(command, logs / "cuda-image.log", cwd=root)
        log = (logs / "cuda-image.log").read_text()
        receipt["cuda_objects"] = {"compiled": log.count('"cached": false'), "cached": log.count('"cached": true')}
        receipt["library_sha256"] = sha(paths["library"])
        receipt["stack_admission"] = stack_admission(paths["library"], args.max_stack_bytes)
        receipt["catalogues"] = str(cat)
        receipt["catalogue_note"] = ("catalogues-v2 = frozen rebuild-package catalogue (48/49 core roles byte-equal to "
                                     "rv64-joined-fixtures --domain at fbb6c6c76; 8/41 equal --grouped-domain) with core "
                                     "roles 43/44 replaced by --grouped-domain output, split per group. Native .cu sources "
                                     "come from this stream's tree. Regenerate if a stream changes AIR/outer kernels.")
    B.atomic_json(paths["receipt"], receipt)
    print(json.dumps(receipt, indent=2))


def stack_admission(library, limit):
    """Per-thread stack frames become a persistent device local-memory reservation
    (frame x resident threads: 170 SMs x 1536 on a 5090), outside the CUDA pool.
    The accepted image's worst kernel uses 12,544 B; an unsharded core role 44
    (19,832 B) costs ~1.9 GB more and OOMs 24628607. Fail such images early."""
    import re
    text = subprocess.run([str(Path(NVCC).parent / "cuobjdump"), "-res-usage", str(library)], capture_output=True,
                          text=True, check=True).stdout
    rows, function = [], None
    for line in text.splitlines():
        m = re.search(r"Function (\S+):", line)
        if m:
            function = m.group(1)
            continue
        m = re.search(r"STACK:(\d+)", line)
        if m and function:
            rows.append((int(m.group(1)), function))
            function = None
    rows.sort(reverse=True)
    result = {"functions": len(rows), "limit_bytes": limit, "top": [{"stack_bytes": s, "function": f[:120]} for s, f in rows[:8]],
              "reservation_estimate_bytes_5090": rows[0][0] * 170 * 1536 if rows else 0}
    result["admitted"] = bool(rows) and rows[0][0] <= limit
    if not result["admitted"]:
        raise SystemExit("stack admission failed: " + json.dumps(result["top"][:3]) + " (pass --max-stack-bytes to override)")
    return result


# ----------------------------------------------------------------------------- inputs

def inputs(args):
    """Copy the full15 harness inputs into /workspace/m3/inputs (read-only originals)."""
    out = M3 / "inputs"
    (out / "requests").mkdir(parents=True, exist_ok=True)
    shutil.copyfile(FULL15 / "run/plan.json", out / "plan-template.json")
    shutil.copyfile(FULL15 / "source-authority.json", out / "source-authority.json")
    shutil.copyfile(FULL15 / "accepted-v7.json", out / "accepted-v7.json")
    shutil.copyfile(SESSION_INPUTS / "guest.elf", out / "guest.elf")
    for request in sorted((FULL15 / "requests").glob("*.json")):
        block = request.stem
        value = B.load(request)
        source = Path(value["input"])
        local = out / f"{block}.bin"
        if not local.is_file() or sha(local) != value["input_sha256"]:
            shutil.copyfile(source, local)
        value["elf"], value["input"] = str(out / "guest.elf"), str(local)
        value["output_directory"] = None  # set per run
        if sha(local) != value["input_sha256"] or sha(out / "guest.elf") != value["elf_sha256"]:
            raise SystemExit("input copy hash mismatch for " + block)
        B.atomic_json(out / "requests" / f"{block}.json", value)
    print(json.dumps({"inputs": str(out), "requests": len(list((out / "requests").glob("*.json")))}))


# ----------------------------------------------------------------------------- prove

def make_plan(args, run, paths, root):
    template = B.load(M3 / "inputs/plan-template.json")
    job = copy.deepcopy(next(j for j in template["jobs"] if j["block"] == args.block))
    request = B.load(M3 / "inputs/requests" / f"{args.block}.json")
    request["output_directory"] = str(run / "capture")
    request_path = run / "request.json"
    B.atomic_json(request_path, request)
    devices = list(range(args.gpus))
    job.update(devices=devices, device_count=args.gpus, request=str(request_path), request_sha256=sha(request_path),
               target=str(run / "case"))
    if args.gpus == 1:
        schedule = job["resources"]["schedule"]
        total = sum(schedule.get("lane_workers") or [schedule["workers_per_lane"]] * schedule["lanes"])
        schedule.update(lanes=1, workers_per_lane=total, lane_workers=[total])
    plan = copy.deepcopy(template)
    plan["jobs"] = [job]
    plan["execution_order"] = [args.block]
    plan["gpu_lock"] = None  # the harness holds /workspace/m3/locks/gpu.lock via flock(2) itself
    plan["producer_cwd"] = str(root)
    plan["assets"] = {"driver": str(paths["driver"]), "library": str(paths["library"]),
                      "receiver": str(paths["receiver"]), "recursive_receiver": str(paths["receiver"])}
    plan["asset_sha256"] = {k: sha(v) if Path(v).is_file() else None for k, v in plan["assets"].items()}
    plan["runtime_target_sha256"] = plan["asset_sha256"]["library"]
    plan["producer_source_commit"] = source_commit(root)
    plan["resident_environment"] = dict(kv.split("=", 1) for kv in args.env)
    B.atomic_json(run / "plan.json", plan)
    return plan, job


def acquire_gpu_lock():
    GPU_LOCK.parent.mkdir(parents=True, exist_ok=True)
    handle = GPU_LOCK.open("a")
    deadline = time.monotonic() + GPU_LOCK_WAIT
    while True:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return handle
        except BlockingIOError:
            if time.monotonic() > deadline:
                raise SystemExit("GPU lock wait exceeded 7200 s")
            time.sleep(2)


def produce(plan, job, run, nsys=None):
    """R.produce_job, with an optional Nsight Systems wrapper and the m3 GPU lock."""
    target = Path(job["target"])
    target.mkdir(parents=True, exist_ok=False)
    for key in ("driver", "library"):
        path = plan["assets"][key]
        if sha(path) != plan["asset_sha256"][key]:
            raise ValueError("asset changed since planning: " + key)
    manifest = R.producer_manifest(plan, job)
    B.atomic_json(target / "manifest.json", manifest)
    worker = {"device": ",".join(map(str, job["devices"])), "device_caps_bytes": [plan["device_cap_bytes"]] * job["device_count"],
              "planned_cpu_workers": job["segments"], "retained_scopes": 64}
    environment = {k: v for k, v in os.environ.items() if not k.startswith("STWO_RV64_")}
    environment.update(plan["resident_environment"])
    environment = B.worker_environment(worker, environment)
    for key in ("STWO_RV64_GPU_HOST_RETAINED", "STWO_RV64_DEEP_TIMING", "STWO_RV64_DEEP_COORDINATES", "STWO_RV64_PCS_PHASE_TIMING"):
        if key not in plan["resident_environment"]:
            environment.pop(key, None)
    environment["STWO_RV64_GPU_LIBRARY"] = plan["assets"]["library"]
    environment["CUDA_MODULE_LOADING"] = "EAGER"
    argv = [plan["assets"]["driver"], "combined-batch", str(target / "manifest.json"), str(target / "batch")]
    if nsys:
        argv = ["nsys", "profile", "--trace=cuda", "--sample=none", "--cpuctxsw=none",
                "--force-overwrite=true", "-o", str(run / "nsys" / "timeline")] + argv
        (run / "nsys").mkdir(exist_ok=True)
    lock = acquire_gpu_lock()
    try:
        monitor = B.DeviceMonitor(worker["device"])
        monitor.thread.start()
        try:
            usage = B.measure(argv, target, "producer", environment, cwd=plan["producer_cwd"])
        finally:
            memory = monitor.finish()
            B.atomic_json(target / "gpu-memory.json", memory)
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN)
        lock.close()
    if nsys and (run / "nsys/timeline.nsys-rep").is_file():
        subprocess.run(["nsys", "export", "--type", "sqlite", "--force-overwrite", "true", "-o",
                        str(run / "nsys/timeline.sqlite"), str(run / "nsys/timeline.nsys-rep")], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    if usage.get("exit_code") != 0:
        raise SystemExit(f"producer failed exit={usage.get('exit_code')}; see {target}/producer.stderr")
    log = (target / "producer.stdout").read_text(errors="replace") + (target / "producer.stderr").read_text(errors="replace")
    pending = {"status": "produced_pending_verification", "accepted": False, "plan_sha256": R.plan_identity(plan),
               "block": job["block"], "device_count": job["device_count"], "producer_process": usage,
               "physical_gpu_memory": memory, "markers": R.request_markers(log, job["block"], job["device_count"], plan.get("repeat", 2)),
               "gpu": B.gpu_diagnostics(target / "producer.stderr"),
               "environment": {k: v for k, v in environment.items() if k.startswith(("STWO_RV64_", "CUDA_"))},
               "artifact_snapshot": R.produced_snapshot(plan, job),
               "log_sha256": {name: sha(target / name) for name in ("producer.stdout", "producer.stderr")}}
    B.atomic_json(target / "produced.json", pending)
    return pending


def proof_dir(job):
    return Path(job["target"]) / "batch/trial-0" / str(job["block"]) / "proof"


def numeric(value):
    return {k: v for k, v in value.items() if isinstance(v, (int, float)) and not isinstance(v, bool)}


def stage_breakdown(proof, markers):
    report = B.load(proof / "report.json")
    combined = B.load(proof / "combined-report.json") if (proof / "combined-report.json").is_file() else {}
    s = lambda ns: None if ns is None else round(ns / 1e9, 3)
    stages = {"request_wall_s": s(markers.get(0) if isinstance(markers, dict) else None),
              "capture_s": s(report.get("capture_ns")), "setup_s": s(report.get("setup_ns")),
              "native_prove_s": s(report.get("prove_ns")), "native_verify_s": s(report.get("same_process_verify_ns")),
              "native_total_before_report_s": s(report.get("total_before_report_ns")),
              "recursion_s": s(combined.get("recursion_ns"))}
    return stages, report, combined


def parity(block, proof, leaves):
    """Byte parity against the accepted-v7 originals pinned in source-authority.json."""
    control = B.load(M3 / "inputs/source-authority.json")["blocks"][str(block)]
    native = {p.name: sha(p) for p in proof.glob("*.bin")}
    result = {"native_bins": native == control["control_native"],
              "bundle": sha(proof / "bundle.json") == control["control_bundle"]}
    try:
        snapshot = R.recursive_snapshot(proof, control["leaves"])
        result["recursive_tree"] = snapshot["tree_sha256"] == control["control_recursive"]["tree_sha256"]
        result["recursive_proofs"] = snapshot["proof_sha256"] == control["control_recursive"]["proof_sha256"]
        mismatched = sorted(k for k, v in snapshot["proof_sha256"].items() if control["control_recursive"]["proof_sha256"].get(k) != v)
        result["recursive_mismatched"] = mismatched[:40]
        result["root_sha256"] = snapshot["proof_sha256"]["root.proof"]
        result["control_root_sha256"] = control["control_recursive"]["proof_sha256"]["root.proof"]
    except Exception as error:  # incomplete tree is a parity failure, not a crash
        result["recursive_error"] = repr(error)
    result["native_mismatched"] = sorted(k for k in set(native) | set(control["control_native"]) if native.get(k) != control["control_native"].get(k))
    result["byte_identical"] = all(result.get(k) is True for k in ("native_bins", "bundle", "recursive_tree", "recursive_proofs"))
    return result


def recursion_counters(log, combined):
    prefixes = ("CUDA_OUTER_PREPROCESS ", "GPU_OUTER ", "GPU_OUTER_ASSIGNMENT ")
    return {"recursive_report": combined.get("recursive", {}),
            "node_record_lines": {p.strip(): sum(1 for line in log.splitlines() if line.startswith(p)) for p in prefixes}}


def receipt_path(run):
    return run / "receipt.json"


def prove(args):
    if args.block not in DEV_BLOCKS and not args.allow_scale_up:
        raise SystemExit("owner rule: develop/measure only on 26235156 and 24628607 (use --allow-scale-up for the final ordered scale-up)")
    root = src_root(args.stream)
    paths = build_paths(args.stream)
    if args.driver:
        paths["driver"] = Path(args.driver)
    if args.library:
        paths["library"] = Path(args.library)
    if args.receiver:
        paths["receiver"] = Path(args.receiver)
    for key in ("driver", "library"):
        if not Path(paths[key]).is_file():
            raise SystemExit(f"missing {key}: {paths[key]} (run build)")
    tag = args.tag or now()
    run = M3 / "runs" / args.stream / f"{args.block}-{args.gpus}gpu-{tag}"
    run.mkdir(parents=True, exist_ok=False)
    plan, job = make_plan(args, run, paths, root)
    started = time.time()
    pending = produce(plan, job, run, nsys=args.nsys)
    proof = proof_dir(job)
    stages, report, combined = stage_breakdown(proof, pending["markers"])
    log = (Path(job["target"]) / "producer.stdout").read_text(errors="replace") + (Path(job["target"]) / "producer.stderr").read_text(errors="replace")
    leaves = report.get("cpu_proofs", 0) + report.get("truth_proofs", 0)
    receipt = {"schema": "rv64-m3-receipt/v1", "label": "measured", "stream": args.stream, "block": args.block,
               "gpus": args.gpus, "run": str(run), "started_unix": started, "source_commit": plan["producer_source_commit"],
               "assets": plan["asset_sha256"], "environment_overrides": plan["resident_environment"], "nsys": bool(args.nsys),
               "stages": stages, "producer_process": pending["producer_process"], "gpu": pending["gpu"],
               "physical_gpu_memory_peak": pending["physical_gpu_memory"],
               "native": {"cpu_proofs": report.get("cpu_proofs"), "truth_proofs": report.get("truth_proofs"),
                          "profile": report.get("profile"), "accepted_in_process": report.get("accepted"),
                          "completed_ethereum_block": report.get("completed_ethereum_block"),
                          "output_matches_pin": bytes(report.get("output", [])).hex() == job["expected_output"],
                          "numeric": numeric(report)},
               "recursion": {"numeric": numeric(combined), "counters": recursion_counters(log, combined)},
               "proof_sha256": {"native": {p.name: sha(p) for p in sorted(proof.glob("*.bin"))},
                                "bundle": sha(proof / "bundle.json")},
               "parity_vs_accepted_v7": parity(args.block, proof, leaves),
               "receiver": {"status": "not_run"}}
    try:
        receipt["proof_sha256"]["recursive"] = R.recursive_snapshot(proof, leaves)
    except Exception as error:
        receipt["proof_sha256"]["recursive_error"] = repr(error)
    B.atomic_json(receipt_path(run), receipt)
    summary(receipt)
    return run


def receive(args, run=None):
    run = Path(run or args.run)
    plan = B.load(run / "plan.json")
    job = plan["jobs"][0]
    receiver = Path(args.receiver) if getattr(args, "receiver", None) else Path(plan["assets"]["recursive_receiver"])
    proof = proof_dir(job)
    report = B.load(proof / "report.json")
    count = report["cpu_proofs"] + report["truth_proofs"]
    out = run / f"receiver-{now()}"
    out.mkdir()
    before = {str(p.relative_to(Path(job["target"]))): sha(p) for p in sorted(Path(job["target"]).rglob("*")) if p.is_file()}
    request = B.load(job["request"])
    request["workers"] = args.workers
    request["output_directory"] = str(out / "capture")
    request_path = out / "receiver-request.json"
    B.atomic_json(request_path, request)
    environment = dict(os.environ)
    environment.pop("STWO_ZIG_RV64_SETUP_CACHE", None)  # cache-disabled
    environment = R.receiver_environment(environment, out / "gpu-disabled")
    command = ["nice", "-n", "10", *B.command(receiver, plan["profile"], "verify-recursion-candidate", request_path, proof,
                                               job["resources"]["fixed_setup_bytes"], args.host_bytes)]
    usage = B.measure(command, out, "strict-receiver", environment, cwd=plan["producer_cwd"])
    verdict = {"status": "rejected", "accepted": False, "receiver_sha256": sha(receiver), "argv": command,
               "process": usage, "directory": str(out), "host": os.uname().nodename,
               "gpu_disabled": {"CUDA_VISIBLE_DEVICES": "", "STWO_RV64_GPU_PCS_HELPER": "/bin/false", "STWO_ZIG_RV64_SETUP_CACHE": "unset"}}
    try:
        if usage.get("exit_code") != 0:
            raise ValueError(f"receiver exit {usage.get('exit_code')}")
        received = B.load(out / "strict-receiver.stdout")
        R.check_trial(report, received["native"], job, plan["profile"])
        if (received["native"].get("cpu_proofs"), received["native"].get("truth_proofs")) != (report["cpu_proofs"], report["truth_proofs"]):
            raise ValueError("fresh native receiver proof inventory differs")
        if received.get("accepted") is not True or received.get("completed_ethereum_block") is not True:
            raise ValueError("fresh recursive receiver rejected the complete statement")
        R.check_recursive_report(received["recursive"], count, restored=True)
        after = {str(p.relative_to(Path(job["target"]))): sha(p) for p in sorted(Path(job["target"]).rglob("*")) if p.is_file()}
        if after != before:
            raise ValueError("receiver changed producer artifacts")
        verdict.update(status="accepted", accepted=True, native_receiver_accepted=True, recursive_receiver_accepted=True,
                       restored_leaves=received["recursive"].get("restored_leaves"), restored_folds=received["recursive"].get("restored_folds"))
    except Exception as error:
        verdict["error"] = repr(error)
    # Producer-side strict checks (log census, zero CPU assignment, device FIXED) are
    # recorded separately: architecture streams may legitimately change log shapes.
    try:
        log = (Path(job["target"]) / "producer.stdout").read_text(errors="replace") + (Path(job["target"]) / "producer.stderr").read_text(errors="replace")
        if verdict["accepted"]:
            R.qualify_recursive_trial(plan, job, proof, report, out, 0, [], log, environment,
                                      received_override=B.load(out / "strict-receiver.stdout"), shared_usage=usage)
        verdict["producer_strict_checks"] = "pass" if verdict["accepted"] else "skipped"
    except Exception as error:
        verdict["producer_strict_checks"] = "fail: " + repr(error)
    path = receipt_path(run)
    receipt = B.load(path) if path.is_file() else {"run": str(run)}
    receipt["receiver"] = verdict
    receipt["accepted"] = bool(verdict["accepted"] and receipt.get("native", {}).get("output_matches_pin"))
    B.atomic_json(path, receipt)
    summary(receipt)
    return verdict


def summary(receipt):
    p = receipt.get("parity_vs_accepted_v7", {})
    r = receipt.get("receiver", {})
    print(json.dumps({"block": receipt.get("block"), "gpus": receipt.get("gpus"), "stages": receipt.get("stages"),
                      "byte_identical_vs_v7": p.get("byte_identical"), "receiver": r.get("status"),
                      "receipt": str(Path(receipt["run"]) / "receipt.json")}, indent=1))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    b = sub.add_parser("build")
    b.add_argument("--stream", default="infra")
    b.add_argument("--only", choices=("zig", "cuda"))
    b.add_argument("--catalogues", default=str(M3 / "catalogues-v2"),
                   help="AOT catalogue root (v2 = frozen catalogue with generator-regenerated grouped core roles 43/44)")
    b.add_argument("--jobs", type=int, default=32)
    b.add_argument("--max-stack-bytes", type=int, default=12544, help="Worst per-thread kernel stack admitted (accepted image: 12544)")
    sub.add_parser("inputs")
    for name in ("prove", "bench"):
        p = sub.add_parser(name)
        p.add_argument("block", type=int)
        p.add_argument("--gpus", type=int, choices=(1, 2), default=2)
        p.add_argument("--stream", default="infra")
        p.add_argument("--tag")
        p.add_argument("--env", action="append", default=[], help="K=V producer environment override")
        p.add_argument("--driver")
        p.add_argument("--library")
        p.add_argument("--receiver")
        p.add_argument("--nsys", action="store_true", help="Wrap the producer in nsys profile (timeline in run/nsys)")
        p.add_argument("--allow-scale-up", action="store_true")
        p.add_argument("--workers", type=int, default=16)
        p.add_argument("--host-bytes", type=int, default=32 << 30)
    r = sub.add_parser("receive")
    r.add_argument("block", type=int)
    r.add_argument("--run", required=True)
    r.add_argument("--receiver")
    r.add_argument("--workers", type=int, default=16)
    r.add_argument("--host-bytes", type=int, default=32 << 30)
    q = sub.add_parser("parity")
    q.add_argument("--run", required=True)
    args = parser.parse_args()
    if args.command == "build":
        build(args)
    elif args.command == "inputs":
        inputs(args)
    elif args.command == "prove":
        prove(args)
    elif args.command == "bench":
        receive(args, prove(args))
    elif args.command == "receive":
        receive(args)
    elif args.command == "parity":
        run = Path(args.run)
        job = B.load(run / "plan.json")["jobs"][0]
        print(json.dumps(parity(job["block"], proof_dir(job), None), indent=1))


if __name__ == "__main__":
    main()
