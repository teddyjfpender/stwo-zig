#!/usr/bin/env python3
"""RV64 M4 stream `resident`: resident prover service + persisted ArtifactStore harness.

Runs ON the pod. One producer process (the resident service: `combined-batch`) holds both
CUDA contexts, the program image/authority session and the SetupCache for its whole life
and serves an ordered list of requests (blocks x repeat).  Immutable setup comes from a
persisted, content-addressed ArtifactStore under /workspace/m3/store/<branch>/<key>/.

  python3 rv64_m4_resident.py store-key [--stream S]            # print the store key + components
  python3 rv64_m4_resident.py serve BLOCK [BLOCK ...] --repeat N --tag T [--loading eager|lazy]
          [--store fresh|reuse|none] [--nsys] [--receive all|first|none] [--env K=V]
  python3 rv64_m4_resident.py receive --run DIR                 # fresh receivers, store DELETED
  python3 rv64_m4_resident.py catalogue-gate [--catalogues DIR] # AOT catalogue == regeneration

Every request in the service gets: request wall (driver marker), stage breakdown
(capture/setup/native/recursion), byte parity against the M3 baseline receipt for that block
(native bins, bundle, every recursive proof, tree), and (optionally) the verdict of a fresh,
separate, CPU-only receiver run while the ArtifactStore directory does not exist.

Store keying (see design/riscv-proving-stack/rv64-m4-artifact-store.md):
  key = SHA-256("rv64-m4-artifact-store/v1" || canonical JSON of
        {driver_sha256 (code identity), library_sha256, catalogue_sha256 (generator output),
         elf_sha256 (image), profile, field_hash, store_format})
The driver additionally keys every artifact on SHA-256(own executable) and the receiver
program identity and SHA-256-seals header/VK/bulk (setup_cache.zig), so a stale store can
never be read; a store.json whose components disagree with the recomputed ones is refused.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import rv64_m3_pod as P  # noqa: E402
import rv64_resident_basket as R  # noqa: E402

B = R.B
M3 = P.M3
BRANCH = "codex-rv64-m4-resident"
STORE_ROOT = Path(os.environ["RV64_STORE_ROOT"]) if os.environ.get("RV64_STORE_ROOT") else M3 / "store" / BRANCH
BASELINE_RUNS = M3 / "runs/integrate"  # M3 integrate scale receipts = the M4 parity baseline
STORE_FORMAT = "rv64-m4-artifact-store/v1"
FIELD_HASH = "m31-circle/blake2s-merkle/om31-recursion"


def tree_sha(directory):
    """Order-independent content hash of a catalogue tree (relative path + file sha)."""
    h = hashlib.sha256(b"rv64-m4-catalogue-tree/v1\x00")
    root = Path(directory)
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        h.update(str(path.relative_to(root)).encode() + b"\x00" + bytes.fromhex(P.sha(path)))
    return h.hexdigest()


def store_components(paths, catalogues, profile):
    build = B.load(paths["receipt"]) if paths["receipt"].is_file() else {}
    elf = M3 / "inputs/guest.elf"
    return {"store_format": STORE_FORMAT, "driver_sha256": P.sha(paths["driver"]),
            "library_sha256": P.sha(paths["library"]), "catalogue_sha256": tree_sha(catalogues),
            "catalogue_dir": str(catalogues), "build_catalogues": build.get("catalogues"),
            "elf_sha256": P.sha(elf), "profile": profile, "field_hash": FIELD_HASH}


def store_key(components):
    keyed = {k: v for k, v in components.items() if k not in ("catalogue_dir", "build_catalogues")}
    blob = json.dumps(keyed, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(STORE_FORMAT.encode() + b"\x00" + blob).hexdigest()


def open_store(components, mode):
    """fresh: new empty store dir; reuse: existing dir whose store.json must match exactly."""
    if mode == "none":
        return None, None
    key = store_key(components)
    directory = STORE_ROOT / key[:24]
    manifest = directory / "store.json"
    if mode == "fresh":
        if directory.exists():
            shutil.rmtree(directory)
        (directory / "setup").mkdir(parents=True)
        B.atomic_json(manifest, {"schema": STORE_FORMAT, "key": key, "components": components,
                                 "created_unix": time.time()})
    else:
        if not manifest.is_file():
            raise SystemExit(f"store {directory} missing: run with --store fresh first")
        recorded = B.load(manifest)
        if recorded.get("key") != key or recorded.get("components", {}).get("driver_sha256") != components["driver_sha256"]:
            raise SystemExit("ArtifactStore key mismatch: refusing to load " + str(directory))
    return directory, key


def store_census(directory):
    if directory is None or not directory.exists():
        return None
    files = [p for p in directory.rglob("*") if p.is_file()]
    return {"files": len(files), "bytes": sum(p.stat().st_size for p in files),
            "setup_artifacts": sum(1 for p in files if p.suffix == ".rv64-setup"),
            "class_artifacts": sum(1 for p in files if p.suffix == ".rv64-class")}


def baseline(block):
    path = BASELINE_RUNS / f"{block}-2gpu-scale/receipt.json"
    return B.load(path), path


def m3_parity(block, proof, leaves):
    """Byte parity against the M3 integrate receipt for this block (the M4 baseline)."""
    control, path = baseline(block)
    ref = control["proof_sha256"]
    native = {p.name: P.sha(p) for p in sorted(proof.glob("*.bin"))}
    result = {"baseline_receipt": str(path), "native_bins": native == ref["native"],
              "bundle": P.sha(proof / "bundle.json") == ref["bundle"]}
    try:
        snap = R.recursive_snapshot(proof, leaves)
        result["recursive_tree"] = snap["tree_sha256"] == ref["recursive"]["tree_sha256"]
        result["recursive_proofs"] = snap["proof_sha256"] == ref["recursive"]["proof_sha256"]
        result["recursive_mismatched"] = sorted(k for k, v in snap["proof_sha256"].items() if ref["recursive"]["proof_sha256"].get(k) != v)[:40]
        result["root_sha256"] = snap["proof_sha256"].get("root.proof")
        result["baseline_root_sha256"] = ref["recursive"]["proof_sha256"].get("root.proof")
        result["proof_count"] = len(snap["proof_sha256"])
    except Exception as error:
        result["recursive_error"] = repr(error)
    result["native_mismatched"] = sorted(k for k in set(native) | set(ref["native"]) if native.get(k) != ref["native"].get(k))
    result["byte_identical"] = all(result.get(k) is True for k in ("native_bins", "bundle", "recursive_tree", "recursive_proofs"))
    return result


MARK = re.compile(r"GPU_RESIDENT_BLOCK block=(\d+) trial=(\d+) iteration=(\d+) request_wall_ns=(\d+)(.*)")


def markers(log):
    out = {}
    for m in MARK.finditer(log):
        fields = dict(kv.split("=", 1) for kv in m[5].split() if "=" in kv)
        out[(int(m[1]), int(m[2]))] = {"iteration": int(m[3]), "request_wall_ns": int(m[4]), **fields}
    return out


def plan_for(blocks, args, run, paths, root):
    template = P.plan_template()
    if getattr(args, "security_profile", None) is not None:
        template = dict(template, profile=args.security_profile)
    jobs = []
    for block in blocks:
        job = next(j for j in template["jobs"] if j["block"] == block)
        request = B.load(M3 / "inputs/requests" / f"{block}.json")
        request["output_directory"] = str(run / f"capture-{block}")
        request_path = run / f"request-{block}.json"
        B.atomic_json(request_path, request)
        job = dict(job, devices=[0, 1], device_count=2, request=str(request_path), request_sha256=P.sha(request_path),
                   target=str(run / "case"))
        if getattr(args, "coalesce_truth_families", False):
            job["resources"] = dict(job["resources"], coalesce_truth_families=True)
        jobs.append(job)
    resources = jobs[0]["resources"]
    if any(j["resources"] != resources for j in jobs):
        raise SystemExit("blocks need different resources; a single service manifest cannot serve them")
    plan = dict(template, jobs=jobs, execution_order=list(blocks), repeat=args.repeat, gpu_lock=None,
                producer_cwd=str(root))
    plan["assets"] = {"driver": str(paths["driver"]), "library": str(paths["library"]),
                      "receiver": str(paths["receiver"]), "recursive_receiver": str(paths["receiver"])}
    plan["asset_sha256"] = {k: P.sha(v) if Path(v).is_file() else None for k, v in plan["assets"].items()}
    plan["producer_source_commit"] = P.source_commit(root)
    plan["resident_environment"] = P.producer_env(args)
    return plan


def service_manifest(plan):
    jobs = plan["jobs"]
    return {"schema": "rv64-ethereum-basket-inputs/v1", "profile": plan["profile"],
            "blocks": {str(j["block"]): {"request": j["request"], "expected_cpu_segments": j["segments"]} for j in jobs},
            "execution_order": plan["execution_order"], "resources": jobs[0]["resources"], "repeat": plan["repeat"],
            "immutable_host_key_bytes": plan.get("immutable_host_key_bytes", 8 << 30),
            "immutable_device_bytes": plan.get("immutable_device_bytes", 512 << 20),
            "combined_host_bytes": plan.get("combined_host_bytes", 48 << 30),
            "combined_immutable_device_bytes": plan.get("combined_immutable_device_bytes", 2 << 30),
            **({k: plan[k] for k in ("recursion_mode", "recursion_worker_budget", "recursion_max_pending_authorities")}
               if plan.get("recursion_mode", "serial") == "ready_candidate" else {}),
            **({"recursion_device_fixed_candidate": True} if plan.get("recursion_device_fixed_candidate") else {})}


def nsys_api_census(sqlite):
    """cuLibraryLoadData / cuLibraryUnload / cudaMallocFromPoolAsync / sync counts from an nsys sqlite."""
    import sqlite3
    if not Path(sqlite).is_file():
        return None
    db = sqlite3.connect(str(sqlite))
    try:
        rows = db.execute("SELECT s.value, COUNT(*), SUM(r.end-r.start), MIN(r.start), MAX(r.end) FROM CUPTI_ACTIVITY_KIND_RUNTIME r "
                          "JOIN StringIds s ON r.nameId = s.id GROUP BY s.value").fetchall()
    except Exception as error:
        return {"error": repr(error)}
    finally:
        pass
    out = {name: {"count": n, "seconds": round((t or 0) / 1e9, 4), "first_ns": a, "last_ns": b} for name, n, t, a, b in rows}
    db.close()
    keep = ("cuLibraryLoadData", "cuLibraryUnload", "cudaMallocFromPoolAsync", "cudaStreamSynchronize", "cudaMemPoolTrimTo",
            "cudaLaunchKernel", "cudaMemcpyAsync", "cuModuleLoadData", "cuLibraryGetKernel", "cuKernelGetFunction")
    return {k: v for k, v in out.items() if any(k.startswith(p) for p in keep)}


def nsys_window_counts(sqlite, windows):
    """Per-request counts of library loads / pool mallocs / syncs, by UTC window (nsys session start + offset)."""
    import sqlite3
    db = sqlite3.connect(str(sqlite))
    try:
        start = db.execute("SELECT utcEpochNs FROM TARGET_INFO_SESSION_START_TIME").fetchone()[0]
        names = ("cuLibraryLoadData", "cuLibraryUnload", "cudaMallocFromPoolAsync", "cudaStreamSynchronize", "cudaLaunchKernel")
        out = []
        for lo, hi in windows:
            row = {}
            for name in names:
                row[name] = db.execute("SELECT COUNT(*) FROM CUPTI_ACTIVITY_KIND_RUNTIME r JOIN StringIds s ON r.nameId=s.id "
                                       "WHERE s.value LIKE ? AND r.start + ? BETWEEN ? AND ?", (name + "%", start, lo, hi)).fetchone()[0]
            out.append(row)
        before = db.execute("SELECT COUNT(*) FROM CUPTI_ACTIVITY_KIND_RUNTIME r JOIN StringIds s ON r.nameId=s.id "
                            "WHERE s.value LIKE 'cuLibraryLoadData%' AND r.start + ? < ?", (start, windows[0][0])).fetchone()[0] if windows else None
        return {"session_start_utc_ns": start, "requests": out, "cuLibraryLoadData_before_first_request": before}
    except Exception as error:
        return {"error": repr(error)}
    finally:
        db.close()


def serve(args):
    for block in args.blocks:
        if block not in P.DEV_BLOCKS:
            raise SystemExit("owner rule: develop/measure only on 26235156 and 24628607")
    root = P.src_root(args.stream)
    paths = P.build_paths(args.build_stream or args.stream)
    for key in ("driver", "library", "receiver"):
        if getattr(args, key):
            paths[key] = Path(getattr(args, key))
    run = M3 / "runs" / args.stream / f"serve-{'-'.join(map(str, args.blocks))}-r{args.repeat}-{args.tag}"
    run.mkdir(parents=True, exist_ok=False)
    plan = plan_for(args.blocks, args, run, paths, root)
    components = store_components(paths, Path(args.catalogues), plan["profile"])
    store_dir, key = open_store(components, args.store)
    store_before = store_census(store_dir)
    target = run / "case"
    target.mkdir()
    manifest = service_manifest(plan)
    B.atomic_json(target / "manifest.json", manifest)
    worker = {"device": "0,1", "device_caps_bytes": [plan["device_cap_bytes"]] * 2,
              "planned_cpu_workers": plan["jobs"][0]["segments"], "retained_scopes": 64}
    environment = {k: v for k, v in os.environ.items() if not k.startswith(("STWO_RV64_", "STWO_ZIG_RV64_SETUP_CACHE"))}
    environment.update(plan["resident_environment"])
    environment = B.worker_environment(worker, environment)
    for k in ("STWO_RV64_GPU_HOST_RETAINED", "STWO_RV64_DEEP_TIMING", "STWO_RV64_DEEP_COORDINATES", "STWO_RV64_PCS_PHASE_TIMING"):
        if k not in plan["resident_environment"]:
            environment.pop(k, None)
    environment["STWO_RV64_GPU_LIBRARY"] = plan["assets"]["library"]
    environment["CUDA_MODULE_LOADING"] = args.loading.upper()
    if store_dir is not None:
        environment["STWO_ZIG_RV64_SETUP_CACHE"] = str(store_dir / "setup")
        if not args.no_class_store:
            environment["STWO_RV64_OUTER_PLAN_CLASS_STORE"] = str(store_dir / "classes")
    plan["environment"] = {k: v for k, v in environment.items() if k.startswith(("STWO_", "CUDA_"))}
    plan["store"] = {"mode": args.store, "directory": str(store_dir) if store_dir else None, "key": key, "components": components}
    B.atomic_json(run / "plan.json", plan)
    argv = [plan["assets"]["driver"], "combined-batch", str(target / "manifest.json"), str(target / "batch")]
    if args.nsys:
        (run / "nsys").mkdir()
        argv = ["nsys", "profile", "--trace=cuda", "--sample=none", "--cpuctxsw=none", "--force-overwrite=true",
                "-o", str(run / "nsys/timeline")] + argv
    load_before = os.getloadavg()
    lock = P.acquire_gpu_lock()
    try:
        monitor = B.DeviceMonitor("0,1")
        monitor.thread.start()
        try:
            usage = B.measure(argv, target, "producer", environment, cwd=plan["producer_cwd"])
        finally:
            memory = monitor.finish()
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN)
        lock.close()
    api = None
    if args.nsys and (run / "nsys/timeline.nsys-rep").is_file():
        subprocess.run(["nsys", "export", "--type", "sqlite", "--force-overwrite", "true", "-o", str(run / "nsys/timeline.sqlite"),
                        str(run / "nsys/timeline.nsys-rep")], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        api = nsys_api_census(run / "nsys/timeline.sqlite")
    log = (target / "producer.stdout").read_text(errors="replace") + (target / "producer.stderr").read_text(errors="replace")
    marks = markers(log)
    requests = []
    for trial in range(args.repeat):
        for iteration, block in enumerate(args.blocks):
            proof = target / "batch" / f"trial-{trial}" / str(block) / "proof"
            entry = {"block": block, "trial": trial, "iteration": iteration, "ordinal": trial * len(args.blocks) + iteration,
                     "proof": str(proof)}
            mark = marks.get((block, trial))
            entry["marker"] = mark
            if not (proof / "report.json").is_file():
                entry["error"] = "missing proof"
                requests.append(entry)
                continue
            stages, report, combined = P.stage_breakdown(proof, {0: mark["request_wall_ns"]} if mark else {})
            entry["stages"] = stages
            entry["setup_breakdown"] = combined.get("setup_breakdown")
            entry["setup_cache"] = report.get("setup_cache") or combined.get("setup_cache")
            entry["output_matches_pin"] = bytes(report.get("output", [])).hex() == next(j for j in plan["jobs"] if j["block"] == block)["expected_output"]
            entry["proof_bytes_root"] = (proof / "recursion-om31/root.proof").stat().st_size if (proof / "recursion-om31/root.proof").is_file() else None
            leaves = report.get("cpu_proofs", 0) + report.get("truth_proofs", 0)
            entry["leaves"] = leaves
            entry["parity_vs_m3"] = m3_parity(block, proof, leaves)
            requests.append(entry)
    receipt = {"schema": "rv64-m4-resident-service/v1", "label": "measured", "stream": args.stream, "run": str(run),
               "blocks": args.blocks, "repeat": args.repeat, "loading": args.loading, "nsys": bool(args.nsys),
               "source_commit": plan["producer_source_commit"], "assets": plan["asset_sha256"],
               "environment": plan["environment"], "store": dict(plan["store"], before=store_before, after=store_census(store_dir)),
               "load_avg_before": load_before, "load_avg_after": os.getloadavg(),
               "producer_process": usage, "physical_gpu_memory": memory, "cuda_api": api,
               "service_overhead_s": round(usage["wall_ns"] / 1e9 - sum((r.get("marker") or {}).get("request_wall_ns", 0) for r in requests) / 1e9, 3),
               "requests": requests, "receivers": []}
    B.atomic_json(run / "receipt.json", receipt)
    print_summary(receipt)
    if args.receive != "none":
        receive_run(run, args.receive, args.receiver_workers)
    return run


def daemon(args):
    """True resident service: start `combined-serve`, wait READY, submit requests one at a time
    through the spool, then STOP.  Service start (process + CUDA contexts + 686-library load +
    pool + session) is reported separately from every request, never hidden."""
    for block in args.blocks:
        if block not in P.DEV_BLOCKS:
            raise SystemExit("owner rule: develop/measure only on 26235156 and 24628607")
    root = P.src_root(args.stream)
    paths = P.build_paths(args.build_stream or args.stream)
    for key in ("driver", "library", "receiver"):
        if getattr(args, key):
            paths[key] = Path(getattr(args, key))
    order = [b for _ in range(args.repeat) for b in args.blocks]
    run = M3 / "runs" / args.stream / f"daemon-{'-'.join(map(str, args.blocks))}-r{args.repeat}-{args.tag}"
    run.mkdir(parents=True, exist_ok=False)
    plan = plan_for(args.blocks, args, run, paths, root)
    plan["repeat"] = 1
    components = store_components(paths, Path(args.catalogues), plan["profile"])
    store_dir, key = open_store(components, args.store)
    store_before = store_census(store_dir)
    spool = run / "spool"
    spool.mkdir()
    manifest = service_manifest(plan)
    if args.warm:
        # Service boot pre-warm (setup only: capture, plan, keys, FIXED; no proof) maps the
        # ArtifactStore into the session before READY. Counted in service_start_s, never in a request.
        manifest["warm_order"] = list(args.blocks)
    B.atomic_json(run / "manifest.json", manifest)
    environment = {k: v for k, v in os.environ.items() if not k.startswith(("STWO_RV64_", "STWO_ZIG_RV64_SETUP_CACHE"))}
    environment.update(plan["resident_environment"])
    environment = B.worker_environment({"device": "0,1", "device_caps_bytes": [plan["device_cap_bytes"]] * 2,
                                        "planned_cpu_workers": plan["jobs"][0]["segments"], "retained_scopes": 64}, environment)
    for k in ("STWO_RV64_GPU_HOST_RETAINED", "STWO_RV64_DEEP_TIMING", "STWO_RV64_DEEP_COORDINATES", "STWO_RV64_PCS_PHASE_TIMING"):
        if k not in plan["resident_environment"]:
            environment.pop(k, None)
    environment["STWO_RV64_GPU_LIBRARY"] = plan["assets"]["library"]
    environment["CUDA_MODULE_LOADING"] = args.loading.upper()
    if store_dir is not None:
        environment["STWO_ZIG_RV64_SETUP_CACHE"] = str(store_dir / "setup")
        if not args.no_class_store:
            environment["STWO_RV64_OUTER_PLAN_CLASS_STORE"] = str(store_dir / "classes")
    plan["environment"] = {k: v for k, v in environment.items() if k.startswith(("STWO_", "CUDA_"))}
    plan["store"] = {"mode": args.store, "directory": str(store_dir) if store_dir else None, "key": key, "components": components}
    B.atomic_json(run / "plan.json", plan)
    argv = [plan["assets"]["driver"], "combined-serve", str(run / "manifest.json"), str(spool)]
    if args.nsys:
        (run / "nsys").mkdir()
        argv = ["nsys", "profile", "--trace=cuda", "--sample=none", "--cpuctxsw=none", "--force-overwrite=true",
                "-o", str(run / "nsys/timeline")] + argv
    load_before = os.getloadavg()
    timeline = []
    lock = P.acquire_gpu_lock()
    try:
        monitor = B.DeviceMonitor("0,1")
        monitor.thread.start()
        started = time.monotonic_ns()
        with (run / "producer.stdout").open("wb") as out, (run / "producer.stderr").open("wb") as err:
            process = subprocess.Popen(argv, stdout=out, stderr=err, env=environment, cwd=plan["producer_cwd"])
            try:
                while not (spool / "READY").is_file():
                    if process.poll() is not None:
                        raise SystemExit(f"service exited before READY ({process.returncode})")
                    time.sleep(0.01)
                ready_ns = time.monotonic_ns() - started
                for index, block in enumerate(order):
                    name = f"{index:04d}-{block}"
                    submitted = time.monotonic_ns()
                    submitted_utc = time.time_ns()
                    (spool / "inbox" / f"{name}.tmp").write_text(f"{block}\n")
                    os.rename(spool / "inbox" / f"{name}.tmp", spool / "inbox" / f"{name}.request")
                    done = spool / "done" / f"{name}.json"
                    while not done.is_file():
                        if process.poll() is not None:
                            raise SystemExit(f"service exited during {name} ({process.returncode})")
                        time.sleep(0.005)
                    latency = time.monotonic_ns() - submitted
                    timeline.append({"name": name, "block": block, "client_latency_ns": latency, "service": B.load(done),
                                     "utc_window_ns": [submitted_utc, time.time_ns()]})
                    if args.gap:
                        time.sleep(args.gap)
                stop_at = time.monotonic_ns()
                (spool / "inbox" / "STOP").write_text("")
                _, status, usage = os.wait4(process.pid, 0)
                code = os.waitstatus_to_exitcode(status)
                stop_ns = time.monotonic_ns() - stop_at
            except BaseException:
                process.kill()
                raise
        wall_ns = time.monotonic_ns() - started
    finally:
        memory = monitor.finish()
        fcntl.flock(lock, fcntl.LOCK_UN)
        lock.close()
    process_usage = {"argv": argv, "exit_code": code, "wall_ns": wall_ns, "user_seconds": usage.ru_utime,
                     "system_seconds": usage.ru_stime, "peak_rss_bytes": usage.ru_maxrss * 1024,
                     "minor_faults": usage.ru_minflt, "major_faults": usage.ru_majflt}
    api = None
    if args.nsys and (run / "nsys/timeline.nsys-rep").is_file():
        subprocess.run(["nsys", "export", "--type", "sqlite", "--force-overwrite", "true", "-o", str(run / "nsys/timeline.sqlite"),
                        str(run / "nsys/timeline.nsys-rep")], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        api = nsys_api_census(run / "nsys/timeline.sqlite")
        if api is not None:
            api["per_request"] = nsys_window_counts(run / "nsys/timeline.sqlite", [t["utc_window_ns"] for t in timeline])
    requests = []
    for ordinal, item in enumerate(timeline):
        block = item["block"]
        proof = spool / "out" / item["name"] / str(block) / "proof"
        entry = {"block": block, "trial": ordinal // len(args.blocks), "ordinal": ordinal, "proof": str(proof),
                 "client_latency_ns": item["client_latency_ns"], "marker": {"request_wall_ns": item["service"]["request_wall_ns"]},
                 "queue_ns": item["service"].get("queue_ns")}
        stages, report, combined = P.stage_breakdown(proof, {0: item["service"]["request_wall_ns"]})
        entry["stages"] = stages
        entry["setup_breakdown"] = combined.get("setup_breakdown")
        entry["output_matches_pin"] = bytes(report.get("output", [])).hex() == next(j for j in plan["jobs"] if j["block"] == block)["expected_output"]
        root_proof = proof / "recursion-om31/root.proof"
        entry["proof_bytes_root"] = root_proof.stat().st_size if root_proof.is_file() else None
        entry["leaves"] = report.get("cpu_proofs", 0) + report.get("truth_proofs", 0)
        entry["parity_vs_m3"] = m3_parity(block, proof, entry["leaves"])
        requests.append(entry)
    receipt = {"schema": "rv64-m4-resident-daemon/v1", "label": "measured", "stream": args.stream, "run": str(run),
               "blocks": args.blocks, "repeat": args.repeat, "loading": args.loading, "nsys": bool(args.nsys),
               "source_commit": plan["producer_source_commit"], "assets": plan["asset_sha256"], "environment": plan["environment"],
               "store": dict(plan["store"], before=store_before, after=store_census(store_dir)),
               "load_avg_before": load_before, "load_avg_after": os.getloadavg(),
               "service_start_s": round(ready_ns / 1e9, 3), "service_stop_s": round(stop_ns / 1e9, 3),
               "service_ready_record": B.load(spool / "READY"),
               "producer_process": process_usage, "physical_gpu_memory": memory, "cuda_api": api,
               "service_overhead_s": round(wall_ns / 1e9 - sum(r["marker"]["request_wall_ns"] for r in requests) / 1e9, 3),
               "requests": requests, "receivers": []}
    B.atomic_json(run / "receipt.json", receipt)
    print_summary(receipt)
    print(json.dumps({"service_start_s": receipt["service_start_s"], "service_stop_s": receipt["service_stop_s"],
                      "client_latency_s": [round(r["client_latency_ns"] / 1e9, 3) for r in requests]}))
    if args.receive != "none":
        receive_run(run, args.receive, args.receiver_workers)
    return run


def ledger_rows(receipt, commit, milestone="M4", notes=""):
    """One progress row per served request (protocol row schema), for vectors/reports/progress/resident.jsonl."""
    rows = []
    rss = round(receipt["producer_process"].get("peak_rss_bytes", 0) / 2**30, 2)
    peaks = (receipt.get("physical_gpu_memory") or {}).get("peak_used_bytes") or {}
    verdicts = {(v["block"], v.get("trial")): v for v in receipt.get("receivers", [])}
    for r in receipt["requests"]:
        s = r.get("stages") or {}
        v = verdicts.get((r["block"], r["trial"]))
        rows.append({"date": time.strftime("%Y-%m-%d"), "commit": commit, "stream": "resident", "milestone": milestone,
                     "block": r["block"], "gpus": 2, "request_s": s.get("request_wall_s"), "capture_s": s.get("capture_s"),
                     "setup_s": s.get("setup_s"), "native_s": s.get("native_prove_s"), "recursion_s": s.get("recursion_s"),
                     "verifier_s": round(v["process"]["wall_ns"] / 1e9, 2) if v else None,
                     "rss_peak_gib": rss, "device_peak_gb": {k: round(x / 1e9, 2) for k, x in peaks.items()},
                     "proof_bytes": r.get("proof_bytes_root"),
                     "byte_identical_to": "M3 integrate scale receipt" if (r.get("parity_vs_m3") or {}).get("byte_identical") else None,
                     "receiver_accepted": v["accepted"] if v else None, "label": "M",
                     "service_position": r["ordinal"], "service_trial": r["trial"], "loading": receipt.get("loading"),
                     "store_mode": receipt["store"]["mode"], "load_avg_1m": receipt["load_avg_before"][0],
                     "run": Path(receipt["run"]).name, "notes": notes})
    return rows


def receive_one(plan, block, proof, out_root, workers):
    job = next(j for j in plan["jobs"] if j["block"] == block)
    report = B.load(proof / "report.json")
    count = report["cpu_proofs"] + report["truth_proofs"]
    out = out_root / f"receiver-{block}-{proof.parent.parent.name}-{P.now()}"
    out.mkdir()
    request = B.load(job["request"])
    request["workers"] = workers
    request["output_directory"] = str(out / "capture")
    request_path = out / "receiver-request.json"
    B.atomic_json(request_path, request)
    environment = {k: v for k, v in os.environ.items() if k not in ("STWO_ZIG_RV64_SETUP_CACHE", "STWO_RV64_OUTER_PLAN_CLASS_STORE")}
    environment = R.receiver_environment(environment, out / "gpu-disabled")
    environment = P.format_environment(environment, plan)
    environment["STWO_RV64_FOLD_CLASS_CACHE"] = "0"
    receiver = Path(plan["assets"]["recursive_receiver"])
    before = {str(p.relative_to(proof)): P.sha(p) for p in sorted(proof.rglob("*")) if p.is_file()}
    command = ["nice", "-n", "10", *B.command(receiver, plan["profile"], "verify-recursion-candidate", request_path, proof,
                                               job["resources"]["fixed_setup_bytes"], 32 << 30)]
    usage = B.measure(command, out, "strict-receiver", environment, cwd=plan["producer_cwd"])
    verdict = {"block": block, "proof": str(proof), "status": "rejected", "accepted": False, "receiver_sha256": P.sha(receiver),
               "process": usage, "directory": str(out),
               "isolation": {"CUDA_VISIBLE_DEVICES": "", "STWO_RV64_GPU_PCS_HELPER": "/bin/false",
                             "STWO_ZIG_RV64_SETUP_CACHE": "unset", "STWO_RV64_OUTER_PLAN_CLASS_STORE": "unset",
                             "STWO_RV64_FOLD_CLASS_CACHE": "0"}}
    try:
        if usage.get("exit_code") != 0:
            raise ValueError(f"receiver exit {usage.get('exit_code')}")
        received = B.load(out / "strict-receiver.stdout")
        R.check_trial(report, received["native"], job, plan["profile"])
        if received.get("accepted") is not True or received.get("completed_ethereum_block") is not True:
            raise ValueError("fresh recursive receiver rejected the complete statement")
        R.check_recursive_report(received["recursive"], count, restored=True)
        after = {str(p.relative_to(proof)): P.sha(p) for p in sorted(proof.rglob("*")) if p.is_file()}
        if after != before:
            raise ValueError("receiver changed producer artifacts")
        verdict.update(status="accepted", accepted=True)
    except Exception as error:
        verdict["error"] = repr(error)
    return verdict


def receive_run(run, which="all", workers=16):
    """Fresh CPU-only receivers while the ArtifactStore directory is DELETED (moved out of reach)."""
    run = Path(run)
    receipt = B.load(run / "receipt.json")
    plan = B.load(run / "plan.json")
    store = plan.get("store", {}).get("directory")
    quarantine = None
    if store and Path(store).exists():
        quarantine = Path(str(store) + f".quarantine-{P.now()}")
        Path(store).rename(quarantine)
    try:
        if store and Path(store).exists():
            raise SystemExit("store still visible to the receiver")
        verdicts = []
        for entry in receipt["requests"]:
            if "error" in entry or (which == "first" and entry["trial"] != 0):
                continue
            verdict = receive_one(plan, entry["block"], Path(entry["proof"]), run, workers)
            verdict["trial"] = entry["trial"]
            verdict["store_present_during_receive"] = bool(store and Path(store).exists())
            verdicts.append(verdict)
            print(json.dumps({k: verdict[k] for k in ("block", "trial", "status")} | {"wall_s": round(verdict["process"]["wall_ns"] / 1e9, 1)}))
    finally:
        if quarantine is not None:
            quarantine.rename(store)
    receipt["receivers"] = verdicts
    receipt["all_received"] = bool(verdicts) and all(v["accepted"] for v in verdicts)
    B.atomic_json(run / "receipt.json", receipt)
    return verdicts


def print_summary(receipt):
    rows = []
    for r in receipt["requests"]:
        s = r.get("stages") or {}
        rows.append({"block": r["block"], "trial": r["trial"], "request_s": s.get("request_wall_s"), "capture": s.get("capture_s"),
                     "setup": s.get("setup_s"), "native": s.get("native_prove_s"), "recursion": s.get("recursion_s"),
                     "m3_identical": (r.get("parity_vs_m3") or {}).get("byte_identical"),
                     "setup_hits": (r.get("marker") or {}).get("setup_disk_hits"), "resident_hits": (r.get("marker") or {}).get("setup_resident_hits")})
    print(json.dumps({"run": receipt["run"], "process_wall_s": round(receipt["producer_process"]["wall_ns"] / 1e9, 2),
                      "service_overhead_s": receipt["service_overhead_s"], "rss_gib": round(receipt["producer_process"].get("peak_rss_bytes", 0) / 2**30, 2),
                      "cuda_api": {k: v["count"] for k, v in (receipt.get("cuda_api") or {}).items() if isinstance(v, dict) and "count" in v},
                      "requests": rows}, indent=1))


# ----------------------------------------------------------------------------- catalogue gate

GENERATORS = {
    # family: list of (tool, argv template); a catalogue file must byte-equal the same-named file of
    # at least one generator output (core mixes --domain and --grouped-domain roles by design).
    "core": [("rv64-joined-fixtures", ["--domain", "{out}"]), ("rv64-joined-fixtures", ["--grouped-domain", "{out}"])],
    "truth": [("rv64-joined-fixtures", ["--truth-domain", "{out}"])],
    "rational": [("rv64-joined-fixtures", ["--truth-interactions", "{out}"])],
    "outer": [("rv64-joined-fixtures", ["--outer-native-om31", "{out}"])],
    "global": [("rv64-global-fixtures", ["{out}", "--catalog"])],
    "projection": [("rv64-projection-fixtures", ["{out}"])],
}
TOOL_STEPS = {"rv64-joined-fixtures": "build-rv64-joined-tool", "rv64-global-fixtures": "build-rv64-global-tool",
              "rv64-projection-fixtures": "build-rv64-projection-tool"}


def build_tools(args):
    """Build the AOT catalogue generators (CPU only; caller wraps in a build.N.lock flock)."""
    root = P.src_root(args.stream)
    prefix = M3 / "build" / args.stream / "tools"
    prefix.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, ZIG_GLOBAL_CACHE_DIR=str(M3 / "cache/zig-global"))
    seconds = {}
    for tool, step in TOOL_STEPS.items():
        seconds[tool] = P.run_logged([P.ZIG, "build", step, "-Dtarget=x86_64-linux-gnu", "-Dcpu=x86_64_v4+sha", "-Doptimize=ReleaseFast",
                                      "--cache-dir", str(root / ".zig-cache"), "--prefix", str(prefix)],
                                     prefix / f"{step}.log", cwd=root / "src/integrations/riscv_cuda", env=env)
    print(json.dumps({"tools": str(prefix / "bin"), "seconds": seconds}))


def catalogue_gate(args):
    """Byte-compare every AOT catalogue file against fresh generator output from THIS tree."""
    root = P.src_root(args.stream)
    tools = Path(args.tools)
    cat = Path(args.catalogues)
    work = M3 / "scratch" / args.stream / f"catalogue-gate-{P.now()}"
    work.mkdir(parents=True)
    result = {"schema": "rv64-m4-catalogue-gate/v1", "catalogues": str(cat), "catalogue_sha256": tree_sha(cat),
              "source_commit": P.source_commit(root), "tools": {}, "families": {}}
    for family, gens in GENERATORS.items():
        fam_dir = cat / family
        if not fam_dir.is_dir():
            continue
        outputs = []
        for index, (tool, argv) in enumerate(gens):
            exe = tools / tool
            if not exe.is_file():
                result["families"][family] = {"status": "tool_missing", "tool": str(exe)}
                break
            out = work / f"{family}-{index}"
            started = time.monotonic()
            code = subprocess.run([str(exe), *[a.format(out=out) for a in argv]], cwd=str(root), stdout=(work / f"{family}-{index}.log").open("w"),
                                  stderr=subprocess.STDOUT).returncode
            result["tools"][f"{family}-{index}"] = {"tool": tool, "sha256": P.sha(exe), "argv": argv, "exit": code,
                                                   "seconds": round(time.monotonic() - started, 1)}
            if code != 0:
                result["families"][family] = {"status": "generator_failed", "log": str(work / f"{family}-{index}.log")}
                break
            outputs.append(out)
        else:
            equal, differ, missing = [], [], []
            for path in sorted(p for p in fam_dir.rglob("*") if p.is_file()):
                rel = path.relative_to(fam_dir)
                candidates = [o / rel for o in outputs if (o / rel).is_file()]
                if not candidates:
                    missing.append(str(rel))
                elif any(c.read_bytes() == path.read_bytes() for c in candidates):
                    equal.append(str(rel))
                else:
                    differ.append(str(rel))
            status = "equal" if not differ and not missing else ("drift" if differ else "partial")
            result["families"][family] = {"status": status, "equal": len(equal), "differ": differ, "missing_in_regeneration": missing}
    # truth-parts are a partition of `truth` (rv64_cuda_partition_grouped.py with role-specific options that are
    # not recorded); the gate does NOT regenerate them. It checks the recorded input digests against truth/ and
    # reports the family as not covered, never as equal.
    parts = cat / "truth-parts" / "partition.json"
    if parts.is_file():
        manifest = B.load(parts)
        roles = manifest.get("roles", [])
        recorded = [r for r in roles if "input_sha256" in r]
        bad = [Path(r["input"]).name for r in recorded
               if not (cat / "truth" / Path(r["input"]).name).is_file() or P.sha(cat / "truth" / Path(r["input"]).name) != r["input_sha256"]]
        result["families"]["truth-parts"] = {"status": "drift" if bad else "not_regenerated", "roles": len(roles),
                                             "roles_with_input_digest": len(recorded), "input_digest_mismatch": bad}
    statuses = {f: v["status"] for f, v in result["families"].items()}
    result["gate"] = "pass" if all(s in ("equal", "not_regenerated") for s in statuses.values()) else "fail"
    result["coverage"] = sorted(f for f, s in statuses.items() if s == "equal")
    result["not_covered"] = sorted(f for f, s in statuses.items() if s == "not_regenerated")
    result["statuses"] = statuses
    out = Path(args.output) if args.output else work / "catalogue-gate.json"
    B.atomic_json(out, result)
    print(json.dumps({"gate": result["gate"], "statuses": statuses, "receipt": str(out)}, indent=1))
    if result["gate"] != "pass" and args.strict:
        raise SystemExit(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    k = sub.add_parser("store-key")
    k.add_argument("--stream", default="m4-resident")
    k.add_argument("--catalogues", default=str(M3 / "catalogues-v3"))
    s = sub.add_parser("serve")
    s.add_argument("blocks", type=int, nargs="+")
    s.add_argument("--repeat", type=int, default=2)
    s.add_argument("--coalesce-truth-families", action="store_true", help="opt-in non-Keccak family coalescing; preserves bounded Keccak shards")
    s.add_argument("--security-profile", choices=("conjectured128_b2_q108_p20_fold4", "d2_native_b4_q54_p20_fold4"), help="explicit opt-in native profile; preserves template default when absent")
    s.add_argument("--stream", default="m4-resident")
    s.add_argument("--build-stream", help="use binaries from /workspace/m3/build/<this> (e.g. integrate = M3 baseline)")
    s.add_argument("--tag", required=True)
    s.add_argument("--loading", choices=("eager", "lazy"), default="eager")
    s.add_argument("--store", choices=("fresh", "reuse", "none"), default="reuse")
    s.add_argument("--catalogues", default=str(M3 / "catalogues-v3"))
    s.add_argument("--env", action="append", default=[])
    s.add_argument("--no-default-env", action="store_true", help="do not apply rv64_m3_pod.DEFAULT_PRODUCER_ENV")
    s.add_argument("--driver")
    s.add_argument("--library")
    s.add_argument("--receiver")
    s.add_argument("--nsys", action="store_true")
    s.add_argument("--receive", choices=("all", "first", "none"), default="first")
    s.add_argument("--receiver-workers", type=int, default=16)
    s.add_argument("--no-class-store", action="store_true", help="do not persist fold-class templates in the store")
    d = sub.add_parser("daemon")
    for action in s._actions:
        if action.dest in ("help",):
            continue
        d._add_action(action)
    d.add_argument("--gap", type=float, default=0.0, help="idle seconds between requests")
    d.add_argument("--warm", action="store_true", help="pre-warm the session from the store at service boot (before READY)")
    l = sub.add_parser("ledger")
    l.add_argument("receipt")
    l.add_argument("--commit", required=True)
    l.add_argument("--notes", default="")
    l.add_argument("--out", required=True)
    r = sub.add_parser("receive")
    r.add_argument("--run", required=True)
    r.add_argument("--which", choices=("all", "first"), default="all")
    r.add_argument("--receiver-workers", type=int, default=16)
    t = sub.add_parser("build-tools")
    t.add_argument("--stream", default="m4-resident")
    g = sub.add_parser("catalogue-gate")
    g.add_argument("--stream", default="m4-resident")
    g.add_argument("--catalogues", default=str(M3 / "catalogues-v3"))
    g.add_argument("--tools", default=str(M3 / "build/m4-resident/tools/bin"))
    g.add_argument("--output")
    g.add_argument("--strict", action="store_true")
    args = parser.parse_args()
    if args.command == "store-key":
        paths = P.build_paths(args.stream)
        comps = store_components(paths, Path(args.catalogues), "conjectured128_b2_q108_p20_fold4")
        print(json.dumps({"key": store_key(comps), "components": comps}, indent=1))
    elif args.command == "serve":
        serve(args)
    elif args.command == "daemon":
        daemon(args)
    elif args.command == "ledger":
        with open(args.out, "a") as handle:
            for row in ledger_rows(B.load(Path(args.receipt)), args.commit, notes=args.notes):
                handle.write(json.dumps(row, sort_keys=True) + "\n")
    elif args.command == "receive":
        receive_run(args.run, args.which, args.receiver_workers)
    elif args.command == "build-tools":
        build_tools(args)
    elif args.command == "catalogue-gate":
        catalogue_gate(args)


if __name__ == "__main__":
    main()
