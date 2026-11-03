#!/usr/bin/env python3
"""Measured 1/2/4-GPU resident-batch basket, using the production CLI unchanged.

A fresh process per block/device count runs two requests against one persistent
pool: cold, then warm. The cold proof gets an independent receiver; warm acceptance requires exact byte parity. Missing/unsupported
cases stay explicit failures; a partial matrix is never called complete.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import re
import subprocess

import rv64_ethereum_basket as B

SCHEMA = "rv64-resident-basket/v1"
PROFILE = "conjectured128_b2_q108_p20_fold4"
RUNTIME = "6d9a8d6188fb6df68b68d41557c2d905b2e17caa30a100d64cbbc7555c93a0ed"


def positive(value, name):
    if type(value) is not int or value <= 0:
        raise ValueError(name + " must be a positive integer")
    return value


def device_resources(resources, device_count):
    """Expose every device without increasing the manifest's CPU worker budget.

    GPU byte admission is still enforced by the producer. A lane is permission
    to schedule work, not a promise that another proof fits concurrently.
    """
    result = copy.deepcopy(resources)
    schedule = result.get("schedule")
    if not schedule:
        raise ValueError("explicit coordinator schedule required for GPU measurements")
    lanes = positive(schedule.get("lanes"), "coordinator lanes")
    workers = positive(schedule.get("workers_per_lane"), "workers per lane")
    explicit = schedule.get("lane_workers", [])
    if lanes > 4 or len(explicit) > lanes:
        raise ValueError("invalid coordinator lane geometry")
    budget = sum(positive(explicit[i] or workers, "lane workers") if i < len(explicit) else workers for i in range(lanes))
    target = max(lanes, device_count)
    if budget < target:
        raise ValueError("CPU worker budget cannot expose every GPU; increase the manifest schedule explicitly")
    if target != lanes:
        each, extra = divmod(budget, target)
        schedule.update(lanes=target, workers_per_lane=each,
                        lane_workers=[each + (i < extra) for i in range(target)])
    return result


def build_plan(basket, manifest, root, driver, receiver, library, output, devices, counts, cap, expected_runtime=RUNTIME):
    if manifest.get("schema") != "rv64-ethereum-basket-inputs/v1":
        raise ValueError("unsupported input manifest")
    if manifest.get("profile", PROFILE) != PROFILE:
        raise ValueError("the matrix requires the pinned profile")
    if len(set(devices)) != len(devices) or any(type(x) is not int or x < 0 for x in devices):
        raise ValueError("distinct nonnegative physical devices required")
    if not counts or len(set(counts)) != len(counts) or any(n not in (1, 2, 4) or n > len(devices) for n in counts):
        raise ValueError("matrix requires available distinct 1/2/4-device groups")
    positive(cap, "device cap")
    assets = {"driver": driver, "receiver": receiver, "library": library}
    missing = [str(p) for p in assets.values() if not p.is_file()]
    pins = {k: B.sha(p) for k, p in assets.items() if p.is_file()}
    if not re.fullmatch(r"[0-9a-f]{64}", expected_runtime):
        raise ValueError("explicit runtime SHA256 required")
    if pins.get("library", expected_runtime) != expected_runtime:
        raise ValueError("runtime differs from the qualified default image; update the pinned runtime explicitly")
    resources = copy.deepcopy(manifest["resources"])
    resources.update(park_main=False, disk_bytes=0, keccak_uniform_throughput=True)
    positive(resources.get("fixed_setup_bytes"), "fixed setup budget")
    positive(resources.get("retained_frontend_bytes"), "frontend budget")
    jobs, elf = [], None
    for block in basket["blocks"]:
        number = block["block"]
        entry = manifest.get("blocks", {}).get(str(number))
        absent = list(missing)
        request_path = B.absolute(entry["request"], root) if entry else None
        request = None
        if request_path is None or not request_path.is_file():
            absent.append("request for block " + str(number))
        else:
            request = B.load(request_path)
            if entry.get("prefix_count", 0) or entry.get("jobs", "-") != "-":
                raise ValueError("only full direct-capture requests are admitted")
            for key in ("elf", "input"):
                path = B.absolute(request[key], request_path.parent)
                if not path.is_file():
                    absent.append(str(path))
                elif B.sha(path) != request[key + "_sha256"]:
                    raise ValueError(f"{number}: {key} hash mismatch")
            if elf is not None and elf != request["elf_sha256"]:
                raise ValueError("guest identity differs within basket")
            elf = request["elf_sha256"]
            if not request["expected_output"].lower().startswith(block["new_payload_request_root"][2:].lower()):
                raise ValueError("expected output differs from the pinned basket root")
            if request.get("execution_profile") != "ethereum_services_v3":
                raise ValueError("requires the pinned V3 guest execution profile")
            positive(entry.get("expected_cpu_segments"), "expected CPU segment count")
        for n in counts:
            target = output / (str(n) + "gpu") / str(number)
            jobs.append({"block": number, "set": block["set"], "devices": devices[:n], "device_count": n,
                         "request": str(request_path) if request_path else None, "missing": absent,
                         "request_sha256": B.sha(request_path) if request else None,
                         "expected_output": request["expected_output"] if request else None,
                         "input_sha256": request["input_sha256"] if request else None,
                         "segments": entry["expected_cpu_segments"] if request else None,
                         "target": str(target), "resources": device_resources(resources, n)})
    return {"schema": SCHEMA, "profile": PROFILE, "runtime_target_sha256": expected_runtime,
            "assets": {k: str(p) for k, p in assets.items()}, "asset_sha256": pins,
            "elf_sha256": elf, "jobs": jobs, "device_cap_bytes": cap,
            "input_ready": all(not j["missing"] for j in jobs),
            "resident_environment": manifest.get("resident_environment", {}),
            "capacity_qualification": "Production per-device byte admission remains authoritative; input readiness does not establish that all retained MAINs fit.",
            "measurement_scope": "One process/block/config, two requests sharing immutable setup. Cold/warm request wall excludes initial pool creation; process wall includes it. No recursion or projected timings."}


def gpu_inventory(devices):
    raw = subprocess.check_output(["nvidia-smi", "--query-gpu=index,uuid,name,memory.total", "--format=csv,noheader,nounits"], text=True)
    inventory = {}
    for line in raw.splitlines():
        index, uuid, name, memory = [p.strip() for p in line.split(",")]
        inventory[int(index)] = {"uuid": uuid, "name": name, "memory_bytes": int(memory) << 20}
    for device in devices:
        if device not in inventory or "5090" not in inventory[device]["name"]:
            raise ValueError("requested physical RTX 5090 absent: " + str(device))
    return {str(d): inventory[d] for d in devices}


def check_trial(report, receiver, job, profile):
    if (receiver.get("accepted") is not True or receiver.get("completed_ethereum_block") is not True
            or report.get("completed_ethereum_block") is not True):
        raise ValueError("fresh full-block acceptance missing")
    if receiver.get("security_profile") != profile or report.get("capture_source") != "in_process_execution":
        raise ValueError("profile or direct-capture authority mismatch")
    if bytes(receiver["output"]).hex() != job["expected_output"] or bytes(report["output"]).hex() != job["expected_output"]:
        raise ValueError("pinned output mismatch")
    if report["cpu_proofs"] != job["segments"]:
        raise ValueError("segment count differs from independently pinned execution")
    if not report.get("keccak_uniform_throughput") or report.get("retained_main") is not None:
        raise ValueError("strict resident geometry/ownership mismatch")


def request_markers(log, block, count):
    result = {}
    pattern = r"GPU_RESIDENT_BLOCK block=(\d+) trial=(\d+) iteration=(\d+) request_wall_ns=(\d+).*?gpu_contexts=(\d+)"
    for m in re.finditer(pattern, log):
        if int(m[1]) != block or int(m[3]) != 0 or int(m[5]) != count or int(m[2]) in result:
            raise ValueError("resident request lifecycle markers disagree")
        result[int(m[2])] = int(m[4])
    if set(result) != {0, 1}:
        raise ValueError("missing cold/warm request lifecycle markers")
    return result


def run_job(plan, job):
    target = Path(job["target"])
    target.mkdir(parents=True, exist_ok=False)
    if job["missing"]:
        raise ValueError("missing inputs: " + repr(job["missing"]))
    for key, path in plan["assets"].items():
        if B.sha(path) != plan["asset_sha256"][key]:
            raise ValueError("asset changed since planning: " + key)
    if B.sha(job["request"]) != job["request_sha256"]:
        raise ValueError("request changed since planning")
    request = B.load(job["request"])
    for key in ("elf", "input"):
        if B.sha(B.absolute(request[key], Path(job["request"]).parent)) != request[key + "_sha256"]:
            raise ValueError("guest/input changed since planning")
    manifest = {"schema": "rv64-ethereum-basket-inputs/v1", "profile": plan["profile"],
                "blocks": {str(job["block"]): {"request": job["request"], "expected_cpu_segments": job["segments"]}},
                "execution_order": [job["block"]], "resources": job["resources"], "repeat": 2,
                "immutable_host_key_bytes": 8 << 30, "immutable_device_bytes": 512 << 20}
    B.atomic_json(target / "manifest.json", manifest)
    worker = {"device": ",".join(map(str, job["devices"])), "device_caps_bytes": [plan["device_cap_bytes"]] * job["device_count"],
              "planned_cpu_workers": job["segments"], "retained_scopes": 64}
    environment = {k: v for k, v in os.environ.items() if not k.startswith("STWO_RV64_")}
    environment.update(plan["resident_environment"])
    environment = B.worker_environment(worker, environment)
    for key in ("STWO_RV64_GPU_HOST_RETAINED", "STWO_RV64_DEEP_TIMING", "STWO_RV64_DEEP_COORDINATES", "STWO_RV64_PCS_PHASE_TIMING"):
        environment.pop(key, None)
    environment["STWO_RV64_GPU_LIBRARY"] = plan["assets"]["library"]
    monitor = B.DeviceMonitor(worker["device"])
    monitor.thread.start()
    try:
        usage = B.measure([plan["assets"]["driver"], "resident-batch", str(target / "manifest.json"), str(target / "batch")], target, "producer", environment)
    finally:
        memory = monitor.finish()
        B.atomic_json(target / "gpu-memory.json", memory)
    log = (target / "producer.stdout").read_text(errors="replace") + (target / "producer.stderr").read_text(errors="replace")
    markers = request_markers(log, job["block"], job["device_count"])
    gpu = B.gpu_diagnostics(target / "producer.stderr")
    if gpu["kernel_launches"] <= 0 or gpu["device_ms"] <= 0:
        raise ValueError("actual GPU numerical evidence missing; fallback rejected")
    trials = []
    for trial in (0, 1):
        proof = target / "batch" / ("trial-" + str(trial)) / str(job["block"]) / "proof"
        report = B.load(proof / "report.json")
        command = B.command(plan["assets"]["receiver"], plan["profile"], "verify-candidate", job["request"], proof,
                            job["resources"]["fixed_setup_bytes"], 32 << 30)
        artifacts = {p.name: B.sha(p) for p in proof.glob("*.bin")}
        bundle_hash = B.sha(proof / "bundle.json")
        if not artifacts:
            raise ValueError("proof binaries missing")
        if trial == 0:
            receiver_usage = B.measure(command, target, "receiver-0")
            accepted_receiver = B.load(target / "receiver-0.stdout")
        else:
            if artifacts != trials[0]["artifact_sha256"] or bundle_hash != trials[0]["bundle_sha256"]:
                raise ValueError("warm bytes differ from freshly accepted cold proof")
            receiver_usage = None
        check_trial(report, accepted_receiver, job, plan["profile"])
        trials.append({"temperature": "cold" if trial == 0 else "warm", "request_wall_ns": markers[trial],
                       "capture_ns": report["capture_ns"], "setup_ns": report["setup_ns"], "prove_ns": report["prove_ns"],
                       "same_process_verify_ns": report["same_process_verify_ns"], "workers": report.get("workers"),
                       "gkr_tree_policy": report.get("gkr_tree_policy"), "total_before_report_ns": report["total_before_report_ns"],
                       "instructions": report["total_steps"], "segments": report["cpu_proofs"], "truths": report["truth_proofs"],
                       "native_cells": report.get("native_cells"), "cell_scope": report.get("cell_scope"),
                       "cell_accounting_status": "producer measured" if report.get("native_cells") else "not emitted by this producer; no inferred cell-rate claim",
                       "fresh_receiver": receiver_usage, "fresh_receiver_accepted": trial == 0,
                       "acceptance": "fresh receiver" if trial == 0 else "inherited from fresh cold receiver by exact proof and bundle SHA parity",
                       "artifact_sha256": artifacts, "bundle_sha256": bundle_hash, "report_sha256": B.sha(proof / "report.json")})
    if trials[0]["artifact_sha256"] != trials[1]["artifact_sha256"] or trials[0]["bundle_sha256"] != trials[1]["bundle_sha256"]:
        raise ValueError("cold/warm deterministic byte parity failed")
    cross_device_parity = None
    baseline = Path(job["target"]).parents[1] / "1gpu" / str(job["block"]) / "result.json"
    if job["device_count"] != 1 and baseline.is_file():
        reference = B.load(baseline)
        if (reference.get("status") != "accepted" or reference.get("asset_sha256") != plan["asset_sha256"]
                or reference.get("request_sha256") != job["request_sha256"]):
            raise ValueError("single-device reference authority differs")
        if (trials[0]["artifact_sha256"] != reference["trials"][0]["artifact_sha256"] or
                trials[0]["bundle_sha256"] != reference["trials"][0]["bundle_sha256"]):
            raise ValueError("cross-device exact proof parity failed")
        cross_device_parity = True
    return {"schema": SCHEMA, "status": "accepted", "block": job["block"], "device_count": job["device_count"],
            "coordinator_schedule": job["resources"]["schedule"],
            "request_sha256": job["request_sha256"], "input_sha256": job["input_sha256"], "asset_sha256": plan["asset_sha256"],
            "single_device_proof_byte_parity": cross_device_parity,
            "profile": plan["profile"], "trials": trials,
            "environment": {k: v for k, v in environment.items() if k.startswith(("STWO_RV64_", "CUDA_"))}, "producer_process": usage, "gpu": gpu, "physical_gpu_memory": memory,
            "process_unattributed_wall_ns": usage["wall_ns"] - sum(markers.values()),
            "wall_scope": "Request wall includes execution/capture/setup/prove/native verification; process-unattributed wall includes device-pool startup/teardown and outer CLI work. Fresh receiver wall is separate.",
            "residency_scope": "Strict resident-batch rejects host-retained mode; device trace/binding required. No CPU fallback. Wide-transfer absence is a production contract, not a CUPTI measurement."}


def render(plan, results):
    by_key = {(r["device_count"], r["block"]): r for r in results}
    lines = ["# Resident Ethereum basket measurements", "", "128-bit security target under documented conjectured assumptions; no whole-protocol certificate. No recursion or projected GPU figures.", "",
             "| GPUs | Block | Status | Cold prove s | Warm prove s | Cold request s | Warm request s |", "|---:|---:|---|---:|---:|---:|---:|"]
    for job in plan["jobs"]:
        r = by_key.get((job["device_count"], job["block"]))
        values = ["—"] * 4
        if r and r.get("status") == "accepted":
            a, b = r["trials"]
            values = [f"{v / 1e9:.3f}" for v in (a["prove_ns"], b["prove_ns"], a["request_wall_ns"], b["request_wall_ns"])]
        lines.append(f"| {job['device_count']} | {job['block']} | {r.get('status') if r else 'not run'} | " + " | ".join(values) + " |")
    accepted = sum(r.get("status") == "accepted" for r in results)
    lines += ["", f"Freshly accepted configurations: {accepted}/{len(plan['jobs'])}. A partial matrix is not a complete basket result.", "", plan["measurement_scope"], "",
              "| GPUs | Block | Process wall s | Startup/outer wall s | Peak RSS GiB | Sampled peak GPU GiB |", "|---:|---:|---:|---:|---:|---|"]
    for r in results:
        if r.get("status") != "accepted":
            continue
        gpu_peak = ", ".join(f"{k}: {v / 2**30:.2f}" if v is not None else f"{k}: unavailable" for k, v in r["physical_gpu_memory"].get("peak_used_bytes", {}).items())
        lines.append(f"| {r['device_count']} | {r['block']} | {r['producer_process']['wall_ns']/1e9:.3f} | {r['process_unattributed_wall_ns']/1e9:.3f} | {r['producer_process'].get('peak_rss_bytes',0)/2**30:.2f} | {gpu_peak} |")
    for r in results:
        if r.get("status") == "failed":
            lines += ["", f"Failure, {r['device_count']} GPU(s), block {r['block']}: {r['error']}"]
    lines += ["", "Peak RSS is measured per two-request process. VRAM is sampled whole-device use, not exact process allocation. GPU phase totals overlap and cannot be substituted for wall time."]
    lines += ["", "| GPUs | Coordinator lanes | CPU workers per lane | Host memory admission bytes |", "|---:|---:|---|---:|"]
    for count in sorted({j["device_count"] for j in plan["jobs"]}):
        schedule = next(j["resources"]["schedule"] for j in plan["jobs"] if j["device_count"] == count)
        workers = schedule.get("lane_workers") or [schedule["workers_per_lane"]] * schedule["lanes"]
        lines.append(f"| {count} | {schedule['lanes']} | {', '.join(map(str, workers))} | {schedule.get('memory_cap_bytes', 0)} |")
    return "\n".join(lines) + "\n"


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode", choices=("plan", "run", "report"))
    p.add_argument("--basket", type=Path, default=Path("autoresearch/guest_efficiency/basket.json"))
    p.add_argument("--inputs", type=Path, required=True)
    p.add_argument("--driver", type=Path, required=True)
    p.add_argument("--receiver", type=Path, required=True)
    p.add_argument("--library", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--library-sha256", default=RUNTIME)
    p.add_argument("--devices", default="0,1,2,3")
    p.add_argument("--keep-going", action="store_true", help="Record failed cases and continue; final status remains failed")
    p.add_argument("--counts", default="1,2,4")
    p.add_argument("--device-cap-bytes", type=int, default=28 << 30)
    args = p.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    plan = build_plan(B.load(args.basket), B.load(args.inputs), args.inputs.resolve().parent,
                      args.driver.resolve(), args.receiver.resolve(), args.library.resolve(), args.output.resolve(),
                      list(map(int, args.devices.split(","))), list(map(int, args.counts.split(","))), args.device_cap_bytes, args.library_sha256)
    plan.update(basket_sha256=B.sha(args.basket), inputs_sha256=B.sha(args.inputs))
    if args.mode != "report":
        B.atomic_json(args.output / "plan.json", plan)
    else:
        if B.load(args.output / "plan.json") != plan:
            raise ValueError("report authority differs from original pinned plan")
    if args.mode == "run":
        if not plan["input_ready"]:
            raise ValueError("matrix has missing assets/inputs; inspect plan.json")
        inventory = gpu_inventory(sorted({d for j in plan["jobs"] for d in j["devices"]}))
        B.atomic_json(args.output / "gpu-inventory.json", inventory)
        for job in plan["jobs"]:
            path = Path(job["target"]) / "result.json"
            try:
                result = run_job(plan, job)
            except Exception as error:
                result = {"schema": SCHEMA, "status": "failed", "block": job["block"], "device_count": job["device_count"], "error": str(error),
                          "process_measurement": getattr(error, "measurement", None)}
                path.parent.mkdir(parents=True, exist_ok=True)
                B.atomic_json(path, result)
                partial = [B.load(Path(j["target"]) / "result.json") for j in plan["jobs"] if (Path(j["target"]) / "result.json").is_file()]
                B.atomic_json(args.output / "results.json", {"schema": SCHEMA, "complete": False, "results": partial})
                (args.output / "report.md").write_text(render(plan, partial))
                if not args.keep_going:
                    raise
                continue
            B.atomic_json(path, result)
            partial = [B.load(Path(j["target"]) / "result.json") for j in plan["jobs"] if (Path(j["target"]) / "result.json").is_file()]
            B.atomic_json(args.output / "results.json", {"schema": SCHEMA, "complete": False, "results": partial})
            (args.output / "report.md").write_text(render(plan, partial))
    results = [B.load(Path(j["target"]) / "result.json") for j in plan["jobs"] if (Path(j["target"]) / "result.json").is_file()]
    B.atomic_json(args.output / "results.json", {"schema": SCHEMA, "complete": len(results) == len(plan["jobs"]) and all(r["status"] == "accepted" for r in results), "results": results})
    (args.output / "report.md").write_text(render(plan, results))
    if args.mode == "run" and any(r["status"] != "accepted" for r in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
