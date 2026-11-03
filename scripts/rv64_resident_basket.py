#!/usr/bin/env python3
"""Measured 1/2/4-GPU resident-batch basket, using the production CLI unchanged.

A fresh process per block/device count runs one cold request, or (by default)
two requests against one persistent pool: cold, then warm. The cold proof gets an independent receiver; warm acceptance requires exact byte parity. Missing/unsupported
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
    if lanes > 4 or not isinstance(explicit, list) or len(explicit) > lanes or any(type(x) is not int or not 0 <= x <= 32 for x in explicit):
        raise ValueError("invalid coordinator lane geometry")
    budget = sum(positive(explicit[i] or workers, "lane workers") if i < len(explicit) else workers for i in range(lanes))
    if workers > 32 or budget > 32:
        raise ValueError("coordinator schedule exceeds the production 32-worker limit")
    target = max(lanes, device_count)
    if budget < target:
        raise ValueError("CPU worker budget cannot expose every GPU; increase the manifest schedule explicitly")
    if target != lanes:
        each, extra = divmod(budget, target)
        schedule.update(lanes=target, workers_per_lane=each,
                        lane_workers=[each + (i < extra) for i in range(target)])
    return result


def build_plan(basket, manifest, root, driver, receiver, library, output, devices, counts, cap, expected_runtime=RUNTIME, combined=False, recursive_receiver=None, repeat=2):
    if type(repeat) is not int or repeat not in (1, 2):
        raise ValueError("repeat must be 1 (fresh cold) or 2 (fresh cold/warm)")
    if manifest.get("schema") != "rv64-ethereum-basket-inputs/v1":
        raise ValueError("unsupported input manifest")
    if manifest.get("profile", PROFILE) != PROFILE:
        raise ValueError("the matrix requires the pinned profile")
    if len(set(devices)) != len(devices) or any(type(x) is not int or x < 0 for x in devices):
        raise ValueError("distinct nonnegative physical devices required")
    if not counts or len(set(counts)) != len(counts) or any(n not in (1, 2, 4) or n > len(devices) for n in counts):
        raise ValueError("matrix requires available distinct 1/2/4-device groups")
    if combined and counts != [1]:
        raise ValueError("combined recursion supports exactly one GPU; 2/4-device admission remains closed")
    if combined and recursive_receiver is None:
        raise ValueError("combined qualification requires an independently pinned recursive receiver")
    positive(cap, "device cap")
    if combined:
        host = positive(manifest.get("combined_host_bytes", 48 << 30), "combined host budget")
        immutable = positive(manifest.get("combined_immutable_device_bytes", 2 << 30), "combined immutable budget")
        keys = positive(manifest.get("immutable_host_key_bytes", 8 << 30), "host key budget")
        if cap > 28 << 30 or immutable > cap or keys > host:
            raise ValueError("combined budgets exceed the admitted device/host bounds")
    assets = {"driver": driver, "receiver": receiver, "library": library}
    if combined:
        assets["recursive_receiver"] = recursive_receiver
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
    return {"schema": SCHEMA, "combined": combined, "repeat": repeat, "profile": PROFILE,
            "immutable_host_key_bytes": manifest.get("immutable_host_key_bytes", 8 << 30),
            "combined_immutable_device_bytes": manifest.get("combined_immutable_device_bytes", 2 << 30),
            "combined_host_bytes": manifest.get("combined_host_bytes", 48 << 30), "runtime_target_sha256": expected_runtime,
            "assets": {k: str(p) for k, p in assets.items()}, "asset_sha256": pins,
            "elf_sha256": elf, "jobs": jobs, "device_cap_bytes": cap,
            "input_ready": all(not j["missing"] for j in jobs),
            "resident_environment": manifest.get("resident_environment", {}),
            "capacity_qualification": "Production per-device byte admission remains authoritative; input readiness does not establish that all retained MAINs fit.",
            "measurement_scope": (f"One process/block/config, {repeat} fresh complete native plus recursive request(s) with bounded immutable setup. Request wall excludes initial pool creation; process wall includes it. Only requested trials are measured; no resumed proofs or projected timings." if combined else f"One process/block/config, {repeat} fresh native request(s) with bounded immutable setup. Request wall excludes initial pool creation; process wall includes it. Only requested trials are measured; no recursion or projected timings.")}


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


def request_markers(log, block, count, repeat=2):
    result = {}
    pattern = r"GPU_RESIDENT_BLOCK block=(\d+) trial=(\d+) iteration=(\d+) request_wall_ns=(\d+).*?gpu_contexts=(\d+)"
    for m in re.finditer(pattern, log):
        if int(m[1]) != block or int(m[3]) != 0 or int(m[5]) != count or int(m[2]) in result:
            raise ValueError("resident request lifecycle markers disagree")
        result[int(m[2])] = int(m[4])
    if set(result) != set(range(repeat)):
        raise ValueError("missing requested lifecycle markers")
    return result


def recursive_snapshot(proof, leaf_count):
    """Freeze every physical proof and ordered sidecar before independent replay."""
    directory = proof / "recursion-om31"
    tree = B.load(directory / "tree.json")
    nodes = tree.get("nodes", [])
    if leaf_count < 1 or len(nodes) != 2 * leaf_count - 1 or tree.get("root") != len(nodes) - 1:
        raise ValueError("recursive tree coverage mismatch")
    names, leaves, uses = set(), set(), [0] * len(nodes)
    for index, node in enumerate(nodes):
        left, right = node.get("left"), node.get("right")
        if left is None and right is None:
            first = node.get("first_leaf")
            if type(first) is not int or not 0 <= first < leaf_count or first in leaves or node.get("leaf_count") != 1:
                raise ValueError("recursive leaf coverage mismatch")
            leaves.add(first)
            names.add(f"leaf-{first:06}.proof")
        else:
            if type(left) is not int or type(right) is not int or not 0 <= left < index or not 0 <= right < index or left == right:
                raise ValueError("recursive child ordering mismatch")
            a, b = nodes[left], nodes[right]
            if (node.get("first_leaf") != a["first_leaf"] or b["first_leaf"] != a["first_leaf"] + a["leaf_count"]
                    or node.get("leaf_count") != a["leaf_count"] + b["leaf_count"]):
                raise ValueError("recursive adjacency mismatch")
            uses[left] += 1
            uses[right] += 1
            names.add(f"fold-{index:06}.proof")
    if leaves != set(range(leaf_count)) or uses != [1] * (len(nodes) - 1) + [0] or nodes[-1]["first_leaf"] != 0 or nodes[-1]["leaf_count"] != leaf_count:
        raise ValueError("recursive complete coverage missing")
    names.add("root.proof")
    if {p.name for p in directory.glob("*.proof")} != names:
        raise ValueError("missing or extra physical recursive proofs; verification cannot re-prove")
    hashes = {name: B.sha(directory / name) for name in sorted(names)}
    final = f"fold-{len(nodes)-1:06}.proof" if leaf_count > 1 else "leaf-000000.proof"
    if hashes["root.proof"] != hashes[final]:
        raise ValueError("root proof differs from the physical final node")
    return {"proof_sha256": hashes, "tree_sha256": B.sha(directory / "tree.json")}


def check_recursive_report(report, leaf_count, restored=False):
    if report.get("accepted") is not True or report.get("leaf_proofs") != leaf_count or report.get("fold_proofs") != leaf_count - 1:
        raise ValueError("complete recursive acceptance missing")
    expected_restored = (leaf_count, leaf_count - 1) if restored else (0, 0)
    if (report.get("restored_leaves"), report.get("restored_folds")) != expected_restored:
        raise ValueError("recursive verification re-proved a missing proof" if restored else "resumed proofs cannot be a benchmark")
    expected_new = (0, 0) if restored else (leaf_count, leaf_count - 1)
    if (report.get("gpu_new_leaf_proofs"), report.get("gpu_new_fold_proofs")) != expected_new:
        raise ValueError("recursive device proof counts disagree")
    if not restored and (report.get("outer_backend") != "cuda_trace_only" or report.get("assignment_source") != "gpu_original_circuit_dag"):
        raise ValueError("CPU assignment or proving fallback rejected")


def receiver_environment(environment):
    """Fresh receivers cannot allocate CUDA memory or invoke a PCS helper."""
    result = dict(environment)
    result.pop("STWO_RV64_GPU_LIBRARY", None)
    result.pop("STWO_RV64_GPU_DEVICES", None)
    result["CUDA_VISIBLE_DEVICES"] = ""
    result["STWO_RV64_GPU_PCS_HELPER"] = "/bin/false"
    return result


def qualify_recursive_trial(plan, job, proof, native, target, trial, prior, log, environment):
    combined = B.load(proof / "combined-report.json")
    entry = B.load(proof / "combined-entry.json")
    count = native["cpu_proofs"] + native["truth_proofs"]
    if (combined.get("accepted") is not True or combined.get("completed_ethereum_block") is not True
            or combined.get("native_bundle_reload") is not False or combined.get("restored_recursive_proofs") is not False
            or combined.get("native_authority_session_used") is not True or entry.get("accepted") is not True
            or entry.get("device_lifecycle_audit") != "all request leases released"):
        raise ValueError("combined authority/lifecycle acceptance missing")
    recursive = combined["recursive"]
    check_recursive_report(recursive, count)
    matches = list(re.finditer(r"GPU_RESIDENT_BLOCK block=(\d+) trial=(\d+).*?gpu_contexts=(\d+)", log))
    marker = next((m for m in matches if int(m[2]) == trial), None)
    if marker is None:
        raise ValueError("combined request marker missing")
    start = 0 if trial == 0 else next(m.end() for m in matches if int(m[2]) == trial - 1)
    scoped_log = log[start:marker.start()]
    assignment = re.findall(r"GPU_OUTER .*?assignment_bytes=(\d+)", scoped_log)
    uploads = re.findall(r"GPU_OUTER_ASSIGNMENT .*?full_assignment_upload_words=(\d+)", scoped_log)
    if len(assignment) != 2 * count - 1 or len(uploads) != 2 * count - 1 or set(assignment) != {"0"} or set(uploads) != {"0"}:
        raise ValueError("physical zero-CPU-assignment generation evidence missing")
    snapshot = recursive_snapshot(proof, count)
    usage = None
    if trial == 0:
        verify_env = receiver_environment(environment)
        command = B.command(plan["assets"]["recursive_receiver"], plan["profile"], "resume-recursion-candidate", job["request"], proof,
                            job["resources"]["fixed_setup_bytes"], plan["combined_host_bytes"])
        usage = B.measure(command, target, "recursive-receiver-0", verify_env)
        received = B.load(target / "recursive-receiver-0.stdout")
        if received.get("accepted") is not True or received.get("completed_ethereum_block") is not True or received.get("native_profile") != native["profile"]:
            raise ValueError("fresh recursive receiver rejected the complete statement")
        check_recursive_report(received["recursive"], count, restored=True)
        if recursive_snapshot(proof, count) != snapshot:
            raise ValueError("fresh recursive receiver repaired or changed a proof/tree")
    elif snapshot != prior[0]["recursive_snapshot"]:
        raise ValueError("warm recursive bytes differ from freshly accepted cold proof")
    return {"recursion_ns": combined["recursion_ns"], "recursive": recursive,
            "root_proof_bytes": recursive["root_proof_bytes"], "recursive_snapshot": snapshot,
            "fresh_recursive_receiver": usage, "fresh_recursive_receiver_accepted": trial == 0,
            "recursive_acceptance": "fresh full-context receiver" if trial == 0 else "exact cold proof/tree SHA parity",
            "device_lifecycle_audit": entry["device_lifecycle_audit"], "zero_cpu_assignments": True,
            "combined_report_sha256": B.sha(proof / "combined-report.json"), "entry_sha256": B.sha(proof / "combined-entry.json")}


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
                "execution_order": [job["block"]], "resources": job["resources"], "repeat": plan.get("repeat", 2),
                "immutable_host_key_bytes": plan.get("immutable_host_key_bytes", 8 << 30), "immutable_device_bytes": 512 << 20,
                "combined_host_bytes": plan.get("combined_host_bytes", 48 << 30),
                "combined_immutable_device_bytes": plan.get("combined_immutable_device_bytes", 2 << 30)}
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
        usage = B.measure([plan["assets"]["driver"], "combined-batch" if plan.get("combined") else "resident-batch", str(target / "manifest.json"), str(target / "batch")], target, "producer", environment)
    finally:
        memory = monitor.finish()
        B.atomic_json(target / "gpu-memory.json", memory)
    log = (target / "producer.stdout").read_text(errors="replace") + (target / "producer.stderr").read_text(errors="replace")
    markers = request_markers(log, job["block"], job["device_count"], plan.get("repeat", 2))
    gpu = B.gpu_diagnostics(target / "producer.stderr")
    if gpu["kernel_launches"] <= 0 or gpu["device_ms"] <= 0:
        raise ValueError("actual GPU numerical evidence missing; fallback rejected")
    trials = []
    for trial in range(plan.get("repeat", 2)):
        proof = target / "batch" / ("trial-" + str(trial)) / str(job["block"]) / "proof"
        report = B.load(proof / "report.json")
        command = B.command(plan["assets"]["receiver"], plan["profile"], "verify-candidate", job["request"], proof,
                            job["resources"]["fixed_setup_bytes"], 32 << 30)
        artifacts = {p.name: B.sha(p) for p in proof.glob("*.bin")}
        bundle_hash = B.sha(proof / "bundle.json")
        if not artifacts:
            raise ValueError("proof binaries missing")
        if trial == 0:
            receiver_usage = B.measure(command, target, "receiver-0", receiver_environment(environment))
            accepted_receiver = B.load(target / "receiver-0.stdout")
        else:
            if artifacts != trials[0]["artifact_sha256"] or bundle_hash != trials[0]["bundle_sha256"]:
                raise ValueError("warm bytes differ from freshly accepted cold proof")
            receiver_usage = None
        check_trial(report, accepted_receiver, job, plan["profile"])
        trial_result = {"temperature": "cold" if trial == 0 else "warm", "request_wall_ns": markers[trial],
                       "capture_ns": report["capture_ns"], "setup_ns": report["setup_ns"], "prove_ns": report["prove_ns"],
                       "same_process_verify_ns": report["same_process_verify_ns"], "workers": report.get("workers"),
                       "gkr_tree_policy": report.get("gkr_tree_policy"), "total_before_report_ns": report["total_before_report_ns"],
                       "instructions": report["total_steps"], "segments": report["cpu_proofs"], "truths": report["truth_proofs"],
                       "native_cells": report.get("native_cells"), "cell_scope": report.get("cell_scope"),
                       "cell_accounting_status": "producer measured" if report.get("native_cells") else "not emitted by this producer; no inferred cell-rate claim",
                       "fresh_receiver": receiver_usage, "fresh_receiver_accepted": trial == 0,
                       "acceptance": "fresh receiver" if trial == 0 else "inherited from fresh cold receiver by exact proof and bundle SHA parity",
                       "artifact_sha256": artifacts, "bundle_sha256": bundle_hash, "report_sha256": B.sha(proof / "report.json")}
        if plan.get("combined"):
            if (accepted_receiver.get("cpu_proofs"), accepted_receiver.get("truth_proofs")) != (report["cpu_proofs"], report["truth_proofs"]):
                raise ValueError("fresh native receiver proof inventory differs")
            trial_result.update(qualify_recursive_trial(plan, job, proof, report, target, trial, trials, log, environment))
        trials.append(trial_result)
    if len(trials) > 1 and (trials[0]["artifact_sha256"] != trials[1]["artifact_sha256"] or trials[0]["bundle_sha256"] != trials[1]["bundle_sha256"]):
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
    return {"schema": SCHEMA, "combined": plan.get("combined", False), "status": "accepted", "block": job["block"], "device_count": job["device_count"],
            "coordinator_schedule": job["resources"]["schedule"],
            "request_sha256": job["request_sha256"], "input_sha256": job["input_sha256"], "asset_sha256": plan["asset_sha256"],
            "single_device_proof_byte_parity": cross_device_parity,
            "profile": plan["profile"], "trials": trials,
            "environment": {k: v for k, v in environment.items() if k.startswith(("STWO_RV64_", "CUDA_"))}, "producer_process": usage, "gpu": gpu, "physical_gpu_memory": memory,
            "process_unattributed_wall_ns": usage["wall_ns"] - sum(markers.values()),
            "wall_scope": ("Request wall includes execution/capture/setup, native proving and verification, fresh recursion and the device lifecycle audit. Process remainder includes pool startup/teardown and reporting. Independent verification is separate." if plan.get("combined") else "Request wall includes execution/capture/setup/prove/native verification; process-unattributed wall includes device-pool startup/teardown and outer CLI work. Fresh receiver wall is separate."),
            "residency_scope": "Strict resident-batch rejects host-retained mode; device trace/binding required. No CPU fallback. Wide-transfer absence is a production contract, not a CUPTI measurement."}


def render(plan, results):
    by_key = {(r["device_count"], r["block"]): r for r in results}
    lines = ["# Resident Ethereum basket measurements", "", "128-bit security target under documented conjectured assumptions; no whole-protocol certificate. " + ("Includes fresh native and recursive proving; one GPU only." if plan.get("combined") else "No recursion or projected GPU figures."), "",
             "| GPUs | Block | Status | Cold prove s | Warm prove s | Cold request s | Warm request s |", "|---:|---:|---|---:|---:|---:|---:|"]
    for job in plan["jobs"]:
        r = by_key.get((job["device_count"], job["block"]))
        values = ["—"] * 4
        if r and r.get("status") == "accepted":
            a = r["trials"][0]
            b = r["trials"][1] if len(r["trials"]) > 1 else None
            values = [f"{v / 1e9:.3f}" if v is not None else "—" for v in (a["prove_ns"], b["prove_ns"] if b else None, a["request_wall_ns"], b["request_wall_ns"] if b else None)]
        lines.append(f"| {job['device_count']} | {job['block']} | {r.get('status') if r else 'not run'} | " + " | ".join(values) + " |")
    if plan.get("combined"):
        lines[4] = lines[4].replace("Cold prove s", "Cold native prove s").replace("Warm prove s", "Warm native prove s")
    accepted = sum(r.get("status") == "accepted" for r in results)
    lines += ["", f"Freshly accepted configurations: {accepted}/{len(plan['jobs'])}. A partial matrix is not a complete basket result.", "", plan["measurement_scope"], "",
              "| GPUs | Block | Process wall s | Startup/outer wall s | Peak RSS GiB | Sampled peak GPU GiB |", "|---:|---:|---:|---:|---:|---|"]
    for r in results:
        if r.get("status") != "accepted":
            continue
        gpu_peak = ", ".join(f"{k}: {v / 2**30:.2f}" if v is not None else f"{k}: unavailable" for k, v in r["physical_gpu_memory"].get("peak_used_bytes", {}).items())
        lines.append(f"| {r['device_count']} | {r['block']} | {r['producer_process']['wall_ns']/1e9:.3f} | {r['process_unattributed_wall_ns']/1e9:.3f} | {r['producer_process'].get('peak_rss_bytes',0)/2**30:.2f} | {gpu_peak} |")
    if plan.get("combined"):
        lines += ["", "| Block | Cold recursion s | Warm recursion s | Cold complete request s | Warm complete request s | Root bytes |", "|---:|---:|---:|---:|---:|---:|"]
        for r in results:
            if r.get("status") != "accepted":
                continue
            cold = r["trials"][0]
            warm = r["trials"][1] if len(r["trials"]) > 1 else None
            warm_recursion = f"{warm['recursion_ns']/1e9:.3f}" if warm else "—"
            warm_request = f"{warm['request_wall_ns']/1e9:.3f}" if warm else "—"
            lines.append(f"| {r['block']} | {cold['recursion_ns']/1e9:.3f} | {warm_recursion} | {cold['request_wall_ns']/1e9:.3f} | {warm_request} | {cold['root_proof_bytes']} |")
        lines += ["", "Cold verification independently reconstructs native and recursive authorities and verifies the existing proofs. When requested, warm acceptance inherits only through exact native bundle, all native proofs, all outer proofs and tree SHA parity. A single-trial result makes no warm or parity claim. Verification is outside request proving wall. This is full-context verification; portable root-only key admission remains unqualified."]
    for r in results:
        if r.get("status") == "failed":
            lines += ["", f"Failure, {r['device_count']} GPU(s), block {r['block']}: {r['error']}"]
    lines += ["", f"Peak RSS is measured per {plan.get('repeat', 2)}-request process. VRAM is sampled whole-device use, not exact process allocation. GPU phase totals overlap and cannot be substituted for wall time."]
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
    p.add_argument("--combined", action="store_true", help="Qualify complete native plus recursive cold/warm requests; currently one GPU only")
    p.add_argument("--recursive-receiver", type=Path, help="Current recursive receiver supporting resume-recursion-candidate; all cached proofs must be restored and verified, never newly proved")
    p.add_argument("--library", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--library-sha256", default=RUNTIME)
    p.add_argument("--devices", default="0,1,2,3")
    p.add_argument("--keep-going", action="store_true", help="Record failed cases and continue; final status remains failed")
    p.add_argument("--counts", default="1,2,4")
    p.add_argument("--repeat", type=int, choices=(1, 2), default=2, help="1: fresh cold proof and receivers per case; 2: additionally prove warm and require exact parity")
    p.add_argument("--device-cap-bytes", type=int, default=28 << 30)
    args = p.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    plan = build_plan(B.load(args.basket), B.load(args.inputs), args.inputs.resolve().parent,
                      args.driver.resolve(), args.receiver.resolve(), args.library.resolve(), args.output.resolve(),
                      list(map(int, args.devices.split(","))), list(map(int, args.counts.split(","))), args.device_cap_bytes, args.library_sha256, args.combined, args.recursive_receiver.resolve() if args.recursive_receiver else None, args.repeat)
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
