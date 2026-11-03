#!/usr/bin/env python3
"""Strict CPU-only qualification of a sealed resident case on another host.

Original producer plans/requests are immutable. Explicit path mappings select
copies for I/O; only independently pinned receivers may change authority.
"""
import argparse
import copy
import fcntl
import os
from pathlib import Path
import platform
import shutil
import tempfile

import rv64_resident_basket as R

B = R.B
ARM_RECEIVER = "/private/tmp/rv64-cpu-v2-arm/bin/rv64-word16-ethereum-recursion-receiver"
ARM_SHA256 = "0025ac3c498822c9ce1db66c1aad9bbaf76fa6490e4172342ada25167bf30395"
RECYCLER_BYTES = 4 << 30  # Contract of the independently qualified receiver.


def file_snapshot(directory):
    return {str(p.relative_to(directory)): B.sha(p) for p in sorted(directory.rglob("*")) if p.is_file()}


def qualify(plan_path, case, block, device_count, request_path, driver, library, output,
            receiver=ARM_RECEIVER, receiver_sha256=ARM_SHA256, workers=4,
            host_bytes=32 << 30, lock=None):
    plan_path, case, request_path, output = map(lambda p: Path(p).resolve(), (plan_path, case, request_path, output))
    receiver, driver, library = map(lambda p: Path(p).resolve(), (receiver, driver, library))
    if output.is_relative_to(case):
        raise ValueError("qualification output must be outside the immutable produced case")
    if type(workers) is not int or not 1 <= workers <= 4 or type(host_bytes) is not int or not 0 < host_bytes <= 32 << 30:
        raise ValueError("off-host qualification requires at most 4 workers and 32 GiB live heap")
    original = B.load(plan_path)
    if not original.get("combined"):
        raise ValueError("off-host strict qualification requires combined native and recursive proving")
    jobs = [j for j in original["jobs"] if j["block"] == block and j["device_count"] == device_count]
    if len(jobs) != 1:
        raise ValueError("original plan must contain exactly one selected case")
    declared = jobs[0]
    pending = B.load(case / "produced.json")
    if set(pending.get("log_sha256", {})) != {"producer.stdout", "producer.stderr"}:
        raise ValueError("both immutable producer log hashes are required")
    if B.sha(receiver) != receiver_sha256:
        raise ValueError("independently pinned CPU receiver changed")
    request = B.load(request_path)
    source_assets = {}
    for name in ("elf", "input"):
        # Worker-only operational copies cannot change guest/input paths. The
        # caller installs these exact original absolute paths before admission.
        path = Path(request[name])
        if not path.is_absolute() or B.sha(path) != request[name + "_sha256"]:
            raise ValueError("original absolute guest/input path missing or changed: " + name)
        source_assets[name] = {"original": str(path), "local": str(path.resolve()), "sha256": B.sha(path)}
    if request["elf_sha256"] != original["elf_sha256"] or request["input_sha256"] != declared["input_sha256"]:
        raise ValueError("guest/input identity differs from original production plan")
    qualified = copy.deepcopy(original)
    qualified["strict_recursive_receiver"] = True
    for name in ("receiver", "recursive_receiver"):
        qualified["assets"][name] = str(receiver)
        qualified["asset_sha256"][name] = receiver_sha256
    R.qualification_view(original, qualified)
    io_job = dict(declared, target=str(case))
    mapped_assets = {"driver": driver, "library": library}
    R.validate_pending(qualified, io_job, pending, original, asset_paths=mapped_assets, request_path=request_path)
    before = file_snapshot(case)
    pins = {"plan": B.sha(plan_path), "request": B.sha(request_path), "receiver": receiver_sha256,
            "driver": B.sha(driver), "library": B.sha(library)}
    log = (case / "producer.stdout").read_text(errors="replace") + (case / "producer.stderr").read_text(errors="replace")
    repeat = original.get("repeat", 2)
    if type(repeat) is not int or repeat not in (1, 2) or pending["producer_process"].get("exit_code") != 0:
        raise ValueError("original sealed production must contain successful requested trials")
    actual_gpu = B.gpu_diagnostics(case / "producer.stderr")
    if actual_gpu["kernel_launches"] <= 0 or actual_gpu["device_ms"] <= 0 or actual_gpu != pending["gpu"]:
        raise ValueError("pending GPU evidence differs from immutable producer log")
    markers = R.request_markers(log, block, device_count, repeat)
    if markers != {int(k): v for k, v in pending["markers"].items()}:
        raise ValueError("pending request timings differ from immutable producer logs")
    output.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(plan_path, output / "original-plan.json")
    shutil.copyfile(request_path, output / "original-request.json")
    operational = copy.deepcopy(request)
    operational["workers"] = workers
    operational_path = output / "receiver-request.json"
    B.atomic_json(operational_path, operational)
    B.atomic_json(output / "qualification-plan.json", qualified)
    B.atomic_json(output / "artifacts-before.json", before)
    lock = Path(lock) if lock is not None else Path(tempfile.gettempdir()) / "rv64-offhost-strict-receiver.lock"
    environment = R.receiver_environment(dict(os.environ), output / "gpu-disabled")
    proof = case / "batch" / "trial-0" / str(block) / "proof"
    command = ["nice", "-n", "10", *B.command(receiver, original["profile"], "verify-recursion-candidate",
               operational_path, proof, declared["resources"]["fixed_setup_bytes"], host_bytes)]
    with lock.open("a") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        R.validate_pending(qualified, io_job, pending, original, asset_paths=mapped_assets, request_path=request_path)
        if B.sha(receiver) != pins["receiver"] or B.sha(plan_path) != pins["plan"]:
            raise ValueError("qualification authority changed while waiting for the receiver")
        for name, info in source_assets.items():
            if B.sha(info["local"]) != info["sha256"]:
                raise ValueError("guest/input changed before receiver launch: " + name)
        usage = B.measure(command, output, "strict-receiver", environment)
    received = B.load(output / "strict-receiver.stdout")
    trials = []
    for trial in range(repeat):
        proof = case / "batch" / ("trial-" + str(trial)) / str(block) / "proof"
        report = B.load(proof / "report.json")
        artifacts = {p.name: B.sha(p) for p in proof.glob("*.bin")}
        bundle = B.sha(proof / "bundle.json")
        if not artifacts:
            raise ValueError("physical native proof binaries missing")
        if trial and (artifacts != trials[0]["artifact_sha256"] or bundle != trials[0]["bundle_sha256"]):
            raise ValueError("warm native proof/bundle bytes differ from fresh cold acceptance")
        R.check_trial(report, received["native"], declared, original["profile"])
        if (received["native"].get("cpu_proofs"), received["native"].get("truth_proofs")) != (report["cpu_proofs"], report["truth_proofs"]):
            raise ValueError("fresh native receiver proof inventory differs")
        item = {"temperature": "cold" if trial == 0 else "warm", "request_wall_ns": markers[trial],
                "artifact_sha256": artifacts, "bundle_sha256": bundle, "report_sha256": B.sha(proof / "report.json"),
                "fresh_receiver": usage if trial == 0 else None, "fresh_receiver_accepted": trial == 0}
        for name in ("capture_ns", "setup_ns", "prove_ns", "same_process_verify_ns", "total_before_report_ns"):
            item[name] = report[name]
        item.update(R.qualify_recursive_trial(qualified, io_job, proof, report, output, trial, trials, log,
                                            environment, received_override=received if trial == 0 else None,
                                            shared_usage=usage if trial == 0 else None))
        trials.append(item)
    R.validate_pending(qualified, io_job, pending, original, asset_paths=mapped_assets, request_path=request_path)
    if file_snapshot(case) != before or B.sha(plan_path) != pins["plan"] or B.sha(request_path) != pins["request"] or B.sha(receiver) != pins["receiver"]:
        raise ValueError("independent receiver changed immutable provenance/artifacts")
    for name, info in source_assets.items():
        if B.sha(info["local"]) != info["sha256"]:
            raise ValueError("guest/input changed during independent qualification: " + name)
    result = {"schema": "rv64-resident-offhost-qualification/v1", "status": "accepted", "accepted": True,
              "block": block, "device_count": device_count, "profile": original["profile"],
              "production_plan_sha256": pending["plan_sha256"], "production_plan_file_sha256": pins["plan"],
              "qualification_plan_sha256": R.plan_identity(qualified), "producer_asset_sha256": original["asset_sha256"],
              "asset_sha256": qualified["asset_sha256"], "strict_recursive_receiver": True,
              "request_sha256": pins["request"], "receiver_request_sha256": B.sha(operational_path),
              "request_overrides": {"workers": workers}, "receiver_sha256": pins["receiver"],
              "receiver_host_live_cap_bytes": host_bytes, "receiver_recycler_cache_cap_bytes": RECYCLER_BYTES,
              "recycler_cap_basis": "qualified receiver build contract; not an operational CLI override",
              "receiver_host": {"system": platform.system(), "machine": platform.machine()},
              "receiver_argv": command, "receiver_process": usage, "receiver_lock": str(lock),
              "path_mapping": {"target": {"original": declared["target"], "local": str(case)},
                               "request": {"original": declared["request"], "local": str(request_path)},
                               "assets": {k: {"original": original["assets"][k], "local": str(p), "sha256": pins[k]} for k, p in mapped_assets.items()},
                               "receiver": {"original_native": original["assets"].get("receiver"),
                                            "original_recursive": original["assets"].get("recursive_receiver"),
                                            "local": str(receiver), "sha256": pins["receiver"]},
                               "guest_input": source_assets},
              "producer_process": pending["producer_process"], "gpu": pending["gpu"], "physical_gpu_memory": pending["physical_gpu_memory"],
              "trials": trials, "artifacts_unchanged": True, "immutable_case_files": len(before),
              "artifact_snapshot_sha256": B.sha(output / "artifacts-before.json"),
              "gpu_disabled_environment": {"CUDA_VISIBLE_DEVICES": "", "STWO_RV64_GPU_PCS_HELPER": "/bin/false"},
              "qualification_scope": "One CPU-only strict receiver shares fresh native authority and restores every recursive node. Producer plan/request/proofs/logs are unchanged; no producer replay or invented warm trial."}
    B.atomic_json(output / "result.json", result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("plan", "case", "request", "driver", "library", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--block", type=int, required=True)
    parser.add_argument("--device-count", type=int, default=1)
    parser.add_argument("--receiver", type=Path, default=Path(ARM_RECEIVER))
    parser.add_argument("--receiver-sha256", default=ARM_SHA256)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--host-bytes", type=int, default=32 << 30)
    parser.add_argument("--lock", type=Path)
    args = parser.parse_args()
    result = qualify(args.plan, args.case, args.block, args.device_count, args.request, args.driver, args.library,
                     args.output, args.receiver, args.receiver_sha256, args.workers, args.host_bytes, args.lock)
    print(__import__("json").dumps({"accepted": True, "block": result["block"], "result": str(args.output / "result.json")}))


if __name__ == "__main__":
    main()
