#!/usr/bin/env python3
"""Plan or run the pinned Ethereum basket through real producer/receiver CLIs.

Execution is opt-in. CPU and GPU use the same candidate CLI contract. A GPU
producer must supply device telemetry; a successful CPU fallback is rejected.
"""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import threading
import time

SCHEMA = "rv64-ethereum-basket-run/v1"
PROFILES = ("conjectured128_b2_q108_p20_fold4", "proven_beta2_q256_p0_fold4")


def load(path):
    return json.loads(Path(path).read_text())


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def atomic_json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


def absolute(value, root):
    path = Path(os.path.expandvars(value)).expanduser()
    return path.resolve() if path.is_absolute() else (root / path).resolve()


def command(driver, profile, mode, request, output, *tail):
    return [str(driver), "--security-profile", profile, mode,
            str(request), str(output), *map(str, tail)]


def measure(argv, directory, name, environment=None):
    """Per-child wait4 usage, never differences of shared process-wide counters."""
    start = time.monotonic_ns()
    with (directory / (name + ".stdout")).open("wb") as stdout, (directory / (name + ".stderr")).open("wb") as stderr:
        process = subprocess.Popen(argv, stdout=stdout, stderr=stderr, env=environment)
        _, status, usage = os.wait4(process.pid, 0)
        process.returncode = os.waitstatus_to_exitcode(status)
    result = {"argv": argv, "exit_code": process.returncode,
              "wall_ns": time.monotonic_ns() - start,
              "user_seconds": usage.ru_utime, "system_seconds": usage.ru_stime,
              "peak_rss_bytes": usage.ru_maxrss if platform.system() == "Darwin" else usage.ru_maxrss * 1024,
              "minor_faults": usage.ru_minflt, "major_faults": usage.ru_majflt}
    if process.returncode:
        error = RuntimeError(f"{name} failed ({process.returncode}); see {directory / (name + '.stderr')}")
        error.measurement = result
        raise error
    return result


class Admission:
    """A worker owns its byte credit until its child has joined and verified."""
    def __init__(self, workers, host_capacity=None):
        if not workers or any(type(w.get("capacity_bytes")) is not int or w["capacity_bytes"] <= 0 for w in workers):
            raise ValueError("workers require positive byte capacities")
        self.workers = workers
        self.live = [0] * len(workers)
        self.host = [0] * len(workers)
        self.host_capacity = host_capacity
        self.busy = [False] * len(workers)
        self.condition = threading.Condition()

    def acquire(self, amount, host=0):
        if amount <= 0 or not any(amount <= w["capacity_bytes"] for w in self.workers):
            raise ValueError("job does not fit any admitted worker")
        if host < 0 or (self.host_capacity is not None and host > self.host_capacity):
            raise ValueError("job exceeds admitted host memory")
        with self.condition:
            while True:
                for i, worker in enumerate(self.workers):
                    if not self.busy[i] and amount <= worker["capacity_bytes"] and (self.host_capacity is None or host <= self.host_capacity - sum(self.host)):
                        self.live[i], self.busy[i] = amount, True
                        self.host[i] = host
                        return i, worker
                self.condition.wait()

    def release(self, index):
        with self.condition:
            if not self.busy[index]:
                raise ValueError("retired worker credit")
            self.live[index], self.busy[index] = 0, False
            self.host[index] = 0
            self.condition.notify_all()


def job_for(block, entry, manifest, root, backend, output, profile):
    if entry is None:
        return {"block": block["block"], "set": block["set"], "ready": False, "missing": ["request/jobs manifest entry"]}
    request_path = absolute(entry["request"], root)
    direct = entry["jobs"] == "-"
    jobs = "-" if direct else absolute(entry["jobs"], root)
    missing = [str(path) for path in (request_path, *([] if direct else [jobs])) if not path.exists()]
    result = {"block": block["block"], "set": block["set"], "gas_used": block["gas_used"],
              "request": str(request_path), "jobs": str(jobs), "ready": False,
              "missing": missing, "profile": profile, "prefix_count": entry.get("prefix_count", 0)}
    if missing:
        return result
    request = load(request_path)
    for key in ("elf", "input"):
        path = absolute(request[key], request_path.parent)
        if not path.is_file():
            result["missing"].append(str(path))
        elif sha(path) != request[key + "_sha256"]:
            raise ValueError(f"block {block['block']}: {key} hash mismatch")
    if result["missing"]:
        return result
    if not request["expected_output"].lower().startswith(block["new_payload_request_root"][2:].lower()):
        raise ValueError("request output does not match the pinned basket block")
    resources = dict(manifest.get("resources", {}))
    resources.update(entry.get("resources", {}))
    if not resources.get("fixed_setup_bytes"):
        raise ValueError("candidate requires explicit fixed_setup_bytes")
    driver_name = backend + "_driver"
    if not manifest.get(driver_name):
        result["missing"].append(driver_name + " (GPU runtime must be integrated explicitly)")
        return result
    driver = absolute(manifest[driver_name], root)
    receiver = absolute(manifest.get("receiver", manifest.get("cpu_driver", "")), root)
    if not driver.is_file() or not receiver.is_file():
        result["missing"].append("producer/receiver executable")
        return result
    target = output / str(block["block"])
    result.update({"ready": True, "driver_sha256": sha(driver), "receiver_sha256": sha(receiver),
                   "request_sha256": sha(request_path), "resources": resources,
                   "resident_bytes": entry.get("resident_bytes"), "output": str(target),
                   "host_bytes": entry.get("host_bytes"),
                   "produce": command(driver, profile, "produce-candidate", request_path, jobs,
                                      target / "proof", result["prefix_count"], target / "resources.json"),
                   "verify": command(receiver, profile, "verify-prefix-candidate" if result["prefix_count"] else "verify-candidate",
                                     request_path, target / "proof", resources["fixed_setup_bytes"], manifest.get("receiver_bytes", 32 << 30))})
    if entry.get("reference_directory"):
        result["reference_directory"] = str(absolute(entry["reference_directory"], root))
    collection = None if direct else jobs.parent / "collection.json"
    if collection is not None and collection.is_file():
        value = load(collection)
        result["cached_capture"] = {"receipt_sha256": sha(collection), "instructions": value.get("instructions"), "segments": value.get("collected_batches"), "completed": value.get("completed")}
    if entry.get("historical_receipt"):
        path = absolute(entry["historical_receipt"], root)
        receipt = load(path)
        result["historical_control"] = {"sha256": sha(path), "scope": "Pinned earlier run, not a fresh baseline and not normalized across profiles", "receipt": receipt}
    return result


def gpu_diagnostics(path):
    """Actual backend evidence; GPU time is never inferred from process wall."""
    records = []
    for line in Path(path).read_text(errors="replace").splitlines():
        if not line.startswith(("GPU_GKR_SPANS ", "GPU_GKR ", "GPU_COMPOSITION_TIMING ", "GPU_PCS_NATIVE ", "GPU_CPU_PROJECTION ")):
            continue
        fields = {key: float(value) if "." in value else int(value)
                  for key, value in re.findall(r"(\w+)=([0-9]+(?:\.[0-9]+)?)", line)}
        records.append({"stage": line.split()[0], **fields})
    launches = sum(r.get("gkr_kernel_launches", 0) for r in records)
    device_ms = 0.0
    for r in records:
        if r["stage"] == "GPU_GKR_SPANS":
            device_ms += sum(value for key, value in r.items() if key.endswith("_ms"))
        elif r["stage"] == "GPU_COMPOSITION_TIMING":
            device_ms += r.get("gpu_enqueued_kernel_spans_ms", 0)
        elif r["stage"] == "GPU_PCS_NATIVE":
            device_ms += r.get("device_ns", 0) / 1e6
    return {"kernel_launches": launches, "device_ms": device_ms, "records": records,
            "launch_count_scope": "Source-derived GKR traversal only, not CUPTI; excludes other stages",
            "device_time_scope": "Summed GKR/composition CUDA-event spans and PCS resident time; includes enqueue gaps; excludes untimed stages and overlaps",
            "memory_scope": "Native logical counters; physical device peak is sampled separately"}


class DeviceMonitor:
    """Whole-device sampling, explicitly not process-exclusive allocation."""
    def __init__(self, devices):
        self.devices = {int(x) for x in str(devices).split(",")}
        self.stop = threading.Event()
        self.samples = []
        self.errors = []
        self.thread = threading.Thread(target=self.run, daemon=True)

    def run(self):
        while not self.stop.is_set():
            try:
                result = subprocess.run(["nvidia-smi", "--query-gpu=index,uuid,memory.used,utilization.gpu", "--format=csv,noheader,nounits"], capture_output=True, text=True, timeout=3, check=True)
                for line in result.stdout.splitlines():
                    index, uuid, memory, utilization = [part.strip() for part in line.split(",")]
                    if int(index) in self.devices:
                        self.samples.append({"device": int(index), "uuid": uuid, "memory_used_bytes": int(memory) * 1024 * 1024})
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                if not self.errors:
                    self.errors.append(str(error))
            self.stop.wait(.2)

    def finish(self):
        self.stop.set()
        self.thread.join()
        return {"scope": "Sampled whole-device usage, includes driver and unrelated processes; target interval 200ms, not exact process peak",
                "samples": len(self.samples), "errors": self.errors,
                "peak_used_bytes": {str(device): max((s["memory_used_bytes"] for s in self.samples if s["device"] == device), default=None) for device in sorted(self.devices)}}


def worker_environment(worker, environment):
    visible = str(worker["device"])
    devices = visible.split(",")
    if any(not value.isdecimal() for value in devices) or len({int(value) for value in devices}) != len(devices):
        raise ValueError("GPU groups require distinct nonnegative physical ordinals")
    mode = worker.get("mode", "resident")
    if mode == "host-retained":
        if len(devices) != 1 or type(worker.get("capacity_bytes")) is not int or worker["capacity_bytes"] <= 0:
            raise ValueError("host-retained hybrid requires one explicitly capped GPU")
        for key in ("STWO_RV64_GPU_DEVICES", "STWO_RV64_GPU_DEVICE_CAPS", "STWO_RV64_GPU_PLANNED_CPU_WORKERS",
                    "STWO_RV64_GPU_DEVICE_TRACE", "STWO_RV64_GPU_DEVICE_BINDING"):
            environment.pop(key, None)
        environment.update({"CUDA_VISIBLE_DEVICES": visible,
                            "STWO_RV64_GPU_HOST_RETAINED": "1",
                            "STWO_RV64_GPU_BYTE_CAP": str(worker["capacity_bytes"]),
                            "STWO_RV64_GPU_RETAINED_SCOPES": "2"})
        return environment
    if mode != "resident":
        raise ValueError("unknown GPU worker execution mode")
    environment.pop("STWO_RV64_GPU_HOST_RETAINED", None)
    caps = worker.get("device_caps_bytes", [])
    if (len(devices) not in (1, 2, 4) or len(caps) != len(devices)
            or any(type(cap) is not int or cap <= 0 for cap in caps)
            or type(worker.get("planned_cpu_workers")) is not int or worker["planned_cpu_workers"] <= 0
            or type(worker.get("retained_scopes")) is not int or worker["retained_scopes"] <= 0
            or worker["planned_cpu_workers"] > len(devices) * worker["retained_scopes"]):
        raise ValueError("GPU groups require 1/2/4 devices, explicit device_caps_bytes, planned_cpu_workers and sufficient retained_scopes")
    environment.update({"CUDA_VISIBLE_DEVICES": visible,
                        "STWO_RV64_GPU_DEVICES": ",".join(map(str, range(len(devices)))),
                        "STWO_RV64_GPU_PLANNED_CPU_WORKERS": str(worker["planned_cpu_workers"]),
                        "STWO_RV64_GPU_RETAINED_SCOPES": str(worker["retained_scopes"]),
                        "STWO_RV64_GPU_DEVICE_CAPS": ",".join(map(str, caps)),
                        "STWO_RV64_GPU_DEVICE_TRACE": "1", "STWO_RV64_GPU_DEVICE_BINDING": "1"})
    return environment


def execute(job, backend, admission, nsys=None):
    target = Path(job["output"])
    target.mkdir(parents=True, exist_ok=False)
    if "resources" in job:
        atomic_json(target / "resources.json", job["resources"])
    worker_index = None
    monitor = None
    physical_memory = None
    try:
        environment = os.environ.copy()
        worker = None
        if backend == "gpu":
            worker_index, worker = admission.acquire(job["resident_bytes"], job.get("host_bytes", 0))
            worker_environment(worker, environment)
            monitor = DeviceMonitor(worker["device"])
            monitor.thread.start()
        argv = job["produce"]
        if nsys:
            argv = [nsys, "profile", "--trace=cuda,nvtx,osrt", "--force-overwrite=false", "--stats=false", "--output=" + str(target / "nsight"), *argv]
        producer = measure(argv, target, "producer", environment)
        report = load(target / "proof/report.json")
        gpu = report.get("gpu")
        if backend == "gpu" and gpu is None:
            gpu = gpu_diagnostics(target / "producer.stderr")
        physical_memory = monitor.finish() if monitor else None
        monitor = None
        if backend == "gpu" and (not isinstance(gpu, dict) or gpu.get("kernel_launches", 0) <= 0 or gpu.get("device_ms", -1) < 0):
            raise ValueError("GPU producer did not report actual kernel launches/device time; CPU fallback rejected")
        receiver_usage = measure(job["verify"], target, "receiver")
        receiver = load(target / "receiver.stdout")
        complete = job["prefix_count"] == 0
        if receiver.get("accepted") is not True or receiver.get("completed_ethereum_block") is not complete:
            raise ValueError("fresh receiver did not accept the requested coverage")
        if complete and bytes(receiver["output"]).hex() != load(job["request"])["expected_output"]:
            raise ValueError("fresh receiver output differs from the pinned request")
        cells = report.get("native_cells")
        if cells is not None and (type(cells) is not int or cells <= 0 or not isinstance(report.get("cell_scope"), str) or not report["cell_scope"]):
            raise ValueError("native cell count requires a positive count and explicit cell_scope")
        proof = target / "proof"
        reference_parity = None
        if job.get("reference_directory"):
            reference = Path(job["reference_directory"])
            reference_report = load(reference / "report.json")
            for key in ("profile", "total_steps", "cpu_proofs", "truth_proofs"):
                if reference_report[key] != report[key]:
                    raise ValueError("reference context differs: " + key)
            reference_files = {p.name: sha(p) for p in reference.glob("*.bin")}
            actual_files = {p.name: sha(p) for p in proof.glob("*.bin")}
            if actual_files != reference_files or sha(proof / "bundle.json") != sha(reference / "bundle.json"):
                raise ValueError("native proof byte parity failed")
            reference_parity = True
        direct = report.get("capture_source") == "in_process_execution"
        stage_seconds = {}
        for path in proof.glob("physical-*.stages.json"):
            for stage in load(path)["stages"]:
                stage_seconds[stage["id"]] = stage_seconds.get(stage["id"], 0) + stage["seconds"]
        result = {"block": job["block"], "backend": backend, "profile": job["profile"], "fresh_receiver_accepted": True,
                  "completed_block": complete, "instructions": report["total_steps"], "segments": report["cpu_proofs"], "truth_proofs": report["truth_proofs"],
                  "capture_ns": report["capture_ns"], "setup_ns": report["setup_ns"], "prove_ns": report["prove_ns"],
                  "execution_included": direct, "direct_capture": report.get("direct_capture"),
                  "execution_note": "In-process execution included" if direct else "Prepared packet import is included; guest execution/job creation is a separate measurement",
                  "producer_process": producer, "receiver_process": receiver_usage, "worker": worker,
                  "native_cells": cells, "cell_scope": report.get("cell_scope"),
                  "prove_ns_per_native_cell": report["prove_ns"] / cells if cells else None,
                  "gpu_device_ns_per_native_cell": gpu["device_ms"] * 1000000 / cells if cells and gpu else None,
                  "native_reference_byte_parity": reference_parity,
                  "summed_worker_stage_seconds": stage_seconds,
                  "stage_scope": "Top-level stage elapsed summed over physical workers; overlaps are not block wall time",
                  "gpu": gpu, "physical_gpu_memory": physical_memory, "profiled": bool(nsys),
                  "memory_budgets": {"host_job_bytes": job.get("host_bytes"), "aggregate_gpu_job_credit_bytes": job.get("resident_bytes"),
                                     "per_device_gpu_caps_bytes": worker.get("device_caps_bytes") if worker else None},
                  "artifact_sha256": {p.name: sha(p) for p in proof.glob("*.bin")},
                  "bundle_sha256": sha(proof / "bundle.json"),
                  "report_sha256": sha(proof / "report.json")}
        atomic_json(target / "result.json", result)
        return result
    except Exception as error:
        if monitor:
            physical_memory = monitor.finish()
            monitor = None
        atomic_json(target / "failure.json", {"block": job["block"], "backend": backend, "error": str(error), "accepted": False,
                                              "failed_process": getattr(error, "measurement", None),
                                              "physical_gpu_memory": physical_memory if backend == "gpu" else None})
        raise
    finally:
        if monitor:
            monitor.finish()
        if worker_index is not None:
            admission.release(worker_index)


def ordered_blocks(blocks, selected, execution_order):
    if execution_order is None:
        return [block for block in blocks if block["block"] in selected]
    known = {block["block"] for block in blocks}
    if (any(type(value) is not int for value in execution_order)
            or len(set(execution_order)) != len(execution_order)
            or not set(execution_order) <= known or not selected <= set(execution_order)):
        raise ValueError("execution_order must name every selected block exactly once without unknown IDs")
    lookup = {block["block"]: block for block in blocks}
    return [lookup[number] for number in execution_order if number in selected]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--basket", type=Path, default=Path(__file__).resolve().parents[1] / "autoresearch/guest_efficiency/basket.json")
    p.add_argument("--manifest", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--backend", choices=["cpu", "gpu"], default="cpu")
    p.add_argument("--profile", choices=PROFILES, default=PROFILES[0])
    p.add_argument("--blocks", help="Comma-separated pinned block numbers; default is the complete basket")
    p.add_argument("--execute", action="store_true", help="Run producers; otherwise only validate inputs and write command plans")
    p.add_argument("--nsys", help="Nsight Systems executable; profiling overhead is labeled in results")
    args = p.parse_args()
    manifest = load(args.manifest)
    if manifest.get("schema") != "rv64-ethereum-basket-inputs/v1":
        p.error("unsupported manifest schema")
    basket = load(args.basket)
    selected = set(map(int, args.blocks.split(","))) if args.blocks else {b["block"] for b in basket["blocks"]}
    known = {b["block"] for b in basket["blocks"]}
    if not selected <= known:
        p.error("block selection contains an entry outside the pinned basket")
    args.output.mkdir(parents=True, exist_ok=True)
    jobs = [job_for(block, manifest.get("blocks", {}).get(str(block["block"])), manifest, args.manifest.resolve().parent, args.backend, args.output.resolve(), args.profile)
            for block in ordered_blocks(basket["blocks"], selected, manifest.get("execution_order"))]
    plan = {"schema": SCHEMA, "basket_sha256": sha(args.basket), "manifest_sha256": sha(args.manifest), "backend": args.backend,
            "profile": args.profile, "executed": False, "jobs": jobs}
    atomic_json(args.output / "plan.json", plan)
    if not args.execute:
        print(json.dumps({"plan": str(args.output / "plan.json"), "ready": sum(j["ready"] for j in jobs), "selected": len(jobs), "executed": False}))
        return
    if not all(job["ready"] for job in jobs):
        p.error("input/driver inventory is incomplete; see plan.json")
    workers = manifest.get("gpu_workers", []) if args.backend == "gpu" else [{"device": None, "capacity_bytes": 1}]
    if not workers or len({w["device"] for w in workers}) != len(workers):
        p.error("GPU workers require distinct admitted device ordinals")
    if args.backend == "gpu" and (type(manifest.get("host_capacity_bytes")) is not int or manifest["host_capacity_bytes"] <= 0 or any(type(j["resident_bytes"]) is not int or j["resident_bytes"] <= 0 or type(j["host_bytes"]) is not int or j["host_bytes"] <= 0 for j in jobs)):
        p.error("GPU jobs require positive resident_bytes, host_bytes and fleet host_capacity_bytes admission")
    if args.backend == "gpu":
        physical = []
        try:
            for worker in workers:
                worker_environment(worker, {})
                physical.extend(str(worker["device"]).split(","))
        except ValueError as error:
            p.error(str(error))
        if len(set(physical)) != len(physical):
            p.error("concurrent GPU groups must not overlap physical devices")
    admission = Admission(workers, manifest.get("host_capacity_bytes") if args.backend == "gpu" else None)
    start = time.monotonic_ns()
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(workers)) as pool:
        futures = {pool.submit(execute, job, args.backend, admission, args.nsys): job["block"] for job in jobs}
        results = [future.result() for future in concurrent.futures.as_completed(futures)]
    plan.update({"executed": True, "wall_ns": time.monotonic_ns() - start, "results": sorted(results, key=lambda x: x["block"])})
    atomic_json(args.output / "result.json", plan)
    print(json.dumps({"result": str(args.output / "result.json"), "accepted": len(results)}))


if __name__ == "__main__":
    main()
