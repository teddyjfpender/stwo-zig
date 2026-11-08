#!/usr/bin/env python3
"""Scheduling sweep for the Word16 RV64 Ethereum driver (operational only).

Runs `<driver> produce` once per (config, run), each under the shared heavy
lock and `/usr/bin/time -l`, checks byte identity of every output named in a
sha256 file, optionally runs a fresh receiver, and writes one JSON receipt with
wall/user/sys/faults/peak footprint plus per-stage and per-lane CPU taken from
physical-*.stages.json and schedule.json.

Run with `python3 -I`. Standard library only.

Config syntax (repeat --config, or pass --configs-json with a list of objects):
  label=l2x8,request_workers=16
  label=l4x4,proof_jobs=4,request_workers=16
  label=l3,lane_workers=6:6:4,memory_cap=24G,request_workers=18
Keys: label (required), request_workers (int, rewrites the request copy),
proof_jobs (1..4), lane_workers (colon list), memory_cap (bytes; K/M/G
suffixes are binary), extra (raw driver option, may repeat with ';').
"""
import argparse
import datetime
import hashlib
import json
import os
import platform
import re
import shutil
import statistics
import subprocess
import sys
import time

TIME_FIELDS = {
    "maximum resident set size": "max_rss_bytes",
    "page reclaims": "minor_faults",
    "page faults": "major_faults",
    "voluntary context switches": "voluntary_switches",
    "involuntary context switches": "involuntary_switches",
    "instructions retired": "instructions_retired",
    "cycles elapsed": "cycles_elapsed",
    "peak memory footprint": "peak_footprint_bytes",
}
SUFFIX = {"": 1, "K": 1 << 10, "M": 1 << 20, "G": 1 << 30, "T": 1 << 40}


def parse_bytes(text):
    m = re.fullmatch(r"(\d+)([KMGT]?)(?:i?B)?", text.strip(), re.IGNORECASE)
    if not m:
        raise ValueError(f"invalid byte size {text!r}")
    return int(m.group(1)) * SUFFIX[m.group(2).upper()]


def parse_config(spec):
    cfg = {}
    for part in spec.split(","):
        if not part:
            continue
        if "=" not in part:
            raise ValueError(f"config item {part!r} lacks '='")
        key, value = part.split("=", 1)
        cfg[key.strip()] = value.strip()
    return normalize_config(cfg)


def normalize_config(cfg):
    out = {"label": str(cfg.get("label") or "").strip()}
    if not out["label"] or not re.fullmatch(r"[A-Za-z0-9_.-]+", out["label"]):
        raise ValueError(f"config needs a filesystem-safe label: {cfg!r}")
    if cfg.get("request_workers") not in (None, ""):
        out["request_workers"] = int(cfg["request_workers"])
        if not 1 <= out["request_workers"] <= 32:
            raise ValueError("request_workers must be 1..32")
    if cfg.get("proof_jobs") not in (None, ""):
        out["proof_jobs"] = int(cfg["proof_jobs"])
        if not 1 <= out["proof_jobs"] <= 4:
            raise ValueError("proof_jobs must be 1..4")
    lw = cfg.get("lane_workers")
    if lw not in (None, "", []):
        values = lw if isinstance(lw, list) else [v for v in str(lw).replace(":", " ").split()]
        out["lane_workers"] = [int(v) for v in values]
        if not 1 <= len(out["lane_workers"]) <= 4 or sum(out["lane_workers"]) > 32 or min(out["lane_workers"]) < 1:
            raise ValueError("lane_workers needs 1..4 positive entries summing to <= 32")
    cap = cfg.get("memory_cap")
    if cap not in (None, "", 0, "0"):
        out["memory_cap"] = cap if isinstance(cap, int) else parse_bytes(str(cap))
    extra = cfg.get("extra")
    if extra:
        out["extra"] = extra if isinstance(extra, list) else [e for e in str(extra).split(";") if e]
    return out


def driver_options(cfg):
    opts = []
    if "proof_jobs" in cfg:
        opts.append(f"--proof-jobs={cfg['proof_jobs']}")
    if "lane_workers" in cfg:
        opts.append("--lane-workers=" + ",".join(str(v) for v in cfg["lane_workers"]))
    if "memory_cap" in cfg:
        opts.append(f"--proof-memory-cap={cfg['memory_cap']}")
    opts.extend(cfg.get("extra", []))
    return opts


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_expected(path):
    expected = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            digest, name = line.split(None, 1)
            name = name.lstrip("*").strip()
            if os.path.basename(name) != name:
                raise ValueError(f"expected flat file names in {path}: {name!r}")
            if expected.get(name, digest) != digest:
                raise ValueError(f"conflicting digests for {name} in {path}")
            expected[name] = digest
    if not expected:
        raise ValueError(f"no digests in {path}")
    return expected


def parse_time(text):
    out = {}
    m = re.search(r"([\d.]+)\s+real\s+([\d.]+)\s+user\s+([\d.]+)\s+sys", text)
    if m:
        out["wall_seconds"], out["user_seconds"], out["sys_seconds"] = (float(v) for v in m.groups())
    for line in text.splitlines():
        m = re.match(r"\s*(\d+)\s+(.+?)\s*$", line)
        if m and m.group(2) in TIME_FIELDS:
            out[TIME_FIELDS[m.group(2)]] = int(m.group(1))
    return out


def walk(nodes, prefix, depth, max_depth, sink):
    for node in nodes or []:
        key = f"{prefix}/{node['id']}" if prefix else node["id"]
        usage = node.get("process_usage") or {}
        row = sink.setdefault(key, {"seconds": 0.0, "proofs": 0, "lane_user_seconds": 0.0, "lane_system_seconds": 0.0, "lane_samples": 0, "process_user_seconds": 0.0, "process_system_seconds": 0.0, "minor_faults": 0, "major_faults": 0, "max_resident_bytes_at_end": 0, "max_footprint_bytes_at_end": 0})
        row["seconds"] += float(node.get("seconds") or 0)
        row["proofs"] += 1
        if usage.get("lane_user_seconds") is not None:
            row["lane_user_seconds"] += usage["lane_user_seconds"]
            row["lane_system_seconds"] += usage.get("lane_system_seconds") or 0
            row["lane_samples"] += 1
        row["process_user_seconds"] += usage.get("user_seconds") or 0
        row["process_system_seconds"] += usage.get("system_seconds") or 0
        row["minor_faults"] += usage.get("minor_faults") or 0
        row["major_faults"] += usage.get("major_faults") or 0
        row["max_resident_bytes_at_end"] = max(row["max_resident_bytes_at_end"], usage.get("process_resident_bytes_at_end") or 0)
        row["max_footprint_bytes_at_end"] = max(row["max_footprint_bytes_at_end"], usage.get("process_footprint_bytes_at_end") or 0)
        if depth + 1 < max_depth:
            walk(node.get("children"), key, depth + 1, max_depth, sink)


def stage_summary(out_dir, max_depth):
    stages, proofs = {}, []
    for name in sorted(os.listdir(out_dir)):
        if not re.fullmatch(r"physical-\d{4}\.stages\.json", name):
            continue
        with open(os.path.join(out_dir, name)) as f:
            doc = json.load(f)
        per = {}
        walk(doc.get("stages"), "", 0, 1, per)
        proofs.append({"file": name, "top_level": {k: {"seconds": round(v["seconds"], 6), "lane_user_seconds": round(v["lane_user_seconds"], 6) if v["lane_samples"] else None, "lane_system_seconds": round(v["lane_system_seconds"], 6) if v["lane_samples"] else None} for k, v in per.items()}})
        walk(doc.get("stages"), "", 0, max_depth, stages)
    for row in stages.values():
        for k, v in list(row.items()):
            if isinstance(v, float):
                row[k] = round(v, 6)
        if not row["lane_samples"]:
            row["lane_user_seconds"] = row["lane_system_seconds"] = None
    return {"note": "seconds and lane_* CPU are additive across proofs; process_* counters are whole-process and overlap between concurrent lanes, so they are not additive", "by_stage": stages, "per_proof": proofs}


def schedule_summary(out_dir):
    path = os.path.join(out_dir, "schedule.json")
    if not os.path.exists(path):
        return None
    with open(path) as f:
        doc = json.load(f)
    out = {"policy": doc.get("policy")}
    for phase in ("stage1", "stage2"):
        rows = doc.get(phase) or []
        if not rows:
            continue
        lanes = {}
        for index, r in enumerate(rows):
            lane = lanes.setdefault(str(r["lane"]), {"indices": [], "busy_seconds": 0.0, "admission_wait_seconds": 0.0})
            lane["indices"].append(index)
            lane["busy_seconds"] += (r["finished_ns"] - r["started_ns"]) / 1e9
            lane["admission_wait_seconds"] += (r["started_ns"] - r["claimed_ns"]) / 1e9
        span = max(r["finished_ns"] for r in rows) / 1e9
        out[phase] = {"span_seconds": round(span, 6), "max_in_flight_estimate_bytes": max(r["in_flight_bytes_at_start"] for r in rows), "lanes": {k: {**v, "busy_seconds": round(v["busy_seconds"], 6), "admission_wait_seconds": round(v["admission_wait_seconds"], 6)} for k, v in lanes.items()}}
    return out


def git_head(path):
    try:
        return subprocess.run(["git", "-C", path, "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def aggregate(runs):
    keys = ["wall_seconds", "user_seconds", "sys_seconds", "minor_faults", "major_faults", "peak_footprint_bytes", "max_rss_bytes", "involuntary_switches", "prove_seconds"]
    out = {}
    for key in keys:
        values = [r["process"].get(key) for r in runs if r["process"].get(key) is not None]
        if values:
            out[key] = {"median": statistics.median(values), "min": min(values), "max": max(values), "n": len(values)}
    stage_keys = set()
    for r in runs:
        stage_keys.update((r.get("stages") or {}).get("by_stage", {}).keys())
    per_stage = {}
    for key in sorted(stage_keys):
        rows = [r["stages"]["by_stage"][key] for r in runs if key in (r.get("stages") or {}).get("by_stage", {})]
        entry = {"seconds_median": statistics.median(x["seconds"] for x in rows)}
        lane = [x["lane_user_seconds"] + (x["lane_system_seconds"] or 0) for x in rows if x["lane_user_seconds"] is not None]
        if lane:
            entry["lane_cpu_seconds_median"] = statistics.median(lane)
        per_stage[key] = entry
    out["stages"] = per_stage
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--driver", required=True)
    ap.add_argument("--request", required=True, help="base request.json (copied per request_workers)")
    ap.add_argument("--jobs", required=True, help="native jobs directory")
    ap.add_argument("--sha256", required=True, help="expected digests (sha256sum format)")
    ap.add_argument("--out-root", required=True, help="new directory for run outputs and request copies")
    ap.add_argument("--receipt", required=True)
    ap.add_argument("--count", type=int, default=4, help="CPU proof prefix; 0 = complete block")
    ap.add_argument("--runs", type=int, default=1)
    ap.add_argument("--config", action="append", default=[])
    ap.add_argument("--configs-json")
    ap.add_argument("--order", choices=["interleaved", "grouped"], default="interleaved", help="interleaved runs config A,B,..,A,B to spread machine noise")
    ap.add_argument("--heavy-lock", default="/private/tmp/stwo-rv64-perf-heavy.lock")
    ap.add_argument("--verify", choices=["none", "first", "all"], default="first", help="fresh receiver: none, first run per config, or every run")
    ap.add_argument("--keep-outputs", action="store_true", help="keep proof directories (default deletes each after hashing and verification)")
    ap.add_argument("--stage-depth", type=int, default=2)
    ap.add_argument("--timeout", type=int, default=3600)
    args = ap.parse_args()

    configs = [parse_config(c) for c in args.config]
    if args.configs_json:
        with open(args.configs_json) as f:
            configs.extend(normalize_config(c) for c in json.load(f))
    if not configs:
        ap.error("no configs")
    labels = [c["label"] for c in configs]
    if len(set(labels)) != len(labels):
        ap.error("duplicate config labels")
    if args.runs < 1 or args.count < 0:
        ap.error("runs >= 1 and count >= 0 required")
    for tool in ("/usr/bin/time", shutil.which("lockf") or ""):
        if not tool or not os.access(tool, os.X_OK):
            sys.exit(f"missing tool: {tool or 'lockf'}")
    driver = os.path.abspath(args.driver)
    expected = load_expected(args.sha256)
    os.makedirs(args.out_root, exist_ok=False)
    with open(args.request) as f:
        base_request = json.load(f)

    request_paths = {}

    def request_for(cfg):
        workers = cfg.get("request_workers")
        if workers is None:
            return os.path.abspath(args.request)
        if workers not in request_paths:
            req = dict(base_request)
            req["workers"] = workers
            path = os.path.join(args.out_root, f"request-w{workers}.json")
            with open(path, "w") as f:
                json.dump(req, f, indent=2)
            request_paths[workers] = path
        return request_paths[workers]

    schedule = [(cfg, run) for run in range(args.runs) for cfg in configs] if args.order == "interleaved" else [(cfg, run) for cfg in configs for run in range(args.runs)]
    receipt = {
        "schema": 1,
        "scope": "operational scheduling sweep; proof bytes must be identical to the expected digests for every run",
        "started": datetime.datetime.now().isoformat(timespec="seconds"),
        "host": {"platform": platform.platform(), "machine": platform.machine(), "cpu_count": os.cpu_count()},
        "driver": driver,
        "driver_sha256": sha256_file(driver),
        "driver_repo_head": git_head(os.path.dirname(driver)),
        "request": os.path.abspath(args.request),
        "jobs": os.path.abspath(args.jobs),
        "count": args.count,
        "runs_per_config": args.runs,
        "order": args.order,
        "expected_sha256_file": os.path.abspath(args.sha256),
        "expected": expected,
        "configs": configs,
        "runs": [],
    }

    def save():
        tmp = args.receipt + ".tmp"
        with open(tmp, "w") as f:
            json.dump(receipt, f, indent=2)
        os.replace(tmp, args.receipt)

    verified_once = set()
    for cfg, run in schedule:
        out_dir = os.path.join(args.out_root, f"{cfg['label']}-r{run}")
        cmd = ["lockf", "-k", args.heavy_lock, "/usr/bin/time", "-l", driver, "produce", request_for(cfg), os.path.abspath(args.jobs), out_dir, str(args.count)] + driver_options(cfg)
        record = {"label": cfg["label"], "run": run, "out_dir": out_dir, "command": cmd}
        print(f"[sweep] {cfg['label']} run {run}: {' '.join(cmd[5:])}", file=sys.stderr, flush=True)
        started = time.time()
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=args.timeout)
            record["exit_code"] = proc.returncode
            stderr = proc.stderr
        except subprocess.TimeoutExpired as e:
            record["exit_code"] = None
            record["error"] = f"timeout after {args.timeout}s"
            stderr = (e.stderr or b"").decode() if isinstance(e.stderr, bytes) else (e.stderr or "")
        record["outer_wall_seconds"] = round(time.time() - started, 3)
        with open(out_dir + ".time.txt", "w") as f:
            f.write(stderr)
        record["process"] = parse_time(stderr)
        report_path = os.path.join(out_dir, "report.json")
        if os.path.exists(report_path):
            with open(report_path) as f:
                report = json.load(f)
            record["process"]["prove_seconds"] = report.get("prove_ns", 0) / 1e9
            record["report"] = {k: report.get(k) for k in ("coordinator_schedule", "capture_ns", "setup_ns", "prove_ns", "same_process_verify_ns", "total_before_report_ns", "cpu_proofs", "truth_proofs")}
        if record.get("exit_code") == 0:
            digests, mismatches = {}, []
            for name, want in expected.items():
                path = os.path.join(out_dir, name)
                got = sha256_file(path) if os.path.exists(path) else None
                digests[name] = got
                if got != want:
                    mismatches.append(name)
            record["identical"] = not mismatches
            record["mismatches"] = mismatches
            record["stages"] = stage_summary(out_dir, args.stage_depth)
            record["schedule"] = schedule_summary(out_dir)
            if args.verify == "all" or (args.verify == "first" and cfg["label"] not in verified_once):
                mode = "verify" if args.count == 0 else "verify-prefix"
                vproc = subprocess.run(["lockf", "-k", args.heavy_lock, driver, mode, os.path.abspath(args.request), out_dir], capture_output=True, text=True, timeout=args.timeout)
                try:
                    accepted = vproc.returncode == 0 and json.loads(vproc.stdout).get("accepted") is True
                except ValueError:
                    accepted = False
                record["fresh_verify"] = {"mode": mode, "exit_code": vproc.returncode, "accepted": accepted}
                if not accepted:
                    record["fresh_verify"]["stderr_tail"] = vproc.stderr[-2000:]
                verified_once.add(cfg["label"])
        else:
            record["identical"] = False
            record["stderr_tail"] = stderr[-4000:]
        if not args.keep_outputs and os.path.isdir(out_dir):
            shutil.rmtree(out_dir)
            record["outputs_deleted"] = True
        receipt["runs"].append(record)
        save()
        print(f"[sweep] {cfg['label']} run {run}: exit={record.get('exit_code')} identical={record['identical']} wall={record['process'].get('wall_seconds')} user={record['process'].get('user_seconds')} footprint={record['process'].get('peak_footprint_bytes')}", file=sys.stderr, flush=True)

    receipt["summary"] = {}
    for cfg in configs:
        runs = [r for r in receipt["runs"] if r["label"] == cfg["label"]]
        good = [r for r in runs if r.get("exit_code") == 0]
        receipt["summary"][cfg["label"]] = {
            "runs": len(runs),
            "succeeded": len(good),
            "all_identical": bool(runs) and all(r.get("identical") for r in runs),
            "fresh_verify_accepted": [r["fresh_verify"]["accepted"] for r in runs if "fresh_verify" in r],
            **aggregate(good),
        }
    receipt["all_identical"] = all(r.get("identical") for r in receipt["runs"])
    receipt["all_verified"] = all(r["fresh_verify"]["accepted"] for r in receipt["runs"] if "fresh_verify" in r)
    receipt["finished"] = datetime.datetime.now().isoformat(timespec="seconds")
    save()
    print(json.dumps({"receipt": os.path.abspath(args.receipt), "all_identical": receipt["all_identical"], "all_verified": receipt["all_verified"]}))
    return 0 if receipt["all_identical"] and receipt["all_verified"] else 1


if __name__ == "__main__":
    sys.exit(main())
