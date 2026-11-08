#!/usr/bin/env python3
"""Run the RV64 GKR `block_to_inputs` phase report over a list of blocks.

Each block entry names a request JSON (pinned ELF/input) and a native jobs
directory (from `rv64-ethereum-proof nativeprepare`, optionally run here with
`--prepare-bin` when the directory is missing). Per block this runs, through
memguard, either `inputs-candidate` (default: setup + every worker's source
build, no proof; a few GB) or `produce-candidate` (`--mode produce`: the full
proof, reporting the same phases from inside the scheduled prove), and
collects `block_to_inputs` (T_first, T_all and per-stage times).

`--setup-cache DIR` sets STWO_ZIG_RV64_SETUP_CACHE (phase P1). `--repeat N`
runs each block N times in a row, so with a cache run 1 is cold and the rest
are warm. Observation only: nothing here selects protocol or proof authority.

blocks file (JSON): {"blocks": [{"name": "24628607", "request": "/abs/request.json",
                    "jobs": "/abs/jobs", "prefix": 0}, ...]}
Paths are resolved relative to the blocks file.

Example:
  python3 -I scripts/rv64_block_to_inputs.py --bin BIN --blocks blocks.json \\
      --resources resources.json --out ~/Coding/ge-cache/me/b2i --setup-cache ~/Coding/ge-cache/me/setup
"""
import argparse
import json
import os
import subprocess
import sys
import time

MEMGUARD = os.path.expanduser("~/Coding/ge-ops/bin/memguard")


def resolve(base, path):
    path = os.path.expanduser(path)
    return path if os.path.isabs(path) else os.path.normpath(os.path.join(base, path))


def run(cmd, env, log_path, gb, label):
    full = [MEMGUARD, "run", "--gb", str(gb), "--label", label, "--"] + cmd if os.path.exists(MEMGUARD) else cmd
    with open(log_path, "w") as log:
        start = time.monotonic()
        rc = subprocess.run(full, env=env, stdout=subprocess.PIPE, stderr=log).returncode
    return rc, time.monotonic() - start


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--bin", required=True, help="rv64-word16-ethereum-gkr binary")
    p.add_argument("--blocks", required=True)
    p.add_argument("--resources", required=True, help="candidate resources JSON (fixed_setup_bytes, schedule, ...)")
    p.add_argument("--out", required=True)
    p.add_argument("--mode", choices=["inputs", "produce"], default="inputs")
    p.add_argument("--setup-cache", default=None)
    p.add_argument("--repeat", type=int, default=1)
    p.add_argument("--gb", type=int, default=None, help="memguard reservation (default 10 inputs / 22 produce)")
    p.add_argument("--prepare-bin", default=None, help="rv64-ethereum-proof, to run nativeprepare for missing jobs")
    p.add_argument("--security-profile", default=None)
    a = p.parse_args()

    blocks_path = os.path.abspath(a.blocks)
    base = os.path.dirname(blocks_path)
    blocks = json.load(open(blocks_path))["blocks"]
    out = os.path.abspath(os.path.expanduser(a.out))
    os.makedirs(out, exist_ok=True)
    gb = a.gb or (10 if a.mode == "inputs" else 22)
    env = dict(os.environ)
    if a.setup_cache:
        env["STWO_ZIG_RV64_SETUP_CACHE"] = os.path.abspath(os.path.expanduser(a.setup_cache))
    rows = []
    for block in blocks:
        name = str(block["name"])
        request = resolve(base, block["request"])
        jobs = resolve(base, block["jobs"])
        prefix = str(block.get("prefix", 0))
        if not os.path.isdir(jobs):
            if not a.prepare_bin:
                print(f"{name}: missing jobs {jobs} (pass --prepare-bin)", file=sys.stderr)
                rows.append({"block": name, "error": "missing jobs"})
                continue
            rc, wall = run([a.prepare_bin, "nativeprepare", request], env, os.path.join(out, f"{name}.prepare.log"), 8, f"b2i-prep-{name}")
            rows.append({"block": name, "stage": "nativeprepare", "rc": rc, "wall_s": round(wall, 3)})
            if rc != 0:
                continue
        for i in range(a.repeat):
            tag = f"{name}.{i}"
            prof = ["--security-profile", a.security_profile] if a.security_profile else []
            if a.mode == "inputs":
                cmd = [a.bin] + prof + ["inputs-candidate", request, jobs, prefix, a.resources]
            else:
                bundle = os.path.join(out, f"{tag}.bundle")
                subprocess.run(["rm", "-rf", bundle])
                cmd = [a.bin] + prof + ["produce-candidate", request, jobs, bundle, prefix, a.resources]
            log = os.path.join(out, f"{tag}.log")
            full = [MEMGUARD, "run", "--gb", str(gb), "--label", f"b2i-{tag}", "--"] + cmd
            start = time.monotonic()
            proc = subprocess.run(full, env=env, stdout=subprocess.PIPE, stderr=open(log, "w"))
            wall = time.monotonic() - start
            row = {"block": name, "run": i, "rc": proc.returncode, "process_wall_s": round(wall, 3)}
            try:
                if a.mode == "inputs":
                    report = json.loads(proc.stdout)
                else:
                    report = json.load(open(os.path.join(bundle, "report.json")))
                with open(os.path.join(out, f"{tag}.report.json"), "w") as f:
                    json.dump(report, f, indent=1)
                b = report["block_to_inputs"]
                with open(os.path.join(out, f"{tag}.block_to_inputs.json"), "w") as f:
                    json.dump(b, f, indent=1)
                row.update({
                    "t_first_s": b["t_first_ns"] / 1e9,
                    "t_all_cpu_s": b["t_all_cpu_ns"] / 1e9,
                    "t_all_s": b["t_all_ns"] / 1e9,
                    **{k.replace("_ns", "_s"): v / 1e9 for k, v in b["stages"].items()},
                    "segments": len(b["segments"]),
                    "setup_cache": b.get("setup_cache"),
                })
                if report.get("resident_next_block_setup_ns") is not None:
                    row["resident_next_block_setup_s"] = report["resident_next_block_setup_ns"] / 1e9
            except Exception as e:  # report what failed; never hide an rc
                row["error"] = repr(e)
            rows.append(row)
            print(json.dumps({k: (round(v, 3) if isinstance(v, float) else v) for k, v in row.items() if k != "setup_cache"}))
    json.dump({"mode": a.mode, "bin": a.bin, "setup_cache": a.setup_cache, "rows": rows}, open(os.path.join(out, "summary.json"), "w"), indent=1)


if __name__ == "__main__":
    main()
