"""Replay every proposed exact-count block segment through admission geometry.

This records sizing evidence only. It never labels the proposed schedule a proof.
"""
from pathlib import Path
import hashlib
import json
import subprocess
import sys
import time

H = Path(__file__).resolve().parent
R = H.parents[2]
sys.path.insert(0, str(R / "scripts"))

out = H / "exact-schedule-geometry-v1"
out.mkdir(exist_ok=False)
binary = H / "segment-geometry-exact"
schedule = H / "exact-schedule-proposal-v1/schedule.json"
inputs = [
    H / "ethereum-block-sha-default-v3.elf",
    H / "fixture/stwo-runner-input-evm-hints.bin",
    H / "fixture/expected-output.bin",
]
with (out / "build.log").open("x") as log:
    subprocess.run(
        [sys.executable, str(H / "build_stream_memory_lifetimes.py"),
         "--root", str(R / "src/frontends/riscv/ethereum_segment_geometry.zig"),
         "--output", str(binary)],
        cwd=R, stdout=log, stderr=subprocess.STDOUT, check=True,
    )
command = [str(binary), *(str(p) for p in inputs), "4194304", "all", str(schedule)]
start = time.monotonic()
with (out / "segments.jsonl").open("x") as stdout, (out / "stderr.log").open("x") as stderr:
    result = subprocess.run(command, cwd=R, stdout=stdout, stderr=stderr)
records = [json.loads(line) for line in (out / "segments.jsonl").read_text().splitlines()]
summary = records[-1] if records and records[-1].get("kind") == "summary" else None
expected = len(json.loads(schedule.read_text()))
complete = (result.returncode == 0 and summary is not None
            and summary["segments_checked"] == expected
            and len(records) == expected + 1
            and [r["target"] for r in records[:-1]] == list(range(expected)))
admitted = bool(complete and summary["all_commitment_traces_fit"]
                and max(summary["maximum_commitment_rows"]) <= 1 << 24)
report = {
    "scope": "all-segment admission geometry only; no native, recursive or complete-block proof",
    "command": command,
    "exit_code": result.returncode,
    "wall_seconds": time.monotonic() - start,
    "complete_geometry_scan": complete,
    "every_component_at_most_log24": admitted,
    "proof_verified": False,
    "summary": summary,
    "sha256": {str(p.relative_to(R)): hashlib.sha256(p.read_bytes()).hexdigest()
               for p in [binary, *inputs, schedule]},
}
(out / "qualification.json").write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps({k: report[k] for k in ("exit_code", "complete_geometry_scan", "every_component_at_most_log24", "wall_seconds")}))
if not complete:
    raise SystemExit(1)
