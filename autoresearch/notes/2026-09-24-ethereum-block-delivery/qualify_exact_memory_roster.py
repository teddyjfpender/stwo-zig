"""Replay the proposed exact block schedule and record its real memory roster.

This is a host-only sizing pass. It never turns the roster into proof authority.
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

out = H / "exact-schedule-memory-roster-v1"
out.mkdir(exist_ok=False)
binary = H / "block-memory-roster-exact"
schedule = H / "exact-schedule-proposal-v1/schedule.json"
inputs = [
    H / "ethereum-block-sha-default-v3.elf",
    H / "fixture/stwo-runner-input-evm-hints.bin",
    H / "fixture/expected-output.bin",
]
with (out / "build.log").open("x") as log:
    subprocess.run(
        [sys.executable, str(H / "build_stream_memory_lifetimes.py"),
         "--root", str(R / "src/frontends/riscv/ethereum_block_memory_roster.zig"),
         "--output", str(binary)],
        cwd=R, stdout=log, stderr=subprocess.STDOUT, check=True,
    )
roster = out / "first-touch.bin"
initial_roster = out / "first-touch.bin.initial-nonzero.bin"
report = out / "roster.json"
command = [str(binary), *(str(p) for p in inputs), "4194304",
           str(roster), str(report), str(schedule)]
start = time.monotonic()
with (out / "stdout.log").open("x") as stdout, (out / "stderr.log").open("x") as stderr:
    result = subprocess.run(command, cwd=R, stdout=stdout, stderr=stderr)
summary = json.loads(report.read_text()) if report.exists() else None
expected = len(json.loads(schedule.read_text()))
complete = bool(result.returncode == 0 and summary is not None
                and summary["segments"] == expected
                and summary["cycles"] > 0
                and roster.exists() and initial_roster.exists()
                and summary["first_touch_keys"] * 10 == roster.stat().st_size
                and summary["initial_snapshot_nonzero_rw_words"] * 8 == initial_roster.stat().st_size
                and summary["roster_sha256"] == hashlib.sha256(roster.read_bytes()).hexdigest()
                and summary["initial_snapshot_nonzero_rw_roster_sha256"]
                == hashlib.sha256(initial_roster.read_bytes()).hexdigest())
qualification = {
    "scope": "host-only sorted memory/initial snapshot census; no STARK proof",
    "command": command,
    "exit_code": result.returncode,
    "wall_seconds": time.monotonic() - start,
    "complete_roster_scan": complete,
    "proof_verified": False,
    "summary": summary,
    "sha256": {str(p.relative_to(R)): hashlib.sha256(p.read_bytes()).hexdigest()
               for p in [binary, *inputs, schedule,
                         *([roster] if roster.exists() else []),
                         *([initial_roster] if initial_roster.exists() else [])]},
}
(out / "qualification.json").write_text(json.dumps(qualification, indent=2) + "\n")
print(json.dumps({k: qualification[k] for k in
                  ("exit_code", "complete_roster_scan", "wall_seconds")}))
if not complete:
    raise SystemExit(1)
