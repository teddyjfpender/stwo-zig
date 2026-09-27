"""Prove the work-balanced 256-leaf mainnet schedule's terminal leaf."""
from pathlib import Path
import hashlib
import json
import subprocess
import sys
import time

H = Path(__file__).resolve().parent
R = H.parents[2]
sys.path.insert(0, str(R / "scripts"))
from zig_serial_build import build_lock

segment = int(sys.argv[1]) if len(sys.argv) > 1 else 255
if not 0 <= segment < 256:
    raise ValueError("segment must be in the 256-leaf schedule")
out = H / ("terminal-256-proof-v1" if segment == 255 else f"segment-{segment}-256-proof-v1")
out.mkdir(exist_ok=False)
binary = R / "zig-out/bin/stwo-ethereum-block-stream"
elf = H / "ethereum-block-sha-default-v3.elf"
input_path = H / "fixture/stwo-runner-input-evm-hints.bin"
oracle = H / "fixture/expected-output.bin"
schedule = H / "work-schedule-qualification-v1/schedule-256.json"
report = out / "report.json"
command = [str(binary), str(elf), str(input_path), str(oracle), "4194304", str(out / "selected.proof"), str(report), "canonical", f"segment={segment}", "schedule=" + str(schedule)]
start = time.monotonic()
with build_lock(label="terminal-256-full-custody-proof"):
    with (out / "prove.log").open("x") as log:
        result = subprocess.run(command, cwd=R, stdout=log, stderr=subprocess.STDOUT)
record = {"scope": "selected terminal execution leaf and full-custody recursive wrapper; excludes other 255 leaves, aggregation and complete block", "command": command, "wall_seconds": time.monotonic() - start, "exit_code": result.returncode, "proof_verified": result.returncode == 0, "sha256": {str(path.relative_to(R)): hashlib.sha256(path.read_bytes()).hexdigest() for path in (binary, elf, input_path, oracle, schedule)}}
if report.exists():
    record["report"] = json.loads(report.read_text())
    record["sha256"][str(report.relative_to(R))] = hashlib.sha256(report.read_bytes()).hexdigest()
(out / "qualification.json").write_text(json.dumps(record, indent=2) + "\n")
if result.returncode:
    raise RuntimeError("terminal leaf proof failed; see prove.log")
assert record["report"]["segment_recursive_proof_verified"] and record["report"]["segment_index"] == segment
print(f"segment {segment} of 256-leaf schedule proved", flush=True)
