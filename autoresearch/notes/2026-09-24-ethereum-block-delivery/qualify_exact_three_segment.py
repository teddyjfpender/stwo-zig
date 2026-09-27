"""Canonical three-segment exact-forest and memory-witness qualification."""
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

out = H / "exact-three-segment-v1"
out.mkdir(exist_ok=False)
fixture = json.loads((H / "measurements-auth1-canonical-stages/measurement.json").read_text())
elf, input_path, oracle = map(Path, fixture["command"][3:6])
binary = R / "zig-out/bin/stwo-ethereum-block-stream"
receiver = R / "zig-out/bin/stwo-ethereum-block-exact-verify"
schedule = out / "schedule.json"
schedule.write_text("[7000,7000,7635]\n")
bundle = out / "forest.json"
report = out / "report.json"
command = [str(binary), str(elf), str(input_path), str(oracle), "16384", str(bundle), str(report), "canonical", "paired", "exact", "memory-witness", "schedule=" + str(schedule)]
start = time.monotonic()
with build_lock(label="exact-three-segment-qualification"):
    with (out / "prove.log").open("x") as log:
        result = subprocess.run(command, cwd=R, stdout=log, stderr=subprocess.STDOUT)
    if result.returncode:
        raise RuntimeError("exact forest proof failed; see prove.log")
    claimed = json.loads(report.read_text())
    assert claimed["complete_execution_forest_verified"]
    assert claimed["segments"] == 3 and claimed["cycles"] == 21635
    assert claimed["proof_count"] == 2
    assert claimed["queries"] == 70 and claimed["pow_bits"] == 26
    assert claimed["memory_event_rows"] > 0 and claimed["memory_instances"] > 0
    pin = bytes(claimed["roster_digest"]).hex()
    (out / "roster-pin.hex").write_text(pin + "\n")
    checked = subprocess.run([str(receiver), str(bundle), pin], cwd=R, capture_output=True, text=True)
    (out / "receiver.stdout").write_text(checked.stdout)
    (out / "receiver.stderr").write_text(checked.stderr)
    assert checked.returncode == 0 and json.loads(checked.stdout)["complete_execution_proof_verified"]
    files = (binary, receiver, elf, input_path, oracle, schedule, bundle, report)
    (out / "qualification.json").write_text(json.dumps({
        "scope": "complete three-segment authentication fixture with exact-count verified forest and host-only sorted memory witness; existing per-leaf memory custody, not mainnet or separate memory proof",
        "command": command,
        "wall_seconds": time.monotonic() - start,
        "proof_verified": True,
        "roster_pin_provenance": "frozen from producer report for development qualification; independent deployment pin required",
        "sha256": {str(path.relative_to(R)): hashlib.sha256(path.read_bytes()).hexdigest() for path in files},
    }, indent=2) + "\n")
print("exact three-segment forest and fresh receiver passed", flush=True)
