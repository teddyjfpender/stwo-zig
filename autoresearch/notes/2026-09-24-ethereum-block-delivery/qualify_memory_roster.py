"""Fast host-only first-touch census for the qualified three-segment fixture."""
from pathlib import Path
import hashlib
import json
import subprocess
import sys

H = Path(__file__).resolve().parent
R = H.parents[2]
sys.path.insert(0, str(R / "scripts"))
from zig_serial_build import build_lock

fixture = H / "exact-three-segment-v1"
qualified = json.loads((fixture / "qualification.json").read_text())
command = qualified["command"]
binary = H / "ethereum-block-memory-roster"
roster = fixture / "memory-first-touch.bin"
report = fixture / "memory-first-touch.json"
invocation = [str(binary), *command[1:5], str(roster), str(report), command[-1].removeprefix("schedule=")]
with build_lock(label="exact-three-segment-memory-roster"):
    with (fixture / "memory-roster.log").open("x") as log:
        subprocess.run(invocation, cwd=R, stdout=log, stderr=subprocess.STDOUT, check=True)
result = json.loads(report.read_text())
proof_report = json.loads((fixture / "report.json").read_text())
assert not result["proof_verified"]
assert result["memory_events"] == proof_report["memory_event_rows"] == 51929
assert result["first_touch_keys"] == sum(proof_report["memory_initial_sources"])
assert list(result["source_counts"].values()) == proof_report["memory_initial_sources"]
assert result["roster_sha256"] == hashlib.sha256(roster.read_bytes()).hexdigest()
assert roster.stat().st_size == result["first_touch_keys"] * 10
print(json.dumps({"first_touch_keys": result["first_touch_keys"],
                  "source_counts": result["source_counts"],
                  "roster_sha256": result["roster_sha256"]}))
