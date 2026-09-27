"""Fresh-process canonical qualification of the two-segment joint block route."""
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

out = H / "joint-two-segment-root-v1"
out.mkdir(exist_ok=False)
fixture = json.loads((H / "measurements-auth1-canonical-stages/measurement.json").read_text())
elf, input_path, oracle = map(Path, fixture["command"][3:6])
binary = R / "zig-out/bin/stwo-ethereum-block-stream"
receiver = R / "zig-out/bin/stwo-ethereum-block-verify"
schedule = out / "schedule.json"
schedule.write_text("[8000,13635]\n")
proof = out / "root.proof"
report = out / "report.json"
command = [str(binary), str(elf), str(input_path), str(oracle), "16384", str(proof), str(report), "canonical", "paired", "joint", "schedule=" + str(schedule)]
start = time.monotonic()
with build_lock(label="joint-two-segment-root-qualification"):
    with (out / "prove.log").open("x") as log:
        result = subprocess.run(command, cwd=R, stdout=log, stderr=subprocess.STDOUT)
    if result.returncode:
        raise RuntimeError("joint block proof failed; see prove.log")
    claimed = json.loads(report.read_text())
    assert claimed["complete_execution_proof_verified"]
    assert claimed["joint_execution_manifest"] and claimed["paired_execution_leaves"]
    assert claimed["segments"] == 2 and claimed["cycles"] == 21635
    assert claimed["queries"] == 70 and claimed["pow_bits"] == 26
    pin = bytes(claimed["admission"]["expected_id"]).hex()
    checked = subprocess.run([str(receiver), str(proof), str(report), pin], cwd=R, capture_output=True, text=True)
    (out / "receiver.stdout").write_text(checked.stdout)
    (out / "receiver.stderr").write_text(checked.stderr)
    assert checked.returncode == 0 and json.loads(checked.stdout)["complete_execution_proof_verified"]
    (out / "qualification.json").write_text(json.dumps({
        "scope": "complete two-segment authentication fixture, shared execution manifest and existing memory custody; not mainnet or separate sorted-memory proof",
        "command": command,
        "wall_seconds": time.monotonic() - start,
        "proof_verified": True,
        "sha256": {str(path.relative_to(R)): hashlib.sha256(path.read_bytes()).hexdigest() for path in (binary, receiver, elf, input_path, oracle, schedule, proof, report)},
    }, indent=2) + "\n")
print("joint two-segment root and fresh receiver passed", flush=True)
