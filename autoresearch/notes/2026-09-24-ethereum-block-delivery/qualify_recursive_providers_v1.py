"""One frozen CPU provider batch; no guest, STARK construction or device run.

Semantic mode checks all real bodies without LLVM output or test execution.
Focused mode emits one retained binary and runs only the explicit provider gates.
Every attempt retains distinct source hashes, command, result and failure log.
"""
from pathlib import Path
import argparse
import hashlib
import json
import re
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
GATES = HERE / "cpu-performance-gates-v1"
sys.path.insert(0, str(ROOT / "scripts"))
from zig_serial_build import build_lock


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", type=int, required=True)
    parser.add_argument("--mode", choices=("semantic", "focused"), required=True)
    parser.add_argument("--filter", action="append", help="narrow a justified corrective gate; exact Zig filter data")
    options = parser.parse_args()
    if options.version < 3:
        parser.error("versions 1 and 2 already have retained evidence")
    stem = f"provider-cohesive-{options.mode}-v{options.version}"
    source_path = GATES / f"{stem}-source.json"
    result_path = GATES / f"{stem}-result.json"
    log_path = GATES / f"{stem}.log"
    if any(path.exists() for path in (source_path, result_path, log_path)):
        parser.error("attempt already exists; preserve evidence and select a new version")
    seed = json.loads((GATES / "provider-cohesive-source-candidate-v2.json").read_text())
    paths = {entry["path"] for entry in seed["sources"]}
    paths.add(str(Path(__file__).resolve().relative_to(ROOT)))
    source = [{"path": path, "sha256": hashlib.sha256((ROOT / path).read_bytes()).hexdigest()}
              for path in sorted(paths)]
    arguments = json.loads((GATES / "provider-cohesive-qualification-command-v1.json").read_text())["command"]
    if options.filter:
        selected = []
        source_args = iter(arguments)
        for argument in source_args:
            if argument == "--test-filter":
                next(source_args)
            else:
                selected.append(argument)
        arguments = selected + [part for value in options.filter for part in ("--test-filter", value)]
    binary = f"/tmp/block-v5-provider-qualified-tests-v{options.version}"
    arguments = [argument for argument in arguments if not argument.startswith("-femit-bin=")]
    arguments.append("-fno-emit-bin" if options.mode == "semantic" else f"-femit-bin={binary}")
    source_path.write_text(json.dumps({"sources": source, "command": arguments}, indent=2) + "\n")
    print(f"Starting {options.mode} provider gate with {len(source)} source pins.", flush=True)
    started = time.monotonic()
    with build_lock(label=f"provider-{options.mode}"):
        with log_path.open("w") as output:
            completed = subprocess.run(arguments, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT)
    changed = [entry["path"] for entry in source
               if hashlib.sha256((ROOT / entry["path"]).read_bytes()).hexdigest() != entry["sha256"]]
    output_text = log_path.read_text()
    record = {"mode": options.mode, "source_candidate": source_path.name, "command": arguments,
              "exit_code": completed.returncode, "elapsed_seconds": time.monotonic() - started,
              "log": str(log_path.relative_to(ROOT)), "changed_source_pins": changed,
              "segments_run": False, "stark_proving_run": False, "device_run": False,
              "tests_run": bool(re.search(r"^\d+/\d+ ", output_text, re.MULTILINE)),
              "test_summary": re.findall(r"^(?:All \d+ tests passed\.|\d+ passed;.*)$", output_text, re.MULTILINE),
              "qualified": completed.returncode == 0 and not changed,
              "binary": binary if options.mode == "focused" else None}
    result_path.write_text(json.dumps(record, indent=2) + "\n")
    print(f"Exit {completed.returncode}; elapsed {record['elapsed_seconds']:.2f}s; changed pins {changed}", flush=True)
    print(output_text[-16000:], flush=True)
    return completed.returncode or int(bool(changed))


if __name__ == "__main__":
    raise SystemExit(main())
