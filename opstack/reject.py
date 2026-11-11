#!/usr/bin/env python3
"""Real-fixture negative controls: bad admission, used preimage and block claim.

Input SHA pins are deliberately recomputed for each mutation. This exercises
guest validation rather than merely testing the outer file-identity check.
"""

import argparse
import copy
import hashlib
import json
import struct
import subprocess
from pathlib import Path


def mutations(data, root):
    metadata, count = struct.unpack_from("<II", data, 8)
    table = 24 + metadata
    payload = table + count * 40
    reserved = bytearray(data)
    struct.pack_into("<I", reserved, 20, 1)
    claimed = bytearray(data)
    # Canonical Range metadata ends with its ordered Vec<[u8;32]> of hashes.
    # This control uses an isolated one-block fixture.
    claimed[table - 1] ^= 1
    poisoned = bytearray(data)
    for index in range(count):
        descriptor = table + index * 40
        if data[descriptor : descriptor + 32] == root:
            offset, length = struct.unpack_from("<II", data, descriptor + 32)
            if not length:
                raise ValueError("empty parent trie root")
            poisoned[payload + offset] ^= 1
            break
    else:
        raise ValueError("parent state-root preimage absent")
    return {
        "reserved_header": reserved,
        "wrong_computed_hash": claimed,
        "poisoned_used_preimage": poisoned,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--request", type=Path, required=True)
    p.add_argument("--execution", type=Path, required=True)
    p.add_argument("--fixture", type=Path, required=True)
    p.add_argument("--host", type=Path, required=True)
    p.add_argument("--runner", type=Path, required=True)
    p.add_argument("--artifacts", type=Path, required=True)
    args = p.parse_args()
    config = json.loads(args.request.read_text())
    execution = json.loads(args.execution.read_text())
    fixture = json.loads(args.fixture.read_text())
    data = Path(config["input"]).read_bytes()
    if hashlib.sha256(data).hexdigest() != config["input_sha256"]:
        raise ValueError("input identity differs")
    if (
        hashlib.sha256(Path(config["elf"]).read_bytes()).hexdigest()
        != config["elf_sha256"]
    ):
        raise ValueError("guest identity differs")
    if (
        execution.get("status") != "completed"
        or execution.get("verified_output") is not True
    ):
        raise ValueError("control requires complete positive execution")
    root = bytes.fromhex(fixture["parent_header"]["stateRoot"][2:])
    args.artifacts.mkdir(parents=True, exist_ok=False)
    rows = []
    for name, mutated in mutations(data, root).items():
        path = (args.artifacts / f"{name}.opx").resolve()
        path.write_bytes(mutated)
        native_errors = {}
        for mode in ("eager", "lazy"):
            native = subprocess.run(
                [str(args.host.resolve()), "run", str(path), mode],
                capture_output=True,
                text=True,
                check=False,
                timeout=120,
            )
            if native.returncode == 0 or native.stdout.strip():
                raise ValueError(name + ": native reference admitted corruption")
            native_errors[mode] = native.stderr.strip()
        request = {
            k: copy.deepcopy(config[k])
            for k in (
                "elf",
                "input",
                "elf_sha256",
                "input_sha256",
                "expected_output",
                "symbols",
                "execution_profile",
            )
        }
        request.update(
            input=str(path),
            input_sha256=hashlib.sha256(mutated).hexdigest(),
            max_steps=2 * execution["instructions"] + 1,
            engine="fast",
        )
        request_path = args.artifacts / f"{name}.json"
        request_path.write_text(json.dumps(request, indent=2) + "\n")
        result = subprocess.run(
            [str(args.runner.resolve()), str(request_path.resolve())],
            capture_output=True,
            text=True,
            timeout=120,
            check=True,
        )
        observed = json.loads(result.stdout)
        if (
            observed.get("status") != "trap"
            or observed.get("verified_output") is not False
            or observed.get("output") is not None
        ):
            raise ValueError(name + ": guest did not trap before publication")
        rows.append(
            {
                "control": name,
                "input_sha256": request["input_sha256"],
                "native_errors": native_errors,
                "rv64": observed,
            }
        )
        print(name, "rejected by native eager/lazy and RV64 guest", flush=True)
    receipt = {
        "schema": "stwo.opstack.rejections.v1",
        "proof_verified": False,
        "elf_sha256": config["elf_sha256"],
        "positive_input_sha256": config["input_sha256"],
        "source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "rows": rows,
    }
    (args.artifacts / "summary.json").write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    main()
