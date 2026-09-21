#!/usr/bin/env python3
"""Derive canonical compact-Poseidon tree keys from a pinned retained admission.

Intermediate keys preserve their preprocessing commitments. The root key is
set up separately from independently verified canonical children, because child
key changes alter constants in the root's fixed columns. No root proof candidate
is used to authorize its key. Public input artifacts remain unchanged.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess

from zig_protocol_lib.command import protocol_module_args
from zig_serial_build import build_lock

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "src/frontends/riscv/poseidon2_identity_migration.zig"
CANONICAL = "e37c589fabffa3711c41c6cb259e68303543bc36edcef3d5be5caec7459f8ddf"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--admission", type=Path, required=True)
    parser.add_argument("--admission-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--parent-producer", type=Path, required=True)
    parser.add_argument("--parent-producer-sha256", required=True)
    parser.add_argument("--parent-verifier", type=Path, required=True)
    parser.add_argument("--parent-verifier-sha256", required=True)
    parser.add_argument("--leaf-bundles", type=Path, required=True)
    args = parser.parse_args()
    for path, pin in ((args.parent_producer, args.parent_producer_sha256), (args.parent_verifier, args.parent_verifier_sha256)):
        if sha256(path) != pin:
            parser.error(f"pinned executable changed: {path}")
    source = args.admission.resolve()
    if sha256(source) != args.admission_sha256:
        parser.error("independent admission digest mismatch")
    original = json.loads(source.read_bytes())
    if original["version"] != 1 or original["profile"] != "recursive_q193_v1" or len(original["leaves"]) != 4 or [len(level) for level in original["parents"]] != [2, 1]:
        parser.error("expected the reviewed four-segment q193 admission shape")
    admission = copy.deepcopy(original)
    # Resolve and authenticate every original artifact before building anything.
    for node in admission["leaves"] + [node for level in admission["parents"] for node in level]:
        for field in ("key", "expected"):
            artifact = node[field]
            path = (source.parent / artifact["path"]).resolve()
            if sha256(path) != artifact["sha256"]:
                parser.error(f"pinned {field} artifact changed: {path}")
            artifact["path"] = str(path)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    helper = output / "migrate-parent-key"
    with build_lock(label="recursive-identity-migration"):
        subprocess.run(["zig", "build-exe", *protocol_module_args(str(HELPER), optimize="ReleaseSafe"), f"-femit-bin={helper}"], cwd=ROOT, check=True)
    changes = []
    previous = admission["leaves"]
    previous_old = original["leaves"]
    for level_index, level in enumerate(admission["parents"]):
        for index, node in enumerate(level):
            old_path = Path(node["key"]["path"])
            old_key = json.loads(old_path.read_bytes())
            old_children = previous_old[2 * index:2 * index + 2]
            if old_key["child_key_sha256"] != [list(bytes.fromhex(child["key"]["sha256"])) for child in old_children]:
                raise ValueError("old parent pins do not match the independent tree")
            children = previous[2 * index:2 * index + 2]
            child_pins = [child["key"]["sha256"] for child in children]
            new_path = output / f"parent-{level_index + 1}-{index}-key.json"
            subprocess.run([str(helper), str(old_path), node["key"]["sha256"], *child_pins, str(new_path)], check=True)
            new_key = json.loads(new_path.read_bytes())
            if level_index == 1:
                # Child identity constants belong in the fixed commitment. Use
                # the shared setup owner, not a producer-generated root proof.
                setup_path = output / "root-setup-key.json"
                command = [str(args.parent_producer.resolve()), "derive-key", "--profile", "tiny-parent-root-v2", str(setup_path)]
                for child_index, child in enumerate(previous):
                    command += [str(output / f"pair-{child_index}"), child["key"]["sha256"], child["expected"]["path"]]
                command += ["--proof-profile", "recursive_q193_v1"]
                with build_lock(label="canonical-root-key-setup"):
                    with (output / "root-key-setup.log").open("x") as log:
                        subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True)
                setup_key = json.loads(setup_path.read_bytes())
                metadata = copy.deepcopy(new_key)
                metadata["preprocessed_root"] = setup_key["preprocessed_root"]
                if metadata != setup_key:
                    raise ValueError("root setup changed data outside its fixed commitment")
                new_path.write_bytes(setup_path.read_bytes())
                new_key = setup_key
            expected = copy.deepcopy(old_key)
            expected["manifest"]["placements"][34]["geometry"]["semantic_digest"] = list(bytes.fromhex(CANONICAL))
            expected["manifest"]["seal"] = new_key["manifest"]["seal"]
            expected["child_key_sha256"] = [list(bytes.fromhex(pin)) for pin in child_pins]
            if level_index == 1:
                expected["preprocessed_root"] = new_key["preprocessed_root"]
            if expected != new_key or old_key["manifest"]["seal"] == new_key["manifest"]["seal"]:
                raise ValueError("migration changed data outside identity, seal and child pins")
            new_pin = sha256(new_path)
            changes.append({"level": level_index + 1, "index": index, "old_key_sha256": node["key"]["sha256"], "new_key_sha256": new_pin})
            node["key"] = {"path": str(new_path), "sha256": new_pin}
        if level_index == 0:
            for index, node in enumerate(level):
                command = ["python3", str(ROOT / "scripts/riscv_segment_v2_detached_parent_gate.py"), "--proof-profile", "recursive_q193_v1", "--producer", str(args.parent_producer.resolve()), "--producer-sha256", args.parent_producer_sha256, "--verifier", str(args.parent_verifier.resolve()), "--verifier-sha256", args.parent_verifier_sha256, "--bundle", str(output / f"pair-{index}"), "--parent-key", node["key"]["path"], "--key-sha256", node["key"]["sha256"], "--expected-root", node["expected"]["path"], "--expected-root-sha256", node["expected"]["sha256"], "--publication-mode", "intermediate", "--child-family", "segment", "--memory-profile", "initial" if index == 0 else "continuation", "--output", str(output / f"pair-{index}-accepted.json")]
                for side, child_index in (("left", 2 * index), ("right", 2 * index + 1)):
                    child = admission["leaves"][child_index]
                    command += ["--" + side, str(args.leaf_bundles.resolve() / f"child-{child_index}"), child["key"]["sha256"], child["expected"]["path"]]
                with (output / f"pair-{index}-gate.log").open("x") as log:
                    subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True)
                if json.loads((output / f"pair-{index}-accepted.json").read_bytes()).get("passed") is not True:
                    raise ValueError("canonical child proof qualification failed")
        previous = level
        previous_old = original["parents"][level_index]
    for node in admission["leaves"] + [node for level in admission["parents"] for node in level]:
        for field in ("key", "expected"):
            node[field]["path"] = os.path.relpath(node[field]["path"], output)
    destination = output / "admission.json"
    destination.write_text(json.dumps(admission, indent=2) + "\n")
    receipt = {"source_admission_sha256": args.admission_sha256, "admission_sha256": sha256(destination), "canonical_identity": CANONICAL, "script_sha256": sha256(Path(__file__)), "helper_source_sha256": sha256(HELPER), "helper_binary_sha256": sha256(helper), "keys": changes, "public_inputs_unchanged": True, "root_proof_produced": False, "intermediate_proofs_qualified": 2, "root_preprocessing_rederived": True, "parent_producer_sha256": args.parent_producer_sha256, "parent_verifier_sha256": args.parent_verifier_sha256}
    (output / "migration.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"admission": str(destination), "sha256": receipt["admission_sha256"]}))


if __name__ == "__main__":
    main()
