"""Benchmark a CUDA-grind PIE-to-root run from already adapted PIE inputs.

The reference directory is a successful circuit_pipeline.py run. Its adapted
inputs and preimages are copied to the GPU host; this script proves the same
two leaves and root, then requires byte equality with the reference digests.
Adaptation is deliberately outside this timed scope.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from circuit_pipeline import REGISTRY, ROOT, digest, leaf_input, leaf_stages, phase_breakdown, run


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--prover", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    reference = args.reference.resolve()
    prover = args.prover.resolve()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    baseline = json.loads((reference / "receipt.json").read_text())
    if baseline["backend"] not in ("cpu", "metal") or len(baseline["leaves"]) != 2:
        raise ValueError("reference must be a qualified two-leaf CPU or Metal receipt")
    rows = []
    leaves = []
    for baseline_row in baseline["leaves"]:
        name = Path(baseline_row["pie"]).stem
        adapted = reference / f"{name}.prover_input.json"
        preimage = reference / f"{name}.preimage.hex.json"
        if not adapted.is_file() or not preimage.is_file():
            raise FileNotFoundError(f"missing adapted input or preimage for {name}")
        proof = out / f"{name}.leaf_proof.json"
        measured = run([str(prover), "leaf-wrap", "--registry", str(REGISTRY),
                        "--program", str(ROOT / "vectors/circuit/official/programs/leaf_simple_bootloader_compiled.json"),
                        "--prover-input", str(adapted), "--output", str(proof), "--assets", str(ROOT)],
                       out / f"{name}.leaf_wrap.log")
        if digest(proof) != baseline_row["leaf_proof_sha256"]:
            raise ValueError(f"{name}: CUDA-hybrid leaf differs from reference")
        leaf = out / f"{name}.leaf.json"
        leaf_input(proof, preimage, leaf)
        if digest(leaf) != baseline_row["leaf_input_sha256"]:
            raise ValueError(f"{name}: CUDA-hybrid leaf input differs from reference")
        rows.append({"name": name, "adapted_input_sha256": digest(adapted),
                     "preimage_sha256": digest(preimage), "leaf_wrap": measured,
                     "leaf_stages": leaf_stages(out / f"{name}.leaf_wrap.log"),
                     "leaf_proof_sha256": digest(proof)})
        leaves.append(str(leaf))
    manifest = out / "leaves.json"
    manifest.write_text(json.dumps({"leaves": leaves}, indent=2) + "\n")
    root = out / "root.proof"
    outputs = out / "root_outputs.json"
    packed = out / "root_packed.json"
    fold = run([str(prover), "fold-tree", "--program_input", str(manifest),
                "--circuit_registry_json", str(REGISTRY), "--proof_path", str(root),
                "--program_output", str(outputs), "--packed_output_path", str(packed)],
               out / "fold.log")
    for key, path in (("proof", root), ("outputs", outputs), ("packed", packed)):
        if digest(path) != baseline["root"][key]["sha256"]:
            raise ValueError(f"CUDA-hybrid root {key} differs from reference")
    phase_rows = [{**row, "adapt": {"wall_s": 0}} for row in rows]
    receipt = {
        "schema": "stwo-circuit-cuda-hybrid-pipeline-v1",
        "scope": "adapted inputs to one root; circuit interaction and FRI grinds on CUDA, all other proving on CPU",
        "reference_backend": baseline["backend"],
        "reference_receipt_sha256": digest(reference / "receipt.json"),
        "prover_sha256": digest(prover),
        "registry_sha256": digest(REGISTRY),
        "leaves": rows,
        "fold": fold,
        "phase_breakdown_s": phase_breakdown(phase_rows, fold),
        "adapted_input_to_root_wall_s": round(sum(row["leaf_wrap"]["wall_s"] for row in rows) + fold["wall_s"], 3),
        "root_sha256": digest(root),
        "byte_equal_to_reference": True,
    }
    (out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
