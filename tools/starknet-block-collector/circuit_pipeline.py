"""Prove contiguous Starknet PIEs as circuit leaves and fold one root.

The pinned Rust adapter runs the Cairo leaf bootloader; Zig proves that
execution, wraps each Cairo proof, and folds the resulting circuit proofs.
All generated inputs and receipts stay in --out, never in committed vectors.
The final applicative bootloader that binds the root to Starknet aggregation
is a subsequent stage; this command measures and verifies the PIE-to-root path.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VECTOR = ROOT / "vectors/starknet/mainnet"
LEAF_PROGRAM = "crates/cairo-program-runner-lib/resources/compiled_programs/bootloaders/leaf_simple_bootloader_compiled.json"
PINNED_PROVING_COMMIT = "5a7c5ede4299c91a61df19a07cba4f7502c14230"
REGISTRY = ROOT / "vectors/circuit/official/registries/production.json"


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run(command: list[str], log: Path) -> dict:
    started = time.perf_counter()
    with log.open("w") as sink:
        result = subprocess.run(["/usr/bin/time", "-l", *command], cwd=ROOT, stdout=sink, stderr=subprocess.STDOUT)
    content = log.read_text(errors="replace")
    if result.returncode:
        raise RuntimeError(f"{command[0]} exited {result.returncode}; see {log}:\n{content[-2000:]}")
    rss = re.search(r"(\d+)\s+maximum resident set size", content)
    footprint = re.search(r"(\d+)\s+peak memory footprint", content)
    return {"wall_s": round(time.perf_counter() - started, 3),
            "peak_rss_bytes": int(rss.group(1)) if rss else None,
            "peak_memory_footprint_bytes": int(footprint.group(1)) if footprint else None,
            "log": str(log)}


def pie_sequence(names: list[str]) -> list[tuple[str, Path, dict]]:
    manifest = json.loads((VECTOR / "manifest.json").read_text())
    by_name = {Path(row["file"]).stem: row for row in manifest["pies"] if row["file"].startswith("pies/leaves/")}
    result = []
    prior = None
    if len(names) != len(set(names)):
        raise ValueError("duplicate PIE name")
    for name in names:
        row = by_name[name]
        if prior and (row["blocks"][0] != prior["blocks"][1] + 1 or row["initial_root"] != prior["final_root"]):
            raise ValueError(f"{name} does not continue the preceding leaf")
        path = VECTOR / row["file"]
        if digest(path) != row["sha256"]:
            raise ValueError(f"manifest digest mismatch: {path}")
        result.append((name, path, row))
        prior = row
    return result


def leaf_input(proof: Path, preimage: Path, output: Path) -> None:
    wrapped = json.loads(proof.read_text())
    if set(wrapped) != {"circuit_preprocessed_root", "circuit_hash", "proof"}:
        raise ValueError(f"invalid serialized leaf proof: {proof}")
    values = json.loads(preimage.read_text())
    if not isinstance(values, list) or not all(isinstance(x, str) and x.startswith("0x") for x in values):
        raise ValueError(f"invalid output preimage: {preimage}")
    decimal = [str(int(value, 16)) for value in values]
    output.write_text(json.dumps({**wrapped, "output_preimage": decimal}, separators=(",", ":")))


def leaf_stages(log: Path) -> dict[str, float]:
    match = re.search(r"leaf-wrap: load ([\d.]+) s, cairo prove ([\d.]+) s, wrap ([\d.]+) s", log.read_text())
    if not match:
        raise ValueError(f"missing leaf stage timings: {log}")
    return dict(zip(("load_s", "cairo_prove_s", "wrap_s"), map(float, match.groups())))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--oracle", type=Path, required=True, help="pinned stwo-circuit-oracle binary")
    parser.add_argument("--proving-root", type=Path, required=True, help="proving@5a7c5ed checkout")
    parser.add_argument("--backend", choices=("cpu", "metal"), default="cpu")
    parser.add_argument("--circuit-prover", type=Path, help="override the selected backend's binary")
    parser.add_argument("--rust-reducer", type=Path, help="optional pinned Rust reducer for byte parity")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("names", nargs="+", help="contiguous leaf PIE names, in block order")
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    oracle = args.oracle.resolve()
    proving = args.proving_root.resolve()
    proving_commit = subprocess.check_output(["git", "-C", str(proving), "rev-parse", "HEAD"], text=True).strip()
    if proving_commit != PINNED_PROVING_COMMIT:
        raise ValueError(f"expected proving@{PINNED_PROVING_COMMIT}, got {proving_commit}")
    default_prover = (ROOT / "zig-out/bin/stwo-circuit-recursion-cpu" if args.backend == "cpu"
                      else ROOT / "src/integrations/circuit_metal/zig-out/bin/stwo-circuit-recursion-metal")
    prover = (args.circuit_prover or default_prover).resolve()
    rows = []
    manifest = []
    for name, pie, source in pie_sequence(args.names):
        input_path = out / f"{name}.bootloader_input.json"
        preimage = out / f"{name}.preimage.hex.json"
        adapted = out / f"{name}.prover_input.json"
        wrapped = out / f"{name}.leaf_proof.json"
        leaf = out / f"{name}.leaf.json"
        input_path.write_text(json.dumps({
            "tasks": [{"type": "CairoPiePath", "path": str(pie), "program_hash_function": "blake"}],
            "fact_topologies_path": None, "single_page": True,
            "output_preimage_dump_path": str(preimage),
        }, indent=2) + "\n")
        print(f"adapting {name}", flush=True)
        adapt = run([str(oracle), "adapt-program", "--proving-root", str(proving),
                     "--program", LEAF_PROGRAM, "--program-input", str(input_path),
                     "--output", str(adapted)], out / f"{name}.adapt.log")
        print(f"proving and wrapping {name}", flush=True)
        wrap = run([str(prover), "leaf-wrap", "--registry", str(REGISTRY),
                    "--program", str(ROOT / "vectors/circuit/official/programs/leaf_simple_bootloader_compiled.json"),
                    "--prover-input", str(adapted), "--output", str(wrapped), "--assets", str(ROOT)],
                   out / f"{name}.leaf_wrap.log")
        leaf_input(wrapped, preimage, leaf)
        manifest.append(str(leaf))
        rows.append({"pie": str(pie), "blocks": source["blocks"], "cairo_steps": source["n_steps"],
                     "initial_root": source["initial_root"], "final_root": source["final_root"],
                     "adapt": adapt, "leaf_wrap": wrap, "leaf_stages": leaf_stages(out / f"{name}.leaf_wrap.log"),
                     "leaf_proof_sha256": digest(wrapped), "leaf_input_sha256": digest(leaf)})

    manifest_path = out / "leaves.json"
    manifest_path.write_text(json.dumps({"leaves": manifest}, indent=2) + "\n")
    root = out / "root.proof"
    outputs = out / "root_outputs.json"
    packed = out / "root_packed.json"
    print(f"folding {len(manifest)} leaves", flush=True)
    fold = run([str(prover), "fold-tree", "--program_input", str(manifest_path),
                "--circuit_registry_json", str(REGISTRY), "--proof_path", str(root),
                "--program_output", str(outputs), "--packed_output_path", str(packed)],
               out / "fold.log")
    rust = None
    if args.rust_reducer:
        reducer = args.rust_reducer.resolve()
        rust_paths = {"proof": out / "rust_root.proof", "outputs": out / "rust_root_outputs.json",
                      "packed": out / "rust_root_packed.json"}
        rust_run = run([str(reducer), "--program_input", str(manifest_path),
                        "--circuit_registry_json", str(REGISTRY), "--proof_path", str(rust_paths["proof"]),
                        "--program_output", str(rust_paths["outputs"]),
                        "--packed_output_path", str(rust_paths["packed"])], out / "rust_fold.log")
        equal = {key: path.read_bytes() == rust_paths[key].read_bytes() for key, path in
                 (("proof", root), ("outputs", outputs), ("packed", packed))}
        rust = {"run": rust_run, "byte_equal": equal}
        if not all(equal.values()):
            raise ValueError(f"Rust root mismatch: {equal}")
    registry = json.loads(REGISTRY.read_text())
    receipt = {"schema": "stwo-starknet-circuit-pipeline-v1", "backend": args.backend,
               "proving_commit": proving_commit,
               "oracle_binary_sha256": digest(oracle), "prover_binary_sha256": digest(prover),
               "scope": "contiguous Starknet PIEs to one recursive circuit root; final applicative aggregation is separate",
               "security": {"cairo_fri": registry["cairo_prover_params"]["fri_config"],
                            "circuit_fri": registry["circuit_proof_configs"]["default"]["fri_config"]},
               "registry_sha256": digest(REGISTRY),
               "leaves": rows, "fold": fold,
               "serial_wall_s": round(sum(row["adapt"]["wall_s"] + row["leaf_wrap"]["wall_s"] for row in rows) + fold["wall_s"], 3),
               "serial_peak_rss_bytes": max([fold["peak_rss_bytes"], *[row["leaf_wrap"]["peak_rss_bytes"] for row in rows]]),
               "serial_peak_memory_footprint_bytes": max([fold["peak_memory_footprint_bytes"], *[row["leaf_wrap"]["peak_memory_footprint_bytes"] for row in rows]]),
               "root": {key: {"path": str(path), "sha256": digest(path)} for key, path in
                        (("proof", root), ("outputs", outputs), ("packed", packed))}}
    if rust is not None:
        rust["reducer_binary_sha256"] = digest(reducer)
        receipt["rust_parity"] = rust
    (out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (KeyError, ValueError, RuntimeError) as exc:
        sys.exit(str(exc))
