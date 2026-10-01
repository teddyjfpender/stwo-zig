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
import shutil
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
    time_flags = ["-l"] if sys.platform == "darwin" else ["-v"]
    with log.open("w") as sink:
        result = subprocess.run(["/usr/bin/time", *time_flags, *command], cwd=ROOT, stdout=sink, stderr=subprocess.STDOUT)
    content = log.read_text(errors="replace")
    if result.returncode:
        raise RuntimeError(f"{command[0]} exited {result.returncode}; see {log}:\n{content[-2000:]}")
    rss = re.search(r"(\d+)\s+maximum resident set size", content)
    rss_kb = re.search(r"Maximum resident set size \(kbytes\):\s*(\d+)", content)
    footprint = re.search(r"(\d+)\s+peak memory footprint", content)
    return {"wall_s": round(time.perf_counter() - started, 3),
            "peak_rss_bytes": int(rss.group(1)) if rss else int(rss_kb.group(1)) * 1024 if rss_kb else None,
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


def resident_leaf_stages(log: Path, report: Path) -> dict[str, float]:
    match = re.search(r"circuit-cuda leaf-wrap total_ns=(\d+) wrap_ns=(\d+)", log.read_text())
    if not match:
        raise ValueError(f"missing resident leaf stage timings: {log}")
    receipt = json.loads(report.read_text())["completed_trials"][0]
    verdict = receipt["verdict"]
    if not verdict.get("resident", False) and not verdict.get("is_resident", False):
        # The exact verdict representation is versioned by the CUDA runtime;
        # the Zig product itself enforces resident circuit proof production.
        if verdict.get("counters", {}).get("cpu_fallback_attempts", 0):
            raise ValueError(f"nonresident Cairo proof: {report}")
    return {"load_s": 0.0,
            "cairo_prove_s": receipt["adapted_input_until_publication_ns"] / 1e9,
            "wrap_s": int(match.group(2)) / 1e9}


def phase_breakdown(rows: list[dict], fold: dict) -> dict[str, float]:
    """Account for the serial wall clock without hiding process overhead."""
    phases = {
        "adapt_s": sum(row["adapt"]["wall_s"] for row in rows),
        "load_s": sum(row["leaf_stages"]["load_s"] for row in rows),
        "cairo_prove_s": sum(row["leaf_stages"]["cairo_prove_s"] for row in rows),
        "circuit_wrap_s": sum(row["leaf_stages"]["wrap_s"] for row in rows),
        "fold_s": fold["wall_s"],
    }
    total = sum(row["adapt"]["wall_s"] + row["leaf_wrap"]["wall_s"] for row in rows) + fold["wall_s"]
    phases["process_overhead_s"] = total - sum(phases.values())
    return {key: round(value, 3) for key, value in phases.items()}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--oracle", type=Path, help="pinned stwo-circuit-oracle binary")
    parser.add_argument("--proving-root", type=Path, help="proving@5a7c5ed checkout")
    parser.add_argument("--adapted-dir", type=Path, help="reuse separately authenticated adapted inputs and preimages")
    parser.add_argument("--backend", choices=("cpu", "metal", "cuda-hybrid", "cuda-resident"), default="cpu")
    parser.add_argument("--circuit-prover", type=Path, help="override the selected backend's binary")
    parser.add_argument("--rust-reducer", type=Path, help="optional pinned Rust reducer for byte parity")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("names", nargs="+", help="contiguous leaf PIE names, in block order")
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    if args.adapted_dir is None and (args.oracle is None or args.proving_root is None):
        raise ValueError("--oracle and --proving-root are required unless --adapted-dir is set")
    oracle = args.oracle.resolve() if args.oracle else None
    proving = args.proving_root.resolve() if args.proving_root else None
    proving_commit = (subprocess.check_output(["git", "-C", str(proving), "rev-parse", "HEAD"], text=True).strip()
                      if proving else None)
    if proving_commit is not None and proving_commit != PINNED_PROVING_COMMIT:
        raise ValueError(f"expected proving@{PINNED_PROVING_COMMIT}, got {proving_commit}")
    default_provers = {
        "cpu": ROOT / "zig-out/bin/stwo-circuit-recursion-cpu",
        "metal": ROOT / "src/integrations/circuit_metal/zig-out/bin/stwo-circuit-recursion-metal",
        "cuda-hybrid": ROOT / "src/integrations/circuit_cuda/zig-out/bin/stwo-circuit-recursion-cuda-hybrid",
        "cuda-resident": ROOT / "src/integrations/circuit_cuda/zig-out/bin/stwo-circuit-recursion-cuda",
    }
    default_prover = default_provers[args.backend]
    prover = (args.circuit_prover or default_prover).resolve()
    rows = []
    manifest = []
    for name, pie, source in pie_sequence(args.names):
        input_path = out / f"{name}.bootloader_input.json"
        preimage = out / f"{name}.preimage.hex.json"
        adapted = out / f"{name}.prover_input.json"
        wrapped = out / f"{name}.leaf_proof.json"
        leaf = out / f"{name}.leaf.json"
        if args.adapted_dir:
            source_dir = args.adapted_dir.resolve()
            shutil.copyfile(source_dir / adapted.name, adapted)
            shutil.copyfile(source_dir / preimage.name, preimage)
            adapt = {"wall_s": 0.0, "peak_rss_bytes": 0, "log": None,
                     "reused_adapted_input_sha256": digest(adapted),
                     "reused_preimage_sha256": digest(preimage)}
        else:
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
        if args.backend == "cuda-resident":
            cairo_proof = out / f"{name}.cairo_proof.json"
            cairo_report = out / f"{name}.cairo_report.json"
            command = [str(prover), "leaf-wrap", "--registry", str(REGISTRY),
                       "--program", str(ROOT / "vectors/circuit/official/programs/leaf_simple_bootloader_compiled.json"),
                       "--input", str(adapted), "--output", str(wrapped),
                       "--cairo-proof", str(cairo_proof), "--cairo-report", str(cairo_report)]
        else:
            command = [str(prover), "leaf-wrap", "--registry", str(REGISTRY),
                       "--program", str(ROOT / "vectors/circuit/official/programs/leaf_simple_bootloader_compiled.json"),
                       "--prover-input", str(adapted), "--output", str(wrapped), "--assets", str(ROOT)]
        wrap = run(command, out / f"{name}.leaf_wrap.log")
        leaf_input(wrapped, preimage, leaf)
        manifest.append(str(leaf))
        rows.append({"pie": str(pie), "blocks": source["blocks"], "cairo_steps": source["n_steps"],
                     "initial_root": source["initial_root"], "final_root": source["final_root"],
                     "adapt": adapt, "leaf_wrap": wrap,
                     "leaf_stages": (resident_leaf_stages(out / f"{name}.leaf_wrap.log", cairo_report)
                                     if args.backend == "cuda-resident" else leaf_stages(out / f"{name}.leaf_wrap.log")),
                     "leaf_proof_sha256": digest(wrapped), "leaf_input_sha256": digest(leaf)})

    manifest_path = out / "leaves.json"
    manifest_path.write_text(json.dumps({"leaves": manifest}, indent=2) + "\n")
    root = out / "root.proof"
    outputs = out / "root_outputs.json"
    packed = out / "root_packed.json"
    print(f"folding {len(manifest)} leaves", flush=True)
    if args.backend == "cuda-resident":
        fold_command = [str(prover), "fold-tree", "--manifest", str(manifest_path),
                        "--registry", str(REGISTRY), "--proof", str(root),
                        "--outputs", str(outputs), "--packed", str(packed)]
    else:
        fold_command = [str(prover), "fold-tree", "--program_input", str(manifest_path),
                        "--circuit_registry_json", str(REGISTRY), "--proof_path", str(root),
                        "--program_output", str(outputs), "--packed_output_path", str(packed)]
    fold = run(fold_command, out / "fold.log")
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
               "device_scope": ("circuit interaction and FRI proof-of-work grinds only; Cairo and circuit PCS on CPU"
                                if args.backend == "cuda-hybrid" else
                                "Cairo PIE, circuit leaf wrap, and all circuit folds on resident CUDA"
                                if args.backend == "cuda-resident" else args.backend),
               "proving_commit": proving_commit,
               "oracle_binary_sha256": digest(oracle) if oracle else None,
               "prover_binary_sha256": digest(prover),
               "scope": "contiguous Starknet PIEs to one recursive circuit root; final applicative aggregation is separate",
               "security": {"cairo_fri": registry["cairo_prover_params"]["fri_config"],
                            "circuit_fri": registry["circuit_proof_configs"]["default"]["fri_config"]},
               "registry_sha256": digest(REGISTRY),
               "leaves": rows, "fold": fold,
               "phase_breakdown_s": phase_breakdown(rows, fold),
               "serial_wall_s": round(sum(row["adapt"]["wall_s"] + row["leaf_wrap"]["wall_s"] for row in rows) + fold["wall_s"], 3),
               "serial_peak_rss_bytes": max([fold["peak_rss_bytes"], *[row["leaf_wrap"]["peak_rss_bytes"] for row in rows]]),
               "serial_peak_memory_footprint_bytes": max((value for value in
                   [fold["peak_memory_footprint_bytes"], *[row["leaf_wrap"]["peak_memory_footprint_bytes"] for row in rows]]
                   if value is not None), default=None),
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
