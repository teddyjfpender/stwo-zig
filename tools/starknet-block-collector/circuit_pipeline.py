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
import os
import re
import shutil
import subprocess
import sys
import threading
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


def gpu_used_bytes() -> int:
    result = subprocess.run(["nvidia-smi", "--query-gpu=memory.used", "--format=csv,noheader,nounits"],
                            capture_output=True, text=True, check=True, timeout=2)
    return int(result.stdout.splitlines()[0].strip()) * (1 << 20)


def run(command: list[str], log: Path, sample_device_memory: bool = False,
        env: dict[str, str] | None = None) -> dict:
    idle_gpu_bytes = gpu_used_bytes() if sample_device_memory else None
    samples = []
    stop_probe = threading.Event()

    def probe() -> None:
        while not stop_probe.is_set():
            try:
                samples.append(gpu_used_bytes())
            except (OSError, subprocess.SubprocessError, ValueError, IndexError):
                pass
            stop_probe.wait(0.25)

    sampler = threading.Thread(target=probe, daemon=True) if sample_device_memory else None
    started = time.perf_counter()
    time_flags = ["-l"] if sys.platform == "darwin" else ["-v"]
    if sampler:
        sampler.start()
    try:
        with log.open("w") as sink:
            result = subprocess.run(["/usr/bin/time", *time_flags, *command], cwd=ROOT,
                                    stdout=sink, stderr=subprocess.STDOUT, env=env)
        wall_s = round(time.perf_counter() - started, 3)
    finally:
        stop_probe.set()
        if sampler:
            sampler.join()
    content = log.read_text(errors="replace")
    if result.returncode:
        raise RuntimeError(f"{command[0]} exited {result.returncode}; see {log}:\n{content[-2000:]}")
    rss = re.search(r"(\d+)\s+maximum resident set size", content)
    rss_kb = re.search(r"Maximum resident set size \(kbytes\):\s*(\d+)", content)
    footprint = re.search(r"(\d+)\s+peak memory footprint", content)
    return {"wall_s": wall_s,
            "peak_rss_bytes": int(rss.group(1)) if rss else int(rss_kb.group(1)) * 1024 if rss_kb else None,
            "peak_memory_footprint_bytes": int(footprint.group(1)) if footprint else None,
            "gpu_idle_used_bytes": idle_gpu_bytes,
            "gpu_peak_used_bytes": max(samples) if samples else None,
            "gpu_sample_interval_s": 0.25 if sampler else None,
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
    cairo_cuda_metrics(report)
    return {"load_s": 0.0,
            "cairo_prove_s": receipt["adapted_input_until_publication_ns"] / 1e9,
            "wrap_s": int(match.group(2)) / 1e9}


def resident_batch_leaf_stages(log: Path, report: Path, index: int) -> dict[str, float]:
    content = log.read_text()
    match = re.search(rf"circuit-cuda batch-leaf index={index} wrap_ns=(\d+)", content)
    if not match:
        raise ValueError(f"missing resident batch leaf {index} telemetry: {log}")
    releases = re.findall(r"cairo-cuda handoff prepared_arena_release_ns=(\d+)", content)
    if len(releases) <= index:
        raise ValueError(f"missing resident batch arena release {index} telemetry: {log}")
    receipt = json.loads(report.read_text())["completed_trials"][0]
    cairo_cuda_metrics(report)
    return {"load_s": 0.0,
            "cairo_prove_s": receipt["adapted_input_until_publication_ns"] / 1e9,
            "arena_release_s": int(releases[index]) / 1e9,
            "wrap_s": int(match.group(1)) / 1e9}


def cairo_cuda_metrics(report: Path) -> dict[str, int | float]:
    trial = json.loads(report.read_text())["completed_trials"][0]
    verdict = trial["verdict"]
    counters = verdict["counters"]
    if (verdict["provider"] != "nvidia_cuda" or counters["cpu_fallback_attempts"] != 0 or
            counters["cpu_fallbacks_completed"] != 0 or counters["d2h_proof_operations"] != 1):
        raise ValueError(f"nonresident Cairo proof: {report}")
    stages = counters["stages"]
    if len(stages) != 10:
        raise ValueError(f"unexpected Cairo CUDA stage telemetry: {report}")
    return {"planned_arena_bytes": trial["planned_arena_bytes"],
            "peak_live_bytes": counters["peak_live_bytes"],
            "persistent_bytes": counters["persistent_bytes"],
            "h2d_bytes": counters["h2d_bytes"],
            "d2d_bytes": counters["d2d_bytes"],
            "d2h_proof_bytes": counters["d2h_proof_bytes"],
            "kernel_launches": counters["kernel_launches"],
            "ingress_stage_elapsed_s": stages[0]["device_elapsed_ns"] / 1e9}


def resident_cairo_static_phases(log: Path, index: int = 0) -> dict[str, float | bool]:
    pattern = (r"cairo-cuda static-phase initial_upload_ns=(\d+) "
               r"preprocessed_load_ns=(\d+) materialize_ns=(\d+) cached=(true|false)"
               r"(?: device_image_hit=(true|false))?")
    phases = re.findall(pattern, log.read_text())
    if len(phases) <= index:
        return {}
    initial, load, materialize, cached, image_hit = phases[index]
    result = {"initial_upload_s": int(initial) / 1e9,
            "preprocessed_load_s": int(load) / 1e9,
            "materialize_s": int(materialize) / 1e9,
            "cached": cached == "true"}
    if image_hit:
        result["device_image_hit"] = image_hit == "true"
    return result


def resident_circuit_proofs(log: Path) -> list[dict]:
    pattern = (r"circuit-cuda circuit-proof profile=(internal|root) resident_ns=(\d+) "
               r"verify_ns=(\d+) convert_ns=(\d+) arena_bytes=(\d+) "
               r"peak_device_bytes=(\d+) terminal_bytes=(\d+)")
    content = log.read_text()
    proofs = [{"profile": profile, "resident_s": int(prove) / 1e9,
             "verify_s": int(verify) / 1e9, "convert_s": int(convert) / 1e9,
             "arena_bytes": int(arena), "peak_device_bytes": int(peak),
             "terminal_bytes": int(terminal)}
            for profile, prove, verify, convert, arena, peak, terminal
            in re.findall(pattern, content)]
    phase_pattern = (r"circuit-cuda resident-phase profile=(internal|root) plan_ns=(\d+) "
                     r"static_hash_ns=(\d+) ingress_ns=(\d+) schedule_ns=(\d+) "
                     r"finish_ns=(\d+) decode_ns=(\d+)")
    phases = re.findall(phase_pattern, content)
    if phases and len(phases) != len(proofs):
        raise ValueError(f"incomplete resident circuit phase telemetry: {log}")
    for proof, (profile, *values) in zip(proofs, phases):
        if proof["profile"] != profile:
            raise ValueError(f"resident circuit phase order mismatch: {log}")
        proof["resident_phases_s"] = dict(zip(
            ("plan", "static_hash", "ingress", "schedule", "finish", "decode"),
            (int(value) / 1e9 for value in values)))
    return proofs


def resident_host_phases(log: Path, command: str) -> dict | None:
    content = log.read_text()
    if command == "integrated-fold":
        match = re.search(r"circuit-cuda integrated-fold leaves=(\d+) reductions=(\d+) fold_ns=(\d+) proof_bytes=(\d+)", content)
        return {"leaves": int(match.group(1)), "reductions": int(match.group(2)),
                "fold_s": int(match.group(3)) / 1e9, "proof_bytes": int(match.group(4))} if match else None
    if command == "fold-tree":
        match = re.search(r"circuit-cuda fold-tree parse_ns=(\d+) catalog_ns=(\d+) fold_ns=(\d+) publish_ns=(\d+)", content)
        return dict(zip(("parse_s", "catalog_s", "fold_s", "publish_s"),
                        (int(value) / 1e9 for value in match.groups()))) if match else None
    if command == "leaf-wrap-batch":
        match = re.search(r"circuit-cuda leaf-wrap-batch setup_ns=(\d+) execution_ns=(\d+) cache_hits=(\d+) cache_misses=(\d+)", content)
        return {"setup_s": int(match.group(1)) / 1e9, "execution_s": int(match.group(2)) / 1e9,
                "leaf_topology_cache_hits": int(match.group(3)),
                "leaf_topology_cache_misses": int(match.group(4))} if match else None
    return None


def phase_breakdown(rows: list[dict], fold: dict, batch: dict | None = None,
                    integrated: bool = False) -> dict[str, float]:
    """Account for the serial wall clock without hiding process overhead."""
    phases = {
        "adapt_s": sum(row["adapt"]["wall_s"] for row in rows),
        "load_s": sum(row["leaf_stages"]["load_s"] for row in rows),
        "cairo_prove_s": sum(row["leaf_stages"]["cairo_prove_s"] for row in rows),
        "arena_release_s": sum(row["leaf_stages"].get("arena_release_s", 0) for row in rows),
        "circuit_wrap_s": sum(row["leaf_stages"]["wrap_s"] for row in rows),
        "fold_s": fold["wall_s"],
    }
    total = sum(row["adapt"]["wall_s"] for row in rows) + (
        batch["wall_s"] if batch else sum(row["leaf_wrap"]["wall_s"] for row in rows))
    if not integrated:
        total += fold["wall_s"]
    phases["process_overhead_s"] = total - sum(phases.values())
    return {key: round(value, 3) for key, value in phases.items()}


def compare_qualified_reference(receipt: dict, reference_path: Path, compact_root: bool = False) -> dict:
    """Bind a new run to a previously Rust-qualified PIE-to-root receipt."""
    reference = json.loads(reference_path.read_text())
    if reference.get("schema") != "stwo-circuit-cuda-resident-pipeline-benchmark-v1":
        raise ValueError(f"unsupported qualified reference: {reference_path}")
    if reference.get("rust_root_byte_equal") != {"proof": True, "outputs": True, "packed": True}:
        raise ValueError(f"reference lacks complete Rust root parity: {reference_path}")
    if receipt["registry_sha256"] != reference["registry_sha256"] or receipt["security"] != reference["security"]:
        raise ValueError("registry or security differs from qualified reference")
    expected_leaves = reference["leaves"]
    if len(receipt["leaves"]) != len(expected_leaves):
        raise ValueError("leaf count differs from qualified reference")
    for index, (actual, expected) in enumerate(zip(receipt["leaves"], expected_leaves)):
        same = (Path(actual["pie"]).name == expected["pie"] and
                actual["blocks"] == expected["blocks"] and
                actual["cairo_steps"] == expected["cairo_steps"] and
                actual["leaf_proof_sha256"] == expected["leaf_proof_sha256"] and
                actual["leaf_input_sha256"] == expected["leaf_input_sha256"] and
                actual["adapt"].get("reused_adapted_input_sha256") == expected["adapted_input_sha256"] and
                actual["adapt"].get("reused_preimage_sha256") == expected["preimage_sha256"])
        if not same:
            raise ValueError(f"leaf {index} differs from qualified reference")
    root_names = ("outputs",) if compact_root else reference["root_sha256"].keys()
    for name in root_names:
        expected = reference["root_sha256"][name]
        if receipt["root"][name]["sha256"] != expected:
            raise ValueError(f"{name} differs from qualified Rust root")
    return {"reference_sha256": digest(reference_path),
            "rust_root_byte_equal_by_digest": not compact_root,
            "rust_root_output_byte_equal_by_digest": True,
            "leaf_and_input_byte_equal_by_digest": True}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--oracle", type=Path, help="pinned stwo-circuit-oracle binary")
    parser.add_argument("--proving-root", type=Path, help="proving@5a7c5ed checkout")
    parser.add_argument("--adapted-dir", type=Path, help="reuse separately authenticated adapted inputs and preimages")
    parser.add_argument("--backend", choices=("cpu", "metal", "cuda-hybrid", "cuda-resident"), default="cpu")
    parser.add_argument("--cuda-batch", action="store_true", help="reuse one Cairo CUDA runtime across distinct PIE leaves")
    parser.add_argument("--cuda-static-image", action="store_true", help="reuse authenticated fixed Cairo coefficients on the GPU (experimental)")
    parser.add_argument("--cuda-integrated", action="store_true", help="fold the recursive root in the same CUDA process as the leaves")
    parser.add_argument("--cuda-compact-root", action="store_true", help="experimental smaller terminal AIR; changes root proof bytes")
    parser.add_argument("--sample-device-memory", action="store_true", help="sample whole-device CUDA memory with nvidia-smi")
    parser.add_argument("--circuit-prover", type=Path, help="override the selected backend's binary")
    parser.add_argument("--rust-reducer", type=Path, help="optional pinned Rust reducer for byte parity")
    parser.add_argument("--expected-receipt", type=Path,
                        help="require byte-identical leaf/input/root digests against a Rust-qualified receipt")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("names", nargs="+", help="contiguous leaf PIE names, in block order")
    args = parser.parse_args()
    if args.cuda_batch and args.backend != "cuda-resident":
        raise ValueError("--cuda-batch requires --backend cuda-resident")
    if args.cuda_static_image and not args.cuda_batch:
        raise ValueError("--cuda-static-image requires --cuda-batch")
    if args.cuda_integrated and not args.cuda_batch:
        raise ValueError("--cuda-integrated requires --cuda-batch")
    if args.cuda_compact_root and not args.cuda_integrated:
        raise ValueError("--cuda-compact-root requires --cuda-integrated")
    if args.sample_device_memory and args.backend != "cuda-resident":
        raise ValueError("--sample-device-memory requires --backend cuda-resident")
    pipeline_started = time.perf_counter()
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
    planned = []
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
        if args.cuda_batch:
            planned.append((name, pie, source, preimage, adapted, wrapped, leaf, adapt))
            continue
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
        wrap = run(command, out / f"{name}.leaf_wrap.log", args.sample_device_memory)
        leaf_input(wrapped, preimage, leaf)
        manifest.append(str(leaf))
        circuit_proofs = resident_circuit_proofs(out / f"{name}.leaf_wrap.log") if args.backend == "cuda-resident" else []
        if args.backend == "cuda-resident" and len(circuit_proofs) != 1:
            raise ValueError(f"expected one resident circuit wrap proof for {name}")
        rows.append({"pie": str(pie), "blocks": source["blocks"], "cairo_steps": source["n_steps"],
                     "initial_root": source["initial_root"], "final_root": source["final_root"],
                     "adapt": adapt, "leaf_wrap": wrap,
                     "leaf_stages": (resident_leaf_stages(out / f"{name}.leaf_wrap.log", cairo_report)
                                     if args.backend == "cuda-resident" else leaf_stages(out / f"{name}.leaf_wrap.log")),
                     "circuit_proofs": circuit_proofs,
                     "cairo_cuda_metrics": cairo_cuda_metrics(cairo_report)
                     if args.backend == "cuda-resident" else {},
                     "cairo_static_phases": resident_cairo_static_phases(out / f"{name}.leaf_wrap.log")
                     if args.backend == "cuda-resident" else {},
                     "leaf_proof_sha256": digest(wrapped), "leaf_input_sha256": digest(leaf)})

    batch = None
    if args.cuda_batch:
        batch_manifest = out / "cuda_batch.json"
        batch_manifest.write_text(json.dumps([{
            "registry": str(REGISTRY),
            "program": str(ROOT / "vectors/circuit/official/programs/leaf_simple_bootloader_compiled.json"),
            "input": str(adapted), "output": str(wrapped),
            "cairo_proof": str(out / f"{name}.cairo_proof.json"),
            "cairo_report": str(out / f"{name}.cairo_report.json"),
            "output_preimage": [str(int(value, 16)) for value in json.loads(preimage.read_text())],
        } for name, _, _, preimage, adapted, wrapped, _, _ in planned], indent=2) + "\n")
        print(f"proving and wrapping {len(planned)} leaves in one CUDA runtime", flush=True)
        batch_log = out / "cuda_batch.log"
        batch_env = {key: value for key, value in os.environ.items()
                     if key != "STWO_CAIRO_CUDA_STATIC_IMAGE"}
        if args.cuda_static_image:
            batch_env["STWO_CAIRO_CUDA_STATIC_IMAGE"] = "1"
        batch_command = [str(prover), "leaf-wrap-batch", "--manifest", str(batch_manifest)]
        if args.cuda_integrated:
            batch_command.extend(["--root-proof", str(out / "root.proof"),
                                  "--root-outputs", str(out / "root_outputs.json"),
                                  "--root-packed", str(out / "root_packed.json")])
            if args.cuda_compact_root:
                batch_command.extend(["--root-mode", "compact"])
        batch = run(batch_command, batch_log,
                    args.sample_device_memory, batch_env)
        batch["host_phases"] = resident_host_phases(batch_log, "leaf-wrap-batch")
        proofs = resident_circuit_proofs(batch_log)
        expected_proofs = len(planned) + (max(1, len(planned) - 1) if args.cuda_integrated else 0)
        if (len(proofs) != expected_proofs or
                any(proof["profile"] != "internal" for proof in proofs[:len(planned)]) or
                (args.cuda_integrated and proofs[-1]["profile"] != "root")):
            raise ValueError("missing resident batch wrap proof telemetry")
        for index, (name, pie, source, preimage, adapted, wrapped, leaf, adapt) in enumerate(planned):
            leaf_input(wrapped, preimage, leaf)
            manifest.append(str(leaf))
            stages = resident_batch_leaf_stages(batch_log, out / f"{name}.cairo_report.json", index)
            rows.append({"pie": str(pie), "blocks": source["blocks"], "cairo_steps": source["n_steps"],
                         "initial_root": source["initial_root"], "final_root": source["final_root"],
                         "adapt": adapt,
                         "leaf_wrap": {"wall_s": round(stages["cairo_prove_s"] + stages["arena_release_s"] + stages["wrap_s"], 3),
                                       "peak_rss_bytes": batch["peak_rss_bytes"],
                                       "peak_memory_footprint_bytes": batch["peak_memory_footprint_bytes"],
                                       "log": str(batch_log), "shared_process": True},
                         "leaf_stages": stages, "circuit_proofs": [proofs[index]],
                         "cairo_cuda_metrics": cairo_cuda_metrics(out / f"{name}.cairo_report.json"),
                         "cairo_static_phases": resident_cairo_static_phases(batch_log, index),
                         "leaf_proof_sha256": digest(wrapped), "leaf_input_sha256": digest(leaf)})

    manifest_path = out / "leaves.json"
    manifest_path.write_text(json.dumps({"leaves": manifest}, indent=2) + "\n")
    root = out / "root.proof"
    outputs = out / "root_outputs.json"
    packed = out / "root_packed.json"
    print(f"folding {len(manifest)} leaves", flush=True)
    if args.cuda_integrated:
        host_phases = resident_host_phases(out / "cuda_batch.log", "integrated-fold")
        if host_phases is None or host_phases["leaves"] != len(manifest) or host_phases["reductions"] != max(1, len(manifest) - 1):
            raise ValueError("missing integrated root telemetry")
        fold = {"wall_s": host_phases["fold_s"], "peak_rss_bytes": batch["peak_rss_bytes"],
                "peak_memory_footprint_bytes": batch["peak_memory_footprint_bytes"],
                "gpu_peak_used_bytes": batch["gpu_peak_used_bytes"],
                "log": str(out / "cuda_batch.log"), "shared_process": True,
                "host_phases": host_phases,
                "circuit_proofs": resident_circuit_proofs(out / "cuda_batch.log")[len(manifest):]}
    elif args.backend == "cuda-resident":
        fold_command = [str(prover), "fold-tree", "--manifest", str(manifest_path),
                        "--registry", str(REGISTRY), "--proof", str(root),
                        "--outputs", str(outputs), "--packed", str(packed)]
    else:
        fold_command = [str(prover), "fold-tree", "--program_input", str(manifest_path),
                        "--circuit_registry_json", str(REGISTRY), "--proof_path", str(root),
                        "--program_output", str(outputs), "--packed_output_path", str(packed)]
    if not args.cuda_integrated:
        fold = run(fold_command, out / "fold.log", args.sample_device_memory)
    adapted_input_to_root_wall_s = round(time.perf_counter() - pipeline_started, 3)
    if args.backend == "cuda-resident" and not args.cuda_integrated:
        fold["circuit_proofs"] = resident_circuit_proofs(out / "fold.log")
        fold["host_phases"] = resident_host_phases(out / "fold.log", "fold-tree")
        if len(fold["circuit_proofs"]) != max(1, len(manifest) - 1) or fold["circuit_proofs"][-1]["profile"] != "root":
            raise ValueError("missing resident fold/root proof telemetry")
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
               "leaves": rows, "fold": fold, "cuda_batch": batch,
               "cuda_static_image": args.cuda_static_image,
               "cuda_integrated": args.cuda_integrated,
               "cuda_compact_root": args.cuda_compact_root,
               "adapted_input_to_root_wall_s": adapted_input_to_root_wall_s,
               "phase_breakdown_s": phase_breakdown(rows, fold, batch, args.cuda_integrated),
               "serial_wall_s": round(sum(row["adapt"]["wall_s"] for row in rows) +
                                      (batch["wall_s"] if batch else sum(row["leaf_wrap"]["wall_s"] for row in rows)) +
                                      (0 if args.cuda_integrated else fold["wall_s"]), 3),
               "serial_peak_rss_bytes": max([fold["peak_rss_bytes"], *([batch["peak_rss_bytes"]] if batch else
                                                                        [row["leaf_wrap"]["peak_rss_bytes"] for row in rows])]),
               "serial_peak_memory_footprint_bytes": max((value for value in
                   [fold["peak_memory_footprint_bytes"], *[row["leaf_wrap"]["peak_memory_footprint_bytes"] for row in rows]]
                   if value is not None), default=None),
               "sampled_whole_device_peak_used_bytes": max((value for value in
                   [fold["gpu_peak_used_bytes"], *([batch["gpu_peak_used_bytes"]] if batch else
                                                         [row["leaf_wrap"]["gpu_peak_used_bytes"] for row in rows])]
                   if value is not None), default=None),
               "root": {key: {"path": str(path), "sha256": digest(path)} for key, path in
                        (("proof", root), ("outputs", outputs), ("packed", packed))}}
    if rust is not None:
        rust["reducer_binary_sha256"] = digest(reducer)
        receipt["rust_parity"] = rust
    if args.expected_receipt:
        receipt["qualified_reference_parity"] = compare_qualified_reference(
            receipt, args.expected_receipt.resolve(), args.cuda_compact_root)
    (out / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (KeyError, ValueError, RuntimeError) as exc:
        sys.exit(str(exc))
