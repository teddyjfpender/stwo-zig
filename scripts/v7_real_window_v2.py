#!/usr/bin/env python3
"""Run the new v7 state-delta proof against explicitly selected real snapshots.

The caller selects capture.json's hash. Snapshot identities inside that selected
manifest are benchmark statement inputs, not proof-derived authority. The skipped
prefix is not proved. Physical disk I/O is not inferred from file sizes.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
import platform
from pathlib import Path
import subprocess
import tempfile
import time
from v7_real_window_corpus import ROOT, PINS, checked_bytes, snapshot_bytes


def timed_command(binary: Path, system: str | None = None) -> list[str]:
    system = platform.system() if system is None else system
    if system not in ("Darwin", "Linux"):
        raise ValueError("measured runner supports Darwin and Linux only")
    return ["/usr/bin/time", "-l" if system == "Darwin" else "-v", str(binary.resolve())]


def run(args: argparse.Namespace) -> int:
    shared_union = getattr(args, "shared_union", False)
    shared_union_root = getattr(args, "shared_union_root", False)
    reload_union = getattr(args, "reload_union", None)
    if shared_union_root and (shared_union or reload_union or args.complete_root or args.cuda_deep or args.cuda_reference):
        raise ValueError("joined recursive union uses its own CPU gate, separate from other proof and CUDA modes")
    if shared_union and (args.complete_root or args.cuda_deep or args.cuda_reference):
        raise ValueError("shared original union uses its CPU gate, separately from recursive-root and CUDA gates")
    if reload_union and (shared_union or args.complete_root or args.cuda_deep or args.cuda_reference):
        raise ValueError("saved-union reload is verification only, separate from proving gates")
    report_bytes = (args.snapshots / "capture.json").read_bytes()
    if len(report_bytes) > 1 << 20 or hashlib.sha256(report_bytes).hexdigest() != args.capture_sha256:
        raise ValueError("capture manifest does not match independently selected hash")
    report = json.loads(report_bytes)
    if report["elf_sha256"] != PINS["guest.elf"][0]:
        raise ValueError("capture uses another retained ELF")
    checked_bytes(args.bundle / "guest.elf", "guest.elf")
    binary_hash = hashlib.sha256(args.binary.read_bytes()).hexdigest()
    provenance = json.loads(args.build_manifest.read_text())
    if provenance["binary_sha256"] != binary_hash:
        raise ValueError("binary does not match the selected build manifest")
    if args.destination.exists():
        raise ValueError("destination exists; preserving previous evidence")
    args.destination.mkdir(parents=True)
    incoming = snapshot_bytes(args.snapshots, "incoming.b7win")
    outgoing = snapshot_bytes(args.snapshots, "outgoing.b7win")
    with tempfile.TemporaryDirectory(prefix="stwo-v7-window-input-") as staging:
        stage = Path(staging)
        (stage / "incoming.b7win").write_bytes(incoming)
        (stage / "outgoing.b7win").write_bytes(outgoing)
        env = os.environ.copy()
        # Benchmark options come from this invocation, never inherited ad-hoc
        # diagnostic switches (especially security, source and worker choices).
        for key in tuple(env):
            if key.startswith(("STWO_REAL_WINDOW_V2_", "STWO_V7_WINDOW_", "STWO_RISCV_CUDA_")) or key in {"STWO_RISCV_RECURSIVE_PARENT_PROFILE", "STWO_RISCV_MATERIALIZED_POLYNOMIALS"}:
                env.pop(key)
        env.update({
            "STWO_V7_PROFILE_ERRORS": "1",
            "STWO_REAL_WINDOW_V2_ELF": str((args.bundle / "guest.elf").resolve()),
            "STWO_REAL_WINDOW_V2_ELF_SHA256": report["elf_sha256"],
            "STWO_REAL_WINDOW_V2_INCOMING": str(stage / "incoming.b7win"),
            "STWO_REAL_WINDOW_V2_OUTGOING": str(stage / "outgoing.b7win"),
            "STWO_REAL_WINDOW_V2_INCOMING_SHA256": report["incoming_sha256"],
            "STWO_REAL_WINDOW_V2_OUTGOING_SHA256": report["outgoing_sha256"],
            "STWO_REAL_WINDOW_V2_SKIP": str(report["window"]["skip_cycles"]),
            "STWO_REAL_WINDOW_V2_CYCLES": str(report["window"]["cycles"]),
            "STWO_REAL_WINDOW_V2_SEGMENT": str(args.segment_cycles),
            "STWO_REAL_WINDOW_V2_OUTPUT": str(args.destination.resolve()),
            "STWO_REAL_WINDOW_V2_WORKERS": str(args.workers),
            "STWO_REAL_WINDOW_V2_NATIVE_LAYOUT": args.native_layout,
            "STWO_REAL_WINDOW_V2_FUSED_PROJECTION_ROWS": str(int(getattr(args, "fused_projection_rows", False))),
            "STWO_REAL_WINDOW_V2_SPARSE_INITIALIZATION": str(int(args.sparse_initialization)),
            "STWO_REAL_WINDOW_V2_RESIDENT_MEMORY": str(int(args.resident_memory)),
            "STWO_REAL_WINDOW_V2_NATIVE_MAIN_CACHE_MIB": str(args.native_main_cache_mib),
            "STWO_REAL_WINDOW_V2_DEEP_GROUP_MIB": str(args.deep_group_mib),
        })
        if reload_union:
            env["STWO_REAL_WINDOW_V2_UNION_SOURCE"] = str(reload_union.resolve())
        if getattr(args, "resident_original_stages", False):
            if not shared_union_root:
                raise ValueError("resident original stages require the CPU shared-union recursive-root gate")
            env["STWO_REAL_WINDOW_V2_RESIDENT_ORIGINAL_STAGES"] = "1"
        if getattr(args, "ram_target_components", None) is not None:
            if not shared_union_root or not 1 <= args.ram_target_components <= 4096:
                raise ValueError("RAM component target requires the joined recursive CPU gate and 1..4096 components")
            env["STWO_REAL_WINDOW_V2_RAM_TARGET_COMPONENTS"] = str(args.ram_target_components)
        if args.complete_root:
            env.update({
                "STWO_V7_WINDOW_BENCHMARK": "1",
                "STWO_V7_WINDOW_CANONICAL": "1",
                "STWO_V7_WINDOW_ELF": str((args.bundle / "guest.elf").resolve()),
                "STWO_V7_WINDOW_ELF_SHA256": report["elf_sha256"],
                "STWO_V7_WINDOW_INCOMING": str(stage / "incoming.b7win"),
                "STWO_V7_WINDOW_OUTGOING": str(stage / "outgoing.b7win"),
                "STWO_V7_WINDOW_INCOMING_SHA256": report["incoming_sha256"],
                "STWO_V7_WINDOW_OUTGOING_SHA256": report["outgoing_sha256"],
                "STWO_V7_WINDOW_SKIP": str(report["window"]["skip_cycles"]),
                "STWO_V7_WINDOW_CYCLES": str(report["window"]["cycles"]),
                "STWO_V7_WINDOW_SEGMENT_CYCLES": str(args.segment_cycles),
                "STWO_V7_WINDOW_WORKERS": str(args.workers),
                "STWO_V7_WINDOW_NATIVE_LAYOUT": args.native_layout,
                "STWO_V7_WINDOW_FUSED_PROJECTION_ROWS": str(int(getattr(args, "fused_projection_rows", False))),
                "STWO_V7_WINDOW_SPARSE_INITIALIZATION": str(int(args.sparse_initialization)),
                "STWO_V7_WINDOW_RESIDENT_MEMORY": str(int(args.resident_memory)),
                "STWO_V7_WINDOW_NATIVE_MAIN_CACHE_MIB": str(args.native_main_cache_mib),
                "STWO_V7_WINDOW_DEEP_GROUP_MIB": str(args.deep_group_mib),
                "STWO_V7_WINDOW_ROOT_PREPARATION_MIB": str(args.root_preparation_mib),
                "STWO_V7_WINDOW_ROOT_ROW_LOG": str(args.root_row_log),
                "STWO_V7_WINDOW_ROOT_BATCH_SIZE": str(args.root_batch_size),
                "STWO_V7_WINDOW_ROOT_PARALLEL_FAMILIES": str(args.root_parallel_families),
                "STWO_V7_WINDOW_ROOT_PARALLEL_PREPARATION": str(args.root_parallel_preparation),
                "STWO_V7_WINDOW_REUSE_NATIVE_COMPILER": str(int(args.reuse_native_compiler)),
                "STWO_V7_WINDOW_SHARED_EPOCH_PREFIX": str(int(args.shared_epoch_prefix)),
                "STWO_V7_WINDOW_REUSE_ORIGINAL_CAPTURES": str(int(args.reuse_original_captures)),
                "STWO_V7_WINDOW_ORIGINAL_CAPTURE_MIB": str(args.original_capture_mib),
                "STWO_V7_WINDOW_NATIVE_COMPILER_MIB": str(args.native_compiler_mib),
                "STWO_V7_WINDOW_REPORT": str((args.destination / "report.json").resolve()),
                "STWO_V7_WINDOW_ROOT_OUTPUT": str((args.destination / "root.proof").resolve()),
            })
        if args.cuda_deep or args.cuda_reference:
            gpu_dir = args.destination / "gpu"
            gpu_dir.mkdir()
            env.update({
                "STWO_RISCV_CUDA_REPORT_DIR": str(gpu_dir.resolve()),
                "STWO_RISCV_CUDA_ORIGINALS_ONLY": str(int(not args.complete_root)),
                "STWO_RISCV_CUDA_DEVICE": str(args.cuda_device),
                "STWO_RISCV_CUDA_SM": str(args.cuda_sm),
                "STWO_RISCV_CUDA_DEVICE_MIB": str(args.cuda_device_mib),
                "STWO_RISCV_CUDA_CPU_REFERENCE": str(int(args.cuda_reference)),
                "STWO_RISCV_CUDA_PARENT_COMPOSITION": str(int(args.cuda_composition)),
                "STWO_RISCV_CUDA_PARENT_INTERACTIONS": str(int(args.cuda_interactions)),
            })
        if args.profile_root:
            env["STWO_RISCV_RECURSIVE_PARENT_PROFILE"] = "1"
        if args.materialized_parent_polynomials:
            env["STWO_RISCV_MATERIALIZED_POLYNOMIALS"] = "1"
        env["LC_ALL"] = "C"
        command = timed_command(args.binary)
        invocation = {
            "schema": "stwo-v7-real-window-new-invocation-v2", "command": command,
            "capture_sha256": args.capture_sha256, "binary_sha256": binary_hash,
            "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "complete_recursive_root": args.complete_root or shared_union_root,
            "shared_recursive_union": shared_union_root,
            "ram_target_components": getattr(args, "ram_target_components", None),
            "resident_original_stages": getattr(args, "resident_original_stages", False),
            "shared_original_union": shared_union,
            "verification_only": bool(reload_union),
            "worker_count": args.workers,
            "native_layout": args.native_layout,
            "fused_projection_rows": getattr(args, "fused_projection_rows", False),
            "sparse_initialization": args.sparse_initialization,
            "resident_memory": args.resident_memory,
            "native_main_cache_mib": args.native_main_cache_mib,
            "deep_group_mib": args.deep_group_mib,
            "cuda_deep": args.cuda_deep,
            "cuda_reference": args.cuda_reference,
            "cuda_composition": args.cuda_composition,
            "cuda_interactions": args.cuda_interactions,
            "reuse_native_compiler": args.reuse_native_compiler,
            "shared_epoch_prefix": args.shared_epoch_prefix,
            "materialized_parent_polynomials": args.materialized_parent_polynomials,
            "reuse_original_captures": args.reuse_original_captures,
            "original_capture_mib": args.original_capture_mib,
            "native_compiler_mib": args.native_compiler_mib,
            "root_resources": {"preparation_mib": args.root_preparation_mib,
                               "row_log": args.root_row_log, "batch_size": args.root_batch_size,
                               "parallel_families": args.root_parallel_families,
                               "parallel_preparation": args.root_parallel_preparation} if args.complete_root else None,
            "report_checked": False,
            "build_manifest_sha256": hashlib.sha256(args.build_manifest.read_bytes()).hexdigest(),
            "preparation": {"decompressed_snapshot_bytes_read": len(incoming) + len(outgoing),
                            "temporary_snapshot_bytes_written": len(incoming) + len(outgoing),
                            "prefix_replay": False, "physical_disk_bytes": None},
            "started_unix_ns": time.time_ns(),
        }
        (args.destination / "invocation.json").write_text(json.dumps(invocation, indent=2) + "\n")
        with (args.destination / "qualification.log").open("wb") as log:
            result = subprocess.run(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, check=False)
        invocation.update(returncode=result.returncode, finished_unix_ns=time.time_ns())
        (args.destination / "invocation.json").write_text(json.dumps(invocation, indent=2) + "\n")
        if result.returncode == 0 and not (args.destination / "report.json").is_file():
            raise RuntimeError("gate returned success without measured proof report")
        if result.returncode == 0:
            measured = json.loads((args.destination / "report.json").read_text())
        if result.returncode == 0 and not reload_union:
            if measured.get("fused_projection_rows", False) is not getattr(args, "fused_projection_rows", False):
                raise RuntimeError("gate did not attest the selected projection producer")
            if measured.get("worker_count", 4) != args.workers:
                raise RuntimeError("gate did not attest the selected worker count")
            mode = {"canonical": "canonical_v1", "degree-bounded-q2": "degree_bounded_q2_v1"}[args.native_layout]
            if measured.get("native_layout_mode", "canonical_v1") != mode or measured.get("sparse_window_initialization", False) is not args.sparse_initialization:
                raise RuntimeError("gate did not attest the selected native/initialization policy")
            if measured.get("resident_memory", False) is not args.resident_memory or measured.get("native_main_cache_mib", 256) != args.native_main_cache_mib or measured.get("deep_group_mib", 1) != args.deep_group_mib:
                raise RuntimeError("gate did not attest the selected memory/performance policy")
        if result.returncode == 0 and args.complete_root:
            if not all(measured.get(key) is True for key in (
                "canonical_security", "external_capsules", "originals_destroyed",
                "complete_global_closure", "verified",
            )) or measured.get("scope") != "declared_nonterminal_window_to_complete_recursive_root":
                raise RuntimeError("root gate did not attest complete canonical window closure")
            if measured.get("query_count") != 70 or measured.get("pow_bits") != 26:
                raise RuntimeError("root security differs from canonical q70/26")
            if measured.get("worker_count") != args.workers or measured.get("segment_cycles") != args.segment_cycles:
                raise RuntimeError("root gate ignored the selected CPU/window geometry")
            if any(measured.get(key, default) != requested for key, default, requested in (
                ("root_preparation_mib", 8192, args.root_preparation_mib),
                ("root_row_log", 25, args.root_row_log),
                ("root_batch_size", 0, args.root_batch_size),
                ("root_parallel_families", 1, args.root_parallel_families),
                ("root_parallel_preparation", 1, args.root_parallel_preparation),
                ("reuse_native_compiler", False, args.reuse_native_compiler),
                ("shared_epoch_prefix", False, args.shared_epoch_prefix),
                ("materialized_parent_polynomials", False, args.materialized_parent_polynomials),
                ("reuse_original_captures", False, args.reuse_original_captures),
                ("original_capture_mib", 4096, args.original_capture_mib),
                ("native_compiler_mib", 2048, args.native_compiler_mib),
            )):
                raise RuntimeError("root gate ignored the selected recursive resource policy")
            if measured.get("ethereum_block") is not False or measured.get("skipped_prefix_proved") is not False:
                raise RuntimeError("window report claims an unsupported complete-block theorem")
            if any(measured.get(key) != report[key] for key in (
                "elf_sha256", "incoming_sha256", "outgoing_sha256",
            )) or measured.get("cycles") != report["window"]["cycles"] or measured.get("skip_cycles") != report["window"]["skip_cycles"]:
                raise RuntimeError("root report does not bind the selected window")
            root_bytes = (args.destination / "root.proof").read_bytes()
            if len(root_bytes) != measured.get("root_bytes") or hashlib.sha256(root_bytes).hexdigest() != measured.get("root_sha256"):
                raise RuntimeError("root artifact does not match the measured proof")
        if result.returncode == 0 and shared_union:
            if measured.get("schema") != "stwo-real-window-shared-union-v1" or measured.get("scope") != "declared_nonterminal_window_to_shared_original_stark" or measured.get("union_proof") is not True:
                raise RuntimeError("gate did not attest the selected shared original union")
            if not all(measured.get(k) is True for k in ("verified", "canonical_security", "complete_global_closure")) or any(measured.get(k) is not False for k in ("complete_recursive_root", "ethereum_block", "skipped_prefix_proved")):
                raise RuntimeError("shared union gate has an invalid theorem or closure boundary")
            if measured.get("query_count") != 70 or measured.get("pow_bits") != 26 or measured.get("window") != report["window"] or any(measured.get(k) != report[k] for k in ("elf_sha256", "incoming_sha256", "outgoing_sha256")):
                raise RuntimeError("shared union proof differs from selected security or window")
            detail = json.loads((args.destination / "union-verification.json").read_text())
            proof_bytes = (args.destination / "union.proof").read_bytes()
            if detail.get("producer_proof_destroyed") is not True or detail.get("verified", {}).get("scope") != "declared_window" or measured.get("artifacts", {}).get("proof_count") != 1 or len(proof_bytes) != detail.get("proof_bytes") or hashlib.sha256(proof_bytes).hexdigest() != detail.get("proof_sha256"):
                raise RuntimeError("shared union artifact lacks fresh detached verification")
        if result.returncode == 0 and shared_union_root:
            if measured.get("schema") != "stwo-real-window-shared-union-root-v1" or measured.get("scope") != "declared_nonterminal_window_to_shared_recursive_root":
                raise RuntimeError("gate did not attest the joined recursive root mode")
            if not all(measured.get(k) is True for k in ("verified", "canonical_security", "complete_global_closure", "complete_recursive_root", "union_proof")) or any(measured.get(k) is not False for k in ("ethereum_block", "skipped_prefix_proved")):
                raise RuntimeError("joined recursive root has an invalid proof boundary")
            if measured.get("query_count") != 70 or measured.get("pow_bits") != 26 or measured.get("window") != report["window"] or measured.get("segment_cycles") != args.segment_cycles or any(measured.get(k) != report[k] for k in ("elf_sha256", "incoming_sha256", "outgoing_sha256")):
                raise RuntimeError("joined recursive root differs from the selected security or window")
            if getattr(args, "resident_original_stages", False):
                stats = measured.get("stats", {})
                if measured.get("resident_original_stages") is not True or stats.get("resident_original_stages") is not True or stats.get("checkpoint_bytes") != 0:
                    raise ValueError("resident original stages were not attested, or disk checkpoints were still written")
            if getattr(args, "ram_target_components", None) is not None and (measured.get("ram_target_components") != args.ram_target_components or measured.get("stats", {}).get("ram_component_plan") is None):
                raise RuntimeError("joined root ignored the selected RAM component planner")
            detail = json.loads((args.destination / "union-root-verification.json").read_text())
            if detail.get("schema") != "stwo-window-shared-recursive-root-verification-v1" or detail.get("scope") != measured["scope"] or detail.get("verified", {}).get("scope") != "declared_window" or detail.get("source_stark_count") != 1 or detail.get("recursive_stark_count") != 1 or measured.get("artifacts", {}).get("proof_count") != 1:
                raise RuntimeError("joined recursive root lacks an independently verified complete source roster")
            if not all(detail.get(k) is True for k in ("original_proofs_destroyed", "producer_capture_destroyed", "producer_parent_rows_destroyed", "independent_fixed_key_reconstructed", "canonical_security")) or detail.get("query_count") != 70 or detail.get("pow_bits") != 26:
                raise RuntimeError("joined recursive root retained producer authority or changed security")
            for name, size_key, hash_key in (("root.proof", "root_bytes", "root_sha256"), ("union.claims", "claims_bytes", "claims_sha256"), ("union-public.json", "metadata_bytes", "metadata_sha256")):
                raw = (args.destination / name).read_bytes()
                if len(raw) != detail.get(size_key) or hashlib.sha256(raw).hexdigest() != detail.get(hash_key):
                    raise RuntimeError("joined recursive artifact differs from the verified bytes")
        if result.returncode == 0 and reload_union:
            if measured.get("schema") != "stwo-real-window-shared-union-reload-v1" or measured.get("scope") != "fresh_verification_only_of_saved_shared_original" or measured.get("producer_objects_present") is not False or measured.get("complete_recursive_root") is not False or measured.get("verified", {}).get("scope") != "declared_window":
                raise RuntimeError("saved-union loader did not attest fresh verification-only scope")
            if measured.get("query_count") != 70 or measured.get("pow_bits") != 26 or measured.get("window") != report["window"] or any(measured.get(k) != report[k] for k in ("elf_sha256", "incoming_sha256", "outgoing_sha256")):
                raise RuntimeError("saved-union loader differs from selected security or endpoints")
            for name, size_key, hash_key in (("union.proof", "proof_bytes", "proof_sha256"), ("union-public.json", "metadata_bytes", "metadata_sha256")):
                raw = (reload_union / name).read_bytes()
                if len(raw) != measured.get(size_key) or hashlib.sha256(raw).hexdigest() != measured.get(hash_key):
                    raise RuntimeError("saved-union loader verified a different artifact")
        if result.returncode == 0 and (args.cuda_deep or args.cuda_reference):
            gpu = json.loads((args.destination / "gpu" / "cuda-deep-receipt.json").read_text())
            if gpu.get("schema") != "stwo-v7-cuda-deep-v1" or gpu.get("complete_helper_succeeded") is not True or gpu.get("fallback_allowed") is not False or gpu.get("resident_proof") is not False:
                raise RuntimeError("missing verified experimental CUDA DEEP receipt")
            expected = measured["source"]["original_proofs"] + measured["recursive_proof_count"] if args.complete_root else measured["artifacts"]["proof_count"]
            stats = gpu["stats"]
            if gpu.get("gpu_selected") is not args.cuda_deep:
                raise RuntimeError("numeric backend does not match the requested CPU/GPU mode")
            if args.cuda_reference:
                expected = 0
            expansion_launches = stats.get("expansion_kernel_launches", 0)
            if type(expansion_launches) is not int or expansion_launches < 0 or \
                    stats["calls"] != expected or stats["kernel_launches"] != 2 * expected + expansion_launches:
                raise RuntimeError("CUDA did not cover every original and recursive proof")
            if args.cuda_reference and expansion_launches != 0:
                raise RuntimeError("CPU reference unexpectedly ran CUDA coefficient expansion")
        if result.returncode == 0 and args.cuda_composition:
            composition = json.loads((args.destination / "gpu" / "cuda-composition-receipt.json").read_text())
            validate_composition_receipt(composition, measured)
        if result.returncode == 0 and args.cuda_interactions:
            interaction = json.loads((args.destination / "gpu" / "cuda-interaction-receipt.json").read_text())
            validate_interaction_receipt(interaction, measured)
        invocation["report_checked"] = result.returncode == 0
        (args.destination / "invocation.json").write_text(json.dumps(invocation, indent=2) + "\n")
        return result.returncode


def validate_composition_receipt(receipt: dict, report: dict) -> None:
    """Require a real selected stage for every recursive proof, without fallback."""
    if receipt.get("schema") != "stwo-v7-cuda-framework-composition-v1" or \
            receipt.get("complete_helper_succeeded") is not True or \
            receipt.get("fallback_allowed") is not False or receipt.get("resident_proof") is not False:
        raise RuntimeError("missing verified experimental CUDA composition receipt")
    count = report.get("recursive_proof_count")
    stats = receipt.get("stats", {})
    if report.get("external_composition_executor") is not True or \
            type(count) is not int or count <= 0 or stats.get("calls") != count or \
            type(stats.get("kernel_launches")) is not int or stats["kernel_launches"] < count:
        raise RuntimeError("CUDA composition did not cover every recursive proof")


def validate_interaction_receipt(receipt: dict, report: dict) -> None:
    if receipt.get("schema") != "stwo-v7-cuda-framework-interaction-v1" or \
            receipt.get("complete_helper_succeeded") is not True or \
            receipt.get("fallback_allowed") is not False or receipt.get("resident_proof") is not False:
        raise RuntimeError("missing verified experimental CUDA interaction receipt")
    count = report.get("recursive_proof_count")
    stats = receipt.get("stats", {})
    if report.get("external_interaction_executor") is not True or type(count) is not int or count <= 0 or \
            receipt.get("cohorts_per_parent") != 25 or stats.get("calls") != 25 * count or stats.get("kernel_launches") != 100 * count:
        raise RuntimeError("CUDA interactions did not cover every recursive cohort")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--snapshots", type=Path, required=True)
    parser.add_argument("--capture-sha256", required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--build-manifest", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--segment-cycles", type=int, default=16384)
    parser.add_argument("--complete-root", action="store_true",
                        help="use the complete-root gate with canonical q70/26 security")
    parser.add_argument("--shared-union", action="store_true", help="use the CPU shared-original union gate; this is not a recursive-root benchmark")
    parser.add_argument("--shared-union-root", action="store_true", help="use one shared original and its single CPU recursive verifier, at canonical q70/26")
    parser.add_argument("--resident-original-stages", action="store_true", help="keep original native witnesses and coefficient trees resident; CPU joined recursive gate only")
    parser.add_argument("--ram-target-components", type=int, help="explicit target for recursion-aware RAM sizing; joined recursive CPU gate only")
    parser.add_argument("--reload-union", type=Path, help="verify saved union.proof and union-public.json against pinned endpoints without proving again")
    parser.add_argument("--workers", type=int, default=4,
                        help="total CPU workers, including coordinator (1..32)")
    parser.add_argument("--native-layout", choices=("canonical", "degree-bounded-q2"), default="canonical")
    parser.add_argument("--fused-projection-rows", action="store_true", help="build typed row entries once for all native physical projections; unchanged proof protocol")
    parser.add_argument("--sparse-initialization", action="store_true",
                        help="derive allowed first-touch values from the pinned complete incoming snapshot")
    parser.add_argument("--resident-memory", action="store_true",
                        help="retain RAM witness and interaction evaluations instead of coefficients")
    parser.add_argument("--native-main-cache-mib", type=int, default=256)
    parser.add_argument("--deep-group-mib", type=int, choices=(1, 4, 8), default=1)
    parser.add_argument("--root-preparation-mib", type=int, default=8192)
    parser.add_argument("--root-row-log", type=int, default=25)
    parser.add_argument("--root-batch-size", type=int, default=0,
                        help="0: direct complete root; 1..64: bounded direct batches plus one reduction")
    parser.add_argument("--root-parallel-families", type=int, choices=(1, 2, 4), default=1)
    parser.add_argument("--root-parallel-preparation", type=int, choices=(1, 2, 4), default=1)
    parser.add_argument("--reuse-native-compiler", action="store_true")
    parser.add_argument("--shared-epoch-prefix", action="store_true", help="prove common original epoch challenge generation once; explicit distinct recursive key")
    parser.add_argument("--materialized-parent-polynomials", action="store_true", help="retain parent evaluations to trade host memory for less repeated polynomial work")
    parser.add_argument("--reuse-original-captures", action="store_true", help="retain the full original receiver's owned captures for direct recursive preparation")
    parser.add_argument("--original-capture-mib", type=int, default=4096)
    parser.add_argument("--native-compiler-mib", type=int, default=2048)
    parser.add_argument("--profile-root", action="store_true")
    parser.add_argument("--cuda-deep", action="store_true", help="require actual CUDA DEEP for every proof; other stages remain CPU")
    parser.add_argument("--cuda-reference", action="store_true", help="explicit zero-GPU reference mode of the same experimental executable")
    parser.add_argument("--cuda-composition", action="store_true", help="require CUDA composition for every recursive parent; needs --complete-root --cuda-deep")
    parser.add_argument("--cuda-interactions", action="store_true", help="require CUDA fractions and scans for all25 parent interaction cohorts")
    parser.add_argument("--cuda-device", type=int, default=0)
    parser.add_argument("--cuda-sm", type=int, default=90)
    parser.add_argument("--cuda-device-mib", type=int, default=16384)
    args = parser.parse_args()
    if not 0 < args.segment_cycles < 1 << 26:
        parser.error("segment cycles must be positive and below 2^26")
    if not 1 <= args.workers <= 32:
        parser.error("workers must be 1..32")
    if not 0 <= args.native_main_cache_mib <= 2048:
        parser.error("native MAIN cache must be 0..2048 MiB")
    if not 1 <= args.native_compiler_mib <= 32768 or (args.reuse_native_compiler and not args.complete_root):
        parser.error("native compiler reuse needs a complete root and 1..32768 MiB cap")
    if args.cuda_device < 0 or args.cuda_sm < 1 or not 1 <= args.cuda_device_mib <= 196608:
        parser.error("invalid CUDA numeric device policy")
    if args.cuda_reference and args.cuda_deep:
        parser.error("select either CPU reference or CUDA DEEP")
    if args.cuda_composition and not (args.complete_root and args.cuda_deep):
        parser.error("CUDA composition needs --complete-root --cuda-deep")
    if args.cuda_interactions and not (args.complete_root and args.cuda_deep):
        parser.error("CUDA interactions need --complete-root --cuda-deep")
    if args.shared_epoch_prefix and (not args.complete_root or args.root_batch_size or args.root_row_log > 25 or args.root_parallel_families != 1):
        parser.error("shared epoch prefix needs a direct complete root, row log at most25 and serial cold families")
    if args.materialized_parent_polynomials and not args.complete_root:
        parser.error("materialized parent polynomials need --complete-root")
    if not 1 <= args.original_capture_mib <= 16384 or (args.reuse_original_captures and (not args.complete_root or args.root_batch_size)):
        parser.error("original capture reuse needs a direct complete root and1..16384MiB cap")
    if not 1 <= args.root_preparation_mib <= 32768 or not 1 <= args.root_row_log <= 27 or not 0 <= args.root_batch_size <= 64:
        parser.error("invalid recursive resource limit")
    if args.root_batch_size and args.root_row_log > 25:
        parser.error("the bounded recursive planner currently admits row logs through 25")
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
