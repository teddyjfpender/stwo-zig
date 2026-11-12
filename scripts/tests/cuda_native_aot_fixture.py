"""One process-local cache product for tests that consume Native CUDA AOT."""

from __future__ import annotations

import atexit
import os
import shutil
import subprocess
import tempfile
import unittest
from functools import lru_cache
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
_TEMPORARY: tempfile.TemporaryDirectory | None = None


@lru_cache(maxsize=1)
def native_aot_root() -> Path:
    override = os.environ.get("STWO_CUDA_NATIVE_AOT_ROOT")
    if override:
        root = Path(override).resolve()
        if not (root / "aot_manifest.json").is_file():
            raise RuntimeError(f"Native CUDA AOT fixture is absent: {root}")
        return root

    zig = shutil.which("zig")
    if zig is None:
        raise unittest.SkipTest("Zig compiler unavailable")
    global _TEMPORARY
    _TEMPORARY = tempfile.TemporaryDirectory(prefix="stwo-native-cuda-aot-")
    atexit.register(_TEMPORARY.cleanup)
    temporary = Path(_TEMPORARY.name)
    executable = temporary / "cairo-cuda-witness-aot"
    compile_process = subprocess.run(
        [
            zig,
            "build-exe",
            "-OReleaseFast",
            "--dep",
            "cairo_witness_model",
            f"-Mroot={ROOT / 'src/products/cairo/tools/cuda_witness_aot/main.zig'}",
            "--dep",
            "cairo_deduction_contract",
            f"-Mcairo_witness_model={ROOT / 'src/products/cairo/tools/witness_cpu_codegen/model.zig'}",
            f"-Mcairo_deduction_contract={ROOT / 'src/frontends/cairo/witness/deduction_contract.zig'}",
            f"-femit-bin={executable}",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if compile_process.returncode != 0:
        raise RuntimeError(
            "cannot compile Native CUDA AOT fixture:\n"
            + compile_process.stdout
            + compile_process.stderr
        )
    product = temporary / "cuda"
    generate_process = subprocess.run(
        [
            executable,
            ROOT / "vectors/cairo/sn_pie_2_witness_programs.bin",
            ROOT / "src/backends/cuda/aot/native",
            ROOT / "src/backends/cuda/authority/active",
            ROOT / "src/backends/cuda/native",
            product,
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if generate_process.returncode != 0:
        raise RuntimeError(
            "cannot generate Native CUDA AOT fixture:\n"
            + generate_process.stdout
            + generate_process.stderr
        )
    root = product / "aot/native"
    if not (root / "aot_manifest.json").is_file():
        raise RuntimeError("Native CUDA AOT fixture did not publish its manifest")
    return root


EXPECTED_NATIVE_IMPLEMENTATION_SOURCES = {
    "host": {"aot_loader.cpp"},
    "runtime": {"runtime/context.cu"},
    "trace": {
        "kernels/wide_fibonacci_trace.cu",
        "kernels/xor_trace.cu",
    },
    "cairo": {
        "cairo/casm_input.cu",
        "cairo/eval_params.cu",
        "cairo/memory_base.cu",
        "cairo/memory_execution.cu",
        "cairo/witness_edge.cu",
        "cairo/witness_compact_v2.cu",
        "cairo/witness_multi_edge.cu",
        "cairo/witness_seed.cu",
    },
    "circuit": {
        "circuit/base_witness.cu",
        "circuit/interaction_fractions.cu",
        "circuit/lookup_sum.cu",
    },
    "commitment": {
        "commitment/merkle.cu",
        "commitment/progressive.cu",
    },
    "constraint": {
        "constraints/powers.cu",
    },
    "witness": {"witness/active_feeds.cu"},
    "transform": {
        "transform/b2n_retained.cu",
        "transform/composition_split.cu",
        "transform/lde.cu",
        "transform/n2b.cu",
    },
    "oods": {
        "oods/barycentric.cu",
        "oods/evaluate.cu",
    },
    "transcript": {
        "transcript/transcript.cu",
    },
    "quotient": {
        "quotient/combine.cu",
        "quotient/numerator.cu",
        "quotient/prepare.cu",
    },
    "fri": {
        "fri/final.cu",
        "fri/fold.cu",
    },
    "pow": {
        "pow/search.cu",
    },
    "relation": {
        "relation/batch_inverse.cu",
        "relation/graph.cu",
    },
    "decommit": {
        "decommit/fri.cu",
        "decommit/query_planning.cu",
        "decommit/sparse_parents.cu",
        "decommit/trace.cu",
    },
    "riscv_and_shared_extensions": set("""
        rv64/arith256_witness.cu rv64/arithmetic_witness.cu rv64/batch.cu
        rv64/batch_oracles.cu rv64/binding.cu rv64/bridge_witness.cu
        rv64/bulk_witness.cu rv64/channel.cu rv64/circuit_assignment.cu
        rv64/circuit_fill_chain.cu rv64/circuit_interaction.cu rv64/closure.cu
        rv64/composition_finalize.cu rv64/cpu_witness.cu rv64/curve_witness.cu
        rv64/deep.cu rv64/events.cu rv64/family_witness.cu
        rv64/fri.cu rv64/fused_blake2s.cu rv64/gkr.cu
        rv64/gkr_loop.cu rv64/global.cu rv64/jobs/channel_ops.cu
        rv64/jobs/native_composition.cu rv64/jobs/native_encode_checks.cu rv64/jobs/native_encode_oods.cu
        rv64/jobs/native_encode_proof.cu rv64/jobs/native_gkr_wire.cu rv64/jobs/native_leaf_wire.cu
        rv64/jobs/native_manifest_wire.cu rv64/jobs/native_parity.cu rv64/jobs/native_seal_chi.cu
        rv64/jobs/native_witness_stage1.cu rv64/jobs/oods_points.cu rv64/jobs/outer_checks.cu
        rv64/jobs/outer_encode.cu rv64/jobs/outer_graph.cu rv64/jobs/outer_packed_class.cu
        rv64/jobs/outer_rc_params.cu rv64/jobs/outer_seed.cu rv64/jobs/pcs_enqueue.cu
        rv64/jobs/peer_ops.cu rv64/jobs/runtime.cu rv64/jobs/truth_oods.cu
        rv64/jobs/truth_ops.cu rv64/keccak_witness.cu rv64/ls_dword_witness.cu
        rv64/m9_class_unpack.cu rv64/memory_witness.cu rv64/outer_fs_ops.cu
        rv64/outer_gkr_binding.cu rv64/outer_gkr_projected.cu rv64/parameters.cu
        rv64/pcs.cu rv64/pcs_native.cu rv64/rc_sparse_lde.cu
        rv64/round.cu rv64/sample_order.cu rv64/samples.cu
        rv64/secp_witness.cu rv64/sha256_witness.cu rv64/sponge_witness.cu
        rv64/tail.cu rv64/trace.cu
    """.split()),
}
