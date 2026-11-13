#!/usr/bin/env python3
"""Run the narrowest package-owned tests for local worktree changes."""

from __future__ import annotations

import argparse
from contextlib import nullcontext
import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
OPTIMIZE_MODES = ("Debug", "ReleaseSafe", "ReleaseFast", "ReleaseSmall")
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.repo import ci_package_graph, ci_scope_plan, ci_scope_push, ci_scope_run, zig_serial_build
from scripts.repo.ci_scope_plan import normalize_path, owns


FOCUSED_RULES = (
    ("stwo_ethereum_statement", "src/products/ethereum/statement/cpu/word16_execution/alu_fused_tail_proof_test.zig", "test-word16-alu-fused-tail-proof"),
    ("stwo_ethereum_statement", "src/products/ethereum/statement/cpu/word16_execution/alu_read_induction_proof_test.zig", "test-word16-alu-read-induction-proof"),
    ("stwo_ethereum_statement", "src/products/ethereum/statement/cpu/word16_execution/cpu_clock_induction_proof_test.zig", "test-word16-cpu-clock-induction-proof"),
    ("stwo_ethereum_statement", "src/products/ethereum/statement/cpu/word16_execution/cpu_compact_decode_proof_test.zig", "test-word16-cpu-compact-decode-proof"),
    ("stwo_ethereum_statement", "src/products/ethereum/statement/cpu/word16_execution/cpu_fused_tail_proof_test.zig", "test-word16-cpu-fused-tail-proof"),
    ("stwo_ethereum_statement", "src/products/ethereum/statement/cpu/word16_execution/cpu_u8_pairs_proof_test.zig", "test-word16-cpu-u8-pairs-proof"),
    ("stwo_ethereum_statement", "src/products/ethereum/statement/cpu/word16_execution/cpu_zero_induction_proof_test.zig", "test-word16-cpu-zero-induction-proof"),
    ("stwo_ethereum_statement", "src/products/ethereum/statement/cpu/word16_execution/ls_fused_pairs_proof_test.zig", "test-word16-ls-fused-pairs-proof"),
    ("stwo_ethereum_statement", "src/products/ethereum/statement/cpu/word16_execution/memory/boundary_anchor_test.zig", "test-word16-boundary-anchor"),
    ("stwo_ethereum_statement", "src/products/ethereum/statement/cpu/word16_execution/memory/joint_write_proof_test.zig", "test-word16-joint-write-proof"),
    ("stwo_ethereum_statement", "src/products/ethereum/statement/cpu/word16_execution/memory/range_induction_proof_test.zig", "test-word16-range-induction-proof"),
    ("stwo_ethereum_statement", "src/products/ethereum/statement/cpu/word16_execution/mul_u8_pairs_proof_test.zig", "test-word16-mul-u8-pairs-proof"),
    ("stwo_ethereum_statement", "src/products/ethereum/statement/cpu/word16_execution/shift_read_induction_proof_test.zig", "test-word16-shift-read-induction-proof"),
    ("stwo_ethereum_statement", "src/products/ethereum/statement/cpu/rv64_ethereum_image_admission_test_root.zig", "test-receiver-boundaries"),
    ("stwo_ethereum_statement", "src/products/ethereum/statement/cpu/rv64_ethereum_receiver_boundary_test_root.zig", "test-receiver-boundaries"),
    ("stwo_ethereum_statement", "src/products/ethereum/statement/cpu/tests/rv64_ethereum_chain_test.zig", "test-receiver-boundaries"),
    ("stwo_ethereum_statement", "src/products/ethereum/statement/cpu/tests/rv64_word16_execution_image_test.zig", "test-receiver-boundaries"),
    ("stwo_ethereum_statement", "src/products/ethereum/statement/cpu/rv64_gkr_resources_test_root.zig", "test-gkr-resources"),
    ("stwo_ethereum_statement", "src/products/ethereum/statement/cpu/word16_global_execution/ethereum/gkr_resources.zig", "test-gkr-resources"),
    ("stwo_ethereum_statement", "src/products/ethereum/statement/cpu/word16_global_execution/ethereum/gkr_resources_test.zig", "test-gkr-resources"),
    ("stwo_ethereum_statement", "src/products/ethereum/statement/cpu/rv64_capture_prefetch_test_root.zig", "test-capture-prefetch"),
    ("stwo_ethereum_statement", "src/products/ethereum/statement/cpu/word16_global_execution/ethereum/capture_prefetch_test.zig", "test-capture-prefetch"),
    ("stwo_ethereum_statement", "src/products/ethereum/statement/cpu/word16_global_execution/ethereum/capture_test_support.zig", "test-capture-prefetch"),
    ("stwo_ethereum_statement", "src/products/ethereum/statement/cpu/rv64_setup_cache_test_root.zig", "test-setup-cache"),
    ("stwo_ethereum_statement", "src/products/ethereum/statement/cpu/word16_global_execution/ethereum/setup_cache.zig", "test-setup-cache"),
    ("stwo_ethereum_statement", "src/products/ethereum/statement/cpu/word16_global_execution/ethereum/setup_cache_format.zig", "test-setup-cache"),
    ("stwo_ethereum_statement", "src/products/ethereum/statement/cpu/word16_global_execution/ethereum/setup_cache_test.zig", "test-setup-cache"),
    ("stwo_ethereum_statement", "src/products/ethereum/statement/cpu/rv64_services_gkr_policy_test_root.zig", "test-services-gkr-policy"),
    ("stwo_ethereum_statement", "src/products/ethereum/statement/cpu/rv64_word16_services_test_root.zig", "test-word16-services"),
    ("stwo_ethereum_statement", "src/products/ethereum/statement/cpu/rv64_word16_zbb_services_test_root.zig", "test-word16-zbb-services"),
    ("stwo_ethereum_statement", "src/products/ethereum/statement/cpu/rv64_word16_sponge_services_test_root.zig", "test-word16-sponge-services"),
    ("stwo_ethereum_statement", "src/products/ethereum/statement/cpu/rv64_word16_ls_dword_services_test_root.zig", "test-word16-ls-dword-services"),
    ("stwo_ethereum_statement", "src/products/ethereum/statement/cpu/rv64_services_recursion_test_root.zig", "test-services-recursion"),
    ("stwo_ethereum_statement", "src/products/ethereum/statement/build_components.zig", "test-build-components"),
    ("stwo_ethereum_statement", "src/products/ethereum/statement/build_components_test.zig", "test-build-components"),
    ("stwo_riscv_frontend", "src/frontends/riscv/compat/assembly/recursion/vm_composition_preparation.zig", "test-composition-custody"),
    ("stwo_ethereum_statement", "src/products/ethereum/statement/frontend/recursion/vm_composition_preparation.zig", "test-composition-custody"),
    ("stwo_ethereum_statement", "src/products/ethereum/statement/frontend/recursion/initial_wrapper_admission.zig", "test-composition-custody"),
    ("stwo_ethereum_statement", "src/products/ethereum/statement/tests/coordinator_boundary_test.zig", "test-component-boundaries"),
    ("stwo_ethereum_statement", "src/products/ethereum/statement/tests/composition_custody_test.zig", "test-component-boundaries"),
    ("stwo_ethereum_statement", "src/products/ethereum/statement/cpu/csp_ecdsa_proof_test.zig", "test-csp-ecdsa-proof"),
    ("stwo_riscv_cpu_integration", "src/integrations/riscv_cpu/rv64_proof_artifact_support.zig", "test-proof-artifact-support"),
    ("stwo_riscv_cpu_integration", "src/integrations/riscv_cpu/tests/proof_artifact_support_contract_test.zig", "test-proof-artifact-support"),
    ("stwo_riscv_frontend", "src/frontends/riscv/precompiles/focused_test_guest_precompile_0.zig", "test-guest-precompile"),
    ("stwo_riscv_frontend", "src/frontends/riscv/rv32/air/extract/runtime_program.zig", "test-runtime-selector"),
    ("stwo_riscv_frontend", "src/frontends/riscv/rv32/focused_test_runtime_selector_0.zig", "test-runtime-selector"),
    ("stwo_riscv_frontend", "src/frontends/riscv/air_lang/framework/control_row.zig", "test-recursion-framework-interaction"),
    ("stwo_riscv_frontend", "src/frontends/riscv/compat/tests/testing/cases/recursion/tests/segment_leaf_local_projection_test.zig", "test-retained-transcript-contracts"),
    ("stwo_ethereum_statement", "src/products/ethereum/statement/frontend/recursion/tests/ethereum_vm_composition_program_test.zig", "test-ethereum-composition-program"),
    ("stwo_riscv_cpu_integration", "src/integrations/riscv_cpu/recursive_segment_detached_child_transcript.zig", "test-detached-child-capture"),
    ("stwo_riscv_frontend", "src/frontends/riscv/testing/cases/air/lang/tests/runtime_profile_test.zig", "test-air-runtime-profile"),
    ("stwo_riscv_cpu_integration", "src/integrations/riscv_cpu/blake3_proof_tests", "test-blake3-proof-contracts"),
    ("stwo_riscv_cpu_integration", "src/integrations/riscv_cpu/blake3_proof_contract_test_root.zig", "test-blake3-proof-contracts"),
    ("stwo_riscv_cpu_integration", "src/integrations/riscv_cpu/blake3_memory_path_proof_test_root.zig", "test-blake3-proof-contracts"),

    ("stwo_riscv_frontend", "src/frontends/riscv/rv32/air/lang/function_activation_logup_test_support.zig", "test-retained-authority-contracts"),
    ("stwo_riscv_frontend", "src/frontends/riscv/compat/tests/testing/cases/air/lang/tests/function_activation_logup_test.zig", "test-retained-authority-contracts"),
    ("stwo_riscv_frontend", "src/frontends/riscv/testing/cases/air/guest_precompile/tests/sha256_memory_caller_test.zig", "test-retained-authority-contracts"),
    ("stwo_riscv_frontend", "src/frontends/riscv/compat/tests/testing/cases/recursion/air/tests/blake3_draw_witness_test.zig", "test-retained-authority-contracts"),
    ("stwo_riscv_cpu_integration", "src/integrations/riscv_cpu/rv64_distributed/functional_test.zig", "test-distributed-binary-contracts"),
    ("stwo_riscv_cpu_integration", "src/integrations/riscv_cpu/rv64_distributed/unified_test.zig", "test-distributed-binary-contracts"),
    ("stwo_riscv_frontend", "src/frontends/riscv/recursion_air/tests/blake3_rejection_fixture_test_support.zig", "test-retained-authority-contracts"),
    ("stwo_riscv_cpu_integration", "src/integrations/riscv_cpu/rv64_poseidon2_native_fixture_main.zig", "poseidon2-native-fixture"),
    ("stwo_riscv_cpu_integration", "src/integrations/riscv_cpu/keccakf_precompile_proof_test.zig", "test-keccakf-precompile-proof"),
    ("stwo_riscv_cpu_integration", "src/integrations/riscv_cpu/secp256k1_precompile_proof_test.zig", "test-secp256k1-precompile-proof"),
    ("stwo_riscv_cpu_integration", "src/integrations/riscv_cpu/universal_typed_component_proof_test.zig", "test-universal-typed-proof"),
    ("stwo_riscv_cpu_integration", "src/integrations/riscv_cpu/universal_typed_component_proof_test_support.zig", "test-universal-typed-proof"),
    ("stwo_riscv_cpu_integration", "src/integrations/riscv_cpu/rv64_poseidon2_native_test_root.zig", "test-poseidon2-native-cpu"),
    ("stwo_riscv_cpu_integration", "src/integrations/riscv_cpu/word16_global_execution/services/poseidon2_native", "test-poseidon2-native-cpu"),
    ("stwo_riscv_frontend", "src/frontends/riscv/recursion/tests/fri_profile_frontier_test.zig", "test-retained-fri-frontier"),
    ("stwo_riscv_cpu_integration", "src/integrations/riscv_cpu/word16_image_program_contract_test_root.zig", "test-word16-image-program-contracts"),
    ("stwo_riscv_cpu_integration", "src/integrations/riscv_cpu/tests/rv64_word16_execution_image_test.zig", "test-word16-image-program-contracts"),
    ("stwo_riscv_cpu_integration", "src/integrations/riscv_cpu/tests/rv64_word16_execution_program_test.zig", "test-word16-image-program-contracts"),
    ("stwo_riscv_cpu_integration", "src/integrations/riscv_cpu/tests/rv64_word16_execution_false_prover_test_support.zig", "test-word16-image-program-contracts"),
    ("stwo_riscv_cpu_integration", "src/integrations/riscv_cpu/word16_execution/native_diagnostic_test_support.zig", "test-word16-image-program-contracts"),
    ("stwo_riscv_cpu_integration", "src/integrations/riscv_cpu/distributed_binary_contract_test_root.zig", "test-distributed-binary-contracts"),
    ("stwo_riscv_cpu_integration", "src/integrations/riscv_cpu/rv64_distributed/manifest_test.zig", "test-distributed-binary-contracts"),
    ("stwo_riscv_cpu_integration", "src/integrations/riscv_cpu/rv64_distributed_execution/binary_worker_test.zig", "test-distributed-binary-contracts"),
    ("stwo_riscv_frontend", "src/frontends/riscv/compat/tests/testing/cases/recursion/air/tests/universal_typed_component_test.zig", "test-retained-typed-components"),
    ("stwo_riscv_frontend", "src/frontends/riscv/compat/tests/testing/cases/recursion/air/tests/universal_typed_quotient_test.zig", "test-retained-typed-components"),
    ("stwo_riscv_frontend", "src/frontends/riscv/compat/tests/testing/cases/recursion/air/tests/universal_typed_component_test_support.zig", "test-retained-typed-components"),
    ("stwo_riscv_frontend", "src/frontends/riscv/recursion_air/tests/qm31_mul_full_relation_test_support.zig", "test-retained-typed-components"),
    ("stwo_riscv_frontend", "src/frontends/riscv/recursion/tests/scheduled_channel_test_support.zig", "test-retained-transcript-contracts"),
    ("stwo_riscv_frontend", "src/frontends/riscv/recursion/tests/transcript_program_v2_test.zig", "test-retained-transcript-contracts"),

    ("stwo_core", "src/waist/core/air_components_test_root.zig", "test-air-components"),
    ("stwo_core", "src/waist/core/tests/borrowed_proof_capture_root.zig", "test-proof-capture"),
    ("stwo_core", "src/waist/core/tests/borrowed_proof_capture_test.zig", "test-proof-capture"),
    ("stwo_core", "src/waist/core/tests/borrowed_pcs_capture_success_test.zig", "test-proof-capture"),

    ("stwo_riscv_frontend", "src/frontends/riscv/testing/cases/air/guest_precompile/tests/relation_test.zig", "test-retained-authority-contracts"),
    ("stwo_riscv_frontend", "src/frontends/riscv/recursion/tests/segment_range_authority_test.zig", "test-retained-authority-contracts"),
    ("stwo_riscv_cpu_integration", "src/integrations/riscv_cpu/word16_execution/division_product_integration_test.zig", "test-division-contracts"),
    ("stwo_riscv_cpu_integration", "src/integrations/riscv_cpu/word16_execution/optional_division_test.zig", "test-division-contracts"),
    ("stwo_riscv_cpu_integration", "src/integrations/riscv_cpu/word16_global_execution/services/gkr_local/metadata_test.zig", "test-services-truth-contracts"),
    ("stwo_riscv_cpu_integration", "src/integrations/riscv_cpu/word16_global_execution/services/gkr_local/truth_test.zig", "test-services-truth-contracts"),
    ("stwo_riscv_cpu_integration", "src/integrations/riscv_cpu/word16_global_execution/services/gkr_local/truth_worker_test.zig", "test-services-truth-contracts"),
    ("stwo_riscv_frontend", "src/frontends/riscv/recursion/tests/claim_relation_test_support.zig", "test-retained-authority-contracts"),
    ("stwo_riscv_cpu_integration", "src/integrations/riscv_cpu/word16_execution/measurement_test_support.zig", "test-word16-image-program-contracts"),
    ("stwo_riscv_cpu_integration", "src/integrations/riscv_cpu/word16_global_execution/services/gkr_local/dispatch_test_support.zig", "test-services-truth-contracts"),
    ("stwo_riscv_cpu_integration", "src/integrations/riscv_cpu/word16_global_execution/services/gkr_local/truth_inputs_test_support.zig", "test-services-truth-contracts"),
    ("stwo_riscv_cpu_integration", "src/integrations/riscv_cpu/division_contract_test_root.zig", "test-division-contracts"),
    ("stwo_riscv_cpu_integration", "src/integrations/riscv_cpu/services_truth_contract_test_root.zig", "test-services-truth-contracts"),

    ("stwo_riscv_frontend", "src/frontends/riscv/test_inventory.zig", "test-inventory"),
    ("stwo_riscv_frontend", "src/frontends/riscv/rv64_test_inventory.zig", "test-inventory"),
    ("stwo_riscv_cuda_integration", "src/integrations/riscv_cuda/rv64/jobs/gpu_native_classes.zig", "test-rv64-class-cache"),
    ("stwo_riscv_cuda_integration", "src/integrations/riscv_cuda/rv64/jobs/gpu_native_protocol.zig", "test-rv64-class-cache"),
    ('stwo_riscv_metal_integration', 'src/integrations/riscv_metal/native_polynomial_aot_export.zig', 'test-native-polynomial-aot'),
    ('stwo_riscv_metal_integration', 'src/integrations/riscv_metal/native_polynomial_aot_test_root.zig', 'test-native-polynomial-aot'),
    ('stwo_metal_backend', 'src/backends/metal/composition_pool_test_root.zig', 'test-resource-contracts'),
    ('stwo_metal_backend', 'src/backends/metal/external_allocation_admission_test_root.zig', 'test-resource-contracts'),
    ('stwo_metal_backend', 'src/backends/metal/fri_budget_test_root.zig', 'test-resource-contracts'),
    ('stwo_metal_backend', 'src/backends/metal/fri_inverse_lease_test_root.zig', 'test-resource-contracts'),
    ('stwo_metal_backend', 'src/backends/metal/quotient_allocation_budget_test_root.zig', 'test-resource-contracts'),
    ('stwo_metal_backend', 'src/backends/metal/quotient_result_ownership_test_root.zig', 'test-resource-contracts'),
    ('stwo_metal_backend', 'src/backends/metal/resident_budget_test_root.zig', 'test-resource-contracts'),
    ('stwo_metal_backend', 'src/backends/metal/sampled_budget_test_root.zig', 'test-resource-contracts'),
    ("stwo_riscv_cpu_integration", "src/integrations/riscv_cpu/rv64_recursion/om31_native/ready_dag.zig", "test-recursion-dag"),
    ("stwo_riscv_cpu_integration", "src/integrations/riscv_cpu/rv64_recursion/om31_native/publication.zig", "test-recursion-publication"),
    ("stwo_core", "src/waist/core/fields", "test-fields"),
    ("stwo_core", "src/waist/core/fields_test_root.zig", "test-fields"),
    ("stwo_core", "src/waist/core/crypto", "test-crypto"),
    ("stwo_core", "src/waist/core/crypto_test_root.zig", "test-crypto"),
    ("stwo_core", "src/waist/core/fri", "test-fri"),
    ("stwo_core", "src/waist/core/fri_test_root.zig", "test-fri"),
    ("stwo_core", "src/waist/core/pcs", "test-pcs"),
    ("stwo_core", "src/waist/core/pcs_test_root.zig", "test-pcs"),
    ("stwo_prover_engine", "src/engine/prover/air", "test-air"),
    ("stwo_prover_engine", "src/engine/prover/air_test_root.zig", "test-air"),
    ("stwo_prover_engine", "src/engine/prover/poly", "test-poly"),
    ("stwo_prover_engine", "src/engine/prover/poly_test_root.zig", "test-poly"),
    ("stwo_prover_engine", "src/engine/prover/pcs", "test-pcs-commitments"),
    (
        "stwo_prover_engine",
        "src/engine/prover/pcs_commitments_test_root.zig",
        "test-pcs-commitments",
    ),
    ("stwo_riscv_frontend", "src/frontends/riscv/isa", "test-isa"),
    ("stwo_riscv_frontend", "src/frontends/riscv/runner", "test-runner"),
    ("stwo_riscv_frontend", "src/frontends/riscv/rv32/focused_benchmark_minimal_trace_parallel_replay_0.zig", "test-runner"),
    (
        "stwo_riscv_frontend",
        "src/frontends/riscv/air/semantics",
        "test-air-semantics",
    ),
    (
        "stwo_riscv_frontend",
        "src/frontends/riscv/rv32/focused_test_air_semantics_0.zig",
        "test-air-semantics",
    ),
    ("stwo_sm83_frontend", "src/frontends/sm83/isa", "test-isa"),
    ("stwo_sm83_frontend", "src/frontends/sm83/runner", "test-runner"),
    (
        "stwo_sm83_frontend",
        "src/frontends/sm83/runner_test_root.zig",
        "test-runner",
    ),
)

PROVER_QUOTIENT_STEPS = {
    "src/engine/prover/pcs/quotient_column_geometry.zig": "test-pcs-quotient-geometry",
    "src/engine/prover/pcs/quotient_domain_walk.zig": "test-pcs-quotient-geometry",
    "src/engine/prover/pcs_quotient_geometry_test_root.zig": "test-pcs-quotient-geometry",
    "src/engine/prover/pcs/quotient_compact_groups.zig": "test-pcs-quotient-planning",
    "src/engine/prover/pcs/quotient_direct_groups.zig": "test-pcs-quotient-planning",
    "src/engine/prover/pcs/quotient_direct_plan.zig": "test-pcs-quotient-planning",
    "src/engine/prover/pcs/quotients/planning.zig": "test-pcs-quotient-planning",
    "src/engine/prover/pcs_quotient_planning_test_root.zig": "test-pcs-quotient-planning",
    "src/engine/prover/pcs/quotient_ops.zig": "test-pcs-quotient-ops",
    "src/engine/prover/pcs_quotient_ops_test_root.zig": "test-pcs-quotient-ops",
    "src/engine/prover/pcs/quotient_row_executor.zig": "test-pcs-quotient-rows",
    "src/engine/prover/pcs/quotient_scalar_executor.zig": "test-pcs-quotient-rows",
    "src/engine/prover/pcs/quotients/execution.zig": "test-pcs-quotient-rows",
    "src/engine/prover/pcs/quotients/lazy_provider.zig": "test-pcs-quotient-rows",
    "src/engine/prover/pcs_quotient_rows_test_root.zig": "test-pcs-quotient-rows",
    "src/engine/prover/pcs/quotient_tile_executor.zig": "test-pcs-quotient-tiles",
    "src/engine/prover/pcs/quotient_tile_sink.zig": "test-pcs-quotient-tiles",
    "src/engine/prover/pcs_quotient_tiles_test_root.zig": "test-pcs-quotient-tiles",
}


class DevTestError(ValueError):
    pass


def worktree_paths(root: Path) -> list[str]:
    tracked = subprocess.run(
        ["git", "diff", "--name-only", "-z", "HEAD", "--"],
        cwd=root,
        check=True,
        capture_output=True,
    ).stdout
    untracked = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
    ).stdout
    return sorted({
        normalize_path(raw.decode("utf-8", errors="strict"))
        for raw in (tracked + untracked).split(b"\0")
        if raw
    })


def frontend_root_step(root: Path, path: str) -> str | None:
    catalog = root / "src/frontends/riscv/build_focused_tests.zig"
    if not catalog.is_file():
        return None
    matches: list[tuple[str, int]] = []
    for step, body in re.findall(
        r'\.\{\s*\.step = "([^"\n]+)"(.*?)\n    \},', catalog.read_text(), re.S,
    ):
        source = re.search(r'^\s*\.root = "([^"\n]+)",', body, re.M)
        floor = re.search(r'^\s*\.minimum = ([0-9][0-9_]*),', body, re.M)
        partitions = re.search(r'\.partition_roots = &\.\{(.*?)\}', body, re.S)
        sources = ([source[1]] if source else []) + (
            re.findall(r'"([^"\n]+)"', partitions[1]) if partitions else []
        )
        if path in {"src/frontends/riscv/" + name for name in sources}:
            matches.append((step, int(floor[1].replace("_", "")) if floor else 0))
    if len(matches) != 1:
        return None
    step, minimum = matches[0]
    return step if step.startswith("test-") and minimum > 0 else None


def focus_step(package: str, path: str, root: Path = ROOT) -> str | None:
    if package == "stwo_metal_backend":
        for owner, filename, step in FOCUSED_RULES:
            if owner == package:
                source = root / filename
                imports = re.findall(r'@import\("([^"\n]+)"\)', source.read_text())
                if path == filename or path in {(source.parent / name).relative_to(root).as_posix() for name in imports if name.endswith(".zig")}:
                    return step
    if package == "stwo_riscv_cuda_integration":
        directory = "src/integrations/riscv_cuda/"
        resource_root = "rv64_resources_test_root.zig"
        imports = re.findall(r'@import\("([^"\n]+)"\)', (root / directory / resource_root).read_text())
        resources = {directory + name for name in imports}
        # Include only test files actually imported by an owned module;
        # guessing sibling names could silently omit a newly added test.
        for module in tuple(resources):
            text = (root / module).read_text()
            tests = re.findall(r'@import\("([^"\n]+_test\.zig)"\)', text)
            resources.update((Path(module).parent / name).as_posix() for name in tests)
        if path == directory + resource_root or path in resources:
            return "test-rv64-resources"
        node = {"outer_job.zig", "outer_encode_job.zig", "outer_result.zig"}
        runtime = {"api.zig", "api_test.zig", "worker.zig", "worker_test.zig",
                   "channel.zig", "slab.zig", "plan.zig", "plan_test.zig", "lint.zig",
                   "fake.zig", "retained.zig", "retained_test.zig", "driver.zig",
                   "driver_request.zig", "driver_install.zig", "driver_dag.zig", "driver_memory.zig", "driver_test.zig",
                   "driver_fixture_test.zig", "driver_service_test.zig"}
        prefix = "src/integrations/riscv_cuda/rv64/jobs/"
        if path.startswith(prefix) and path[len(prefix):] in node:
            return "test-rv64-jobs-node"
        if path.startswith(prefix) and path[len(prefix):] in runtime:
            return "test-rv64-jobs-runtime"
        # The roots own their direct source coverage. Derive routing from
        # those imports instead of maintaining a second native/truth/outer
        # file inventory; unknown files still take the package fallback.
        for filename, step in (
            ("rv64_native_gkr_codegen_test_root.zig", "test-native-gkr-codegen"),
            ("rv64_jobs_recursion_test_root.zig", "test-rv64-jobs-recursion"),
            ("rv64_jobs_native_test_root.zig", "test-rv64-jobs-native"),
            ("rv64_jobs_truth_test_root.zig", "test-rv64-jobs-truth"),
            ("rv64_jobs_outer_test_root.zig", "test-rv64-jobs-outer"),
        ):
            imports = re.findall(r'@import\("([^"\n]+)"\)', (root / directory / filename).read_text())
            if path == directory + filename or path in {directory + name for name in imports}:
                return step
    if package == "stwo_prover_engine" and path in PROVER_QUOTIENT_STEPS:
        return PROVER_QUOTIENT_STEPS[path]
    if package == "stwo_prover_engine" and (
        path.startswith("src/engine/prover/pcs/quotient")
        or path.startswith("src/engine/prover/pcs_quotient")
    ):
        return None
    for owner, prefix, step in FOCUSED_RULES:
        if owner == package and owns(path, prefix):
            return step
    return frontend_root_step(root, path) if package == "stwo_riscv_frontend" else None


def local_command(command: list[str], optimize: str = "ReleaseSafe") -> list[str]:
    localized: list[str] = []
    saw_optimize = False
    saw_jobs = False
    for argument in command:
        if argument.startswith("-Doptimize="):
            localized.append(f"-Doptimize={optimize}")
            saw_optimize = True
        elif argument.startswith("-j"):
            localized.append("-j1")
            saw_jobs = True
        else:
            localized.append(argument)
    if not saw_optimize:
        localized.append(f"-Doptimize={optimize}")
    if not saw_jobs:
        localized.append("-j1")
    return localized


def broad_command(root: Path, package: ci_package_graph.Package, optimize: str) -> list[str]:
    contract_path = root / package.directory / ci_package_graph.CONTRACT_NAME
    payload = json.loads(contract_path.read_text(encoding="utf-8"))
    command = payload.get("ci", {}).get("command")
    if not isinstance(command, list) or not all(
        isinstance(argument, str) and argument for argument in command
    ):
        raise DevTestError(f"package {package.name} has no valid CI command")
    return local_command(command, optimize)


def tracked_deletions(root: Path) -> set[str]:
    return set(subprocess.check_output(["git", "diff", "--diff-filter=D", "--name-only", "HEAD", "--"], cwd=root, text=True).splitlines()) if (root / ".git").exists() else set()


def focused_test_owner(package: str, path: str, packages: dict, root: Path) -> str:
    """Use an explicit consumer-owned test only across a declared dependency."""
    candidates = {owner for owner, source, _ in FOCUSED_RULES if owns(path, source)}
    if frontend_root_step(root, path) is not None:
        candidates.add("stwo_riscv_frontend")
    admitted = {owner for owner in candidates if owner in packages and
                (owner == package or package in packages[owner].dependencies)}
    return next(iter(admitted)) if len(admitted) == 1 else package


def commands_for_paths(
    root: Path,
    raw_paths: Iterable[str],
    *,
    check_only: bool = False,
    optimize: str | None = None,
    deferred: list[str] | None = None,
) -> list[list[str]]:
    if optimize is not None and optimize not in OPTIMIZE_MODES:
        raise DevTestError(f"unknown optimization mode: {optimize}")
    paths = sorted({normalize_path(path) for path in raw_paths})
    python_paths = [path for path in paths if path.startswith("scripts/") and path.endswith(".py")]
    commands: list[list[str]] = []
    deleted: set[str] | None = None
    missing = {path for path in paths if not (root / path).exists()}
    if missing:
        deleted = tracked_deletions(root)
        if unknown := missing - deleted:
            raise DevTestError("path does not exist and is not a tracked deletion: " + ", ".join(sorted(unknown)))
    if python_paths:
        if check_only:
            commands.append([sys.executable, "-m", "compileall", "-q", "scripts"])
        else:
            modules: set[str] = set()
            for path in python_paths:
                source = Path(path)
                test = source if source.parent.as_posix() == "scripts/tests" and source.name.startswith("test_") else Path("scripts/tests") / ("test_" + source.stem + ".py")
                if not (root / source).is_file() or not (root / test).is_file():
                    commands.append([sys.executable, "-m", "unittest", "discover", "-s", "scripts/tests", "-p", "test_*.py"])
                    break
                modules.add(test.with_suffix("").as_posix().replace("/", "."))
            else:
                commands.append([sys.executable, "-m", "unittest", *sorted(modules)])
        paths = [path for path in paths if path not in python_paths]
        if not paths:
            return commands
    packages = ci_package_graph.load_packages(root)
    policy = ci_scope_plan.strict_json(root / "conformance/ci-touchpoints-v1.json")
    ci_scope_plan.validate_policy(policy)
    bindings = ci_package_graph.lane_packages(policy, packages)
    consumer_paths = {path: package for package in packages.values() for path in package.consumer_roots}
    for path in paths:
        if path not in consumer_paths:
            continue
        provider = consumer_paths[path]
        if check_only:
            if deferred is None:
                raise DevTestError("consumer contracts require execution, not check-only")
            deferred.append(provider.name + " consumer contracts (execution required)")
        else:
            for mode in ((optimize,) if optimize else ("Debug", "ReleaseFast")):
                commands.append(["zig", "build", "test-cdc-" + provider.name.replace("_", "-"), "-Doptimize=" + mode, "-j1"])
    paths = [path for path in paths if path not in consumer_paths]
    selected: dict[str, list[str]] = {}
    extra_lanes: set[str] = set()
    unowned: list[str] = []
    for path in paths:
        documentation = ci_scope_plan.is_documentation(path, policy)
        lanes = ci_scope_plan.rule_lanes(path, policy, documentation_only=documentation)
        if not lanes and (documentation or ci_scope_plan.is_externally_validated(path, policy)):
            continue
        package = ci_package_graph.owning_package(path, packages)
        if package is not None:
            package = focused_test_owner(package, path, packages, root)
            selected.setdefault(package, []).append(path)
            continue
        if not lanes and not (root / path).exists() and (root / ".git").exists():
            if deleted is None:
                deleted = tracked_deletions(root)
            if path in deleted:
                lanes = set(policy["always_lanes"])
        if lanes:
            extra_lanes.update(lanes)
        else:
            unowned.append(path)
    if unowned:
        raise DevTestError(
            "no Zig package owns changed path(s): " + ", ".join(unowned)
        )

    host = "macos" if sys.platform == "darwin" else "linux"
    xcode = ci_scope_push.full_xcode_available() if "metal_aot" in extra_lanes else False
    full_contracts = False
    for lane in sorted(extra_lanes):
        spec = policy["lanes"][lane]
        full_lane = check_only and lane not in bindings and lane not in ("static", "script_contracts")
        if full_lane or not ci_scope_push.locally_runnable(lane, spec["host"], spec.get("local", "run"), host, xcode):
            if deferred is None:
                reason = "full-lane validation" if full_lane else "hosted validation"
                raise DevTestError(f"CI lane {lane} requires {reason}; use dev_test to report deferrals")
            deferred.append(lane)
            continue
        if lane in bindings:
            selected.setdefault(bindings[lane], []).append("")
        elif lane == "script_contracts" and check_only:
            commands.append([sys.executable, "-m", "compileall", "-q", "scripts"])
        else:
            commands.append([sys.executable, "scripts/repo/ci_scope_run.py", "--root", str(root),
                             "--policy", str(root / "conformance/ci-touchpoints-v1.json"),
                             "--lane", lane, "--output", str(root / ".zig-cache/dev-test" / f"{lane}.json"),
                             "--local-compatible"])
            full_contracts |= lane == "script_contracts"

    for package_name, package_paths in sorted(selected.items()):
        package = packages[package_name]
        steps = {focus_step(package_name, path, root) for path in package_paths}
        if None in steps:
            if check_only:
                if deferred is None:
                    raise DevTestError(f"check-only requires a focused owner; {package_name} needs full package validation")
                deferred.append(package_name + " (full package validation)")
                continue
            commands.append(broad_command(root, package, optimize or "ReleaseSafe"))
            continue
        selected_steps = sorted(value for value in steps if value is not None)
        if check_only and package_name == "stwo_ethereum_statement":
            if deferred is None:
                raise DevTestError("Ethereum consumer contracts require focused contract execution")
            deferred.append(package_name + " (focused contract execution)")
            continue
        if package_name == "stwo_ethereum_statement" and selected_steps == ["test-build-components"]:
            commands.append(["zig", "test", "-O" + (optimize or "Debug"), package.directory + "/build_components_test.zig"])
            continue
        if package_name == "stwo_riscv_cpu_integration" and selected_steps == ["test-proof-artifact-support"]:
            # These std-only paths consume the actual public module; loading the
            # full package build runner would dwarf their four bounded tests.
            base = ["zig", "test", "-O" + (optimize or "Debug")]
            if check_only:
                base.append("-fno-emit-bin")
            commands.append(base + ["--dep", package_name,
                "-Mroot=" + package.directory + "/tests/proof_artifact_support_contract_test.zig",
                "-M" + package_name + "=" + package.directory + "/mod.zig"])
            commands.append(base + [package.directory + "/rv64_proof_artifact_support.zig"])
            continue
        if selected_steps:
            command = [
                "zig",
                "build",
                *selected_steps,
                "--build-file",
                f"{package.directory}/build.zig",
                f"-Doptimize={optimize or 'Debug'}",
                "-j1",
            ]
            if check_only:
                command.extend(("-Dcheck-only=true", "-fincremental"))
            commands.append(command)
    unique = {}
    for command in commands:
        if full_contracts and command[1:3] == ["-m", "unittest"] and (command[3:] == ["discover", "-s", "scripts/tests", "-p", "test_*.py"] or all(module.startswith("scripts.tests.") for module in command[3:])):
            continue
        command = [sys.executable if index == 0 and argument == "python3" else argument for index, argument in enumerate(command)]
        unique.setdefault(tuple(command), command)
    return list(unique.values())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", help="changed paths; defaults to the worktree diff")
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--optimize", choices=OPTIMIZE_MODES,
                        help="reproduce an explicit build mode, such as optimized CI")
    parser.add_argument(
        "--check",
        action="store_true",
        help="type-check focused roots without code generation or test execution",
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        help="continuously type-check one focused package using Zig incremental compilation",
    )
    args = parser.parse_args(argv)
    try:
        root = args.root.resolve(strict=True)
        paths = args.paths or worktree_paths(root)
        if not paths:
            print("dev test: no worktree changes")
            return 0
        deferred: list[str] = []
        commands = commands_for_paths(
            root,
            paths,
            check_only=args.check or args.watch,
            optimize=args.optimize,
            deferred=deferred,
        )
        for lane in deferred:
            print(f"dev test: DEFER {lane} to its CI execution policy")
        if not commands:
            print("dev test: DEFERRED" if deferred else "dev test: CI policy selects no local runtime tests for documentation/external validation")
            return 0
        if args.watch:
            if len(commands) != 1 or "-Dcheck-only=true" not in commands[0]:
                raise DevTestError("--watch requires one focused package")
            commands[0].append("--watch")
        for command in commands:
            if os.environ.get(zig_serial_build.HELD_LOCK_ENV) != zig_serial_build.DEFAULT_LOCK:
                command = ci_scope_run.local_build_command(command)
            print(f"+ {shlex.join(command)}", flush=True)
            if args.dry_run:
                continue
            direct_test = command[:2] == ["zig", "test"] and os.environ.get(zig_serial_build.HELD_LOCK_ENV) != zig_serial_build.DEFAULT_LOCK
            with zig_serial_build.build_lock() if direct_test else nullcontext():
                result = subprocess.run(command, cwd=root, check=False)
            if result.returncode != 0:
                return result.returncode
        verb = "PLAN" if args.dry_run else ("PASS_LOCAL" if deferred else "PASS")
        label = "dev check" if args.check or args.watch else "dev test"
        print(f"{label}: {verb} ({len(commands)} focused command(s))")
        return 0
    except (
        DevTestError,
        ci_scope_plan.PlanError,
        ci_package_graph.GraphError,
        json.JSONDecodeError,
        OSError,
        subprocess.CalledProcessError,
    ) as error:
        print(f"dev test: FAIL: {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
