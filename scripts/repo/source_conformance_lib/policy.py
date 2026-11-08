"""Active-scope dependency and thin-owner policy."""

from __future__ import annotations

BUILD_ROOT_CEILING = 200
BUILD_SUPPORT_CEILING = 500
PYTHON_ROOT_CEILING = 350
PYTHON_ENTRYPOINT_CEILING = 100
PYTHON_CONTROLLER_CEILING = 850
ZIG_OWNER_CEILING = 300
ZIG_ENTRYPOINT_CEILING = 200
RUST_ENTRYPOINT_CEILING = 100
# Every size ceiling warns, without failing, once a file has consumed this share of it.
HEADROOM_PERCENT = 90
ACTIVE_NATIVE_RUST_CRATES = frozenset({"stwo-interop-rs", "stwo-vector-gen"})
ACTIVE_FORMAL_EVIDENCE_ROOTS = (
    "scripts/archive_native_matrix.py",
    "scripts/benchmark_delta.py",
    "scripts/benchmark_full.py",
    "scripts/benchmark_smoke.py",
    "scripts/build_architecture_receipt.py",
    "scripts/architecture_host_gate.py",
    "scripts/compare_optimization.py",
    "scripts/e2e_interop.py",
    "scripts/metal_core_aot_receipt.py",
    "scripts/metal_profile_report.py",
    "scripts/native_profile_capture.py",
    "scripts/native_proof_matrix.py",
    "scripts/profile_smoke.py",
    "scripts/check_riscv_release_contract.py",
    "scripts/riscv_release_gate.py",
)
# Every active evidence package may consume these stable cross-cutting contracts.
PYTHON_FOUNDATION_LIBRARIES = frozenset({
    "benchmark_product_contract_lib",
    "interop_cli_lib",
    "process_resources_lib",
    "product_identity_lib",
    "riscv_air_ir_lib",
    "typed_air_work_profile_contract_lib",
    "zig_protocol_lib",
})
# Controller packages with historical executable names that are not a direct
# ``<root>_lib`` spelling declare their stable command facade here.
PYTHON_CONTROLLER_ROOTS = {
    "optimization_compare_lib": "compare_optimization.py",
}
# Higher-level evidence packages may additionally consume these lower-level contracts.
PYTHON_LIBRARY_DEPENDENCIES = {
    "architecture_host_gate_lib": frozenset({
        "benchmark_delta_lib",
        "build_architecture_receipt_lib",
        "e2e_interop_lib",
        "metal_core_aot_receipt_lib",
        "product_closure",
        "product_identity_lib",
    }),
    "riscv_operand_classes_lib": frozenset({
        "riscv_equivalence_lib",
        "riscv_sail_oracle_lib",
    }),
    "riscv_infrastructure_uniqueness_lib": frozenset({
        "air_satisfaction_lib",
    }),
    "riscv_poseidon_table_uniqueness_lib": frozenset({
        "air_satisfaction_lib",
    }),
    "riscv_sail_oracle_lib": frozenset({"riscv_equivalence_lib"}),
    # Differential CSP evidence composes the canonical single-lane benchmark
    # contract rather than reimplementing its proof and host authorities.
    "riscv_csp_ab_benchmark_lib": frozenset({"riscv_csp_benchmark_lib"}),
    "riscv_recursion_csp_benchmark_lib": frozenset({
        "riscv_csp_benchmark_lib",
    }),
    # R-006 is the terminal paired capture controller.  It deliberately
    # consumes the lower-level CSP lane contract and its AB host classifier.
    "typed_air_r006_capture_lib": frozenset({
        "riscv_csp_ab_benchmark_lib",
        "riscv_csp_benchmark_lib",
    }),
    "native_profile_capture_lib": frozenset({
        "metal_profile_report_lib",
        "native_proof_matrix_lib",
    }),
    "native_cuda_benchmark_lib": frozenset({
        "native_cuda_diagnostic_lib",
    }),
}
DEFERRED_PREFIXES = (
    "src/bench/cairo_metal/",
    "src/frontends/cairo/",
    "src/integrations/cairo_metal/",
    "src/tests/cairo/",
    "src/tools/cairo/",
    "src/tools/cairo_metal_codegen/",
    "src/tools/metal_arena_plan/",
    "src/tools/metal_prover_session/",
    "src/tools/metal_session/",
    "src/tools/riscv/bench/",
    "src/tools/riscv/trace/",
    "scripts/cairo_",
    "scripts/sn_pie_",
    "scripts/tests/test_cairo_",
    "scripts/tests/test_sn_pie_",
    "tools/stark-v-",
    "tools/stwo-cairo-",
)
