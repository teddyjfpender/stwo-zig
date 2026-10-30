//! The gate on `test_inventory.zig`: a test-bearing file this package forgets to
//! name there is compiled into nothing, and nothing else would say so.
//!
//! The inventory is a hand-written list because Zig's test collection needs a
//! literal `@import`, and a hand-written path list drifts. This walks
//! the package tree instead of trusting it. A test count floor catches tests
//! *dropped* from a binary; this catches tests that were never in one, which is
//! the failure that hid 142 of them.
//!
//! Fails closed. A run that cannot find the package directory reports that
//! rather than passing, because "the checker could not look" and "there is
//! nothing to find" are the two answers this repository has most often confused.

const std = @import("std");

/// The inventory's own text, embedded so the membership check needs no working
/// directory even though the tree walk does.
const INVENTORY = @embedFile("test_inventory.zig");

/// Files that hold tests and are deliberately absent from the inventory.
const excluded = [_]struct { path: []const u8, why: []const u8 }{
    .{
        .path = "recursion_poseidon_degree3_test_root.zig",
        .why = "backend-neutral semantic root, also consumed by scripts/recursive_poseidon_degree3_proof.py",
    },
    .{
        .path = "poseidon_merkle_test_root.zig",
        .why = "focused complete Poseidon Merkle scalar/SIMD parity root, run by test-poseidon-merkle",
    },
    .{
        .path = "mod.zig",
        .why = "the module root; the compiler always collects the root file's tests",
    },
    .{
        .path = "test_inventory.zig",
        .why = "the inventory itself, imported by mod.zig",
    },
    .{
        .path = "test_inventory_test.zig",
        .why = "this file, imported by mod.zig",
    },
    .{
        .path = "refinement_ir_export_test.zig",
        .why = "demands RISCV_AIR_IR_DIR; driven by the riscv-refinement-ir step, " ++
            "which is the only caller that sets it",
    },
    .{
        .path = "refinement_program_export_test.zig",
        .why = "demands RISCV_AIR_PROGRAM_IR_DIR; driven by the riscv-refinement-ir " ++
            "step, which supplies a fresh output directory",
    },
    .{
        .path = "build.zig",
        .why = "this package's build script, not part of the module",
    },
    .{
        .path = "r012_universal_adapter_test_root.zig",
        .why = "explicit focused evidence root; its tests are collected through the canonical root",
    },
    .{
        .path = "recursion_air_core_test_root.zig",
        .why = "explicit production-decoupled recursion edit root",
    },
    .{
        .path = "recursion_vm_composition_test_root.zig",
        .why = "compile-isolated row-18 VM composition edit root",
    },
    .{
        .path = "semantic_component_test_root.zig",
        .why = "explicit semantic-component prepared-domain edit root",
    },
    .{
        .path = "r012_fri_circuit_test_root.zig",
        .why = "temporary focused R-012 circuit evidence root",
    },
    .{
        .path = "recursion_air_r012_composition_circuit_dev_test_root.zig",
        .why = "temporary focused R-012 composition evidence root",
    },
    .{
        .path = "recursion_air_r012_dev_test_root.zig",
        .why = "temporary focused R-012 development root",
    },
    .{
        .path = "transcript_word_dev_test_root.zig",
        .why = "temporary focused row-4 development root",
    },
    .{
        .path = "transcript_binding_test_root.zig",
        .why = "temporary focused row-2 development root",
    },
    .{
        .path = "transcript_state_test_root.zig",
        .why = "temporary focused row-3 development root",
    },
    .{
        .path = "vm_public_claim_hash_test_root.zig",
        .why = "focused row-13 development root; its tests are collected through the canonical root",
    },
    .{
        .path = "vm_public_io_hash_test_root.zig",
        .why = "focused row-14 development root; its tests are collected through the canonical root",
    },
    .{
        .path = "pair_node_test_root.zig",
        .why = "focused pair-node evidence root; its tests are collected through the canonical root",
    },
    .{
        .path = "shifts_imm_private_test_root.zig",
        .why = "focused private-cutover evidence root",
    },
    .{
        .path = "shifts_reg_private_test_root.zig",
        .why = "focused private-cutover evidence root",
    },
    .{
        .path = "load_store_private_test_root.zig",
        .why = "focused private-cutover evidence root",
    },
    .{
        .path = "lt_reg_private_test_root.zig",
        .why = "focused private-cutover evidence root",
    },
    .{
        .path = "mul_private_test_root.zig",
        .why = "focused private-cutover evidence root",
    },
    .{
        .path = "mulh_private_test_root.zig",
        .why = "focused private-cutover evidence root",
    },
    .{
        .path = "div_private_test_root.zig",
        .why = "focused private-cutover evidence root",
    },
    .{
        .path = "hash_component_prepared_test_root.zig",
        .why = "focused prepared hash-component evidence root",
    },
    .{
        .path = "lookup_source_ingest_test_root.zig",
        .why = "focused lookup source-ingest evidence root",
    },
    .{
        .path = "lookup_table_interaction_test_root.zig",
        .why = "focused lookup-table interaction evidence root",
    },
    .{
        .path = "opcode_interaction_test_root.zig",
        .why = "focused opcode-interaction evidence root",
    },
};

/// Explicit focused product inventory for the declared-window and CPU scaling
/// work. The generic frontend module has no CPU backend and must not acquire
/// heavyweight proof/benchmark execution as a side effect of ordinary tests.
/// Every entry names a runnable zig_protocol_test.py root; the gate below
/// checks the literal import edge rather than treating an exclusion as coverage.
const focused_products = [_]struct { path: []const u8, root: []const u8, why: []const u8 }{
    .{ .path = "prover/tests/block_v8_endpoint_mixed_pipeline_test.zig", .root = "block_v8_endpoint_mixed_pipeline_test_root.zig", .why = "Canonical q70 real mixed reexecution, authenticated endpoint retention and fresh durable original closure; requires CPU backend." },
    .{ .path = "prover/tests/block_v8_execution_checkpoint_writer_test.zig", .root = "block_v8_execution_checkpoint_writer_test_root.zig", .why = "Focused bounded checkpoint publication, exact execution coverage and snapshot tampering controls for the full-block input pipeline." },
    .{ .path = "prover/tests/block_v8_caller_halt_policy_test.zig", .root = "block_v8_caller_halt_policy_test_root.zig", .why = "Explicit versioned endpoint architecture, original/recursive proof, bounded CPU ownership and independent receiving gate." },
    .{ .path = "recursion/tests/block_v8_compact_ram_recursion_test.zig", .root = "block_v8_compact_ram_recursion_test_root.zig", .why = "Explicit versioned endpoint architecture, original/recursive proof, bounded CPU ownership and independent receiving gate." },
    .{ .path = "recursion/tests/block_v8_endpoint_bridge_recursion_test.zig", .root = "block_v8_endpoint_bridge_recursion_test_root.zig", .why = "Explicit versioned endpoint architecture, original/recursive proof, bounded CPU ownership and independent receiving gate." },
    .{ .path = "prover/tests/block_v8_endpoint_caller_plan_test.zig", .root = "block_v8_endpoint_caller_plan_test_root.zig", .why = "Explicit versioned endpoint architecture, original/recursive proof, bounded CPU ownership and independent receiving gate." },
    .{ .path = "recursion/air/tests/blake3_recursive_column_inventory_test.zig", .root = "block_v8_endpoint_custody_test_root.zig", .why = "Explicit versioned endpoint architecture, original/recursive proof, bounded CPU ownership and independent receiving gate." },
    .{ .path = "recursion/tests/block_v8_endpoint_join_saved_benchmark.zig", .root = "block_v8_endpoint_join_saved_benchmark_root.zig", .why = "Explicit versioned endpoint architecture, original/recursive proof, bounded CPU ownership and independent receiving gate." },
    .{ .path = "recursion/tests/block_v8_endpoint_join_saved_receiver_test.zig", .root = "block_v8_endpoint_join_saved_receiver_test_root.zig", .why = "Explicit versioned endpoint architecture, original/recursive proof, bounded CPU ownership and independent receiving gate." },
    .{ .path = "recursion/tests/block_v8_endpoint_join_test.zig", .root = "block_v8_endpoint_join_test_root.zig", .why = "Explicit versioned endpoint architecture, original/recursive proof, bounded CPU ownership and independent receiving gate." },
    .{ .path = "prover/tests/block_v8_endpoint_local_directory_test.zig", .root = "block_v8_endpoint_local_directory_test_root.zig", .why = "Explicit versioned endpoint architecture, original/recursive proof, bounded CPU ownership and independent receiving gate." },
    .{ .path = "prover/tests/block_v8_endpoint_local_sparse_test.zig", .root = "block_v8_endpoint_local_sparse_test_root.zig", .why = "Explicit versioned endpoint architecture, original/recursive proof, bounded CPU ownership and independent receiving gate." },
    .{ .path = "prover/tests/block_v8_sparse_rom_original_test.zig", .root = "block_v8_sparse_rom_original_test_root.zig", .why = "Explicit versioned endpoint architecture, original/recursive proof, bounded CPU ownership and independent receiving gate." },
    .{ .path = "air/guest_precompile/tests/bulk_memcpy_byte_loop_v1_test.zig", .root = "bulk_memcpy_byte_loop_test_root.zig", .why = "Same-ROM byte-loop macro arithmetic, original proof and exact projection qualification; whole-VM integration is separately gated." },
    .{ .path = "prover/tests/block_v8_compact_ram_proof_test.zig", .root = "block_v8_compact_ram_proof_test_root.zig", .why = "Focused endpoint architecture, exact original/recursive proof and independent receiving gate." },
    .{ .path = "prover/tests/block_v8_compact_ram_test.zig", .root = "block_v8_compact_ram_test_root.zig", .why = "Focused endpoint architecture, exact original/recursive proof and independent receiving gate." },
    .{ .path = "prover/tests/block_v8_endpoint_local_compact_execution_benchmark.zig", .root = "block_v8_endpoint_local_compact_execution_benchmark_root.zig", .why = "Opt-in scale or execution-only diagnostic with external input pins; not part of ordinary frontend test execution." },
    .{ .path = "prover/tests/block_v8_endpoint_local_execution_benchmark.zig", .root = "block_v8_endpoint_local_execution_benchmark_root.zig", .why = "Opt-in scale or execution-only diagnostic with external input pins; not part of ordinary frontend test execution." },
    .{ .path = "prover/tests/block_v8_endpoint_local_execution_test.zig", .root = "block_v8_endpoint_local_compact_execution_benchmark_root.zig", .why = "Focused endpoint architecture, exact original/recursive proof and independent receiving gate." },
    .{ .path = "prover/tests/block_v8_global_window_policy_test.zig", .root = "block_v8_global_window_policy_test_root.zig", .why = "Focused endpoint architecture, exact original/recursive proof and independent receiving gate." },
    .{ .path = "prover/tests/block_v8_ram_clock_v3_test.zig", .root = "block_v8_ram_clock_v3_test_root.zig", .why = "Focused endpoint architecture, exact original/recursive proof and independent receiving gate." },
    .{ .path = "prover/tests/block_v8_real_pc_census.zig", .root = "block_v8_real_pc_census_root.zig", .why = "Opt-in scale or execution-only diagnostic with external input pins; not part of ordinary frontend test execution." },
    .{ .path = "prover/tests/bulk_memcpy_byte_loop_original_test.zig", .root = "bulk_memcpy_byte_loop_original_test_root.zig", .why = "Same-ROM byte-loop macro arithmetic, original proof and exact projection qualification; whole-VM integration is separately gated." },
    .{ .path = "recursion/tests/block_v8_endpoint_local_recursion_test.zig", .root = "block_v8_endpoint_local_recursion_test_root.zig", .why = "Focused endpoint architecture, exact original/recursive proof and independent receiving gate." },
    .{ .path = "block_v8_endpoint_local_execution_test_root.zig", .root = "block_v8_endpoint_local_execution_test_root.zig", .why = "Focused endpoint architecture CPU product root; explicit protocol runner invocation required." },
    .{ .path = "prover/block_v8_endpoint_whole_placement_v1.zig", .root = "block_v8_endpoint_whole_proof_test_root.zig", .why = "Explicit B8 typed endpoint and fresh CPU proof-admission gate; backend-dependent execution stays outside the generic frontend suite." },
    .{ .path = "prover/tests/block_v8_caller_ram_owner_test.zig", .root = "block_v8_caller_ram_owner_test_root.zig", .why = "Explicit B8 typed endpoint and fresh CPU proof-admission gate; backend-dependent execution stays outside the generic frontend suite." },
    .{ .path = "prover/tests/block_v8_caller_ram_projection_test.zig", .root = "block_v8_caller_ram_projection_test_root.zig", .why = "Explicit B8 typed endpoint and fresh CPU proof-admission gate; backend-dependent execution stays outside the generic frontend suite." },
    .{ .path = "prover/tests/block_v8_endpoint_execution_benchmark.zig", .root = "block_v8_endpoint_execution_benchmark_root.zig", .why = "Opt-in B8 scale measurement with explicitly pinned external artifacts; not an implicit benchmark in frontend tests." },
    .{ .path = "prover/tests/block_v8_endpoint_execution_test.zig", .root = "block_v8_endpoint_execution_test_root.zig", .why = "Explicit B8 typed endpoint and fresh CPU proof-admission gate; backend-dependent execution stays outside the generic frontend suite." },
    .{ .path = "prover/tests/block_v8_endpoint_global_bridge_test.zig", .root = "block_v8_endpoint_global_bridge_test_root.zig", .why = "Explicit B8 typed endpoint and fresh CPU proof-admission gate; backend-dependent execution stays outside the generic frontend suite." },
    .{ .path = "prover/tests/block_v8_endpoint_local_proof_test.zig", .root = "block_v8_endpoint_local_proof_test_root.zig", .why = "Explicit B8 typed endpoint and fresh CPU proof-admission gate; backend-dependent execution stays outside the generic frontend suite." },
    .{ .path = "prover/tests/block_v8_endpoint_range_provider_test.zig", .root = "block_v8_endpoint_range_provider_test_root.zig", .why = "Explicit B8 typed endpoint and fresh CPU proof-admission gate; backend-dependent execution stays outside the generic frontend suite." },
    .{ .path = "prover/tests/block_v8_endpoint_source_descriptor_test.zig", .root = "block_v8_endpoint_source_descriptor_test_root.zig", .why = "Explicit B8 typed endpoint and fresh CPU proof-admission gate; backend-dependent execution stays outside the generic frontend suite." },
    .{ .path = "prover/tests/block_v8_endpoint_whole_proof_test.zig", .root = "block_v8_endpoint_whole_proof_test_root.zig", .why = "Explicit B8 typed endpoint and fresh CPU proof-admission gate; backend-dependent execution stays outside the generic frontend suite." },
    .{ .path = "prover/tests/block_v8_native_endpoint_closure_test.zig", .root = "block_v8_native_endpoint_closure_test_root.zig", .why = "Explicit B8 typed endpoint and fresh CPU proof-admission gate; backend-dependent execution stays outside the generic frontend suite." },
    .{ .path = "prover/tests/block_v8_native_endpoint_components_test.zig", .root = "block_v8_native_endpoint_components_test_root.zig", .why = "Explicit B8 typed endpoint and fresh CPU proof-admission gate; backend-dependent execution stays outside the generic frontend suite." },
    .{ .path = "prover/tests/block_v8_native_endpoint_local_source_test.zig", .root = "block_v8_native_endpoint_local_source_test_root.zig", .why = "Explicit B8 typed endpoint and fresh CPU proof-admission gate; backend-dependent execution stays outside the generic frontend suite." },
    .{ .path = "prover/tests/block_v8_native_halt_policy_test.zig", .root = "block_v8_native_halt_policy_test_root.zig", .why = "Explicit B8 typed endpoint and fresh CPU proof-admission gate; backend-dependent execution stays outside the generic frontend suite." },
    .{ .path = "prover/tests/block_v8_ram_endpoint_collector_test.zig", .root = "block_v8_ram_endpoint_collector_test_root.zig", .why = "Explicit B8 typed endpoint and fresh CPU proof-admission gate; backend-dependent execution stays outside the generic frontend suite." },
    .{ .path = "prover/tests/block_v8_ram_endpoint_component_test.zig", .root = "block_v8_ram_endpoint_component_test_root.zig", .why = "Explicit B8 typed endpoint and fresh CPU proof-admission gate; backend-dependent execution stays outside the generic frontend suite." },
    .{ .path = "prover/tests/block_v8_ram_endpoint_kernel_test.zig", .root = "block_v8_ram_endpoint_kernel_test_root.zig", .why = "Explicit B8 typed endpoint and fresh CPU proof-admission gate; backend-dependent execution stays outside the generic frontend suite." },
    .{ .path = "prover/tests/block_v8_saved_union_root_benchmark.zig", .root = "block_v8_saved_union_root_benchmark_root.zig", .why = "Opt-in B8 scale measurement with explicitly pinned external artifacts; not an implicit benchmark in frontend tests." },
    .{ .path = "recursion/tests/block_v8_endpoint_public_custody_test.zig", .root = "block_v8_endpoint_custody_test_root.zig", .why = "Explicit recursive endpoint, global closure and independently reconstructed key gate; CPU proof execution stays focused." },
    .{ .path = "recursion/tests/block_v8_endpoint_recursion_test.zig", .root = "block_v8_endpoint_recursion_test_root.zig", .why = "Explicit recursive endpoint, global closure and independently reconstructed key gate; CPU proof execution stays focused." },
    .{ .path = "recursion/tests/block_v8_endpoint_saved_root_benchmark.zig", .root = "block_v8_endpoint_saved_root_benchmark_root.zig", .why = "Opt-in B8 scale measurement with explicitly pinned external artifacts; not an implicit benchmark in frontend tests." },
    .{ .path = "recursion/tests/block_v8_fresh_boundary_test.zig", .root = "block_v8_window_chain_test_root.zig", .why = "Explicit recursive endpoint, global closure and independently reconstructed key gate; CPU proof execution stays focused." },
    .{ .path = "recursion/tests/block_v8_union_closed_test.zig", .root = "block_v8_union_closed_test_root.zig", .why = "Explicit recursive endpoint, global closure and independently reconstructed key gate; CPU proof execution stays focused." },
    .{ .path = "recursion/tests/block_v8_union_geometry_parity_test.zig", .root = "block_v8_union_geometry_parity_test_root.zig", .why = "Explicit recursive endpoint, global closure and independently reconstructed key gate; CPU proof execution stays focused." },
    .{ .path = "recursion/tests/block_v8_window_chain_test.zig", .root = "block_v8_window_chain_test_root.zig", .why = "Explicit recursive endpoint, global closure and independently reconstructed key gate; CPU proof execution stays focused." },
    .{ .path = "recursion/tests/block_v8_window_closure_algebra_test.zig", .root = "block_v8_window_closure_algebra_test_root.zig", .why = "Explicit recursive endpoint, global closure and independently reconstructed key gate; CPU proof execution stays focused." },
    .{ .path = "prover/tests/block_v7_window_sparse_initial_v1_test.zig", .root = "block_v7_window_sparse_initial_test_root.zig", .why = "Focused independently reconstructed window initialization and CPU policy integration gate." },
    .{ .path = "prover/tests/block_v7_native_cache_parity_test.zig", .root = "block_v7_native_cache_parity_test_root.zig", .why = "CPU proof-byte control for explicit proof-scoped retained-cache budgets." },
    .{ .path = "prover/tests/block_v7_native_access_interaction_test.zig", .root = "block_v7_native_access_interaction_test_root.zig", .why = "CPU production sidecar generation and physical-claim differential gate." },
    .{ .path = "prover/tests/block_v5_native_projection_fused_unit_test.zig", .root = "block_v7_native_cache_parity_test_root.zig", .why = "Original fused-source algebra control explicitly included by the native cache and generation gate." },
    .{ .path = "prover/block_v7_word_quotient_tiles_test_v1.zig", .root = "block_v7_word_quotient_tiles_test_root.zig", .why = "Opt-in CPU original-proof parity and large RAM quotient measurements, outside generic frontend execution." },
    .{ .path = "prover/block_v7_ram_quotient_policy_v1.zig", .root = "block_v7_word_quotient_tiles_test_root.zig", .why = "Production CPU RAM tile-admission policy is qualified by the explicit tiled-quotient product root." },
    .{ .path = "prover/block_v7_word_quotient_tiles_v1.zig", .root = "block_v7_word_quotient_tiles_test_root.zig", .why = "CPU coefficient/tile scratch and predecessor-mapping tests require the prover module graph." },
    .{ .path = "prover/tests/block_v7_real_window_policy_v2_test.zig", .root = "block_v7_real_window_v2_test_root.zig", .why = "Independent captured-state fixtures are kept in the focused window-policy product gate." },
    .{ .path = "prover/tests/block_v7_real_window_geometry_v2_test.zig", .root = "block_v7_real_window_geometry_v2_test_root.zig", .why = "Requires explicitly pinned external ELF and incoming snapshot environment." },
    .{ .path = "prover/tests/block_v7_real_window_execution_v2_test.zig", .root = "block_v7_real_window_execution_v2_test_root.zig", .why = "Requires stwo_cpu_backend and genuine original-proof generation." },
    .{ .path = "prover/tests/block_v7_real_window_continuation_v2_test.zig", .root = "block_v7_real_window_continuation_v2_test_root.zig", .why = "Requires CPU product initialization and explicit continuation-snapshot fixtures." },
    .{ .path = "prover/tests/block_v7_real_window_continuation_export_v2.zig", .root = "block_v7_real_window_continuation_export_v2_root.zig", .why = "Opt-in external-state export harness; never run as an ordinary frontend unit test." },
    .{ .path = "prover/tests/block_v7_real_window_v2_benchmark.zig", .root = "block_v7_real_window_v2_benchmark_root.zig", .why = "Opt-in CPU benchmark with external corpus and output paths; measured separately from test suites." },
    .{ .path = "prover/tests/block_v7_window_union_test.zig", .root = "block_v7_window_union_test_root.zig", .why = "Shared original STARK and detached byte verification require the explicitly wired CPU product graph." },
    .{ .path = "block_v7_real_window_union_benchmark_root.zig", .root = "block_v7_real_window_union_benchmark_root.zig", .why = "Opt-in canonical-security retained-window shared original benchmark; requires external pinned snapshots and output paths." },
    .{ .path = "block_v7_window_union_reload_benchmark_root.zig", .root = "block_v7_window_union_reload_benchmark_root.zig", .why = "Fresh verification-only saved shared-original artifacts require independent external endpoint snapshots and the CPU product graph." },
    .{ .path = "block_v7_window_union_recursive_benchmark_root.zig", .root = "block_v7_window_union_recursive_benchmark_root.zig", .why = "Opt-in canonical shared-original recursive-root benchmark requires pinned external endpoint snapshots and the CPU product graph." },
    .{ .path = "prover/tests/block_v7_window_memory_endpoint_test.zig", .root = "block_v7_window_memory_endpoint_test_root.zig", .why = "CPU original STARK hostile-prover gate; requires stwo_cpu_backend." },
    .{ .path = "block_v7_window_memory_joint_test_root.zig", .root = "block_v7_window_memory_joint_test_root.zig", .why = "Explicit CPU producer/verifier semantic instantiation root." },
    .{ .path = "prover/block_v7_window_memory_composition_test_v1.zig", .root = "block_v7_window_memory_composition_test_root.zig", .why = "Focused scalar/symbolic original quotient parity gate with protocol module wiring." },
    .{ .path = "recursion/block_v7_real_window_root_test_v2.zig", .root = "block_v7_real_window_root_test_root_v2.zig", .why = "CPU recursive original-proof verification gate; does not belong in backend-neutral frontend compilation." },
    .{ .path = "prover/tests/block_v7_degree_bounded_native_test.zig", .root = "block_v7_degree_bounded_native_test_root.zig", .why = "CPU original-proof q3/q2 mode, detached verification and hostile compensated-claim gate." },
    .{ .path = "prover/tests/block_v7_degree_bounded_relation_layout_test.zig", .root = "block_v7_degree_bounded_relation_layout_test_root.zig", .why = "Opt-in CPU product geometry and physical-claim framing gate; no runtime promotion implied." },
    .{ .path = "prover/tests/block_v7_native_mul_q3_test.zig", .root = "block_v7_native_mul_q3_test_root.zig", .why = "CPU genuine MUL and degree-lift proof gate, including original quotient parity." },
    .{ .path = "prover/tests/block_v7_shared_quotient_cache_test.zig", .root = "block_v7_shared_quotient_cache_test_root.zig", .why = "CPU proof-scoped composition-cache ownership and parity gate." },
    .{ .path = "prover/tests/block_v5_quotient_column_cache_test.zig", .root = "block_v7_shared_quotient_cache_test_root.zig", .why = "Original CPU quotient cache regression control imported by the new shared-cache gate." },
    .{ .path = "prover/tests/block_v7_multi_union_test.zig", .root = "block_v7_multi_union_test_root.zig", .why = "CPU complete-proof and opt-in Ethereum profiling workload; driver scripts select measured cases." },
    .{ .path = "prover/tests/block_v7_real_window_capture_test.zig", .root = "block_v7_real_window_capture_test_root.zig", .why = "External retained-window capture harness; opt-in corpus paths and output ownership." },
    .{ .path = "prover/tests/block_v7_real_window_import_test.zig", .root = "block_v7_real_window_capture_test_root.zig", .why = "Explicit retained-state import/replay harness with corpus-dependent environment." },
    .{ .path = "prover/tests/block_v7_real_window_proof_test.zig", .root = "block_v7_real_window_proof_test_root.zig", .why = "Historical CPU partial-window proof control; distinct theorem and explicitly selected corpus." },
    .{ .path = "block_v7_real_window_reload_test_root.zig", .root = "block_v7_real_window_reload_test_root.zig", .why = "Fresh-process CPU verifier with independent externally pinned report and artifact paths." },
    .{ .path = "benchmarks/ethereum_workloads_test.zig", .root = "ethereum_workloads_test_root.zig", .why = "Focused runner contract for benchmark cycle/output/family counts, separate from timing runs." },
    .{ .path = "prover/block_v7_execution_epoch_v1.zig", .root = "block_v7_execution_epoch_test_root.zig", .why = "Focused complete/window epoch grammar and byte-compatibility gate with protocol imports." },
};

/// Where this package's sources sit, relative to the test's working directory.
///
/// Both spellings are real: the product gate runs from the repository root and
/// the package's own `zig build test --build-file src/frontends/riscv/build.zig`
/// does too, while running that build file from inside the package directory
/// gives the second. A directory only counts as this package when it holds both
/// the contract and the inventory, so a partial match cannot be mistaken for a
/// hit.
const candidate_roots = [_][]const u8{ "src/frontends/riscv", "." };

fn openPackageRoot() !std.fs.Dir {
    for (candidate_roots) |candidate| {
        var dir = std.fs.cwd().openDir(candidate, .{ .iterate = true }) catch continue;
        const claimed = blk: {
            dir.access("package.contract.json", .{}) catch break :blk false;
            dir.access("test_inventory.zig", .{}) catch break :blk false;
            break :blk true;
        };
        if (claimed) return dir;
        dir.close();
    }
    std.debug.print(
        "the RISC-V frontend package directory is not reachable from the test working " ++
            "directory; tried {s} and {s}\n",
        .{ candidate_roots[0], candidate_roots[1] },
    );
    return error.PackageRootUnreachable;
}

/// True when `source` declares at least one `test` block. Matched on
/// line-leading `test` followed by `{` or `"`, which is how every test in this
/// package is written, including the ones nested inside a generic container.
fn declaresTests(source: []const u8) bool {
    var lines = std.mem.tokenizeAny(u8, source, "\r\n");
    while (lines.next()) |line| {
        const trimmed = std.mem.trimLeft(u8, line, " \t");
        if (!std.mem.startsWith(u8, trimmed, "test")) continue;
        const rest = std.mem.trimLeft(u8, trimmed["test".len..], " ");
        if (rest.len == 0) continue;
        if (rest[0] == '{' or rest[0] == '"') return true;
    }
    return false;
}

fn isExcluded(path: []const u8) bool {
    for (focused_products) |entry| if (std.mem.eql(u8, entry.path, path) or std.mem.eql(u8, entry.root, path)) return true;
    for (excluded) |entry| {
        if (std.mem.eql(u8, entry.path, path)) return true;
    }
    return false;
}

test "test inventory: every test-bearing file in this package is named" {
    const allocator = std.testing.allocator;
    var root = try openPackageRoot();
    defer root.close();

    var walker = try root.walk(allocator);
    defer walker.deinit();

    var missing: usize = 0;
    var named: usize = 0;
    while (try walker.next()) |entry| {
        if (entry.kind == .directory) continue;
        if (!std.mem.endsWith(u8, entry.basename, ".zig")) continue;
        // Build caches hold generated copies of these sources; they are not
        // part of the module and must not be required in the inventory.
        if (std.mem.indexOf(u8, entry.path, ".zig-cache") != null) continue;
        if (std.mem.startsWith(u8, entry.path, ".")) continue;
        if (isExcluded(entry.path)) continue;

        const source = try root.readFileAlloc(allocator, entry.path, 1 << 21);
        defer allocator.free(source);
        if (!declaresTests(source)) continue;

        const quoted = try std.fmt.allocPrint(allocator, "\"{s}\"", .{entry.path});
        defer allocator.free(quoted);
        if (std.mem.indexOf(u8, INVENTORY, quoted) != null) {
            named += 1;
            continue;
        }
        missing += 1;
        std.debug.print(
            "test_inventory.zig does not name {s}, so its tests are compiled by nothing\n",
            .{entry.path},
        );
    }
    if (missing != 0) return error.TestBearingFileNotInInventory;
    // A walk that matched nothing would report zero missing files and prove
    // nothing, which is the shape this file exists to reject.
    try std.testing.expect(named > 100);
}

test "test inventory: every path it names exists and holds tests" {
    // The other direction: a renamed or deleted file leaves an import that
    // still compiles only because Zig resolves it, so this is the pin that
    // makes the list's length mean something.
    const allocator = std.testing.allocator;
    var root = try openPackageRoot();
    defer root.close();

    var listed: usize = 0;
    // Comment lines are skipped before the scan. The doc comment above the list
    // quotes the import form it is explaining, and a scanner that cannot tell
    // prose from code pressures its author into garbling the explanation --
    // issue #152 item 10, twice over in this repository already.
    var lines = std.mem.tokenizeAny(u8, INVENTORY, "\r\n");
    while (lines.next()) |line| {
        const code = std.mem.trimLeft(u8, line, " \t");
        if (std.mem.startsWith(u8, code, "//")) continue;
        const needle = "_ = @import(\"";
        const hit = std.mem.indexOf(u8, code, needle) orelse continue;
        const start = hit + needle.len;
        const end = std.mem.indexOfScalarPos(u8, code, start, '"') orelse
            return error.UnterminatedInventoryPath;
        const path = code[start..end];
        const source = root.readFileAlloc(allocator, path, 1 << 21) catch |err| {
            std.debug.print(
                "test_inventory.zig names {s}, which is not readable: {s}\n",
                .{ path, @errorName(err) },
            );
            return error.InventoryPathMissing;
        };
        defer allocator.free(source);
        if (!declaresTests(source)) {
            std.debug.print(
                "test_inventory.zig names {s}, which declares no test\n",
                .{path},
            );
            return error.InventoryPathHasNoTests;
        }
        listed += 1;
    }
    try std.testing.expect(listed > 100);
}

// This test is cheap: it validates registration, not the expensive product.
test "test inventory: focused product registrations resolve explicit test roots" {
    const a = std.testing.allocator;
    var root = try openPackageRoot();
    defer root.close();
    for (focused_products, 0..) |entry, i| {
        try std.testing.expect(entry.why.len != 0);
        for (focused_products[0..i]) |prior| try std.testing.expect(!std.mem.eql(u8, entry.path, prior.path));
        const body = try root.readFileAlloc(a, entry.path, 1 << 21);
        defer a.free(body);
        try std.testing.expect(declaresTests(body));
        const source = try root.readFileAlloc(a, entry.root, 1 << 21);
        defer a.free(source);
        if (std.mem.eql(u8, entry.path, entry.root)) continue;
        const literal = try std.fmt.allocPrint(a, "@import(\"{s}\")", .{entry.path});
        defer a.free(literal);
        try std.testing.expect(std.mem.indexOf(u8, source, literal) != null);
        try std.testing.expect(std.mem.indexOf(u8, source, "test") != null or std.mem.indexOf(u8, source, "comptime") != null);
    }
}
