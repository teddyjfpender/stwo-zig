//! This package's one focused test root.
//!
//! Focused suites live in `tests/focused/`. Zig confines a module's file
//! imports to the directory of its root file, so a suite cannot be its own
//! root without losing access to the package it exercises. Every focused
//! build step therefore roots here and names one suite through the
//! `focused_suite` build option. Only that suite is analysed; an unknown name
//! is a compile error rather than an empty, passing binary.

const suites = struct {
    pub const air_function_frames = @import("tests/focused/air_function_frames.zig");
    pub const air_runtime_profile = @import("tests/focused/air_runtime_profile.zig");
    pub const testing_air_semantics_0 = @import("tests/focused/testing_air_semantics_0.zig");
    pub const testing_air_semantics_1 = @import("tests/focused/testing_air_semantics_1.zig");
    pub const testing_air_semantics_2 = @import("tests/focused/testing_air_semantics_2.zig");
    pub const testing_air_semantics_3 = @import("tests/focused/testing_air_semantics_3.zig");
    pub const air_static_profile = @import("tests/focused/air_static_profile.zig");
    pub const air_static_profile_registry = @import("tests/focused/air_static_profile_registry.zig");
    pub const testing_bulk_memcpy_candidate = @import("tests/focused/testing_bulk_memcpy_candidate.zig");
    pub const testing_compact_poseidon_authority = @import("tests/focused/testing_compact_poseidon_authority.zig");
    pub const testing_execution_session = @import("tests/focused/testing_execution_session.zig");
    pub const testing_guest_precompile_0 = @import("tests/focused/testing_guest_precompile_0.zig");
    pub const guest_precompile_1 = @import("tests/focused/guest_precompile_1.zig");
    pub const guest_precompile_2 = @import("tests/focused/guest_precompile_2.zig");
    pub const testing_guest_precompile_3 = @import("tests/focused/testing_guest_precompile_3.zig");
    pub const hash_component_prepared = @import("tests/focused/hash_component_prepared.zig");
    pub const interaction_trace_plan_execution = @import("tests/focused/interaction_trace_plan_execution.zig");
    pub const interaction_witness_work = @import("tests/focused/interaction_witness_work.zig");
    pub const testing_keccakf_precompile = @import("tests/focused/testing_keccakf_precompile.zig");
    pub const testing_keccakf_row = @import("tests/focused/testing_keccakf_row.zig");
    pub const load_store_private = @import("tests/focused/load_store_private.zig");
    pub const load_store_private_1 = @import("tests/focused/load_store_private_1.zig");
    pub const lookup_batching = @import("tests/focused/lookup_batching.zig");
    pub const lookup_batching_edit = @import("tests/focused/lookup_batching_edit.zig");
    pub const lookup_polynomial_and_manifest = @import("tests/focused/lookup_polynomial_and_manifest.zig");
    pub const testing_lookup_source_ingest = @import("tests/focused/testing_lookup_source_ingest.zig");
    pub const main_trace_plan_execution = @import("tests/focused/main_trace_plan_execution.zig");
    pub const testing_minimal_trace_parallel_replay = @import("tests/focused/testing_minimal_trace_parallel_replay.zig");
    pub const testing_minimal_trace_parallel_replay_benchmark = @import("tests/focused/testing_minimal_trace_parallel_replay_benchmark.zig");
    pub const native_boundary_authority = @import("tests/focused/native_boundary_authority.zig");
    pub const testing_opcode_interaction = @import("tests/focused/testing_opcode_interaction.zig");
    pub const testing_polynomial_compiler = @import("tests/focused/testing_polynomial_compiler.zig");
    pub const poseidon2_protocol_identity = @import("tests/focused/poseidon2_protocol_identity.zig");
    pub const testing_poseidon_materialization_frontier = @import("tests/focused/testing_poseidon_materialization_frontier.zig");
    pub const poseidon_merkle = @import("tests/focused/poseidon_merkle.zig");
    pub const poseidon_universal_degree3 = @import("tests/focused/poseidon_universal_degree3.zig");
    pub const poseidon_witness_work = @import("tests/focused/poseidon_witness_work.zig");
    pub const recursion_arithmetic_fusion = @import("tests/focused/recursion_arithmetic_fusion.zig");
    pub const testing_recursion_composition_recorder = @import("tests/focused/testing_recursion_composition_recorder.zig");
    pub const testing_recursion_framework_export = @import("tests/focused/testing_recursion_framework_export.zig");
    pub const recursion_opening_accumulation = @import("tests/focused/recursion_opening_accumulation.zig");
    pub const testing_recursion_vm_composition = @import("tests/focused/testing_recursion_vm_composition.zig");
    pub const testing_releasefast_acceptance = @import("tests/focused/testing_releasefast_acceptance.zig");
    pub const retained_authority_contracts_1 = @import("tests/focused/retained_authority_contracts_1.zig");
    pub const retained_authority_contracts_2 = @import("tests/focused/retained_authority_contracts_2.zig");
    pub const testing_row_windows = @import("tests/focused/testing_row_windows.zig");
    pub const row_windows_edit = @import("tests/focused/row_windows_edit.zig");
    pub const testing_runner = @import("tests/focused/testing_runner.zig");
    pub const testing_secp256k1_precompile = @import("tests/focused/testing_secp256k1_precompile.zig");
    pub const segment_boundary_components = @import("tests/focused/segment_boundary_components.zig");
    pub const segment_leaf_outer_authority = @import("tests/focused/segment_leaf_outer_authority.zig");
    pub const segment_outer_adapter_manifest = @import("tests/focused/segment_outer_adapter_manifest.zig");
    pub const segment_outer_noncore_audits = @import("tests/focused/segment_outer_noncore_audits.zig");
    pub const segment_public_outer_components = @import("tests/focused/segment_public_outer_components.zig");
    pub const segment_public_outer_source = @import("tests/focused/segment_public_outer_source.zig");
    pub const segment_statement_layout = @import("tests/focused/segment_statement_layout.zig");
    pub const segment_transcript_outer_components = @import("tests/focused/segment_transcript_outer_components.zig");
    pub const segment_transcript_outer_source = @import("tests/focused/segment_transcript_outer_source.zig");
    pub const signer_recovery = @import("tests/focused/signer_recovery.zig");
    pub const testing_trace_authority = @import("tests/focused/testing_trace_authority.zig");
    pub const testing_transcript_support = @import("tests/focused/testing_transcript_support.zig");
    pub const typed_witness_benchmarks = @import("tests/focused/typed_witness_benchmarks.zig");
    pub const testing_wide_poseidon_authority = @import("tests/focused/testing_wide_poseidon_authority.zig");
};

comptime {
    _ = @field(suites, @import("focused_suite").name);
}
