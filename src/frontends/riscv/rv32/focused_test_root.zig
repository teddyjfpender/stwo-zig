//! This package's one focused test root.
//!
//! Focused suites live in `tests/focused/`. Zig confines a module's file
//! imports to the directory of its root file, so a suite cannot be its own
//! root without losing access to the package it exercises. Every focused
//! build step therefore roots here and names one suite through the
//! `focused_suite` build option. Only that suite is analysed; an unknown name
//! is a compile error rather than an empty, passing binary.

const suites = struct {
    pub const air_semantics_0 = @import("tests/focused/air_semantics_0.zig");
    pub const air_semantics_1 = @import("tests/focused/air_semantics_1.zig");
    pub const air_semantics_2 = @import("tests/focused/air_semantics_2.zig");
    pub const air_semantics_3 = @import("tests/focused/air_semantics_3.zig");
    pub const bulk_memcpy_candidate = @import("tests/focused/bulk_memcpy_candidate.zig");
    pub const execution_session = @import("tests/focused/execution_session.zig");
    pub const infrastructure_component = @import("tests/focused/infrastructure_component.zig");
    pub const interaction_trace_plan_1 = @import("tests/focused/interaction_trace_plan_1.zig");
    pub const interaction_witness_work_1 = @import("tests/focused/interaction_witness_work_1.zig");
    pub const interaction_witness_work_2 = @import("tests/focused/interaction_witness_work_2.zig");
    pub const interaction_witness_work_3 = @import("tests/focused/interaction_witness_work_3.zig");
    pub const keccakf_precompile = @import("tests/focused/keccakf_precompile.zig");
    pub const keccakf_row = @import("tests/focused/keccakf_row.zig");
    pub const load_store_private_2 = @import("tests/focused/load_store_private_2.zig");
    pub const lookup_source_ingest = @import("tests/focused/lookup_source_ingest.zig");
    pub const lookup_table_framework_export = @import("tests/focused/lookup_table_framework_export.zig");
    pub const lookup_table_interaction = @import("tests/focused/lookup_table_interaction.zig");
    pub const main_trace_plan_execution_1 = @import("tests/focused/main_trace_plan_execution_1.zig");
    pub const main_trace_plan_execution_2 = @import("tests/focused/main_trace_plan_execution_2.zig");
    pub const main_trace_plan_execution_3 = @import("tests/focused/main_trace_plan_execution_3.zig");
    pub const main_trace_plan_execution_4 = @import("tests/focused/main_trace_plan_execution_4.zig");
    pub const minimal_trace_parallel_replay = @import("tests/focused/minimal_trace_parallel_replay.zig");
    pub const minimal_trace_parallel_replay_benchmark = @import("tests/focused/minimal_trace_parallel_replay_benchmark.zig");
    pub const opcode_interaction = @import("tests/focused/opcode_interaction.zig");
    pub const poseidon_witness_work_1 = @import("tests/focused/poseidon_witness_work_1.zig");
    pub const proof_phase_meter = @import("tests/focused/proof_phase_meter.zig");
    pub const recursion_composition_recorder = @import("tests/focused/recursion_composition_recorder.zig");
    pub const row_windows = @import("tests/focused/row_windows.zig");
    pub const runner = @import("tests/focused/runner.zig");
    pub const runtime_selector = @import("tests/focused/runtime_selector.zig");
    pub const segment_statement_v2 = @import("tests/focused/segment_statement_v2.zig");
    pub const semantic_component = @import("tests/focused/semantic_component.zig");
    pub const trace_authority = @import("tests/focused/trace_authority.zig");
    pub const transcript_support = @import("tests/focused/transcript_support.zig");
};

comptime {
    _ = @field(suites, @import("focused_suite").name);
}
