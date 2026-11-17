//! This package's one focused test root.
//!
//! Focused suites live in `tests/focused/`. Zig confines a module's file
//! imports to the directory of its root file, so a suite cannot be its own
//! root without losing access to the package it exercises. Every focused
//! build step therefore roots here and names one suite through the
//! `focused_suite` build option. Only that suite is analysed; an unknown name
//! is a compile error rather than an empty, passing binary.

const suites = struct {
    pub const execution_session = @import("tests/focused/execution_session.zig");
    pub const guest_precompile_3 = @import("tests/focused/guest_precompile_3.zig");
    pub const keccakf_precompile = @import("tests/focused/keccakf_precompile.zig");
    pub const keccakf_row = @import("tests/focused/keccakf_row.zig");
    pub const legacy_benchmarks = @import("tests/focused/legacy_benchmarks.zig");
    pub const lookup_table_framework_export = @import("tests/focused/lookup_table_framework_export.zig");
    pub const lookup_table_interaction = @import("tests/focused/lookup_table_interaction.zig");
    pub const minimal_trace_parallel_replay = @import("tests/focused/minimal_trace_parallel_replay.zig");
    pub const minimal_trace_parallel_replay_benchmark = @import("tests/focused/minimal_trace_parallel_replay_benchmark.zig");
    pub const recursion_segment_publication_provider_v2_1 = @import("tests/focused/recursion_segment_publication_provider_v2_1.zig");
    pub const recursion_temporal_pair = @import("tests/focused/recursion_temporal_pair.zig");
    pub const releasefast_acceptance = @import("tests/focused/releasefast_acceptance.zig");
    pub const retained_authority_contract = @import("tests/focused/retained_authority_contract.zig");
    pub const retained_transcript_contracts = @import("tests/focused/retained_transcript_contracts.zig");
    pub const retained_typed_components_upper = @import("tests/focused/retained_typed_components_upper.zig");
    pub const runner = @import("tests/focused/runner.zig");
    pub const rv64_execution = @import("tests/focused/rv64_execution.zig");
    pub const sail_oracle = @import("tests/focused/sail_oracle.zig");
    pub const segment_publication_input_provider_authority = @import("tests/focused/segment_publication_input_provider_authority.zig");
    pub const segment_statement_v2 = @import("tests/focused/segment_statement_v2.zig");
    pub const statement_wire = @import("tests/focused/statement_wire.zig");
    pub const transcript_support = @import("tests/focused/transcript_support.zig");
};

comptime {
    _ = @field(suites, @import("focused_suite").name);
}
