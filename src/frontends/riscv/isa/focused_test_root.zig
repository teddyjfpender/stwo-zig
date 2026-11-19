//! This package's one focused test root.
//!
//! Focused suites live in `tests/focused/`. Zig confines a module's file
//! imports to the directory of its root file, so a suite cannot be its own
//! root without losing access to the package it exercises. Every focused
//! build step therefore roots here and names one suite through the
//! `focused_suite` build option. Only that suite is analysed; an unknown name
//! is a compile error rather than an empty, passing binary.

const suites = struct {
    pub const bulk_memcpy_candidate = @import("tests/focused/bulk_memcpy_candidate.zig");
    pub const isa_execution_session = @import("tests/focused/isa_execution_session.zig");
    pub const isa = @import("tests/focused/isa.zig");
    pub const isa_keccakf_precompile = @import("tests/focused/isa_keccakf_precompile.zig");
    pub const isa_keccakf_row = @import("tests/focused/isa_keccakf_row.zig");
    pub const isa_minimal_trace_parallel_replay = @import("tests/focused/isa_minimal_trace_parallel_replay.zig");
    pub const isa_minimal_trace_parallel_replay_benchmark = @import("tests/focused/isa_minimal_trace_parallel_replay_benchmark.zig");
    pub const isa_runner = @import("tests/focused/isa_runner.zig");
    pub const runtime_profile_decode = @import("tests/focused/runtime_profile_decode.zig");
    pub const rv64_execution = @import("tests/focused/rv64_execution.zig");
    pub const segment_access_clock = @import("tests/focused/segment_access_clock.zig");
    pub const isa_transcript_support = @import("tests/focused/isa_transcript_support.zig");
};

comptime {
    _ = @field(suites, @import("focused_suite").name);
}
