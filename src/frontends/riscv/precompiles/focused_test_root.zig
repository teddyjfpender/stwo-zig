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
    pub const execution_session = @import("tests/focused/execution_session.zig");
    pub const guest_precompile_0 = @import("tests/focused/guest_precompile_0.zig");
    pub const isa = @import("tests/focused/isa.zig");
    pub const keccakf_precompile = @import("tests/focused/keccakf_precompile.zig");
    pub const keccakf_row = @import("tests/focused/keccakf_row.zig");
    pub const minimal_trace_parallel_replay = @import("tests/focused/minimal_trace_parallel_replay.zig");
    pub const minimal_trace_parallel_replay_benchmark = @import("tests/focused/minimal_trace_parallel_replay_benchmark.zig");
    pub const runner = @import("tests/focused/runner.zig");
    pub const secp256k1_precompile = @import("tests/focused/secp256k1_precompile.zig");
    pub const transcript_support = @import("tests/focused/transcript_support.zig");
};

comptime {
    _ = @field(suites, @import("focused_suite").name);
}
