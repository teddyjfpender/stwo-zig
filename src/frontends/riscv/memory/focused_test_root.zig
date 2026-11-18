//! This package's one focused test root.
//!
//! Focused suites live in `tests/focused/`. Zig confines a module's file
//! imports to the directory of its root file, so a suite cannot be its own
//! root without losing access to the package it exercises. Every focused
//! build step therefore roots here and names one suite through the
//! `focused_suite` build option. Only that suite is analysed; an unknown name
//! is a compile error rather than an empty, passing binary.

const suites = struct {
    pub const compact_poseidon_authority = @import("tests/focused/compact_poseidon_authority.zig");
    pub const merkle_authority = @import("tests/focused/merkle_authority.zig");
    pub const parent_canonical_admission_1 = @import("tests/focused/parent_canonical_admission_1.zig");
    pub const parent_canonical_admission_3 = @import("tests/focused/parent_canonical_admission_3.zig");
    pub const memory_polynomial_compiler = @import("tests/focused/memory_polynomial_compiler.zig");
    pub const poseidon_materialization_frontier = @import("tests/focused/poseidon_materialization_frontier.zig");
    pub const poseidon_merkle_1 = @import("tests/focused/poseidon_merkle_1.zig");
    pub const memory_transcript_support = @import("tests/focused/memory_transcript_support.zig");
    pub const wide_poseidon_authority = @import("tests/focused/wide_poseidon_authority.zig");
};

comptime {
    _ = @field(suites, @import("focused_suite").name);
}
