//! Lean process runner for the real authenticated temporal parent proof.
//!
//! The guarded test remains the release-evidence target. This executable
//! omits transitive test declarations from code generation so parent-cohort
//! compiler and closure iterations do not pay the full test-discovery cost.

const std = @import("std");
const gate = @import("recursive_temporal_parent_real_proof_test.zig");

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    try gate.runGate(gpa.allocator());
}
