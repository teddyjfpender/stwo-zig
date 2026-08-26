//! Lean process runner for the real 39-row SegmentV2 outer proof.
//!
//! The imported gate is also exercised by an exact-name guarded test target.
//! Running it as an executable omits transitive test declarations from code
//! generation, keeping relation-closure and proof debugging iterations short.

const std = @import("std");
const gate = @import("recursive_segment_v2_concrete_outer_proof_test.zig");

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    try gate.runGate(gpa.allocator());
}
