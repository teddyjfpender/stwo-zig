//! Lean process runner for the real native-V2-to-recursion ingress gate.
//!
//! The evidence-bearing test target remains authoritative. This executable
//! deliberately imports the same gate body outside Zig's test runner so that
//! transitive `test` declarations are not code-generated on every proof-loop
//! iteration. It is a development-speed surface, never a second proof path.

const std = @import("std");
const gate = @import("recursive_segment_v2_leaf_outer_proof_test.zig");

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    try gate.runGate(gpa.allocator());
}
