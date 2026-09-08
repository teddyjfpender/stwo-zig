//! Lean process runner for the real 39-row SegmentV2 outer proof.
//!
//! The imported gate is also exercised by an exact-name guarded test target.
//! Running it as an executable omits transitive test declarations from code
//! generation, keeping relation-closure and proof debugging iterations short.

const std = @import("std");
const gate = @import("recursive_segment_v2_concrete_outer_proof_test.zig");

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .init;
    defer std.debug.assert(gpa.deinit() == .ok);
    const allocator = gpa.allocator();
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    if (args.len == 1) {
        try gate.runGate(allocator);
        return;
    }
    if (args.len == 2 and std.mem.eql(u8, args[1], "--check-workload")) {
        try gate.checkSizedWorkload(allocator);
        std.debug.print("SEGMENT_V2_LADDER_EXECUTION status=passed sizes=1,4,16,64 continuation_steps=16\n", .{});
        return;
    }
    if (args.len != 3 or !std.mem.eql(u8, args[1], "--native-steps")) {
        std.debug.print("usage: {s} [--native-steps 1|4|16|64 | --check-workload]\n", .{args[0]});
        return error.InvalidArguments;
    }
    const steps = std.fmt.parseInt(usize, args[2], 10) catch return error.InvalidNativeStepCount;
    switch (steps) {
        1, 4, 16, 64 => {},
        else => return error.InvalidNativeStepCount,
    }
    std.debug.print(
        "SEGMENT_V2_LADDER mode=narrow_complete_proof requested_steps={d}\n",
        .{steps},
    );
    try gate.runSizedProof(allocator, steps);
    // The native admission owner, both cohorts, outer proof and verifier
    // capture have all been destroyed before this process-level completion.
    std.debug.print("SEGMENT_V2_LADDER status=verified requested_steps={d} owners_destroyed=true\n", .{steps});
}
