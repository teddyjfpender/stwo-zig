//! Public register side of the block-v2 first-touch relation. The admitted
//! job carries all 32 initial register values, so only a 32-bit use mask has
//! to be committed in the block manifest before relation challenges are drawn.
//! The verifier recomputes every emitted tuple from that public job and mask.
const std = @import("std");
const core = @import("stwo_core");
const spans = @import("../recursion/span_statement_blake3.zig");
const bus = @import("block_memory_relation_v2.zig");
const M = core.fields.m31.M31;
const QM = core.fields.qm31.QM31;

pub const Claim = struct {
    /// Bit i means the sorted memory component must contain a first touch of
    /// register i. This mask is public transcript input, never an uncommitted
    /// verifier-local guess after the challenge has been sampled.
    used: u32,

    pub fn count(self: Claim) u6 {
        return @popCount(self.used);
    }

    pub fn tuple(self: Claim, job: spans.JobContext, index: u5) !bus.InitialTuple {
        try job.validate();
        if (self.used & (@as(u32, 1) << index) == 0) return error.UnusedRegisterInitialValue;
        var result: bus.InitialTuple = @splat(M.zero());
        result[0] = M.zero();
        result[1] = M.fromCanonical(index);
        const value = job.complete.initial_state.registers[index];
        for (0..4) |i| result[5 + i] = M.fromCanonical(@as(u8, @truncate(value >> @intCast(i * 8))));
        return result;
    }

    pub fn emitSum(self: Claim, job: spans.JobContext, challenges: *const bus.Challenges) !QM {
        var sums = bus.WitnessSums{};
        for (0..32) |i| {
            const index: u5 = @intCast(i);
            if (self.used & (@as(u32, 1) << index) == 0) continue;
            try sums.addInitial(challenges, try self.tuple(job, index), .emit);
        }
        return sums.initial;
    }
};

test "public initial register provider emits exact byte tuples for selected keys" {
    const machine = try spans.MachineState.init(0, blk: {
        var regs: [32]u32 = @splat(0);
        regs[1] = 0x12345678;
        break :blk regs;
    }, .{ .bytes = @splat(0) }, .{ .bytes = @splat(0) });
    const complete = try spans.CompleteExecution.init(.{ .bytes = @splat(0) }, .{ .bytes = @splat(0) }, machine, machine, .{ .bytes = @splat(0) }, .{ .bytes = @splat(0) }, 1);
    const job = try spans.JobContext.init(complete, 1);
    const claim = Claim{ .used = 1 << 1 };
    try std.testing.expectEqual(@as(u6, 1), claim.count());
    const tuple = try claim.tuple(job, 1);
    const decoded = try bus.decodeInitialTuple(tuple);
    try std.testing.expectEqual(@as(u1, 0), decoded.space);
    try std.testing.expectEqual(@as(u32, 1), decoded.address);
    try std.testing.expectEqual(@as(u32, 0x12345678), decoded.value);
    try std.testing.expectError(error.UnusedRegisterInitialValue, claim.tuple(job, 2));
}
