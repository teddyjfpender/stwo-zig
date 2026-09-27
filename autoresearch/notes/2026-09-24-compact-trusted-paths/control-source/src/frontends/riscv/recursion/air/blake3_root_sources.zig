//! Canonical root slots: trace trees first, then FRI layers, eight words each.
const std = @import("std");
const core = @import("stwo_core");
pub const CIRCUIT: u32 = 4_000_003;
pub fn caller(index: usize) !@import("blake3_frame_route.zig").Caller {
    const first = try std.math.mul(usize, index, 8);
    if (first > core.fields.m31.Modulus - 8) return error.InvalidParentRootSource;
    return .{ .circuit = CIRCUIT, .first_wire = @intCast(first) };
}
