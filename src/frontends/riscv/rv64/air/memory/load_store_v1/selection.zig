//! Exhaustive 2^17 facts; exact key and all outputs, no host semantic acceptance.
const E = @import("../../evaluation.zig");
const M = @import("stwo_core").fields.m31.M31;
pub const SIZE = 1 << 17;
pub fn fact(index: usize) [5]u32 {
    std.debug.assert(index < SIZE);
    const input: u32 = @intCast(index >> 1);
    const parity: u1 = @truncate(index);
    const selected = (input >> (@as(u5, parity) * 8)) & 255;
    return .{ input, parity, selected, selected >> 7, input >> 15 };
}
pub fn rowIndex(tuple: [5]u32) !usize {
    if (tuple[0] >= 65536 or tuple[1] > 1) return error.InvalidLoadStoreSelection;
    const index = 2 * tuple[0] + tuple[1];
    if (!std.mem.eql(u32, &fact(index), &tuple)) return error.InvalidLoadStoreSelection;
    return index;
}
const std = @import("std");

/// One physical row carries both semantic parity facts.
pub fn fixedFact(input: usize) [4]u32 {
    std.debug.assert(input < 65536);
    const x: u32 = @intCast(input);
    return .{ x, x >> 8, (x & 255) >> 7, x >> 15 };
}
pub fn tupleFor(comptime F: type, fixed: []const F, comptime parity: u1) [5]F {
    const c256 = if (F == M) M.fromCanonical(256) else E.qFor(F, 256);
    return .{ fixed[0], if (parity == 0) F.zero() else F.one(), if (parity == 0) fixed[0].sub(fixed[1].mul(c256)) else fixed[1], fixed[if (parity == 0) 2 else 3], fixed[3] };
}
