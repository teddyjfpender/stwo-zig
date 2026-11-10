//! BYTE convolution bounds; independent from witness values and quotients.
const std = @import("std");
pub const P = @import("../curves/spec.zig").BN254_P;
pub const OFFSET: i64 = 1 << 21;
pub const CARRY_BITS = 22;
pub const QUOTIENT_BYTES = 33;
pub const Limbs = 65;
pub fn coefficientBound(n: usize) i64 {
    var products: i64 = 0;
    for (0..32) |i| for (0..32) |j| {
        if (i + j == n) products += 12 * 18 * 255 * 255;
    };
    var quotient: i64 = 0;
    for (0..33) |i| for (0..32) |j| {
        if (i + j == n) quotient += 255 * @as(i64, @intCast((P >> @intCast(8 * j)) & 255));
    };
    return products + quotient + (if (n < 32) @as(i64, 255) else 0);
}
pub const Report = struct { max_residual: i64, max_valid_carry: i64 };
pub fn derive() Report {
    var lo: i64 = 0;
    var hi: i64 = 0;
    var max_residual: i64 = 0;
    var max_carry: i64 = 0;
    for (0..Limbs) |n| {
        const c = coefficientBound(n);
        const residual_lo = -c + (if (n == 0) @as(i64, 0) else -OFFSET) + (if (n < 64) -256 * (OFFSET - 1) else 0);
        const residual_hi = c + (if (n == 0) @as(i64, 0) else OFFSET - 1) + (if (n < 64) 256 * OFFSET else 0);
        max_residual = @max(max_residual, @as(i64, @intCast(@max(@abs(residual_lo), @abs(residual_hi)))));
        if (n < 64) {
            lo = @divFloor(-c + lo, 256);
            hi = @divFloor(c + hi + 255, 256);
            max_carry = @max(max_carry, @as(i64, @intCast(@max(@abs(lo), @abs(hi)))));
            std.debug.assert(lo >= -OFFSET and hi < OFFSET);
        }
    }
    std.debug.assert(max_residual < 2147483647);
    return .{ .max_residual = max_residual, .max_valid_carry = max_carry };
}
pub const MAX_QUOTIENT: u272 = 216 * @as(u272, P) - 431;
