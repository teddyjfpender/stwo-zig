//! Numeric hint witnesses. Canonical constraints, BYTE and source-owned SSA
//! binding must all be physical before any consumer inherits this authority.
const std = @import("std");
const S = @import("source.zig");
pub fn fill(value: u256) !S.Row {
    if (value >= S.MODULUS) return error.NonCanonicalPrivateHint;
    var row = rawForTesting(value, S.MODULUS - 1 - value);
    std.debug.assert(valid(&row, .{ 1, 0, 1 }));
    return row;
}
pub fn padding() S.Row {
    return @splat(0);
}
/// Exact integer byte constraints, not a separate value<modulus assumption.
pub fn valid(row: *const S.Row, fixed: S.Fixed) bool {
    if (fixed[S.ACTIVE] > 1 or fixed[S.WRITER_ID] >= 2147483647 or fixed[S.FANOUT] >= 2147483647) return false;
    const active = fixed[S.ACTIVE];
    for (row[0..64]) |byte| if (byte >= 256 or (active == 0 and byte != 0)) return false;
    for (row[S.CARRY..]) |carry| if (carry > active) return false;
    for (0..32) |i| {
        const before = if (i == 0) active else row[S.CARRY + i - 1];
        const after = if (i == 31) 0 else row[S.CARRY + i];
        const residual = @as(i64, row[i]) + row[32 + i] + before - @as(i64, active) * @as(i64, @intCast((S.MODULUS >> @intCast(8 * i)) & 255)) - 256 * @as(i64, after);
        if (residual != 0) return false;
    }
    return true;
}
pub fn read(row: *const S.Row, start: usize) u256 {
    var out: u256 = 0;
    for (0..32) |i| out |= @as(u256, row[start + i]) << @intCast(8 * i);
    return out;
}
/// Constructs low31 carries even for a noncanonical alias; the mandatory last
/// equation still sees the overflow. Only used by source tests and valid fill.
pub fn rawForTesting(value: u256, distance: u256) S.Row {
    var row: S.Row = @splat(0);
    var carry: u32 = 1;
    for (0..32) |i| {
        row[i] = @intCast((value >> @intCast(8 * i)) & 255);
        row[32 + i] = @intCast((distance >> @intCast(8 * i)) & 255);
        const sum: @TypeOf(@as(i64, 0)) = @as(i64, row[i]) + row[32 + i] + carry - @as(i64, @intCast((S.MODULUS >> @intCast(8 * i)) & 255));
        carry = if (sum >= 0 and @mod(sum, 256) == 0) @intCast(@divExact(sum, 256)) else 2;
        if (i < 31) row[S.CARRY + i] = carry;
    }
    return row;
}
