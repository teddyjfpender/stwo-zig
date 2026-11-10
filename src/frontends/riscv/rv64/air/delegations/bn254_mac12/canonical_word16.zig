//! Canonical comparison only; products elsewhere remain BYTE8 convolutions.
const E = @import("../../evaluation.zig");
const P = @import("../curves/spec.zig").BN254_P;
pub const Offsets = struct { output: usize, distance: usize, borrow: usize };
pub const CONSTRAINTS = 31;
fn k(comptime F: type, x: u32) F {
    return E.qFor(F, x);
}
fn chunk(comptime F: type, v: anytype, start: usize, i: usize) F {
    return v.main(start + 2 * i).add(v.main(start + 2 * i + 1).mul(k(F, 256)));
}
pub fn emit(comptime F: type, v: anytype, o: Offsets, active: F, sink: anytype) void {
    for (0..15) |i| {
        const c = v.main(o.borrow + i);
        sink.emit(c.mul(c.sub(active)));
    }
    for (0..16) |i| {
        var residual = chunk(F, v, o.output, i).add(chunk(F, v, o.distance, i)).sub(active.mul(k(F, @intCast((P >> @intCast(16 * i)) & 65535))));
        residual = residual.add(if (i == 0) active else v.main(o.borrow + i - 1));
        if (i < 15) residual = residual.sub(v.main(o.borrow + i).mul(k(F, 65536)));
        sink.emit(residual);
    }
}
pub fn valid(row: []const u32, o: Offsets, active: u32) bool {
    for (0..15) |i| if (row[o.borrow + i] > active) return false;
    for (0..16) |i| {
        const x = row[o.output + 2 * i] + 256 * row[o.output + 2 * i + 1];
        const d = row[o.distance + 2 * i] + 256 * row[o.distance + 2 * i + 1];
        const c = if (i == 0) active else row[o.borrow + i - 1];
        const next = if (i == 15) 0 else row[o.borrow + i];
        if (@as(i64, x) + d + c - @as(i64, active) * @as(i64, @intCast((P >> @intCast(16 * i)) & 65535)) - 65536 * @as(i64, next) != 0) return false;
    }
    return true;
}
pub fn fill(row: []u32, o: Offsets, value: u256) void {
    const distance = (P - 1) -% value;
    var carry: u32 = 1;
    for (0..32) |i| {
        row[o.output + i] = @intCast((value >> @intCast(8 * i)) & 255);
        row[o.distance + i] = @intCast((distance >> @intCast(8 * i)) & 255);
    }
    for (0..16) |i| {
        const residual = @as(i64, row[o.output + 2 * i]) + 256 * @as(i64, row[o.output + 2 * i + 1]) + row[o.distance + 2 * i] + 256 * @as(i64, row[o.distance + 2 * i + 1]) + carry - @as(i64, @intCast((P >> @intCast(16 * i)) & 65535));
        carry = if (residual >= 0 and @mod(residual, 65536) == 0) @intCast(@divExact(residual, 65536)) else 2;
        if (i < 15) row[o.borrow + i] = carry;
    }
}
