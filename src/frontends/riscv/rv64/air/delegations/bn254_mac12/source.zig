//! NEW signed MAC12 source row. Fixed program coefficients and SSA IDs are
//! receiver/source authority. No VM/protocol or production admission.
const std = @import("std");
const E = @import("../../evaluation.zig");
pub const B = @import("bounds.zig");
const Canon = @import("canonical_word16.zig");
pub const PRODUCTS = 12;
pub const INPUTS = 25;
pub const ACTIVE = 0;
pub const INPUT = 1;
pub const OUTPUT = INPUT + 32 * INPUTS;
pub const SIGN = OUTPUT + 32;
pub const QUOTIENT = SIGN + 1;
pub const CARRY = QUOTIENT + 33;
pub const DISTANCE = CARRY + 64 * 3;
pub const BORROW = DISTANCE + 32;
pub const MAIN = BORROW + 15;
pub const FIXED = 40;
pub const FIX_ACTIVE = 0;
pub const COEFFICIENT = 1;
pub const INPUT_ID = 13;
pub const WRITER_ID = 38;
pub const FANOUT = 39;
pub const BYTE_QUERIES = 353;
pub const CONSTRAINTS = 1 + (MAIN - 1) + 1 + 65 + Canon.CONSTRAINTS;
pub const Row = [MAIN]u32;
pub const Fixed = [FIXED]i32;
pub const canonical = Canon.Offsets{ .output = OUTPUT, .distance = DISTANCE, .borrow = BORROW };
/// Trusted immutable ROM constructor; inputs inherit canonical BYTE writers
/// through exact unit-weight SSA reads. This does not establish that closure.
pub fn fixed(active: bool, coefficients: [PRODUCTS]i32, ids: [INPUTS]u32, writer: u32, fanout: u32) !Fixed {
    const p = 2147483647;
    var out: Fixed = @splat(0);
    if (!active) {
        for (coefficients) |c| if (c != 0) return error.Mac12InactiveAuthority;
        for (ids) |id| if (id != 0) return error.Mac12InactiveAuthority;
        if (writer != 0 or fanout != 0) return error.Mac12InactiveAuthority;
        return out;
    }
    if (writer >= p or fanout >= p) return error.Mac12SourceMassBound;
    out[FIX_ACTIVE] = 1;
    for (coefficients, 0..) |c, i| {
        if (@abs(c) > 18) return error.Mac12CoefficientBound;
        out[COEFFICIENT + i] = c;
    }
    for (ids, 0..) |id, i| {
        if (id >= p or id == writer) return error.Mac12SourceIdBound;
        out[INPUT_ID + i] = @intCast(id);
    }
    out[WRITER_ID] = @intCast(writer);
    out[FANOUT] = @intCast(fanout);
    return out;
}
fn k(comptime F: type, value: u32) F {
    return E.qFor(F, value);
}
fn carry(comptime F: type, v: anytype, n: usize) F {
    var out = F.zero();
    for (0..3) |i| out = out.add(v.main(CARRY + 3 * n + i).mul(k(F, @as(u32, 1) << @intCast(8 * i))));
    return out.sub(v.main(ACTIVE).mul(k(F, @intCast(B.OFFSET))));
}
pub fn byteQuery(comptime F: type, v: anytype, index: usize) F {
    std.debug.assert(index < BYTE_QUERIES);
    if (index < 32) return v.main(OUTPUT + index);
    var i = index - 32;
    if (i < 33) return v.main(QUOTIENT + i);
    i -= 33;
    if (i < 192) return v.main(CARRY + i);
    i -= 192;
    if (i < 64) return v.main(CARRY + 3 * i + 2).add(v.main(ACTIVE).mul(k(F, 192)));
    i -= 64;
    return v.main(DISTANCE + i);
}
pub fn emit(comptime F: type, v: anytype, sink: anytype) void {
    const active = v.main(ACTIVE);
    sink.emit(active.sub(v.fixed(FIX_ACTIVE)));
    for (INPUT..MAIN) |c| sink.emit(F.one().sub(active).mul(v.main(c)));
    const sign = v.main(SIGN);
    sink.emit(sign.mul(sign.sub(active)));
    for (0..65) |n| {
        var residual = F.zero();
        if (n < 63) for (0..12) |term| {
            var product = F.zero();
            const first = if (n >= 32) n - 31 else 0;
            for (first..@min(n + 1, 32)) |i| product = product.add(v.main(INPUT + 64 * term + i).mul(v.main(INPUT + 64 * term + 32 + n - i)));
            residual = residual.add(v.fixed(COEFFICIENT + term).mul(product));
        };
        if (n < 32) residual = residual.add(v.main(INPUT + 32 * 24 + n)).sub(v.main(OUTPUT + n));
        var q = F.zero();
        const first = if (n >= 32) n - 31 else 0;
        var i = first;
        while (i < 33 and i <= n) : (i += 1) q = q.add(v.main(QUOTIENT + i).mul(k(F, @intCast((B.P >> @intCast(8 * (n - i))) & 255))));
        residual = residual.sub(F.one().sub(sign.mul(k(F, 2))).mul(q));
        if (n > 0) residual = residual.add(carry(F, v, n - 1));
        if (n < 64) residual = residual.sub(carry(F, v, n).mul(k(F, 256)));
        sink.emit(residual);
    }
    Canon.emit(F, v, canonical, active, sink);
}
