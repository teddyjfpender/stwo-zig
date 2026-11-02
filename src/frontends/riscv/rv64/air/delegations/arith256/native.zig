//! Native arith256_mod witness. This is producer advice only: the AIR
//! re-derives r from the exact carried identity and the r < m chain, and the
//! Wire35 bus binds a, b, c, m and both r values to guest RAM.
const std = @import("std");
const core = @import("stwo_core");
const L = @import("layout.zig");
const M31 = core.fields.m31.M31;

/// One call: the five packet coordinates before the call.
pub const Input = struct { a: u256, b: u256, c: u256, m: u256, r_before: u256 = 0 };

/// Reference semantics (ABI): r = (a*b + c) mod m, and r = 0 when m = 0.
pub fn reference(a: u256, b: u256, c: u256, m: u256) u256 {
    if (m == 0) return 0;
    return @truncate((@as(u512, a) * @as(u512, b) + @as(u512, c)) % @as(u512, m));
}

/// Canonical M31 values of one MAIN row.
pub const Row = [L.MAIN]u32;

pub fn bytes(value: u256) [32]u8 {
    var out: [32]u8 = undefined;
    std.mem.writeInt(u256, &out, value, .little);
    return out;
}
fn put(row: *Row, base: usize, comptime count: usize, value: std.meta.Int(.unsigned, 8 * count)) void {
    var b: [count]u8 = undefined;
    std.mem.writeInt(@TypeOf(value), &b, value, .little);
    for (b, 0..) |x, i| row[base + i] = x;
}

/// Fills an ACTIVE row (MULT is left zero; the trace sets it) and returns r.
pub fn fill(row: *Row, input: Input) u256 {
    @memset(row, 0);
    row[L.ACTIVE] = 1;
    put(row, L.A, 32, input.a);
    put(row, L.B, 32, input.b);
    put(row, L.C, 32, input.c);
    put(row, L.M, 32, input.m);
    put(row, L.R_BEFORE, 32, input.r_before);
    const z = input.m == 0;
    const total = @as(u512, input.a) * @as(u512, input.b) + @as(u512, input.c);
    const q: u512 = if (z) 0 else total / @as(u512, input.m);
    const r: u256 = if (z) 0 else @truncate(total % @as(u512, input.m));
    put(row, L.R, 32, r);
    put(row, L.QUOTIENT, 64, q);
    row[L.Z] = @intFromBool(z);
    var sum_m: u32 = 0;
    for (0..L.LIMBS) |i| sum_m += row[L.M + i];
    row[L.INV] = if (sum_m == 0) 0 else (M31.fromCanonical(sum_m).inv() catch unreachable).v;
    // Signed coefficients of (1 - z)(a*b + c) - q*m - r.
    var p: [L.COEFFICIENTS + 1]i64 = @splat(0);
    if (!z) {
        for (0..L.LIMBS) |i| for (0..L.LIMBS) |j| {
            p[i + j] += @as(i64, row[L.A + i]) * row[L.B + j];
        };
        for (0..L.LIMBS) |k| p[k] += row[L.C + k];
    }
    for (0..L.Q_LIMBS) |i| for (0..L.LIMBS) |j| {
        p[i + j] -= @as(i64, row[L.QUOTIENT + i]) * row[L.M + j];
    };
    for (0..L.LIMBS) |k| p[k] -= row[L.R + k];
    var carry: i64 = 0;
    for (0..L.GROUPS) |j| {
        const g = p[2 * j] + 256 * p[2 * j + 1] + carry;
        std.debug.assert(@mod(g, 65536) == 0);
        carry = @divExact(g, 65536);
        if (j == L.CARRIES) {
            std.debug.assert(carry == 0);
            break;
        }
        std.debug.assert(carry >= -@as(i64, L.CARRY_OFFSET) and carry < L.CARRY_OFFSET);
        const encoded: u32 = @intCast(carry + L.CARRY_OFFSET);
        row[L.CARRY_LO + j] = encoded & 0xff;
        row[L.CARRY_HI + j] = encoded >> 8;
    }
    // d = m - r - (1 - z) over 16-bit chunks with borrows.
    const d: u256 = if (z) 0 else input.m - r - 1;
    put(row, L.D, 32, d);
    var borrow: u32 = 0;
    for (0..L.BORROWS) |i| {
        const mi = row[L.M + 2 * i] + 256 * row[L.M + 2 * i + 1];
        const ri = row[L.R + 2 * i] + 256 * row[L.R + 2 * i + 1];
        const s: u32 = if (i == 0) @intFromBool(!z) else 0;
        borrow = @intFromBool(mi < ri + s + borrow);
        row[L.BORROW + i] = borrow;
    }
    return r;
}

/// The Wire35 payload of `wire` for one call.
pub fn wireBytes(input: Input, r: u256, wire: u32) [32]u8 {
    return bytes(switch (wire) {
        0 => input.a,
        1 => input.b,
        2 => input.c,
        3 => input.m,
        4 => input.r_before,
        L.OUTPUT_WIRE => r,
        else => unreachable,
    });
}
