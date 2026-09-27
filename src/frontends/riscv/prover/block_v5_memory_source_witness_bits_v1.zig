//! Exact existing source bit codec; no hash/snapshot is proof authority.
const std = @import("std");
const M = @import("stwo_core").fields.m31.M31;
const Eq = @import("../recursion/air/block_v5_memory_source_equations_v1.zig");
pub fn writeBits(w: Eq.Witness, out: *[Eq.BIT_COUNT]M) void {
    var at: usize = 0;
    for (w.raw) |x| putBits(out, &at, x, 8);
    for (w.state) |x| putBits(out, &at, x, 32);
    for ([_]u32{ w.address, w.previous_address, w.before, w.after }) |x| putBits(out, &at, x, 32);
    putBits(out, &at, w.clock, 64);
    for ([_][32]u8{ w.before_hash, w.after_hash, w.sibling }) |d| for (d) |x| {
        putBits(out, &at, x, 8);
    };
    std.debug.assert(at == Eq.BIT_COUNT);
}
fn putBits(out: *[Eq.BIT_COUNT]M, at: *usize, value: u64, bits: usize) void {
    for (0..bits) |i| {
        out[at.*] = M.fromCanonical(@intCast((value >> @intCast(i)) & 1));
        at.* += 1;
    }
}
fn putLimbs(out: []M, value: u64) void {
    for (out, 0..) |*v, i| v.* = M.fromCanonical(@intCast((value >> @intCast(16 * i)) & 65535));
}
pub fn restoreBits(bits: *const [Eq.BIT_COUNT]M) !Eq.Witness {
    var at: usize = 0;
    var w: Eq.Witness = undefined;
    for (&w.raw) |*v| v.* = @intCast(try takeBits(bits, &at, 8));
    for (&w.state) |*v| v.* = @intCast(try takeBits(bits, &at, 32));
    w.address = @intCast(try takeBits(bits, &at, 32));
    w.previous_address = @intCast(try takeBits(bits, &at, 32));
    w.before = @intCast(try takeBits(bits, &at, 32));
    w.after = @intCast(try takeBits(bits, &at, 32));
    w.clock = try takeBits(bits, &at, 64);
    for (&w.before_hash) |*v| v.* = @intCast(try takeBits(bits, &at, 8));
    for (&w.after_hash) |*v| v.* = @intCast(try takeBits(bits, &at, 8));
    for (&w.sibling) |*v| v.* = @intCast(try takeBits(bits, &at, 8));
    std.debug.assert(at == Eq.BIT_COUNT);
    return w;
}
fn takeBits(bits: *const [Eq.BIT_COUNT]M, at: *usize, n: usize) !u64 {
    var value: u64 = 0;
    for (0..n) |i| {
        const bit = bits[at.*].toU32();
        if (bit > 1) return error.InvalidSourcePrivateBit;
        value |= @as(u64, bit) << @intCast(i);
        at.* += 1;
    }
    return value;
}
