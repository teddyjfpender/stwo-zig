//! Shared scalar and SIMD BLAKE2s arithmetic; schedules remain with their owners.
const builtin = @import("builtin");
const V4 = @Vector(4, u32);
const V8 = @Vector(8, u32);
const Shift4 = @Vector(4, u5);
const V16u8 = @Vector(16, u8);

fn rotateScalar(x: u32, bits: u5) u32 {
    const left_bits: u5 = @intCast((@as(u6, 32) - @as(u6, bits)) & 31);
    return (x >> bits) | (x << left_bits);
}

pub fn rotate4(x: V4, comptime bits: u5) V4 {
    if (comptime builtin.cpu.arch.endian() == .little) {
        const bytes: V16u8 = @bitCast(x);
        switch (bits) {
            8 => return @bitCast(@shuffle(u8, bytes, bytes, @Vector(16, i32){
                1,  2,  3,  0,
                5,  6,  7,  4,
                9,  10, 11, 8,
                13, 14, 15, 12,
            })),
            16 => return @bitCast(@shuffle(u8, bytes, bytes, @Vector(16, i32){
                2,  3,  0,  1,
                6,  7,  4,  5,
                10, 11, 8,  9,
                14, 15, 12, 13,
            })),
            else => {},
        }
    }
    const left_bits: u5 = @intCast((@as(u6, 32) - @as(u6, bits)) & 31);
    const r: Shift4 = @splat(bits);
    const l: Shift4 = @splat(left_bits);
    return (x >> r) | (x << l);
}

pub fn rotate8(x: V8, comptime bits: u5) V8 {
    const halves: [2]V4 = @bitCast(x);
    return @bitCast([2]V4{ rotate4(halves[0], bits), rotate4(halves[1], bits) });
}

pub fn Lane(comptime T: type) type {
    const rotate = if (T == u32) rotateScalar else if (T == V4) rotate4 else if (T == V8) rotate8 else @compileError("unsupported BLAKE2s lane type");
    return struct {
        pub inline fn mix(a: *T, b: *T, c: *T, d: *T, x: T, y: T) void {
            a.* = a.* +% b.* +% x;
            d.* = rotate(d.* ^ a.*, 16);
            c.* = c.* +% d.*;
            b.* = rotate(b.* ^ c.*, 12);
            a.* = a.* +% b.* +% y;
            d.* = rotate(d.* ^ a.*, 8);
            c.* = c.* +% d.*;
            b.* = rotate(b.* ^ c.*, 7);
        }
    };
}

/// Advances four independent BLAKE2s G functions in lockstep. Grouping each
/// dependency level exposes four-way instruction-level parallelism while
/// retaining the caller's four-message SIMD lane layout.
pub inline fn g4Interleaved(
    comptime V: type,
    comptime rotate: anytype,
    v: *[16]V,
    comptime a_indices: [4]u8,
    comptime b_indices: [4]u8,
    comptime c_indices: [4]u8,
    comptime d_indices: [4]u8,
    x: [4]V,
    y: [4]V,
) void {
    inline for (0..4) |i| {
        v[a_indices[i]] = v[a_indices[i]] +% v[b_indices[i]] +% x[i];
    }
    inline for (0..4) |i| {
        v[d_indices[i]] = rotate(v[d_indices[i]] ^ v[a_indices[i]], 16);
    }
    inline for (0..4) |i| {
        v[c_indices[i]] +%= v[d_indices[i]];
    }
    inline for (0..4) |i| {
        v[b_indices[i]] = rotate(v[b_indices[i]] ^ v[c_indices[i]], 12);
    }
    inline for (0..4) |i| {
        v[a_indices[i]] = v[a_indices[i]] +% v[b_indices[i]] +% y[i];
    }
    inline for (0..4) |i| {
        v[d_indices[i]] = rotate(v[d_indices[i]] ^ v[a_indices[i]], 8);
    }
    inline for (0..4) |i| {
        v[c_indices[i]] +%= v[d_indices[i]];
    }
    inline for (0..4) |i| {
        v[b_indices[i]] = rotate(v[b_indices[i]] ^ v[c_indices[i]], 7);
    }
}

test "BLAKE2s shared rotations match independent scalar rotations for every shift" {
    const std = @import("std");
    const input: V8 = .{ 0, 0xffffffff, 0x01234567, 0x80000001, 0xdeadbeef, 1, 0x7fffffff, 0x89abcdef };
    inline for (0..32) |shift| {
        const rotated = rotate8(input, @intCast(shift));
        for (0..8) |index| {
            const expected = std.math.rotr(u32, input[index], shift);
            try std.testing.expectEqual(expected, rotated[index]);
            try std.testing.expectEqual(expected, rotateScalar(input[index], @intCast(shift)));
        }
    }
}
