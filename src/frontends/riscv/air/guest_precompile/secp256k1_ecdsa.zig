//! Successful secp256k1 ECDSA transaction witness authority.
//!
//! Parsing alone is not proof authority. This path records the curve equation,
//! scalar inverse and products, GLV scalar program, and final `x mod n == r`
//! check in one exact tape range consumed by the typed ECDSA component.

const std = @import("std");
const affine = @import("secp256k1_affine.zig");
const field = @import("secp256k1_field.zig");

pub fn verify(
    tape: *affine.Tape,
    digest_big_endian: [32]u8,
    public_key_sec1: [65]u8,
    r_big_endian: [32]u8,
    s_big_endian: [32]u8,
) !bool {
    const public_key = affine.pointFromSec1(&public_key_sec1) catch return false;
    const product_start = tape.products.items.len;
    const linear_start = tape.linears.items.len;
    const point_start = tape.points.items.len;
    const split_start = tape.scalar_splits.items.len;
    var digest = reverse(digest_big_endian);
    const r = reverse(r_big_endian);
    const s = reverse(s_big_endian);
    const order = field.scalar_modulus.integer();
    if (integer(r) == 0 or integer(s) == 0 or integer(r) >= order or integer(s) >= order)
        return false;

    try assertOnCurve(tape, public_key);
    digest = try tape.reduceScalarOnce(digest);
    const inverse_s = try tape.inverse(.scalar, s);
    const generator_scalar = try tape.mul(.scalar, digest, inverse_s);
    const public_key_scalar = try tape.mul(.scalar, r, inverse_s);
    const program_index = tape.scalar_programs.items.len;
    const result = try affine.doubleScalarGlvWnaf(
        tape,
        generator_scalar,
        public_key,
        public_key_scalar,
    );
    if (result.infinity) return false;
    const x_scalar = try tape.reduceScalarOnce(result.x);
    if (!std.mem.eql(u8, &x_scalar, &r)) return false;

    const product_count = tape.products.items.len - product_start;
    const linear_count = tape.linears.items.len - linear_start;
    const point_count = tape.points.items.len - point_start;
    const split_count = tape.scalar_splits.items.len - split_start;
    if (product_start > std.math.maxInt(u32) or
        linear_start > std.math.maxInt(u32) or
        point_start > std.math.maxInt(u32) or
        split_start > std.math.maxInt(u32) or
        program_index > std.math.maxInt(u32) or
        product_count > std.math.maxInt(u32) or
        linear_count > std.math.maxInt(u32) or
        point_count > std.math.maxInt(u32) or
        split_count > std.math.maxInt(u8))
    {
        return error.TapeOverflow;
    }
    try tape.ecdsa.append(tape.allocator, .{
        .digest_big_endian = digest_big_endian,
        .public_key = public_key,
        .r = r,
        .s = s,
        .reduced_digest = digest,
        .inverse_s = inverse_s,
        .generator_scalar = generator_scalar,
        .public_key_scalar = public_key_scalar,
        .result = result,
        .program_index = @intCast(program_index),
        .product_start = @intCast(product_start),
        .product_count = @intCast(product_count),
        .linear_start = @intCast(linear_start),
        .linear_count = @intCast(linear_count),
        .point_start = @intCast(point_start),
        .point_count = @intCast(point_count),
        .split_start = @intCast(split_start),
        .split_count = @intCast(split_count),
    });
    return true;
}

/// Records `y² = x³ + 7` through the same product and linear buses used
/// by every later affine transition.
pub fn assertOnCurve(tape: *affine.Tape, point: affine.Point) !void {
    if (point.infinity) return error.IdentityPoint;
    const y_squared = try tape.mul(.base, point.y, point.y);
    const x_squared = try tape.mul(.base, point.x, point.x);
    const x_cubed = try tape.mul(.base, x_squared, point.x);
    const rhs = try tape.add(.base, x_cubed, field.bytesFromInteger(7));
    if (!std.mem.eql(u8, &y_squared, &rhs)) return error.PointNotOnCurve;
}

fn reverse(input: [32]u8) [32]u8 {
    var result: [32]u8 = undefined;
    for (input, 0..) |byte, index| result[input.len - 1 - index] = byte;
    return result;
}

fn integer(value: affine.Value) u256 {
    return std.mem.readInt(u256, &value, .little);
}
