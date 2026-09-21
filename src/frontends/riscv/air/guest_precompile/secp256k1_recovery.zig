//! Successful parity-bound secp256k1 public-key recovery witness authority.
//!
//! This is a separate transaction from ordinary ECDSA verification. Ethereum
//! supplies only recovery ids 0/1, so `R.x = r` and the id selects the parity
//! of `R.y`; the unsupported `x = r + n` branch is unrepresentable.

const std = @import("std");
const affine = @import("secp256k1_affine.zig");
const ecdsa = @import("secp256k1_ecdsa.zig");
const field = @import("secp256k1_field.zig");

const Secp256k1 = std.crypto.ecc.Secp256k1;

pub const Error = error{
    InvalidRecoveryId,
    InvalidScalar,
    RecoveredIdentity,
    RecoveredPublicKeyMismatch,
    TapeOverflow,
};

/// Records one successful recovery transaction, or leaves `tape` unchanged.
/// The public key is the ABI's uncompressed x||y big-endian encoding.
pub fn recover(
    tape: *affine.Tape,
    digest_big_endian: [32]u8,
    r_big_endian: [32]u8,
    s_big_endian: [32]u8,
    recovery_id: u32,
    public_key_big_endian: [64]u8,
) !void {
    if (recovery_id > 1) return error.InvalidRecoveryId;

    const r = reverse(r_big_endian);
    const s = reverse(s_big_endian);
    const order = field.scalar_modulus.integer();
    if (integer(r) == 0 or integer(s) == 0 or
        integer(r) >= order or integer(s) >= order)
    {
        return error.InvalidScalar;
    }

    const r_fe = Secp256k1.Fe.fromBytes(r_big_endian, .big) catch
        return error.InvalidScalar;
    const recovery_y = Secp256k1.recoverY(r_fe, recovery_id == 1) catch
        return error.InvalidScalar;
    const recovery_std = Secp256k1.fromAffineCoordinates(.{
        .x = r_fe,
        .y = recovery_y,
    }) catch return error.InvalidScalar;
    const recovery_point = affine.pointFromSec1(
        &recovery_std.toUncompressedSec1(),
    ) catch return error.InvalidScalar;

    const checkpoint = Checkpoint.capture(tape);
    errdefer checkpoint.restore(tape);
    const product_start = tape.products.items.len;
    const linear_start = tape.linears.items.len;
    const point_start = tape.points.items.len;
    const split_start = tape.scalar_splits.items.len;

    try ecdsa.assertOnCurve(tape, recovery_point);
    const reduced_digest = try tape.reduceScalarOnce(reverse(digest_big_endian));
    const inverse_r = try tape.inverse(.scalar, r);
    const inverse_s = try tape.inverse(.scalar, s);
    const negative_digest = try tape.sub(.scalar, @splat(0), reduced_digest);
    const generator_scalar = try tape.mul(
        .scalar,
        negative_digest,
        inverse_r,
    );
    const recovery_point_scalar = try tape.mul(.scalar, s, inverse_r);
    const program_index = tape.scalar_programs.items.len;
    const public_key = try affine.doubleScalarGlvWnaf(
        tape,
        generator_scalar,
        recovery_point,
        recovery_point_scalar,
    );
    if (public_key.infinity) return error.RecoveredIdentity;
    const encoded = (try affine.pointToStd(public_key)).toUncompressedSec1();
    if (!std.mem.eql(u8, encoded[1..], &public_key_big_endian))
        return error.RecoveredPublicKeyMismatch;

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
    try tape.recoveries.append(tape.allocator, .{
        .digest_big_endian = digest_big_endian,
        .r = r,
        .s = s,
        .recovery_id = @intCast(recovery_id),
        .recovery_point = recovery_point,
        .public_key = public_key,
        .reduced_digest = reduced_digest,
        .inverse_r = inverse_r,
        .inverse_s = inverse_s,
        .negative_digest = negative_digest,
        .generator_scalar = generator_scalar,
        .recovery_point_scalar = recovery_point_scalar,
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
}

const Checkpoint = struct {
    products: usize,
    linears: usize,
    points: usize,
    scalar_splits: usize,
    tables: usize,
    scalar_steps: usize,
    scalar_programs: usize,
    ecdsa: usize,
    recoveries: usize,

    fn capture(tape: *const affine.Tape) Checkpoint {
        return .{
            .products = tape.products.items.len,
            .linears = tape.linears.items.len,
            .points = tape.points.items.len,
            .scalar_splits = tape.scalar_splits.items.len,
            .tables = tape.tables.items.len,
            .scalar_steps = tape.scalar_steps.items.len,
            .scalar_programs = tape.scalar_programs.items.len,
            .ecdsa = tape.ecdsa.items.len,
            .recoveries = tape.recoveries.items.len,
        };
    }

    fn restore(self: Checkpoint, tape: *affine.Tape) void {
        tape.products.shrinkRetainingCapacity(self.products);
        tape.linears.shrinkRetainingCapacity(self.linears);
        tape.points.shrinkRetainingCapacity(self.points);
        tape.scalar_splits.shrinkRetainingCapacity(self.scalar_splits);
        tape.tables.shrinkRetainingCapacity(self.tables);
        tape.scalar_steps.shrinkRetainingCapacity(self.scalar_steps);
        tape.scalar_programs.shrinkRetainingCapacity(self.scalar_programs);
        tape.ecdsa.shrinkRetainingCapacity(self.ecdsa);
        tape.recoveries.shrinkRetainingCapacity(self.recoveries);
    }
};

fn reverse(input: [32]u8) [32]u8 {
    var result: [32]u8 = undefined;
    for (input, 0..) |byte, index| result[input.len - 1 - index] = byte;
    return result;
}

fn integer(value: affine.Value) u256 {
    return std.mem.readInt(u256, &value, .little);
}
