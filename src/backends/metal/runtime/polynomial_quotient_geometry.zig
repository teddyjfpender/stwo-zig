//! Exact quotient-coset geometry shared by resident polynomial kernels.
//!
//! Legacy degree-three components use two denominator cosets.  The append-only
//! degree-five/six path uses four/eight respectively.  Keeping this arithmetic
//! outside the full Metal runtime gives backend work a seconds-scale semantic
//! test instead of rebuilding the AOT toolchain.

const std = @import("std");
const core = @import("stwo_core");

const M31 = core.fields.m31.M31;

pub const MAX_DENOMINATORS: usize = 8;

pub const Set = struct {
    values: [MAX_DENOMINATORS]M31,
    count: u32,
};

pub fn derive(trace_log_size: u32, eval_log_size: u32) !Set {
    if (eval_log_size <= trace_log_size or
        eval_log_size - trace_log_size > 3)
    {
        return error.InvalidBasePolynomialProgram;
    }
    const extension_bits: u5 = @intCast(eval_log_size - trace_log_size);
    const count: usize = @as(usize, 1) << extension_bits;
    const eval_domain = core.poly.circle.canonic.CanonicCoset.new(
        eval_log_size,
    ).circleDomain();
    const coset = core.poly.circle.canonic.CanonicCoset.new(
        trace_log_size,
    ).coset();
    var result = Set{
        .values = .{M31.zero()} ** MAX_DENOMINATORS,
        .count = @intCast(count),
    };
    for (result.values[0..count], 0..) |*inverse, index| {
        inverse.* = try core.constraints.cosetVanishing(
            M31,
            coset,
            eval_domain.at(core.utils.bitReverseIndex(index, extension_bits)),
        ).inv();
    }
    return result;
}

pub fn words(set: Set) [MAX_DENOMINATORS]u32 {
    var result = [_]u32{0} ** MAX_DENOMINATORS;
    for (set.values[0..set.count], 0..) |value, index| {
        result[index] = value.toU32();
    }
    return result;
}

test "quotient denominators preserve legacy and degree-six cosets" {
    const expanded = try derive(5, 8);
    try std.testing.expectEqual(@as(u32, 8), expanded.count);
    for (words(expanded)) |word| try std.testing.expect(word != 0);
    const legacy = try derive(5, 6);
    try std.testing.expectEqual(@as(u32, 2), legacy.count);
    try std.testing.expectError(
        error.InvalidBasePolynomialProgram,
        derive(5, 9),
    );
}
