//! Contiguous bit-reversed LDE partitions on smaller conjugate cosets.
const std = @import("std");
const core = @import("stwo_core");
const poly = @import("mod.zig");
const M31 = core.fields.m31.M31;

pub fn domain(full: poly.CircleDomain, log_parts: u32, part: usize) !poly.CircleDomain {
    if (log_parts > full.half_coset.log_size or part >= @as(usize, 1) << @intCast(log_parts))
        return error.InvalidCosetPartition;
    if (log_parts == 0) return full;
    const natural_part = core.utils.bitReverseIndex(part, log_parts);
    return poly.CircleDomain.new(core.circle.Coset.new(
        full.half_coset.initial_index.add(full.half_coset.step_size.mul(natural_part)),
        full.half_coset.log_size - log_parts,
    ));
}

test "coefficient storage coset partitions reproduce contiguous full LDE slices" {
    const a = std.testing.allocator;
    for (2..7) |native| {
        const coefficients = try a.alloc(M31, @as(usize, 1) << @intCast(native));
        defer a.free(coefficients);
        for (coefficients, 0..) |*c, i| c.* = M31.fromU64(37 * i + 19 * i * i + 13);
        const polynomial = try poly.CircleCoefficients.initBorrowed(coefficients);
        for (1..4) |extra| {
            const full_domain = poly.CanonicCoset.new(@intCast(native + extra)).circleDomain();
            const full = try polynomial.evaluate(a, full_domain);
            defer a.free(full.values);
            for (0..@as(usize, 1) << @intCast(extra)) |part| {
                const subdomain = try domain(full_domain, @intCast(extra), part);
                const values = try polynomial.evaluate(a, subdomain);
                defer a.free(values.values);
                try std.testing.expectEqualSlices(M31, full.values[part * coefficients.len ..][0..coefficients.len], values.values);
            }
        }
    }
}
