const std = @import("std");
const circle = @import("stwo_core").circle;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;

const M31 = m31.M31;
const QM31 = qm31.QM31;
const CirclePointQM31 = circle.CirclePointQM31;

/// Evaluates circle-basis coefficients using precomputed point factors.
///
/// The carry-style reduction preserves the recursive evaluator's left/right
/// merge order while using bounded stack storage and no recursion.
pub inline fn evalAtPointIterative(
    coeffs: []const M31,
    factors: []const QM31,
    log_size: u32,
) QM31 {
    std.debug.assert(coeffs.len == (@as(usize, 1) << @intCast(log_size)));
    std.debug.assert(factors.len == log_size);

    if (log_size == 0) return QM31.fromBase(coeffs[0]);

    var pending: [circle.M31_CIRCLE_LOG_ORDER + 1]QM31 = undefined;

    for (coeffs, 0..) |coeff, coeff_idx| {
        var value = QM31.fromBase(coeff);
        var level: usize = @as(usize, @intCast(@ctz(~coeff_idx)));
        if (level > @as(usize, @intCast(log_size))) level = @as(usize, @intCast(log_size));
        var merge_level: usize = 0;
        while (merge_level < level) : (merge_level += 1) {
            value = pending[merge_level].add(value.mul(factors[merge_level]));
        }
        pending[level] = value;
    }

    return pending[log_size];
}

const PackedM31 = m31.PackedM31;

const PackedCM31 = struct {
    a: PackedM31,
    b: PackedM31,
};

const PackedQM31 = struct {
    c0: PackedCM31,
    c1: PackedCM31,
};

const PreparedPackedCM31 = struct {
    a: PackedM31,
    b: PackedM31,
    a_plus_b: PackedM31,
};

const PreparedPackedQM31 = struct {
    c0: PreparedPackedCM31,
    c1: PreparedPackedCM31,
    c0_plus_c1: PreparedPackedCM31,
};

inline fn addPackedCM31(lhs: PackedCM31, rhs: PackedCM31) PackedCM31 {
    return .{
        .a = m31.addPacked(lhs.a, rhs.a),
        .b = m31.addPacked(lhs.b, rhs.b),
    };
}

inline fn subPackedCM31(lhs: PackedCM31, rhs: PackedCM31) PackedCM31 {
    return .{
        .a = m31.subPacked(lhs.a, rhs.a),
        .b = m31.subPacked(lhs.b, rhs.b),
    };
}

inline fn mulPackedCM31(lhs: PackedCM31, rhs: PackedCM31) PackedCM31 {
    const ac = m31.mulPacked(lhs.a, rhs.a);
    const bd = m31.mulPacked(lhs.b, rhs.b);
    const cross = m31.mulPacked(
        m31.addPacked(lhs.a, lhs.b),
        m31.addPacked(rhs.a, rhs.b),
    );
    return .{
        .a = m31.subPacked(ac, bd),
        .b = m31.subPacked(m31.subPacked(cross, ac), bd),
    };
}

inline fn preparePackedCM31(value: PackedCM31) PreparedPackedCM31 {
    return .{
        .a = value.a,
        .b = value.b,
        .a_plus_b = m31.addPacked(value.a, value.b),
    };
}

inline fn preparePackedQM31(value: PackedQM31) PreparedPackedQM31 {
    return .{
        .c0 = preparePackedCM31(value.c0),
        .c1 = preparePackedCM31(value.c1),
        .c0_plus_c1 = preparePackedCM31(addPackedCM31(value.c0, value.c1)),
    };
}

inline fn mulPreparedPackedCM31(
    lhs: PreparedPackedCM31,
    rhs: PreparedPackedCM31,
) PackedCM31 {
    const ac = m31.mulPacked(lhs.a, rhs.a);
    const bd = m31.mulPacked(lhs.b, rhs.b);
    const cross = m31.mulPacked(lhs.a_plus_b, rhs.a_plus_b);
    return .{
        .a = m31.subPacked(ac, bd),
        .b = m31.subPacked(m31.subPacked(cross, ac), bd),
    };
}

inline fn mulPreparedPackedQM31(
    lhs: PreparedPackedQM31,
    rhs: PreparedPackedQM31,
) PackedQM31 {
    const ac = mulPreparedPackedCM31(lhs.c0, rhs.c0);
    const bd = mulPreparedPackedCM31(lhs.c1, rhs.c1);
    const cross_product = mulPreparedPackedCM31(lhs.c0_plus_c1, rhs.c0_plus_c1);
    return .{
        .c0 = addPackedCM31(ac, mulPackedCM31ByR(bd)),
        .c1 = subPackedCM31(subPackedCM31(cross_product, ac), bd),
    };
}

inline fn mulPackedCM31ByR(value: PackedCM31) PackedCM31 {
    // (a + bi) * (2 + i) = (2a - b) + (a + 2b)i.
    return .{
        .a = m31.subPacked(m31.addPacked(value.a, value.a), value.b),
        .b = m31.addPacked(value.a, m31.addPacked(value.b, value.b)),
    };
}

inline fn addPackedQM31(lhs: PackedQM31, rhs: PackedQM31) PackedQM31 {
    return .{
        .c0 = addPackedCM31(lhs.c0, rhs.c0),
        .c1 = addPackedCM31(lhs.c1, rhs.c1),
    };
}

inline fn mulPackedQM31(lhs: PackedQM31, rhs: PackedQM31) PackedQM31 {
    const ac = mulPackedCM31(lhs.c0, rhs.c0);
    const bd = mulPackedCM31(lhs.c1, rhs.c1);
    const cross = subPackedCM31(
        subPackedCM31(
            mulPackedCM31(
                addPackedCM31(lhs.c0, lhs.c1),
                addPackedCM31(rhs.c0, rhs.c1),
            ),
            ac,
        ),
        bd,
    );
    return .{
        .c0 = addPackedCM31(ac, mulPackedCM31ByR(bd)),
        .c1 = cross,
    };
}

inline fn packedQM31FromBase(values: PackedM31) PackedQM31 {
    const zero: PackedM31 = @splat(0);
    return .{
        .c0 = .{ .a = values, .b = zero },
        .c1 = .{ .a = zero, .b = zero },
    };
}

inline fn splatQM31(value: QM31) PackedQM31 {
    const limbs = value.toM31Array();
    return .{
        .c0 = .{
            .a = m31.splatPacked(limbs[0]),
            .b = m31.splatPacked(limbs[1]),
        },
        .c1 = .{
            .a = m31.splatPacked(limbs[2]),
            .b = m31.splatPacked(limbs[3]),
        },
    };
}

inline fn packQM31(values: [m31.PACK_WIDTH]QM31) PackedQM31 {
    var packed_value: PackedQM31 = undefined;
    for (values, 0..) |value, lane| {
        const limbs = value.toM31Array();
        packed_value.c0.a[lane] = limbs[0].v;
        packed_value.c0.b[lane] = limbs[1].v;
        packed_value.c1.a[lane] = limbs[2].v;
        packed_value.c1.b[lane] = limbs[3].v;
    }
    return packed_value;
}

inline fn unpackQM31(value: PackedQM31) [m31.PACK_WIDTH]QM31 {
    var values: [m31.PACK_WIDTH]QM31 = undefined;
    for (0..m31.PACK_WIDTH) |lane| {
        values[lane] = QM31.fromU32Unchecked(
            value.c0.a[lane],
            value.c0.b[lane],
            value.c1.a[lane],
            value.c1.b[lane],
        );
    }
    return values;
}

inline fn mulPackedQM31ByPackedM31(value: PackedQM31, scalar: PackedM31) PackedQM31 {
    return .{
        .c0 = .{
            .a = m31.mulPacked(value.c0.a, scalar),
            .b = m31.mulPacked(value.c0.b, scalar),
        },
        .c1 = .{
            .a = m31.mulPacked(value.c1.a, scalar),
            .b = m31.mulPacked(value.c1.b, scalar),
        },
    };
}

/// Materializes the multilinear subset-product basis induced by `factors`.
/// Each entry reuses the basis value obtained by clearing its least-significant
/// set bit, so the complete basis needs exactly one QM31 multiplication per
/// non-constant entry.
pub fn fillSubsetProductBasis(factors: []const QM31, out: []QM31) void {
    std.debug.assert(out.len == (@as(usize, 1) << @intCast(factors.len)));
    out[0] = QM31.one();
    const low_log = @min(factors.len, 8);
    const low_len = @as(usize, 1) << @intCast(low_log);
    for (out[1..low_len], 1..) |*value, index| {
        const previous = index & (index - 1);
        const factor_index: usize = @intCast(@ctz(index));
        value.* = out[previous].mul(factors[factor_index]);
    }
    if (factors.len <= 8) return;

    const block_count = out.len >> 8;
    var packed_low_values: [256 / m31.PACK_WIDTH]PreparedPackedQM31 = undefined;
    if (comptime m31.PACK_WIDTH > 1) {
        for (&packed_low_values, 0..) |*packed_low, low_batch| {
            var low_values: [m31.PACK_WIDTH]QM31 = undefined;
            for (0..m31.PACK_WIDTH) |lane| {
                low_values[lane] = out[low_batch * m31.PACK_WIDTH + lane];
            }
            packed_low.* = preparePackedQM31(packQM31(low_values));
        }
    }
    for (1..block_count) |block| {
        const previous_block = block & (block - 1);
        const factor_index = 8 + @as(usize, @intCast(@ctz(block)));
        const high_value = out[previous_block << 8].mul(factors[factor_index]);

        if (comptime m31.PACK_WIDTH > 1) {
            const packed_high = preparePackedQM31(splatQM31(high_value));
            for (packed_low_values, 0..) |packed_low, low_batch| {
                const low_index = low_batch * m31.PACK_WIDTH;
                const products = unpackQM31(mulPreparedPackedQM31(packed_low, packed_high));
                for (products, 0..) |product, lane| {
                    out[(block << 8) + low_index + lane] = product;
                }
            }
        } else {
            for (0..256) |low_index| {
                out[(block << 8) + low_index] = out[low_index].mul(high_value);
            }
        }
    }
}

/// Evaluates one native-width batch against an already materialized basis.
/// Independent columns occupy packed lanes while each basis value is multiplied
/// only by base-field coefficients, avoiding a full extension multiplication
/// per column and coefficient.
pub inline fn evalBatchWithSubsetProductBasis(
    coefficient_batches: [m31.PACK_WIDTH][]const M31,
    basis: []const QM31,
) [m31.PACK_WIDTH]QM31 {
    for (coefficient_batches) |coefficients| {
        std.debug.assert(coefficients.len == basis.len);
    }

    const zero: PackedM31 = @splat(0);
    var accumulator = packedQM31FromBase(zero);
    var coefficient_index: usize = 0;
    // Four canonical products fit exactly in u64. Reduce their sum once,
    // using the shared field primitive instead of reducing each product and
    // each intermediate addition in the sampled-value hot loop.
    while (coefficient_index + 4 <= basis.len) : (coefficient_index += 4) {
        var coefficients: [4]PackedM31 = undefined;
        var factors: [4][4]PackedM31 = undefined;
        inline for (0..4) |term| {
            inline for (0..m31.PACK_WIDTH) |lane|
                coefficients[term][lane] = coefficient_batches[lane][coefficient_index + term].v;
            const coordinates = basis[coefficient_index + term].toM31Array();
            inline for (0..4) |coordinate|
                factors[coordinate][term] = m31.splatPacked(coordinates[coordinate]);
        }
        accumulator = addPackedQM31(accumulator, .{
            .c0 = .{ .a = m31.dot4Packed(coefficients, factors[0]), .b = m31.dot4Packed(coefficients, factors[1]) },
            .c1 = .{ .a = m31.dot4Packed(coefficients, factors[2]), .b = m31.dot4Packed(coefficients, factors[3]) },
        });
    }
    while (coefficient_index < basis.len) : (coefficient_index += 1) {
        var packed_coefficients: PackedM31 = undefined;
        for (0..m31.PACK_WIDTH) |lane| {
            packed_coefficients[lane] = coefficient_batches[lane][coefficient_index].v;
        }
        accumulator = addPackedQM31(
            accumulator,
            mulPackedQM31ByPackedM31(splatQM31(basis[coefficient_index]), packed_coefficients),
        );
    }

    return unpackQM31(accumulator);
}

/// Factor a long basis into cache-sized low blocks and a shared high basis.
/// Only the accumulated block result needs an extension multiplication.
pub inline fn evalBatchWithSplitProductBasis(coefficient_batches: [m31.PACK_WIDTH][]const M31, low: []const QM31, high: []const QM31) [m31.PACK_WIDTH]QM31 {
    for (coefficient_batches) |column| std.debug.assert(column.len == low.len * high.len);
    var accumulator = packedQM31FromBase(@splat(0));
    for (high, 0..) |factor, block| {
        var columns: [m31.PACK_WIDTH][]const M31 = undefined;
        for (coefficient_batches, &columns) |column, *slice| slice.* = column[block * low.len ..][0..low.len];
        const value = evalBatchWithSubsetProductBasis(columns, low);
        accumulator = addPackedQM31(accumulator, mulPreparedPackedQM31(
            preparePackedQM31(packQM31(value)),
            preparePackedQM31(splatQM31(factor)),
        ));
    }
    return unpackQM31(accumulator);
}

/// Independent ragged columns retain the same exact split factorization.
pub inline fn evalWithSplitProductBasis(coefficients: []const M31, low: []const QM31, high: []const QM31) QM31 {
    std.debug.assert(coefficients.len == low.len * high.len);
    var result = QM31.zero();
    for (high, 0..) |factor, block|
        result = result.add(evalWithSubsetProductBasis(coefficients[block * low.len ..][0..low.len], low).mul(factor));
    return result;
}

/// Scalar tail for `evalBatchWithSubsetProductBasis`.
pub inline fn evalWithSubsetProductBasis(coefficients: []const M31, basis: []const QM31) QM31 {
    std.debug.assert(coefficients.len == basis.len);
    var value = QM31.zero();
    var index: usize = 0;
    while (index + 4 <= coefficients.len) : (index += 4) {
        const values: [4]M31 = coefficients[index..][0..4].*;
        if (comptime m31.PACK_WIDTH == 4) {
            // One SIMD lane per secure-field coordinate, rather than duplicating
            // a singleton polynomial into four identical column lanes.
            var scalars: [4]PackedM31 = undefined;
            var weights: [4]PackedM31 = undefined;
            inline for (0..4) |term| {
                scalars[term] = @splat(values[term].v);
                const coords = basis[index + term].toM31Array();
                weights[term] = .{ coords[0].v, coords[1].v, coords[2].v, coords[3].v };
            }
            const sum = m31.dot4Packed(scalars, weights);
            value = value.add(QM31.fromU32Unchecked(sum[0], sum[1], sum[2], sum[3]));
        } else {
            var sums: [4]M31 = undefined;
            inline for (0..4) |coordinate| {
                var weights: [4]M31 = undefined;
                inline for (0..4) |term| weights[term] = basis[index + term].toM31Array()[coordinate];
                sums[coordinate] = m31.dot4(values, weights);
            }
            value = value.add(QM31.fromM31Array(sums));
        }
    }
    while (index < coefficients.len) : (index += 1)
        value = value.add(basis[index].mulM31(coefficients[index]));
    return value;
}

test "point evaluation: packed high-block subset basis matches scalar products" {
    const log_size: u32 = 10;
    const basis_len = @as(usize, 1) << @intCast(log_size);
    var factors: [log_size]QM31 = undefined;
    for (&factors, 0..) |*factor, index| {
        const value: u32 = @intCast(index + 2);
        factor.* = QM31.fromU32Unchecked(value, value + 17, value + 31, value + 47);
    }

    const allocator = std.testing.allocator;
    const basis = try allocator.alloc(QM31, basis_len);
    defer allocator.free(basis);
    fillSubsetProductBasis(&factors, basis);

    for (basis, 0..) |actual, index| {
        var expected = QM31.one();
        for (factors, 0..) |factor, factor_index| {
            if ((index & (@as(usize, 1) << @intCast(factor_index))) != 0) {
                expected = expected.mul(factor);
            }
        }
        try std.testing.expect(expected.eql(actual));
    }
}

test "point evaluation: subset basis evaluation crosses packed high-block boundary" {
    const log_size: u32 = 10;
    const basis_len = @as(usize, 1) << @intCast(log_size);
    var factors: [log_size]QM31 = undefined;
    for (&factors, 0..) |*factor, index| {
        const value: u32 = @intCast(index * 13 + 5);
        factor.* = QM31.fromU32Unchecked(value, value + 1, value + 2, value + 3);
    }

    const allocator = std.testing.allocator;
    const coefficients = try allocator.alloc(M31, basis_len);
    defer allocator.free(coefficients);
    for (coefficients, 0..) |*coefficient, index| {
        coefficient.* = M31.fromCanonical(@intCast(index * 29 + 7));
    }
    const basis = try allocator.alloc(QM31, basis_len);
    defer allocator.free(basis);
    fillSubsetProductBasis(&factors, basis);

    const expected = evalAtPointIterative(coefficients, &factors, log_size);
    const actual = evalWithSubsetProductBasis(coefficients, basis);
    try std.testing.expect(expected.eql(actual));
}

/// Evaluates one native-width batch of independent coefficient polynomials at
/// the same secure-field point. Each polynomial occupies one packed M31 lane;
/// its carry-style reduction and field-operation order match
/// `evalAtPointIterative` exactly.
pub inline fn evalBatchAtPointIterative(
    coefficient_batches: [m31.PACK_WIDTH][]const M31,
    factors: []const QM31,
    log_size: u32,
) [m31.PACK_WIDTH]QM31 {
    const expected_len = @as(usize, 1) << @intCast(log_size);
    for (coefficient_batches) |coefficients| {
        std.debug.assert(coefficients.len == expected_len);
    }
    std.debug.assert(factors.len == log_size);

    if (log_size == 0) {
        var constants: [m31.PACK_WIDTH]QM31 = undefined;
        for (coefficient_batches, 0..) |coefficients, lane| {
            constants[lane] = QM31.fromBase(coefficients[0]);
        }
        return constants;
    }

    var packed_factors: [circle.M31_CIRCLE_LOG_ORDER]PackedQM31 = undefined;
    for (factors, 0..) |factor, factor_idx| {
        packed_factors[factor_idx] = splatQM31(factor);
    }

    var pending: [circle.M31_CIRCLE_LOG_ORDER + 1]PackedQM31 = undefined;
    for (coefficient_batches[0], 0..) |_, coeff_idx| {
        var packed_coefficients: PackedM31 = undefined;
        for (0..m31.PACK_WIDTH) |lane| {
            packed_coefficients[lane] = coefficient_batches[lane][coeff_idx].v;
        }
        var value = packedQM31FromBase(packed_coefficients);
        var level: usize = @as(usize, @intCast(@ctz(~coeff_idx)));
        if (level > @as(usize, @intCast(log_size))) {
            level = @as(usize, @intCast(log_size));
        }
        var merge_level: usize = 0;
        while (merge_level < level) : (merge_level += 1) {
            value = addPackedQM31(
                pending[merge_level],
                mulPackedQM31(value, packed_factors[merge_level]),
            );
        }
        pending[level] = value;
    }

    const packed_result = pending[log_size];
    var results: [m31.PACK_WIDTH]QM31 = undefined;
    for (0..m31.PACK_WIDTH) |lane| {
        results[lane] = QM31.fromU32Unchecked(
            packed_result.c0.a[lane],
            packed_result.c0.b[lane],
            packed_result.c1.a[lane],
            packed_result.c1.b[lane],
        );
    }
    return results;
}

/// Fills the circle-basis factors for one secure-field point.
pub fn fillEvalFactorsForPoint(
    point: CirclePointQM31,
    log_size: u32,
    out: *[circle.M31_CIRCLE_LOG_ORDER]QM31,
) []const QM31 {
    fillEvalFactors(point, log_size, out);
    return out[0..log_size];
}

/// Fills point-major factors after applying the requested circle folds.
pub fn fillEvalFactorsForPointsFolded(
    points: []const CirclePointQM31,
    fold_count: u32,
    log_size: u32,
    out: []QM31,
) void {
    std.debug.assert(log_size == 0 or out.len == points.len * log_size);
    if (log_size == 0) return;

    var at: usize = 0;
    var factors: [circle.M31_CIRCLE_LOG_ORDER]QM31 = undefined;
    for (points) |point| {
        const folded_point = if (fold_count == 0) point else repeatedDoubleOnCircleQM31(point, fold_count);
        fillEvalFactors(folded_point, log_size, &factors);
        @memcpy(out[at .. at + log_size], factors[0..log_size]);
        at += log_size;
    }
}

/// Applies the circle doubling map exactly `n` times in the secure field.
pub inline fn repeatedDoubleOnCircleQM31(point: CirclePointQM31, n: u32) CirclePointQM31 {
    var x = point.x;
    var y = point.y;
    var i: u32 = 0;
    while (i < n) : (i += 1) {
        const xx = x.square();
        const xy = x.mul(y);
        x = xx.add(xx).sub(QM31.one());
        y = xy.add(xy);
    }
    return .{ .x = x, .y = y };
}

inline fn fillEvalFactors(
    point: CirclePointQM31,
    log_size: u32,
    out: *[circle.M31_CIRCLE_LOG_ORDER]QM31,
) void {
    const max_log_size = circle.M31_CIRCLE_LOG_ORDER;
    std.debug.assert(log_size <= max_log_size);
    if (log_size == 0) return;

    out[0] = point.y;
    if (log_size > 1) {
        var x = point.x;
        out[1] = x;
        var bit: u32 = 2;
        while (bit < log_size) : (bit += 1) {
            x = circle.CirclePoint(QM31).doubleX(x);
            out[bit] = x;
        }
    }
}

fn evalAtPointRecursive(
    coeffs: []const M31,
    factors: []const QM31,
    bits_left: u32,
) QM31 {
    std.debug.assert(coeffs.len == (@as(usize, 1) << @intCast(bits_left)));
    if (bits_left == 0) return QM31.fromBase(coeffs[0]);

    const mid = coeffs.len / 2;
    const left = evalAtPointRecursive(coeffs[0..mid], factors, bits_left - 1);
    const right = evalAtPointRecursive(coeffs[mid..], factors, bits_left - 1);
    return left.add(right.mul(factors[bits_left - 1]));
}

fn evalAtPointReference(
    coeffs: []const M31,
    log_size: u32,
    point: CirclePointQM31,
) QM31 {
    if (log_size == 0) return QM31.fromBase(coeffs[0]);

    var mappings: [circle.M31_CIRCLE_LOG_ORDER]QM31 = undefined;
    mappings[log_size - 1] = point.y;
    if (log_size > 1) {
        var x = point.x;
        var i: usize = log_size - 1;
        while (i > 0) {
            i -= 1;
            mappings[i] = x;
            x = circle.CirclePoint(QM31).doubleX(x);
        }
    }

    var acc = QM31.zero();
    for (coeffs, 0..) |coeff, index| {
        var twiddle = QM31.one();
        var bit_index: usize = 0;
        var bit_words = index;
        while (bit_index < log_size and bit_words != 0) : (bit_index += 1) {
            if ((bit_words & 1) == 1) {
                const mapping_index = log_size - 1 - bit_index;
                twiddle = twiddle.mul(mappings[mapping_index]);
            }
            bit_words >>= 1;
        }
        acc = acc.add(QM31.fromBase(coeff).mul(twiddle));
    }
    return acc;
}

test "circle point evaluation matches the monomial reference" {
    const allocator = std.testing.allocator;
    const log_sizes = [_]u32{ 1, 2, 3, 4, 5, 6, 7, 8 };

    var prng = std.Random.DefaultPrng.init(0x97d8_114a_3f61_55cc);
    const random = prng.random();

    for (log_sizes) |log_size| {
        const coefficient_count = @as(usize, 1) << @intCast(log_size);
        const coeffs = try allocator.alloc(M31, coefficient_count);
        defer allocator.free(coeffs);
        for (coeffs) |*coeff| {
            coeff.* = M31.fromCanonical(random.intRangeLessThan(u32, 0, m31.Modulus));
        }

        var sample_index: usize = 0;
        while (sample_index < 24) : (sample_index += 1) {
            const point = circle.SECURE_FIELD_CIRCLE_GEN.mul(@as(u64, random.int(u32)) + 11);
            var factor_storage: [circle.M31_CIRCLE_LOG_ORDER]QM31 = undefined;
            const factors = fillEvalFactorsForPoint(point, log_size, &factor_storage);
            const iterative = evalAtPointIterative(coeffs, factors, log_size);
            const reference = evalAtPointReference(coeffs, log_size, point);
            try std.testing.expect(iterative.eql(reference));
        }
    }
}

test "circle point evaluation iterative reduction matches recursive oracle" {
    const allocator = std.testing.allocator;
    const log_sizes = [_]u32{ 1, 2, 3, 4, 5, 6, 7, 8 };

    var prng = std.Random.DefaultPrng.init(0x8a3f_77de_13cc_59e1);
    const random = prng.random();

    for (log_sizes) |log_size| {
        const coefficient_count = @as(usize, 1) << @intCast(log_size);
        const coeffs = try allocator.alloc(M31, coefficient_count);
        defer allocator.free(coeffs);
        for (coeffs) |*coeff| {
            coeff.* = M31.fromCanonical(random.intRangeLessThan(u32, 0, m31.Modulus));
        }

        var sample_index: usize = 0;
        while (sample_index < 24) : (sample_index += 1) {
            const point = circle.SECURE_FIELD_CIRCLE_GEN.mul(@as(u64, random.int(u32)) + 29);
            var factor_storage: [circle.M31_CIRCLE_LOG_ORDER]QM31 = undefined;
            const factors = fillEvalFactorsForPoint(point, log_size, &factor_storage);

            const iterative = evalAtPointIterative(coeffs, factors, log_size);
            const recursive = evalAtPointRecursive(coeffs, factors, log_size);
            try std.testing.expect(iterative.eql(recursive));
        }
    }
}

test "point evaluation: singleton subset dot products retain coordinate edges and ragged tails" {
    var random_source = std.Random.DefaultPrng.init(0x96665);
    const random = random_source.random();
    var coefficients: [17]M31 = undefined;
    var basis: [17]QM31 = undefined;
    for (&coefficients, &basis, 0..) |*coefficient, *weight, index| {
        coefficient.* = M31.fromCanonical(if (index < 4) m31.Modulus - 1 else random.uintLessThan(u32, m31.Modulus));
        weight.* = if (index < 4) QM31.fromU32Unchecked(m31.Modulus - 1, 0, 1, m31.Modulus - 1) else QM31.fromU32Unchecked(
            random.uintLessThan(u32, m31.Modulus),
            random.uintLessThan(u32, m31.Modulus),
            random.uintLessThan(u32, m31.Modulus),
            random.uintLessThan(u32, m31.Modulus),
        );
    }
    for (0..18) |length| {
        var expected = QM31.zero();
        for (coefficients[0..length], basis[0..length]) |coefficient, weight| expected = expected.add(weight.mulM31(coefficient));
        try std.testing.expect(expected.eql(evalWithSubsetProductBasis(coefficients[0..length], basis[0..length])));
    }
}
