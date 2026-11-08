//! Native-pack execution of the core quadratic DEEP row law. This changes
//! arithmetic scheduling only: constants, denominator authority and scalar tail
//! are identical, and there is no allocation or extra retained plane.
const std = @import("std");
const core = @import("stwo_core");
const m = core.fields.m31;
const O = core.fields.om31.OM31;
const Q = core.fields.qm31.QM31;
const po = core.fields.packed_om31;
const pq = core.fields.packed_qm31;
const Authority = core.pcs.ForField(O).quotients;
const Group = @import("quotients/coefficient_groups.zig").ForField(O).Group;

/// Evaluate the same core law across rows. The numerator groups and inverse
/// scratch are already column/batch-major; keeping that orientation avoids a
/// per-row gather into OM31 values followed by a transpose across batches.
/// No additional retained plane or heap allocation is needed.
/// Output planes must be mutually disjoint and must not alias any input. The
/// quotient owner supplies disjoint output ranges and immutable group storage.
pub fn finalizeRows(constants: *const Authority.QuotientConstants, groups: []const Group, start: usize, points: []const core.circle.CirclePointM31, inverses: []const Q, output: *const [8][]m.M31) !void {
    const count = points.len;
    const batches = constants.batch_linear_terms.len;
    if (inverses.len != try std.math.mul(usize, count, batches)) return error.ShapeMismatch;
    const end = try std.math.add(usize, start, count);
    for (output) |plane| if (plane.len != count) return error.ShapeMismatch;
    var previous: usize = 0;
    for (groups, 0..) |group, i| {
        if (group.batch_index >= batches or (i != 0 and group.batch_index < previous)) return error.ShapeMismatch;
        previous = group.batch_index;
        if (count != 0) {
            const upper = if (group.is_direct) end else try std.math.add(usize, try std.math.mul(usize, (end - 1) >> group.shift_amt, 2), 2);
            for (group.coordinates) |plane| if (plane.len < upper) return error.ShapeMismatch;
        }
    }
    // A bounded tile keeps the row accumulators in L1 while each batch's
    // immutable packed linear coefficients and group span are prepared once.
    // Each row still sums groups and batches in exactly the original order.
    const TILE_PACKS = 16;
    var row: usize = 0;
    while (row + m.PACK_WIDTH <= count) {
        const packs = @min(TILE_PACKS, (count - row) / m.PACK_WIDTH);
        var sums: [TILE_PACKS]po.PackedOM31 = undefined;
        var ys: [TILE_PACKS]m.PackedM31 = undefined;
        for (0..packs) |pack| {
            sums[pack] = po.splat(O.zero());
            inline for (0..m.PACK_WIDTH) |lane| ys[pack][lane] = points[row + pack * m.PACK_WIDTH + lane].y.v;
        }
        var group_index: usize = 0;
        for (constants.batch_linear_terms, 0..) |term, batch| {
            const first_group = group_index;
            while (group_index < groups.len and groups[group_index].batch_index == batch) : (group_index += 1) {}
            const linear_a = po.splat(term.sum_a);
            const linear_b = po.splat(term.sum_b);
            for (0..packs) |pack| {
                const current = row + pack * m.PACK_WIDTH;
                var numerator = po.splat(O.zero());
                for (groups[first_group..group_index]) |group| {
                    var coordinates: [8]m.PackedM31 = undefined;
                    inline for (0..8) |coordinate| {
                        const plane = group.coordinates[coordinate];
                        if (group.is_direct) {
                            coordinates[coordinate] = m.loadPacked(plane[start + current ..].ptr);
                        } else if (m.PACK_WIDTH == 4 and group.shift_amt >= 2 and (start + current) % 4 == 0) {
                            // Lifting repeats the same adjacent pair throughout
                            // an aligned native pack. Arbitrary starts retain the
                            // exact general gather below.
                            const index = ((start + current) >> group.shift_amt) << 1;
                            const left = plane[index].v;
                            const right = plane[index + 1].v;
                            coordinates[coordinate] = .{ left, right, left, right };
                        } else {
                            inline for (0..m.PACK_WIDTH) |lane| {
                                const position = start + current + lane;
                                const index = ((position >> group.shift_amt) << 1) + (position & 1);
                                coordinates[coordinate][lane] = plane[index].v;
                            }
                        }
                    }
                    numerator = numerator.add(po.fromCoordinates(coordinates));
                }
                var inverse: [4]m.PackedM31 = undefined;
                inline for (0..m.PACK_WIDTH) |lane| {
                    const coordinates = inverses[batch * count + current + lane].toM31Array();
                    inline for (0..4) |coordinate| inverse[coordinate][lane] = coordinates[coordinate].v;
                }
                const linear = linear_a.mulBase(ys[pack]).add(linear_b);
                sums[pack] = sums[pack].add(numerator.sub(linear).mulInner(pq.PackedQM31.fromCoordinates(inverse)));
            }
        }
        for (0..packs) |pack| {
            const coordinates = po.coordinates(sums[pack]);
            inline for (0..8) |coordinate| m.storePacked(output[coordinate][row + pack * m.PACK_WIDTH ..].ptr, coordinates[coordinate]);
        }
        row += packs * m.PACK_WIDTH;
    }
    // Arbitrary chunk starts and lengths remain supported, including tails
    // shorter than a native vector. This is the scalar core formula verbatim.
    while (row < count) : (row += 1) {
        var sum = O.zero();
        var group_index: usize = 0;
        for (constants.batch_linear_terms, 0..) |term, batch| {
            var numerator = O.zero();
            while (group_index < groups.len and groups[group_index].batch_index == batch) : (group_index += 1)
                numerator = numerator.add(groups[group_index].at(start + row));
            sum = sum.add(numerator.sub(term.sum_a.mulM31(points[row].y).add(term.sum_b)).mulInner(inverses[batch * count + row]));
        }
        for (sum.toM31Array(), 0..) |value, coordinate| output[coordinate][row] = value;
    }
}
pub fn finalize(constants: *const Authority.QuotientConstants, y: m.M31, numerators: []const O, inverses: []const Q) !O {
    if (constants.batch_linear_terms.len != numerators.len or inverses.len != numerators.len) return error.ShapeMismatch;
    var sum = po.splat(O.zero());
    var index: usize = 0;
    while (index + m.PACK_WIDTH <= numerators.len) : (index += m.PACK_WIDTH) {
        var a: [8]m.PackedM31 = undefined;
        var b: [8]m.PackedM31 = undefined;
        var inv: [4]m.PackedM31 = undefined;
        inline for (0..m.PACK_WIDTH) |lane| {
            const term = constants.batch_linear_terms[index + lane];
            const av = term.sum_a.toM31Array();
            const bv = term.sum_b.toM31Array();
            const iv = inverses[index + lane].toM31Array();
            inline for (0..8) |coordinate| {
                a[coordinate][lane] = av[coordinate].v;
                b[coordinate][lane] = bv[coordinate].v;
            }
            inline for (0..4) |coordinate| inv[coordinate][lane] = iv[coordinate].v;
        }
        const linear = po.fromCoordinates(a).mulBase(@as(m.PackedM31, @splat(y.v))).add(po.fromCoordinates(b));
        const numerator = po.loadNative(numerators[index..]).sub(linear);
        sum = sum.add(numerator.mulInner(pq.PackedQM31.fromCoordinates(inv)));
    }
    var result = O.zero();
    inline for (0..m.PACK_WIDTH) |lane| result = result.add(po.lane(sum, lane));
    for (constants.batch_linear_terms[index..], numerators[index..], inverses[index..]) |term, numerator, inverse| {
        result = result.add(numerator.sub(term.sum_a.mulM31(y).add(term.sum_b)).mulInner(inverse));
    }
    return result;
}
fn dense(seed: usize) O {
    var coordinates: [8]m.M31 = undefined;
    for (&coordinates, 0..) |*c, i| c.* = m.M31.fromCanonical(@intCast((seed + 13) * (i + 17) % 2147483647));
    return O.fromM31Array(coordinates);
}
test "coefficient storage packed wide DEEP finalization matches independent core authority" {
    const Term = std.meta.Child(@TypeOf(@as(Authority.QuotientConstants, undefined).batch_linear_terms));
    var terms: [65]Term = undefined;
    var numerators: [65]O = undefined;
    var inverses: [65]Q = undefined;
    for (&terms, &numerators, &inverses, 0..) |*term, *n, *inverse, i| {
        term.* = .{ .sum_a = dense(i + 7), .sum_b = dense(i + 91) };
        n.* = dense(i + 113);
        inverse.* = dense(i + 257).c0;
    }
    for ([_]usize{ 0, 1, 2, 3, 4, 5, 8, 13, 16, 31, 64, 65 }) |count| {
        const constants = Authority.QuotientConstants{ .line_coeffs = &.{}, .batch_linear_terms = terms[0..count] };
        for ([_]m.M31{ m.M31.zero(), m.M31.one(), m.M31.fromCanonical(2147483646) }) |y| {
            const expected = try Authority.finalizeRowQuotients(&constants, y, numerators[0..count], inverses[0..count]);
            const actual = try finalize(&constants, y, numerators[0..count], inverses[0..count]);
            try std.testing.expectEqual(expected, actual);
        }
    }
    const constants = Authority.QuotientConstants{ .line_coeffs = &.{}, .batch_linear_terms = &terms };
    try std.testing.expectError(error.ShapeMismatch, finalize(&constants, m.M31.one(), numerators[0..64], &inverses));
    try std.testing.expectError(error.ShapeMismatch, finalize(&constants, m.M31.one(), &numerators, inverses[0..64]));
}

test "coefficient storage row-packed wide DEEP preserves lifted geometry and every scalar tail" {
    const Term = std.meta.Child(@TypeOf(@as(Authority.QuotientConstants, undefined).batch_linear_terms));
    var terms: [5]Term = undefined;
    for (&terms, 0..) |*term, i| term.* = .{ .sum_a = dense(i + 11), .sum_b = dense(i + 103) };
    const constants = Authority.QuotientConstants{ .line_coeffs = &.{}, .batch_linear_terms = &terms };
    var backing: [4][8][128]m.M31 = undefined;
    var groups: [4]Group = undefined;
    for (&backing, &groups, 0..) |*planes, *group, i| {
        group.* = .{ .coordinates = undefined, .batch_index = if (i == 0) 0 else if (i == 2) 2 else i + 1, .shift_amt = @intCast(i + 1), .is_direct = i == 0 };
        for (planes, &group.coordinates, 0..) |*plane, *column, coordinate| {
            for (plane, 0..) |*value, row| value.* = m.M31.fromCanonical(@intCast(31 * row + 113 * coordinate + 1709 * i));
            column.* = plane;
        }
    }
    var points: [128]core.circle.CirclePointM31 = undefined;
    const domain = core.poly.circle.canonic.CanonicCoset.new(7).circleDomain();
    for (&points, 0..) |*point, i| point.* = domain.at(i);
    var inverses: [5 * 128]Q = undefined;
    for (&inverses, 0..) |*inverse, i| inverse.* = dense(131 + i).c0;
    var output: [8][128]m.M31 = undefined;
    for ([_]usize{ 0, 1, 3, 7, 13, 31, 63 }) |start| {
        for ([_]usize{ 0, 1, 2, 3, 4, 5, 7, 8, 13, 17, 31, 63, 64, 65, 97, 127 }) |count| {
            if (start + count > points.len) continue;
            var planes: [8][]m.M31 = undefined;
            for (&planes, &output) |*plane, *storage| plane.* = storage[0..count];
            try finalizeRows(&constants, &groups, start, points[0..count], inverses[0 .. terms.len * count], &planes);
            for (0..count) |row| {
                var numerators = [_]O{O.zero()} ** terms.len;
                for (groups) |group| numerators[group.batch_index] = numerators[group.batch_index].add(group.at(start + row));
                var row_inverses: [terms.len]Q = undefined;
                for (&row_inverses, 0..) |*inverse, batch| inverse.* = inverses[batch * count + row];
                const expected = try Authority.finalizeRowQuotients(&constants, points[row].y, &numerators, &row_inverses);
                for (expected.toM31Array(), 0..) |coordinate, i| try std.testing.expectEqual(coordinate, output[i][row]);
            }
        }
    }
    var planes: [8][]m.M31 = undefined;
    for (&planes, &output) |*plane, *storage| plane.* = storage[0..4];
    try std.testing.expectError(error.ShapeMismatch, finalizeRows(&constants, &groups, 0, points[0..4], inverses[0..19], &planes));
    var wrong = groups;
    wrong[0].batch_index = 6;
    try std.testing.expectError(error.ShapeMismatch, finalizeRows(&constants, &wrong, 0, points[0..4], inverses[0..20], &planes));
    wrong = groups;
    wrong[2].batch_index = 0;
    try std.testing.expectError(error.ShapeMismatch, finalizeRows(&constants, &wrong, 0, points[0..4], inverses[0..20], &planes));
    try std.testing.expectError(error.ShapeMismatch, finalizeRows(&constants, &groups, 127, points[0..4], inverses[0..20], &planes));
    wrong = groups;
    wrong[0].is_direct = false;
    wrong[0].shift_amt = 0;
    try std.testing.expectError(error.Overflow, finalizeRows(&constants, &wrong, std.math.maxInt(usize) / 2 + 1, points[0..4], inverses[0..20], &planes));
}
