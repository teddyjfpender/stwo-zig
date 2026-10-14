//! Arithmetic for one source column paired with one explicit OOD claim.
//!
//! This module does not authenticate inputs or admit a PCS proof. The owner
//! must bind every point/value to its transcript and every row to its source
//! Merkle root before calling it. No legacy periodicity sample is invented.
const std = @import("std");
const circle = @import("../circle.zig");
const constraints = @import("../constraints.zig");
const fields = @import("../fields/mod.zig");
const M31 = fields.m31.M31;
const CM31 = fields.cm31.CM31;
const QM31 = fields.qm31.QM31;

pub const max_claims: usize = 73;
pub const PairWords = [2][2]QM31;
pub const ClaimInput = struct {
    point: circle.CirclePointQM31,
    claimed_value: QM31,
    source_rows: [2]circle.CirclePointM31,
    source_values: [2]M31,
};

/// Compute `(f(x), q_Q(x))` at both authenticated source rows for each
/// explicit claim, with `q_Q` using the native conjugate-line quotient law.
/// One Montgomery inversion covers all 2*claims.len denominators. The output
/// is written atomically; a degenerate point or denominator leaves it intact.
pub fn derive(inputs: []const ClaimInput, output: []PairWords) !void {
    if (inputs.len == 0 or inputs.len > max_claims or output.len != inputs.len)
        return error.InvalidClaimShape;
    var coefficients: [max_claims]constraints.LineCoeffs = undefined;
    var denominators: [2 * max_claims]CM31 = undefined;
    var inverses: [2 * max_claims]CM31 = undefined;
    var staged: [max_claims]PairWords = undefined;
    for (inputs, 0..) |input, claim| {
        coefficients[claim] = constraints.complexConjugateLineCoeffs(
            input.point,
            input.claimed_value,
            QM31.one(),
        ) catch return error.DegenerateLine;
        for (input.source_rows, 0..) |row, side| {
            denominators[2 * claim + side] = input.point.x.c0.sub(CM31.fromBase(row.x))
                .mul(input.point.y.c1)
                .sub(input.point.y.c0.sub(CM31.fromBase(row.y)).mul(input.point.x.c1));
        }
    }
    fields.batchInverseInPlace(CM31, denominators[0 .. 2 * inputs.len], inverses[0 .. 2 * inputs.len]) catch
        return error.DegenerateDenominator;
    for (inputs, 0..) |input, claim| {
        const coeff = coefficients[claim];
        for (input.source_rows, input.source_values, 0..) |row, value, side| {
            const numerator = coeff.c.mulM31(value)
                .sub(coeff.a.mulM31(row.y))
                .sub(coeff.b);
            staged[claim][side] = .{
                QM31.fromBase(value),
                numerator.mulCM31(inverses[2 * claim + side]),
            };
        }
    }
    @memcpy(output, staged[0..inputs.len]);
}

test "per-claim paired rows repeat one source and match independent row context" {
    const canonic = @import("../poly/circle/canonic.zig");
    const context = @import("paired_row_context_v2.zig");
    const source = canonic.CanonicCoset.new(5).circleDomain();
    const rows = [2]circle.CirclePointM31{
        source.at(0),
        source.at(16),
    };
    const values = [2]M31{ M31.fromCanonical(17), M31.fromCanonical(23) };
    const base = try circle.secureFieldPointFromRandomSeedChecked(QM31.fromU32Unchecked(9, 3, 7, 2));
    const offset = canonic.CanonicCoset.new(5).step();
    const shifted = base.add(.{ .x = QM31.fromBase(offset.x), .y = QM31.fromBase(offset.y) });
    const inputs = [2]ClaimInput{
        .{ .point = shifted, .claimed_value = QM31.fromBase(M31.fromCanonical(11)), .source_rows = rows, .source_values = values },
        .{ .point = base, .claimed_value = QM31.fromBase(M31.fromCanonical(13)), .source_rows = rows, .source_values = values },
    };
    var paired: [2]PairWords = undefined;
    try derive(&inputs, &paired);
    for (inputs, paired) |input, pair| {
        var independent = try context.RowContextV2.init(std.testing.allocator, input.point, &.{input.claimed_value}, QM31.one());
        defer independent.deinit();
        for (pair, 0..) |word, side| {
            const expected = try independent.openedValues(&.{input.source_values[side]}, input.source_rows[side]);
            try std.testing.expectEqualDeep(expected, word);
        }
    }
    try std.testing.expectEqualDeep(paired[0][0][0], paired[1][0][0]);
    try std.testing.expectEqualDeep(paired[0][1][0], paired[1][1][0]);
    var changed = inputs;
    changed[0].claimed_value = changed[0].claimed_value.add(QM31.one());
    var changed_pairs: [2]PairWords = undefined;
    try derive(&changed, &changed_pairs);
    for (0..2) |side| {
        try std.testing.expectEqualDeep(paired[0][side][0], changed_pairs[0][side][0]);
        try std.testing.expect(!paired[0][side][1].eql(changed_pairs[0][side][1]));
        try std.testing.expectEqualDeep(paired[1][side], changed_pairs[1][side]);
    }
    const before = paired;
    try std.testing.expectError(error.InvalidClaimShape, derive(&inputs, paired[0..1]));
    try std.testing.expectEqualDeep(before, paired);
}
