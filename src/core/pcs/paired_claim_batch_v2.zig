//! Candidate sparse H3 explicit-claim batching, with no proof admission.
//!
//! Protocol 3 Eq. (66) advances the random-power exponent once per
//! function. For a literal ordered list `(f_0, q_0, f_1, q_1, ...)`, the
//! provisional weights here are `1, lambda, lambda^2, lambda^3, ...`.
//! The original of a two-claim column occurs twice, under distinct powers.
//! This arithmetic receipt does not establish the multi-Q batch theorem,
//! source-polynomial extraction, BCS bound, or FRI degree claim.
const std = @import("std");
const QM31 = @import("../fields/qm31.zig").QM31;
const PairWords = @import("paired_claim_rows_v2.zig").PairWords;

pub const claim_count: usize = 73;
pub const claims_by_height = [3]usize{ 18, 32, 23 };
pub const Error = error{
    InvalidClaimShape,
    InvalidClaimOrder,
    InvalidClaimHeight,
    SourceIdentityMismatch,
};

pub const ClaimRecord = struct {
    root_index: u8,
    column_index: u8,
    claim_index: u8,
    height: u8,
    words: PairWords,
};

/// `[height slot][adjacent source side][original or own quotient]`.
pub const WeightedRows = [3]PairWords;

/// Validate the literal claim schedule and compute one *provisional* paired
/// row at each of the three accepted heights. The exponent restarts at zero
/// for each height's ordered subsequence. A future selected profile must
/// prove that this schedule matches its native source ensemble and theorem.
pub fn deriveCandidate(claims: []const ClaimRecord, lambda: QM31) Error!WeightedRows {
    if (claims.len != claim_count) return error.InvalidClaimShape;
    var out: WeightedRows = std.mem.zeroes(WeightedRows);
    var powers = [3]QM31{ QM31.one(), QM31.one(), QM31.one() };
    var counts = [3]usize{ 0, 0, 0 };
    var repeated: usize = 0;
    for (claims, 0..) |claim, i| {
        if (claim.claim_index != i or claim.root_index >= 4)
            return error.InvalidClaimOrder;
        if (i > 0) {
            const prior = claims[i - 1];
            if (claim.root_index < prior.root_index or
                (claim.root_index == prior.root_index and claim.column_index < prior.column_index))
                return error.InvalidClaimOrder;
            if (claim.root_index == prior.root_index and claim.column_index == prior.column_index) {
                if (repeated != 0 or claim.height != prior.height) return error.InvalidClaimOrder;
                for (0..2) |side| if (!claim.words[side][0].eql(prior.words[side][0]))
                    return error.SourceIdentityMismatch;
                repeated = 1;
            } else repeated = 0;
        }
        const slot: usize = switch (claim.height) {
            17 => 0,
            11 => 1,
            5 => 2,
            else => return error.InvalidClaimHeight,
        };
        const original_power = powers[slot];
        const quotient_power = original_power.mul(lambda);
        for (0..2) |side| {
            out[slot][side][0] = out[slot][side][0].add(original_power.mul(claim.words[side][0]));
            out[slot][side][1] = out[slot][side][1].add(quotient_power.mul(claim.words[side][1]));
        }
        powers[slot] = quotient_power.mul(lambda);
        counts[slot] += 1;
    }
    if (!std.mem.eql(usize, &counts, &claims_by_height)) return error.InvalidClaimShape;
    return out;
}

test "candidate literal pair powers advance per function and repeat the same source" {
    const M31 = @import("../fields/m31.zig").M31;
    const base = struct {
        fn at(value: u32) QM31 {
            return QM31.fromBase(M31.fromCanonical(value));
        }
    }.at;
    var claims: [claim_count]ClaimRecord = undefined;
    var at: usize = 0;
    for ([_]u8{ 17, 11, 5 }, claims_by_height) |height, count| {
        for (0..count) |_| {
            claims[at] = .{
                .root_index = @intCast(at / 20),
                .column_index = @intCast(at % 20),
                .claim_index = @intCast(at),
                .height = height,
                .words = .{ .{ base(1), base(2) }, .{ base(3), base(4) } },
            };
            // The first two claims deliberately share a source identity.
            if (at == 1) claims[at].column_index = claims[0].column_index;
            at += 1;
        }
    }
    // One source column has two different OOD quotient functions.
    claims[1].words[0][1] = base(9);
    claims[1].words[1][1] = base(11);
    const lambda = base(2);
    const weighted = try deriveCandidate(&claims, lambda);
    // Pin the whole geometric sum independently over the 18 claim positions.
    var even_power = QM31.one();
    var want_original = QM31.zero();
    var want_quotient = QM31.zero();
    for (0..18) |_| {
        want_original = want_original.add(even_power.mul(base(1)));
        want_quotient = want_quotient.add(even_power.mul(base(4)));
        even_power = even_power.mul(base(4));
    }
    // At j=1, q changes from 2 to 9, with function exponent 2j+1=3.
    want_quotient = want_quotient.add(base(56));
    try std.testing.expect(weighted[0][0][0].eql(want_original));
    try std.testing.expect(weighted[0][0][1].eql(want_quotient));
    try std.testing.expect(weighted[1][0][0].eql(
        blk: {
            var sum = QM31.zero();
            var power = QM31.one();
            for (0..32) |_| {
                sum = sum.add(power);
                power = power.mul(base(4));
            }
            break :blk sum;
        },
    ));
    claims[1].words[0][0] = base(9);
    try std.testing.expectError(error.SourceIdentityMismatch, deriveCandidate(&claims, lambda));
    claims[1].words[0][0] = base(1);
    claims[1].height = 11;
    try std.testing.expectError(error.InvalidClaimOrder, deriveCandidate(&claims, lambda));
    claims[1].height = 17;
    claims[1].claim_index = 2;
    try std.testing.expectError(error.InvalidClaimOrder, deriveCandidate(&claims, lambda));
}

test "candidate h5 paired source and own quotient have expected degree on full domain" {
    const M31 = @import("../fields/m31.zig").M31;
    const circle = @import("../circle.zig");
    const canonic = @import("../poly/circle/canonic.zig");
    const utils = @import("../utils.zig");
    const rows = @import("paired_claim_rows_v2.zig");
    const roster_mod = @import("sparse_h3_claim_roster_v2.zig");
    const linear = struct {
        fn coefficients(tree: u8, column: u8) [3]M31 {
            return .{
                M31.fromCanonical(@as(u32, tree) * 3 + column + 1),
                M31.fromCanonical(@as(u32, column) + 2),
                M31.fromCanonical(@as(u32, tree) + 3),
            };
        }
        fn at(coeffs: [3]M31, point: circle.CirclePointQM31) QM31 {
            return QM31.fromBase(coeffs[0])
                .add(QM31.fromBase(coeffs[1]).mul(point.x))
                .add(QM31.fromBase(coeffs[2]).mul(point.y));
        }
        fn atBase(coeffs: [3]M31, point: circle.CirclePointM31) M31 {
            return coeffs[0].add(coeffs[1].mul(point.x)).add(coeffs[2].mul(point.y));
        }
    };
    const fixed = [_]u32{ 5, 5, 5, 11, 11, 11, 11, 11, 11, 11, 11, 17 };
    const main = [_]u32{ 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 5, 5, 5, 5, 17 };
    const interaction = [_]u32{ 11, 11, 11, 11, 11, 11, 11, 11, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 17, 17, 17, 17 };
    const composition = [_]u32{17} ** 8;
    const logs = [4][]const u32{ &fixed, &main, &interaction, &composition };
    var offsets: [4][24]roster_mod.MaskOffsets = undefined;
    var offset_views: [4][]const roster_mod.MaskOffsets = undefined;
    for (logs, 0..) |tree_logs, tree| {
        offset_views[tree] = offsets[tree][0..tree_logs.len];
        for (tree_logs, 0..) |_, column| {
            const two = tree == 2 and ((column >= 4 and column <= 7) or column >= 16);
            offsets[tree][column] = .{
                .count = if (two) 2 else 1,
                .values = .{ @intCast(tree * 100 + column), if (two) @intCast(tree * 100 + column + 1) else 0 },
            };
        }
    }
    const roster = try roster_mod.ClaimRoster.init(logs, offset_views);
    const ood = try circle.secureFieldPointFromRandomSeedChecked(QM31.fromU32Unchecked(9, 3, 7, 2));
    const mask_step = canonic.CanonicCoset.new(16).step();
    const domain = canonic.CanonicCoset.new(5).circleDomain();
    const lambda = QM31.fromBase(M31.fromCanonical(7));
    var h5_claims: [23]usize = undefined;
    var h5_count: usize = 0;
    for (roster.claims, 0..) |claim, i| if (claim.height == 5) {
        h5_claims[h5_count] = i;
        h5_count += 1;
    };
    try std.testing.expectEqual(@as(usize, 23), h5_count);

    var expected_a = QM31.zero();
    var expected_b = QM31.zero();
    var expected_c = QM31.zero();
    var power = QM31.one();
    for (h5_claims) |i| {
        const claim = roster.claims[i];
        const coeffs = linear.coefficients(claim.tree, claim.column);
        expected_a = expected_a.add(power.mul(QM31.fromBase(coeffs[0])));
        expected_b = expected_b.add(power.mul(QM31.fromBase(coeffs[1])));
        expected_c = expected_c.add(power.mul(QM31.fromBase(coeffs[2])));
        power = power.mul(lambda).mul(lambda);
    }

    var constant_quotient: ?QM31 = null;
    var mutated_first: ?QM31 = null;
    var mutation_changes_degree = false;
    for (0..16) |pair| {
        const raw = 2 * pair;
        const source_rows = [2]circle.CirclePointM31{
            domain.at(utils.bitReverseIndex(raw, 5)),
            domain.at(utils.bitReverseIndex(raw + 1, 5)),
        };
        var inputs: [23]rows.ClaimInput = undefined;
        var claims: [claim_count]ClaimRecord = undefined;
        var h5_at: usize = 0;
        for (roster.claims, 0..) |claim, i| {
            claims[i] = .{
                .root_index = claim.tree,
                .column_index = claim.column,
                .claim_index = @intCast(i),
                .height = claim.height,
                .words = std.mem.zeroes(rows.PairWords),
            };
            if (claim.height != 5) continue;
            const coeffs = linear.coefficients(claim.tree, claim.column);
            const shift = mask_step.mulSigned(claim.offset);
            const point = ood.add(.{
                .x = QM31.fromBase(shift.x),
                .y = QM31.fromBase(shift.y),
            }).repeatedDouble(12);
            const source_values = [2]M31{
                linear.atBase(coeffs, source_rows[0]),
                linear.atBase(coeffs, source_rows[1]),
            };
            inputs[h5_at] = .{
                .point = point,
                .claimed_value = linear.at(coeffs, point),
                .source_rows = source_rows,
                .source_values = source_values,
            };
            h5_at += 1;
        }
        var words: [23]rows.PairWords = undefined;
        try rows.derive(&inputs, &words);
        for (h5_claims, words) |i, word| claims[i].words = word;
        const aggregate = try deriveCandidate(&claims, lambda);
        for (0..2) |side| {
            const point = source_rows[side];
            const expected_original = expected_a
                .add(expected_b.mul(QM31.fromBase(point.x)))
                .add(expected_c.mul(QM31.fromBase(point.y)));
            try std.testing.expect(aggregate[2][side][0].eql(expected_original));
            if (constant_quotient) |want|
                try std.testing.expect(aggregate[2][side][1].eql(want))
            else
                constant_quotient = aggregate[2][side][1];
        }

        // One false OOD value makes its own quotient a rational function with
        // a nonconstant restriction to this complete height-5 domain.
        inputs[0].claimed_value = inputs[0].claimed_value.add(QM31.one());
        try rows.derive(&inputs, &words);
        for (h5_claims, words) |i, word| claims[i].words = word;
        const mutated = try deriveCandidate(&claims, lambda);
        for (0..2) |side| {
            const value = mutated[2][side][1];
            if (mutated_first) |first| {
                if (!value.eql(first)) mutation_changes_degree = true;
            } else mutated_first = value;
        }
    }
    try std.testing.expect(!constant_quotient.?.eql(QM31.zero()));
    try std.testing.expect(mutation_changes_degree);
}
