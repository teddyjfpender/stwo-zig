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
