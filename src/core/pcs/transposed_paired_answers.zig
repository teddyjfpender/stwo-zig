//! Degree-corrected source/quotient answers from authenticated S31XDM02 rows.
//! The caller must first verify the source wire against its expected root and
//! Fiat-Shamir queries. Point, claims, and batch challenge must come from the
//! separately bound outer transcript; this module does not admit a proof.

const std = @import("std");
const circle = @import("../circle.zig");
const constraints = @import("../constraints.zig");
const cm31 = @import("../fields/cm31.zig");
const m31 = @import("../fields/m31.zig");
const qm31 = @import("../fields/qm31.zig");
const canonic = @import("../poly/circle/canonic.zig");
const utils = @import("../utils.zig");
const xdm = @import("transposed_merkle.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
const CM31 = cm31.CM31;

pub const Answers = struct {
    allocator: std.mem.Allocator,
    large: []QM31,
    small: []QM31,

    pub fn deinit(self: *Answers) void {
        self.allocator.free(self.large);
        self.allocator.free(self.small);
        self.* = undefined;
    }
};

/// Source and own quotient alternate in each batch. One determinant inverse
/// serves every column at a row, just as in the experimental host prover.
pub fn fromVerifiedOpenings(
    allocator: std.mem.Allocator,
    opened: xdm.VerifiedOpenings,
    raw_queries: []const usize,
    point: circle.CirclePointQM31,
    large_claims: []const QM31,
    small_claims: []const QM31,
    batch: QM31,
) !Answers {
    if (raw_queries.len != opened.profile.query_count or
        large_claims.len != opened.profile.large_columns or
        small_claims.len != opened.profile.small_columns)
        return error.InvalidPairedShape;
    var result = Answers{
        .allocator = allocator,
        .large = try allocator.alloc(QM31, raw_queries.len * 4),
        .small = undefined,
    };
    errdefer allocator.free(result.large);
    result.small = try allocator.alloc(QM31, raw_queries.len * 2);
    errdefer allocator.free(result.small);
    try heightAnswers(allocator, opened, raw_queries, point, large_claims, batch, true, result.large);
    try heightAnswers(allocator, opened, raw_queries, point, small_claims, batch, false, result.small);
    return result;
}

fn heightAnswers(
    allocator: std.mem.Allocator,
    opened: xdm.VerifiedOpenings,
    raw_queries: []const usize,
    point: circle.CirclePointQM31,
    claims: []const QM31,
    batch: QM31,
    comptime large: bool,
    output: []QM31,
) !void {
    const log_size = opened.profile.log_size - @as(u32, if (large) 0 else 1);
    const domain = canonic.CanonicCoset.new(log_size).circleDomain();
    const width: usize = if (large) 4 else 2;
    const coefficients = try allocator.alloc(constraints.LineCoeffs, claims.len);
    defer allocator.free(coefficients);
    for (claims, coefficients) |claim, *coefficient|
        coefficient.* = try constraints.complexConjugateLineCoeffs(point, claim, QM31.one());
    const powers = try allocator.alloc([2]QM31, claims.len);
    defer allocator.free(powers);
    var power = QM31.one();
    for (powers) |*pair| {
        pair[0] = power;
        power = power.mul(batch);
        pair[1] = power;
        power = power.mul(batch);
    }
    for (raw_queries, 0..) |raw, query| {
        const first_row = if (large) raw & ~@as(usize, 3) else (raw >> 2) << 1;
        for (0..width) |j| {
            const row = first_row + j;
            const p = domain.at(utils.bitReverseIndex(row, log_size));
            const denominator = point.x.c0.sub(CM31.fromBase(p.x)).mul(point.y.c1)
                .sub(point.y.c0.sub(CM31.fromBase(p.y)).mul(point.x.c1));
            const inverse = try denominator.inv();
            var answer = QM31.zero();
            for (coefficients, powers, 0..) |coefficient, pair, col| {
                const source = if (large) opened.largeAt(query, j, col) else opened.smallAt(query, j, col);
                const numerator = coefficient.c.mulM31(source)
                    .sub(coefficient.a.mulM31(p.y)).sub(coefficient.b);
                const quotient = numerator.mulCM31(inverse);
                answer = answer.add(pair[0].mul(QM31.fromBase(source)))
                    .add(pair[1].mul(quotient));
            }
            output[query * width + j] = answer;
        }
    }
}
