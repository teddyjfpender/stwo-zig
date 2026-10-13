//! Degree-corrected batch answers from fully authenticated XDM03 source rows.
//! Only the complete cascade verifier may treat the resulting slices as proof
//! inputs; the public struct itself conveys no authentication capability.

const std = @import("std");
const circle = @import("../circle.zig");
const constraints = @import("../constraints.zig");
const cm31 = @import("../fields/cm31.zig");
const m31 = @import("../fields/m31.zig");
const qm31 = @import("../fields/qm31.zig");
const canonic = @import("../poly/circle/canonic.zig");
const utils = @import("../utils.zig");
const xdm = @import("transposed_merkle_cascade.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
const CM31 = cm31.CM31;

pub const Answers = struct {
    allocator: std.mem.Allocator,
    values: [][]QM31,
    pub fn deinit(self: *Answers) void {
        for (self.values) |height| self.allocator.free(height);
        self.allocator.free(self.values);
        self.* = undefined;
    }
};

pub fn fromVerifiedOpenings(
    allocator: std.mem.Allocator,
    opened: xdm.VerifiedOpenings,
    raw_queries: []const usize,
    point: circle.CirclePointQM31,
    claims: []const []const QM31,
    batch: QM31,
) !Answers {
    const profile = opened.profile;
    if (raw_queries.len != profile.query_count or claims.len != profile.height_count)
        return error.InvalidCascadeShape;
    const values = try allocator.alloc([]QM31, profile.height_count);
    var built: usize = 0;
    errdefer {
        for (values[0..built]) |height| allocator.free(height);
        allocator.free(values);
    }
    while (built < profile.height_count) : (built += 1)
        values[built] = try allocator.alloc(QM31, profile.query_count * profile.width(built));
    for (claims, 0..) |height_claims, height| {
        if (height_claims.len != profile.columns[height]) return error.InvalidCascadeShape;
        const log_size = profile.largest_log_size - @as(u32, @intCast(height));
        const domain = canonic.CanonicCoset.new(log_size).circleDomain();
        const coefficients = try allocator.alloc(constraints.LineCoeffs, height_claims.len);
        defer allocator.free(coefficients);
        const powers = try allocator.alloc([2]QM31, height_claims.len);
        defer allocator.free(powers);
        var power = QM31.one();
        for (height_claims, coefficients, powers) |claim, *coefficient, *pair| {
            coefficient.* = try constraints.complexConjugateLineCoeffs(point, claim, QM31.one());
            pair[0] = power;
            power = power.mul(batch);
            pair[1] = power;
            power = power.mul(batch);
        }
        const width = profile.width(height);
        for (raw_queries, 0..) |raw, query| {
            const base = (raw & ~(profile.width(0) - 1)) >> @intCast(height);
            for (0..width) |j| {
                const row = base + j;
                const p = domain.at(utils.bitReverseIndex(row, log_size));
                const denominator = point.x.c0.sub(CM31.fromBase(p.x)).mul(point.y.c1)
                    .sub(point.y.c0.sub(CM31.fromBase(p.y)).mul(point.x.c1));
                const inverse = try denominator.inv();
                var answer = QM31.zero();
                for (coefficients, powers, 0..) |coefficient, pair, col| {
                    const source = opened.at(height, query, j, col);
                    const numerator = coefficient.c.mulM31(source)
                        .sub(coefficient.a.mulM31(p.y)).sub(coefficient.b);
                    const quotient = numerator.mulCM31(inverse);
                    answer = answer.add(pair[0].mul(QM31.fromBase(source)))
                        .add(pair[1].mul(quotient));
                }
                values[height][query * width + j] = answer;
            }
        }
    }
    return .{ .allocator = allocator, .values = values };
}
