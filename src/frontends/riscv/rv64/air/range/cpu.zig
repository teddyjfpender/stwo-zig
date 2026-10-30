//! Positive byte-table LogUp requests, batched three per secure inverse.
//! Counts are committed in the provider before alpha is sampled. No row enable
//! is needed: padding bytes are requests too. One prefix covers every request.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const E = @import("../evaluation.zig");
const Q = E.Q;
const Plan = @import("../encoding.zig").Plan;
const W = @import("../witness.zig");
pub fn batches(plan: *const Plan) usize {
    return (plan.range_count + 2) / 3;
}
pub fn interactionCount(plan: *const Plan) usize {
    return (batches(plan) + 1) * 4;
}
pub fn constraintCount(plan: *const Plan) usize {
    return batches(plan) + 2;
}
pub const Columns = struct {
    allocator: std.mem.Allocator,
    storage: []M,
    log_size: u32,
    claim: Q,
    pub fn deinit(self: *Columns) void {
        self.allocator.free(self.storage);
        self.* = undefined;
    }
};
/// Main columns and returned storage use the existing bit-reversed circle
/// order. Publication is transactional; errors release all provisional memory.
pub fn buildInteraction(a: std.mem.Allocator, plan: *const Plan, main: []const []const M, log_size: u32, alpha: Q) !Columns {
    if (log_size >= @bitSizeOf(usize) or main.len != plan.main_count) return error.InvalidByteRangeGeometry;
    const size = @as(usize, 1) << @intCast(log_size);
    for (main) |column| if (column.len != size) return error.InvalidByteRangeGeometry;
    const storage = try a.alloc(M, try std.math.mul(usize, size, interactionCount(plan)));
    errdefer a.free(storage);
    // This family has only 256 possible denominators. Construct the immutable
    // inverse dictionary once instead of doing an extension inversion for each
    // batch in every execution row. The AIR still checks the original product
    // identity and prefix relation; this changes witness construction only.
    var inverse_bytes: [256]Q = undefined;
    for (&inverse_bytes, 0..) |*inverse, byte| inverse.* = try alpha.sub(Q.fromBase(M.fromCanonical(@intCast(byte)))).inv();
    var sum = Q.zero();
    for (0..size) |logical_row| {
        const row = W.physical(logical_row, log_size);
        for (0..batches(plan)) |batch| {
            const count = @min(3, plan.range_count - batch * 3);
            var inverse = Q.one();
            var contribution = Q.zero();
            for (0..count) |i| {
                const byte = main[plan.range_sources[batch * 3 + i]][row].v;
                // Keep the adversarial witness constructor usable: out-of-range
                // values take the slow path and must fail provider closure.
                const term = if (byte < 256) inverse_bytes[byte] else try alpha.sub(Q.fromBase(M.fromCanonical(byte))).inv();
                inverse = inverse.mul(term);
                contribution = contribution.add(term);
            }
            store(storage, size, row, batch * 4, inverse);
            sum = sum.add(contribution);
        }
        store(storage, size, row, batches(plan) * 4, sum);
    }
    return .{ .allocator = a, .storage = storage, .log_size = log_size, .claim = sum };
}

/// Same extension-field authority for prover-domain and verifier OODS values.
/// Product denominators have degree three, inverse identity degree four.
pub fn evaluate(plan: *const Plan, physical: []const Q, current: []const Q, previous: []const Q, first: Q, last: Q, alpha: Q, claim: Q, out: *E.Sink) void {
    const prepared = PreparedAlpha.init(alpha);
    evaluatePrepared(plan, physical, current, previous, first, last, &prepared, claim, out);
}
pub fn evaluatePrepared(plan: *const Plan, physical: []const Q, current: []const Q, previous: []const Q, first: Q, last: Q, prepared: *const PreparedAlpha, claim: Q, out: *E.Sink) void {
    std.debug.assert(physical.len == plan.main_count);
    std.debug.assert(current.len == interactionCount(plan) and previous.len == current.len);
    var contribution = Q.zero();
    for (0..batches(plan)) |batch| {
        var values: [3]Q = undefined;
        const count = @min(3, plan.range_count - batch * 3);
        for (0..count) |i| values[i] = physical[plan.range_sources[batch * 3 + i]];
        const terms = prepared.terms(values[0..count]);
        const inverse = secure(current, batch * 4);
        out.emit(terms.denominator.mul(inverse).sub(Q.one()));
        contribution = contribution.add(terms.numerator.mul(inverse));
    }
    const sum = secure(current, batches(plan) * 4);
    const prior = secure(previous, batches(plan) * 4);
    out.emit(sum.sub(Q.one().sub(first).mul(prior)).sub(contribution));
    out.emit(last.mul(sum.sub(claim)));
}

pub const Terms = struct { numerator: Q, denominator: Q };
/// Challenge-only powers are prepared once per component. The same symmetric
/// polynomial is evaluated over both base-valued domains and arbitrary OODS
/// coordinates; no field-type-specific constraint branch is introduced.
pub const PreparedAlpha = struct {
    alpha: Q,
    square: Q,
    cube: Q,
    twice_alpha: Q,
    thrice_square: Q,
    pub fn init(alpha: Q) PreparedAlpha {
        const square = alpha.square();
        return .{ .alpha = alpha, .square = square, .cube = square.mul(alpha), .twice_alpha = alpha.add(alpha), .thrice_square = square.add(square).add(square) };
    }
    pub fn terms(self: *const PreparedAlpha, values: []const Q) Terms {
        std.debug.assert(values.len <= 3);
        return switch (values.len) {
            0 => .{ .numerator = Q.zero(), .denominator = Q.one() },
            1 => .{ .numerator = Q.one(), .denominator = self.alpha.sub(values[0]) },
            2 => blk: {
                const s1 = values[0].add(values[1]);
                const s2 = values[0].mul(values[1]);
                break :blk .{ .numerator = self.twice_alpha.sub(s1), .denominator = self.square.sub(self.alpha.mul(s1)).add(s2) };
            },
            3 => blk: {
                const pair_sum = values[0].add(values[1]);
                const pair_product = values[0].mul(values[1]);
                const s1 = pair_sum.add(values[2]);
                const s2 = pair_product.add(pair_sum.mul(values[2]));
                const s3 = pair_product.mul(values[2]);
                break :blk .{ .numerator = self.thrice_square.sub(self.twice_alpha.mul(s1)).add(s2), .denominator = self.cube.sub(self.square.mul(s1)).add(self.alpha.mul(s2)).sub(s3) };
            },
            else => unreachable,
        };
    }
};
pub fn secure(columns: []const Q, offset: usize) Q {
    return Q.fromPartialEvals(columns[offset..][0..4].*);
}
fn store(storage: []M, size: usize, row: usize, column: usize, value: Q) void {
    for (value.toM31Array(), 0..) |coordinate, i| storage[(column + i) * size + row] = coordinate;
}
