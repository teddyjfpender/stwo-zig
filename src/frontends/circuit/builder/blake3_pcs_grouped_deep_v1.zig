//! Opt-in grouped native DEEP arithmetic. This sibling is intentionally not
//! imported by the original PCS verifier until native/ungrouped parity passes.
//! Grouping is receiver geometry: canonical BASE circle offsets, including
//! native periodicity. Beta powers retain original tree/column/response order.
//! No Merkle, FRI or transcript acceptance authority is supplied by this module.
const std = @import("std");
const core = @import("stwo_core");
const b = @import("mod.zig");
const pcs = @import("blake3_pcs_reuse_v1.zig");
const circle = @import("../stark_verifier/circle.zig");
const select_queries = @import("../stark_verifier/select_queries.zig");
const Q = core.fields.qm31.QM31;
const BasePoint = core.circle.CirclePointM31;
const M = b.wrappers.M31Wrapper(b.Var);
pub const production_active = false;

pub const Term = struct {
    tree: usize,
    column: usize,
    sample: usize,
    /// Exact ordinal BEFORE grouping, including extra periodic responses.
    response: usize,
};
pub const Group = struct { offset: BasePoint, terms: []Term };
const GroupBuilder = struct { offset: BasePoint, terms: std.ArrayList(Term) = .empty };
pub const Plan = struct {
    allocator: std.mem.Allocator,
    groups: []Group,
    response_count: usize,
    /// Independent structural plan only. No OODS/sample/query witness is read.
    pub fn init(a: std.mem.Allocator, geometry: pcs.Geometry) !Plan {
        try geometry.validate();
        var builders: std.ArrayList(GroupBuilder) = .empty;
        defer {
            for (builders.items) |*group| group.terms.deinit(a);
            builders.deinit(a);
        }
        var indices = std.AutoHashMap(u64, usize).init(a);
        defer indices.deinit();
        const generator = core.poly.circle.canonic.CanonicCoset.new((try geometry.friGeometry()).startLog()).step();
        var sample: usize = 0;
        var response: usize = 0;
        for (geometry.trees, 0..) |tree, tree_index| for (tree.columns, 0..) |column, column_index| {
            // The extra response uses sample1 and precedes BOTH declared masks.
            if (column.masks.len == 2) {
                const periodic = maskOffset(column.masks[1]).add(generator.repeatedDouble(column.log_size + geometry.config.fri_config.log_blowup_factor));
                try appendTerm(a, &builders, &indices, periodic, .{ .tree = tree_index, .column = column_index, .sample = try std.math.add(usize, sample, 1), .response = response });
                response = try std.math.add(usize, response, 1);
            }
            for (column.masks, 0..) |mask, i| {
                try appendTerm(a, &builders, &indices, maskOffset(mask), .{ .tree = tree_index, .column = column_index, .sample = try std.math.add(usize, sample, i), .response = response });
                response = try std.math.add(usize, response, 1);
            }
            sample = try std.math.add(usize, sample, column.masks.len);
        };
        if (sample != geometry.sampleCount() or response == 0) return error.InvalidGroupedDeepGeometry;
        const groups = try a.alloc(Group, builders.items.len);
        errdefer a.free(groups);
        var initialized: usize = 0;
        errdefer for (groups[0..initialized]) |group| a.free(group.terms);
        for (groups, builders.items) |*group, *builder| {
            group.* = .{ .offset = builder.offset, .terms = try builder.terms.toOwnedSlice(a) };
            initialized += 1;
        }
        return .{ .allocator = a, .groups = groups, .response_count = response };
    }
    pub fn deinit(v: *Plan) void {
        for (v.groups) |group| v.allocator.free(group.terms);
        v.allocator.free(v.groups);
        v.* = undefined;
    }
};
fn appendTerm(a: std.mem.Allocator, builders: *std.ArrayList(GroupBuilder), indices: *std.AutoHashMap(u64, usize), offset: BasePoint, term: Term) !void {
    const result = try indices.getOrPut(pointKey(offset));
    if (!result.found_existing) {
        result.value_ptr.* = builders.items.len;
        try builders.append(a, .{ .offset = offset });
    }
    try builders.items[result.value_ptr.*].terms.append(a, term);
}
fn maskOffset(mask: pcs.Mask) BasePoint {
    return if (mask.offset == 0) BasePoint.zero() else core.poly.circle.canonic.CanonicCoset.new(mask.row_log).step().mulSigned(mask.offset);
}
fn pointKey(point: BasePoint) u64 {
    return (@as(u64, point.x.toU32()) << 32) | point.y.toU32();
}

pub const WeightedTerm = struct { tree: usize, column: usize, c: b.Var };
pub const ResponseGroup = struct {
    terms: []WeightedTerm,
    a_sum: b.Var,
    b_sum: b.Var,
    prx: b.Var,
    pry: b.Var,
    pix: b.Var,
    piy: b.Var,
};
fn addBasePoint(comptime V: type, ctx: *b.Context(V), point: pcs.Point, offset: BasePoint) !pcs.Point {
    if (offset.eql(BasePoint.zero())) return point;
    return circle.addPoints(V, ctx, point, .{ .x = try ctx.constant(Q.fromBase(offset.x)), .y = try ctx.constant(Q.fromBase(offset.y)) });
}
/// Same per-response coefficients as the native complex-conjugate law, summed
/// by structurally equal sample point. Every distinct raw_c nonzero guard is
/// retained; repeated guards for the SAME constrained expression are shared.
pub fn responses(comptime V: type, ctx: *b.Context(V), geometry: pcs.Geometry, proof: pcs.Proof, oods: pcs.Oods, beta: b.Var) ![]ResponseGroup {
    try geometry.validate();
    if (proof.sampled_values.len != geometry.sampleCount()) return error.InvalidGroupedDeepShape;
    var plan = try Plan.init(ctx.scratch(), geometry);
    defer plan.deinit();
    // Assign powers in original order, never in grouped iteration order.
    const powers = try ctx.scratch().alloc(b.Var, plan.response_count);
    powers[0] = ctx.one();
    for (powers[1..], 1..) |*power, i| power.* = try ctx.mul(powers[i - 1], beta);
    const groups = try ctx.scratch().alloc(ResponseGroup, plan.groups.len);
    const inv_u = try ctx.constant(try Q.fromU32Unchecked(0, 0, 1, 0).inv());
    for (groups, plan.groups) |*group, shape| {
        const point = try addBasePoint(V, ctx, oods.point, shape.offset);
        const raw_c = try ctx.sub(try b.ops.conj(V, ctx, point.y), point.y);
        // Value-mode witness expansion must reject native degeneracy instead
        // of invoking the builder's division-by-zero panic. The inverse gate
        // below remains the acceptance authority in both value modes.
        if (V == Q and ctx.get(raw_c).isZero()) return error.DegenerateLine;
        _ = try ctx.inv(raw_c);
        const im_x = try b.ops.im(V, ctx, point.x);
        const im_y = try b.ops.im(V, ctx, point.y);
        const terms = try ctx.scratch().alloc(WeightedTerm, shape.terms.len);
        var a_sum = ctx.zero();
        var b_sum = ctx.zero();
        for (terms, shape.terms) |*term, original| {
            if (original.sample >= proof.sampled_values.len or original.response >= powers.len) return error.InvalidGroupedDeepShape;
            const value = proof.sampled_values[original.sample];
            const power = powers[original.response];
            const raw_a = try ctx.sub(try b.ops.conj(V, ctx, value), value);
            const raw_b = try ctx.sub(try ctx.mul(value, raw_c), try ctx.mul(raw_a, point.y));
            a_sum = try ctx.add(a_sum, try ctx.mul(power, raw_a));
            b_sum = try ctx.add(b_sum, try ctx.mul(power, raw_b));
            term.* = .{ .tree = original.tree, .column = original.column, .c = try ctx.mul(power, raw_c) };
        }
        group.* = .{ .terms = terms, .a_sum = a_sum, .b_sum = b_sum, .prx = try ctx.sub(point.x, im_x), .pry = try ctx.sub(point.y, im_y), .pix = try ctx.mul(im_x, inv_u), .piy = try ctx.mul(im_y, inv_u) };
    }
    return groups;
}

/// Exact native batch identity for each raw query:
///   sum_s (c_s*f_s - a_s*y - b_s)/D =
///   (sum_s c_s*f_s - y*sum_s a_s - sum_s b_s)/D.
/// Sample/trace/query wires are borrowed unchanged. Denominator inversion is
/// constrained once per group/query, including D != 0 as native requires.
pub fn deepAnswers(comptime V: type, ctx: *b.Context(V), geometry: pcs.Geometry, proof: pcs.Proof, oods: pcs.Oods, beta: b.Var, queries: []const M) ![]b.Var {
    try geometry.validate();
    if (queries.len != geometry.config.fri_config.n_queries or proof.trace.len != geometry.trees.len) return error.InvalidGroupedDeepShape;
    for (geometry.trees, proof.trace) |tree, trace| if (trace.values.len != try std.math.mul(usize, tree.columns.len, queries.len)) return error.InvalidGroupedDeepShape;
    const groups = try responses(V, ctx, geometry, proof, oods, beta);
    const packed_indices = try b.simd.pack(V, ctx, queries);
    const points = try select_queries.selectQueries(V, ctx, packed_indices, (try geometry.friGeometry()).startLog());
    const answers = try ctx.scratch().alloc(b.Var, queries.len);
    for (answers, 0..) |*answer, q| {
        const x = try b.simd.unpackIdx(V, ctx, points.points.x, q);
        const y = try b.simd.unpackIdx(V, ctx, points.points.y, q);
        var sum = ctx.zero();
        for (groups) |group| {
            var values_sum = ctx.zero();
            for (group.terms) |term| {
                if (term.tree >= proof.trace.len or term.column >= geometry.trees[term.tree].columns.len) return error.InvalidGroupedDeepShape;
                const value = proof.trace[term.tree].values[term.column * queries.len + q].get();
                values_sum = try ctx.add(values_sum, try ctx.mul(term.c, value));
            }
            const numerator = try ctx.sub(values_sum, try ctx.add(try ctx.mul(group.a_sum, y), group.b_sum));
            const denominator = try ctx.sub(try ctx.mul(try ctx.sub(group.prx, x), group.piy), try ctx.mul(try ctx.sub(group.pry, y), group.pix));
            if (V == Q and ctx.get(denominator).isZero()) return error.DivisionByZero;
            const inverse = try ctx.inv(denominator);
            sum = try ctx.add(sum, try ctx.mul(numerator, inverse));
        }
        answer.* = sum;
    }
    return answers;
}

test {
    _ = @import("blake3_pcs_grouped_deep_v1_test.zig");
}
