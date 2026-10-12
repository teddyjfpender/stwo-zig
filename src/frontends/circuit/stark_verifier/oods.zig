//! Out-of-domain sampling: port of `crates/stark_verifier/src/oods.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230).
//!
//! `collect_oods_responses` lists every sampled column value with its point
//! in the stwo prover's order; `compute_fri_input` turns them into the FRI
//! input at each query, batching the responses by point in first-seen order
//! of the point's `(x, y)` wires (upstream's `IndexMap` key), not by the
//! core PCS quotient batching.

const std = @import("std");
const core = @import("stwo_core");
const builder = @import("../builder/mod.zig");
const circle = @import("circle.zig");
const proof_mod = @import("proof.zig");
const select_queries = @import("select_queries.zig");

const QM31 = core.fields.qm31.QM31;
const Var = builder.Var;
const Context = builder.Context;
const Error = builder.context.Error;
const simd = builder.simd;
const Simd = simd.Simd;
const ops = builder.ops;
const Point = circle.Point;

/// `COMPOSITION_SPLIT`: the composition polynomial is split into
/// `2^COMPOSITION_LOG_SPLIT` parts.
pub const COMPOSITION_SPLIT: usize = @as(usize, 1) << core.verifier_types.COMPOSITION_LOG_SPLIT;
/// `N_COMPOSITION_COLUMNS`: one M31 column per QM31 coordinate of each part.
pub const N_COMPOSITION_COLUMNS: usize = COMPOSITION_SPLIT * core.fields.qm31.SECURE_EXTENSION_DEGREE;

comptime {
    if (N_COMPOSITION_COLUMNS != 8) @compileError("oods.rs fixes 8 composition columns");
}

/// `period_generators`: per component, `component_size * trace_gen`, from
/// the bits of the (power of two) component sizes.
fn periodGenerators(comptime V: type, ctx: *Context(V), trace_gen: core.circle.CirclePointM31, component_sizes_bits: []const Simd) Error![]Point(Var) {
    var period_gen: Point(builder.wrappers.M31Wrapper(Var)) = .{
        .x = try builder.wrappers.constM31(V, ctx, trace_gen.x),
        .y = try builder.wrappers.constM31(V, ctx, trace_gen.y),
    };
    const bits_0 = component_sizes_bits[0];
    var res: Point(Simd) = .{
        .x = try simd.scalarMul(V, ctx, bits_0, period_gen.x),
        .y = try simd.scalarMul(V, ctx, bits_0, period_gen.y),
    };
    for (component_sizes_bits[1..]) |bit| {
        period_gen = try circle.doublePoint(V, ctx, period_gen);
        const zero_or_x = try simd.scalarMul(V, ctx, bit, period_gen.x);
        const zero_or_y = try simd.scalarMul(V, ctx, bit, period_gen.y);
        res = .{ .x = try simd.add(V, ctx, res.x, zero_or_x), .y = try simd.add(V, ctx, res.y, zero_or_y) };
    }
    const xs = try simd.unpack(V, ctx, res.x);
    const ys = try simd.unpack(V, ctx, res.y);
    const points = try ctx.scratch().alloc(Point(Var), xs.len);
    for (points, xs, ys) |*point, x, y| point.* = .{ .x = x, .y = y };
    return points;
}

/// `extract_expected_composition_eval`: `left + pi^(max_log_degree_bound -
/// 2)(oods.x) * right`, with `left` and `right` the two composition parts.
pub fn extractExpectedCompositionEval(
    comptime V: type,
    ctx: *Context(V),
    composition_eval_at_oods: []const Var,
    oods_point: Point(Var),
    max_log_degree_bound: usize,
    composition_log_split: u32,
) (Error || error{InvalidCompositionShape})!Var {
    const count = core.verifier_types.compositionChunkCount(composition_log_split) orelse return error.InvalidCompositionShape;
    if (composition_eval_at_oods.len != count * core.fields.qm31.SECURE_EXTENSION_DEGREE or
        max_log_degree_bound <= composition_log_split) return error.InvalidCompositionShape;
    var chunks: [@as(usize, 1) << core.verifier_types.MAX_COMPOSITION_LOG_SPLIT]Var = undefined;
    for (chunks[0..count], 0..) |*chunk, i| {
        chunk.* = try ops.fromPartialEvals(V, ctx, composition_eval_at_oods[4 * i ..][0..4].*);
    }
    var active = count;
    var parent_log = max_log_degree_bound - composition_log_split + 1;
    while (active > 1) {
        var factor = oods_point.x;
        for (0..parent_log - 2) |_| factor = try circle.doubleX(V, ctx, factor);
        for (0..active / 2) |i| {
            chunks[i] = try ctx.add(chunks[2 * i], try ctx.mul(factor, chunks[2 * i + 1]));
        }
        active /= 2;
        parent_log += 1;
    }
    return chunks[0];
}

/// `OodsResponse`: column `column_idx` of tree `trace_idx` claims `value`
/// at `pt` (the OODS point, its previous row, or a periodicity point).
pub const OodsResponse = struct {
    trace_idx: usize,
    column_idx: usize,
    pt: Point(Var),
    value: Var,
};

/// `collect_oods_responses`, in the stwo prover's order: every preprocessed
/// column at the OODS point, every trace-column mask point in verifier-owned
/// order, then each interaction column at the OODS
/// point, a cumulative-sum column preceded by its periodicity and
/// previous-row samples; then the composition columns.
pub fn collectOodsResponses(
    comptime V: type,
    ctx: *Context(V),
    config: proof_mod.ProofConfig,
    oods_point: Point(Var),
    component_sizes_bits: []const Simd,
    proof: *const proof_mod.Proof(Var),
) Error![]const OodsResponse {
    const trace_gen = circle.generatorPoint(config.log_trace_size);
    const period_generators = try periodGenerators(V, ctx, trace_gen, component_sizes_bits);
    const periodicity_points = try ctx.scratch().alloc(Point(Var), period_generators.len);
    for (periodicity_points, period_generators) |*point, generator| point.* = try circle.addPoints(V, ctx, oods_point, generator);

    const neg_trace_gen: Point(Var) = .{
        .x = try ctx.constant(QM31.fromBase(trace_gen.x)),
        .y = try ctx.constant(QM31.fromBase(trace_gen.y.neg())),
    };
    const oods_point_at_prev_row = try circle.addPoints(V, ctx, oods_point, neg_trace_gen);

    // Reuse the exact same point wires for columns sharing an offset. The
    // quotient groups responses by point-wire identity, not coordinates.
    var shifted_points: std.AutoArrayHashMapUnmanaged(i8, Point(Var)) = .empty;
    try shifted_points.put(ctx.scratch(), 0, oods_point);
    try shifted_points.put(ctx.scratch(), -1, oods_point_at_prev_row);
    const mask_step = core.poly.circle.CanonicCoset.new(@intCast(config.log_trace_size)).step();

    var n_cumulative: usize = 0;
    for (config.cumulative_sum_columns) |is_cumulative_sum| n_cumulative += @intFromBool(is_cumulative_sum);
    const responses = try ctx.scratch().alloc(
        OodsResponse,
        config.n_preprocessed_columns + config.shape().nTraceOodsValues() + config.n_interaction_columns + 2 * n_cumulative + config.shape().nCompositionColumns(),
    );
    var at: usize = 0;
    for (proof.preprocessed_columns_at_oods, 0..) |value, column_idx| {
        responses[at] = .{ .trace_idx = 0, .column_idx = column_idx, .pt = oods_point, .value = value };
        at += 1;
    }
    var trace_value_index: usize = 0;
    for (0..config.n_trace_columns) |column_idx| {
        for (config.shape().columnMaskOffsets(1, column_idx)) |offset| {
            const point = shifted_points.get(offset) orelse blk: {
                const delta = mask_step.mulSigned(@as(isize, offset));
                const shifted = try circle.addPoints(V, ctx, oods_point, .{
                    .x = try ctx.constant(QM31.fromBase(delta.x)),
                    .y = try ctx.constant(QM31.fromBase(delta.y)),
                });
                try shifted_points.put(ctx.scratch(), offset, shifted);
                break :blk shifted;
            };
            responses[at] = .{ .trace_idx = 1, .column_idx = column_idx, .pt = point, .value = proof.trace_at_oods[trace_value_index] };
            at += 1;
            trace_value_index += 1;
        }
    }
    std.debug.assert(trace_value_index == proof.trace_at_oods.len);
    var column_idx: usize = 0;
    for (config.component_shapes, periodicity_points) |shape, periodicity_point| {
        for (0..shape.interaction_columns) |_| {
            const column = proof.interaction_at_oods[column_idx];
            if (config.cumulative_sum_columns[column_idx]) {
                responses[at] = .{ .trace_idx = 2, .column_idx = column_idx, .pt = periodicity_point, .value = column.at_oods };
                responses[at + 1] = .{ .trace_idx = 2, .column_idx = column_idx, .pt = oods_point_at_prev_row, .value = column.at_prev.? };
                at += 2;
            }
            responses[at] = .{ .trace_idx = 2, .column_idx = column_idx, .pt = oods_point, .value = column.at_oods };
            at += 1;
            column_idx += 1;
        }
    }
    for (proof.composition_eval_at_oods, 0..) |value, composition_idx| {
        responses[at] = .{ .trace_idx = 3, .column_idx = composition_idx, .pt = oods_point, .value = value };
        at += 1;
    }
    std.debug.assert(at == responses.len);
    return responses;
}

/// `OodsPointAuxiliary`: the denominator line `d·x - e·y - f` through a point
/// and its conjugate, and the batched numerator coefficients of the
/// responses at that point.
const OodsPointAuxiliary = struct {
    d: Var,
    e: Var,
    f: Var,
    /// Per response: `d · alpha^i`, with its tree and column.
    c_vec: std.ArrayListUnmanaged(struct { coeff: Var, trace_idx: usize, column_idx: usize }) = .empty,
    a_sum: Var,
    b_sum: Var,
    mul_v_sum: Var,
    py: Var,

    fn init(comptime V: type, ctx: *Context(V), px: Var, py: Var) Error!OodsPointAuxiliary {
        const d = try ops.im(V, ctx, py);
        const e = try ops.im(V, ctx, px);
        const d_px = try ctx.mul(d, px);
        const e_py = try ctx.mul(e, py);
        const f = try ctx.sub(d_px, e_py);
        return .{ .d = d, .e = e, .f = f, .a_sum = ctx.zero(), .b_sum = ctx.zero(), .mul_v_sum = ctx.zero(), .py = py };
    }

    fn accumulate(self: *OodsPointAuxiliary, comptime V: type, ctx: *Context(V), alpha_power: Var, response: OodsResponse) Error!void {
        const coeff = try ctx.mul(self.d, alpha_power);
        try self.c_vec.append(ctx.scratch(), .{ .coeff = coeff, .trace_idx = response.trace_idx, .column_idx = response.column_idx });
        const v_im = try ops.im(V, ctx, response.value);
        self.a_sum = try ctx.add(self.a_sum, try ctx.mul(alpha_power, v_im));
        self.mul_v_sum = try ctx.add(self.mul_v_sum, try ctx.mul(alpha_power, response.value));
    }

    fn finalize(self: *OodsPointAuxiliary, comptime V: type, ctx: *Context(V)) Error!void {
        const d_v = try ctx.mul(self.d, self.mul_v_sum);
        const a_py = try ctx.mul(self.a_sum, self.py);
        self.b_sum = try ctx.sub(d_v, a_py);
    }
};

/// `compute_fri_input`: at every query `q`, `sum over points p` of
/// `(a_p · q.y + b_p - sum_i c_i · column_i(q)) / (d_p · q.x - (e_p · q.y + f_p))`,
/// with the coefficients scaled by `-2u` and powers of `alpha`.
pub fn computeFriInput(
    comptime V: type,
    ctx: *Context(V),
    responses: []const OodsResponse,
    queries: select_queries.Queries,
    samples: *const proof_mod.EvalDomainSamples(Var),
    alpha: Var,
) Error![]const Var {
    const scratch = ctx.scratch();
    // Points in first-seen order of their `(x, y)` wires.
    var keys: std.AutoArrayHashMapUnmanaged([2]u32, OodsPointAuxiliary) = .empty;

    // Scaled by `-2u` for the different denominator from stwo's.
    var alpha_pow = try ctx.constant(QM31.fromU32Unchecked(0, 0, 2, 0).neg());
    for (responses, 0..) |response, i| {
        if (i > 0) alpha_pow = try ctx.mul(alpha_pow, alpha);
        const entry = try keys.getOrPut(scratch, .{ response.pt.x.idx, response.pt.y.idx });
        if (!entry.found_existing) entry.value_ptr.* = try OodsPointAuxiliary.init(V, ctx, response.pt.x, response.pt.y);
        try entry.value_ptr.accumulate(V, ctx, alpha_pow, response);
    }
    const auxes = keys.values();
    var prod = ctx.one();
    for (auxes, 0..) |*aux, i| {
        try aux.finalize(V, ctx);
        prod = if (i == 0) aux.d else try ctx.mul(prod, aux.d);
    }
    // Every `d = im(pt.y)` is non-zero, which binds the column values and
    // keeps the denominators off the (M31) query points.
    _ = try ctx.inv(prod);

    const query_xs = try simd.unpack(V, ctx, queries.points.x);
    const query_ys = try simd.unpack(V, ctx, queries.points.y);
    const fri_queries = try scratch.alloc(Var, query_xs.len);
    for (fri_queries, query_xs, query_ys, 0..) |*sum, q_x, q_y, query_idx| {
        sum.* = ctx.zero();
        for (auxes) |aux| {
            var numerator = try ctx.add(try ctx.mul(aux.a_sum, q_y), aux.b_sum);
            for (aux.c_vec.items) |c| {
                const value = samples.at(c.trace_idx, c.column_idx, query_idx).get();
                numerator = try ctx.sub(numerator, try ctx.mul(c.coeff, value));
            }
            const d_qx = try ctx.mul(aux.d, q_x);
            const e_qy = try ctx.mul(aux.e, q_y);
            const denominator = try ctx.sub(d_qx, try ctx.add(e_qy, aux.f));
            const quotient = try ctx.div(numerator, denominator);
            sum.* = try ctx.add(sum.*, quotient);
        }
    }
    return fri_queries;
}

test {
    _ = @import("oods_test.zig");
}
