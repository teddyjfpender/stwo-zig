//! OM31 FRI arithmetic on the unchanged M31 circle domain; dedicated P2 trees.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const C = @import("common.zig");
const P = @import("proof.zig");
const F = C.F;
const Q = C.Q;
const B = circuit.builder;
const native = circuit.native_verifier;
const helpers = native.fold_helpers;
const merkle = @import("merkle.zig");
const simd = B.simd;
const Simd = simd.Simd;
const Point = circuit.stark_verifier.circle.Point;
pub const Queries = native.fri.Queries;
pub fn commit(ctx: *C.Context, channel: *C.Channel, proof: *const P.Proof) ![]const F {
    const alphas = try ctx.scratch().alloc(F, proof.layers.len);
    for (proof.layers, alphas) |layer, *alpha| {
        try channel.mixRoot(ctx, layer.commitment);
        alpha.* = try channel.draw(ctx);
    }
    try channel.mixFelts(ctx, proof.last_layer_coefs);
    return alphas;
}
fn hashLeaf(ctx: *C.Context, values: []const F) !C.Hash {
    const halves = try ctx.scratch().alloc(C.Var, 2 * values.len);
    for (values, 0..) |v, i| {
        halves[2 * i] = v.c0.v;
        halves[2 * i + 1] = v.c1.v;
    }
    return merkle.hashLeafQm31s(Q, ctx, halves);
}
fn select(ctx: *C.Context, values: []const F, bits: []const C.Var) !F {
    const c0 = try ctx.scratch().alloc(C.Var, values.len);
    const c1 = try ctx.scratch().alloc(C.Var, values.len);
    for (values, c0, c1) |value, *a, *b| {
        a.* = value.c0.v;
        b.* = value.c1.v;
    }
    return F.wire(try B.select.selectByIndex(Q, ctx, c0, bits), try B.select.selectByIndex(Q, ctx, c1, bits));
}
fn fold(ctx: *C.Context, values: []const F, twiddles: []const []C.Var, alphas: []const F) !F {
    const v = try ctx.scratch().dupe(F, values);
    for (alphas, twiddles) |alpha, tw| for (tw, 0..) |t, i| {
        v[i] = v[2 * i].add(v[2 * i + 1]).add(alpha.mul(v[2 * i].sub(v[2 * i + 1]).mul(C.base(t))));
    };
    return v[0];
}
pub fn decommit(ctx: *C.Context, proof: *const P.Proof, lifting_log: u32, config: core.fri.FriConfig, input: []const F, queries: Queries, alphas: []const F) !void {
    const a = ctx.scratch();
    if (input.len != queries.n_queries or alphas.len != proof.layers.len or lifting_log < config.log_blowup_factor) return error.ShapeMismatch;
    const degree_log = lifting_log - config.log_blowup_factor;
    if (degree_log < config.log_last_layer_degree_bound) return error.ShapeMismatch;
    var step_buffer: [64]u32 = undefined;
    const steps = core.fri.allFoldSteps(degree_log - config.log_last_layer_degree_bound, config.fold_step, &step_buffer);
    if (steps.len != proof.layers.len) return error.ShapeMismatch;
    var values = try a.dupe(F, input);
    var bits = queries.unpacked;
    var packed_bits = queries.bits;
    var base_point: Point(Simd) = undefined;
    var doublings: usize = 0;
    const query_bits = try a.alloc(C.Var, lifting_log);
    const alpha_powers = try a.alloc(F, config.fold_step);
    for (proof.layers, steps, 0..) |layer, step_u32, layer_index| {
        const step: usize = step_u32;
        const layer_log = bits.len;
        const size = @as(usize, 1) << @intCast(step);
        const coset_bits = helpers.splitOff(Simd, &packed_bits, step);
        if (layer_index == 0) {
            base_point = try helpers.circleTranslateToBasePoint(Q, ctx, queries.points, coset_bits);
            doublings = step - 1;
        } else {
            const point = try circuit.stark_verifier.circle.repeatedDoublePointSimd(Q, ctx, base_point, doublings);
            base_point = try helpers.translateToBasePoint(Q, ctx, point, coset_bits);
            doublings = step;
        }
        const twiddles = if (layer_index == 0) try helpers.circleComputeTwiddlesFromBasePoint(Q, ctx, base_point, step) else try helpers.computeTwiddlesFromBasePoint(Q, ctx, base_point, step);
        const position = helpers.splitOff([]const C.Var, &bits, step);
        const pack = layer_log >= core.fri.LOG_PACKED_LEAF_SIZE and step > 1;
        const width: usize = if (pack) 1 << core.fri.LOG_PACKED_LEAF_SIZE else 1;
        const nfolds = step - if (pack) @as(usize, core.fri.LOG_PACKED_LEAF_SIZE) else 0;
        const leaves = try a.alloc(C.Hash, size / width);
        alpha_powers[0] = alphas[layer_index];
        for (alpha_powers[1..step], 0..) |*power, i| power.* = alpha_powers[i].square();
        const next = try a.alloc(F, queries.n_queries);
        const per_fold = try a.alloc([]C.Var, step);
        const cap_log: usize = if (layer.cap.len == 0) 0 else std.math.log2_int(usize, layer.cap.len);
        if (cap_log != 0) try merkle.verifyCap(Q, ctx, layer.cap, layer.commitment);
        for (layer.cosets, layer.auth_paths, values, next, 0..) |coset, path, value, *out, q| {
            if (coset.len != size or path.len + cap_log != bits.len) return error.ShapeMismatch;
            for (position, query_bits[0..step]) |column, *bit| bit.* = column[q];
            try C.eq(ctx, value, try select(ctx, coset, query_bits[0..step]));
            for (leaves, 0..) |*leaf, i| leaf.* = try hashLeaf(ctx, coset[i * width ..][0..width]);
            for (0..nfolds) |f| for (0..@as(usize, 1) << @intCast(nfolds - f - 1)) |i| {
                leaves[i] = try merkle.hashNode(Q, ctx, leaves[2 * i], leaves[2 * i + 1]);
            };
            for (bits, query_bits[0..bits.len]) |column, *bit| bit.* = column[q];
            if (cap_log == 0) {
                try merkle.verifyPath(Q, ctx, leaves[0], query_bits[0..bits.len], path, layer.commitment);
            } else {
                try merkle.verifyPathToCap(Q, ctx, leaves[0], query_bits[0..bits.len], path, layer.cap);
            }
            for (per_fold, twiddles) |*dst, src| {
                dst.* = try a.alloc(C.Var, src.len);
                for (dst.*, src) |*t, packed_t| t.* = try simd.unpackIdx(Q, ctx, packed_t, q);
            }
            out.* = try fold(ctx, coset, per_fold, alpha_powers[0..step]);
        }
        values = next;
    }
    if (bits.len != config.log_last_layer_degree_bound + config.log_blowup_factor) return error.ShapeMismatch;
    if (config.log_last_layer_degree_bound == 0) {
        for (values) |value| try C.eq(ctx, value, proof.last_layer_coefs[0]);
        return;
    }
    const last_point = try circuit.stark_verifier.circle.repeatedDoublePointSimd(Q, ctx, base_point, doublings);
    const xs = try simd.unpack(Q, ctx, last_point.x);
    for (values, xs) |value, x| try C.eq(ctx, value, try evalLine(ctx, proof.last_layer_coefs, C.base(x)));
    try C.lane.check();
}
fn evalLine(ctx: *C.Context, coefficients: []const F, x: F) !F {
    const factors = try ctx.scratch().alloc(F, std.math.log2_int(usize, coefficients.len));
    var point = x;
    for (factors) |*f| {
        f.* = point;
        point = C.doubleX(point);
    }
    return foldCoefficients(coefficients, factors);
}
fn foldCoefficients(values: []const F, factors: []const F) F {
    if (values.len == 1) return values[0];
    const half = values.len / 2;
    return foldCoefficients(values[0..half], factors[1..]).add(foldCoefficients(values[half..], factors[1..]).mul(factors[0]));
}
