//! OM31 FRI on the unchanged M31 circle domain and prefixed Blake tree.
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
    return native.merkle.hashLeafQm31s(Q, ctx, halves);
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
        v[i] = v[2 * i].add(v[2 * i + 1]).add(alpha.mul(v[2 * i].sub(v[2 * i + 1]).mulInner(C.Inner.wire(t))));
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
        alpha_powers[0] = alphas[layer_index];
        for (alpha_powers[1..step], 0..) |*power, i| power.* = alpha_powers[i].square();
        const cl = if (layer.cap.len == 0) 0 else std.math.log2_int(usize, layer.cap.len);
        if (native.fri.shortLineGroups(layer_index, layer_log - step, step, queries.n_queries, cl) != 0) {
            values = try verifyShortLine(ctx, layer, lifting_log, layer_log, step, bits, values, alpha_powers[0..step]);
            bits = bits[step..];
            continue;
        }
        const twiddles = if (layer_index == 0) try helpers.circleComputeTwiddlesFromBasePoint(Q, ctx, base_point, step) else try helpers.computeTwiddlesFromBasePoint(Q, ctx, base_point, step);
        const position = helpers.splitOff([]const C.Var, &bits, step);
        const pack = layer_log >= core.fri.LOG_PACKED_LEAF_SIZE and step > 1;
        const width: usize = if (pack) 1 << core.fri.LOG_PACKED_LEAF_SIZE else 1;
        const nfolds = step - if (pack) @as(usize, core.fri.LOG_PACKED_LEAF_SIZE) else 0;
        const leaves = try a.alloc(C.Hash, size / width);
        const next = try a.alloc(F, queries.n_queries);
        const per_fold = try a.alloc([]C.Var, step);
        if (cl != 0) try native.merkle.verifyCap(Q, ctx, layer.cap, layer.commitment);
        for (layer.cosets, layer.auth_paths, values, next, 0..) |coset, path, value, *out, q| {
            if (coset.len != size or path.len + cl != bits.len) return error.ShapeMismatch;
            for (position, query_bits[0..step]) |column, *bit| bit.* = column[q];
            try C.eq(ctx, value, try select(ctx, coset, query_bits[0..step]));
            for (leaves, 0..) |*leaf, i| leaf.* = try hashLeaf(ctx, coset[i * width ..][0..width]);
            for (0..nfolds) |f| for (0..@as(usize, 1) << @intCast(nfolds - f - 1)) |i| {
                leaves[i] = try native.merkle.hashNode(Q, ctx, leaves[2 * i], leaves[2 * i + 1]);
            };
            for (bits, query_bits[0..bits.len]) |column, *bit| bit.* = column[q];
            if (cl == 0) {
                try native.merkle.verifyPath(Q, ctx, leaves[0], query_bits[0..bits.len], path, layer.commitment);
            } else {
                try native.merkle.verifyPathToCap(Q, ctx, leaves[0], query_bits[0..bits.len], path, layer.cap);
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

/// Every selected root is constrained by its multiplicity in authenticated
/// query bits. Missing groups may contain zeros. The count cannot wrap in M31.
pub fn verifyShortLine(ctx: *C.Context, layer: P.Layer, lifting: u32, log: usize, step: usize, bits: []const []const C.Var, values: []const F, alphas: []const F) ![]F {
    if (log >= lifting or lifting > core.poly.circle.MAX_CIRCLE_DOMAIN_LOG_SIZE or step > log or
        native.fri.shortLineGroups(1, log - step, step, values.len, 0) == 0 or alphas.len != step) return error.ShapeMismatch;
    for (bits) |column| if (column.len != values.len) return error.ShapeMismatch;
    const a = ctx.scratch();
    const groups = @as(usize, 1) << @intCast(log - step);
    const width = @as(usize, 1) << @intCast(step);
    const leaf_width: usize = if (step > 1) @as(usize, 1) << core.fri.LOG_PACKED_LEAF_SIZE else 1;
    if (layer.cap.len != 0 or layer.cosets.len != groups or layer.auth_paths.len != groups or bits.len != log) return error.ShapeMismatch;
    const roots = try a.alloc(C.Hash, groups);
    const outputs = try a.alloc(F, groups);
    const leaves = try a.alloc(C.Hash, width / leaf_width);
    const line = core.poly.line.LineDomain.fromCircleDomain(core.poly.circle.canonic.CanonicCoset.new(lifting).circleDomain()).repeatedDouble(lifting - 1 - @as(u32, @intCast(log)));
    for (layer.cosets, layer.auth_paths, 0..) |coset, path, g| {
        if (coset.len != width or path.len != log - step) return error.ShapeMismatch;
        for (leaves, 0..) |*v, i| v.* = try hashLeaf(ctx, coset[i * leaf_width ..][0..leaf_width]);
        var live = leaves.len;
        while (live > 1) {
            live /= 2;
            for (0..live) |i| leaves[i] = try native.merkle.hashNode(Q, ctx, leaves[2 * i], leaves[2 * i + 1]);
        }
        var d = leaves[0];
        for (path, 0..) |sib, k| d = if ((g >> @intCast(k)) & 1 == 0) try native.merkle.hashNode(Q, ctx, d, sib) else try native.merkle.hashNode(Q, ctx, sib, d);
        roots[g] = d;
        const tw = try a.alloc([]C.Var, step);
        var domain = line;
        for (tw, 0..) |*row, k| {
            const len = width >> @intCast(k + 1);
            row.* = try a.alloc(C.Var, len);
            for (row.*, 0..) |*t, i| {
                const pos = core.utils.bitReverseIndex(2 * (g * len + i), domain.logSize());
                t.* = C.Inner.fromBase(try domain.at(pos).inv()).v;
            }
            domain = domain.double();
        }
        outputs[g] = try fold(ctx, coset, tw, alphas);
    }
    const indices = try a.alloc(C.Var, log);
    const result = try a.alloc(F, values.len);
    const counts = try a.alloc(C.Inner, groups);
    const selected = try a.alloc(F, groups);
    const group_weights = try a.alloc(C.Inner, groups);
    const entry_weights = try a.alloc(C.Inner, width);
    @memset(counts, C.Inner.zero());
    for (values, result, 0..) |v, *out, q| {
        for (bits, indices) |col, *b| b.* = col[q];
        indicators(group_weights, indices[step..]);
        indicators(entry_weights, indices[0..step]);
        for (counts, group_weights, layer.cosets, selected) |*count, w, coset, *s| {
            count.* = count.add(w);
            s.* = weighted(coset, entry_weights);
        }
        try C.eq(ctx, v, weighted(selected, group_weights));
        out.* = weighted(outputs, group_weights);
    }
    for (roots, counts) |root, count| for (root.words, layer.commitment.words) |l, r|
        try ctx.eq(count.mul(C.Inner.wire(l.get()).sub(C.Inner.wire(r.get()))).v, ctx.zero());
    return result;
}
/// Multilinear equality weights, in the same little-endian order as the FRI image.
fn indicators(weights: []C.Inner, bits: []const C.Var) void {
    weights[0] = C.Inner.one();
    var live: usize = 1;
    for (bits) |b| {
        const bit = C.Inner.wire(b);
        for (0..live) |i| {
            weights[i + live] = weights[i].mul(bit);
            weights[i] = weights[i].sub(weights[i + live]);
        }
        live *= 2;
    }
}

fn weighted(vs: []const F, ws: []const C.Inner) F {
    var sum = vs[0].mulInner(ws[0]);
    for (vs[1..], ws[1..]) |v, w| sum = sum.add(v.mulInner(w));
    return sum;
}

test {
    _ = @import("short_fri_test.zig");
}
