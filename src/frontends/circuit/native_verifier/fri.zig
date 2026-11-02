//! In-circuit FRI of the native protocol: port of `FriVerifier.commit` and
//! `decommitImpl` in `core/fri.zig`, the folds of `core/fri/folding.zig`,
//! the leaf layout of `core/fri/merkle_queries.zig`, the fold schedule of
//! `core/fri/config.zig` and the query positions of `core/queries.zig`.
//!
//! Commit: the first layer root is mixed and its alpha drawn, then each
//! inner layer's root and alpha, then the last layer coefficients are mixed
//! (`mixFelts`). Decommit, per layer: each query's value sits at its
//! position in the `2^fold_step` coset (the values of positions sharing
//! `position >> fold_step`, in position order); the coset hashes to the
//! layer root (leaves of one QM31, or of four when `fold_step > 1` on a
//! domain of at least four values, as `pack_leaves`), through the domain
//! prefixed hashes; the coset folds with `fold_step` folds, circle-to-line
//! first, alpha squared after each fold, into the next layer's value. The
//! last layer is the line polynomial of the mixed coefficients evaluated at
//! the query's last-domain point (`LinePoly.evalAtPoint` with
//! `poly/utils.zig` `fold`), a constant when `log_last_layer == 0`.
//!
//! Positions as points. `friAnswers` evaluates at `domain.at(bitReverse(p))`
//! of the canonic circle domain: `p`'s bit 0 picks the conjugate and bit
//! `i >= 1` adds the generator of order `2^i` to the generator of order
//! `2^(log+1)`, which `queryPoints` builds as `select_queries.zig` does. The
//! fold arithmetic (twiddles from the coset base point, doubling between
//! layers) is the `stark_verifier/fri.zig` one, which stwo shares.

const std = @import("std");
const core = @import("stwo_core");
const builder = @import("../builder/mod.zig");
const sv_circle = @import("../stark_verifier/circle.zig");
const sv_fri = @import("fold_helpers.zig");
const select_queries = @import("../stark_verifier/select_queries.zig");
const channel_mod = @import("channel.zig");
const merkle = @import("merkle.zig");

const FriConfig = core.fri.FriConfig;
const Var = builder.Var;
const Context = builder.Context;
const Error = builder.context.Error;
const simd = builder.simd;
const Simd = simd.Simd;
const HashValue = builder.blake.HashValue;
const Point = sv_circle.Point;
const NativeChannel = channel_mod.NativeChannel;

pub const FriError = Error || error{
    /// The proof has a different number of layers, cosets or path nodes
    /// than the schedule implies.
    ShapeMismatch,
};

/// One FRI layer of the fixed-width witness: the root, per raw query the
/// full coset of `2^fold_step` values (position order) and the
/// authentication path above the coset's subtree (leaf side first).
pub fn Layer(comptime T: type) type {
    return struct {
        commitment: HashValue(T),
        cosets: []const []const T,
        auth_paths: []const []const HashValue(T),
    };
}

/// The FRI proof: the first layer, the inner layers, the last layer.
pub fn FriProof(comptime T: type) type {
    return struct {
        layers: []const Layer(T),
        last_layer_coefs: []const T,
    };
}

/// The queries: their bits (packed and unpacked, LSB first) and their
/// points in the lifting domain.
pub const Queries = struct {
    bits: []const Simd,
    unpacked: []const []const Var,
    points: Point(Simd),
    n_queries: usize,
};

/// `FriVerifier.commit`: returns the folding alphas, one per layer
/// (scratch-owned).
pub fn friCommit(comptime V: type, ctx: *Context(V), channel: *NativeChannel, proof: *const FriProof(Var)) Error![]const Var {
    const alphas = try ctx.scratch().alloc(Var, proof.layers.len);
    for (proof.layers, alphas) |layer, *alpha| {
        try channel.mixRoot(V, ctx, layer.commitment);
        alpha.* = try channel.drawSecureFelt(V, ctx);
    }
    try channel.mixFelts(V, ctx, proof.last_layer_coefs);
    return alphas;
}

/// `CanonicCoset.new(log_domain).circleDomain().at(bitReverse(p))` for every
/// query from its bits: the generator of order `2^(log_domain + 1)`, plus
/// the generator of order `2^i` for every set bit `i >= 1`, conjugated when
/// bit 0 is set.
pub fn queryPoints(comptime V: type, ctx: *Context(V), bits: []const Simd, log_domain: usize) Error!Point(Simd) {
    std.debug.assert(bits.len == log_domain and log_domain >= 1);
    const n = bits[0].len;
    var point = try sv_circle.generatorPointSimd(V, ctx, log_domain + 1, n);
    for (bits[1..], 1..) |bit, i| {
        const generator = try sv_circle.generatorPointSimd(V, ctx, i, n);
        const point_if_bit = try sv_circle.addPointsSimd(V, ctx, point, generator);
        point = .{
            .x = try simd.select(V, ctx, bit, point.x, point_if_bit.x),
            .y = try simd.select(V, ctx, bit, point.y, point_if_bit.y),
        };
    }
    const neg_y = try select_queries.negSimd(V, ctx, point.y);
    point.y = try simd.select(V, ctx, bits[0], point.y, neg_y);
    return point;
}

/// The queries of a draw: bits plus points.
pub fn queriesFromBits(comptime V: type, ctx: *Context(V), drawn: channel_mod.QueryBits, log_domain: u32) Error!Queries {
    return .{
        .bits = drawn.bits,
        .unpacked = drawn.unpacked,
        .points = try queryPoints(V, ctx, drawn.bits, log_domain),
        .n_queries = drawn.n_queries,
    };
}

/// `FriVerifier.decommitImpl`: checks `fri_input` (one value per query) and
/// the proof against the alphas of `friCommit`, for the lifting domain of
/// log size `lifting_log` and the configuration `config`.
pub fn friDecommit(
    comptime V: type,
    ctx: *Context(V),
    proof: *const FriProof(Var),
    lifting_log: u32,
    config: FriConfig,
    fri_input: []const Var,
    queries: Queries,
    alphas: []const Var,
) FriError!void {
    const scratch = ctx.scratch();
    const n_queries = queries.n_queries;
    if (fri_input.len != n_queries or alphas.len != proof.layers.len) return error.ShapeMismatch;
    if (lifting_log < config.log_blowup_factor) return error.ShapeMismatch;
    const log_degree_bound = lifting_log - config.log_blowup_factor;
    if (log_degree_bound < config.log_last_layer_degree_bound) return error.ShapeMismatch;
    var steps_buffer: [64]u32 = undefined;
    const steps = core.fri.allFoldSteps(log_degree_bound - config.log_last_layer_degree_bound, config.fold_step, &steps_buffer);
    if (steps.len != proof.layers.len) return error.ShapeMismatch;
    if (proof.last_layer_coefs.len != @as(usize, 1) << @intCast(config.log_last_layer_degree_bound)) return error.ShapeMismatch;

    var layer_values = try scratch.dupe(Var, fri_input);
    var bits = queries.unpacked;
    var packed_bits = queries.bits;
    if (bits.len != lifting_log) return error.ShapeMismatch;

    var base_point: Point(Simd) = undefined;
    var doublings_after: usize = 0;
    const bits_for_query = try scratch.alloc(Var, lifting_log);
    const alpha_powers = try scratch.alloc(Var, config.fold_step);

    for (proof.layers, steps, 0..) |layer, step_u32, layer_idx| {
        const step: usize = step_u32;
        const log_layer_size = bits.len;
        const coset_size = @as(usize, 1) << @intCast(step);
        if (layer.cosets.len != n_queries or layer.auth_paths.len != n_queries) return error.ShapeMismatch;

        // The base point of each query's coset and the fold twiddles.
        const coset_bits = sv_fri.splitOff(Simd, &packed_bits, step);
        if (layer_idx == 0) {
            base_point = try sv_fri.circleTranslateToBasePoint(V, ctx, queries.points, coset_bits);
            doublings_after = step - 1;
        } else {
            const query_domain_point = try sv_circle.repeatedDoublePointSimd(V, ctx, base_point, doublings_after);
            base_point = try sv_fri.translateToBasePoint(V, ctx, query_domain_point, coset_bits);
            doublings_after = step;
        }
        const twiddles_per_fold = if (layer_idx == 0)
            try sv_fri.circleComputeTwiddlesFromBasePoint(V, ctx, base_point, step)
        else
            try sv_fri.computeTwiddlesFromBasePoint(V, ctx, base_point, step);

        // Each query's value is the coset value its low `step` bits select.
        const position_bits = sv_fri.splitOff([]const Var, &bits, step);
        const query_bits = try scratch.alloc(Var, step);
        for (layer_values, layer.cosets, 0..) |value, coset, q| {
            if (coset.len != coset_size) return error.ShapeMismatch;
            for (query_bits, position_bits) |*bit, column| bit.* = column[q];
            const expected = try builder.select.selectByIndex(V, ctx, coset, query_bits);
            try ctx.eq(value, expected);
        }

        // The Merkle decommitment of every coset.
        const pack_leaves = log_layer_size >= core.fri.LOG_PACKED_LEAF_SIZE and step > 1;
        const leaf_width: usize = if (pack_leaves) @as(usize, 1) << @intCast(core.fri.LOG_PACKED_LEAF_SIZE) else 1;
        const n_leaves = coset_size / leaf_width;
        const n_folds = step - (if (pack_leaves) @as(usize, core.fri.LOG_PACKED_LEAF_SIZE) else 0);
        const leaves = try scratch.alloc(HashValue(Var), n_leaves);
        for (layer.cosets, layer.auth_paths, 0..) |coset, path, q| {
            if (path.len != bits.len) return error.ShapeMismatch;
            for (leaves, 0..) |*leaf, i| leaf.* = try merkle.hashLeafQm31s(V, ctx, coset[i * leaf_width ..][0..leaf_width]);
            for (0..n_folds) |fold| {
                for (0..@as(usize, 1) << @intCast(n_folds - fold - 1)) |i| {
                    leaves[i] = try merkle.hashNode(V, ctx, leaves[2 * i], leaves[2 * i + 1]);
                }
            }
            for (bits_for_query[0..bits.len], bits) |*bit, column| bit.* = column[q];
            try merkle.verifyPath(V, ctx, leaves[0], bits_for_query[0..bits.len], path, layer.commitment);
        }

        // alpha, alpha^2, ..., alpha^(2^(step - 1)).
        alpha_powers[0] = alphas[layer_idx];
        for (alpha_powers[1..step], 0..) |*power, i| power.* = try ctx.mul(alpha_powers[i], alpha_powers[i]);

        // Fold every coset into the next layer's value.
        const next_values = try scratch.alloc(Var, n_queries);
        const per_fold = try scratch.alloc([]Var, step);
        for (next_values, layer.cosets, 0..) |*value, coset, q| {
            for (per_fold, twiddles_per_fold) |*fold, packed_fold| {
                fold.* = try scratch.alloc(Var, packed_fold.len);
                for (fold.*, packed_fold) |*twiddle, packed_twiddle| twiddle.* = try simd.unpackIdx(V, ctx, packed_twiddle, q);
            }
            value.* = try sv_fri.foldCoset(V, ctx, coset, per_fold, alpha_powers[0..step]);
        }
        layer_values = next_values;
    }
    if (bits.len != config.log_last_layer_degree_bound + config.log_blowup_factor) return error.ShapeMismatch;

    if (config.log_last_layer_degree_bound == 0) {
        for (layer_values) |value| try ctx.eq(value, proof.last_layer_coefs[0]);
        return;
    }
    // `decommitLastLayer`: the last domain's point of each query is the
    // doubled base point; evaluate the line polynomial there.
    const last_point = try sv_circle.repeatedDoublePointSimd(V, ctx, base_point, doublings_after);
    const xs = try simd.unpack(V, ctx, last_point.x);
    for (layer_values, xs) |value, x| {
        const expected = try evalLinePoly(V, ctx, proof.last_layer_coefs, x);
        try ctx.eq(value, expected);
    }
}

/// `LinePoly.evalAtPoint`: `poly/utils.zig` `fold(coeffs, [x, pi(x), pi^2(x), ...])`.
pub fn evalLinePoly(comptime V: type, ctx: *Context(V), coeffs: []const Var, x: Var) Error!Var {
    std.debug.assert(coeffs.len != 0 and std.math.isPowerOfTwo(coeffs.len));
    const log_size = std.math.log2_int(usize, coeffs.len);
    const factors = try ctx.scratch().alloc(Var, log_size);
    var current = x;
    for (factors) |*factor| {
        factor.* = current;
        current = try sv_circle.doubleX(V, ctx, current);
    }
    return foldCoefficients(V, ctx, coeffs, factors);
}

/// `fold(values, factors)`: `fold(low half, factors[1..]) + fold(high half,
/// factors[1..]) * factors[0]`.
fn foldCoefficients(comptime V: type, ctx: *Context(V), values: []const Var, factors: []const Var) Error!Var {
    if (values.len == 1) return values[0];
    const half = values.len / 2;
    const low = try foldCoefficients(V, ctx, values[0..half], factors[1..]);
    const high = try foldCoefficients(V, ctx, values[half..], factors[1..]);
    const scaled = try ctx.mul(high, factors[0]);
    return ctx.add(low, scaled);
}

test {
    _ = @import("fri_test.zig");
}
