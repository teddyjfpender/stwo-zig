//! In-circuit FRI: port of `crates/stark_verifier/src/fri.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230).
//!
//! The commit phase mixes each layer root and draws its folding alpha. The
//! decommit phase checks, per layer and query, that the query value sits at
//! its position in the guessed coset, that the coset hashes to the layer
//! root (packing four QM31s per leaf once a layer has at least four values
//! per coset), and folds the coset with `fold_step` folds (circle-to-line
//! first) into the next layer's query value. The last layer is a constant.

const std = @import("std");
const core = @import("stwo_core");
const builder = @import("../builder/mod.zig");
const channel_mod = @import("channel.zig");
const circle = @import("circle.zig");
const merkle = @import("merkle.zig");
const proof_mod = @import("proof.zig");
const proof_from_stark_proof = @import("proof_from_stark_proof.zig");
const select_queries = @import("select_queries.zig");

const QM31 = core.fields.qm31.QM31;
const FriConfig = core.pcs.config_v2.FriConfigV2;
const Var = builder.Var;
const Context = builder.Context;
const Error = builder.context.Error;
const simd = builder.simd;
const Simd = simd.Simd;
const HashValue = builder.blake.HashValue;
const Point = circle.Point;
const Queries = select_queries.Queries;

/// `mix_fri_config`: `[pow_bits, log_blowup_factor, n_queries,
/// log_last_layer_degree_bound, fold_step]` as two QM31 constants.
pub fn mixFriConfig(comptime V: type, ctx: *Context(V), channel: *channel_mod.Channel, config: FriConfig) Error!void {
    const values = [_]u32{ config.pow_bits, config.log_blowup_factor, config.n_queries, config.log_last_layer_degree_bound, config.fold_step };
    var packed_buffer: [2]QM31 = undefined;
    var vars: [2]Var = undefined;
    for (proof_from_stark_proof.packIntoQm31s(&values, &packed_buffer), &vars) |value, *v| v.* = try ctx.constant(value);
    try channel.mixQm31s(V, ctx, &vars);
}

/// `fri_commit`: mixes every layer root, drawing one alpha after each, then
/// the last layer. Returns the alphas (scratch-owned).
pub fn friCommit(comptime V: type, ctx: *Context(V), channel: *channel_mod.Channel, proof: *const proof_mod.FriProof(Var)) Error![]const Var {
    const alphas = try ctx.scratch().alloc(Var, proof.layer_commitments.len);
    for (proof.layer_commitments, alphas) |root, *alpha| {
        try channel.mixCommitment(V, ctx, root);
        alpha.* = try channel.drawQm31(V, ctx);
    }
    try channel.mixQm31s(V, ctx, proof.last_layer_coefs);
    return alphas;
}

/// `fri_decommit`: checks `fri_input` (one value per query) against the
/// FRI commitment. `bits[i][q]` is bit `i` of query `q`.
pub fn friDecommit(
    comptime V: type,
    ctx: *Context(V),
    proof: *const proof_mod.FriProof(Var),
    log_trace_size: usize,
    config: FriConfig,
    fri_input: []const Var,
    all_bits: []const []const Var,
    queries: Queries,
    alphas: []const Var,
) Error!void {
    const scratch = ctx.scratch();
    const n_queries: usize = config.n_queries;
    var layer_values = try scratch.dupe(Var, fri_input);
    var bits = all_bits;
    var packed_bits = queries.bits;

    var log_degree_bound = log_trace_size;
    var step: usize = config.fold_step;
    std.debug.assert(log_trace_size >= step);
    std.debug.assert(config.log_last_layer_degree_bound == 0);

    // Translate the query points to the base of their circle domains.
    var base_point = try circleTranslateToBasePoint(V, ctx, queries.points, splitOff(Simd, &packed_bits, step));
    var twiddles_per_fold = try circleComputeTwiddlesFromBasePoint(V, ctx, base_point, step);
    // The first fold is circle-to-line, so the base point is doubled
    // `step - 1` times before the next layer.
    var n_doubles = step - 1;

    const bits_for_query = try scratch.alloc(Var, bits.len);
    const alpha_powers = try scratch.alloc(Var, step);
    std.debug.assert(fri_input.len == n_queries);

    for (proof.layer_commitments, proof.witness, 0..) |root, witness, tree_idx| {
        const log_layer_size = bits.len;
        const coset_size = @as(usize, 1) << @intCast(step);
        std.debug.assert(witness.len == n_queries * coset_size);

        try validateQueryPositionInCoset(V, ctx, witness, coset_size, layer_values, splitOff([]const Var, &bits, step));

        // The Merkle decommitment of every query's coset.
        const pack_leaves = log_layer_size >= merkle.LOG_PACKED_LEAF_SIZE and step > 1;
        const n_leaves = if (pack_leaves) coset_size / merkle.PACKED_LEAF_SIZE else coset_size;
        const n_folds = if (pack_leaves) step - merkle.LOG_PACKED_LEAF_SIZE else step;
        const leaves = try scratch.alloc(HashValue(Var), n_leaves);
        for (0..n_queries) |query_idx| {
            const coset = witness[query_idx * coset_size ..][0..coset_size];
            for (leaves, 0..) |*leaf, i| leaf.* = if (pack_leaves)
                try merkle.hashPackedLeafQm31s(V, ctx, coset[i * merkle.PACKED_LEAF_SIZE ..][0..merkle.PACKED_LEAF_SIZE])
            else
                try merkle.hashLeafQm31(V, ctx, coset[i]);
            // Each fold halves the active prefix; the root ends at index 0.
            for (0..n_folds) |fold| {
                for (0..@as(usize, 1) << @intCast(n_folds - fold - 1)) |i| {
                    leaves[i] = try merkle.hashNode(V, ctx, leaves[2 * i], leaves[2 * i + 1]);
                }
            }
            for (bits_for_query[0..bits.len], bits) |*bit, query_bits| bit.* = query_bits[query_idx];
            try merkle.verifyMerklePath(V, ctx, leaves[0], bits_for_query[0..bits.len], root, proof.auth_paths.at(tree_idx, query_idx));
        }

        // alpha, alpha^2, ..., alpha^(2^(step - 1)).
        alpha_powers[0] = alphas[tree_idx];
        for (alpha_powers[1..step], 0..) |*power, i| power.* = try ctx.mul(alpha_powers[i], alpha_powers[i]);

        // Unpack the twiddles per query ([fold][twiddle]) and fold each coset.
        std.debug.assert(twiddles_per_fold.len == step);
        const next_values = try scratch.alloc(Var, n_queries);
        const unpacked = try scratch.alloc([][]Var, n_queries);
        for (unpacked, 0..) |*per_fold, query_idx| {
            per_fold.* = try scratch.alloc([]Var, step);
            for (per_fold.*, twiddles_per_fold) |*fold, packed_fold| {
                fold.* = try scratch.alloc(Var, packed_fold.len);
                for (fold.*, packed_fold) |*twiddle, packed_twiddle| twiddle.* = try simd.unpackIdx(V, ctx, packed_twiddle, query_idx);
            }
        }
        for (next_values, unpacked, 0..) |*value, per_fold, query_idx| {
            value.* = try foldCoset(V, ctx, witness[query_idx * coset_size ..][0..coset_size], per_fold, alpha_powers[0..step]);
        }
        layer_values = next_values;

        log_degree_bound -|= step;
        if (log_degree_bound == 0) break;

        // The query-domain points of the next layer's values.
        const query_domain_point = try circle.repeatedDoublePointSimd(V, ctx, base_point, n_doubles);
        n_doubles = step;
        step = @min(step, log_degree_bound);
        base_point = try translateToBasePoint(V, ctx, query_domain_point, splitOff(Simd, &packed_bits, step));
        twiddles_per_fold = try computeTwiddlesFromBasePoint(V, ctx, base_point, step);
    }
    // The last layer has log size `log_blowup_factor`.
    std.debug.assert(bits.len == config.log_blowup_factor);
    std.debug.assert(packed_bits.len == config.log_blowup_factor);

    // With a last step of 1, the last base point's y was never used.
    if (step == 1) try simd.markPartlyUsed(V, ctx, base_point.y);

    const last_layer_value = proof.last_layer_coefs[0];
    for (layer_values) |value| try ctx.eq(value, last_layer_value);
}

/// `split_off(..n)` on a slice: returns the first `n` items and advances.
fn splitOff(comptime T: type, items: *[]const T, n: usize) []const T {
    std.debug.assert(items.len >= n);
    const head = items.*[0..n];
    items.* = items.*[n..];
    return head;
}

/// `fold_coset`: folds `2^n` coset values to one with `n` folds, fold `i`
/// using `twiddles_per_fold[i]` (length `2^(n-1-i)`) and `alphas[i]`.
fn foldCoset(comptime V: type, ctx: *Context(V), coset_values: []const Var, twiddles_per_fold: []const []Var, alphas: []const Var) Error!Var {
    std.debug.assert(coset_values.len == @as(usize, 1) << @intCast(twiddles_per_fold.len));
    std.debug.assert(alphas.len == twiddles_per_fold.len);
    const values = try ctx.scratch().dupe(Var, coset_values);
    for (alphas, twiddles_per_fold) |alpha, twiddles| {
        for (twiddles, 0..) |twiddle, j| {
            const even = values[2 * j];
            const odd = values[2 * j + 1];
            const g = try ctx.add(even, odd);
            const h = try ctx.mul(try ctx.sub(even, odd), twiddle);
            values[j] = try ctx.add(g, try ctx.mul(alpha, h));
        }
    }
    return values[0];
}

/// `validate_query_position_in_coset`: each query value equals the coset
/// value its low `step` bits select.
fn validateQueryPositionInCoset(
    comptime V: type,
    ctx: *Context(V),
    witness: []const Var,
    coset_size: usize,
    layer_values: []const Var,
    bits: []const []const Var,
) Error!void {
    const query_bits = try ctx.scratch().alloc(Var, bits.len);
    for (layer_values, 0..) |query_value, query_idx| {
        for (query_bits, bits) |*bit, bit_column| bit.* = bit_column[query_idx];
        const coset = witness[query_idx * coset_size ..][0..coset_size];
        const expected = try builder.select.selectByIndex(V, ctx, coset, query_bits);
        try ctx.eq(query_value, expected);
    }
}

/// `circle_compute_twiddles_from_base_point`: the y twiddles of the
/// circle-to-line fold, then the x twiddles of the line folds. The result is
/// `[fold][twiddle]`, each twiddle packed across queries.
fn circleComputeTwiddlesFromBasePoint(comptime V: type, ctx: *Context(V), base_point: Point(Simd), fold_step: usize) Error![]const []const Simd {
    std.debug.assert(fold_step > 0);
    const scratch = ctx.scratch();
    if (fold_step == 1) {
        const folds = try scratch.alloc([]const Simd, 1);
        const twiddle = try scratch.alloc(Simd, 1);
        twiddle[0] = try simd.inv(V, ctx, base_point.y);
        folds[0] = twiddle;
        return folds;
    }

    // The witness domain is a circle domain with a half coset of log size `fold_step - 1`.
    const coset_points = try circle.computeHalfCosetPoints(V, ctx, base_point, @intCast(fold_step - 1));
    if (coset_points.len > 1) try simd.markPartlyUsed(V, ctx, coset_points[coset_points.len - 1].y);

    const y_inverses = try scratch.alloc(Simd, coset_points.len);
    for (y_inverses, coset_points) |*y_inv, point| y_inv.* = try simd.inv(V, ctx, point.y);
    const folds = try scratch.alloc([]const Simd, fold_step);
    const first = try scratch.alloc(Simd, 2 * y_inverses.len);
    for (y_inverses, 0..) |y_inv, i| {
        first[2 * i] = y_inv;
        first[2 * i + 1] = try select_queries.negSimd(V, ctx, y_inv);
    }
    folds[0] = first;

    const x_coords = try scratch.alloc(Simd, coset_points.len);
    for (x_coords, coset_points) |*x, point| x.* = point.x;
    try computeXTwiddles(V, ctx, x_coords, folds[1..]);
    return folds;
}

/// `compute_x_twiddles`: `out.len` folds; each inverts the current x
/// coordinates, then (except the last) keeps every other one, doubled.
fn computeXTwiddles(comptime V: type, ctx: *Context(V), x_coords: []const Simd, out: [][]const Simd) Error!void {
    var xs = x_coords;
    for (out, 0..) |*fold, fold_idx| {
        const inverses = try ctx.scratch().alloc(Simd, xs.len);
        for (inverses, xs) |*x_inv, x| x_inv.* = try simd.inv(V, ctx, x);
        fold.* = inverses;
        // No unused gates in the last iteration.
        if (fold_idx != out.len - 1) {
            const next = try ctx.scratch().alloc(Simd, std.math.divCeil(usize, xs.len, 2) catch unreachable);
            for (next, 0..) |*x, i| x.* = try circle.doubleXSimd(V, ctx, xs[2 * i]);
            xs = next;
        }
    }
}

/// `compute_twiddles_from_base_point`: the x twiddles of a line-to-line
/// step.
fn computeTwiddlesFromBasePoint(comptime V: type, ctx: *Context(V), base_point: Point(Simd), fold_step: usize) Error![]const []const Simd {
    std.debug.assert(fold_step > 0);
    const coset_points = try circle.computeHalfCosetPoints(V, ctx, base_point, @intCast(fold_step));
    // The last half-coset point's y is not necessarily used (a single-point
    // half coset only happens for fold_step 1).
    if (coset_points.len > 1) try simd.markPartlyUsed(V, ctx, coset_points[coset_points.len - 1].y);
    const x_coords = try ctx.scratch().alloc(Simd, coset_points.len);
    for (x_coords, coset_points) |*x, point| x.* = point.x;
    const folds = try ctx.scratch().alloc([]const Simd, fold_step);
    try computeXTwiddles(V, ctx, x_coords, folds);
    return folds;
}

/// `circle_translate_to_base_point`: the circle bit negates `y`, the rest
/// are line bits.
fn circleTranslateToBasePoint(comptime V: type, ctx: *Context(V), point: Point(Simd), packed_bits: []const Simd) Error!Point(Simd) {
    const minus_y = try select_queries.negSimd(V, ctx, point.y);
    const selected: Point(Simd) = .{ .x = point.x, .y = try simd.select(V, ctx, packed_bits[0], point.y, minus_y) };
    return translateToBasePoint(V, ctx, selected, packed_bits[1..]);
}

/// `translate_to_base_point`: subtracts the generator of the subgroup of
/// size `2^(i+1)` from every lane whose bit `i` is set.
fn translateToBasePoint(comptime V: type, ctx: *Context(V), point: Point(Simd), packed_bits: []const Simd) Error!Point(Simd) {
    var base = point;
    for (packed_bits, 0..) |bit, i| {
        const generator = try circle.generatorPointSimd(V, ctx, i + 1, base.x.len);
        const point_if_bit = try circle.subPointsSimd(V, ctx, base, generator);
        base = .{
            .x = try simd.select(V, ctx, bit, base.x, point_if_bit.x),
            .y = try simd.select(V, ctx, bit, base.y, point_if_bit.y),
        };
    }
    return base;
}
