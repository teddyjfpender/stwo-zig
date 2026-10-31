//! The in-circuit native STARK verifier: port of `verifyImpl` in
//! `core/verifier.zig` (lines 165-304) and `verifyValuesImpl` in
//! `core/pcs/verifier.zig` (lines 238-424) for the `stwo_7b211ed` revision,
//! with the statement-specific parts delegated to a duck-typed `statement`.
//!
//! Transcript, in the native order:
//! 1. `statement.mixPublic` (every public word, the `PcsConfig` felt
//!    included, as the native caller mixes them before committing);
//! 2. the roots of the first `statement.nTreesBeforeChallenges()` trees
//!    (`CommitmentSchemeVerifier.commit` = `mixRoot`);
//! 3. `statement.drawChallenges` (lookup elements), `statement.mixClaims`
//!    (claimed sums and the like), then the roots of the remaining trees
//!    but the composition one;
//! 4. `composition_randomness = drawSecureFelt`, the composition root,
//!    `oods_seed = drawSecureFelt`, `oods_point =
//!    secureFieldPointFromRandomSeed(seed)`;
//! 5. `statement.evalComposition` at the OODS point must equal
//!    `reconstructCompositionChunkEvals` of the composition samples;
//! 6. `mixFelts(all sampled values)`, `deep_randomness = drawSecureFelt`;
//! 7. FRI commit, proof of work (`verifyPowNonce` then `mixU64`), the
//!    query draw (`drawQueries` over the lifting domain);
//! 8. Merkle decommitments, the DEEP quotients, FRI decommitment.
//!
//! The statement is a comptime duck type over `Context(V)`:
//!
//! | member | native counterpart |
//! |---|---|
//! | `pub const Challenges = ...;` | the lookup elements' type |
//! | `mixPublic(ctx, *NativeChannel) !void` | the caller's public mixing |
//! | `nTreesBeforeChallenges() usize` | trees committed before the draws |
//! | `drawChallenges(ctx, *NativeChannel) !Challenges` | `channel.drawSecureFelt(s)` |
//! | `mixClaims(ctx, *NativeChannel) !void` | the claim mixing |
//! | `evalComposition(ctx, Point(Var), []const []const []const Var, Var, Challenges) !Var` | `evalCompositionPolynomialAtPoint` |

const std = @import("std");
const core = @import("stwo_core");
const builder = @import("../builder/mod.zig");
const sv_circle = @import("../stark_verifier/circle.zig");
const channel_mod = @import("channel.zig");
const deep = @import("deep.zig");
const fri = @import("fri.zig");
const merkle = @import("merkle.zig");
const proof_mod = @import("proof.zig");
const shape_mod = @import("shape.zig");

const QM31 = core.fields.qm31.QM31;
const Var = builder.Var;
const Context = builder.Context;
const Error = builder.context.Error;
const ops = builder.ops;
const Point = sv_circle.Point;
const NativeChannel = channel_mod.NativeChannel;
const Shape = shape_mod.Shape;

pub const VerifyError = Error || shape_mod.ShapeError || proof_mod.ConvertError || merkle.DecommitError || fri.FriError || deep.DeepError;

/// The statement type behind a `statement` argument (a value or a pointer).
pub fn StatementType(comptime S: type) type {
    return switch (@typeInfo(S)) {
        .pointer => |pointer| pointer.child,
        else => S,
    };
}

/// What `verify` hands back: the transcript values a caller may bind
/// further, and the final channel (its digest is the parity signal).
pub fn Verified(comptime Challenges: type) type {
    return struct {
        /// What `statement.drawChallenges` returned.
        challenges: Challenges,
        composition_randomness: Var,
        oods_point: Point(Var),
        deep_randomness: Var,
        /// One folding alpha per FRI layer, first layer first.
        fri_alphas: []const Var,
        /// The query bits and lifting-domain points.
        queries: fri.Queries,
        /// The DEEP quotient at every query (the FRI first-layer values).
        fri_input: []const Var,
        /// The channel after the query draw; `debugDigest` must equal the
        /// native verifier's final digest.
        channel: NativeChannel,
    };
}

/// Constrains `proof` (guessed wires) to be a valid native proof of
/// `statement` under `shape`.
pub fn verify(
    comptime V: type,
    ctx: *Context(V),
    shape: *const Shape,
    proof: *const proof_mod.Proof(Var),
    statement: anytype,
) VerifyError!Verified(StatementType(@TypeOf(statement)).Challenges) {
    try shape.validate();
    try proof.validateStructure(shape);
    const n_trees = shape.nTrees();
    const composition_tree = shape.compositionTree();
    var channel = try NativeChannel.init(V, ctx);

    try statement.mixPublic(ctx, &channel);
    const n_before = statement.nTreesBeforeChallenges();
    if (n_before == 0 or n_before >= n_trees) return error.InvalidTrees;
    for (proof.commitments[0..n_before]) |root| try channel.mixRoot(V, ctx, root);
    const challenges = try statement.drawChallenges(ctx, &channel);
    try statement.mixClaims(ctx, &channel);
    for (proof.commitments[n_before..composition_tree]) |root| try channel.mixRoot(V, ctx, root);

    const composition_randomness = try channel.drawSecureFelt(V, ctx);
    try channel.mixRoot(V, ctx, proof.commitments[composition_tree]);
    const oods_seed = try channel.drawSecureFelt(V, ctx);
    const oods_point = try pointFromSeed(V, ctx, oods_seed);

    const composition = try statement.evalComposition(ctx, oods_point, proof.sampled_values, composition_randomness, challenges);
    const expected = try reconstructComposition(V, ctx, proof.sampled_values[composition_tree], oods_point, shape.global_log, shape.composition_log_split);
    try ctx.eq(composition, expected);

    try channel.mixFelts(V, ctx, try proof_mod.flattenSampledValues(ctx.scratch(), proof.sampled_values));
    const deep_randomness = try channel.drawSecureFelt(V, ctx);

    const alphas = try fri.friCommit(V, ctx, &channel, &proof.fri);
    try channel.pow(V, ctx, shape.pcs.pow_bits, proof.pow_nonce);
    const lifting_log = shape.liftingLogSize();
    const drawn = try channel.drawQueryBits(V, ctx, lifting_log, shape.nQueries());
    const queries = try fri.queriesFromBits(V, ctx, drawn, lifting_log);

    const log_sizes = try ctx.scratch().alloc([]const u32, n_trees);
    for (log_sizes, 0..) |*tree_logs, tree| tree_logs.* = try shape.extendedLogSizes(ctx.scratch(), tree);
    try merkle.decommitTrees(V, ctx, log_sizes, lifting_log, proof.queried_values, proof.auth_paths, queries.unpacked, proof.commitments);

    const plan = try shape_mod.SamplePlan.init(ctx.scratch(), shape);
    const fri_input = try deep.friInput(V, ctx, &plan, oods_point, proof.sampled_values, deep_randomness, queries.points, proof.queried_values);
    try fri.friDecommit(V, ctx, &proof.fri, lifting_log, shape.pcs.fri_config, fri_input, queries, alphas);

    return .{
        .challenges = challenges,
        .composition_randomness = composition_randomness,
        .oods_point = oods_point,
        .deep_randomness = deep_randomness,
        .fri_alphas = alphas,
        .queries = queries,
        .fri_input = fri_input,
        .channel = channel,
    };
}

/// `secureFieldPointFromRandomSeed`: `((1 - t^2) / (1 + t^2), 2t / (1 + t^2))`.
pub fn pointFromSeed(comptime V: type, ctx: *Context(V), t: Var) Error!Point(Var) {
    const one = try ctx.constant(QM31.one());
    const t2 = try ctx.mul(t, t);
    const denominator_inv = try ctx.inv(try ctx.add(t2, one));
    const x = try ctx.mul(try ctx.sub(one, t2), denominator_inv);
    const two_t = try ctx.add(t, t);
    const y = try ctx.mul(two_t, denominator_inv);
    return .{ .x = x, .y = y };
}

/// `extractCompositionOodsEvalWithSplit` / `reconstructCompositionChunkEvals`:
/// chunk `k` is `fromPartialEvals` of columns `4k..4k+4` (one sample each);
/// pairs combine as `even + pi^(parent_log - 2)(oods.x) * odd` with
/// `parent_log` from `global_log + 1` upwards.
pub fn reconstructComposition(
    comptime V: type,
    ctx: *Context(V),
    composition_samples: []const []const Var,
    oods_point: Point(Var),
    global_log: u32,
    split: u32,
) VerifyError!Var {
    const chunk_count = @as(usize, 1) << @intCast(split);
    if (composition_samples.len != 4 * chunk_count) return error.InvalidCompositionTree;
    const chunks = try ctx.scratch().alloc(Var, chunk_count);
    for (chunks, 0..) |*chunk, k| {
        var coordinates: [4]Var = undefined;
        for (&coordinates, composition_samples[4 * k ..][0..4]) |*coordinate, column| {
            if (column.len != 1) return error.InvalidCompositionTree;
            coordinate.* = column[0];
        }
        chunk.* = try ops.fromPartialEvals(V, ctx, coordinates);
    }
    var factor = oods_point.x;
    for (0..global_log - 1) |_| factor = try sv_circle.doubleX(V, ctx, factor);
    var active = chunk_count;
    while (active > 1) {
        for (0..active / 2) |out| {
            chunks[out] = try ctx.add(chunks[2 * out], try ctx.mul(factor, chunks[2 * out + 1]));
        }
        active /= 2;
        if (active > 1) factor = try sv_circle.doubleX(V, ctx, factor);
    }
    return chunks[0];
}

test "verify: the OODS point map matches secureFieldPointFromRandomSeed" {
    var ctx = try Context(QM31).init(std.testing.allocator, 0);
    defer ctx.deinit();
    const seed = QM31.fromU32Unchecked(1_234_567, 89, 1011, 1213);
    const point = try pointFromSeed(QM31, &ctx, try ctx.guess(seed));
    const expected = core.circle.secureFieldPointFromRandomSeed(seed);
    try std.testing.expect(ctx.get(point.x).eql(expected.x));
    try std.testing.expect(ctx.get(point.y).eql(expected.y));
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
}

test "verify: statement types resolve through pointers and the reconstruction rejects bad shapes" {
    const Dummy = struct {
        pub const Challenges = struct { z: Var };
    };
    try std.testing.expect(StatementType(Dummy) == Dummy);
    try std.testing.expect(StatementType(*const Dummy) == Dummy);
    try std.testing.expect(StatementType(Dummy).Challenges == Dummy.Challenges);

    var ctx = try Context(QM31).init(std.testing.allocator, 0);
    defer ctx.deinit();
    const point: Point(Var) = .{ .x = ctx.one(), .y = ctx.zero() };
    const sample = [_]Var{ctx.one()};
    const two_samples = [_]Var{ ctx.one(), ctx.one() };
    const seven = [_][]const Var{&sample} ** 7;
    try std.testing.expectError(error.InvalidCompositionTree, reconstructComposition(QM31, &ctx, &seven, point, 4, 1));
    const bad_column = [_][]const Var{&sample} ** 7 ++ [_][]const Var{&two_samples};
    try std.testing.expectError(error.InvalidCompositionTree, reconstructComposition(QM31, &ctx, &bad_column, point, 4, 1));
}

test "verify: composition reconstruction matches reconstructCompositionChunkEvals" {
    var ctx = try Context(QM31).init(std.testing.allocator, 0);
    defer ctx.deinit();
    const oods = core.circle.SECURE_FIELD_CIRCLE_GEN.mul(1_000_003);
    const point: Point(Var) = .{ .x = try ctx.guess(oods.x), .y = try ctx.guess(oods.y) };
    for ([_]u32{ 1, 2 }) |split| {
        const n_columns = @as(usize, 4) << @intCast(split);
        const columns = try ctx.scratch().alloc([]const Var, n_columns);
        var chunk_evals: [4]QM31 = undefined;
        for (columns, 0..) |*column, c| {
            const value = QM31.fromU32Unchecked(@intCast(c + 1), @intCast(3 * c), 7, @intCast(c * c));
            const wire = try ctx.scratch().alloc(Var, 1);
            wire[0] = try ctx.guess(value);
            column.* = wire;
            if (c % 4 == 0) chunk_evals[c / 4] = value;
            if (c % 4 == 1) chunk_evals[c / 4] = chunk_evals[c / 4].add(value.mul(QM31.fromU32Unchecked(0, 1, 0, 0)));
            if (c % 4 == 2) chunk_evals[c / 4] = chunk_evals[c / 4].add(value.mul(QM31.fromU32Unchecked(0, 0, 1, 0)));
            if (c % 4 == 3) chunk_evals[c / 4] = chunk_evals[c / 4].add(value.mul(QM31.fromU32Unchecked(0, 0, 0, 1)));
        }
        const global_log: u32 = 6;
        const expected = core.proof.reconstructCompositionChunkEvals(chunk_evals[0 .. @as(usize, 1) << @intCast(split)], oods, global_log + split, split).?;
        const actual = try reconstructComposition(QM31, &ctx, columns, point, global_log, split);
        try std.testing.expect(ctx.get(actual).eql(expected));
    }
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
}
