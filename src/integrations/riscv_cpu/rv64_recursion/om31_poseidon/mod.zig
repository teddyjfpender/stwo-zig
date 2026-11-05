//! Explicit P2v2 native PCS/FRI query circuit. Caller admits statement,
//! source-owned shape and application authority, then binds common.begin().
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
pub const common = @import("common.zig");
pub const shape = @import("../om31_native/shape.zig");
pub const proof = @import("proof.zig");
pub const fri = @import("fri.zig");
pub const deep = @import("../om31_native/deep.zig");
const merkle = @import("merkle.zig");
pub const Shape = shape.Shape;
pub const Captured = proof.Captured;
pub const Proof = proof.Proof;
pub const Channel = common.Channel;
pub const F = common.F;
pub const Point = common.Point;
const Q = common.Q;
pub const Verified = struct {
    composition_randomness: F,
    oods_point: Point,
    deep_randomness: F,
    fri_alphas: []const F,
    queries: fri.Queries,
    fri_input: []const F,
    channel: Channel,
};
pub fn pointFromSeed(t: F) Point {
    const square = t.square();
    const inverse = F.one().add(square).inv();
    return .{ .x = F.one().sub(square).mul(inverse), .y = t.double().mul(inverse) };
}
pub fn reconstructComposition(ctx: *common.Context, samples: []const []const F, point: Point, log: u32, split: u32) !F {
    const count = @as(usize, 1) << @intCast(split);
    if (samples.len != 8 * count or log == 0) return error.InvalidCompositionTree;
    const chunks = try ctx.scratch().alloc(F, count);
    for (chunks, 0..) |*chunk, k| {
        var coordinates: [8]F = undefined;
        for (&coordinates, samples[8 * k ..][0..8]) |*out, column| {
            if (column.len != 1) return error.InvalidCompositionTree;
            out.* = column[0];
        }
        chunk.* = F.fromPartialEvals(coordinates);
    }
    var factor = point.x;
    for (0..log - 1) |_| factor = common.doubleX(factor);
    var active = count;
    while (active > 1) {
        for (0..active / 2) |i| chunks[i] = chunks[2 * i].add(factor.mul(chunks[2 * i + 1]));
        active /= 2;
        if (active > 1) factor = common.doubleX(factor);
    }
    try common.lane.check();
    return chunks[0];
}
/// Statement methods are the legacy native verifier contract over OM31 wires:
/// mixPublic(ctx,channel), nTreesBeforeChallenges(), drawChallenges(ctx,channel),
/// mixClaims(ctx,channel), evalComposition(ctx,point,masks,randomness,challenges).
/// Topology/shape and public authority must be independently admitted by caller.
pub fn verify(ctx: *common.Context, geometry: *const Shape, witness: *const Proof, statement: anytype) !Verified {
    try witness.validate(geometry);
    var channel = try Channel.init(ctx);
    try statement.mixPublic(ctx, &channel);
    const before = statement.nTreesBeforeChallenges();
    const composition_tree = geometry.compositionTree();
    if (before == 0 or before >= geometry.nTrees()) return error.InvalidTrees;
    for (witness.commitments[0..before]) |root| try channel.mixRoot(ctx, root);
    const challenges = try statement.drawChallenges(ctx, &channel);
    try statement.mixClaims(ctx, &channel);
    for (witness.commitments[before..composition_tree]) |root| try channel.mixRoot(ctx, root);
    const randomness = try channel.draw(ctx);
    try channel.mixRoot(ctx, witness.commitments[composition_tree]);
    const point = pointFromSeed(try channel.draw(ctx));
    const actual = try statement.evalComposition(ctx, point, witness.sampled_values, randomness, challenges);
    try common.eq(ctx, actual, try reconstructComposition(ctx, witness.sampled_values[composition_tree], point, geometry.global_log, geometry.composition_log_split));
    var count: usize = 0;
    for (witness.sampled_values) |tree| for (tree) |column| {
        count = try std.math.add(usize, count, column.len);
    };
    const sampled = try ctx.scratch().alloc(F, count);
    var at: usize = 0;
    for (witness.sampled_values) |tree| for (tree) |column| {
        @memcpy(sampled[at..][0..column.len], column);
        at += column.len;
    };

    try channel.mixFelts(ctx, sampled);

    const alpha = try channel.draw(ctx);
    const alphas = try fri.commit(ctx, &channel, witness);
    try channel.raw.inner.pow(Q, ctx, geometry.pcs.pow_bits, witness.pow_nonce);
    const lifting = geometry.liftingLogSize();
    const drawn = try channel.raw.inner.drawQueryBits(Q, ctx, lifting, geometry.nQueries());
    const queries = try circuit.native_verifier.fri.queriesFromBits(Q, ctx, drawn, lifting);
    const logs = try ctx.scratch().alloc([]const u32, geometry.nTrees());
    for (logs, 0..) |*out, tree| out.* = try geometry.extendedLogSizes(ctx.scratch(), tree);
    if (witness.cap_log == 0) {
        try merkle.decommitTrees(Q, ctx, logs, lifting, witness.queried_values, witness.auth_paths, queries.unpacked, witness.commitments);
    } else {
        // M6 diet-wire Merkle cap (rv64-m6-diet-wire.md section 5).
        try merkle.decommitTreesCapped(Q, ctx, logs, lifting, witness.queried_values, witness.auth_paths, queries.unpacked, witness.commitments, witness.caps, witness.cap_log);
    }
    const plan = try shape.SamplePlan.init(ctx.scratch(), geometry);
    const input = try deep.friInput(ctx, &plan, point, witness.sampled_values, alpha, queries.points, witness.queried_values);
    try fri.decommit(ctx, witness, lifting, geometry.pcs.fri_config, input, queries, alphas);
    try common.lane.check();
    return .{ .composition_randomness = randomness, .oods_point = point, .deep_randomness = alpha, .fri_alphas = alphas, .queries = queries, .fri_input = input, .channel = channel };
}
