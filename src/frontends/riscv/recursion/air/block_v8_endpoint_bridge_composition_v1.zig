//! Exact original conditional bridge equations plus an algebraic aggregate
//! export over the same authenticated physical claim ports.
const std = @import("std");
const core = @import("stwo_core");
const G = @import("composition_graph_recorder.zig");
const S = G.Scalar;
const F = @import("block_v5_ram_lanes_composition_v1.zig").Field;
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Source = @import("blake3_execution_composition.zig").Source;
const Profile = @import("../block_v8_endpoint_bridge_profile_v1.zig");
const Original = @import("../../prover/block_v8_endpoint_global_bridge_proof_v1.zig");
const B = @import("../../prover/block_v8_endpoint_global_bridge_component_v1.zig");
const R = @import("../../prover/block_v7_memory_relations_v1.zig");
const Samples = @import("component_sample_graph_v1.zig").Samples;
const input = @import("component_sample_graph_v1.zig").input;
pub const Compiled = struct {
    allocator: std.mem.Allocator,
    circuit: G.Circuit,
    sources: []Source,
    pub fn deinit(self: *Compiled) void {
        self.circuit.deinit();
        self.allocator.free(self.sources);
        self.* = undefined;
    }
};
pub fn publicValues(a: std.mem.Allocator, p: *const Profile.Owned) ![]Q {
    const values = try a.alloc(Q, p.claims.len + 1);
    @memcpy(values[0..p.claims.len], p.claims);
    var sum = Q.zero();
    for (p.claims) |claim| sum = sum.add(claim);
    values[p.claims.len] = sum;
    return values;
}
pub fn compile(a: std.mem.Allocator, p: *const Profile.Owned) !Compiled {
    try p.validate();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const t = arena.allocator();
    var builder = G.Builder.init(a);
    defer builder.deinit();
    var sources: std.ArrayList(Source) = .empty;
    defer sources.deinit(a);
    var sample_sources: std.ArrayList(Source) = .empty;
    const samples = try Samples.init(t, &builder, &sample_sources, &p.shape);
    try sources.appendSlice(a, sample_sources.items);
    var draws: [53][2]S = undefined;
    for (&draws, 0..) |*pair, index| for (pair, 0..) |*value, half| {
        value.* = try input(&builder, a, &sources, .{ .challenge = @intCast(2 * index + half) });
    };
    const public = try t.alloc(S, p.claims.len + 1);
    for (public, 0..) |*value, index| value.* = try input(&builder, a, &sources, .{ .public_input = @intCast(index) });
    const random = try input(&builder, a, &sources, .composition);
    const seed = try input(&builder, a, &sources, .oods);
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    var relation = R.Relation(F, 11){ .z = .{ .symbol = draws[47][0] }, .powers = undefined };
    var power = F.one();
    for (&relation.powers) |*value| {
        value.* = power;
        power = power.mul(.{ .symbol = draws[47][1] });
    }
    var cache: G.DenominatorCache = @splat(null);
    var accumulated = S.zero();
    var aggregate = S.zero();
    const n = p.scope.sources.len;
    for (p.scope.sources, 0..) |source, index| {
        const log = try source.log();
        var row: [B.Spec.MAIN_COUNT]F = undefined;
        var current: [4]F = undefined;
        var previous: [4]F = undefined;
        for (&row, 0..) |*value, column| value.* = .{ .symbol = try samples.at(1 + index, column, 0) };
        for (&current, &previous, 0..) |*value, *before, column| {
            value.* = .{ .symbol = try samples.at(1 + n + index, column, 0) };
            before.* = .{ .symbol = try samples.at(1 + n + index, column, 1) };
        }
        const normalized = F{ .symbol = public[index].mul(S.fromBase(try M.fromCanonical(@as(u32, 1) << @intCast(log)).inv())) };
        const equations = B.equations(F, source.policy, relation, .{ .symbol = try samples.at(0, index, 0) }, row, current, previous, .{normalized});
        const denominator = try G.quotientDenominator(log, p.shape.mask_log, G.pointFromSeed(seed), &cache);
        for (equations) |value| G.accumulate(&accumulated, random, value.symbol, denominator);
        aggregate = aggregate.add(public[index]);
    }
    const chunks = try t.alloc(S, core.verifier_types.compositionChunkCount(p.shape.split) orelse return error.InvalidBridgeRecursiveComposition);
    for (chunks, 0..) |*chunk, index| {
        var limbs: [4]S = undefined;
        for (&limbs, 0..) |*limb, half| limb.* = try samples.at(p.scope.traceTrees(), 4 * index + half, 0);
        chunk.* = G.fromPartialEvals(limbs);
    }
    try builder.constrainZero((try G.reconstructSplitComposition(chunks, G.pointFromSeed(seed), p.shape.composition_log, p.shape.split)).sub(accumulated));
    try builder.constrainZero(public[n].sub(aggregate));
    builder.deactivate();
    var circuit = try builder.finish();
    errdefer circuit.deinit();
    return .{ .allocator = a, .circuit = circuit, .sources = try sources.toOwnedSlice(a) };
}
pub fn prepare(a: std.mem.Allocator, p: *const Profile.Owned, capture: *const Original.VerifiedCapture) !@import("blake3_execution_composition.zig").Prepared {
    try p.requireCapture(capture);
    var compiled = try compile(a, p);
    var owns = true;
    defer if (owns) compiled.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const t = arena.allocator();
    const public = try publicValues(t, p);
    const draws = try @import("block_v7_memory_joint_inputs_mode_v1.zig").ForMode(true).challenges(t, p.scope.epoch);
    const inputs = try t.alloc(Q, compiled.sources.len);
    for (inputs, compiled.sources) |*value, source| value.* = switch (source) {
        .sample => |i| capture.proof.sampled_values[i],
        .public_input => |i| public[i],
        .challenge => |i| draws[i],
        .composition => capture.proof.composition_randomness,
        .oods => capture.proof.oods_seed,
        else => return error.InvalidBridgeRecursiveComposition,
    };
    const values = try t.alloc(Q, compiled.circuit.nodes.len);
    try compiled.circuit.evaluateInto(inputs, values);
    const sources = try t.dupe(Source, compiled.sources);
    var result = @import("blake3_execution_composition.zig").Prepared{ .arena = arena, .circuit = compiled.circuit, .inputs = inputs, .sources = sources, .values = values, .key_id = p.seal, .capture_seal = capture.final_channel.digestBytes(), .seal = undefined };
    result.seal = result.identity();
    a.free(compiled.sources);
    owns = false;
    return result;
}
