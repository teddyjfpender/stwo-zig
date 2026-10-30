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
const Profile = @import("../block_v8_compact_ram_profile_v1.zig");
const Original = @import("../../prover/block_v8_compact_ram_proof_v1.zig");
const B = @import("../../prover/block_v8_compact_ram_component_v1.zig");
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
    const values = try a.alloc(Q, 10);
    @memcpy(values[0..6], &p.claims.ram);
    @memcpy(values[6..8], &p.claims.boundary);
    @memcpy(values[8..10], &p.claims.ranges);
    return values;
}
fn relation(comptime n: usize, pair: [2]S) R.Relation(F, n) {
    var out: R.Relation(F, n) = .{ .z = .{ .symbol = pair[0] }, .powers = undefined };
    var power = F.one();
    for (&out.powers) |*v| {
        v.* = power;
        power = power.mul(.{ .symbol = pair[1] });
    }
    return out;
}
fn row(comptime n: usize, samples: Samples, tree: usize, start: usize, offset: usize) ![n]F {
    var out: [n]F = undefined;
    for (&out, 0..) |*v, i| v.* = .{ .symbol = try samples.at(tree, start + i, offset) };
    return out;
}
fn previousRam(samples: Samples) ![12]F {
    var out: [12]F = undefined;
    for (&out, 0..) |*v, i| v.* = if (B.Spec.PREVIOUS_MAIN_MASK[i]) .{ .symbol = try samples.at(1, i, 1) } else F.zero();
    return out;
}
fn norms(comptime n: usize, public: []S, start: usize, log: u32) [n]F {
    var out: [n]F = undefined;
    for (&out, 0..) |*v, i| v.* = .{ .symbol = public[start + i].mul(S.fromBase((M.fromCanonical(@as(u32, 1) << @intCast(log)).inv() catch unreachable))) };
    return out;
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
    const public = try t.alloc(S, 10);
    for (public, 0..) |*value, index| value.* = try input(&builder, a, &sources, .{ .public_input = @intCast(index) });
    const random = try input(&builder, a, &sources, .composition);
    const seed = try input(&builder, a, &sources, .oods);
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    const memory: R.Challenges(F) = .{ .transition = relation(11, draws[47]), .link = relation(13, draws[48]), .interval = relation(6, draws[52]), .range16 = relation(1, draws[51]) };
    const boundary = relation(5, draws[49]);
    const ram_ch: B.Challenges(F) = .{ .transition = memory.transition, .boundary = boundary, .range16 = memory.range16 };
    var cache: G.DenominatorCache = @splat(null);
    var accumulated = S.zero();
    const ram = B.equations(F, ram_ch, try row(3, samples, 0, 0, 0), try row(12, samples, 1, 0, 0), try previousRam(samples), try row(24, samples, 4, 0, 0), try row(24, samples, 4, 0, 1), norms(6, public, 0, p.scope.ramLog()));
    const bounds = B.BoundarySpec.equationsFor(F, boundary, try row(8, samples, 0, 3, 0), try row(1, samples, 2, 0, 0), try row(8, samples, 5, 0, 0), try row(8, samples, 5, 0, 1), norms(2, public, 6, p.scope.boundaryLog()));
    const ranges = @import("../../prover/block_v7_provider_component_v1.zig").For(.range16).equations(F, try row(2, samples, 0, 11, 0), try row(1, samples, 3, 0, 0), try row(8, samples, 6, 0, 0), try row(8, samples, 6, 0, 1), memory, norms(2, public, 8, 16));
    inline for (.{ ram, bounds, ranges }, .{ p.scope.ramLog(), p.scope.boundaryLog(), @as(u32, 16) }) |equations, log| {
        const denominator = try G.quotientDenominator(log, p.shape.mask_log, G.pointFromSeed(seed), &cache);
        for (equations) |value| G.accumulate(&accumulated, random, value.symbol, denominator);
    }
    const chunks = try t.alloc(S, core.verifier_types.compositionChunkCount(p.shape.split) orelse return error.InvalidBridgeRecursiveComposition);
    for (chunks, 0..) |*chunk, index| {
        var limbs: [4]S = undefined;
        for (&limbs, 0..) |*limb, half| limb.* = try samples.at(7, 4 * index + half, 0);
        chunk.* = G.fromPartialEvals(limbs);
    }
    try builder.constrainZero((try G.reconstructSplitComposition(chunks, G.pointFromSeed(seed), p.shape.composition_log, p.shape.split)).sub(accumulated));
    try builder.constrainZero(public[1].add(public[6]));
    try builder.constrainZero(public[2].add(public[7]));
    try builder.constrainZero(public[3].add(public[4]).add(public[8]));
    try builder.constrainZero(public[5].sub(public[9]));
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
    const draws = try @import("block_v7_memory_joint_inputs_mode_v1.zig").ForMode(true).challenges(t, p.statement.input.epoch);
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
