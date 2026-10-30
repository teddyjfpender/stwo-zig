//! Capture-free v7 native composition compiler. Uses the original native,
//! partitioned projection and packed-access equations, with no legacy seal.
const std = @import("std");
const core = @import("stwo_core");
const G = @import("composition_graph_recorder.zig");
const S = G.Scalar;
const Q = core.fields.qm31.QM31;
const Profile = @import("../block_v7_native_fixed_profile_v1.zig");
const K = @import("block_v6_partitioned_composition_v1.zig");
const U = @import("universal_challenges.zig");
const Source = @import("blake3_execution_composition.zig").Source;
pub const RELATION_COUNT = 53;
pub const Compiled = struct {
    allocator: std.mem.Allocator,
    circuit: G.Circuit,
    sources: []Source,
    profile_id: [32]u8,
    seal: [32]u8,
    pub fn identity(self: *const Compiled) [32]u8 {
        var ch = core.proof_suites.Blake3.Channel{};
        ch.mixU32s(&.{ 0x42374e43, 1, RELATION_COUNT });
        ch.mixRoot(self.profile_id);
        ch.mixRoot(self.circuit.identity_digest);
        for (self.sources) |source| ch.mixU32s(&.{ @intFromEnum(std.meta.activeTag(source)), switch (source) {
            .sample, .claim, .challenge, .public_input, .packed_public_input => |index| index,
            .composition, .oods => 0,
        } });
        return ch.digestBytes();
    }
    pub fn validateAgainst(self: *const Compiled, profile: *const Profile.Owned) !void {
        try self.circuit.validate();
        if (self.sources.len != self.circuit.input_count or !std.meta.eql(self.profile_id, profile.seal) or !std.meta.eql(self.seal, self.identity())) return error.MutatedNativeComposition;
        var expected = try compile(self.allocator, profile);
        defer expected.deinit();
        if (!std.meta.eql(self.seal, expected.seal)) return error.UntrustedNativeComposition;
    }
    pub fn deinit(self: *Compiled) void {
        self.circuit.deinit();
        self.allocator.free(self.sources);
        self.* = undefined;
    }
};
const Samples = struct {
    offsets: [5][]usize,
    lengths: [5][]usize,
    values: []S,
    trees: usize,
    pub fn at(self: @This(), tree: usize, col: usize, sample: usize) !S {
        if (tree >= self.trees or col >= self.offsets[tree].len or sample >= self.lengths[tree][col]) return error.InvalidNativeCompositionSamples;
        return self.values[self.offsets[tree][col] + sample];
    }
};
pub fn compile(a: std.mem.Allocator, profile: *const Profile.Owned) !Compiled {
    try profile.validate();
    if (U.RELATION_COUNT != 47 or profile.trace_count < 3 or profile.trace_count > 4) return error.InvalidNativeCompositionShape;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const temp = arena.allocator();
    var b = G.Builder.init(a);
    defer b.deinit();
    var sources: std.ArrayList(Source) = .empty;
    defer sources.deinit(a);
    var samples = Samples{ .offsets = undefined, .lengths = undefined, .values = try temp.alloc(S, try profile.sampleCount()), .trees = profile.trace_count + 1 };
    var cursor: usize = 0;
    var column: usize = 0;
    for (profile.shape.columns, 0..) |logs, tree| {
        samples.offsets[tree] = try temp.alloc(usize, logs.len);
        samples.lengths[tree] = try temp.alloc(usize, logs.len);
        for (samples.offsets[tree], samples.lengths[tree]) |*offset, *len| {
            offset.* = cursor;
            len.* = profile.shape.layouts[column].sampleCount();
            for (0..len.*) |_| {
                samples.values[cursor] = try input(&b, a, &sources, .{ .sample = @intCast(cursor) });
                cursor += 1;
            }
            column += 1;
        }
    }
    if (cursor != samples.values.len or column != profile.shape.layouts.len) return error.InvalidNativeCompositionSamples;
    var draws: [U.RELATION_COUNT][2]S = undefined;
    var word: [10]S = undefined;
    // All 53 epoch pairs occupy ports. The interval pair is deliberately unused
    // by these native equations, but shares the exact whole-roster schedule.
    for (0..2 * RELATION_COUNT) |i| {
        const symbol = try input(&b, a, &sources, .{ .challenge = @intCast(i) });
        if (i < 2 * U.RELATION_COUNT) draws[i / 2][i % 2] = symbol else if (i < 2 * U.RELATION_COUNT + 10) word[i - 2 * U.RELATION_COUNT] = symbol;
    }
    const public = try temp.alloc(S, try K.publicCount(profile.projections.len, profile.slots.len));
    for (public, 0..) |*value, i| value.* = try input(&b, a, &sources, .{ .public_input = @intCast(i) });
    const random = try input(&b, a, &sources, .composition);
    const seed = try input(&b, a, &sources, .oods);
    try b.activate();
    defer if (b.active) b.deactivate();
    const point = G.pointFromSeed(seed);
    var accumulated = S.zero();
    const count = K.recordEquations(profile.context(), samples, public, draws, word, random, point, profile.shape.mask_log, &accumulated) catch |err| return b.failure orelse err;
    if (b.failure) |err| return err;
    if (count != profile.constraint_count) return error.InvalidNativeCompositionConstraintCount;
    const chunks = try temp.alloc(S, core.verifier_types.compositionChunkCount(profile.shape.split) orelse return error.InvalidNativeCompositionShape);
    for (chunks, 0..) |*chunk, i| chunk.* = G.fromPartialEvals(.{ try samples.at(profile.trace_count, 4 * i, 0), try samples.at(profile.trace_count, 4 * i + 1, 0), try samples.at(profile.trace_count, 4 * i + 2, 0), try samples.at(profile.trace_count, 4 * i + 3, 0) });
    try b.constrainZero((try G.reconstructSplitComposition(chunks, point, profile.shape.composition_log, profile.shape.split)).sub(accumulated));
    b.deactivate();
    var circuit = try b.finish();
    errdefer circuit.deinit();
    const owned = try sources.toOwnedSlice(a);
    var result = Compiled{ .allocator = a, .circuit = circuit, .sources = owned, .profile_id = profile.seal, .seal = undefined };
    result.seal = result.identity();
    return result;
}
pub fn publicInputs(a: std.mem.Allocator, profile: *const Profile.Owned, claims: []const @import("../../prover/block_v5_native_projection_fused_proof_v2.zig").Claim, memory: []const @import("../../prover/block_v5_opcode_memory_sidecar_proof_v1.zig").Claim) ![]Q {
    return publicInputsForSource(a, profile.pin, profile.projections, profile.slots, claims, memory);
}
pub fn publicInputsForSource(a: std.mem.Allocator, pin: @import("../../prover/block_v7_native_source_v1.zig").Pin, projections: []const @import("../../prover/block_v5_native_projection_fused_source_v1.zig").Slot, slots: []const @import("../../prover/block_v5_opcode_memory_sidecar_proof_v1.zig").Slot, claims: []const @import("../../prover/block_v5_native_projection_fused_proof_v2.zig").Claim, memory: []const @import("../../prover/block_v5_opcode_memory_sidecar_proof_v1.zig").Claim) ![]Q {
    if (claims.len != projections.len or memory.len != slots.len) return error.InvalidNativeCompositionClaims;
    const result = try a.alloc(Q, try K.publicCount(claims.len, memory.len));
    errdefer a.free(result);
    @memcpy(result[0..8], &@import("../../prover/block_execution_integer_algebra_v1.zig").clockBytes(Q, try @import("../../prover/block_execution_integer_bridge_v2.zig").baseClockFromPublicFrame(pin.frame)));
    for (claims, projections, result[8..][0..claims.len]) |claim, slot, *out| {
        if (claim.row_count != slot.n_rows) return error.InvalidNativeCompositionClaims;
        out.* = claim.sum;
    }
    var index: usize = 8 + claims.len;
    for (memory, slots) |claim, slot| {
        if (claim.active_count > (@as(u64, 1) << @intCast(slot.log_size))) return error.InvalidNativeCompositionClaims;
        result[index] = claim.transition_sum;
        result[index + 1] = claim.universal_sum;
        result[index + 2] = Q.fromBase(core.fields.m31.M31.fromU64(claim.active_count));
        @memcpy(result[index + 3 ..][0..7], &claim.range_claims);
        index += K.ACCESS_INPUTS;
    }
    return result;
}
fn input(b: *G.Builder, a: std.mem.Allocator, sources: *std.ArrayList(Source), source: Source) !S {
    const result = try b.input();
    try sources.append(a, source);
    return result.value;
}
