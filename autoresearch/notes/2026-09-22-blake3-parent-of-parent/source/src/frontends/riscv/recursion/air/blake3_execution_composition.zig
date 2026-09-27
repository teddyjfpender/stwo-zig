//! Joined native/BLAKE3 composition and public-closure arithmetic. Constraint
//! equations come from the native evaluators and authenticated typed programs.
//! Public boundary values are specialized to the caller-admitted execution key.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const recorder = @import("composition_graph_recorder.zig");
const S = recorder.Scalar;
const native = @import("blake3_execution_composition_native.zig");
const universal = @import("universal_challenges.zig");
const Verified = @import("../../prover/blake3_execution_capture.zig").Verified;
const Airs = @import("../../prover/blake3_commitment_components.zig").Airs;
pub const Source = union(enum) { sample: u32, claim: u32, challenge: u32, composition, oods };
pub const Prepared = struct {
    arena: std.heap.ArenaAllocator,
    circuit: recorder.Circuit,
    inputs: []Q,
    sources: []Source,
    values: []Q,
    key_id: [32]u8,
    capture_seal: [32]u8,
    seal: [32]u8,
    pub fn deinit(self: *Prepared) void {
        self.circuit.deinit();
        self.arena.deinit();
        self.* = undefined;
    }
    pub fn identity(self: *const Prepared) [32]u8 {
        var channel = core.channel.blake3.Channel{};
        const protocol = @import("../../prover/blake3_execution_protocol.zig");
        channel.mixU32s(&.{ 0x42334547, 1 });
        protocol.mixDigest(&channel, self.key_id);
        protocol.mixDigest(&channel, self.capture_seal);
        protocol.mixDigest(&channel, self.circuit.identity_digest);
        for (self.sources) |source| {
            channel.mixU32s(&.{ @intFromEnum(std.meta.activeTag(source)), switch (source) {
                .sample, .claim, .challenge => |i| i,
                else => 0,
            } });
        }
        channel.mixFelts(self.inputs);
        return channel.digestBytes();
    }
    pub fn validate(self: *const Prepared, a: std.mem.Allocator, admitted: anytype, capture: anytype, expected: [32]u8) !void {
        try capture.validate(admitted, expected);
        try self.circuit.validate();
        if (!std.mem.eql(u8, &self.key_id, &expected) or !std.mem.eql(u8, &self.capture_seal, &capture.seal) or self.sources.len != self.inputs.len or !std.mem.eql(u8, &self.identity(), &self.seal)) return error.InvalidExecutionComposition;
        const replay = try a.alloc(Q, self.values.len);
        defer a.free(replay);
        try self.circuit.evaluateInto(self.inputs, replay);
        for (replay, self.values) |actual, value| if (!actual.eql(value)) return error.InvalidExecutionComposition;
    }
};
const Samples = struct {
    offsets: [4][]usize,
    lengths: [4][]usize,
    values: []const S,
    pub fn at(self: Samples, tree: usize, column: usize, sample: usize) !S {
        if (tree >= 4 or column >= self.offsets[tree].len or sample >= self.lengths[tree][column]) return error.InvalidExecutionComposition;
        return self.values[self.offsets[tree][column] + sample];
    }
    pub fn secure(self: Samples, column: usize, sample: usize) !S {
        var partials: [4]S = undefined;
        for (&partials, 0..) |*value, i| value.* = try self.at(2, column + i, sample);
        return recorder.fromPartialEvals(partials);
    }
};
pub fn prepare(a: std.mem.Allocator, admitted: anytype, capture: *const Verified, expected: [32]u8) !Prepared {
    try capture.validate(admitted, expected);
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const temp = arena.allocator();
    var builder = recorder.Builder.init(a);
    defer builder.deinit();
    var inputs: std.ArrayList(Q) = .empty;
    var sources: std.ArrayList(Source) = .empty;
    var samples = Samples{ .offsets = undefined, .lengths = undefined, .values = undefined };
    const sampled = try temp.alloc(S, capture.proof.sampled_values.len);
    for (sampled, capture.proof.sampled_values, 0..) |*symbol, value, i| symbol.* = try input(&builder, temp, &inputs, &sources, .{ .sample = @intCast(i) }, value);
    samples.values = sampled;
    if (capture.proof.sampled_points.len != 4) return error.InvalidExecutionComposition;
    var offset: usize = 0;
    for (capture.proof.sampled_points, 0..) |columns, tree| {
        samples.offsets[tree] = try temp.alloc(usize, columns.len);
        samples.lengths[tree] = try temp.alloc(usize, columns.len);
        for (columns, 0..) |points, column| {
            samples.offsets[tree][column] = offset;
            samples.lengths[tree][column] = points.len;
            offset += points.len;
        }
    }
    if (offset != sampled.len) return error.InvalidExecutionComposition;
    var claim_inputs: std.ArrayList(S) = .empty;
    const shape = &admitted.shape;
    for (shape.component_descs[0..shape.n_components], 0..) |desc, i| {
        for (try capture.native_claims.opcodeClaims(desc.family, i)) |claim| try claim_inputs.append(temp, try input(&builder, temp, &inputs, &sources, .{ .claim = @intCast(claim_inputs.items.len) }, claim));
    }
    for (shape.infra_descs[0..shape.n_infra], 0..) |desc, i| {
        for (try capture.native_claims.infraClaims(desc.kind, i)) |claim| try claim_inputs.append(temp, try input(&builder, temp, &inputs, &sources, .{ .claim = @intCast(claim_inputs.items.len) }, claim));
    }
    const native_claim_count = claim_inputs.items.len;
    for (capture.hash_claims) |claim| try claim_inputs.append(temp, try input(&builder, temp, &inputs, &sources, .{ .claim = @intCast(claim_inputs.items.len) }, claim));
    var draws: [universal.RELATION_COUNT][2]S = undefined;
    for (&draws, capture.relations.elements, 0..) |*pair, element, i| {
        pair[0] = try input(&builder, temp, &inputs, &sources, .{ .challenge = @intCast(2 * i) }, element.z);
        pair[1] = try input(&builder, temp, &inputs, &sources, .{ .challenge = @intCast(2 * i + 1) }, element.alpha);
    }
    const randomness = try input(&builder, temp, &inputs, &sources, .composition, capture.proof.composition_randomness);
    const seed = try input(&builder, temp, &inputs, &sources, .oods, capture.proof.oods_seed);
    const joined = try @import("../../prover/blake3_execution_components.zig").Owner.init(a, shape, capture.native_claims, capture.relations, admitted.admission());
    defer joined.deinit();
    const hashes = admitted.hashes.?;
    try joined.bindCommitments(hashes, capture.hash_claims);
    var components: std.ArrayList(core.air.components.Component) = .empty;
    try components.appendSlice(temp, joined.verifying.components.active());
    try components.appendSlice(temp, &(try hashes.verifiers()));
    const all = core.air.components.Components{ .components = components.items, .n_preprocessed_columns = admitted.logs[0].len };
    const composition_log = all.compositionLogDegreeBound();
    const split = try all.compositionLogSplit();
    const max_log = core.verifier_types.compositionMaskLogSize(composition_log, split) orelse return error.InvalidExecutionComposition;
    try builder.activate();
    const challenges = try recorder.ChallengeSet.init(draws);
    const point = recorder.pointFromSeed(seed);
    var cache: recorder.DenominatorCache = @splat(null);
    var accumulated = S.zero();
    var constraint_count = try native.record(shape, samples, claim_inputs.items[0..native_claim_count], &challenges, randomness, point, max_log, &cache, &accumulated);
    inline for (Airs, 0..) |Air, i| {
        const component = &hashes.typed_components[i];
        const placement = try hashes.manifest().placement(@enumFromInt(i));
        const Runtime = @import("universal_relation_binding.zig").Binding(Air).Runtime;
        var row: [Runtime.LOGICAL_INPUT_COUNT]S = undefined;
        for (row[0..Air.PHYSICAL_MAIN_COLUMN_COUNT], 0..) |*value, c| value.* = try samples.at(1, placement.main_offset + c, 0);
        for (row[Air.PHYSICAL_MAIN_COLUMN_COUNT..], 0..) |*value, c| value.* = try samples.at(0, placement.preprocessed_offset + c, 0);
        var current: [Runtime.BATCH_COUNT]S = undefined;
        for (&current, 0..) |*value, batch| value.* = try samples.secure(placement.interaction_offset + 4 * batch, if (batch + 1 == Runtime.BATCH_COUNT) 1 else 0);
        const previous = try samples.secure(placement.interaction_offset + 4 * (Runtime.BATCH_COUNT - 1), 0);
        const denominator = try recorder.quotientDenominator(hashes.logs[i], max_log, point, &cache);
        const shift = claim_inputs.items[native_claim_count + i].mul(S.fromBase(try M.fromU64(@as(u64, 1) << @intCast(hashes.logs[i])).inv()));
        constraint_count += try recorder.recordComponent(Runtime, component, row, current, previous, shift, &challenges, randomness, denominator, &accumulated);
    }
    var expected_constraints: usize = 0;
    for (components.items) |component| expected_constraints += component.nConstraints();
    if (constraint_count != expected_constraints) return error.InvalidExecutionComposition;
    const chunks_len = core.verifier_types.compositionChunkCount(split) orelse return error.InvalidExecutionComposition;
    const chunks = try temp.alloc(S, chunks_len);
    for (chunks, 0..) |*chunk, i| {
        var partials: [4]S = undefined;
        for (&partials, 0..) |*value, c| value.* = try samples.at(3, i * 4 + c, 0);
        chunk.* = recorder.fromPartialEvals(partials);
    }
    try builder.constrainZero((try recorder.reconstructSplitComposition(chunks, point, composition_log, split)).sub(accumulated));
    var closure = (try @import("../../air/public_logup.zig").blake3RelationSumsFor(S, &shape.public_data, &native.relations(&challenges))).total();
    for (claim_inputs.items) |claim| closure = closure.add(claim);
    try builder.constrainZero(closure);
    builder.deactivate();
    var circuit = try builder.finish();
    errdefer circuit.deinit();
    const values = try temp.alloc(Q, circuit.nodes.len);
    try circuit.evaluateInto(inputs.items, values);
    var result = Prepared{ .arena = arena, .circuit = circuit, .inputs = inputs.items, .sources = sources.items, .values = values, .key_id = expected, .capture_seal = capture.seal, .seal = undefined };
    result.seal = result.identity();
    return result;
}
fn input(builder: *recorder.Builder, a: std.mem.Allocator, inputs: *std.ArrayList(Q), sources: *std.ArrayList(Source), source: Source, value: Q) !S {
    const symbol = try builder.input();
    try inputs.append(a, value);
    try sources.append(a, source);
    return symbol.value;
}
