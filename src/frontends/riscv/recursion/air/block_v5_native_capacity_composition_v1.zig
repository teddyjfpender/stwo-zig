//! Native-only v5 composition verifier graph. The global relation sum is an
//! exported leaf claim, never the old per-leaf custody zero equation.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const recorder = @import("composition_graph_recorder.zig");
const S = recorder.Scalar;
const native = @import("blake3_execution_composition_native.zig");
const universal = @import("universal_challenges.zig");
const admission = @import("../../prover/block_v5_native_capacity_recursive_admission_v1.zig");
const capture_mod = @import("../../prover/block_v5_native_capacity_proof_v1.zig");
const old = @import("blake3_execution_composition.zig");
const frame = @import("../../prover/block_v5_native_frame_v1.zig");
const capacity_protocol = @import("../../prover/block_v5_native_capacity_protocol_v1.zig");
const activity = @import("../../prover/block_v5_native_capacity_activity_v1.zig");
pub const Prepared = old.Prepared;
const Source = old.Source;

const Samples = struct {
    offsets: [4][]usize,
    lengths: [4][]usize,
    values: []const S,
    pub fn at(self: Samples, tree: usize, column: usize, sample: usize) !S {
        if (tree >= 4 or column >= self.offsets[tree].len or sample >= self.lengths[tree][column])
            return error.InvalidExecutionComposition;
        return self.values[self.offsets[tree][column] + sample];
    }
    pub fn secure(self: Samples, column: usize, sample: usize) !S {
        var partials: [4]S = undefined;
        for (&partials, 0..) |*value, i| value.* = try self.at(2, column + i, sample);
        return recorder.fromPartialEvals(partials);
    }
};

pub fn prepare(a: std.mem.Allocator, admitted: *const admission.Prepared, capture: *const capture_mod.VerifiedCapture, expected: [32]u8) !Prepared {
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
    for (sampled, capture.proof.sampled_values, 0..) |*symbol, value, i|
        symbol.* = try input(&builder, temp, &inputs, &sources, .{ .sample = @intCast(i) }, value);
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
    const shape = admitted.shape;
    var claims: std.ArrayList(S) = .empty;
    for (shape.component_descs[0..shape.n_components], 0..) |desc, i|
        for (try capture.native_claims.opcodeClaims(desc.family, i)) |claim|
            try claims.append(temp, try input(&builder, temp, &inputs, &sources, .{ .claim = @intCast(claims.items.len) }, claim));
    for (shape.infra_descs[0..shape.n_infra], 0..) |desc, i|
        for (try capture.native_claims.infraClaims(desc.kind, i)) |claim|
            try claims.append(temp, try input(&builder, temp, &inputs, &sources, .{ .claim = @intCast(claims.items.len) }, claim));
    var draws: [universal.RELATION_COUNT][2]S = undefined;
    for (&draws, capture.relations.elements, 0..) |*pair, element, i| {
        pair[0] = try input(&builder, temp, &inputs, &sources, .{ .challenge = @intCast(2 * i) }, element.z);
        pair[1] = try input(&builder, temp, &inputs, &sources, .{ .challenge = @intCast(2 * i + 1) }, element.alpha);
    }
    const randomness = try input(&builder, temp, &inputs, &sources, .composition, capture.proof.composition_randomness);
    const seed = try input(&builder, temp, &inputs, &sources, .oods, capture.proof.oods_seed);
    const joined = try @import("../../prover/block_v5_native_components_v3.zig").Owner.initWithExternalForProfile(
        a,
        shape,
        capture.native_claims,
        capture.relations,
        admitted.pin,
        admitted.external_retirements,
        admitted.template.execution_profile,
    );
    defer joined.deinit();
    const component = try capture_mod.makeComponent(temp, joined, shape, admitted.external_retirements);
    const components = [_]core.air.components.Component{component.asVerifierComponent()};
    const all = core.air.components.Components{ .components = &components, .n_preprocessed_columns = admitted.logs[0].len };
    const composition_log = all.compositionLogDegreeBound();
    const split = try all.compositionLogSplit();
    const max_log = core.verifier_types.compositionMaskLogSize(composition_log, split) orelse return error.InvalidExecutionComposition;
    // Capacity recursion has no specialized row-count path: every expected
    // count is supplied by the independent public bus, including empty frames.
    if (!admitted.reusable_public_inputs) return error.CapacityRecursivePublicInputsRequired;
    const plan = try capacity_protocol.Plan.fromShape(shape, admitted.external_retirements);
    const public_count = 2 + (if (plan.len == 0) @as(usize, 1) else plan.len);
    const public_inputs = try temp.alloc(S, public_count);
    public_inputs[0] = try input(&builder, temp, &inputs, &sources, .{ .public_input = 0 }, try joined.publicCompensation());
    public_inputs[1] = try input(&builder, temp, &inputs, &sources, .{ .public_input = 1 }, capture.receipt.open_sum);
    if (plan.len == 0) {
        _ = try frame.expected(shape, admitted.external_retirements);
        public_inputs[2] = try input(&builder, temp, &inputs, &sources, .{ .public_input = 2 }, Q.fromBase(core.fields.m31.M31.fromCanonical(admitted.external_retirements)));
    } else {
        for (plan.active(), 0..) |shard, i| {
            public_inputs[2 + i] = try input(&builder, temp, &inputs, &sources, .{ .public_input = @intCast(2 + i) }, Q.fromBase(core.fields.m31.M31.fromCanonical(shard.rows)));
        }
    }
    try builder.activate();
    const challenges = try recorder.ChallengeSet.init(draws);
    const point = recorder.pointFromSeed(seed);
    var cache: recorder.DenominatorCache = @splat(null);
    var accumulated = S.zero();
    const count = try recordConstraints(shape, &plan, samples, claims.items, &challenges, randomness, point, max_log, &cache, &accumulated, public_inputs[2..]);
    var expected_count: usize = 0;
    for (components) |item| expected_count += item.nConstraints();
    if (count != expected_count) return error.InvalidExecutionComposition;
    const chunks_len = core.verifier_types.compositionChunkCount(split) orelse return error.InvalidExecutionComposition;
    const chunks = try temp.alloc(S, chunks_len);
    for (chunks, 0..) |*chunk, i| {
        var partials: [4]S = undefined;
        for (&partials, 0..) |*value, c| value.* = try samples.at(3, i * 4 + c, 0);
        chunk.* = recorder.fromPartialEvals(partials);
    }
    try builder.constrainZero((try recorder.reconstructSplitComposition(chunks, point, composition_log, split)).sub(accumulated));
    var open = public_inputs[0];
    const exported = public_inputs[1];
    for (claims.items) |claim| open = open.add(claim);
    try builder.constrainZero(open.sub(exported));
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

/// Shared symbolic equation replay. The only selector substitution is the
/// exact composite component's fixed-active alias into the committed main tree.
/// `counts` are verifier-owned public graph inputs, never literal shard.rows.
pub fn recordConstraints(shape: *const @import("../../air/statement.zig").Blake3ExecutionStatement, plan: *const capacity_protocol.Plan, samples: anytype, claims: []const S, challenges: *const recorder.ChallengeSet, randomness: S, point: core.circle.CirclePoint(S), max_log: u32, cache: *recorder.DenominatorCache, accumulated: *S, counts: []const S) !usize {
    if (plan.len == 0) {
        if (claims.len != 0 or counts.len != 1 or !frame.required(shape)) return error.InvalidCapacityRecursiveComposition;
        var row: [frame.MAIN_COLUMNS]S = undefined;
        for (&row, 0..) |*value, i| value.* = try samples.at(1, i, 0);
        const expected_values: [frame.MAIN_COLUMNS]S = .{ S.fromBase(core.fields.m31.M31.fromCanonical(frame.TAG)), S.fromBase(core.fields.m31.M31.fromCanonical(frame.VERSION)), counts[0], counts[0] };
        const checks = frame.evaluateGeneric(S, try samples.at(0, 0, 0), row, try samples.at(2, 0, 0), expected_values);
        const denominator = try recorder.quotientDenominator(frame.LOG_SIZE, max_log, point, cache);
        for (checks) |check| recorder.accumulate(accumulated, randomness, check, denominator);
        return frame.N_CONSTRAINTS;
    }
    if (counts.len != plan.len) return error.InvalidCapacityRecursiveComposition;
    const Aliased = struct {
        raw: @TypeOf(samples),
        geometry: *const capacity_protocol.Plan,
        pub fn at(self: @This(), tree: usize, column: usize, sample: usize) !S {
            if (tree == 0) {
                for (self.geometry.active()) |shard| {
                    if (column == shard.active_index) {
                        if (sample != 0) return error.InvalidCapacityRecursiveComposition;
                        return self.raw.at(1, shard.main_index, 0);
                    }
                }
            }
            return self.raw.at(tree, column, sample);
        }
        pub fn secure(self: @This(), column: usize, sample: usize) !S {
            return self.raw.secure(column, sample);
        }
    };
    const aliased = Aliased{ .raw = samples, .geometry = plan };
    var count = try native.record(shape, aliased, claims, challenges, randomness, point, max_log, cache, accumulated);
    // Keep the native composite's order: every original component first, then
    // four exact-prefix equations per shard under the same Horner randomness.
    for (plan.active(), counts) |shard, expected_rows| {
        const checks = activity.evaluate(S, try samples.at(0, shard.first_index, 0), try samples.at(1, shard.main_index, 0), try samples.at(1, shard.main_index, 1), try samples.at(1, shard.main_index + 1, 0), try samples.at(1, shard.main_index + 1, 1), expected_rows);
        const denominator = try recorder.quotientDenominator(shard.log_size, max_log, point, cache);
        for (checks) |check| recorder.accumulate(accumulated, randomness, check, denominator);
        count += activity.N_CONSTRAINTS;
    }
    return count;
}
