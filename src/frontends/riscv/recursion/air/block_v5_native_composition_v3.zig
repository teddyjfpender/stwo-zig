//! Native-only v5 composition verifier graph. The global relation sum is an
//! exported leaf claim, never the old per-leaf custody zero equation.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const recorder = @import("composition_graph_recorder.zig");
const S = recorder.Scalar;
const native = @import("blake3_execution_composition_native.zig");
const universal = @import("universal_challenges.zig");
const admission = @import("../../prover/block_v5_native_recursive_admission_v3.zig");
const capture_mod = @import("../../prover/block_v5_native_execution_proof_v3.zig");
const old = @import("blake3_execution_composition.zig");
const frame = @import("../../prover/block_v5_native_frame_v1.zig");
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
        admitted.template.external_retirements,
        admitted.template.execution_profile,
    );
    defer joined.deinit();
    const components = joined.verifying.components.active();
    const all = core.air.components.Components{ .components = components, .n_preprocessed_columns = admitted.logs[0].len };
    const composition_log = all.compositionLogDegreeBound();
    const split = try all.compositionLogSplit();
    const max_log = core.verifier_types.compositionMaskLogSize(composition_log, split) orelse return error.InvalidExecutionComposition;
    var public_inputs: [2]S = undefined;
    if (admitted.reusable_public_inputs) {
        public_inputs[0] = try input(&builder, temp, &inputs, &sources, .{ .public_input = 0 }, try joined.publicCompensation());
        public_inputs[1] = try input(&builder, temp, &inputs, &sources, .{ .public_input = 1 }, capture.receipt.open_sum);
    }
    try builder.activate();
    const challenges = try recorder.ChallengeSet.init(draws);
    const point = recorder.pointFromSeed(seed);
    var cache: recorder.DenominatorCache = @splat(null);
    var accumulated = S.zero();
    const count = if (frame.required(shape)) frame_count: {
        if (claims.items.len != 0) return error.InvalidExecutionComposition;
        var row: [frame.MAIN_COLUMNS]S = undefined;
        for (&row, 0..) |*value, i| value.* = try samples.at(1, i, 0);
        const values = frame.evaluateGeneric(S, try samples.at(0, 0, 0), row, try samples.at(2, 0, 0), frame.symbols(S, try frame.expected(shape, admitted.template.external_retirements)));
        const denominator = try recorder.quotientDenominator(frame.LOG_SIZE, max_log, point, &cache);
        for (values) |value| recorder.accumulate(&accumulated, randomness, value, denominator);
        break :frame_count frame.N_CONSTRAINTS;
    } else try native.record(shape, samples, claims.items, &challenges, randomness, point, max_log, &cache, &accumulated);
    var expected_count: usize = 0;
    for (components) |component| expected_count += component.nConstraints();
    if (count != expected_count) return error.InvalidExecutionComposition;
    const chunks_len = core.verifier_types.compositionChunkCount(split) orelse return error.InvalidExecutionComposition;
    const chunks = try temp.alloc(S, chunks_len);
    for (chunks, 0..) |*chunk, i| {
        var partials: [4]S = undefined;
        for (&partials, 0..) |*value, c| value.* = try samples.at(3, i * 4 + c, 0);
        chunk.* = recorder.fromPartialEvals(partials);
    }
    try builder.constrainZero((try recorder.reconstructSplitComposition(chunks, point, composition_log, split)).sub(accumulated));
    var open: S = undefined;
    var exported: S = undefined;
    if (admitted.reusable_public_inputs) {
        // These two secure values have no internal provider. The versioned
        // parent admission supplies their exact public recursion-wire tuples.
        open = public_inputs[0];
        exported = public_inputs[1];
    } else {
        open = try @import("../../air/public_logup_arithmetic.zig").registersStateSumFor(
            S,
            &shape.public_data,
            &native.relations(&challenges),
        );
        exported = S.fromSecure(capture.receipt.open_sum);
    }
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
