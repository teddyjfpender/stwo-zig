//! Full original B5IC memory/projection/classifier quotient and public providers.
//! Original per-instance branch retained; bounded providers are not global-v2.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const R = @import("composition_graph_recorder.zig");
const S = R.Scalar;
const Field = @import("block_v5_native_capacity_fused_composition_v1.zig").Field;
const Universal = @import("universal_challenges.zig");
const Admission = @import("../../prover/block_v5_caller_readonly_recursive_admission_v1.zig");
const Capture = @import("../../prover/block_v5_caller_readonly_recursive_capture_v1.zig");
const Base = @import("block_v5_caller_fused_composition_v1.zig");
const Classifier = @import("../../prover/block_v5_caller_readonly_component_v1.zig");
const Shared = @import("blake3_execution_composition.zig");
pub const Prepared = Shared.Prepared;
pub const RELATION_COUNT: usize = Universal.RELATION_COUNT + 7;
pub const Samples = Base.Samples;
pub fn publicCount(program: usize, tables: usize, memory: usize, intervals: usize) !usize {
    return std.math.add(usize, try Base.publicCount(program, tables, memory), try std.math.mul(usize, memory, try std.math.add(usize, 4, try std.math.mul(usize, 2, intervals))));
}
pub fn publicInputs(a: std.mem.Allocator, admitted: *const Admission.Prepared, claims: Admission.Fused.ClaimFrames) ![]Q {
    const challenges = try @import("../../prover/block_v5_caller_readonly_protocol_v1.zig").Challenges.draw(a, admitted.sealed, admitted.plan.digest, Admission.Fused.instanceId(admitted.binding, admitted.witness_root, admitted.frame, 1, &admitted.schedule, admitted.readonly), admitted.binding.first_roots);
    var channel = core.proof_suites.Blake3.Channel{};
    try Admission.Fused.mixClaims(&channel, admitted.binding, &admitted.schedule, &claims, admitted.plan, &challenges, admitted.readonly.limits);
    const base = try Base.publicInputsFor(Admission, a, admitted, claims.base());
    defer a.free(base);
    const inputs = try a.alloc(Q, try publicCount(admitted.schedule.program.len, admitted.schedule.tables.len, admitted.schedule.memory.len, admitted.plan.intervals.len));
    @memcpy(inputs[0..base.len], base);
    var at = base.len;
    for (claims.readonly_claims) |claim| {
        inputs[at] = claim.claim.mutable_sum;
        inputs[at + 1] = claim.claim.classification_sum;
        inputs[at + 2] = claim.claim.read_sum;
        inputs[at + 3] = Q.fromBase(M.fromCanonical(@intCast(claim.claim.readonly_count)));
        at += 4;
        for (claim.counters) |counter| {
            inputs[at] = Q.fromBase(M.fromCanonical(@intCast(counter)));
            inputs[at + 1] = if (counter == 0) Q.zero() else Q.one();
            at += 2;
        }
    }
    std.debug.assert(at == inputs.len);
    return inputs;
}
const FieldSamples = struct {
    original: Samples,
    pub fn at(self: @This(), tree: usize, column: usize, ordinal: usize) !Field {
        return .{ .symbol = try self.original.at(tree, column, ordinal) };
    }
};
pub fn powers(comptime N: usize, alpha: S) [N]Field {
    var result: [N]Field = undefined;
    var power = Field.one();
    for (&result) |*out| {
        out.* = power;
        power = power.mul(.{ .symbol = alpha });
    }
    return result;
}
pub fn recordConstraints(admitted: *const Admission.Prepared, samples: Samples, public: []const S, draws: [Universal.RELATION_COUNT][2]S, word: [10]S, classification: [4]S, random: S, point: core.circle.CirclePoint(S), mask_log: u32, accumulated: *S) !usize {
    return recordConstraintsFor(Admission, admitted, samples, public, draws, word, classification, random, point, mask_log, accumulated, 4 + 2 * admitted.plan.intervals.len);
}
/// Source-v2 supplies compact claim cells and already algebraically shifted
/// global challenges. Both versions execute this one original149 body/order.
pub fn recordConstraintsFor(comptime Admitted: type, admitted: *const Admitted.Prepared, samples: Samples, public: []const S, draws: [Universal.RELATION_COUNT][2]S, word: [10]S, classification: [4]S, random: S, point: core.circle.CirclePoint(S), mask_log: u32, accumulated: *S, width: usize) !usize {
    const schedule = &admitted.schedule;
    const base_count = try Base.publicCount(schedule.program.len, schedule.tables.len, schedule.memory.len);
    if (public.len != try std.math.add(usize, base_count, try std.math.mul(usize, width, schedule.memory.len))) return error.InvalidCallerReadonlyRecursiveClaims;
    var count = try Base.recordConstraintsFor(Admitted, admitted, samples, public[0..base_count], draws, word, random, point, mask_log, accumulated);
    const elements = .{
        .word = .{ .transition = .{ .z = Field{ .symbol = word[0] }, .alpha_powers = powers(11, word[1]) } },
        .classification = .{ .z = Field{ .symbol = classification[0] }, .alpha_powers = powers(5, classification[1]) },
        .read = .{ .z = Field{ .symbol = classification[2] }, .alpha_powers = powers(4, classification[3]) },
    };
    var cache: R.DenominatorCache = @splat(null);
    const fs = FieldSamples{ .original = samples };
    for (schedule.memory, 0..) |slot, i| {
        const pair = try @import("../../prover/block_v5_caller_fused_algebra_v1.zig").externalPair(Field, slot, fs);
        var witness: [48]Field = undefined;
        var metadata: [Classifier.META_COUNT]Field = undefined;
        var current: [Classifier.INTER_COUNT]Field = undefined;
        var previous: [Classifier.INTER_COUNT]Field = undefined;
        for (&witness, 0..) |*out, j| out.* = try fs.at(2, i * 48 + j, 0);
        for (&metadata, 0..) |*out, j| out.* = try fs.at(2, schedule.memory.len * 48 + i * Classifier.META_COUNT + j, 0);
        const begin = schedule.projectionCount() * 4 + schedule.memory.len * 49 + i * Classifier.INTER_COUNT;
        for (&current, &previous, 0..) |*out, *prior, j| {
            out.* = try fs.at(3, begin + j, 0);
            prior.* = try fs.at(3, begin + j, 1);
        }
        const normalize = S.fromBase(try M.fromCanonical(@as(u32, 1) << @intCast(slot.log_size)).inv());
        var shifts: [4]Field = undefined;
        for (&shifts, public[base_count + i * width ..][0..4]) |*out, claim| out.* = .{ .symbol = claim.mul(normalize) };
        const equations = Classifier.Algebra(Field).equations(pair, witness, metadata, current, previous, shifts, &elements);
        for (equations) |equation| R.accumulate(accumulated, random, equation.symbol, try R.quotientDenominator(slot.log_size, mask_log, point, &cache));
        count += equations.len;
    }
    return count;
}
pub fn recordProviders(a: std.mem.Allocator, builder: *R.Builder, admitted: *const Admission.Prepared, public: []const S, classification: [4]S) !void {
    const Provider = @import("block_v5_readonly_public_provider_graph_v1.zig");
    const schedule = &admitted.schedule;
    const begin = try Base.publicCount(schedule.program.len, schedule.tables.len, schedule.memory.len);
    const width = 4 + 2 * admitted.plan.intervals.len;
    const cp = powers(5, classification[1]);
    const rp = powers(4, classification[3]);
    var class_powers: [5]S = undefined;
    var read_powers: [4]S = undefined;
    for (&class_powers, cp) |*out, p| out.* = p.symbol;
    for (&read_powers, rp) |*out, p| out.* = p.symbol;
    const temp = try a.alloc(S, 2 * admitted.plan.intervals.len);
    defer a.free(temp);
    const counters = temp[0..admitted.plan.intervals.len];
    const enabled = temp[admitted.plan.intervals.len..];
    for (schedule.memory, 0..) |_, i| {
        const cells = public[begin + i * width ..][0..width];
        for (counters, enabled, 0..) |*counter, *active, j| {
            counter.* = cells[4 + 2 * j];
            active.* = cells[5 + 2 * j];
        }
        const event_index = 8 + 2 * schedule.program.len + schedule.tables.len + 10 * i + 2;
        try Provider.recordDynamic(builder, admitted.plan.intervals, counters, enabled, .{ .z = classification[0], .alpha_powers = &class_powers }, .{ .z = classification[2], .alpha_powers = &read_powers }, cells[1], cells[2], cells[3], public[event_index]);
    }
}
pub fn prepare(a: std.mem.Allocator, admitted: *const Admission.Prepared, capture: *const Capture.VerifiedCapture, expected: [32]u8) !Prepared {
    try capture.validate(admitted, expected);
    var owner = try @import("block_v5_caller_readonly_components_v1.zig").Owner.init(a, admitted, capture, expected);
    defer owner.deinit();
    const all = owner.all(admitted.logs[0].len);
    const composition_log = all.compositionLogDegreeBound();
    const split = try all.compositionLogSplit();
    const mask_log = core.verifier_types.compositionMaskLogSize(composition_log, split) orelse return error.InvalidCallerReadonlyRecursiveGeometry;
    const point = core.circle.secureFieldPointFromRandomSeed(capture.proof.oods_seed);
    var masks = try all.maskPoints(a, point, mask_log, false);
    defer masks.deinitDeep(a);
    if (masks.items.len != 4 or capture.proof.sampled_points.len != 5) return error.InvalidCallerReadonlyRecursiveSamples;
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const temp = arena.allocator();
    var builder = R.Builder.init(a);
    defer builder.deinit();
    var inputs: std.ArrayList(Q) = .empty;
    var sources: std.ArrayList(Shared.Source) = .empty;
    var samples = Samples{ .offsets = undefined, .lengths = undefined, .values = undefined };
    var cursor: usize = 0;
    for (capture.proof.sampled_points, 0..) |columns, tree| {
        const wanted = if (tree < 4) admitted.logs[tree].len else core.verifier_types.compositionColumnCount(split, 4) orelse return error.InvalidCallerReadonlyRecursiveGeometry;
        if (columns.len != wanted) return error.InvalidCallerReadonlyRecursiveSamples;
        samples.offsets[tree] = try temp.alloc(usize, columns.len);
        samples.lengths[tree] = try temp.alloc(usize, columns.len);
        for (columns, 0..) |points, column| {
            if (tree < 4) {
                if (points.len != masks.items[tree][column].len) return error.InvalidCallerReadonlyRecursiveSamples;
                for (points, masks.items[tree][column]) |actual, wanted_point| if (!actual.eql(wanted_point)) return error.InvalidCallerReadonlyRecursiveSamples;
            } else if (points.len != 1 or !points[0].eql(point)) return error.InvalidCallerReadonlyRecursiveSamples;
            samples.offsets[tree][column] = cursor;
            samples.lengths[tree][column] = points.len;
            cursor = try std.math.add(usize, cursor, points.len);
        }
    }
    if (cursor != capture.proof.sampled_values.len or cursor > admitted.limits.max_samples) return error.CallerReadonlyRecursiveResourceLimit;
    const sampled = try temp.alloc(S, cursor);
    for (sampled, capture.proof.sampled_values, 0..) |*out, value, i| out.* = try input(&builder, temp, &inputs, &sources, .{ .sample = @intCast(i) }, value);
    samples.values = sampled;
    var draws: [Universal.RELATION_COUNT][2]S = undefined;
    for (&draws, capture.relations.elements, 0..) |*out, element, i| {
        out[0] = try input(&builder, temp, &inputs, &sources, .{ .challenge = @intCast(2 * i) }, element.z);
        out[1] = try input(&builder, temp, &inputs, &sources, .{ .challenge = @intCast(2 * i + 1) }, element.alpha);
    }
    var word: [10]S = undefined;
    inline for (.{ "transition", "link", "initial", "endpoint", "range16" }, 0..) |name, i| {
        const element = @field(capture.word_challenges, name);
        word[2 * i] = try input(&builder, temp, &inputs, &sources, .{ .challenge = @intCast(2 * Universal.RELATION_COUNT + 2 * i) }, element.z);
        word[2 * i + 1] = try input(&builder, temp, &inputs, &sources, .{ .challenge = @intCast(2 * Universal.RELATION_COUNT + 2 * i + 1) }, element.alpha);
    }
    var classification: [4]S = undefined;
    inline for (.{ "classification", "read" }, 0..) |name, i| {
        const element = @field(capture.original.classification, name);
        classification[2 * i] = try input(&builder, temp, &inputs, &sources, .{ .challenge = @intCast(2 * (Universal.RELATION_COUNT + 5) + 2 * i) }, element.z);
        classification[2 * i + 1] = try input(&builder, temp, &inputs, &sources, .{ .challenge = @intCast(2 * (Universal.RELATION_COUNT + 5) + 2 * i + 1) }, element.alpha);
    }
    const values = try publicInputs(temp, admitted, capture.original.claims);
    const public = try temp.alloc(S, values.len);
    for (public, values, 0..) |*out, value, i| out.* = try input(&builder, temp, &inputs, &sources, .{ .public_input = @intCast(i) }, value);
    const random = try input(&builder, temp, &inputs, &sources, .composition, capture.proof.composition_randomness);
    const seed = try input(&builder, temp, &inputs, &sources, .oods, capture.proof.oods_seed);
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    const symbolic_point = R.pointFromSeed(seed);
    var accumulated = S.zero();
    const count = try recordConstraints(admitted, samples, public, draws, word, classification, random, symbolic_point, mask_log, &accumulated);
    try recordProviders(temp, &builder, admitted, public, classification);
    var actual_count: usize = 0;
    for (owner.handles) |component| actual_count += component.nConstraints();
    if (count != actual_count) return error.InvalidCallerReadonlyRecursiveEquationCount;
    const chunks = try temp.alloc(S, core.verifier_types.compositionChunkCount(split) orelse return error.InvalidCallerReadonlyRecursiveGeometry);
    for (chunks, 0..) |*out, chunk| out.* = R.fromPartialEvals(.{ try samples.at(4, 4 * chunk, 0), try samples.at(4, 4 * chunk + 1, 0), try samples.at(4, 4 * chunk + 2, 0), try samples.at(4, 4 * chunk + 3, 0) });
    try builder.constrainZero((try R.reconstructSplitComposition(chunks, symbolic_point, composition_log, split)).sub(accumulated));
    builder.deactivate();
    var circuit = try builder.finish();
    errdefer circuit.deinit();
    const outputs = try temp.alloc(Q, circuit.nodes.len);
    try circuit.evaluateInto(inputs.items, outputs);
    var result = Prepared{ .arena = arena, .circuit = circuit, .inputs = inputs.items, .sources = sources.items, .values = outputs, .key_id = expected, .capture_seal = capture.seal, .seal = undefined };
    result.seal = result.identity();
    return result;
}
fn input(builder: *R.Builder, a: std.mem.Allocator, inputs: *std.ArrayList(Q), sources: *std.ArrayList(Shared.Source), source: Shared.Source, value: Q) !S {
    const symbol = try builder.input();
    try inputs.append(a, value);
    try sources.append(a, source);
    return symbol.value;
}
