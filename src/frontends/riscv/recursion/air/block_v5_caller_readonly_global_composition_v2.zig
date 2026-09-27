//! Original full B5IC quotient with compact global2 classifier requests.
//! Shared54 draws are group-shifted symbolically; provider closure remains OPEN.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const R = @import("composition_graph_recorder.zig");
const S = R.Scalar;
const Field = @import("block_v5_native_capacity_fused_composition_v1.zig").Field;
const Universal = @import("universal_challenges.zig");
const Admission = @import("../../prover/block_v5_caller_readonly_global_recursive_admission_v2.zig");
const Capture = @import("../../prover/block_v5_caller_readonly_global_recursive_capture_v2.zig");
const Base = @import("block_v5_caller_fused_composition_v1.zig");
const Classifier = @import("../../prover/block_v5_caller_readonly_component_v1.zig");
const Shared = @import("blake3_execution_composition.zig");
pub const Prepared = Shared.Prepared;
pub const RELATION_COUNT: usize = Universal.RELATION_COUNT + 7;
pub const Samples = Base.Samples;
const OriginalGraph = @import("block_v5_caller_readonly_composition_v1.zig");
/// Compact scope cell is normative public group, not a received shifted draw.
pub fn publicCount(program: usize, tables: usize, memory: usize) !usize {
    return std.math.add(usize, try Base.publicCount(program, tables, memory), try std.math.add(usize, try std.math.mul(usize, memory, 4), 1));
}
pub fn publicInputs(a: std.mem.Allocator, admitted: *const Admission.Prepared, claims: Admission.Fused.ClaimFrames) ![]Q {
    const challenges = try Admission.Fused.classification(a, admitted.sealed, admitted.plan, admitted.binding, admitted.witness_root, admitted.frame, &admitted.schedule, admitted.readonly);
    var channel = core.proof_suites.Blake3.Channel{};
    try Admission.Fused.mixClaims(&channel, admitted.binding, &admitted.schedule, &claims, admitted.plan, &challenges, admitted.readonly);
    const base = try Base.publicInputsFor(Admission, a, admitted, claims.base());
    defer a.free(base);
    const inputs = try a.alloc(Q, try publicCount(admitted.schedule.program.len, admitted.schedule.tables.len, admitted.schedule.memory.len));
    @memcpy(inputs[0..base.len], base);
    var at = base.len;
    for (claims.readonly_claims) |claim| {
        inputs[at] = claim.claim.mutable_sum;
        inputs[at + 1] = claim.claim.classification_sum;
        inputs[at + 2] = claim.claim.read_sum;
        inputs[at + 3] = Q.fromBase(M.fromCanonical(@intCast(claim.claim.readonly_count)));
        at += 4;
    }
    inputs[at] = Q.fromBase(M.fromCanonical(admitted.readonly.group_id));
    return inputs;
}
pub fn recordConstraints(admitted: *const Admission.Prepared, samples: Samples, public: []const S, draws: [Universal.RELATION_COUNT][2]S, word: [10]S, classification: [4]S, random: S, point: core.circle.CirclePoint(S), mask_log: u32, accumulated: *S) !usize {
    if (public.len != try publicCount(admitted.schedule.program.len, admitted.schedule.tables.len, admitted.schedule.memory.len)) return error.InvalidGlobalCallerReadonlyClaims;
    const group = public[public.len - 1];
    // Exact implicit final tuple coordinates: z'=z-alpha^arity*group.
    const cp = OriginalGraph.powers(6, classification[1]);
    const rp = OriginalGraph.powers(5, classification[3]);
    const shifted: [4]S = .{ classification[0].sub(cp[5].symbol.mul(group)), classification[1], classification[2].sub(rp[4].symbol.mul(group)), classification[3] };
    return OriginalGraph.recordConstraintsFor(Admission, admitted, samples, public[0 .. public.len - 1], draws, word, shifted, random, point, mask_log, accumulated, 4);
}
pub fn prepare(a: std.mem.Allocator, admitted: *const Admission.Prepared, capture: *const Capture.VerifiedCapture, expected: [32]u8) !Prepared {
    try capture.validate(admitted, expected);
    var owner = try @import("block_v5_caller_readonly_global_components_v2.zig").Owner.init(a, admitted, capture, expected);
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
        const element = @field(capture.shared_classification, name);
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
