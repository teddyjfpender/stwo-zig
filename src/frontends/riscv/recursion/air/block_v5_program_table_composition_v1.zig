//! Compiler-authenticated ROM provider equation; its claim remains public/open.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const r = @import("composition_graph_recorder.zig");
const S = r.Scalar;
const Native = @import("../../prover/block_v5_program_table_proof_v1.zig");
const Admission = @import("../../prover/block_v5_program_table_recursive_admission_v1.zig");
const Capture = @import("../../prover/block_v5_program_table_recursive_capture_v1.zig");
const shared = @import("blake3_execution_composition.zig");
const Source = shared.Source;
pub const Prepared = shared.Prepared;
/// Actual native handle override, shared by composition and DEEP preparation.
pub fn verifier(component: *const Native.Roster.Component(Native.Air)) !core.air.components.Component {
    return component.asVerifierComponent().withCompositionGeometryOverrideV1(.{ .max_constraint_log_degree_bound_delta = 1, .composition_log_split = 2 });
}
pub fn recordEquation(builder: *r.Builder, component: *const Native.Roster.Component(Native.Air), row: [6]S, current: [4]S, previous: [4]S, claim: S, challenges: *const r.ChallengeSet, randomness: S, seed: S, chunks: [4]S) !void {
    const handle = try verifier(component);
    const composition_log = handle.maxConstraintLogDegreeBound();
    const split = handle.compositionLogSplit();
    const mask_log = core.verifier_types.compositionMaskLogSize(composition_log, split) orelse return error.InvalidProgramRecursiveGeometry;
    const point = r.pointFromSeed(seed);
    var cache: r.DenominatorCache = @splat(null);
    const denominator = try r.quotientDenominator(component.log_size, mask_log, point, &cache);
    const shift = claim.mul(S.fromBase(try M.fromCanonical(@as(u32, 1) << @intCast(component.log_size)).inv()));
    var accumulated = S.zero();
    // Framework final-column current/previous ordering is component-owned.
    const count = try r.recordComponent(Native.Roster.Component(Native.Air).RelationRuntime, component, row, .{r.fromPartialEvals(current)}, r.fromPartialEvals(previous), shift, challenges, randomness, denominator, &accumulated);
    if (count != handle.nConstraints()) return error.InvalidProgramRecursiveGeometry;
    try builder.constrainZero((try r.reconstructSplitComposition(&chunks, point, composition_log, split)).sub(accumulated));
}
pub fn prepare(a: std.mem.Allocator, admitted: *const Admission.Prepared, capture: *const Capture.VerifiedCapture, expected: [32]u8) !Prepared {
    try capture.validate(admitted, expected);
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const temp = arena.allocator();
    var definition = try Native.Air.build(temp);
    defer definition.deinit();
    const relation_plan = try @import("universal_relation_binding.zig").Binding(Native.Air).authenticate(&definition);
    const manifest = Native.Roster.Manifest{ .log_sizes = .{admitted.plan.log_size} };
    const component = try Native.Roster.Component(Native.Air).init(&definition, relation_plan, &manifest, .program, admitted.plan.log_size, .{}, &capture.relations, capture.receipt.claim);
    var builder = r.Builder.init(a);
    defer builder.deinit();
    var inputs: std.ArrayList(Q) = .empty;
    var sources: std.ArrayList(Source) = .empty;
    if (capture.proof.sampled_points.len != 4) return error.InvalidProgramRecursiveSamples;
    const widths = [_]usize{ 6, 0, 4, 16 };
    var offsets: [4][16]usize = undefined;
    var cursor: usize = 0;
    for (capture.proof.sampled_points, widths, 0..) |columns, width, tree| {
        if (columns.len != width) return error.InvalidProgramRecursiveSamples;
        for (columns, 0..) |points, column| {
            if (points.len != (if (tree == 2) @as(usize, 2) else 1)) return error.InvalidProgramRecursiveSamples;
            offsets[tree][column] = cursor;
            cursor = try std.math.add(usize, cursor, points.len);
        }
    }
    if (cursor != capture.proof.sampled_values.len) return error.InvalidProgramRecursiveSamples;
    const samples = try temp.alloc(S, cursor);
    for (samples, capture.proof.sampled_values, 0..) |*symbol, value, index| symbol.* = try input(&builder, temp, &inputs, &sources, .{ .sample = @intCast(index) }, value);
    var draws: [@import("universal_challenges.zig").RELATION_COUNT][2]S = undefined;
    for (&draws, capture.relations.elements, 0..) |*pair, element, index| {
        pair[0] = try input(&builder, temp, &inputs, &sources, .{ .challenge = @intCast(2 * index) }, element.z);
        pair[1] = try input(&builder, temp, &inputs, &sources, .{ .challenge = @intCast(2 * index + 1) }, element.alpha);
    }
    const random = try input(&builder, temp, &inputs, &sources, .composition, capture.proof.composition_randomness);
    const seed = try input(&builder, temp, &inputs, &sources, .oods, capture.proof.oods_seed);
    const claim = try input(&builder, temp, &inputs, &sources, .{ .public_input = 0 }, capture.receipt.claim);
    var row: [6]S = undefined;
    for (&row, 0..) |*value, index| value.* = samples[offsets[0][index]];
    var current: [4]S = undefined;
    var previous: [4]S = undefined;
    for (&current, &previous, 0..) |*value, *prior, index| {
        value.* = samples[offsets[2][index] + 1];
        prior.* = samples[offsets[2][index]];
    }
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    var chunks: [4]S = undefined;
    for (&chunks, 0..) |*chunk, index| {
        var partials: [4]S = undefined;
        for (&partials, 0..) |*limb, coordinate| limb.* = samples[offsets[3][4 * index + coordinate]];
        chunk.* = r.fromPartialEvals(partials);
    }
    const challenges = try r.ChallengeSet.init(draws);
    try recordEquation(&builder, &component, row, current, previous, claim, &challenges, random, seed, chunks);
    builder.deactivate();
    var circuit = try builder.finish();
    errdefer circuit.deinit();
    const values = try temp.alloc(Q, circuit.nodes.len);
    try circuit.evaluateInto(inputs.items, values);
    var result = Prepared{ .arena = arena, .circuit = circuit, .inputs = inputs.items, .sources = sources.items, .values = values, .key_id = expected, .capture_seal = capture.seal, .seal = undefined };
    result.seal = result.identity();
    return result;
}
fn input(builder: *r.Builder, a: std.mem.Allocator, inputs: *std.ArrayList(Q), sources: *std.ArrayList(Source), source: Source, value: Q) !S {
    const symbol = try builder.input();
    try inputs.append(a, value);
    try sources.append(a, source);
    return symbol.value;
}
