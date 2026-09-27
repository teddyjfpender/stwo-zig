//! Original48 unsigned-prefix/provider constraints and split composition,
//! authenticated shared54 challenges, group shift and exact public LE16 totals.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Recorder = @import("composition_graph_recorder.zig");
const S = Recorder.Scalar;
const Original = @import("block_v5_readonly_input_provider_composition_v2.zig");
const Air = @import("../../prover/block_v5_readonly_input_provider_component_v2.zig");
const Admission = @import("../../prover/block_v5_readonly_provider_recursive_admission_v2.zig");
const Capture = @import("../../prover/block_v5_readonly_provider_recursive_capture_v2.zig");
const Shared = @import("blake3_execution_composition.zig");
const Source = Shared.Source;
pub const RELATION_COUNT = @import("universal_challenges.zig").RELATION_COUNT + 7;
pub const Prepared = Shared.Prepared;
pub fn prepare(a: std.mem.Allocator, admitted: *const Admission.Prepared, capture: *const Capture.VerifiedCapture, expected: [32]u8) !Prepared {
    try capture.validate(admitted, expected);
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const temp = arena.allocator();
    var builder = Recorder.Builder.init(a);
    defer builder.deinit();
    var inputs: std.ArrayList(Q) = .empty;
    var sources: std.ArrayList(Source) = .empty;
    if (capture.proof.sampled_points.len != 4) return error.InvalidReadonlyProviderRecursiveSamples;
    var offsets: [4][44]usize = undefined;
    var cursor: usize = 0;
    for (capture.proof.sampled_points, [_]usize{ 10, 18, 44, 16 }, 0..) |columns, width, tree| {
        if (columns.len != width) return error.InvalidReadonlyProviderRecursiveSamples;
        for (columns, 0..) |points, column| {
            const prior = tree == 2 or (tree == 1 and Air.Spec.PREVIOUS_MAIN_MASK[column]);
            if (points.len != (if (prior) @as(usize, 2) else 1)) return error.InvalidReadonlyProviderRecursiveSamples;
            offsets[tree][column] = cursor;
            cursor = try std.math.add(usize, cursor, points.len);
        }
    }
    if (cursor != capture.proof.sampled_values.len) return error.InvalidReadonlyProviderRecursiveSamples;
    const samples = try temp.alloc(S, cursor);
    for (samples, capture.proof.sampled_values, 0..) |*out, value, i| out.* = try input(&builder, temp, &inputs, &sources, .{ .sample = @intCast(i) }, value);
    var pairs: [RELATION_COUNT][2]S = undefined;
    var draw: usize = 0;
    for (capture.challenges.word.universal_prefix.elements) |value| {
        pairs[draw] = .{ try input(&builder, temp, &inputs, &sources, .{ .challenge = @intCast(2 * draw) }, value.z), try input(&builder, temp, &inputs, &sources, .{ .challenge = @intCast(2 * draw + 1) }, value.alpha) };
        draw += 1;
    }
    inline for (.{ "transition", "link", "initial", "endpoint", "range16" }) |field| {
        const value = @field(capture.challenges.word, field);
        pairs[draw] = .{ try input(&builder, temp, &inputs, &sources, .{ .challenge = @intCast(2 * draw) }, value.z), try input(&builder, temp, &inputs, &sources, .{ .challenge = @intCast(2 * draw + 1) }, value.alpha) };
        draw += 1;
    }
    inline for (.{ "classification", "read" }) |field| {
        const value = @field(capture.challenges, field);
        pairs[draw] = .{ try input(&builder, temp, &inputs, &sources, .{ .challenge = @intCast(2 * draw) }, value.z), try input(&builder, temp, &inputs, &sources, .{ .challenge = @intCast(2 * draw + 1) }, value.alpha) };
        draw += 1;
    }
    if (draw != RELATION_COUNT) return error.InvalidReadonlyProviderRecursiveChallenges;
    const randomness = try input(&builder, temp, &inputs, &sources, .composition, capture.proof.composition_randomness);
    const seed = try input(&builder, temp, &inputs, &sources, .oods, capture.proof.oods_seed);
    var claims: [11]S = undefined;
    for (&claims, [_]Q{ capture.receipt.claim.classification_sum, capture.receipt.claim.read_sum } ++ capture.receipt.claim.range_sums, 0..) |*out, value, i| out.* = try input(&builder, temp, &inputs, &sources, .{ .public_input = @intCast(i) }, value);
    var totals: [8]S = undefined;
    for ([_]u64{ capture.receipt.claim.counts.events, capture.receipt.claim.counts.readonly }, 0..) |value, which| for (0..4) |limb| {
        const coordinate = 4 * which + limb;
        totals[coordinate] = try input(&builder, temp, &inputs, &sources, .{ .public_input = @intCast(11 + coordinate) }, Q.fromBase(M.fromCanonical(@intCast((value >> @as(u6, @intCast(16 * limb))) & 65535))));
    };
    const group = try input(&builder, temp, &inputs, &sources, .{ .public_input = 19 }, Q.fromBase(M.fromCanonical(admitted.pin.shape.group_id)));
    var fixed: [10]S = undefined;
    var main: [18]S = undefined;
    var prior: [18]S = undefined;
    var current: [44]S = undefined;
    var previous: [44]S = undefined;
    for (&fixed, 0..) |*out, i| out.* = samples[offsets[0][i]];
    for (&main, 0..) |*out, i| {
        out.* = samples[offsets[1][i]];
        if (Air.Spec.PREVIOUS_MAIN_MASK[i]) prior[i] = samples[offsets[1][i] + 1];
    }
    for (&current, &previous, 0..) |*out, *before, i| {
        out.* = samples[offsets[2][i]];
        before.* = samples[offsets[2][i] + 1];
    }
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    for (&prior, Air.Spec.PREVIOUS_MAIN_MASK) |*out, previous_mask| if (!previous_mask) {
        out.* = S.zero();
    };
    const challenges = Original.forGroup(.{ .classification = Original.element(5, pairs[52][0], pairs[52][1]), .read = Original.element(4, pairs[53][0], pairs[53][1]), .word = .{ .range16 = Original.element(1, pairs[51][0], pairs[51][1]) } }, pairs[52][1], pairs[53][1], group);
    var chunks: [4]S = undefined;
    for (&chunks, 0..) |*out, i| {
        var partials: [4]S = undefined;
        for (&partials, 0..) |*limb, coordinate| limb.* = samples[offsets[3][4 * i + coordinate]];
        out.* = Recorder.fromPartialEvals(partials);
    }
    try Original.recordEquation(&builder, admitted.pin.shape.row_log, fixed, main, prior, current, previous, claims, totals, &challenges, randomness, seed, chunks);
    builder.deactivate();
    var circuit = try builder.finish();
    errdefer circuit.deinit();
    const values = try temp.alloc(Q, circuit.nodes.len);
    try circuit.evaluateInto(inputs.items, values);
    var result = Prepared{ .arena = arena, .circuit = circuit, .inputs = inputs.items, .sources = sources.items, .values = values, .key_id = expected, .capture_seal = capture.seal, .seal = undefined };
    result.seal = result.identity();
    return result;
}
fn input(builder: *Recorder.Builder, a: std.mem.Allocator, inputs: *std.ArrayList(Q), sources: *std.ArrayList(Source), source: Source, value: Q) !S {
    const symbol = try builder.input();
    try inputs.append(a, value);
    try sources.append(a, source);
    return symbol.value;
}
