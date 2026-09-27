//! Exact original205 B5IR equations and complete interval/read compensation.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const r = @import("composition_graph_recorder.zig");
const S = r.Scalar;
const Air = @import("../../prover/block_v5_readonly_input_component_v1.zig");
const Admission = @import("../../prover/block_v5_native_readonly_recursive_admission_v1.zig");
const Capture = @import("../../prover/block_v5_native_readonly_recursive_capture_v1.zig");
const Providers = @import("block_v5_readonly_public_provider_graph_v1.zig");
const shared = @import("blake3_execution_composition.zig");
pub const RELATION_COUNT = @import("universal_challenges.zig").RELATION_COUNT + 7;
pub const Prepared = shared.Prepared;
const Source = shared.Source;
pub fn Element(comptime width: usize) type {
    return struct { z: S, alpha_powers: [width]S };
}
pub const Challenges = struct { word: struct { transition: Element(11) }, classification: Element(5), read: Element(4) };
fn element(comptime width: usize, z: S, alpha: S) Element(width) {
    var out = Element(width){ .z = z, .alpha_powers = undefined };
    var power = S.one();
    for (&out.alpha_powers) |*value| {
        value.* = power;
        power = power.mul(alpha);
    }
    return out;
}
pub fn recordEquation(builder: *r.Builder, log: u32, active: S, main: [103]S, current: [20]S, previous: [20]S, claims: [5]S, challenges: *const Challenges, randomness: S, seed: S, chunks: [4]S) !void {
    if (log == 0 or log > 24) return error.InvalidNativeReadonlyRecursiveGeometry;
    const point = r.pointFromSeed(seed);
    var cache: r.DenominatorCache = @splat(null);
    const denominator = try r.quotientDenominator(log, log, point, &cache);
    const inverse = S.fromBase(try M.fromCanonical(@as(u32, 1) << @intCast(log)).inv());
    var shifts: [5]S = undefined;
    for (&shifts, claims) |*shift, claim| shift.* = claim.mul(inverse);
    const equations = Air.Algebra(S).equations(active, main, current, previous, shifts, challenges);
    var accumulated = S.zero();
    for (equations) |equation| r.accumulate(&accumulated, randomness, equation, denominator);
    try builder.constrainZero((try r.reconstructSplitComposition(&chunks, point, log + Air.Spec.EXPANSION_BITS, Air.Spec.EXPANSION_BITS)).sub(accumulated));
}
pub fn prepare(a: std.mem.Allocator, admitted: *const Admission.Prepared, capture: *const Capture.VerifiedCapture, expected: [32]u8) !Prepared {
    try capture.validate(admitted, expected);
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const temp = arena.allocator();
    var builder = r.Builder.init(a);
    defer builder.deinit();
    var inputs: std.ArrayList(Q) = .empty;
    var sources: std.ArrayList(Source) = .empty;
    if (capture.proof.sampled_points.len != 4) return error.InvalidNativeReadonlyRecursiveSamples;
    var offsets: [4][103]usize = undefined;
    var cursor: usize = 0;
    for (capture.proof.sampled_points, [_]usize{ 1, 103, 20, 16 }, 0..) |columns, width, tree| {
        if (columns.len != width) return error.InvalidNativeReadonlyRecursiveSamples;
        for (columns, 0..) |points, column| {
            if (points.len != (if (tree == 2) @as(usize, 2) else 1)) return error.InvalidNativeReadonlyRecursiveSamples;
            offsets[tree][column] = cursor;
            cursor = try std.math.add(usize, cursor, points.len);
        }
    }
    if (cursor != capture.proof.sampled_values.len) return error.InvalidNativeReadonlyRecursiveSamples;
    const samples = try temp.alloc(S, cursor);
    for (samples, capture.proof.sampled_values, 0..) |*out, value, index| out.* = try input(&builder, temp, &inputs, &sources, .{ .sample = @intCast(index) }, value);
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
    if (draw != RELATION_COUNT) return error.InvalidNativeReadonlyRecursiveChallenges;
    const randomness = try input(&builder, temp, &inputs, &sources, .composition, capture.proof.composition_randomness);
    const seed = try input(&builder, temp, &inputs, &sources, .oods, capture.proof.oods_seed);
    var claims: [5]S = undefined;
    inline for (.{ "source_sum", "mutable_sum", "classification_sum", "read_sum" }, 0..) |field, i| claims[i] = try input(&builder, temp, &inputs, &sources, .{ .public_input = @intCast(i) }, @field(capture.receipt.claim, field));
    claims[4] = try input(&builder, temp, &inputs, &sources, .{ .public_input = 4 }, Q.fromBase(M.fromCanonical(@intCast(capture.receipt.claim.readonly_count))));
    const n = admitted.plan.intervals.len;
    const counters = try temp.alloc(S, n);
    const enabled = try temp.alloc(S, n);
    for (capture.counters, counters, enabled, 0..) |count, *counter, *enabler, i| {
        counter.* = try input(&builder, temp, &inputs, &sources, .{ .public_input = @intCast(5 + i) }, Q.fromBase(M.fromCanonical(@intCast(count))));
        enabler.* = try input(&builder, temp, &inputs, &sources, .{ .public_input = @intCast(5 + n + i) }, Q.fromBase(M.fromCanonical(@intFromBool(count != 0))));
    }
    var main: [103]S = undefined;
    var current: [20]S = undefined;
    var previous: [20]S = undefined;
    for (&main, 0..) |*out, i| out.* = samples[offsets[1][i]];
    for (&current, &previous, 0..) |*out, *prior, i| {
        out.* = samples[offsets[2][i]];
        prior.* = samples[offsets[2][i] + 1];
    }
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    const challenges = Challenges{ .word = .{ .transition = element(11, pairs[47][0], pairs[47][1]) }, .classification = element(5, pairs[52][0], pairs[52][1]), .read = element(4, pairs[53][0], pairs[53][1]) };
    var chunks: [4]S = undefined;
    for (&chunks, 0..) |*out, i| {
        var partials: [4]S = undefined;
        for (&partials, 0..) |*limb, coordinate| limb.* = samples[offsets[3][4 * i + coordinate]];
        out.* = r.fromPartialEvals(partials);
    }
    try recordEquation(&builder, admitted.pin.row_log, samples[offsets[0][0]], main, current, previous, claims, &challenges, randomness, seed, chunks);
    try Providers.record(&builder, admitted.plan.intervals, counters, enabled, .{ .z = challenges.classification.z, .alpha_powers = &challenges.classification.alpha_powers }, .{ .z = challenges.read.z, .alpha_powers = &challenges.read.alpha_powers }, claims[2], claims[3], claims[4], admitted.pin.events);
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
