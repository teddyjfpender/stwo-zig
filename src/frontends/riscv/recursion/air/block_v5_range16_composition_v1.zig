//! Range16 verifier equations use the same typed algebra as CPU/packed/GPU.
//! The exported sum and exact count are public inputs, never scalar sentinels.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const recorder = @import("composition_graph_recorder.zig");
const S = recorder.Scalar;
const Range = @import("../../prover/block_v5_range16_v1.zig");
const Spec = @import("../../prover/block_v5_range16_component_v1.zig").Spec;
pub const RELATION_COUNT = @import("universal_challenges.zig").RELATION_COUNT + 5;
pub const Prepared = @import("blake3_execution_composition.zig").Prepared;
const Source = @import("blake3_execution_composition.zig").Source;
// The generic range algebra expects a field-owned partial-evaluation
// constructor. This wrapper forwards every operation to the existing
// authenticated recorder, without changing the shared Scalar API.
const Field = struct {
    symbol: S,
    pub fn add(self: Field, other: Field) Field {
        return .{ .symbol = self.symbol.add(other.symbol) };
    }
    pub fn sub(self: Field, other: Field) Field {
        return .{ .symbol = self.symbol.sub(other.symbol) };
    }
    pub fn mul(self: Field, other: Field) Field {
        return .{ .symbol = self.symbol.mul(other.symbol) };
    }
    pub fn fromPartialEvals(values: [4]Field) Field {
        var partials: [4]S = undefined;
        for (&partials, values) |*out, value| out.* = value.symbol;
        return .{ .symbol = recorder.fromPartialEvals(partials) };
    }
};
fn wrapped(comptime n: usize, values: [n]S) [n]Field {
    var result: [n]Field = undefined;
    for (&result, values) |*out, value| out.* = .{ .symbol = value };
    return result;
}
const Relation = struct {
    z: Field,
    pub fn combineSecure(self: @This(), values: [1]Field) Field {
        return values[0].sub(self.z);
    }
};
/// One exact component equation, including normalization, coset denominator,
/// Horner coefficient order and split-composition reconstruction.
pub fn recordEquation(builder: *recorder.Builder, fixed: [1]S, main: [1]S, current: [8]S, previous: [8]S, sum: S, count: S, z: S, randomness: S, seed: S, chunks: [2]S) !void {
    const point = recorder.pointFromSeed(seed);
    var cache: recorder.DenominatorCache = @splat(null);
    const denominator = try recorder.quotientDenominator(Range.TABLE_LOG, Range.TABLE_LOG, point, &cache);
    const inverse_size = S.fromBase(try M.fromCanonical(Range.TABLE_SIZE).inv());
    const equations = @import("../../prover/block_v5_range16_algebra_v1.zig").equations(Field, wrapped(1, fixed), wrapped(1, main), wrapped(8, current), wrapped(8, previous), .{ .symbol = sum.mul(inverse_size) }, .{ .symbol = count.mul(inverse_size) }, Relation{ .z = .{ .symbol = z } });
    var accumulated = S.zero();
    for (equations) |equation| recorder.accumulate(&accumulated, randomness, equation.symbol, denominator);
    const reconstructed = try recorder.reconstructSplitComposition(&chunks, point, Range.TABLE_LOG + Spec.EXPANSION_BITS, Spec.EXPANSION_BITS);
    try builder.constrainZero(reconstructed.sub(accumulated));
}
pub fn prepare(a: std.mem.Allocator, admitted: anytype, capture: anytype, expected: [32]u8) !Prepared {
    try capture.validate(admitted, expected);
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const temp = arena.allocator();
    var builder = recorder.Builder.init(a);
    defer builder.deinit();
    var inputs: std.ArrayList(Q) = .empty;
    var sources: std.ArrayList(Source) = .empty;
    if (capture.proof.sampled_points.len != 4) return error.InvalidRangeRecursiveSamples;
    const widths = [_]usize{ 1, 1, 8, 8 };
    var offsets: [4][8]usize = undefined;
    var cursor: usize = 0;
    for (capture.proof.sampled_points, widths, 0..) |columns, width, tree| {
        if (columns.len != width) return error.InvalidRangeRecursiveSamples;
        for (columns, 0..) |points, column| {
            if (points.len != (if (tree == 2) @as(usize, 2) else 1)) return error.InvalidRangeRecursiveSamples;
            offsets[tree][column] = cursor;
            cursor = try std.math.add(usize, cursor, points.len);
        }
    }
    if (cursor != capture.proof.sampled_values.len) return error.InvalidRangeRecursiveSamples;
    const samples = try temp.alloc(S, cursor);
    for (samples, capture.proof.sampled_values, 0..) |*symbol, value, index| symbol.* = try input(&builder, temp, &inputs, &sources, .{ .sample = @intCast(index) }, value);
    var z: S = undefined;
    var draw: u32 = 0;
    for (capture.challenges.universal_prefix.elements) |element| {
        _ = try input(&builder, temp, &inputs, &sources, .{ .challenge = draw }, element.z);
        _ = try input(&builder, temp, &inputs, &sources, .{ .challenge = draw + 1 }, element.alpha);
        draw += 2;
    }
    inline for (.{ "transition", "link", "initial", "endpoint", "range16" }) |field| {
        const element = @field(capture.challenges, field);
        const symbol = try input(&builder, temp, &inputs, &sources, .{ .challenge = draw }, element.z);
        _ = try input(&builder, temp, &inputs, &sources, .{ .challenge = draw + 1 }, element.alpha);
        if (comptime std.mem.eql(u8, field, "range16")) z = symbol;
        draw += 2;
    }
    if (draw != 2 * RELATION_COUNT) return error.InvalidRangeRecursiveChallenges;
    const randomness = try input(&builder, temp, &inputs, &sources, .composition, capture.proof.composition_randomness);
    const seed = try input(&builder, temp, &inputs, &sources, .oods, capture.proof.oods_seed);
    const sum = try input(&builder, temp, &inputs, &sources, .{ .public_input = 0 }, capture.receipt.claim.sum);
    const count = try input(&builder, temp, &inputs, &sources, .{ .public_input = 1 }, Q.fromBase(M.fromCanonical(@intCast(capture.receipt.claim.count))));
    var current: [8]S = undefined;
    var previous: [8]S = undefined;
    for (&current, &previous, 0..) |*value, *prior, column| {
        value.* = samples[offsets[2][column]];
        prior.* = samples[offsets[2][column] + 1];
    }
    try builder.activate();
    var active = true;
    defer if (active) builder.deactivate();
    var chunks: [2]S = undefined;
    for (&chunks, 0..) |*chunk, index| {
        var partials: [4]S = undefined;
        for (&partials, 0..) |*limb, coordinate| limb.* = samples[offsets[3][4 * index + coordinate]];
        chunk.* = recorder.fromPartialEvals(partials);
    }
    try recordEquation(&builder, .{samples[offsets[0][0]]}, .{samples[offsets[1][0]]}, current, previous, sum, count, z, randomness, seed, chunks);
    builder.deactivate();
    active = false;
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
