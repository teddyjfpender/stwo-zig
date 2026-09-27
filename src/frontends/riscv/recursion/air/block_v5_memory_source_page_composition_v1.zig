//! Exact original PAGE union masks and complete typed quotient equations.
//! Source claims are authenticated by the independently rebuilt fixed graph;
//! original component claims remain exact variable original-channel inputs.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Semantic = @import("../../prover/block_v5_memory_source_page_semantic_columns_v1.zig");
const Components = @import("../../prover/block_v5_memory_source_unified_page_components_v1.zig");
const Recorder = @import("composition_graph_recorder.zig");
const S = Recorder.Scalar;
const Equations = @import("block_v5_memory_source_page_record_v1.zig");
const Transcript = @import("block_v5_memory_source_page_transcript_v1.zig");
const Layout = @import("../sample_point_layout.zig");
const Shared = @import("blake3_execution_composition.zig");
pub const Prepared = Shared.Prepared;
pub fn claimCount(comptime kind: Semantic.Kind) usize {
    const C = Components.ForKind(kind);
    return C.CoreAirs.len + 2 + @typeInfo(@TypeOf(@as(C.CaptureClaim, undefined).sums)).array.len + C.SourceInput.PAIRS + C.CaptureInput.PAIRS + 4;
}
pub fn claimValues(comptime kind: Semantic.Kind, claims: Components.ForKind(kind).Claims) [claimCount(kind)]Q {
    var result: [claimCount(kind)]Q = undefined;
    var at: usize = 0;
    inline for (std.meta.fields(@TypeOf(claims))) |field| {
        const values = if (comptime std.mem.eql(u8, field.name, "core") or std.mem.eql(u8, field.name, "arithmetic")) @field(claims, field.name) else @field(claims, field.name).sums;
        @memcpy(result[at..][0..values.len], &values);
        at += values.len;
    }
    return result;
}
pub fn publicInputs(comptime kind: Semantic.Kind, a: std.mem.Allocator, claims: Components.ForKind(kind).Claims) ![]Q {
    return a.dupe(Q, &claimValues(kind, claims));
}
pub fn prepare(a: std.mem.Allocator, admitted: anytype, capture: anytype, expected: [32]u8) !Prepared {
    const kind = comptime Transcript.kindOf(@TypeOf(capture.*));
    try capture.validate(admitted, expected);
    const recipe = try admitted.reconstruct(a, &capture.original.frame, capture.relations);
    defer recipe.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const temp = arena.allocator();
    var builder = Recorder.Builder.init(a);
    defer builder.deinit();
    var inputs: std.ArrayList(Q) = .empty;
    var sources: std.ArrayList(Shared.Source) = .empty;
    const sampled = try temp.alloc(S, capture.proof.sampled_values.len);
    for (sampled, capture.proof.sampled_values, 0..) |*symbol, value, i| symbol.* = try input(&builder, temp, &inputs, &sources, .{ .sample = @intCast(i) }, value);
    var samples = Equations.Samples{ .offsets = undefined, .layouts = undefined, .values = sampled };
    if (capture.proof.sampled_points.len != 10) return error.InvalidSourcePageRecursiveSamples;
    const frame = &capture.original.frame;
    const mask_log = core.verifier_types.compositionMaskLogSize(frame.constraint_log, frame.split) orelse return error.InvalidSourcePageRecursiveGeometry;
    const current = core.circle.secureFieldPointFromRandomSeed(capture.proof.oods_seed);
    const step = core.poly.circle.canonic.CanonicCoset.new(mask_log).step();
    const previous = current.sub(.{ .x = Q.fromBase(step.x), .y = Q.fromBase(step.y) });
    var cursor: usize = 0;
    for (capture.proof.sampled_points, 0..) |columns, tree| {
        samples.offsets[tree] = try temp.alloc(usize, columns.len);
        samples.layouts[tree] = try temp.alloc(Layout.Layout, columns.len);
        for (columns, 0..) |points, column| {
            samples.offsets[tree][column] = cursor;
            samples.layouts[tree][column] = try Layout.classifyColumn(points, current, previous);
            cursor = try std.math.add(usize, cursor, points.len);
        }
    }
    if (cursor != sampled.len) return error.InvalidSourcePageRecursiveSamples;
    var draws: [@import("universal_challenges.zig").RELATION_COUNT][2]S = undefined;
    for (&draws, capture.relations.elements, 0..) |*pair, relation, i| {
        pair[0] = try input(&builder, temp, &inputs, &sources, .{ .challenge = @intCast(2 * i) }, relation.z);
        pair[1] = try input(&builder, temp, &inputs, &sources, .{ .challenge = @intCast(2 * i + 1) }, relation.alpha);
    }
    const randomness = try input(&builder, temp, &inputs, &sources, .composition, capture.proof.composition_randomness);
    const seed = try input(&builder, temp, &inputs, &sources, .oods, capture.proof.oods_seed);
    const values = claimValues(kind, frame.claims);
    var claim_symbols: [values.len]S = undefined;
    for (&claim_symbols, values, 0..) |*out, value, i| out.* = try input(&builder, temp, &inputs, &sources, .{ .public_input = @intCast(i) }, value);
    var claims: Equations.ClaimSymbols(kind) = undefined;
    var position: usize = 0;
    inline for (std.meta.fields(@TypeOf(claims))) |field| {
        const n = @typeInfo(field.type).array.len;
        @field(claims, field.name) = claim_symbols[position..][0..n].*;
        position += n;
    }
    if (position != values.len) return error.InvalidSourcePageRecursiveConstraintCensus;
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    const challenges = try Recorder.ChallengeSet.init(draws);
    const quotient = try Equations.record(kind, &builder, recipe.owner, &recipe.admitted.fixed.plan, frame, samples, claims, &challenges, randomness, seed);
    const parts = core.verifier_types.compositionColumnCount(frame.split, 4) orelse return error.InvalidSourcePageRecursiveGeometry;
    const chunks = try temp.alloc(S, parts / 4);
    for (chunks, 0..) |*chunk, i| {
        var coordinates: [4]S = undefined;
        for (&coordinates, 0..) |*out, j| out.* = try samples.at(9, 4 * i + j, 0);
        chunk.* = Recorder.fromPartialEvals(coordinates);
    }
    try builder.constrainZero((try Recorder.reconstructSplitComposition(chunks, Recorder.pointFromSeed(seed), frame.constraint_log, frame.split)).sub(quotient));
    builder.deactivate();
    var circuit = try builder.finish();
    errdefer circuit.deinit();
    const evaluated = try temp.alloc(Q, circuit.nodes.len);
    try circuit.evaluateInto(inputs.items, evaluated);
    var result = Prepared{ .arena = arena, .circuit = circuit, .inputs = inputs.items, .sources = sources.items, .values = evaluated, .key_id = expected, .capture_seal = capture.seal, .seal = undefined };
    result.seal = result.identity();
    return result;
}
fn input(builder: *Recorder.Builder, a: std.mem.Allocator, inputs: *std.ArrayList(Q), sources: *std.ArrayList(Shared.Source), source: Shared.Source, value: Q) !S {
    const symbol = try builder.input();
    try inputs.append(a, value);
    try sources.append(a, source);
    return symbol.value;
}
