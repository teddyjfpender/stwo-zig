//! Full captured STARK composition equality, using existing equation authorities.
//! Test-only public inputs; this is not yet a joined recursive verifier.
const std = @import("std");
const f = @import("blake3_proof_fixture.zig");
const r = @import("composition_graph_recorder.zig");
const S = r.Scalar;
const Q = f.QM31;
const Capture = f.core.verifier.ProofCapture(f.Hasher);
const tables_equations = @import("../../air/lookups/tables/equations.zig");
const logup = @import("../../air/logup.zig");

pub fn check(comptime F: type, a: std.mem.Allocator, capture: *const Capture, components: *const F.Tuple(.component), tables: *const [2]f.Table, verifiers: []const f.core.air.components.Component, relations: *const f.universal.UniversalRelations, claims: []const Q, config: f.core.pcs.PcsConfig) !void {
    const native = f.core.air.components.Components{ .components = verifiers, .n_preprocessed_columns = capture.column_log_sizes[0].len };
    const composition_log = native.compositionLogDegreeBound();
    const split = try native.compositionLogSplit();
    const mask_log = f.core.verifier_types.compositionMaskLogSize(composition_log, split) orelse return error.InvalidCompositionGeometry;
    const point = f.core.circle.secureFieldPointFromRandomSeed(capture.oods_seed);
    var masks = try native.maskPoints(a, point, mask_log, false);
    defer masks.deinitDeep(a);
    // Derive the inventory from admitted components, never from capture lengths.
    try std.testing.expectEqual(@as(usize, 4), capture.sampled_points.len);
    try std.testing.expectEqual(@as(usize, 3), masks.items.len);
    var builder = r.Builder.init(a);
    defer builder.deinit();
    var inputs: std.ArrayList(Q) = .empty;
    defer inputs.deinit(a);
    var samples: [3][][]S = undefined;
    var cursor: usize = 0;
    for (masks.items, &samples, capture.sampled_points[0..3]) |tree, *destination, captured_tree| {
        try std.testing.expectEqual(tree.len, captured_tree.len);
        destination.* = try a.alloc([]S, tree.len);
        for (tree, destination.*, captured_tree) |column, *values, captured_column| {
            try std.testing.expectEqualSlices(f.core.circle.CirclePointQM31, column, captured_column);
            values.* = try a.alloc(S, column.len);
            for (values.*) |*value| {
                if (cursor >= capture.sampled_values.len) return error.InvalidCompositionGeometry;
                value.* = try input(a, &builder, &inputs, capture.sampled_values[cursor]);
                cursor += 1;
            }
        }
    }
    const composition_start = cursor;
    const chunk_count = f.core.verifier_types.compositionChunkCount(split) orelse return error.InvalidCompositionGeometry;
    try std.testing.expectEqual(chunk_count * 4, capture.sampled_points[3].len);
    const chunks = try a.alloc([4]S, chunk_count);
    for (chunks) |*chunk| for (chunk) |*value| {
        const column = capture.sampled_points[3][cursor - composition_start];
        try std.testing.expectEqualSlices(f.core.circle.CirclePointQM31, &.{point}, column);
        if (cursor >= capture.sampled_values.len) return error.InvalidCompositionGeometry;
        value.* = try input(a, &builder, &inputs, capture.sampled_values[cursor]);
        cursor += 1;
    };
    try std.testing.expectEqual(capture.sampled_values.len, cursor);
    const alpha = try input(a, &builder, &inputs, capture.composition_randomness);
    const seed = try input(a, &builder, &inputs, capture.oods_seed);
    var draws: [f.universal.RELATION_COUNT][2]S = undefined;
    for (&draws, relations.elements) |*draw, element| draw.* = .{ try input(a, &builder, &inputs, element.z), try input(a, &builder, &inputs, element.alpha) };
    try std.testing.expectEqual(F.Airs.len + 2, claims.len);
    const claim_start = inputs.items.len;
    const symbolic_claims = try a.alloc(S, claims.len);
    for (symbolic_claims, claims) |*symbolic, value| symbolic.* = try input(a, &builder, &inputs, value);
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    const symbolic_point = r.pointFromSeed(seed);
    const challenges = try r.ChallengeSet.init(draws);
    var denominators: r.DenominatorCache = @splat(null);
    var accumulation = S.zero();
    inline for (F.Airs, 0..) |Air, i| {
        const component = &components[i];
        const placement = component.placement;
        var row: [Air.LOGICAL_INPUT_COUNT]S = undefined;
        for (row[0..Air.PHYSICAL_MAIN_COLUMN_COUNT], 0..) |*value, j| value.* = samples[1][placement.main_offset + j][0];
        for (row[Air.PHYSICAL_MAIN_COLUMN_COUNT..][0..Air.PREPROCESSED_COLUMN_COUNT], 0..) |*value, j| value.* = samples[0][placement.preprocessed_offset + j][0];
        for (row[Air.PHYSICAL_MAIN_COLUMN_COUNT + Air.PREPROCESSED_COLUMN_COUNT ..], component.parameters) |*value, parameter| value.* = S.fromBase(parameter);
        var current: [Air.INTERACTION_BATCH_COUNT]S = undefined;
        for (&current, 0..) |*value, j| value.* = secure(samples[2], placement.interaction_offset + 4 * j, if (j + 1 == current.len) 1 else 0);
        const previous = secure(samples[2], placement.interaction_offset + 4 * (current.len - 1), 0);
        const size = f.M31.fromCanonical(@as(u32, 1) << @intCast(component.log_size));
        const shift = symbolic_claims[i].mul(S.fromBase(try size.inv()));
        _ = try r.recordComponent(F.Component(Air).RelationRuntime, component, row, current, previous, shift, &challenges, alpha, try r.quotientDenominator(component.log_size, mask_log, symbolic_point, &denominators), &accumulation);
    }
    for (tables, F.Airs.len..) |table, i| {
        const arity = f.schema.arity(table.kind);
        var tuple: [f.schema.MAX_ARITY]S = undefined;
        for (tuple[0..arity], table.tuple_col_indices[0..arity]) |*value, column| value.* = samples[0][column][0];
        const entry = tables_equations.tableEntryGeneric(S, table.kind, tuple[0..arity], samples[1][table.main_col_offset][0]);
        const domain = std.meta.stringToEnum(@import("../../air/lang/relation.zig").Domain, @tagName(entry.domain)) orelse return error.InvalidCompositionGeometry;
        const pair = logup.RowPairFor(S).single(entry.numerator, try challenges.get(domain).combine(entry.values[0..arity]));
        const root = logup.pairConstraintGeneric(S, secure(samples[2], table.interaction_col_offset, 0), secure(samples[2], table.interaction_col_offset, 1), samples[0][table.is_first_col_idx][0], symbolic_claims[i], pair);
        r.accumulate(&accumulation, alpha, root, try r.quotientDenominator(f.schema.logSize(table.kind), mask_log, symbolic_point, &denominators));
    }
    const evaluations = try a.alloc(S, chunk_count);
    for (evaluations, chunks) |*value, chunk| value.* = r.fromPartialEvals(chunk);
    const expected = try r.reconstructSplitComposition(evaluations, symbolic_point, composition_log, split);
    try builder.constrainZero(accumulation.sub(expected));
    var claim_sum = S.zero();
    for (symbolic_claims) |claim| claim_sum = claim_sum.add(claim);
    try builder.constrainZero(claim_sum);
    builder.deactivate();
    var circuit = try builder.finish();
    defer circuit.deinit();
    const values = try a.alloc(Q, circuit.nodes.len);
    try circuit.evaluateInto(inputs.items, values);
    for ([_]usize{ composition_start, claim_start, claim_start + F.Airs.len }) |index| {
        const saved = inputs.items[index];
        inputs.items[index] = saved.add(Q.one());
        try std.testing.expectError(error.UnsatisfiedCircuit, circuit.evaluateInto(inputs.items, values));
        inputs.items[index] = saved;
    }
    try circuit.evaluateInto(inputs.items, values);
    var pcs = try @import("blake3_stark_pcs_fixture.zig").prepare(a, capture, native, config);
    defer pcs.deinit();
    try @import("blake3_arithmetic_proof_fixture.zig").checkMany(a, &.{ circuit.graph(), pcs.deep_graph.graph(), pcs.fri_graph.graph() }, &.{ values, pcs.deep_evaluation.values, pcs.fri_evaluation.values });
}
fn input(a: std.mem.Allocator, builder: *r.Builder, values: *std.ArrayList(Q), value: Q) !S {
    try values.append(a, value);
    return (try builder.input()).value;
}
fn secure(columns: [][]S, offset: usize, sample: usize) S {
    var coordinates: [4]S = undefined;
    for (&coordinates, 0..) |*value, i| value.* = columns[offset + i][sample];
    return r.fromPartialEvals(coordinates);
}
