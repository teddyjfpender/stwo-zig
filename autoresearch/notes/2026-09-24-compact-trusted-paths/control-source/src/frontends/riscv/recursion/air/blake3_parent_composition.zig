//! Recursive composition for the actual typed parent roster. Equations come
//! from authenticated typed programs and the shared lookup-table evaluator.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const r = @import("composition_graph_recorder.zig");
const S = r.Scalar;
const F = @import("blake3_native_parent_roster.zig").Roster;
const universal = @import("universal_challenges.zig");
const schema = @import("../../air/lookups/tables/schema.zig");
const tables_equations = @import("../../air/lookups/tables/equations.zig");
const logup = @import("../../air/logup.zig");
const shared = @import("blake3_execution_composition.zig");
const Source = shared.Source;
pub fn prepare(backing: std.mem.Allocator, admission: anytype, verified: *const @import("../blake3_native_parent_verifier.zig").Verified) !shared.Prepared {
    try verified.validate(admission, admission.expected_id);
    const owner = try @import("../blake3_native_parent_components.zig").Owned.init(backing, admission);
    defer owner.deinit();
    try owner.bind(verified.relations, verified.claims);
    const components = &owner.components;
    const tables = &owner.tables;
    const capture = &verified.capture;
    const relations = &verified.relations;
    const claims = &verified.claims;
    var arena = std.heap.ArenaAllocator.init(backing);
    errdefer arena.deinit();
    const a = arena.allocator();
    const native = owner.admitted();
    const composition_log = native.compositionLogDegreeBound();
    const split = try native.compositionLogSplit();
    const mask_log = core.verifier_types.compositionMaskLogSize(composition_log, split) orelse return error.InvalidCompositionGeometry;
    const point = core.circle.secureFieldPointFromRandomSeed(capture.oods_seed);
    var masks = try native.maskPoints(a, point, mask_log, false);
    defer masks.deinitDeep(a);
    // Derive the inventory from admitted components, never from capture lengths.
    if (capture.sampled_points.len != 4) return error.InvalidCompositionGeometry;
    if (masks.items.len != 3) return error.InvalidCompositionGeometry;
    var builder = r.Builder.init(backing);
    defer builder.deinit();
    var inputs: std.ArrayList(Q) = .empty;
    var sources: std.ArrayList(Source) = .empty;
    var samples: [3][][]S = undefined;
    var cursor: usize = 0;
    for (masks.items, &samples, capture.sampled_points[0..3]) |tree, *destination, captured_tree| {
        if (tree.len != captured_tree.len) return error.InvalidCompositionGeometry;
        destination.* = try a.alloc([]S, tree.len);
        for (tree, destination.*, captured_tree) |column, *values, captured_column| {
            if (column.len != captured_column.len) return error.InvalidCompositionGeometry;
            for (column, captured_column) |actual, expected| if (!actual.eql(expected)) return error.InvalidCompositionGeometry;
            values.* = try a.alloc(S, column.len);
            for (values.*) |*value| {
                if (cursor >= capture.sampled_values.len) return error.InvalidCompositionGeometry;
                value.* = try input(a, &builder, &inputs, &sources, .{ .sample = @intCast(cursor) }, capture.sampled_values[cursor]);
                cursor += 1;
            }
        }
    }
    const composition_start = cursor;
    const chunk_count = core.verifier_types.compositionChunkCount(split) orelse return error.InvalidCompositionGeometry;
    if (chunk_count * 4 != capture.sampled_points[3].len) return error.InvalidCompositionGeometry;
    const chunks = try a.alloc([4]S, chunk_count);
    for (chunks) |*chunk| for (chunk) |*value| {
        const column = capture.sampled_points[3][cursor - composition_start];
        if (column.len != 1 or !column[0].eql(point)) return error.InvalidCompositionGeometry;
        if (cursor >= capture.sampled_values.len) return error.InvalidCompositionGeometry;
        value.* = try input(a, &builder, &inputs, &sources, .{ .sample = @intCast(cursor) }, capture.sampled_values[cursor]);
        cursor += 1;
    };
    if (capture.sampled_values.len != cursor) return error.InvalidCompositionGeometry;
    const alpha = try input(a, &builder, &inputs, &sources, .composition, capture.composition_randomness);
    const seed = try input(a, &builder, &inputs, &sources, .oods, capture.oods_seed);
    var draws: [universal.RELATION_COUNT][2]S = undefined;
    for (&draws, relations.elements, 0..) |*draw, element, i| draw.* = .{ try input(a, &builder, &inputs, &sources, .{ .challenge = @intCast(2 * i) }, element.z), try input(a, &builder, &inputs, &sources, .{ .challenge = @intCast(2 * i + 1) }, element.alpha) };
    if (F.Airs.len + 2 != claims.len) return error.InvalidCompositionGeometry;
    const symbolic_claims = try a.alloc(S, claims.len);
    for (symbolic_claims, claims, 0..) |*symbolic, value, i| symbolic.* = try input(a, &builder, &inputs, &sources, .{ .claim = @intCast(i) }, value);
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    const symbolic_point = r.pointFromSeed(seed);
    const challenges = try r.ChallengeSet.init(draws);
    var denominators: r.DenominatorCache = @splat(null);
    var accumulation = S.zero();
    var recorded: usize = 0;
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
        const size = M.fromCanonical(@as(u32, 1) << @intCast(component.log_size));
        const shift = symbolic_claims[i].mul(S.fromBase(try size.inv()));
        recorded += try r.recordComponent(F.Component(Air).RelationRuntime, component, row, current, previous, shift, &challenges, alpha, try r.quotientDenominator(component.log_size, mask_log, symbolic_point, &denominators), &accumulation);
    }
    for (tables, F.Airs.len..) |table, i| {
        const arity = schema.arity(table.kind);
        var tuple: [schema.MAX_ARITY]S = undefined;
        for (tuple[0..arity], table.tuple_col_indices[0..arity]) |*value, column| value.* = samples[0][column][0];
        const entry = tables_equations.tableEntryGeneric(S, table.kind, tuple[0..arity], samples[1][table.main_col_offset][0]);
        const domain = std.meta.stringToEnum(@import("../../air/lang/relation.zig").Domain, @tagName(entry.domain)) orelse return error.InvalidCompositionGeometry;
        const pair = logup.RowPairFor(S).single(entry.numerator, try challenges.get(domain).combine(entry.values[0..arity]));
        const root = logup.pairConstraintGeneric(S, secure(samples[2], table.interaction_col_offset, 0), secure(samples[2], table.interaction_col_offset, 1), samples[0][table.is_first_col_idx][0], symbolic_claims[i], pair);
        recorded += 1;
        r.accumulate(&accumulation, alpha, root, try r.quotientDenominator(schema.logSize(table.kind), mask_log, symbolic_point, &denominators));
    }
    var expected_count: usize = 0;
    for (owner.verifiers) |component| expected_count += component.nConstraints();
    if (recorded != expected_count) return error.InvalidCompositionGeometry;
    const evaluations = try a.alloc(S, chunk_count);
    for (evaluations, chunks) |*value, chunk| value.* = r.fromPartialEvals(chunk);
    const expected = try r.reconstructSplitComposition(evaluations, symbolic_point, composition_log, split);
    try builder.constrainZero(accumulation.sub(expected));
    var claim_sum = S.zero();
    for (symbolic_claims) |claim| claim_sum = claim_sum.add(claim);
    try builder.constrainZero(claim_sum);
    builder.deactivate();
    var circuit = try builder.finish();
    errdefer circuit.deinit();
    const values = try a.alloc(Q, circuit.nodes.len);
    try circuit.evaluateInto(inputs.items, values);
    var result = shared.Prepared{ .arena = arena, .circuit = circuit, .inputs = inputs.items, .sources = sources.items, .values = values, .key_id = admission.expected_id, .capture_seal = verified.seal, .seal = undefined };
    result.seal = result.identity();
    return result;
}
fn input(a: std.mem.Allocator, builder: *r.Builder, inputs: *std.ArrayList(Q), sources: *std.ArrayList(Source), source: Source, value: Q) !S {
    const symbol = try builder.input();
    try inputs.append(a, value);
    try sources.append(a, source);
    return symbol.value;
}
fn secure(columns: [][]S, offset: usize, sample: usize) S {
    return r.fromPartialEvals(.{ columns[offset][sample], columns[offset + 1][sample], columns[offset + 2][sample], columns[offset + 3][sample] });
}
