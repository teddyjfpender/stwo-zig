//! V5 child-parent verifier: actual typed parent equations plus the child
//! external public-supply closure. Every changing tuple coordinate is a
//! routed graph input; no instance value is embedded in the fixed graph.
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
pub const Compiled = struct {
    arena: std.heap.ArenaAllocator,
    circuit: r.Circuit,
    sources: []Source,
    pub fn deinit(self: *Compiled) void {
        self.circuit.deinit();
        self.arena.deinit();
        self.* = undefined;
    }
};
/// Compile the SAME original equations from independent logs and typed public
/// routing. This type contains no assignments, capture, receipt or verifier key.
pub fn compileShape(backing: std.mem.Allocator, admission: anytype) !Compiled {
    try admission.validate();
    const shape = try @import("../block_v5_recursive_parent_shape_v1.zig").Shape.initForAdmission(backing, admission, .{});
    defer shape.deinit();
    const owner = try @import("../blake3_native_parent_components.zig").Owned.init(backing, admission);
    defer owner.deinit();
    const manifest = F.Manifest{ .log_sizes = owner.logs };
    var arena = std.heap.ArenaAllocator.init(backing);
    errdefer arena.deinit();
    const a = arena.allocator();
    const split = shape.composition_split;
    const mask_log = shape.mask_log;
    const composition_log = try std.math.add(u32, mask_log, split);
    var builder = r.Builder.init(backing);
    defer builder.deinit();
    var sources: std.ArrayList(Source) = .empty;
    var samples: [3][][]S = undefined;
    var cursor: usize = 0;
    var layout_cursor: usize = 0;
    for (shape.columns[0..3], &samples) |tree, *destination| {
        destination.* = try a.alloc([]S, tree.len);
        for (destination.*) |*symbols| {
            symbols.* = try a.alloc(S, shape.layouts[layout_cursor].sampleCount());
            layout_cursor += 1;
            for (symbols.*) |*symbol| {
                symbol.* = try shapeInput(a, &builder, &sources, .{ .sample = @intCast(cursor) });
                cursor += 1;
            }
        }
    }
    const chunk_count = core.verifier_types.compositionChunkCount(split) orelse return error.InvalidCompositionGeometry;
    const chunks = try a.alloc([4]S, chunk_count);
    for (chunks) |*chunk| for (chunk) |*value| {
        value.* = try shapeInput(a, &builder, &sources, .{ .sample = @intCast(cursor) });
        cursor += 1;
    };
    const alpha = try shapeInput(a, &builder, &sources, .composition);
    const seed = try shapeInput(a, &builder, &sources, .oods);
    var draws: [universal.RELATION_COUNT][2]S = undefined;
    for (&draws, 0..) |*draw, i| draw.* = .{ try shapeInput(a, &builder, &sources, .{ .challenge = @intCast(2 * i) }), try shapeInput(a, &builder, &sources, .{ .challenge = @intCast(2 * i + 1) }) };
    const symbolic_claims = try a.alloc(S, F.Airs.len + 2);
    for (symbolic_claims, 0..) |*symbolic, i| symbolic.* = try shapeInput(a, &builder, &sources, .{ .claim = @intCast(i) });
    const public_coordinates = try a.alloc([4]S, admission.source.terms.len);
    for (public_coordinates, 0..) |*tuple, i| {
        for (tuple, 0..) |*symbolic, j| {
            symbolic.* = try shapeInput(a, &builder, &sources, .{ .packed_public_input = @intCast(4 * i + j) });
        }
    }
    const spans = admission.pc_clock_children;
    const span_inputs = try a.alloc([6]S, spans.len);
    for (spans, span_inputs, 0..) |span, *destination, i| {
        try @import("../block_v5_open_parent_public_bus_v1.zig").validateSpanBound(span);
        for (destination, 0..) |*symbolic, j|
            symbolic.* = try shapeInput(a, &builder, &sources, .{ .public_input = @intCast(4 * admission.source.terms.len + 6 * i + j) });
    }
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    const symbolic_point = r.pointFromSeed(seed);
    const challenges = try r.ChallengeSet.init(draws);
    var denominators: r.DenominatorCache = @splat(null);
    var accumulation = S.zero();
    var recorded: usize = 0;
    inline for (F.Airs, 0..) |Air, i| {
        // Geometry-only component view: no claims/challenges or verifier token.
        const definition = &owner.definitions[i];
        const component = .{
            .placement = try manifest.placement(@enumFromInt(i)),
            .parameters = if (@hasDecl(Air, "PROOF_KIND_PARAMETER_COUNT")) @import("blake3_native_parent_rows.zig").selectors else [0]M{},
            .log_size = owner.logs[i],
            .direct = try @import("direct_constraint_program.zig").authenticate(&definition.arena, Air.SEMANTIC_DIGEST, Air.LOGICAL_INPUT_COUNT),
            .relation_plan = owner.plans[i],
        };
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
    for ([_]schema.Kind{ .bitwise, .range_check_8_8 }, owner.table_pp, 0..) |kind, pp_offset, table_index| {
        const i = F.Airs.len + table_index;
        var tuple_columns: [schema.MAX_ARITY]usize = undefined;
        for (tuple_columns[0..schema.arity(kind)], 0..) |*column, j| column.* = pp_offset + 1 + j;
        const table = .{ .kind = kind, .tuple_col_indices = tuple_columns, .main_col_offset = owner.table_main + table_index, .interaction_col_offset = owner.table_interaction + 4 * table_index, .is_first_col_idx = pp_offset };
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
    inline for (F.Airs) |Air| expected_count += Air.DIRECT_CONSTRAINT_COUNT + Air.INTERACTION_BATCH_COUNT;
    expected_count += 2 * @import("../../air/lookups/tables/verifier.zig").N_CONSTRAINTS;
    if (recorded != expected_count) return error.InvalidCompositionGeometry;
    const evaluations = try a.alloc(S, chunk_count);
    for (evaluations, chunks) |*value, chunk| value.* = r.fromPartialEvals(chunk);
    const expected = try r.reconstructSplitComposition(evaluations, symbolic_point, composition_log, split);
    try builder.constrainZero(accumulation.sub(expected));
    var claim_sum = S.zero();
    for (symbolic_claims) |claim| claim_sum = claim_sum.add(claim);
    // This is symbolic under the child proof's actual transcript challenges,
    // not a host-evaluated scalar substituted for the verifier equation.
    for (admission.source.terms, public_coordinates) |wire, coordinates| {
        const tuple = [_]S{ S.fromBase(M.fromCanonical(wire.circuit)), S.fromBase(M.fromCanonical(wire.wire)) } ++ coordinates;
        const denominator = try challenges.get(.recursion_wire).combine(&tuple);
        const term = S.fromBase(M.fromCanonical(wire.uses)).mul(denominator.inverse());
        claim_sum = if (wire.negative) claim_sum.sub(term) else claim_sum.add(term);
    }
    // Exact integer interpretation comes from independently admitted public
    // bounds below 2^30; field equality cannot wrap these adjacent edges.
    if (span_inputs.len != 0) {
        if (span_inputs.len > 32) return error.InvalidV5NestedFanIn;
        for (span_inputs[0 .. span_inputs.len - 1], span_inputs[1..]) |left, right| {
            try builder.constrainZero(left[0].add(left[1]).sub(right[0]));
            try builder.constrainZero(left[3].add(S.fromBase(M.one())).sub(right[2]));
            try builder.constrainZero(left[5].sub(right[4]));
        }
    }
    try builder.constrainZero(claim_sum);
    builder.deactivate();
    var circuit = try builder.finish();
    errdefer circuit.deinit();
    return .{ .arena = arena, .circuit = circuit, .sources = sources.items };
}
/// Live verification keeps every original capture/mask/custody check. The
/// independent compiler above is the only implementation of its equations.
pub fn prepare(backing: std.mem.Allocator, admission: anytype, verified: *const @import("../blake3_native_parent_verifier.zig").Verified) !shared.Prepared {
    try verified.validate(admission, admission.expected_id);
    if (verified.public_input_digest == null) return error.MissingV5RecursivePublicInputs;
    const owner = try @import("../blake3_native_parent_components.zig").Owned.init(backing, admission);
    defer owner.deinit();
    try owner.bind(verified.relations, verified.claims);
    const native = owner.admitted();
    const composition_log = native.compositionLogDegreeBound();
    const split = try native.compositionLogSplit();
    const mask_log = core.verifier_types.compositionMaskLogSize(composition_log, split) orelse return error.InvalidCompositionGeometry;
    const capture = &verified.capture;
    const point = core.circle.secureFieldPointFromRandomSeed(capture.oods_seed);
    var masks = try native.maskPoints(backing, point, mask_log, false);
    defer masks.deinitDeep(backing);
    if (capture.sampled_points.len != 4 or masks.items.len != 3) return error.InvalidCompositionGeometry;
    var count: usize = 0;
    for (masks.items, capture.sampled_points[0..3]) |tree, captured_tree| {
        if (tree.len != captured_tree.len) return error.InvalidCompositionGeometry;
        for (tree, captured_tree) |column, captured_column| {
            if (column.len != captured_column.len) return error.InvalidCompositionGeometry;
            for (column, captured_column) |actual, expected| if (!actual.eql(expected)) return error.InvalidCompositionGeometry;
            count = try std.math.add(usize, count, column.len);
        }
    }
    const chunk_count = core.verifier_types.compositionChunkCount(split) orelse return error.InvalidCompositionGeometry;
    if (chunk_count * 4 != capture.sampled_points[3].len) return error.InvalidCompositionGeometry;
    for (capture.sampled_points[3]) |column| {
        if (column.len != 1 or !column[0].eql(point)) return error.InvalidCompositionGeometry;
        count = try std.math.add(usize, count, 1);
    }
    if (capture.sampled_values.len != count or F.Airs.len + 2 != verified.claims.len) return error.InvalidCompositionGeometry;
    var compiled = try compileShape(backing, admission);
    errdefer compiled.deinit();
    const a = compiled.arena.allocator();
    const inputs = try a.alloc(Q, compiled.sources.len);
    for (compiled.sources, inputs) |source, *value| value.* = switch (source) {
        .sample => |i| capture.sampled_values[i],
        .composition => capture.composition_randomness,
        .oods => capture.oods_seed,
        .challenge => |i| if (i % 2 == 0) verified.relations.elements[i / 2].z else verified.relations.elements[i / 2].alpha,
        .claim => |i| verified.claims[i],
        .packed_public_input => |i| Q.fromBase(admission.source.terms[i / 4].coordinates[i % 4]),
        .public_input => |i| block: {
            const relative = i - @as(u32, @intCast(4 * admission.source.terms.len));
            const words = @import("../block_v5_open_parent_public_bus_v1.zig").spanWords(admission.pc_clock_children[relative / 6]);
            break :block Q.fromBase(M.fromCanonical(words[relative % 6]));
        },
    };
    const values = try a.alloc(Q, compiled.circuit.nodes.len);
    try compiled.circuit.evaluateInto(inputs, values);
    var result = shared.Prepared{ .arena = compiled.arena, .circuit = compiled.circuit, .inputs = inputs, .sources = compiled.sources, .values = values, .key_id = admission.expected_id, .capture_seal = verified.seal, .seal = undefined };
    result.seal = result.identity();
    return result;
}
fn shapeInput(a: std.mem.Allocator, builder: *r.Builder, sources: *std.ArrayList(Source), source: Source) !S {
    const symbol = try builder.input();
    try sources.append(a, source);
    return symbol.value;
}
fn secure(columns: [][]S, offset: usize, sample: usize) S {
    return r.fromPartialEvals(.{ columns[offset][sample], columns[offset + 1][sample], columns[offset + 2][sample], columns[offset + 3][sample] });
}
