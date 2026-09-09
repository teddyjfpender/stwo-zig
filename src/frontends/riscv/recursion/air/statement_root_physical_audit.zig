//! Physical admission regression: replay-only checks cannot see column swaps.
const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const profile = @import("../incremental_ethereum_composition_profile_v4.zig");
const provider = profile.StatementRootProvider;
const legacy = @import("statement_input.zig");
const witness = @import("statement_input_witness.zig");
const roots = @import("vm_statement_roots.zig");
const universal = @import("universal_challenges.zig");
const manifest_mod = @import("universal_adapter_manifest.zig");
const typed = @import("universal_typed_component.zig");
const framework = @import("framework_interaction.zig");
const Adapter = typed.Component(provider, provider.Relation);
const Framework = framework.Runtime(provider.Relation.Runtime);
const recorder = @import("composition_graph_recorder.zig");

test "statement root physical admission matches native and recursive evaluation" {
    var words: @import("../span_statement.zig").StatementWords = undefined;
    for (&words, 0..) |*word, index| word.* = M31.fromU64(index + 100);
    try audit(std.testing.allocator, &words);
}

test "statement root catalog derives the full physical manifest without changing legacy rows" {
    const manifests = @import("universal_manifest.zig");
    var logs = [_]u32{11} ** @import("universal_roster.zig").COMPONENT_COUNT;
    logs[@intFromEnum(manifest_mod.ComponentKey.range_check_8_8)] = @import("range_check_8_8_bridge.zig").LOG_SIZE;
    const old = try manifests.build(logs);
    const selected = try manifests.buildForCatalog(profile.StatementRootOuterCatalog, logs);
    try std.testing.expectEqual(old.total_preprocessed_columns + 1, selected.total_preprocessed_columns);
    try std.testing.expectEqual(old.total_main_columns, selected.total_main_columns);
    try std.testing.expectEqual(old.total_interaction_columns, selected.total_interaction_columns);
    try std.testing.expect(!std.meta.eql(old.seal, selected.seal));
    for (old.placements, selected.placements) |before, after| {
        const prior = before orelse continue;
        const current = after orelse return error.TestUnexpectedResult;
        if (prior.geometry.roster_row == @intFromEnum(manifest_mod.ComponentKey.statement_input)) {
            try std.testing.expectEqualDeep(Adapter.manifestGeometry(.statement_input, 11), current.geometry);
        } else try std.testing.expectEqualDeep(prior.geometry, current.geometry);
    }
}

/// Cold diagnostic for a real statement: no outer proof capability is issued.
pub fn audit(allocator: std.mem.Allocator, words: *const @import("../span_statement.zig").StatementWords) !void {
    var definition = try provider.build(allocator);
    defer definition.deinit();
    const plan = try provider.Relation.authenticate(&definition);
    var pp = try witness.Preprocessed.init(allocator);
    defer pp.deinit();
    const size = @as(usize, 1) << @intCast(pp.log_size);
    const storage = try allocator.alloc(M31, size * provider.PREPROCESSED_COLUMN_COUNT);
    defer allocator.free(storage);
    var columns: [provider.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
    for (&columns, 0..) |*column, index| column.* = storage[index * size ..][0..size];
    try provider.Routing.fillPreprocessedInto(&pp, &columns);
    for (pp.rows, 0..) |row, index| {
        for (columns, provider.Routing.preprocessing(row)) |column, expected|
            try std.testing.expect(column[index].eql(expected));
    }
    for (columns) |column| for (column[pp.rows.len..]) |value|
        try std.testing.expect(value.isZero());
    var aliases = columns;
    aliases[7] = columns[0];
    try std.testing.expectError(error.AliasedDestination, provider.Routing.fillPreprocessedInto(&pp, &aliases));
    try std.testing.expect(columns[7][roots.word_indices[0]].eql(M31.one()));

    const rows = try allocator.alloc(provider.Relation.Row, pp.rows.len);
    defer allocator.free(rows);
    for (rows, pp.rows) |*row, preprocessing|
        row.* = try provider.Routing.logicalRow(preprocessing, .{ .segment_leaf = words });
    const relations = universal.UniversalRelations.dummy();
    var interaction = try Framework.generatePrepared(allocator, &plan, rows, pp.log_size, &relations);
    defer interaction.deinit(allocator);
    var builder = manifest_mod.Builder{};
    _ = try builder.append(Adapter.manifestGeometry(.statement_input, pp.log_size));
    const manifest = try builder.seal();
    const component = try Adapter.init(&definition, plan, &manifest, .statement_input, pp.log_size, witness.parameters(.segment_leaf), &relations, interaction.claimed_sum);
    try std.testing.expectEqual(pp.log_size + 2, component.maxConstraintLogDegreeBound());
    var recorded = try recordPhysicalComponent(allocator, &component);
    defer recorded.deinit();

    // A V2 manifest cannot admit this component even with otherwise valid rows.
    const OldAdapter = typed.Component(legacy, @import("statement_input_relation.zig"));
    var old_builder = manifest_mod.Builder{};
    _ = try old_builder.append(OldAdapter.manifestGeometry(.statement_input, pp.log_size));
    const old_manifest = try old_builder.seal();
    try std.testing.expectError(error.InvalidProofShape, Adapter.init(&definition, plan, &old_manifest, .statement_input, pp.log_size, witness.parameters(.segment_leaf), &relations, interaction.claimed_sum));

    // Feed physical trees through the verifier callback, not its logical-row
    // shortcut. Nonzero, distinct parameters catch the former slot-9 swap.
    for (roots.word_indices) |word| {
        var sample = Samples{};
        const logical = rows[word];
        sample.main[0][0] = QM31.fromBase(logical[0]);
        sample.main[1][0] = QM31.fromBase(logical[1]);
        for (&sample.preprocessing, columns) |*destination, column|
            destination[0] = QM31.fromBase(column[word]);
        const current = framework.committedRow(word, pp.log_size);
        const previous = framework.committedRow((word + size - 1) % size, pp.log_size);
        for (&sample.interaction, interaction.columns, 0..) |*destination, column, index| {
            destination[0] = QM31.fromBase(column[if (index < 4) current else previous]);
            destination[1] = QM31.fromBase(column[current]);
        }
        try std.testing.expect((try sample.evaluate(&component)).isZero());
        try sample.checkRecorded(allocator, &component, &recorded);
        sample.preprocessing[7][0] = QM31.zero();
        try std.testing.expect(!(try sample.evaluate(&component)).isZero());
        try sample.checkRecorded(allocator, &component, &recorded);
    }
}

const Samples = struct {
    preprocessing: [provider.PREPROCESSED_COLUMN_COUNT][1]QM31 = undefined,
    main: [provider.PHYSICAL_MAIN_COLUMN_COUNT][1]QM31 = undefined,
    interaction: [provider.INTERACTION_COLUMN_COUNT][2]QM31 = undefined,

    fn checkRecorded(self: *Samples, allocator: std.mem.Allocator, component: *const Adapter, circuit: *const recorder.Circuit) !void {
        var inputs: [15]QM31 = undefined;
        for (inputs[0..2], self.main) |*value, column| value.* = column[0];
        for (inputs[2..10], self.preprocessing) |*value, column| value.* = column[0];
        inputs[10] = self.secureInteraction(0, 0);
        inputs[11] = self.secureInteraction(1, 1);
        inputs[12] = self.secureInteraction(1, 0);
        inputs[13] = component.claimed_sum_shift;
        inputs[14] = try self.evaluate(component);
        const evaluated = try allocator.alloc(QM31, circuit.nodes.len);
        defer allocator.free(evaluated);
        try circuit.evaluateInto(&inputs, evaluated);
        for (circuit.outputs) |output| try std.testing.expect(evaluated[output].isZero());
    }

    fn secureInteraction(self: *const Samples, batch: usize, point: usize) QM31 {
        var coordinates: [4]QM31 = undefined;
        for (&coordinates, 0..) |*value, index| value.* = self.interaction[4 * batch + index][point];
        return QM31.fromPartialEvals(coordinates);
    }

    fn evaluate(self: *Samples, component: *const Adapter) !QM31 {
        var pp: [provider.PREPROCESSED_COLUMN_COUNT][]QM31 = undefined;
        var main: [provider.PHYSICAL_MAIN_COLUMN_COUNT][]QM31 = undefined;
        var interaction: [provider.INTERACTION_COLUMN_COUNT][]QM31 = undefined;
        for (&pp, &self.preprocessing) |*column, *values| column.* = values;
        for (&main, &self.main) |*column, *values| column.* = values;
        for (&interaction, &self.interaction, 0..) |*column, *values, index|
            column.* = values[0..if (index < 4) @as(usize, 1) else 2];
        var trees = [_][][]QM31{ &pp, &main, &interaction };
        var sampled = core.pcs.TreeVec([][]QM31).initOwned(&trees);
        var accumulator = core.air.accumulation.PointEvaluationAccumulator.init(QM31.fromBase(M31.fromCanonical(17)));
        try component.evaluateConstraintQuotientsAtPoint(core.circle.SECURE_FIELD_CIRCLE_GEN, &sampled, &accumulator, component.log_size);
        return accumulator.finalize();
    }
};

/// Record once; replay authentic and mutated physical values under that same
/// circuit. Statement values and the proof's claimed sum are graph inputs.
fn recordPhysicalComponent(allocator: std.mem.Allocator, component: *const Adapter) !recorder.Circuit {
    var builder = recorder.Builder.init(allocator);
    defer builder.deinit();
    var inputs: [15]recorder.Scalar = undefined;
    for (&inputs) |*input| input.* = (try builder.input()).value;
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    var row: [provider.LOGICAL_INPUT_COUNT]recorder.Scalar = undefined;
    @memcpy(row[0..10], inputs[0..10]);
    for (row[10..], component.parameters) |*value, parameter| value.* = recorder.Scalar.fromBase(parameter);
    var draws: [universal.RELATION_COUNT][2]recorder.Scalar = undefined;
    for (&draws, component.relations.elements) |*pair, element|
        pair.* = .{ recorder.Scalar.fromSecure(element.z), recorder.Scalar.fromSecure(element.alpha) };
    const challenges = try recorder.ChallengeSet.init(draws);
    const inverse = try core.constraints.cosetVanishing(QM31, core.poly.circle.canonic.CanonicCoset.new(component.log_size).coset(), core.circle.SECURE_FIELD_CIRCLE_GEN).inv();
    var accumulation = recorder.Scalar.zero();
    _ = try recorder.recordComponent(provider.Relation.Runtime, component, row, inputs[10..12].*, inputs[12], inputs[13], &challenges, recorder.Scalar.fromBase(M31.fromCanonical(17)), recorder.Scalar.fromSecure(inverse), &accumulation);
    try builder.constrainZero(accumulation.sub(inputs[14]));
    builder.deactivate();
    return builder.finish();
}
