const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const legacy = @import("statement_input.zig");
const provider = @import("statement_input_roots_v3.zig");
const witness = @import("statement_input_witness.zig");
const vm = @import("vm_air_composition_input_witness.zig");
const roots = @import("vm_statement_roots.zig");

test "statement root routing authenticates fixed multiplicities without changing V2" {
    var definition = try provider.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try provider.Relation.authenticate(&definition);
    var old = try legacy.build(std.testing.allocator);
    defer old.deinit();
    const old_plan = try @import("statement_input_relation.zig").authenticate(&old);
    var pp = try witness.Preprocessed.init(std.testing.allocator);
    defer pp.deinit();
    const words = [_]M31{M31.one()} ** legacy.CANONICAL_WORD_COUNT;
    const modes = [_]witness.StatementWitness{
        .{ .segment_leaf = &words },
        .{ .binary_node = .{ .left = &words, .right = &words, .parent = &words } },
        .empty_leaf,
    };
    var extra: usize = 0;
    for (pp.rows) |row| {
        extra += provider.Routing.extraUses(row);
        for (modes) |mode| {
            const old_entries = old_plan.preparedEntries(try witness.logicalRow(row, mode));
            const new_entries = plan.preparedEntries(try provider.Routing.logicalRow(row, mode));
            for (old_entries, new_entries, 0..) |before, after, index| {
                var expected = before;
                if (index == 1 and mode.proofKind() == .segment_leaf)
                    expected.numerator = expected.numerator.add(core.fields.qm31.QM31.fromBase(M31.fromCanonical(provider.Routing.extraUses(row))));
                try std.testing.expectEqualDeep(expected, after);
            }
        }
    }
    try std.testing.expectEqual(@as(usize, 2), extra);
    const identity = try provider.Routing.identity(&pp);
    pp.rows[0].word_index += 1;
    try std.testing.expectError(error.AuthorityMismatch, provider.Routing.identity(&pp));
    pp.rows[0].word_index -= 1;
    try std.testing.expectEqual(identity, try provider.Routing.identity(&pp));
    const profile = try @import("../../air/lang/static_profile.zig").collect(std.testing.allocator, &definition.arena, .{
        .physical_main_columns = provider.PHYSICAL_MAIN_COLUMN_COUNT,
        .lookup_layout = .{ .batch_size = provider.LOOKUP_BATCH_SIZE, .interaction_coordinates_per_batch = 4 },
    });
    try profile.validate();
    try std.testing.expectEqual(@as(u32, 15), profile.logical_input_nodes);
    try std.testing.expectEqual(@as(u32, 2), profile.constraint_roots);
    try std.testing.expectEqual(@as(u32, 4), profile.lookup_events);
    try std.testing.expectEqual(@as(u32, 3), profile.maximum_logical_constraint_degree);
    try std.testing.expectEqual(@as(?u32, 4), profile.maximum_modeled_interaction_degree);
    try std.testing.expectEqual(@as(u32, 27), profile.expression_dag_nodes);
    try std.testing.expectEqual(@as(u32, 0), profile.nodes_outside_constraint_effect_closure);
    definition.arena.effects.items[1].liveness = old.arena.effects.items[1].liveness;
    try std.testing.expectError(error.InvalidStatementRootRoutingDefinition, definition.validate());
}

test "statement root routing closes actual AIR consumers and rejects missing duplicate altered roots" {
    var words: @import("../span_statement.zig").StatementWords = undefined;
    for (&words, 0..) |*word, index| word.* = M31.fromCanonical(@intCast(index));
    var rows: [3]vm.Row = undefined;
    var values: [3]M31 = undefined;
    for (roots.word_indices, 0..) |word, index| {
        rows[index] = .{ .classification = .{ .vm_input = .{ .statement_word = word } }, .circuit_id = 7, .node_id = @intCast(index), .use_count = 1 };
        values[index] = words[word];
    }
    const audit = @import("../statement_root_routing_audit.zig").audit;
    try audit(std.testing.allocator, &words, rows[0..2], values[0..2]);
    try std.testing.expectError(error.StatementRootRoutingNotClosed, audit(std.testing.allocator, &words, rows[0..1], values[0..1]));
    rows[2] = rows[0];
    values[2] = values[0];
    try std.testing.expectError(error.StatementRootRoutingNotClosed, audit(std.testing.allocator, &words, &rows, &values));
    values[0] = values[0].add(M31.one());
    try std.testing.expectError(error.StatementRootRoutingNotClosed, audit(std.testing.allocator, &words, rows[0..2], values[0..2]));
}
