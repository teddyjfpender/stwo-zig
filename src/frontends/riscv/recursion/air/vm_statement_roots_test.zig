const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const graph = @import("composition_circuit.zig");
const roots = @import("vm_statement_roots.zig");
const component = @import("vm_air_composition_input.zig");
const witness = @import("vm_air_composition_input_witness.zig");
const interaction = @import("vm_air_composition_input_relation.zig");
const statement = @import("statement_input.zig");

test "VM field binding publishers preserve V1 words and reject root profile before writing" {
    const Writer = struct {
        values: [4]u32 = .{0} ** 4,
        count: usize = 0,
        pub fn word(self: *@This(), value: anytype) !void {
            self.values[self.count] = @intCast(value);
            self.count += 1;
        }
    };
    const encode = @import("../vm_binding_field_encoding_v1.zig").encode;
    const cases = [_]struct { source: graph.VmSource, words: [4]u32 }{
        .{ .source = .segment_selector, .words = .{ 42, 1, 0, 0 } },
        .{ .source = .{ .sampled_value = .{ .item_index = 3, .word_index = 2 } }, .words = .{ 42, 2, 3, 2 } },
        .{ .source = .{ .claimed_sum = .{ .item_index = 4, .word_index = 1 } }, .words = .{ 42, 3, 4, 1 } },
        .{ .source = .{ .relation_challenge = .{ .challenge = 5, .word_index = 6 } }, .words = .{ 42, 4, 5, 6 } },
        .{ .source = .{ .composition_randomness = 2 }, .words = .{ 42, 5, 2, 0 } },
        .{ .source = .{ .oods_point = 3 }, .words = .{ 42, 6, 3, 0 } },
        .{ .source = .{ .transcript_claimed_sum = .{ .item_index = 8, .word_index = 2 } }, .words = .{ 42, 7, 8, 2 } },
    };
    for (cases) |case| {
        var writer = Writer{};
        try encode(&writer, .{ .node_id = 42, .source = case.source });
        try std.testing.expectEqual(@as(usize, 4), writer.count);
        try std.testing.expectEqualSlices(u32, &case.words, &writer.values);
    }
    var writer = Writer{};
    try std.testing.expectError(error.StatementRootsRequireNewFieldEncoding, encode(&writer, .{
        .node_id = 42,
        .source = .{ .statement_word = roots.word_indices[0] },
    }));
    try std.testing.expectEqual(@as(usize, 0), writer.count);
}

test "VM statement root profile preserves legacy ordering and rejects ambiguous admission" {
    const legacy = graph.InputProfile{ .sampled_value_count = 3, .claimed_sum_count = 2, .relation_challenge_count = 1 };
    var profile = legacy;
    profile.vm_statement_root_count = 2;
    const prefix = try graph.vmInputCount(legacy);
    try std.testing.expectEqual(prefix + 2, try graph.vmInputCount(profile));
    for (0..prefix) |index|
        try std.testing.expectEqualDeep(graph.expectedVmSource(legacy, index), graph.expectedVmSource(profile, index));
    try std.testing.expectEqual(@as(u8, 6), @intFromEnum(std.meta.activeTag(@as(graph.VmSource, .{ .transcript_claimed_sum = .{ .item_index = 0, .word_index = 0 } }))));
    for (roots.word_indices, 0..) |word, index| {
        try std.testing.expectEqualDeep(@as(?graph.VmSource, .{ .statement_word = word }), graph.expectedVmSource(profile, prefix + index));
        try std.testing.expect(word < statement.CANONICAL_WORD_COUNT);
    }
    try std.testing.expect(graph.expectedVmSource(profile, prefix + 2) == null);
    try std.testing.expectError(error.InvalidInputSource, graph.recursionInputCount(profile));
    profile.vm_statement_root_count = 1;
    try std.testing.expectError(error.InvalidInputSource, graph.vmInputCount(profile));
    profile.vm_statement_root_count = 3;
    try std.testing.expectError(error.InvalidInputSource, graph.vmInputCount(profile));
}

test "VM statement root rows consume the canonical statement relation" {
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try interaction.authenticate(&definition);
    for (roots.word_indices) |word| {
        const row = witness.Row{
            .classification = .{ .vm_input = .{ .statement_word = word } },
            .circuit_id = 7,
            .node_id = 9,
            .use_count = 2,
        };
        const value = M31.fromCanonical(12345);
        const entries = try plan.entries(&definition.arena, component.SEMANTIC_DIGEST, definition.events, try witness.logicalRow(row, value, .segment_leaf));
        const statement_entry = entries[6];
        try std.testing.expectEqual(@as(u8, 3), statement_entry.arity);
        try std.testing.expect(statement_entry.numerator.eql(QM31.one().neg()));
        try std.testing.expect(statement_entry.values[0].eql(QM31.fromBase(M31.fromCanonical(statement.SEGMENT_STATEMENT_SCOPE))));
        try std.testing.expect(statement_entry.values[1].eql(QM31.fromBase(M31.fromCanonical(word))));
        try std.testing.expect(statement_entry.values[2].eql(QM31.fromBase(value)));
        try std.testing.expect(entries[7].numerator.eql(QM31.fromBase(M31.fromCanonical(2))));
        try std.testing.expectError(error.InvalidWitnessValue, witness.logicalRow(row, value, .binary_node));
    }
    const invalid = witness.Row{ .classification = .{ .vm_input = .{ .statement_word = 0 } }, .circuit_id = 7, .node_id = 9, .use_count = 1 };
    try std.testing.expectError(error.InvalidInputSource, witness.logicalRow(invalid, M31.one(), .segment_leaf));
}
