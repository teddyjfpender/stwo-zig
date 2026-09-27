const std = @import("std");
const core = @import("stwo_core");
const pack = @import("qm31_pack_wire.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
test "QM31 weighted packing preserves tuple identity and canonical sample links" {
    const a = std.testing.allocator;
    var definition = try pack.build(a);
    defer definition.deinit();
    const plan = try @import("universal_relation_binding.zig").Binding(pack).authenticate(&definition);
    const s = pack.Schedule{ .source_circuit = 1502, .source_nodes = .{ 4, 7, 9, 12 }, .destination_circuit = 1500, .destination_wire = 33 };
    const value = Q.fromU32Unchecked(1, 7, 11, 19);
    for ([_]u32{ 1, 7, core.fields.m31.Modulus - 1 }) |weight| {
        const row = try pack.weightedLogicalRow(s, value, weight);
        const fixed = try pack.weightedFixedRow(s, weight);
        try std.testing.expectEqualSlices(M, fixed[4..], row[4..]);
        const entries = plan.preparedEntries(row);
        for (entries[0..4], s.source_nodes, value.toM31Array()) |entry, node, coordinate| {
            const expected = [_]u32{ 1502, node, coordinate.v, 0, 0, 0 };
            for (entry.values[0..6], expected) |actual, word| try std.testing.expectEqual(word, (try actual.tryIntoM31()).v);
            try std.testing.expectEqual(core.fields.m31.Modulus - weight, (try entry.numerator.tryIntoM31()).v);
        }
        const expected = [_]u32{ 1500, 33, 1, 7, 11, 19 };
        for (entries[4].values[0..6], expected) |actual, word| try std.testing.expectEqual(word, (try actual.tryIntoM31()).v);
        try std.testing.expectEqual(weight, (try entries[4].numerator.tryIntoM31()).v);
    }
    try std.testing.expectError(error.InvalidQm31PackWire, pack.weightedFixedRow(s, 0));
    try std.testing.expectError(error.InvalidQm31PackWire, pack.weightedFixedRow(s, core.fields.m31.Modulus));
    const deep = @import("pcs_deep_circuit.zig");
    var graph = try deep.build(a, .{ .trees = &.{.{ .column_log_sizes = &.{4} }}, .sample_layouts = &.{.current}, .lifting_log_size = 4, .log_blowup_factor = 1, .query_count = 1 });
    defer graph.deinit();
    const links = @import("blake3_sample_links.zig");
    const mapped = try links.build(a, &graph, 1, 77);
    defer a.free(mapped);
    try std.testing.expectEqual(@as(u32, 77), mapped[0].composition);
    var changed: ?usize = null;
    for (graph.bindings, 0..) |binding, i| switch (binding.source) {
        .sampled_value_word => |source| {
            try std.testing.expectEqual(binding.node_id, mapped[source.sample].deep[source.word]);
            if (source.word == 1) changed = i;
        },
        else => {},
    };
    try std.testing.expectError(error.InvalidParentSampleLink, links.build(a, &graph, 2, 0));
    const i = changed orelse return error.MissingSampleCoordinate;
    graph.bindings[i].source.sampled_value_word.word = 0;
    try std.testing.expectError(error.InvalidParentSampleLink, links.build(a, &graph, 1, 0));
}
