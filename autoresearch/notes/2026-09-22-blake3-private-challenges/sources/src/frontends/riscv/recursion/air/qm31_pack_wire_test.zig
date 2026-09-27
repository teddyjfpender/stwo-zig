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
    graph.bindings[i].source.sampled_value_word.word = 1;
    const fri = @import("fri_verifier_circuit.zig");
    var fg = try fri.build(a, .{ .lifting_log_size = 4, .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .fold_widths = &.{ 2, 2, 2 }, .query_count = 1 });
    defer fg.deinit();
    const challenges = @import("blake3_challenge_links.zig");
    const sequence = @import("blake3_transcript_witness.zig");
    const roles = [_]sequence.OutputRole{ .{ .universal = 0 }, .composition, .oods, .deep, .{ .fri = 0 }, .{ .fri = 1 }, .{ .fri = 2 } };
    var outputs: [roles.len]sequence.DrawOutput = undefined;
    for (&outputs, roles, 0..) |*output, role, j| output.* = .{ .operation = j, .role = role, .source = .{ .circuit = @intCast(100 + j), .first_wire = 0 }, .words = if (j == 0) 8 else 4 };
    const sources = challenges.Sources{ .sample_start = 0, .claim_start = 50, .composition = 20, .oods = 21, .universal_start = 30 };
    const connected = try challenges.build(a, &outputs, sources, &graph, &fg, 1, 3);
    defer a.free(connected);
    try std.testing.expectEqual(@as(usize, 8), connected.len);
    try std.testing.expectEqual(@as(?u32, 30), connected[0].composition);
    try std.testing.expectEqual(@as(?u32, 31), connected[1].composition);
    try std.testing.expectEqual(@as(u32, 4), connected[1].source.first_wire);
    try std.testing.expectEqual(@as(?u32, 20), connected[2].composition);
    try std.testing.expectEqual(@as(?u32, 21), connected[3].composition);
    try std.testing.expectEqual(@as(usize, 1), connected[3].scalar.?.lane);
    try std.testing.expectEqual(@as(usize, 2), connected[5].scalar.?.lane);
    try std.testing.expectError(error.InvalidParentChallengeLink, challenges.build(a, outputs[1..], sources, &graph, &fg, 1, 3));
    const saved = outputs[1];
    outputs[1].role = .oods;
    try std.testing.expectError(error.InvalidParentChallengeLink, challenges.build(a, &outputs, sources, &graph, &fg, 1, 3));
    outputs[1] = saved;
    outputs[0].words = 4;
    try std.testing.expectError(error.InvalidParentChallengeLink, challenges.build(a, &outputs, sources, &graph, &fg, 1, 3));
    outputs[0].words = 8;
    for (fg.bindings) |*binding| switch (binding.source) {
        .fri_alpha_word => |source| if (source.layer == 0 and source.word == 1) {
            binding.source.fri_alpha_word.word = 0;
            try std.testing.expectError(error.InvalidParentChallengeLink, challenges.build(a, &outputs, sources, &graph, &fg, 1, 3));
            binding.source.fri_alpha_word.word = 1;
            break;
        },
        else => {},
    };
    const terminal = @import("blake3_terminal_links.zig");
    var joined = try terminal.build(a, &graph, &fg, 1, 1);
    defer joined.deinit();
    try std.testing.expectEqual(@as(usize, 4), joined.answers.len);
    try std.testing.expectEqual(@as(usize, 1), joined.coefficients.len);
    try std.testing.expectError(error.InvalidParentTerminalLink, terminal.build(a, &graph, &fg, 2, 1));
    try std.testing.expectError(error.InvalidParentTerminalLink, terminal.build(a, &graph, &fg, 1, 2));
    var duplicate: ?usize = null;
    for (fg.bindings, 0..) |binding, j| switch (binding.source) {
        .last_layer_coefficient_word => |source| if (source.word == 1) {
            duplicate = j;
        },
        else => {},
    };
    fg.bindings[duplicate orelse return error.MissingCoefficientCoordinate].source.last_layer_coefficient_word.word = 0;
    try std.testing.expectError(error.InvalidParentTerminalLink, terminal.build(a, &graph, &fg, 1, 1));
}
