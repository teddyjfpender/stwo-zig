const std = @import("std");
const circuit = @import("composition_circuit_blake3.zig");
const legacy = @import("composition_circuit.zig");
const profile = circuit.InputProfile{ .sampled_value_count = 0, .claimed_sum_count = 0, .relation_challenge_count = 0 };

test "BLAKE3 composition compiler maps every statement word without shifted randomness" {
    try std.testing.expectEqual(@as(usize, 537), try circuit.recursionInputCount(profile));
    for (0..525) |i| try std.testing.expectEqual(circuit.RecursionSource{ .statement_word = @intCast(i) }, circuit.expectedRecursionSource(profile, 4 + i).?);
    for (0..4) |i| {
        try std.testing.expectEqual(circuit.RecursionSource{ .composition_randomness = @intCast(i) }, circuit.expectedRecursionSource(profile, 529 + i).?);
        try std.testing.expectEqual(circuit.RecursionSource{ .oods_point = @intCast(i) }, circuit.expectedRecursionSource(profile, 533 + i).?);
    }
    try std.testing.expect(circuit.expectedRecursionSource(profile, 537) == null);
    var unsupported = profile;
    unsupported.field_public_extra_word_count = 38;
    try std.testing.expectError(error.InvalidInputSource, circuit.recursionInputCount(unsupported));
    unsupported = profile;
    unsupported.vm_statement_root_count = 2;
    try std.testing.expectError(error.InvalidInputSource, circuit.vmInputCount(unsupported));
}

test "BLAKE3 composition compiler authenticates full statement schedule and rejects substitutions" {
    var vm_nodes: [12]circuit.Node = undefined;
    var recursion_nodes: [540]circuit.Node = undefined;
    fillGraph(&vm_nodes, 9);
    fillGraph(&recursion_nodes, 537);
    const vm_outputs = [_]u32{11};
    const recursion_outputs = [_]u32{539};
    var vm_bindings: [9]circuit.VmInputBinding = undefined;
    var recursion_bindings: [537]circuit.RecursionInputBinding = undefined;
    for (&vm_bindings, 0..) |*binding, i| binding.* = .{ .node_id = @intCast(i), .source = circuit.expectedVmSource(profile, i).? };
    for (&recursion_bindings, 0..) |*binding, i| binding.* = .{ .node_id = @intCast(i), .source = circuit.expectedRecursionSource(profile, i).? };
    const vm = circuit.VmLane{
        .circuit_id = 7,
        .profile = profile,
        .bindings = &vm_bindings,
        .graph = try circuit.CircuitGraph.authenticate(&vm_nodes, &vm_outputs, circuit.computeGraphDigest(&vm_nodes, &vm_outputs)),
    };
    const lanes = [_]circuit.RecursionLane{.{
        .verifier_id = 1,
        .circuit_id = 9,
        .statement_scope = 1,
        .profile = profile,
        .bindings = &recursion_bindings,
        .graph = try circuit.CircuitGraph.authenticate(&recursion_nodes, &recursion_outputs, circuit.computeGraphDigest(&recursion_nodes, &recursion_outputs)),
    }};
    try std.testing.expectError(error.MissingCircuitAnchor, circuit.Reference.authenticate(vm, &lanes, &.{}, circuit.computeReferenceDigest(vm, &lanes, &.{})));
    const anchors = [_]circuit.AnchorLane{.{ .circuit_id = 9, .graph = lanes[0].graph, .active_in = .BINARY }};
    const reference = try circuit.Reference.authenticate(vm, &lanes, &anchors, circuit.computeReferenceDigest(vm, &lanes, &anchors));
    var compiled = try circuit.compile(std.testing.allocator, &reference);
    defer compiled.deinit();
    try circuit.validateCompiledRows(compiled.rows);
    var words: usize = 0;
    var last: ?usize = null;
    for (compiled.rows, 0..) |row, i| {
        if (row.classification != .recursion_input) continue;
        const source = row.classification.recursion_input.source;
        if (source != .statement_word) continue;
        try std.testing.expectEqual(words, source.statement_word);
        words += 1;
        last = i;
    }
    try std.testing.expectEqual(@as(usize, 525), words);
    compiled.rows[last.?].classification.recursion_input.source.statement_word = 525;
    try std.testing.expectError(error.InvalidInputSource, circuit.validateCompiledRows(compiled.rows));
    recursion_bindings[528].source.statement_word = 0;
    try std.testing.expectError(error.InvalidInputSource, reference.validate());
    // Identical graph operations belong to distinct format authority domains.
    var legacy_nodes: [12]legacy.Node = undefined;
    for (&legacy_nodes, 0..) |*node, i| node.* = if (i < 9) .{ .op = .input } else switch (i) {
        9 => .{ .op = .{ .constant = .{ 1, 2, 3, 4 } } },
        10 => .{ .op = .{ .add = .{ .lhs = 0, .rhs = 9 } } },
        else => .{ .op = .{ .neg = 10 } },
    };
    const old_seal = legacy.computeGraphDigest(&legacy_nodes, &vm_outputs);
    try std.testing.expectError(error.GraphSealMismatch, circuit.CircuitGraph.authenticate(&vm_nodes, &vm_outputs, old_seal));
}

fn fillGraph(nodes: []circuit.Node, count: usize) void {
    for (nodes[0..count]) |*node| node.* = .{ .op = .input };
    nodes[count] = .{ .op = .{ .constant = .{ 1, 2, 3, 4 } } };
    nodes[count + 1] = .{ .op = .{ .add = .{ .lhs = 0, .rhs = @intCast(count) } } };
    nodes[count + 2] = .{ .op = .{ .neg = @intCast(count + 1) } };
}
