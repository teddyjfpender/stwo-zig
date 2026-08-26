const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const runtime_program = @import("../extract/runtime_program.zig");
const symbolic = @import("../extract/symbolic.zig");
const trace = @import("../../runner/trace.zig");
const compat_layout = @import("compat_layout.zig");
const lower_constraint = @import("lower_constraint.zig");
const oracle = @import("lower_test_oracle.zig");
const shadow_program = @import("shadow_program.zig");
const source = @import("source.zig");

test "LUI direct lowering exactly matches an independently normalized production DAG" {
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .lui,
        source.SourceSpan.generated(),
    );
    defer imported.deinit();
    const layout = try compat_layout.build(&imported);
    var lowered = try lower_constraint.lower(
        std.testing.allocator,
        &imported,
        &layout,
    );
    defer lowered.deinit();

    var production = try runtime_program.build(std.testing.allocator, .lui);
    defer production.deinit();
    var normalized = try oracle.normalizeBase(std.testing.allocator, &production);
    defer normalized.deinit();

    try std.testing.expectEqual(production.column_count, lowered.columnCount());
    try std.testing.expectEqualSlices(symbolic.Node, normalized.nodes, lowered.nodes);
    try std.testing.expectEqualSlices(u32, normalized.roots, lowered.roots);

    var second = try lower_constraint.lower(
        std.testing.allocator,
        &imported,
        &layout,
    );
    defer second.deinit();
    try std.testing.expectEqualSlices(symbolic.Node, lowered.nodes, second.nodes);
    try std.testing.expectEqualSlices(u32, lowered.roots, second.roots);
}

test "direct lowering exactly normalizes and replays every production family root" {
    var prng = std.Random.DefaultPrng.init(0x434f_4d50_4154_4431);
    const random = prng.random();
    for (0..trace.N_FAMILIES) |family_index| {
        const family: trace.OpcodeFamily = @enumFromInt(family_index);
        var imported = try shadow_program.buildProduction(
            std.testing.allocator,
            family,
            source.SourceSpan.generated(),
        );
        defer imported.deinit();
        const layout = try compat_layout.build(&imported);
        var lowered = try lower_constraint.lower(
            std.testing.allocator,
            &imported,
            &layout,
        );
        defer lowered.deinit();
        var production = try runtime_program.build(std.testing.allocator, family);
        defer production.deinit();
        var normalized = try oracle.normalizeBase(std.testing.allocator, &production);
        defer normalized.deinit();

        try std.testing.expectEqual(production.column_count, lowered.columnCount());
        try std.testing.expectEqual(production.roots.len, lowered.roots.len);
        try std.testing.expectEqualSlices(symbolic.Node, normalized.nodes, lowered.nodes);
        try std.testing.expectEqualSlices(u32, normalized.roots, lowered.roots);
        const columns = try std.testing.allocator.alloc(M31, production.column_count);
        defer std.testing.allocator.free(columns);
        const production_values = try std.testing.allocator.alloc(M31, production.nodes.len);
        defer std.testing.allocator.free(production_values);
        const lowered_values = try std.testing.allocator.alloc(M31, lowered.nodes.len);
        defer std.testing.allocator.free(lowered_values);
        for (0..4) |sample| {
            for (columns[0 .. columns.len - 1]) |*column|
                column.* = M31.fromU64(random.int(u32));
            columns[columns.len - 1] = M31.fromU64(sample & 1);
            try oracle.replayBase(&production, columns, production_values);
            try lowered.replay(columns, lowered_values);
            for (production.roots, lowered.roots) |production_root, lowered_root| {
                try std.testing.expect(
                    production_values[production_root].eql(lowered_values[lowered_root]),
                );
            }
        }
    }
}

test "direct lowering validator rejects corrupted normalized programs" {
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .lui,
        source.SourceSpan.generated(),
    );
    defer imported.deinit();
    const layout = try compat_layout.build(&imported);
    var program = try lower_constraint.lower(
        std.testing.allocator,
        &imported,
        &layout,
    );
    defer program.deinit();

    const saved_column_count = program.column_count;
    program.column_count = 0;
    try std.testing.expectError(error.InvalidColumnLayout, program.validate());
    program.column_count = saved_column_count;

    const saved_first = program.nodes[0];
    program.nodes[0] = .{ .op = .constant, .value = 0 };
    try std.testing.expectError(error.InvalidColumnLayout, program.validate());
    program.nodes[0] = saved_first;

    const constant_index = findOp(program.nodes, .constant).?;
    const saved_constant = program.nodes[constant_index];
    program.nodes[constant_index].value = std.math.maxInt(u32);
    try std.testing.expectError(error.InvalidConstant, program.validate());
    program.nodes[constant_index] = saved_constant;
    program.nodes[constant_index].lhs = 1;
    try std.testing.expectError(error.NonCanonicalNode, program.validate());
    program.nodes[constant_index] = saved_constant;

    const binary_index = findOp(program.nodes, .sub).?;
    const saved_binary = program.nodes[binary_index];
    program.nodes[binary_index].lhs = @intCast(binary_index);
    try std.testing.expectError(error.InvalidNode, program.validate());
    program.nodes[binary_index] = saved_binary;
    program.nodes[binary_index].value = 1;
    try std.testing.expectError(error.NonCanonicalNode, program.validate());
    program.nodes[binary_index] = saved_binary;

    const commutative_index = findNontrivialCommutative(program.nodes).?;
    const saved_commutative = program.nodes[commutative_index];
    std.mem.swap(
        u32,
        &program.nodes[commutative_index].lhs,
        &program.nodes[commutative_index].rhs,
    );
    try std.testing.expectError(error.NonCanonicalNode, program.validate());
    program.nodes[commutative_index] = saved_commutative;

    const duplicate_index = program.nodes.len - 1;
    const saved_last = program.nodes[duplicate_index];
    program.nodes[duplicate_index] = program.nodes[duplicate_index - 1];
    try std.testing.expectError(error.DuplicateNode, program.validate());
    program.nodes[duplicate_index] = saved_last;

    const saved_root = program.roots[0];
    program.roots[0] = std.math.maxInt(u32);
    try std.testing.expectError(error.InvalidRoot, program.validate());
    program.roots[0] = saved_root;
    try program.validate();
}

test "direct lowering replay rejects malformed buffers" {
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .lui,
        source.SourceSpan.generated(),
    );
    defer imported.deinit();
    const layout = try compat_layout.build(&imported);
    var program = try lower_constraint.lower(
        std.testing.allocator,
        &imported,
        &layout,
    );
    defer program.deinit();
    const columns = [_]M31{M31.zero()} ** 1;
    const values = try std.testing.allocator.alloc(M31, program.nodes.len);
    defer std.testing.allocator.free(values);
    try std.testing.expectError(
        error.InvalidReplayColumns,
        program.replay(&columns, values),
    );
    const valid_columns = try std.testing.allocator.alloc(M31, program.columnCount());
    defer std.testing.allocator.free(valid_columns);
    @memset(valid_columns, M31.zero());
    try std.testing.expectError(
        error.InvalidReplayBuffer,
        program.replay(valid_columns, values[0 .. values.len - 1]),
    );
}

test "direct lowering releases every partial allocation" {
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .div,
        source.SourceSpan.generated(),
    );
    defer imported.deinit();
    const layout = try compat_layout.build(&imported);
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        lowerFailureCase,
        .{ &imported, &layout },
    );
}

fn lowerFailureCase(
    allocator: std.mem.Allocator,
    imported: *const shadow_program.ImportedProgram,
    layout: *const compat_layout.Layout,
) !void {
    var lowered = try lower_constraint.lower(allocator, imported, layout);
    defer lowered.deinit();
}

fn findOp(nodes: []const symbolic.Node, op: symbolic.Op) ?usize {
    for (nodes, 0..) |node, index| if (node.op == op) return index;
    return null;
}

fn findNontrivialCommutative(nodes: []const symbolic.Node) ?usize {
    for (nodes, 0..) |node, index| {
        if ((node.op == .add or node.op == .mul) and node.lhs < node.rhs)
            return index;
    }
    return null;
}
