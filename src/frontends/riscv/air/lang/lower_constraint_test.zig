const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const runtime_program = @import("../extract/runtime_program.zig");
const symbolic = @import("../extract/symbolic.zig");
const trace = @import("../../runner/trace.zig");
const compat_layout = @import("compat_layout.zig");
const lower_constraint = @import("lower_constraint.zig");
const shadow_program = @import("shadow_program.zig");
const source = @import("source.zig");

const no_node = std.math.maxInt(u32);

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
    var normalized = try normalizeProduction(std.testing.allocator, &production);
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
        var normalized = try normalizeProduction(std.testing.allocator, &production);
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
            try replayProduction(&production, columns, production_values);
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

    const binary_index = findOp(program.nodes, .sub).?;
    const saved_binary = program.nodes[binary_index];
    program.nodes[binary_index].lhs = @intCast(binary_index);
    try std.testing.expectError(error.InvalidNode, program.validate());
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

const Normalized = struct {
    allocator: std.mem.Allocator,
    nodes: []symbolic.Node,
    roots: []u32,

    fn deinit(self: *Normalized) void {
        self.allocator.free(self.roots);
        self.allocator.free(self.nodes);
        self.* = undefined;
    }
};

/// Independent test oracle: linear-search interning intentionally does not use
/// the lowerer's hash-based canonical arena.
fn normalizeProduction(
    allocator: std.mem.Allocator,
    production: *const prover_component.OwnedBasePolynomialProgram,
) !Normalized {
    try production.validate();
    const reachable = try allocator.alloc(bool, production.nodes.len);
    defer allocator.free(reachable);
    @memset(reachable, false);
    for (production.roots) |root| reachable[root] = true;
    var reverse = production.nodes.len;
    while (reverse > 0) {
        reverse -= 1;
        if (!reachable[reverse]) continue;
        const node = production.nodes[reverse];
        switch (node.op) {
            .constant, .column => {},
            .add, .sub, .mul => {
                reachable[node.lhs] = true;
                reachable[node.rhs] = true;
            },
            .neg => reachable[node.lhs] = true,
        }
    }

    const mapped = try allocator.alloc(u32, production.nodes.len);
    defer allocator.free(mapped);
    @memset(mapped, no_node);
    var nodes: std.ArrayList(symbolic.Node) = .empty;
    defer nodes.deinit(allocator);
    for (0..production.column_count) |column| {
        _ = try referenceIntern(&nodes, allocator, .{
            .op = .column,
            .value = @intCast(column),
        });
    }
    for (production.nodes, 0..) |node, index| {
        if (node.op == .column) {
            if (node.value >= production.column_count)
                return error.InvalidProductionNode;
            mapped[index] = node.value;
            continue;
        }
        if (!reachable[index]) continue;
        mapped[index] = switch (node.op) {
            .constant => try referenceIntern(&nodes, allocator, .{
                .op = .constant,
                .value = node.value,
            }),
            .column => unreachable,
            .add, .sub, .mul => try referenceBinary(
                &nodes,
                allocator,
                @enumFromInt(@intFromEnum(node.op)),
                try referenceOperand(mapped, node.lhs),
                try referenceOperand(mapped, node.rhs),
            ),
            .neg => try referenceIntern(&nodes, allocator, .{
                .op = .neg,
                .lhs = try referenceOperand(mapped, node.lhs),
            }),
        };
    }
    const roots = try allocator.alloc(u32, production.roots.len);
    errdefer allocator.free(roots);
    for (production.roots, roots) |root, *normalized_root|
        normalized_root.* = try referenceOperand(mapped, root);
    return .{
        .allocator = allocator,
        .nodes = try nodes.toOwnedSlice(allocator),
        .roots = roots,
    };
}

fn referenceIntern(
    nodes: *std.ArrayList(symbolic.Node),
    allocator: std.mem.Allocator,
    node: symbolic.Node,
) !u32 {
    for (nodes.items, 0..) |existing, index| {
        if (std.meta.eql(existing, node)) return @intCast(index);
    }
    const id: u32 = @intCast(nodes.items.len);
    try nodes.append(allocator, node);
    return id;
}

fn referenceBinary(
    nodes: *std.ArrayList(symbolic.Node),
    allocator: std.mem.Allocator,
    op: symbolic.Op,
    lhs: u32,
    rhs: u32,
) !u32 {
    var node = symbolic.Node{ .op = op, .lhs = lhs, .rhs = rhs };
    if ((op == .add or op == .mul) and node.rhs < node.lhs)
        std.mem.swap(u32, &node.lhs, &node.rhs);
    return referenceIntern(nodes, allocator, node);
}

fn referenceOperand(mapped: []const u32, source_node: u32) !u32 {
    if (source_node >= mapped.len or mapped[source_node] == no_node)
        return error.InvalidProductionNode;
    return mapped[source_node];
}

fn replayProduction(
    production: *const prover_component.OwnedBasePolynomialProgram,
    columns: []const M31,
    values: []M31,
) !void {
    try production.validate();
    if (columns.len != production.column_count or values.len != production.nodes.len)
        return error.InvalidProductionReplay;
    for (production.nodes, values) |node, *value| {
        value.* = switch (node.op) {
            .constant => M31.fromCanonical(node.value),
            .column => columns[node.value],
            .add => values[node.lhs].add(values[node.rhs]),
            .sub => values[node.lhs].sub(values[node.rhs]),
            .mul => values[node.lhs].mul(values[node.rhs]),
            .neg => values[node.lhs].neg(),
        };
    }
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
