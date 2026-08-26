const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const constraint_program = @import("../constraint_program.zig");
const model = @import("../extract/model.zig");
const symbolic = @import("../extract/symbolic.zig");
const trace = @import("../../runner/trace.zig");
const degree = @import("degree.zig");
const shadow_import = @import("shadow_import.zig");
const source = @import("source.zig");
const types = @import("types.zig");

const Builder = constraint_program.Builder(symbolic.Scalar);
const differential_seed: u64 = 0x5459_5045_4441_4952;

test "shadow import preserves replay while canonicalizing equivalent nodes" {
    var source_arena = symbolic.Arena.init(std.testing.allocator);
    defer source_arena.deinit();
    symbolic.begin(&source_arena);
    const x = source_arena.column("x");
    const y = source_arena.column("y");
    const sum_xy = x.add(y);
    const sum_yx = y.add(x);
    const product_xy = x.mul(y);
    const product_yx = y.mul(x);
    const wrapped = symbolic.Scalar.constant(m31.Modulus + 17);
    _ = sum_xy.sub(product_xy).neg().add(wrapped);
    symbolic.end();

    var imported = try shadow_import.import(
        std.testing.allocator,
        &source_arena,
        source.SourceSpan.generated(),
    );
    defer imported.deinit();

    try std.testing.expectEqualSlices(
        symbolic.Node,
        source_arena.nodes.items,
        imported.source_nodes,
    );
    try imported.validateSourceCopy();

    try std.testing.expectEqual(
        imported.valueForSourceNode(sum_xy.id).?,
        imported.valueForSourceNode(sum_yx.id).?,
    );

    const saved_source = imported.source_nodes[sum_xy.id];
    std.mem.swap(
        u32,
        &imported.source_nodes[sum_xy.id].lhs,
        &imported.source_nodes[sum_xy.id].rhs,
    );
    try std.testing.expectError(
        error.InvalidSymbolicNode,
        imported.validateSourceCopy(),
    );
    imported.source_nodes[sum_xy.id] = saved_source;
    try imported.validateSourceCopy();
    try std.testing.expectEqual(
        imported.valueForSourceNode(product_xy.id).?,
        imported.valueForSourceNode(product_yx.id).?,
    );
    try std.testing.expect(imported.arena.nodeCount() < source_arena.nodes.items.len);
    try std.testing.expectEqual(
        @as(?types.ValueId, null),
        imported.valueForSourceNode(std.math.maxInt(u32)),
    );

    const column_values = [_]m31.M31{
        m31.M31.fromCanonical(2_000_000_000),
        m31.M31.fromCanonical(37),
    };
    try expectReplayEquivalent(&source_arena, &imported, &column_values);
}

test "shadow import differentially replays every production family" {
    var prng = std.Random.DefaultPrng.init(differential_seed);
    const random = prng.random();
    var sample_values: [trace.MAX_FAMILY_COLUMNS + 1]m31.M31 = undefined;

    for (0..trace.N_FAMILIES) |family_index| {
        const family: trace.OpcodeFamily = @enumFromInt(family_index);
        var production = try buildFamilySource(std.testing.allocator, family);
        defer production.deinit();
        var imported = try shadow_import.import(
            std.testing.allocator,
            &production.arena,
            source.SourceSpan.generated(),
        );
        defer imported.deinit();

        try std.testing.expectEqual(
            production.arena.names.items.len,
            imported.columns.len,
        );
        try std.testing.expect(
            imported.arena.nodeCount() <= production.arena.nodes.items.len,
        );
        for (0..8) |_| {
            for (sample_values[0..production.arena.names.items.len]) |*value|
                value.* = m31.M31.fromU64(random.int(u32));
            try expectReplayEquivalent(
                &production.arena,
                &imported,
                sample_values[0..production.arena.names.items.len],
            );
        }
    }
}

test "shadow import preserves independent degree analysis for every production family" {
    for (0..trace.N_FAMILIES) |family_index| {
        const family: trace.OpcodeFamily = @enumFromInt(family_index);
        var production = try buildFamilySource(std.testing.allocator, family);
        defer production.deinit();
        var imported = try shadow_import.import(
            std.testing.allocator,
            &production.arena,
            source.SourceSpan.generated(),
        );
        defer imported.deinit();
        const source_degrees = try symbolicDegreeOracle(
            std.testing.allocator,
            &production.arena,
        );
        defer std.testing.allocator.free(source_degrees);
        var imported_degrees = try degree.analyze(
            std.testing.allocator,
            &imported.arena,
        );
        defer imported_degrees.deinit();

        for (source_degrees, imported.source_to_value) |expected, imported_id| {
            try std.testing.expectEqual(expected, imported_degrees.value(imported_id).?);
        }
        for (production.roots) |root| {
            const imported_root = imported.valueForSourceNode(root).?;
            try std.testing.expectEqual(
                source_degrees[root],
                imported_degrees.value(imported_root).?,
            );
        }
        try std.testing.expectEqual(
            maximumDegree(source_degrees),
            imported_degrees.maximumValueDegree(),
        );
    }
}

test "shadow import owns source names and rejects ambiguous schemas" {
    const owned_name = try std.testing.allocator.dupe(u8, "ephemeral");
    defer std.testing.allocator.free(owned_name);
    var source_arena = symbolic.Arena.init(std.testing.allocator);
    defer source_arena.deinit();
    _ = source_arena.column(owned_name);

    var imported = try shadow_import.import(
        std.testing.allocator,
        &source_arena,
        source.SourceSpan.generated(),
    );
    defer imported.deinit();
    @memset(owned_name, 'z');
    const imported_node = imported.arena.node(imported.columns[0]).?;
    try std.testing.expectEqualStrings(
        "ephemeral",
        imported.arena.name(imported_node.key.op.input).?,
    );

    var duplicate = symbolic.Arena.init(std.testing.allocator);
    defer duplicate.deinit();
    _ = duplicate.column("same");
    _ = duplicate.column("same");
    try std.testing.expectError(
        error.DuplicateSymbolicColumnName,
        shadow_import.import(
            std.testing.allocator,
            &duplicate,
            source.SourceSpan.generated(),
        ),
    );

    var empty = symbolic.Arena.init(std.testing.allocator);
    defer empty.deinit();
    _ = empty.column("");
    try std.testing.expectError(
        error.EmptySymbolicColumnName,
        shadow_import.import(
            std.testing.allocator,
            &empty,
            source.SourceSpan.generated(),
        ),
    );
}

test "shadow import rejects malformed source graphs and replay buffers" {
    var missing_column = symbolic.Arena.init(std.testing.allocator);
    defer missing_column.deinit();
    try missing_column.names.append(std.testing.allocator, "orphan");
    try std.testing.expectError(
        error.MissingSymbolicColumn,
        shadow_import.import(
            std.testing.allocator,
            &missing_column,
            source.SourceSpan.generated(),
        ),
    );

    var invalid_intern = symbolic.Arena.init(std.testing.allocator);
    defer invalid_intern.deinit();
    _ = invalid_intern.column("x");
    try std.testing.expect(invalid_intern.interned.remove(invalid_intern.nodes.items[0]));
    try std.testing.expectError(
        error.InvalidSymbolicInternTable,
        shadow_import.import(
            std.testing.allocator,
            &invalid_intern,
            source.SourceSpan.generated(),
        ),
    );

    var invalid_node = symbolic.Arena.init(std.testing.allocator);
    defer invalid_node.deinit();
    _ = invalid_node.column("x");
    const valid_column = invalid_node.nodes.items[0];
    try std.testing.expect(invalid_node.interned.remove(valid_column));
    invalid_node.nodes.items[0].value = 1;
    try invalid_node.interned.put(invalid_node.nodes.items[0], 0);
    try std.testing.expectError(
        error.InvalidSymbolicNode,
        shadow_import.import(
            std.testing.allocator,
            &invalid_node,
            source.SourceSpan.generated(),
        ),
    );

    var duplicate_column = symbolic.Arena.init(std.testing.allocator);
    defer duplicate_column.deinit();
    _ = duplicate_column.column("first");
    _ = duplicate_column.column("second");
    const second_column = duplicate_column.nodes.items[1];
    try std.testing.expect(duplicate_column.interned.remove(second_column));
    duplicate_column.nodes.items[1].value = 0;
    duplicate_column.nodes.items[1].lhs = 1;
    try duplicate_column.interned.put(duplicate_column.nodes.items[1], 1);
    try std.testing.expectError(
        error.DuplicateSymbolicColumn,
        shadow_import.import(
            std.testing.allocator,
            &duplicate_column,
            source.SourceSpan.generated(),
        ),
    );

    var valid = symbolic.Arena.init(std.testing.allocator);
    defer valid.deinit();
    _ = valid.column("x");
    var imported = try shadow_import.import(
        std.testing.allocator,
        &valid,
        source.SourceSpan.generated(),
    );
    defer imported.deinit();
    var out = [_]m31.M31{m31.M31.zero()};
    try std.testing.expectError(
        error.InvalidColumnCount,
        imported.replay(&.{}, &out),
    );
    try std.testing.expectError(
        error.InvalidReplayBuffer,
        imported.replay(&.{m31.M31.one()}, &.{}),
    );
    imported.column_for_value[0] = std.math.maxInt(u32);
    try std.testing.expectError(
        error.MissingImportedColumn,
        imported.replay(&.{m31.M31.one()}, &out),
    );
    imported.arena.nodes.items[0].key.op = .{ .hint_output = .{
        .hint = @enumFromInt(0),
        .index = 0,
    } };
    try std.testing.expectError(
        error.UnsupportedReplayNode,
        imported.replay(&.{m31.M31.one()}, &out),
    );
}

const FamilySource = struct {
    allocator: std.mem.Allocator,
    arena: symbolic.Arena,
    roots: []u32,

    fn deinit(self: *FamilySource) void {
        self.allocator.free(self.roots);
        self.arena.deinit();
        self.* = undefined;
    }
};

fn buildFamilySource(
    allocator: std.mem.Allocator,
    family: trace.OpcodeFamily,
) !FamilySource {
    var arena = symbolic.Arena.init(allocator);
    errdefer arena.deinit();
    symbolic.begin(&arena);
    defer symbolic.end();

    const main_column_count = Builder.mainColumnCount(family);
    var columns: [trace.MAX_FAMILY_COLUMNS]symbolic.Scalar = undefined;
    try model.declareColumns(&arena, family, columns[0..main_column_count]);
    const selector = arena.column("is_active");
    const direct = (try Builder.buildDirect(
        family,
        columns[0..main_column_count],
        selector,
    )).direct_constraints;
    const roots = try allocator.alloc(u32, direct.len);
    for (direct.values[0..direct.len], roots) |constraint, *root|
        root.* = constraint.id;
    return .{ .allocator = allocator, .arena = arena, .roots = roots };
}

/// Independent recurrence over the shipped six-op DAG. Keeping this separate
/// from `degree.analyze` makes agreement evidence rather than self-comparison.
fn symbolicDegreeOracle(
    allocator: std.mem.Allocator,
    arena: *const symbolic.Arena,
) ![]degree.Degree {
    const result = try allocator.alloc(degree.Degree, arena.nodes.items.len);
    errdefer allocator.free(result);
    for (arena.nodes.items, result) |node, *slot| {
        slot.* = switch (node.op) {
            .constant => 0,
            .column => 1,
            .add, .sub => @max(result[node.lhs], result[node.rhs]),
            .mul => try std.math.add(
                degree.Degree,
                result[node.lhs],
                result[node.rhs],
            ),
            .neg => result[node.lhs],
        };
    }
    return result;
}

fn maximumDegree(degrees: []const degree.Degree) degree.Degree {
    var maximum: degree.Degree = 0;
    for (degrees) |item| maximum = @max(maximum, item);
    return maximum;
}

fn expectReplayEquivalent(
    source_arena: *const symbolic.Arena,
    imported: *const shadow_import.Imported,
    column_values: []const m31.M31,
) !void {
    const source_out = try std.testing.allocator.alloc(
        m31.M31,
        source_arena.nodes.items.len,
    );
    defer std.testing.allocator.free(source_out);
    const imported_out = try std.testing.allocator.alloc(
        m31.M31,
        imported.arena.nodeCount(),
    );
    defer std.testing.allocator.free(imported_out);

    symbolic.replay(source_arena, column_values, source_out);
    try imported.replay(column_values, imported_out);
    for (source_out, imported.source_to_value) |source_value, imported_id| {
        try std.testing.expectEqual(
            source_value.toU32(),
            imported_out[types.idIndex(imported_id)].toU32(),
        );
    }
}

fn allocationFailureCase(
    allocator: std.mem.Allocator,
    source_arena: *const symbolic.Arena,
) !void {
    var imported = try shadow_import.import(
        allocator,
        source_arena,
        source.SourceSpan.generated(),
    );
    defer imported.deinit();
}

test "shadow import releases every partial allocation" {
    var production = try buildFamilySource(
        std.testing.allocator,
        .base_alu_reg,
    );
    defer production.deinit();
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{&production.arena},
    );
}
