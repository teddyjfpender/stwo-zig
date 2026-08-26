const std = @import("std");
const program_json = @import("../extract/program_json.zig");
const symbolic = @import("../extract/symbolic.zig");
const opcode_manifest = @import("../../opcode_manifest.zig");
const compat_layout = @import("compat_layout.zig");
const lower_air_ir = @import("lower_air_ir.zig");
const shadow_program = @import("shadow_program.zig");
const source = @import("source.zig");

test "typed compatibility path emits byte-identical LUI AIR IR v2" {
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .lui,
        source.SourceSpan.generated(),
    );
    defer imported.deinit();
    const layout = try compat_layout.build(&imported);

    var lowered = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer lowered.deinit();
    try lower_air_ir.emitLui(
        std.testing.allocator,
        &lowered.writer,
        &imported,
        &layout,
    );
    var production = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer production.deinit();
    try program_json.emitLui(std.testing.allocator, &production.writer);
    try std.testing.expectEqualSlices(u8, production.written(), lowered.written());
}

test "typed compatibility path emits every manifest AIR IR v2 byte exactly" {
    for (opcode_manifest.entries) |opcode| {
        var imported = try shadow_program.buildProduction(
            std.testing.allocator,
            opcode.family,
            source.SourceSpan.generated(),
        );
        defer imported.deinit();
        const layout = try compat_layout.build(&imported);

        var lowered = std.Io.Writer.Allocating.init(std.testing.allocator);
        defer lowered.deinit();
        try lower_air_ir.emitOpcode(
            std.testing.allocator,
            &lowered.writer,
            &imported,
            &layout,
            opcode,
        );
        var production = std.Io.Writer.Allocating.init(std.testing.allocator);
        defer production.deinit();
        try program_json.emitOpcode(
            std.testing.allocator,
            &production.writer,
            opcode,
        );
        try std.testing.expectEqualSlices(
            u8,
            production.written(),
            lowered.written(),
        );
    }
}

test "AIR IR compatibility owner rejects source schedule corruption" {
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .lui,
        source.SourceSpan.generated(),
    );
    defer imported.deinit();
    const layout = try compat_layout.build(&imported);
    const index = findCommutative(imported.imported.source_nodes).?;
    std.mem.swap(
        u32,
        &imported.imported.source_nodes[index].lhs,
        &imported.imported.source_nodes[index].rhs,
    );
    try std.testing.expectError(
        error.InvalidSymbolicNode,
        lower_air_ir.build(std.testing.allocator, &imported, &layout),
    );
}

test "AIR IR compatibility owner validator rejects corrupted formal state" {
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .lui,
        source.SourceSpan.generated(),
    );
    defer imported.deinit();
    const layout = try compat_layout.build(&imported);
    var lowered = try lower_air_ir.build(
        std.testing.allocator,
        &imported,
        &layout,
    );
    defer lowered.deinit();

    const one_index = lowered.program.column_count;
    const saved_one = lowered.arena.nodes.items[one_index];
    lowered.arena.nodes.items[one_index].value = 2;
    try std.testing.expectError(
        error.InvalidNode,
        lowered.validate(&imported, &layout),
    );
    lowered.arena.nodes.items[one_index] = saved_one;

    const direct_tail = lowered.program.production.direct_constraints.len;
    lowered.program.production.direct_constraints.values[direct_tail].id = 0;
    try std.testing.expectError(
        error.InvalidProgramShape,
        lowered.validate(&imported, &layout),
    );
    lowered.program.production.direct_constraints.values[direct_tail].id =
        std.math.maxInt(u32);

    const entry_tail: usize = lowered.program.production.lookup_entries.entries[0].arity;
    lowered.program.production.lookup_entries.entries[0].values[entry_tail].id = 0;
    try std.testing.expectError(
        error.InvalidProgramShape,
        lowered.validate(&imported, &layout),
    );
    lowered.program.production.lookup_entries.entries[0].values[entry_tail].id =
        std.math.maxInt(u32);

    const saved_event = lowered.program.projection.program_event;
    lowered.program.projection.program_event += 1;
    try std.testing.expectError(
        error.InvalidProgramShape,
        lowered.validate(&imported, &layout),
    );
    lowered.program.projection.program_event = saved_event;
    try lowered.validate(&imported, &layout);
}

test "AIR IR compatibility owner releases every partial allocation" {
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .div,
        source.SourceSpan.generated(),
    );
    defer imported.deinit();
    const layout = try compat_layout.build(&imported);
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        buildFailureCase,
        .{ &imported, &layout },
    );
}

fn buildFailureCase(
    allocator: std.mem.Allocator,
    imported: *const shadow_program.ImportedProgram,
    layout: *const compat_layout.Layout,
) !void {
    var lowered = try lower_air_ir.build(allocator, imported, layout);
    defer lowered.deinit();
}

fn findCommutative(nodes: []const symbolic.Node) ?usize {
    for (nodes, 0..) |node, index| {
        if ((node.op == .add or node.op == .mul) and node.lhs != node.rhs)
            return index;
    }
    return null;
}
