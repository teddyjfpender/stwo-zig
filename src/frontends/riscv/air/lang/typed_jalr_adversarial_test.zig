const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const support = @import("typed_jalr_test_support.zig");
const typed_jalr = @import("typed_jalr.zig");
const types = @import("types.zig");

test "typed JALR named low-bit immediate target link destination and source mutations reject" {
    var authored = try typed_jalr.build(std.testing.allocator, .generated);
    defer authored.deinit();
    const bindings = support.typedBindings(&authored);
    const values = try std.testing.allocator.alloc(M31, authored.arena.nodeCount());
    defer std.testing.allocator.free(values);
    const base = try support.honestRow(.{
        .rs1_value = 0x0100_0000,
        .immediate = 5,
    });
    const mutations = [_]struct { name: []const u8, column: usize }{
        .{ .name = "enabler", .column = 0 },
        .{ .name = "placement selector", .column = 41 },
        .{ .name = "target over two", .column = 23 },
        .{ .name = "cleared low bit", .column = 24 },
        .{ .name = "signed immediate", .column = 25 },
        .{ .name = "link byte", .column = 26 },
        .{ .name = "destination nonzero", .column = 30 },
        .{ .name = "destination inverse", .column = 31 },
        .{ .name = "target low20", .column = 32 },
        .{ .name = "target high8", .column = 33 },
        .{ .name = "target byte", .column = 34 },
        .{ .name = "immediate byte", .column = 38 },
        .{ .name = "immediate nibble", .column = 39 },
        .{ .name = "immediate sign", .column = 40 },
        .{ .name = "destination result", .column = 9 },
        .{ .name = "source emitted value", .column = 19 },
        .{ .name = "source consumed value", .column = 15 },
    };
    for (mutations) |mutation| {
        var row = base;
        row[mutation.column] = row[mutation.column].add(M31.one());
        try support.evaluateInto(&authored.arena, &bindings, &row, values);
        if (support.rowAccepted(&authored, values)) {
            std.log.err("accepted typed JALR mutation: {s}", .{mutation.name});
            return error.MutationAccepted;
        }
    }
}

test "typed JALR fixed tables reject direct-root-valid immediate target result and gap forgeries" {
    var authored = try typed_jalr.build(std.testing.allocator, .generated);
    defer authored.deinit();
    const bindings = support.typedBindings(&authored);
    const values = try std.testing.allocator.alloc(M31, authored.arena.nodeCount());
    defer std.testing.allocator.free(values);

    // Rebind an otherwise consistent row to the unsigned immediate 2048. The
    // direct byte-carry equations remain zero, but the refined nibble is 16.
    var immediate = try support.honestRow(.{
        .rs1_value = 0x1000,
        .immediate = 0,
    });
    immediate[23] = M31.fromCanonical(0x0c00);
    immediate[25] = M31.fromCanonical(2048);
    immediate[32] = M31.fromCanonical(0x600);
    immediate[34] = M31.zero();
    immediate[35] = M31.fromCanonical(0x18);
    immediate[36] = M31.zero();
    immediate[37] = M31.zero();
    immediate[39] = M31.fromCanonical(8);
    try expectRangeOnlyRejection(&authored, &bindings, &immediate, values);

    // target/4 = 2^28 has high8 = 256. Its target bytes and direct equations
    // are valid, but it lies just outside the committed program domain.
    const target_bound = try support.witnessRow(.{
        .rs1_value = 0x4000_0000,
        .immediate = 0,
    });
    try expectRangeOnlyRejection(&authored, &bindings, &target_bound, values);

    // A link at 2^31+4 has a high byte of 128: only the production M31 outer
    // byte table rejects it.
    const result_bound = try support.honestRow(.{
        .rs1_value = 0x1000,
        .immediate = 0,
        .pc = 0x8000_0000,
    });
    try expectRangeOnlyRejection(&authored, &bindings, &result_bound, values);

    // Negative strict gap encodes near the field modulus and cannot enter the
    // ordinal-one range20 table.
    var clock_gap = try support.honestRow(.{
        .rs1_value = 0x1000,
        .immediate = 0,
    });
    clock_gap[18] = M31.fromCanonical(34);
    try expectRangeOnlyRejection(&authored, &bindings, &clock_gap, values);
}

test "typed JALR rejects target bit-one misalignment before state retirement" {
    var authored = try typed_jalr.build(std.testing.allocator, .generated);
    defer authored.deinit();
    const bindings = support.typedBindings(&authored);
    const values = try std.testing.allocator.alloc(M31, authored.arena.nodeCount());
    defer std.testing.allocator.free(values);
    for ([_]u32{ 0x0100_0002, 0x0100_0003 }) |sum| {
        const row = try support.witnessRow(.{
            .rs1_value = sum,
            .immediate = 0,
        });
        try support.evaluateInto(&authored.arena, &bindings, &row, values);
        try std.testing.expect(!support.directConstraintsZero(&authored, values));
        try std.testing.expect(!support.rowAccepted(&authored, values));
    }
}

test "typed JALR x0 alias and padding preserve exact access phases" {
    var authored = try typed_jalr.build(std.testing.allocator, .generated);
    defer authored.deinit();
    const bindings = support.typedBindings(&authored);
    const values = try std.testing.allocator.alloc(M31, authored.arena.nodeCount());
    defer std.testing.allocator.free(values);

    const x0 = try support.honestRow(.{
        .rs1_value = 0x1000,
        .immediate = 0,
        .rd = 0,
    });
    try support.evaluateInto(&authored.arena, &bindings, &x0, values);
    try std.testing.expect(support.rowAccepted(&authored, values));
    for (9..13) |column| try std.testing.expect(x0[column].isZero());

    const alias = try support.honestRow(.{
        .rs1_value = 0x0100_0000,
        .immediate = 5,
        .rd = 5,
        .rs1 = 5,
    });
    try support.evaluateInto(&authored.arena, &bindings, &alias, values);
    try std.testing.expect(support.rowAccepted(&authored, values));
    const source_emit = authored.arena.effectValues(authored.events.source.emit).?;
    const destination_consume = authored.arena.effectValues(
        authored.events.destination.consume,
    ).?;
    for (source_emit, destination_consume) |source_value, destination_value| {
        try std.testing.expectEqual(
            values[types.idIndex(source_value)].toU32(),
            values[types.idIndex(destination_value)].toU32(),
        );
    }

    const padding = support.paddedRow();
    try support.evaluateInto(&authored.arena, &bindings, &padding, values);
    try std.testing.expect(support.rowAccepted(&authored, values));
    for (authored.arena.effectsView()) |effect|
        try std.testing.expect(values[types.idIndex(effect.liveness.?)].isZero());
}

test "typed JALR identity rejects same-shape events roots and refinement premise corruption" {
    {
        var authored = try typed_jalr.build(std.testing.allocator, .generated);
        defer authored.deinit();
        const range = authored.arena.effects.items[4].values;
        authored.arena.effect_values.items[range.start] = authored.columns.rs1.next[0];
        try std.testing.expectError(error.InvalidJalrDefinition, authored.validate());
    }
    {
        var authored = try typed_jalr.build(std.testing.allocator, .generated);
        defer authored.deinit();
        authored.model.roots[0] = authored.columns.enabler;
        authored.arena.constraints.items[0].root = authored.columns.enabler;
        try std.testing.expectError(error.InvalidJalrDefinition, authored.validate());
    }
    {
        var authored = try typed_jalr.build(std.testing.allocator, .generated);
        defer authored.deinit();
        switch (authored.arena.range_refinements.items[1].premise) {
            .aligned_control_target => |*proof| proof.low_effect = authored.events.target_m31,
            else => return error.ExpectedAlignedControlTargetProof,
        }
        try std.testing.expectError(error.InvalidRangeRefinement, authored.validate());
    }
}

test "typed JALR construction rolls back every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

fn expectRangeOnlyRejection(
    authored: *const typed_jalr.Definition,
    bindings: []const support.Binding,
    row: []const M31,
    values: []M31,
) !void {
    try support.evaluateInto(&authored.arena, bindings, row, values);
    try std.testing.expect(support.directConstraintsZero(authored, values));
    try std.testing.expect(!support.rowAccepted(authored, values));
}

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    var authored = try typed_jalr.build(allocator, .generated);
    defer authored.deinit();
}
