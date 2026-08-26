const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const program = @import("program.zig");
const support = @import("typed_div_test_support.zig");
const typed_div = @import("typed_div.zig");

test {
    _ = @import("range_refinement_test.zig");
}

test "typed DIV named quotient remainder flag sign inverse and bound mutations reject" {
    var authored = try typed_div.build(std.testing.allocator, .generated);
    defer authored.deinit();
    const bindings = support.typedBindings(&authored);
    const values = try std.testing.allocator.alloc(M31, authored.arena.nodeCount());
    defer std.testing.allocator.free(values);

    const Mutation = struct {
        name: []const u8,
        opcode_index: usize,
        operands: support.OperandClass,
        column: usize,
        replacement: u32,
    };
    const mutations = [_]Mutation{
        .{ .name = "quotient limb", .opcode_index = 2, .operands = .{ .lhs = 97, .rhs = 7 }, .column = 34, .replacement = 99 },
        .{ .name = "remainder limb", .opcode_index = 0, .operands = .{ .lhs = 97, .rhs = 7 }, .column = 38, .replacement = 99 },
        .{ .name = "zero-divisor flag", .opcode_index = 1, .operands = .{ .lhs = 97, .rhs = 0 }, .column = 32, .replacement = 0 },
        .{ .name = "signed-overflow r-zero flag", .opcode_index = 0, .operands = .{ .lhs = 0x8000_0000, .rhs = 0xffff_ffff }, .column = 33, .replacement = 0 },
        .{ .name = "dividend sign", .opcode_index = 0, .operands = .{ .lhs = 0xffff_fff9, .rhs = 3 }, .column = 42, .replacement = 0 },
        .{ .name = "divisor sign", .opcode_index = 0, .operands = .{ .lhs = 7, .rhs = 0xffff_fffd }, .column = 43, .replacement = 0 },
        .{ .name = "quotient sign", .opcode_index = 0, .operands = .{ .lhs = 7, .rhs = 0xffff_fffd }, .column = 44, .replacement = 0 },
        .{ .name = "sign xor", .opcode_index = 0, .operands = .{ .lhs = 7, .rhs = 0xffff_fffd }, .column = 45, .replacement = 0 },
        .{ .name = "divisor-sum inverse", .opcode_index = 1, .operands = .{ .lhs = 97, .rhs = 7 }, .column = 46, .replacement = 0 },
        .{ .name = "remainder-sum inverse", .opcode_index = 1, .operands = .{ .lhs = 97, .rhs = 7 }, .column = 47, .replacement = 0 },
        .{ .name = "remainder inverse witness", .opcode_index = 0, .operands = .{ .lhs = 0xffff_fff9, .rhs = 3 }, .column = 52, .replacement = 0 },
        .{ .name = "remainder absolute limb", .opcode_index = 0, .operands = .{ .lhs = 0xffff_fff9, .rhs = 3 }, .column = 48, .replacement = 7 },
        .{ .name = "remainder-bound marker", .opcode_index = 1, .operands = .{ .lhs = 97, .rhs = 7 }, .column = 56, .replacement = 0 },
        .{ .name = "remainder-bound difference", .opcode_index = 1, .operands = .{ .lhs = 97, .rhs = 7 }, .column = 60, .replacement = 2 },
        .{ .name = "divisor byte range evidence", .opcode_index = 1, .operands = .{ .lhs = 100, .rhs = 2 }, .column = 28, .replacement = 256 },
        .{ .name = "quotient byte/carry range evidence", .opcode_index = 2, .operands = .{ .lhs = 97, .rhs = 7 }, .column = 34, .replacement = 256 },
        .{ .name = "destination inverse", .opcode_index = 0, .operands = .{ .lhs = 97, .rhs = 7 }, .column = 66, .replacement = 0 },
        .{ .name = "placement selector", .opcode_index = 0, .operands = .{ .lhs = 97, .rhs = 7 }, .column = 67, .replacement = 0 },
    };
    for (mutations, 0..) |mutation, index| {
        var row = try support.honestRow(
            support.opcode(mutation.opcode_index),
            mutation.operands,
            index + 1,
        );
        try support.evaluateInto(&authored.arena, &bindings, &row, values);
        try std.testing.expect(support.rowAccepted(&authored, values));
        row[mutation.column] = M31.fromCanonical(mutation.replacement);
        try support.evaluateInto(&authored.arena, &bindings, &row, values);
        if (support.rowAccepted(&authored, values)) {
            std.log.err("accepted typed DIV mutation: {s}", .{mutation.name});
            return error.MutationAccepted;
        }
    }
}

test "typed DIV construction and native refinement ownership roll back every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

test "typed DIV forged quotient is rejected specifically by carry range evidence" {
    var authored = try typed_div.build(std.testing.allocator, .generated);
    defer authored.deinit();
    const bindings = support.typedBindings(&authored);
    const values = try std.testing.allocator.alloc(M31, authored.arena.nodeCount());
    defer std.testing.allocator.free(values);
    var row = try support.honestRow(
        support.opcode(3),
        .{ .lhs = 7, .rhs = 3 },
        1,
    );
    row[34] = M31.fromCanonical(3);
    try support.evaluateInto(&authored.arena, &bindings, &row, values);
    try std.testing.expect(support.directConstraintsZero(&authored, values));
    try std.testing.expect(!support.rowAccepted(&authored, values));
}

test "typed DIV identity rejects same-shape effect field and root substitutions" {
    {
        var authored = try typed_div.build(std.testing.allocator, .generated);
        defer authored.deinit();
        std.mem.swap(
            program.Effect,
            &authored.arena.effects.items[9],
            &authored.arena.effects.items[10],
        );
        try std.testing.expectError(error.InvalidRange, authored.validate());
    }
    {
        var authored = try typed_div.build(std.testing.allocator, .generated);
        defer authored.deinit();
        const effect = authored.arena.effects.items[11];
        authored.arena.effect_values.items[effect.values.start + 1] = authored.columns.q[0];
        try std.testing.expectError(error.InvalidEffect, authored.validate());
    }
    {
        var authored = try typed_div.build(std.testing.allocator, .generated);
        defer authored.deinit();
        authored.model.roots[0] = authored.model.active;
        authored.arena.constraints.items[0].root = authored.model.active;
        try std.testing.expectError(error.InvalidDivDefinition, authored.validate());
    }
}

test "typed DIV refinement graph rejects wrong premise gate expression bound order omission and coordination" {
    {
        var authored = try typed_div.build(std.testing.allocator, .generated);
        defer authored.deinit();
        authored.arena.range_refinements.items[0].premise.constraint_boolean.constraint =
            authored.model.constraints[0];
        try std.testing.expectError(error.InvalidRangeRefinement, @import("validate.zig").validate(&authored.arena));
    }
    {
        var authored = try typed_div.build(std.testing.allocator, .generated);
        defer authored.deinit();
        authored.arena.range_refinements.items[2].premise.fixed_table_field.liveness =
            authored.columns.is_div;
        try std.testing.expectError(error.InvalidRangeRefinement, @import("validate.zig").validate(&authored.arena));
    }
    {
        var authored = try typed_div.build(std.testing.allocator, .generated);
        defer authored.deinit();
        authored.arena.range_refinements.items[2].source = authored.model.product_carries[1];
        try std.testing.expectError(error.InvalidRangeRefinement, @import("validate.zig").validate(&authored.arena));
    }
    {
        var authored = try typed_div.build(std.testing.allocator, .generated);
        defer authored.deinit();
        const target = authored.arena.range_refinements.items[2].target;
        const target_index = @intFromEnum(target);
        const old_key = authored.arena.nodes.items[target_index].key;
        try std.testing.expect(authored.arena.interned_nodes.remove(old_key));
        authored.arena.nodes.items[target_index].key.ty =
            try @import("types.zig").Type.boundedField(10);
        try authored.arena.interned_nodes.put(
            authored.arena.nodes.items[target_index].key,
            target,
        );
        // The effect schema is the earliest defensive layer able to observe
        // this coordinated type forgery; the proof graph is never trusted to
        // reinterpret an ill-typed range-request field.
        try std.testing.expectError(error.InvalidEffect, @import("validate.zig").validate(&authored.arena));
    }
    {
        var authored = try typed_div.build(std.testing.allocator, .generated);
        defer authored.deinit();
        std.mem.swap(
            program.RangeRefinement,
            &authored.arena.range_refinements.items[2],
            &authored.arena.range_refinements.items[3],
        );
        try std.testing.expectError(error.InvalidRangeRefinement, @import("validate.zig").validate(&authored.arena));
    }
    {
        var authored = try typed_div.build(std.testing.allocator, .generated);
        defer authored.deinit();
        _ = authored.arena.range_refinements.pop();
        try std.testing.expectError(error.InvalidNodeShape, @import("validate.zig").validate(&authored.arena));
    }
    {
        var authored = try typed_div.build(std.testing.allocator, .generated);
        defer authored.deinit();
        const item = &authored.arena.range_refinements.items[2];
        const replacement = authored.model.sign_checks[0];
        const target_index = @intFromEnum(item.target);
        const old_key = authored.arena.nodes.items[target_index].key;
        try std.testing.expect(authored.arena.interned_nodes.remove(old_key));
        item.source = replacement;
        authored.arena.nodes.items[target_index].key.op = authored.arena.node(replacement).?.key.op;
        try authored.arena.interned_nodes.put(
            authored.arena.nodes.items[target_index].key,
            item.target,
        );
        try std.testing.expectError(error.InvalidDivDefinition, authored.validate());
    }
}

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    var authored = try typed_div.build(allocator, .generated);
    defer authored.deinit();
}
