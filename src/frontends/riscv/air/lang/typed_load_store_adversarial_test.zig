const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const program = @import("program.zig");
const support = @import("typed_load_store_test_support.zig");
const typed_load_store = @import("typed_load_store.zig");
const types = @import("types.zig");
const validate = @import("validate.zig");

test "typed signed-load named sign mask bound alias x0 and placement mutations reject" {
    var authored = try typed_load_store.build(std.testing.allocator, .generated);
    defer authored.deinit();
    const bindings = support.typedBindings(&authored);
    const values = try std.testing.allocator.alloc(M31, authored.arena.nodeCount());
    defer std.testing.allocator.free(values);

    const Mutation = struct {
        name: []const u8,
        case: support.LbCase = .{},
        column: usize,
        replacement: u32,
    };
    const mutations = [_]Mutation{
        .{ .name = "selected result", .column = 42, .replacement = 0x81 },
        .{ .name = "selected source byte", .column = 19, .replacement = 0x81 },
        .{ .name = "sign witness", .column = 26, .replacement = 0 },
        .{ .name = "missing byte mask", .column = 30, .replacement = 0 },
        .{ .name = "extra byte mask", .column = 31, .replacement = 1 },
        .{ .name = "shift amount", .column = 27, .replacement = 1 },
        .{ .name = "memory address selector", .column = 28, .replacement = 0x2004 },
        .{ .name = "destination selector", .column = 29, .replacement = 3 },
        .{ .name = "destination inverse", .column = 47, .replacement = 0 },
        .{ .name = "placement selector", .column = 48, .replacement = 0 },
        .{
            .name = "offset-three selected source byte",
            .case = .{ .offset = 3, .selected_byte = 0xff },
            .column = 22,
            .replacement = 0x7f,
        },
        .{
            .name = "x0 discarded result",
            .case = .{ .rd = 0, .selected_byte = 0xff },
            .column = 8,
            .replacement = 0xff,
        },
        .{
            .name = "rd-rs1 alias result",
            .case = .{ .rd = 5, .rs1 = 5, .selected_byte = 0x7f },
            .column = 8,
            .replacement = 0x80,
        },
    };
    for (mutations) |mutation| {
        var row = try support.honestLbRow(mutation.case);
        try support.evaluateInto(&authored.arena, &bindings, &row, values);
        try std.testing.expect(support.rowAccepted(&authored, values));
        row[mutation.column] = M31.fromCanonical(mutation.replacement);
        try support.evaluateInto(&authored.arena, &bindings, &row, values);
        if (support.rowAccepted(&authored, values)) {
            std.log.err("accepted typed signed-load mutation: {s}", .{mutation.name});
            return error.MutationAccepted;
        }
    }
}

test "typed signed-load sign and aligned-address forgeries require lookup evidence" {
    var authored = try typed_load_store.build(std.testing.allocator, .generated);
    defer authored.deinit();
    const bindings = support.typedBindings(&authored);
    const values = try std.testing.allocator.alloc(M31, authored.arena.nodeCount());
    defer std.testing.allocator.free(values);

    var forged_sign = try support.honestLbRow(.{ .selected_byte = 0x80 });
    forged_sign[26] = M31.zero();
    forged_sign[8] = M31.fromCanonical(0x80);
    forged_sign[9] = M31.zero();
    forged_sign[10] = M31.zero();
    forged_sign[11] = M31.zero();
    forged_sign[42] = M31.fromCanonical(0x80);
    forged_sign[43] = M31.zero();
    forged_sign[44] = M31.zero();
    forged_sign[45] = M31.zero();
    try support.evaluateInto(&authored.arena, &bindings, &forged_sign, values);
    try std.testing.expect(support.directConstraintsZero(&authored, values));
    try std.testing.expect(!support.rowAccepted(&authored, values));

    var out_of_range = try support.honestLbRow(.{ .aligned_address = 0x3f_fffc });
    out_of_range[13] = M31.zero();
    out_of_range[14] = M31.zero();
    out_of_range[15] = M31.fromCanonical(0x40);
    out_of_range[16] = M31.zero();
    out_of_range[18] = M31.fromCanonical(0x40_0000);
    out_of_range[28] = M31.fromCanonical(0x40_0000);
    try support.evaluateInto(&authored.arena, &bindings, &out_of_range, values);
    try std.testing.expect(support.directConstraintsZero(&authored, values));
    try std.testing.expect(!support.rowAccepted(&authored, values));
}

test "typed signed-load exact physical phases and strict gaps are live" {
    var authored = try typed_load_store.build(std.testing.allocator, .generated);
    defer authored.deinit();
    const bindings = support.typedBindings(&authored);
    const values = try std.testing.allocator.alloc(M31, authored.arena.nodeCount());
    defer std.testing.allocator.free(values);
    var row = try support.honestLbRow(.{ .clock = 2 });
    try support.evaluateInto(&authored.arena, &bindings, &row, values);
    try std.testing.expect(support.rowAccepted(&authored, values));

    // Production serializes rs1/src/dst as ordinals 1/2/3 while a load uses
    // physical phases 1/3/2. The emitted clock is tuple field two.
    try std.testing.expectEqual(@as(u32, 5), valueAt(values, support.effectFields(&authored, 4)[2]));
    try std.testing.expectEqual(@as(u32, 7), valueAt(values, support.effectFields(&authored, 9)[2]));
    try std.testing.expectEqual(@as(u32, 6), valueAt(values, support.effectFields(&authored, 12)[2]));
    try std.testing.expectEqual(@as(?u8, 1), authored.arena.effectsView()[4].access_ordinal);
    try std.testing.expectEqual(@as(?u8, 2), authored.arena.effectsView()[9].access_ordinal);
    try std.testing.expectEqual(@as(?u8, 3), authored.arena.effectsView()[12].access_ordinal);

    row[23] = M31.fromCanonical(7);
    try support.evaluateInto(&authored.arena, &bindings, &row, values);
    try std.testing.expect(support.directConstraintsZero(&authored, values));
    try std.testing.expect(!support.rowAccepted(&authored, values));
}

test "typed signed-load padding is canonical and inactive" {
    var authored = try typed_load_store.build(std.testing.allocator, .generated);
    defer authored.deinit();
    const bindings = support.typedBindings(&authored);
    const values = try std.testing.allocator.alloc(M31, authored.arena.nodeCount());
    defer std.testing.allocator.free(values);
    var row = support.paddingRow();
    try support.evaluateInto(&authored.arena, &bindings, &row, values);
    try std.testing.expect(support.rowAccepted(&authored, values));
    row[26] = M31.one();
    try support.evaluateInto(&authored.arena, &bindings, &row, values);
    try std.testing.expect(!support.rowAccepted(&authored, values));
}

test "typed load/store identity rejects effect root liveness and ordering substitutions" {
    {
        var authored = try typed_load_store.build(std.testing.allocator, .generated);
        defer authored.deinit();
        std.mem.swap(
            program.Effect,
            &authored.arena.effects.items[14],
            &authored.arena.effects.items[15],
        );
        try expectValidationFailure(&authored);
    }
    {
        var authored = try typed_load_store.build(std.testing.allocator, .generated);
        defer authored.deinit();
        const range = authored.arena.effects.items[14].values;
        authored.arena.effect_values.items[@as(usize, range.start) + 1] =
            authored.columns.result[1];
        try expectValidationFailure(&authored);
    }
    {
        var authored = try typed_load_store.build(std.testing.allocator, .generated);
        defer authored.deinit();
        authored.arena.effects.items[14].liveness = authored.columns.is_lh;
        try expectValidationFailure(&authored);
    }
    {
        var authored = try typed_load_store.build(std.testing.allocator, .generated);
        defer authored.deinit();
        authored.model.roots[0] = authored.model.active;
        authored.arena.constraints.items[0].root = authored.model.active;
        try expectValidationFailure(&authored);
    }
}

test "typed load/store component identity rejects coordinated range liveness forgery" {
    var authored = try typed_load_store.build(std.testing.allocator, .generated);
    defer authored.deinit();
    const effect_id = authored.events.lb_sign_range;
    authored.arena.effects.items[types.idIndex(effect_id)].liveness =
        authored.columns.is_lh;
    for (authored.arena.fixed_table_requests.items) |*proof| {
        if (proof.effect == effect_id) proof.liveness = authored.columns.is_lh;
    }
    for (authored.arena.range_refinements.items) |*refinement| {
        switch (refinement.premise) {
            .fixed_table_field => |proof| if (proof.effect == effect_id) {
                var forged = proof;
                forged.liveness = authored.columns.is_lh;
                refinement.premise = .{ .fixed_table_field = forged };
            },
            else => {},
        }
    }

    // This is a coherent but different logical AIR. Structural validation is
    // expected to accept it; the pinned component identity must not.
    try validate.validate(&authored.arena);
    try expectValidationFailure(&authored);
}

test "typed load/store conditional aliases cannot escape their exact fields" {
    var authored = try typed_load_store.build(std.testing.allocator, .generated);
    defer authored.deinit();
    const proof = authored.arena.conditional_access_plans.items[0];
    effectField(&authored, types.idIndex(authored.events.destination.emit), 2).* =
        proof.source_clock.target;
    try expectValidationFailure(&authored);
}

fn expectValidationFailure(authored: *const typed_load_store.Definition) !void {
    if (authored.validate()) |_| return error.ForgeryAccepted else |_| {}
}

fn effectField(
    authored: *typed_load_store.Definition,
    effect_index: usize,
    field_index: usize,
) *types.ValueId {
    const range = authored.arena.effects.items[effect_index].values;
    return &authored.arena.effect_values.items[@as(usize, range.start) + field_index];
}

test "typed load/store construction rolls back every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    var authored = try typed_load_store.build(allocator, .generated);
    defer authored.deinit();
}

fn valueAt(values: []const M31, id: @import("types.zig").ValueId) u32 {
    return values[@import("types.zig").idIndex(id)].toU32();
}
