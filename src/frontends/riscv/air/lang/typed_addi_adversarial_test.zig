//! Defensive mutations and allocation adversaries for native typed ADDI.

const std = @import("std");
const instruction_effects = @import("instruction_effects.zig");
const ir = @import("ir.zig");
const relation = @import("relation.zig");
const source = @import("source.zig");
const typed_addi = @import("typed_addi.zig");
const types = @import("types.zig");
const validate = @import("validate.zig");

test "typed ADDI rejects relation role schema liveness ordinal and read binding drift" {
    {
        var authored = try typed_addi.build(std.testing.allocator, .generated);
        defer authored.deinit();
        authored.arena.effects.items[7].kind = .range_request;
        try std.testing.expectError(error.InvalidEffect, authored.validate());
    }
    {
        var authored = try typed_addi.build(std.testing.allocator, .generated);
        defer authored.deinit();
        authored.arena.effects.items[7].binding.?.schema =
            relation.id(.range_check_8_8);
        try std.testing.expectError(error.InvalidEffect, authored.validate());
    }
    {
        var authored = try typed_addi.build(std.testing.allocator, .generated);
        defer authored.deinit();
        authored.arena.effects.items[7].binding.?.role = .emit;
        try std.testing.expectError(error.InvalidEffect, authored.validate());
    }
    {
        var authored = try typed_addi.build(std.testing.allocator, .generated);
        defer authored.deinit();
        authored.arena.effects.items[7].liveness = authored.active;
        try validate.validate(&authored.arena);
        try std.testing.expectError(error.InvalidAddiDefinition, authored.validate());
    }
    {
        var authored = try typed_addi.build(std.testing.allocator, .generated);
        defer authored.deinit();
        authored.arena.effects.items[13].access_ordinal = 1;
        try std.testing.expectError(error.InvalidEffect, authored.validate());
    }
    {
        var authored = try typed_addi.build(std.testing.allocator, .generated);
        defer authored.deinit();
        authored.arena.constraints.items[17].root = authored.zero;
        try std.testing.expectError(error.InvalidEffect, authored.validate());
    }
}

test "typed ADDI bounded arithmetic rejects forged types and noninjective products" {
    const span = source.SourceSpan.generated();
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const felt = try arena.input("felt", .felt, span);
    const bit = try arena.input("bit", .bit, span);
    try std.testing.expectError(
        error.InvalidBoundedOperand,
        arena.boundedAdd(felt, bit, span),
    );
    const uint30 = try types.Type.boundedField(30);
    const wide = try arena.input("wide", uint30, span);
    try std.testing.expectError(
        error.BoundedResultOutOfField,
        arena.boundedMul(wide, wide, span),
    );
    try std.testing.expectError(
        error.InvalidOneHotSelector,
        arena.oneHotSelector(&.{ bit, bit }, span),
    );
}

test "one-hot selector admits exactly two through five distinct bits" {
    const span = source.SourceSpan.generated();
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const bits = [_]types.ValueId{
        try arena.input("bit_0", .bit, span),
        try arena.input("bit_1", .bit, span),
        try arena.input("bit_2", .bit, span),
        try arena.input("bit_3", .bit, span),
        try arena.input("bit_4", .bit, span),
        try arena.input("bit_5", .bit, span),
    };
    const selector = try arena.oneHotSelector(bits[0..5], span);
    try std.testing.expectEqual(types.Type.selector, arena.node(selector).?.key.ty);
    try validate.validate(&arena);
    try std.testing.expectError(
        error.InvalidOneHotSelector,
        arena.oneHotSelector(&.{ bits[0], bits[1], bits[0] }, span),
    );
    try std.testing.expectError(
        error.InvalidOneHotSelector,
        arena.oneHotSelector(&bits, span),
    );
}

test "five-way one-hot construction releases every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        fiveWayOneHotAllocationFailureCase,
        .{},
    );
}

test "typed ADDI construction releases every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

test "typed word request rollback preserves a nonempty valid arena" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        wordRequestAllocationFailureCase,
        .{},
    );
}

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    var authored = try typed_addi.build(allocator, .generated);
    defer authored.deinit();
}

fn fiveWayOneHotAllocationFailureCase(allocator: std.mem.Allocator) !void {
    var arena = ir.Arena.init(allocator);
    defer arena.deinit();
    const span = source.SourceSpan.generated();
    const bits = [_]types.ValueId{
        try arena.input("bit_0", .bit, span),
        try arena.input("bit_1", .bit, span),
        try arena.input("bit_2", .bit, span),
        try arena.input("bit_3", .bit, span),
        try arena.input("bit_4", .bit, span),
    };
    _ = try arena.oneHotSelector(&bits, span);
    try validate.validate(&arena);
}

fn wordRequestAllocationFailureCase(allocator: std.mem.Allocator) !void {
    var arena = ir.Arena.init(allocator);
    defer arena.deinit();
    const span = source.SourceSpan.generated();
    const active = try arena.input("active", .selector, span);
    const byte = try arena.input("byte", .byte, span);
    const op = try arena.input("op", try types.Type.boundedField(2), span);
    const prefix = try instruction_effects.rangeCheck88Pairs(
        &arena,
        .{
            .{ .first_byte = byte, .second_byte = byte },
            .{ .first_byte = byte, .second_byte = byte },
        },
        active,
        span,
    );
    _ = prefix;
    const effects_before = arena.effectsView().len;
    const values_before = arena.effectValuesView().len;
    const lanes = [_]instruction_effects.BitwiseInput{.{
        .lhs = byte,
        .rhs = byte,
        .result = byte,
        .operation_id = op,
    }} ** 4;
    _ = instruction_effects.bitwiseWord(
        &arena,
        lanes,
        active,
        span,
    ) catch |failure| {
        try std.testing.expectEqual(effects_before, arena.effectsView().len);
        try std.testing.expectEqual(values_before, arena.effectValuesView().len);
        try validate.validate(&arena);
        return failure;
    };
}
