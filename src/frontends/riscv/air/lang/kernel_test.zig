const std = @import("std");
const ir = @import("ir.zig");
const source = @import("source.zig");
const types = @import("types.zig");

test "typed AIR IDs are non-interchangeable and preserve their tag widths" {
    comptime {
        if (types.ValueId == types.ConstraintId)
            @compileError("value and constraint IDs must remain distinct");
        if (types.EffectId == types.HintId)
            @compileError("effect and hint IDs must remain distinct");
        if (types.NameId == types.SourceId)
            @compileError("name and source IDs must remain distinct");
    }
    try std.testing.expectEqual(@as(usize, 4), @sizeOf(types.ValueId));
    try std.testing.expectEqual(@as(usize, 2), @sizeOf(types.RelationSchemaId));

    const value_id = try types.idFromIndex(types.ValueId, 17);
    try std.testing.expectEqual(@as(usize, 17), types.idIndex(value_id));
    try std.testing.expectError(
        error.IdOverflow,
        types.idFromIndex(
            types.RelationSchemaId,
            @as(usize, std.math.maxInt(u16)) + 1,
        ),
    );
}

test "semantic integer types reject non-injective and malformed layouts" {
    _ = try types.Type.boundedField(20);
    _ = try types.Type.boundedLimbs(32, 8, 4);
    _ = try types.Type.staticArray(.felt, 16);

    try std.testing.expectError(
        error.ZeroBitWidth,
        types.Type.boundedField(0),
    );
    try std.testing.expectError(
        error.FieldRepresentationNotInjective,
        types.Type.boundedField(31),
    );
    try std.testing.expectError(
        error.LimbWidthMismatch,
        types.Type.boundedLimbs(32, 8, 3),
    );
    try std.testing.expectError(
        error.EmptyArray,
        types.Type.staticArray(.byte, 0),
    );
}

test "source spans distinguish generated and real locations" {
    const source_id = try types.idFromIndex(types.SourceId, 0);
    const span = try source.SourceSpan.init(
        source_id,
        .{ .byte_offset = 8, .line = 2, .column = 3 },
        .{ .byte_offset = 13, .line = 2, .column = 8 },
    );
    try span.validate();
    try source.SourceSpan.generated().validate();

    try std.testing.expectError(
        error.InvalidSourcePosition,
        source.SourceSpan.init(
            source_id,
            .{ .byte_offset = 0, .line = 0, .column = 0 },
            .{ .byte_offset = 1, .line = 1, .column = 2 },
        ),
    );
    try std.testing.expectError(
        error.ReversedSourceSpan,
        source.SourceSpan.init(
            source_id,
            .{ .byte_offset = 9, .line = 3, .column = 2 },
            .{ .byte_offset = 8, .line = 2, .column = 9 },
        ),
    );
}

test "logical arena owns and interns stable names and source paths" {
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();

    var name_buffer = [_]u8{ 'r', 'e', 's', 'u', 'l', 't' };
    const result_name = try arena.internName(&name_buffer);
    name_buffer[0] = 'X';
    try std.testing.expectEqualStrings("result", arena.name(result_name).?);
    try std.testing.expectEqual(
        result_name,
        try arena.internName("result"),
    );

    var path_buffer = [_]u8{ 'o', 'p', 's', '/', 'l', 'u', 'i', '.', 'z', 'i', 'g' };
    const source_id = try arena.addSource(&path_buffer);
    path_buffer[0] = 'X';
    try std.testing.expectEqualStrings("ops/lui.zig", arena.sourcePath(source_id).?);
    try std.testing.expectEqual(source_id, try arena.addSource("ops/lui.zig"));

    const span = try source.SourceSpan.init(
        source_id,
        .{ .byte_offset = 0, .line = 1, .column = 1 },
        .{ .byte_offset = 3, .line = 1, .column = 4 },
    );
    try arena.validateSpan(span);
    const unknown = try types.idFromIndex(types.SourceId, 99);
    try std.testing.expectError(
        error.UnknownSource,
        arena.validateSpan(.{
            .source = unknown,
            .start = .{ .byte_offset = 0, .line = 1, .column = 1 },
            .end = .{ .byte_offset = 0, .line = 1, .column = 1 },
        }),
    );
}

test "expression nodes are topological and structurally interned" {
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const generated = source.SourceSpan.generated();
    const source_id = try arena.addSource("components/example.zig");
    const first_sum_span = try source.SourceSpan.init(
        source_id,
        .{ .byte_offset = 10, .line = 2, .column = 1 },
        .{ .byte_offset = 15, .line = 2, .column = 6 },
    );
    const repeated_sum_span = try source.SourceSpan.init(
        source_id,
        .{ .byte_offset = 30, .line = 4, .column = 1 },
        .{ .byte_offset = 35, .line = 4, .column = 6 },
    );

    const a = try arena.input("a", .felt, generated);
    const b = try arena.input("b", .felt, generated);
    const selector = try arena.input("selector", .bit, generated);
    const sum = try arena.add(a, b, first_sum_span);
    try std.testing.expectEqual(sum, try arena.add(a, b, repeated_sum_span));
    try std.testing.expectEqual(sum, try arena.add(b, a, generated));
    try std.testing.expect(std.meta.eql(
        first_sum_span,
        arena.node(sum).?.primary_source,
    ));

    const product = try arena.mul(sum, a, generated);
    try std.testing.expectEqual(product, try arena.mul(a, sum, generated));
    const difference = try arena.sub(a, b, generated);
    const reverse_difference = try arena.sub(b, a, generated);
    try std.testing.expect(difference != reverse_difference);

    const selected = try arena.select(selector, product, difference, generated);
    try std.testing.expectEqual(@as(usize, 8), arena.nodeCount());
    try std.testing.expectEqual(types.idIndex(selected), arena.nodeCount() - 1);

    for (arena.nodesView(), 0..) |node, index| {
        switch (node.key.op) {
            .add, .sub, .mul => |binary| {
                try std.testing.expect(types.idIndex(binary.lhs) < index);
                try std.testing.expect(types.idIndex(binary.rhs) < index);
            },
            .neg => |value| try std.testing.expect(types.idIndex(value) < index),
            .select => |selection| {
                try std.testing.expect(types.idIndex(selection.selector) < index);
                try std.testing.expect(types.idIndex(selection.when_true) < index);
                try std.testing.expect(types.idIndex(selection.when_false) < index);
            },
            else => {},
        }
    }

    var replay = ir.Arena.init(std.testing.allocator);
    defer replay.deinit();
    const replay_source = try replay.addSource("components/example.zig");
    const replay_span = try source.SourceSpan.init(
        replay_source,
        .{ .byte_offset = 10, .line = 2, .column = 1 },
        .{ .byte_offset = 15, .line = 2, .column = 6 },
    );
    const replay_a = try replay.input("a", .felt, generated);
    const replay_b = try replay.input("b", .felt, generated);
    const replay_selector = try replay.input("selector", .bit, generated);
    const replay_sum = try replay.add(replay_a, replay_b, replay_span);
    const replay_product = try replay.mul(replay_sum, replay_a, generated);
    const replay_difference = try replay.sub(replay_a, replay_b, generated);
    _ = try replay.sub(replay_b, replay_a, generated);
    _ = try replay.select(
        replay_selector,
        replay_product,
        replay_difference,
        generated,
    );
    try std.testing.expectEqual(arena.nodeCount(), replay.nodeCount());
    for (arena.nodesView(), replay.nodesView()) |expected, actual| {
        try std.testing.expect(std.meta.eql(expected.key, actual.key));
    }
}

test "expression constructors reject malformed constants and typed operations" {
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const generated = source.SourceSpan.generated();

    try std.testing.expectError(
        error.NonCanonicalFieldConstant,
        arena.constantField(0x7fffffff, generated),
    );
    try std.testing.expectError(
        error.ConstantOutOfRange,
        arena.constantUnsigned(.bit, 2, generated),
    );
    try std.testing.expectError(
        error.UnsupportedConstantType,
        arena.constantUnsigned(.felt, 1, generated),
    );
    try std.testing.expectError(
        error.ConstantOutOfRange,
        arena.constantUnsigned(.clock, 0x7fffffff, generated),
    );

    const word = try arena.input("word", .word32, generated);
    try std.testing.expectError(
        error.NonFieldOperand,
        arena.add(word, word, generated),
    );

    const felt = try arena.input("felt", .felt, generated);
    const bit = try arena.constantUnsigned(.bit, 1, generated);
    try std.testing.expectError(
        error.InvalidSelectorType,
        arena.select(felt, felt, felt, generated),
    );
    try std.testing.expectError(
        error.BranchTypeMismatch,
        arena.select(bit, felt, bit, generated),
    );
    try std.testing.expectError(
        error.InputTypeConflict,
        arena.input("felt", .byte, generated),
    );

    const unknown = try types.idFromIndex(types.ValueId, 999);
    try std.testing.expectError(
        error.UnknownValue,
        arena.neg(unknown, generated),
    );
}

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    var arena = ir.Arena.init(allocator);
    defer arena.deinit();
    _ = try arena.internName("result");
    const source_id = try arena.addSource("ops/lui.zig");
    try arena.validateSpan(try source.SourceSpan.init(
        source_id,
        .{ .byte_offset = 0, .line = 1, .column = 1 },
        .{ .byte_offset = 3, .line = 1, .column = 4 },
    ));
    const generated = source.SourceSpan.generated();
    const lhs = try arena.input("lhs", .felt, generated);
    const rhs = try arena.input("rhs", .felt, generated);
    const live = try arena.input("live", .bit, generated);
    const sum = try arena.add(lhs, rhs, generated);
    const product = try arena.mul(sum, lhs, generated);
    const hint_id = try arena.addHint(
        "allocation.inverse.v1",
        &.{product},
        &.{ .felt, .bit },
        generated,
    );
    const outputs = arena.hintOutputs(hint_id).?;
    _ = try arena.assertZero(
        "allocation.binding",
        outputs[0],
        outputs[1],
        .hint_binding,
        generated,
    );
    _ = try arena.addEffect(
        .register_read,
        &.{ lhs, rhs },
        live,
        0,
        generated,
    );
    _ = try arena.addFunction(
        "allocation.product",
        &.{ lhs, rhs, live },
        &.{ product, outputs[0] },
        generated,
    );
}

test "logical arena releases every partial allocation" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}
