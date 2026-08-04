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
}

test "logical arena releases every partial allocation" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}
