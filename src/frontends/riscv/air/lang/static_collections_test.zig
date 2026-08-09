const std = @import("std");
const collections = @import("static_collections.zig");
const expr = @import("expr.zig");
const ir = @import("ir.zig");
const source = @import("source.zig");
const types = @import("types.zig");

const Felt3 = collections.StaticArray(.felt, 3);
const Byte3 = collections.StaticArray(.byte, 3);

test "static arrays encode shape and scalar semantics without constraints" {
    comptime {
        if (Felt3 == Byte3)
            @compileError("collection element semantics must remain in the type");
        if (Felt3 == collections.StaticArray(.felt, 2))
            @compileError("collection length must remain in the type");
    }

    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const generated = source.SourceSpan.generated();
    const a = try arena.input("a", .felt, generated);
    const b = try arena.input("b", .felt, generated);
    const c = try arena.input("c", .felt, generated);
    const byte = try arena.input("byte", .byte, generated);

    const values = try Felt3.fromValues(&arena, &.{ a, b, c });
    const semantic_type = try Felt3.semanticType();
    try std.testing.expect(std.meta.eql(
        types.Type{ .array = .{ .element = .felt, .len = 3 } },
        semantic_type,
    ));
    try std.testing.expectEqual(a, try values.valueAt(0));
    try std.testing.expectEqual(c, try values.valueAt(2));
    try std.testing.expectError(error.IndexOutOfBounds, values.valueAt(3));
    try std.testing.expectEqual(@as(usize, 0), arena.constraintsView().len);
    try std.testing.expectEqual(@as(usize, 0), arena.effectsView().len);

    try std.testing.expectError(
        error.ShapeMismatch,
        Felt3.fromValues(&arena, &.{ a, b }),
    );
    try std.testing.expectError(
        error.ShapeMismatch,
        Felt3.fromValues(&arena, &.{ a, b, c, a }),
    );
    try std.testing.expectError(
        error.ElementTypeMismatch,
        Felt3.fromValues(&arena, &.{ a, byte, c }),
    );
    const unknown = try types.idFromIndex(types.ValueId, 9_999);
    try std.testing.expectError(
        error.UnknownValue,
        Felt3.fromValues(&arena, &.{ a, unknown, c }),
    );

    const Empty = collections.StaticArray(.felt, 0);
    try std.testing.expectError(
        error.EmptyCollection,
        Empty.fromValues(&arena, &.{}),
    );
    try std.testing.expectError(
        error.EmptyCollection,
        collections.validateStaticLength(0),
    );
    try std.testing.expectError(
        error.StaticLengthOverflow,
        collections.validateStaticLength(
            @as(usize, std.math.maxInt(u16)) + 1,
        ),
    );
    try std.testing.expectEqual(
        std.math.maxInt(u16),
        try collections.validateStaticLength(std.math.maxInt(u16)),
    );
}

test "map preserves every unrolled source span across structural CSE" {
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const source_id = try arena.addSource("components/poseidon2.air");
    const input_span = try testSpan(source_id, 1);
    const spans = [_]source.SourceSpan{
        try testSpan(source_id, 10),
        try testSpan(source_id, 11),
        try testSpan(source_id, 12),
    };
    const input = try arena.input("state", .felt, input_span);
    const repeated = try Felt3.fromValues(&arena, &.{ input, input, input });

    var order = OrderRecorder{};
    const squared = try repeated.mapWithSpans(
        &arena,
        .felt,
        &spans,
        &order,
        Square.recording,
    );
    try std.testing.expectEqual(@as(usize, 3), order.count);
    try std.testing.expectEqualSlices(usize, &.{ 0, 1, 2 }, order.indices[0..3]);

    const shared = squared.items[0].value;
    for (squared.items, spans) |item, expected_span| {
        try std.testing.expectEqual(shared, item.value);
        try std.testing.expect(std.meta.eql(expected_span, item.source_span));
    }
    try std.testing.expect(std.meta.eql(
        spans[0],
        arena.node(shared).?.primary_source,
    ));
    try std.testing.expectEqual(@as(usize, 0), arena.constraintsView().len);
    try std.testing.expectEqual(@as(usize, 0), arena.effectsView().len);
}

test "maps zip maps and left folds have deterministic algebraic semantics" {
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const generated = source.SourceSpan.generated();
    const one = try arena.constantField(1, generated);
    const two = try arena.constantField(2, generated);
    const three = try arena.constantField(3, generated);
    const zero = try arena.constantField(0, generated);
    const lhs = try Felt3.fromValues(&arena, &.{ one, two, three });
    const rhs = try Felt3.fromValues(&arena, &.{ three, two, one });

    const squared = try lhs.map(
        &arena,
        .felt,
        generated,
        {},
        Square.apply,
    );
    const pairwise = try lhs.zipMap(
        &arena,
        .felt,
        rhs,
        .felt,
        generated,
        {},
        Add.apply,
    );
    const sum = try squared.fold(
        &arena,
        .felt,
        .{ .value = zero, .source_span = generated },
        generated,
        {},
        Add.fold,
    );

    try std.testing.expectEqual(@as(u32, 1), try evaluate(&arena, squared.items[0].value));
    try std.testing.expectEqual(@as(u32, 4), try evaluate(&arena, squared.items[1].value));
    try std.testing.expectEqual(@as(u32, 9), try evaluate(&arena, squared.items[2].value));
    for (pairwise.items) |item| {
        try std.testing.expectEqual(@as(u32, 4), try evaluate(&arena, item.value));
    }
    try std.testing.expectEqual(@as(u32, 14), try evaluate(&arena, sum.value));

    const replacement = collections.SourcedValue{
        .value = three,
        .source_span = generated,
    };
    const replaced = try lhs.replaced(&arena, 0, replacement);
    try std.testing.expectEqual(three, replaced.items[0].value);
    try std.testing.expectEqual(one, lhs.items[0].value);
    try std.testing.expectError(
        error.IndexOutOfBounds,
        lhs.replaced(&arena, 3, replacement),
    );
}

test "fold retains the source site of each deterministic reduction step" {
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const source_id = try arena.addSource("components/poseidon2.air");
    const generated = source.SourceSpan.generated();
    const one = try arena.constantField(1, generated);
    const two = try arena.constantField(2, generated);
    const three = try arena.constantField(3, generated);
    const zero = try arena.constantField(0, generated);
    const values = try Felt3.fromValues(&arena, &.{ one, two, three });
    const spans = [_]source.SourceSpan{
        try testSpan(source_id, 20),
        try testSpan(source_id, 21),
        try testSpan(source_id, 22),
    };
    var order = OrderRecorder{};

    const result = try values.foldWithSpans(
        &arena,
        .felt,
        .{ .value = zero, .source_span = generated },
        &spans,
        &order,
        Add.recordingFold,
    );
    try std.testing.expectEqualSlices(usize, &.{ 0, 1, 2 }, order.indices[0..3]);
    try std.testing.expect(std.meta.eql(spans[2], result.source_span));
    try std.testing.expect(std.meta.eql(
        spans[2],
        arena.node(result.value).?.primary_source,
    ));
}

test "invalid callback output types and span shapes reject transactionally" {
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const generated = source.SourceSpan.generated();
    const a = try arena.input("a", .felt, generated);
    const b = try arena.input("b", .felt, generated);
    const c = try arena.input("c", .felt, generated);
    const byte = try arena.input("byte", .byte, generated);
    const values = try Felt3.fromValues(&arena, &.{ a, b, c });

    const before_failed_map = arena.nodeCount();
    try std.testing.expectError(
        error.UnknownValue,
        values.map(&arena, .felt, generated, {}, FailSecond.apply),
    );
    try std.testing.expectEqual(before_failed_map, arena.nodeCount());
    try std.testing.expectEqual(arena.nodeCount(), arena.interned_nodes.count());

    const before_wrong_type = arena.nodeCount();
    try std.testing.expectError(
        error.ElementTypeMismatch,
        values.map(&arena, .felt, generated, byte, WrongType.apply),
    );
    try std.testing.expectEqual(before_wrong_type, arena.nodeCount());

    try std.testing.expectError(
        error.ShapeMismatch,
        values.mapWithSpans(
            &arena,
            .felt,
            &.{ generated, generated },
            {},
            Square.apply,
        ),
    );
    try std.testing.expectError(
        error.ElementTypeMismatch,
        values.fold(
            &arena,
            .felt,
            .{ .value = byte, .source_span = generated },
            generated,
            {},
            Add.fold,
        ),
    );
}

test "invalid explicit provenance rejects before expansion" {
    var arena = ir.Arena.init(std.testing.allocator);
    defer arena.deinit();
    const generated = source.SourceSpan.generated();
    const a = try arena.input("a", .felt, generated);
    const b = try arena.input("b", .felt, generated);
    const c = try arena.input("c", .felt, generated);
    const values = try Felt3.fromValues(&arena, &.{ a, b, c });
    const unknown_source = try types.idFromIndex(types.SourceId, 77);
    const invalid_span = source.SourceSpan{
        .source = unknown_source,
        .start = .{ .byte_offset = 0, .line = 1, .column = 1 },
        .end = .{ .byte_offset = 1, .line = 1, .column = 2 },
    };
    const before = arena.nodeCount();

    try std.testing.expectError(
        error.UnknownSource,
        values.mapWithSpans(
            &arena,
            .felt,
            &.{ generated, invalid_span, generated },
            {},
            Square.apply,
        ),
    );
    try std.testing.expectEqual(before, arena.nodeCount());

    try std.testing.expectError(
        error.UnknownSource,
        Felt3.fromSourced(&arena, &.{
            .{ .value = a, .source_span = generated },
            .{ .value = b, .source_span = invalid_span },
            .{ .value = c, .source_span = generated },
        }),
    );
}

test "static collection expansion is identical across clean arena replays" {
    var first = try buildReplay(std.testing.allocator);
    defer first.deinit();
    var second = try buildReplay(std.testing.allocator);
    defer second.deinit();

    try std.testing.expectEqual(first.nodeCount(), second.nodeCount());
    for (first.nodesView(), second.nodesView()) |lhs, rhs| {
        try std.testing.expect(std.meta.eql(lhs.key, rhs.key));
        try std.testing.expect(std.meta.eql(lhs.primary_source, rhs.primary_source));
    }
}

test "static collection expansion releases every partial allocation" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}

const OrderRecorder = struct {
    indices: [3]usize = undefined,
    count: usize = 0,

    fn record(self: *OrderRecorder, index: usize) void {
        self.indices[self.count] = index;
        self.count += 1;
    }
};

const Square = struct {
    fn apply(
        builder: collections.ScalarBuilder,
        _: void,
        _: usize,
        value: types.ValueId,
    ) collections.Error!types.ValueId {
        return builder.mul(value, value);
    }

    fn recording(
        builder: collections.ScalarBuilder,
        order: *OrderRecorder,
        index: usize,
        value: types.ValueId,
    ) collections.Error!types.ValueId {
        order.record(index);
        return builder.mul(value, value);
    }
};

const Add = struct {
    fn apply(
        builder: collections.ScalarBuilder,
        _: void,
        _: usize,
        lhs: types.ValueId,
        rhs: types.ValueId,
    ) collections.Error!types.ValueId {
        return builder.add(lhs, rhs);
    }

    fn fold(
        builder: collections.ScalarBuilder,
        _: void,
        _: usize,
        accumulator: types.ValueId,
        item: types.ValueId,
    ) collections.Error!types.ValueId {
        return builder.add(accumulator, item);
    }

    fn recordingFold(
        builder: collections.ScalarBuilder,
        order: *OrderRecorder,
        index: usize,
        accumulator: types.ValueId,
        item: types.ValueId,
    ) collections.Error!types.ValueId {
        order.record(index);
        return builder.add(accumulator, item);
    }
};

const FailSecond = struct {
    fn apply(
        builder: collections.ScalarBuilder,
        _: void,
        index: usize,
        value: types.ValueId,
    ) collections.Error!types.ValueId {
        if (index == 1) return types.idFromIndex(types.ValueId, 99_999);
        return builder.mul(value, value);
    }
};

const WrongType = struct {
    fn apply(
        _: collections.ScalarBuilder,
        byte: types.ValueId,
        index: usize,
        value: types.ValueId,
    ) collections.Error!types.ValueId {
        return if (index == 1) byte else value;
    }
};

fn testSpan(source_id: types.SourceId, line: u32) !source.SourceSpan {
    return source.SourceSpan.init(
        source_id,
        .{ .byte_offset = line * 10, .line = line, .column = 1 },
        .{ .byte_offset = line * 10 + 4, .line = line, .column = 5 },
    );
}

fn buildReplay(allocator: std.mem.Allocator) !ir.Arena {
    var arena = ir.Arena.init(allocator);
    errdefer arena.deinit();
    const source_id = try arena.addSource("components/replay.air");
    const input_span = try testSpan(source_id, 1);
    const map_span = try testSpan(source_id, 2);
    const fold_span = try testSpan(source_id, 3);
    const a = try arena.input("a", .felt, input_span);
    const b = try arena.input("b", .felt, input_span);
    const c = try arena.input("c", .felt, input_span);
    const zero = try arena.constantField(0, input_span);
    const values = try Felt3.fromValues(&arena, &.{ a, b, c });
    const squared = try values.map(
        &arena,
        .felt,
        map_span,
        {},
        Square.apply,
    );
    _ = try squared.fold(
        &arena,
        .felt,
        .{ .value = zero, .source_span = input_span },
        fold_span,
        {},
        Add.fold,
    );
    return arena;
}

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    var arena = ir.Arena.init(allocator);
    defer arena.deinit();
    const source_id = try arena.addSource("components/allocation.air");
    const input_span = try testSpan(source_id, 1);
    const map_span = try testSpan(source_id, 2);
    const fold_span = try testSpan(source_id, 3);
    const a = try arena.input("a", .felt, input_span);
    const b = try arena.input("b", .felt, input_span);
    const c = try arena.input("c", .felt, input_span);
    const zero = try arena.constantField(0, input_span);
    const values = try Felt3.fromValues(&arena, &.{ a, b, c });
    const squared = try values.map(
        &arena,
        .felt,
        map_span,
        {},
        Square.apply,
    );
    _ = try squared.fold(
        &arena,
        .felt,
        .{ .value = zero, .source_span = input_span },
        fold_span,
        {},
        Add.fold,
    );
}

fn evaluate(arena: *const ir.Arena, root: types.ValueId) !u32 {
    var values = try std.testing.allocator.alloc(u32, arena.nodeCount());
    defer std.testing.allocator.free(values);
    for (arena.nodesView(), 0..) |node, index| {
        values[index] = switch (node.key.op) {
            .constant => |constant| switch (constant) {
                .field, .unsigned => |value| value,
            },
            .add => |binary| reduce(
                @as(u64, values[types.idIndex(binary.lhs)]) +
                    values[types.idIndex(binary.rhs)],
            ),
            .sub => |binary| reduce(
                @as(u64, values[types.idIndex(binary.lhs)]) + modulus -
                    values[types.idIndex(binary.rhs)],
            ),
            .mul => |binary| reduce(
                @as(u64, values[types.idIndex(binary.lhs)]) *
                    values[types.idIndex(binary.rhs)],
            ),
            .neg => |value| reduce(modulus - values[types.idIndex(value)]),
            .select => |selection| if (values[types.idIndex(selection.selector)] == 1)
                values[types.idIndex(selection.when_true)]
            else
                values[types.idIndex(selection.when_false)],
            .machine_derived => |derived| switch (derived) {
                .register_address => |address| values[types.idIndex(address.index)],
                .aligned_word_address => |address| reduce(
                    @as(u64, values[types.idIndex(address.word_index)]) * 4,
                ),
                .access_clock => |clock| reduce(
                    (@as(u64, values[types.idIndex(clock.instruction_clock)]) +
                        modulus - 1) * 4 + @intFromEnum(clock.phase),
                ),
                .strict_clock_gap => |gap| reduce(
                    @as(u64, values[types.idIndex(gap.current_clock)]) +
                        modulus - values[types.idIndex(gap.previous_clock)] +
                        modulus - 1,
                ),
            },
            .input, .hint_output, .call_output => return error.NotConcrete,
        };
    }
    return values[types.idIndex(root)];
}

const modulus: u64 = 0x7fffffff;

fn reduce(value: u64) u32 {
    return @intCast(value % modulus);
}
