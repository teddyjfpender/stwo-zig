const std = @import("std");
const storage = @import("blake3_parent_row_storage.zig");
const join = @import("blake3_parent_join.zig");
const boundary = @import("blake3_boundary.zig");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
const committed = @import("framework_interaction.zig").committedRow;
test "BLAKE3 memory update proves disjoint parent column join" {
    const a = std.testing.allocator;
    var left = try fixture(a, 1, 3, 42);
    defer left.deinit();
    var right = try fixture(a, 101, 2, 200);
    defer right.deinit();
    const ranges = [2]join.Range{ .{ .first = 1, .end = 2 }, .{ .first = 101, .end = 102 } };
    var combined = try join.join(a, &left, &right, ranges);
    defer combined.deinit();
    try std.testing.expectEqual(@as(usize, 5), combined.fixed[2].len);
    try std.testing.expectEqual(@as(usize, 5), combined.input_count);
    for ([_]u32{ 42, 43, 44, 200, 201 }, 0..) |value, i| {
        try std.testing.expectEqual(value, combined.main[2][0].values[committed(i, 3)].toU32());
        try std.testing.expectEqual(if (i < 3) @as(u32, 1) else 101, combined.fixed[2][i][5 - boundary.PHYSICAL_MAIN_COLUMN_COUNT].toU32());
    }
    for (5..8) |i| try std.testing.expect(combined.main[2][0].values[committed(i, 3)].isZero());
    try std.testing.expectError(error.OverlappingParentNamespaces, join.join(a, &left, &right, .{ ranges[0], ranges[0] }));
    right.fixed[2][0][5 - boundary.PHYSICAL_MAIN_COLUMN_COUNT] = M.one();
    try std.testing.expectError(error.InvalidParentCustodyNamespace, join.join(a, &left, &right, ranges));
    right.fixed[2][0][5 - boundary.PHYSICAL_MAIN_COLUMN_COUNT] = M.fromCanonical(101);
    const values = right.main[2][0].values;
    right.main[2][0].values = &.{};
    try std.testing.expectError(error.InvalidParentJoinColumns, join.join(a, &left, &right, ranges));
    right.main[2][0].values = values;
    try std.testing.expectEqual(@as(u32, 42), left.main[2][0].values[committed(0, 2)].toU32());
}
fn fixture(a: std.mem.Allocator, circuit: u32, count: usize, first: u32) !storage.Prepared {
    var result = storage.Prepared{ .allocator = a, .main = @splat(&.{}), .fixed = undefined, .input_count = count };
    inline for (0..storage.Airs.len) |i| result.fixed[i] = &.{};
    errdefer result.deinit();
    result.fixed[2] = try a.alloc(storage.FixedRow(boundary), count);
    for (result.fixed[2], 0..) |*row, i| row.* = storage.compactFixed(boundary, try boundary.logicalRow(circuit, @intCast(i), M.one(), first + @as(u32, @intCast(i))));
    inline for (storage.Airs, 0..) |Air, i| {
        const log: u32 = if (result.fixed[i].len < 2) 1 else std.math.log2_int_ceil(usize, result.fixed[i].len);
        result.main[i] = try a.alloc(Column, Air.PHYSICAL_MAIN_COLUMN_COUNT);
        for (result.main[i]) |*column| column.* = .{ .log_size = log, .values = &.{} };
        for (result.main[i], 0..) |*column, c| {
            const values = try a.alloc(M, @as(usize, 1) << @intCast(log));
            column.values = values;
            @memset(values, M.zero());
            if (comptime i == 2) for (0..count) |logical| {
                values[committed(logical, log)] = (try boundary.logicalRow(circuit, @intCast(logical), M.one(), first + @as(u32, @intCast(logical))))[c];
            };
        }
    }
    return result;
}

test "BLAKE3 memory update proves tiled join matches logical rows and padding" {
    const a = std.testing.allocator;
    for ([_][2]usize{ .{ 0, 0 }, .{ 0, 3 }, .{ 3, 0 }, .{ 1, 1 }, .{ 3, 5 }, .{ 7, 2 }, .{ 513, 1025 }, .{ 1024, 1024 } }) |counts| {
        var left = try fixture(a, 1, counts[0], 42);
        defer left.deinit();
        var right = try fixture(a, 101, counts[1], 200);
        defer right.deinit();
        var combined = try join.join(a, &left, &right, .{ .{ .first = 1, .end = 2 }, .{ .first = 101, .end = 102 } });
        defer combined.deinit();
        inline for (storage.Airs, 0..) |_, i| {
            const n = left.fixed[i].len + right.fixed[i].len;
            for (combined.main[i], 0..) |column, c| {
                for (0..column.values.len) |logical| {
                    const expected = if (logical < left.fixed[i].len)
                        left.main[i][c].values[committed(logical, left.main[i][c].log_size)]
                    else if (logical < n)
                        right.main[i][c].values[committed(logical - left.fixed[i].len, right.main[i][c].log_size)]
                    else
                        M.zero();
                    try std.testing.expectEqual(expected, column.values[committed(logical, column.log_size)]);
                }
            }
        }
    }
}

test "BLAKE3 draining join preserves columns and releases partial ownership" {
    const a = std.testing.allocator;
    const ranges = [2]join.Range{ .{ .first = 1, .end = 2 }, .{ .first = 101, .end = 102 } };
    for ([_][2]usize{ .{ 0, 0 }, .{ 0, 3 }, .{ 3, 0 }, .{ 3, 5 }, .{ 513, 1025 } }) |counts| {
        var left = try wideFixture(a, 1, counts[0]);
        defer left.deinit();
        var right = try wideFixture(a, 101, counts[1]);
        defer right.deinit();
        const saved = left.main[0][0].values.ptr;
        try std.testing.expectError(error.AliasedAggregateChildren, join.joinDraining(a, &left, &left, ranges));
        try std.testing.expectEqual(saved, left.main[0][0].values.ptr);
        try std.testing.expectError(error.OverlappingParentNamespaces, join.joinDraining(a, &left, &right, .{ ranges[0], ranges[0] }));
        try std.testing.expectEqual(saved, left.main[0][0].values.ptr);
        var expected = try join.join(a, &left, &right, ranges);
        defer expected.deinit();
        var actual = try join.joinDraining(a, &left, &right, ranges);
        defer actual.deinit();
        try std.testing.expectEqual(expected.input_count, actual.input_count);
        inline for (0..storage.Airs.len) |i| {
            try std.testing.expectEqualDeep(expected.fixed[i], actual.fixed[i]);
            for (expected.main[i], actual.main[i]) |wanted, got| try std.testing.expectEqualDeep(wanted, got);
            try std.testing.expectEqual(@as(usize, 0), left.fixed[i].len + right.fixed[i].len);
            for (left.main[i], right.main[i]) |l, r| try std.testing.expectEqual(@as(usize, 0), l.values.len + r.values.len);
        }
    }
    try std.testing.checkAllAllocationFailures(a, drainingFailureCase, .{});
}
fn drainingFailureCase(output_allocator: std.mem.Allocator) !void {
    // Inject failures only into the destination: source owners use their own
    // allocator, exercising cross-budget cleanup after partial column draining.
    var left = try wideFixture(std.testing.allocator, 1, 3);
    defer left.deinit();
    var right = try wideFixture(std.testing.allocator, 101, 5);
    defer right.deinit();
    var output = try join.joinDraining(output_allocator, &left, &right, .{ .{ .first = 1, .end = 2 }, .{ .first = 101, .end = 102 } });
    defer output.deinit();
}
fn wideFixture(a: std.mem.Allocator, circuit: u32, count: usize) !storage.Prepared {
    var result = try fixture(a, circuit, 0, 0);
    errdefer result.deinit();
    const Air = storage.Airs[0];
    result.fixed[0] = try a.alloc(storage.FixedRow(Air), count);
    const fixed = storage.compactFixed(Air, try Air.fixedRow(.{ .circuit = circuit, .input = .{ 0, 1, 2, 3, 4, 5 }, .output = .{ 6, 7, 8, 9 }, .uses = @splat(1) }));
    @memset(result.fixed[0], fixed);
    const log: u32 = if (count < 2) 1 else std.math.log2_int_ceil(usize, count);
    for (result.main[0], 0..) |*column, c| {
        a.free(column.values);
        column.* = .{ .log_size = log, .values = &.{} };
        const values = try a.alloc(M, @as(usize, 1) << @intCast(log));
        column.values = values;
        // Nonzero source padding must not leak into output padding.
        for (values, 0..) |*value, physical| value.* = M.fromCanonical(@intCast(c * 10000 + physical + circuit));
    }
    result.input_count = count;
    return result;
}
test "BLAKE3 draining join bounds simultaneous source and destination columns" {
    const borrowed = try joinPeak(false, 64 * 1024 * 1024);
    const draining = try joinPeak(true, 64 * 1024 * 1024);
    try std.testing.expect(draining < borrowed);
    const limit = draining + (borrowed - draining) / 2;
    try std.testing.expectError(error.OutOfMemory, joinPeak(false, limit));
    try std.testing.expectEqual(draining, try joinPeak(true, limit));
    std.debug.print("BLAKE3_JOIN_PEAK borrowed_bytes={d} draining_bytes={d}\n", .{ borrowed, draining });
}
fn joinPeak(comptime drain: bool, limit: usize) !usize {
    const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
    const budget = try Budget.create(std.testing.allocator, limit);
    defer budget.destroy();
    const a = budget.allocator();
    var left = try wideFixture(a, 1, 4096);
    defer left.deinit();
    var right = try wideFixture(a, 101, 4097);
    defer right.deinit();
    const ranges = [2]join.Range{ .{ .first = 1, .end = 2 }, .{ .first = 101, .end = 102 } };
    var output = if (drain) try join.joinDraining(a, &left, &right, ranges) else try join.join(a, &left, &right, ranges);
    defer output.deinit();
    return budget.snapshot().peak_live_bytes;
}

const hash_columns = @import("../blake3_native_hash_columns.zig");
const HashLayout = @import("../blake3_native_hash_layout.zig").Layout;
fn partitionFixture(a: std.mem.Allocator, circuit: u32, count: usize, columns: *const hash_columns.Owner) !storage.Partition {
    var source = try wideFixture(a, circuit, count);
    defer source.deinit();
    inline for (0..2) |i| {
        for (source.main[i], columns.main[i]) |from, to| {
            for (0..source.fixed[i].len) |logical| {
                @constCast(to.values)[committed(columns.first[i] + logical, to.log_size)] = from.values[committed(logical, from.log_size)];
            }
            a.free(from.values);
        }
        a.free(source.main[i]);
        source.main[i] = &.{};
    }
    var result = storage.Partition{ .allocator = a, .main = source.main, .fixed = source.fixed, .input_count = source.input_count, .first = columns.first, .capacity = columns.capacity };
    result.main[0] = columns.main[0];
    result.main[1] = columns.main[1];
    source.main = @splat(&.{});
    inline for (0..storage.Airs.len) |i| source.fixed[i] = &.{};
    return result;
}
fn sharedFixture(a: std.mem.Allocator, counts: [2]usize) !hash_columns.Shared {
    return hash_columns.Shared.init(a, .{
        try HashLayout.fromCounts(.{ .g = counts[0], .xor = 0 }, .{ .g = 0, .xor = 0 }),
        try HashLayout.fromCounts(.{ .g = counts[1], .xor = 0 }, .{ .g = 0, .xor = 0 }),
    });
}
test "BLAKE3 shared hash partitions preserve join values padding and ownership" {
    const a = std.testing.allocator;
    const ranges = [2]join.Range{ .{ .first = 1, .end = 2 }, .{ .first = 101, .end = 102 } };
    for ([_][2]usize{ .{ 0, 0 }, .{ 0, 3 }, .{ 3, 0 }, .{ 3, 5 }, .{ 513, 1025 } }) |counts| {
        var expected_left = try wideFixture(a, 1, counts[0]);
        defer expected_left.deinit();
        var expected_right = try wideFixture(a, 101, counts[1]);
        defer expected_right.deinit();
        var expected = try join.join(a, &expected_left, &expected_right, ranges);
        defer expected.deinit();
        var shared = try sharedFixture(a, counts);
        defer shared.deinit();
        const left_columns = try shared.partition(0);
        const right_columns = try shared.partition(1);
        var left = try partitionFixture(a, 1, counts[0], &left_columns);
        defer left.deinit();
        var right = try partitionFixture(a, 101, counts[1], &right_columns);
        defer right.deinit();
        const original = shared.owner.main[0][0].values.ptr;
        right.first[0] += 1;
        try std.testing.expectError(error.InvalidParentJoinColumns, join.joinShared(&left, &right, ranges, &shared.owner));
        right.first[0] -= 1;
        try std.testing.expectEqual(original, shared.owner.main[0][0].values.ptr);
        var result = try join.joinShared(&left, &right, ranges, &shared.owner);
        defer result.deinit();
        try std.testing.expectEqual(original, result.main[0][0].values.ptr);
        try std.testing.expectEqual(@as(usize, 0), shared.owner.main[0].len + shared.owner.main[1].len);
        inline for (0..storage.Airs.len) |i| {
            try std.testing.expectEqualDeep(expected.fixed[i], result.fixed[i]);
            for (expected.main[i], result.main[i]) |want, got| try std.testing.expectEqualDeep(want, got);
        }
    }
    try std.testing.checkAllAllocationFailures(a, sharedFailureCase, .{});
}
fn sharedFailureCase(a: std.mem.Allocator) !void {
    var shared = try sharedFixture(a, .{ 3, 5 });
    defer shared.deinit();
    const left_columns = try shared.partition(0);
    const right_columns = try shared.partition(1);
    var left = try partitionFixture(std.testing.allocator, 1, 3, &left_columns);
    defer left.deinit();
    var right = try partitionFixture(std.testing.allocator, 101, 5, &right_columns);
    defer right.deinit();
    var result = try join.joinShared(&left, &right, .{ .{ .first = 1, .end = 2 }, .{ .first = 101, .end = 102 } }, &shared.owner);
    defer result.deinit();
}

test "BLAKE3 shared reserved append is bounded and failure atomic" {
    try reservedAppend(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, reservedAppend, .{});
}
fn reservedAppend(a: std.mem.Allocator) !void {
    const append = @import("blake3_parent_append.zig");
    const G = storage.Airs[0];
    const layout = try HashLayout.fromCounts(.{ .g = 1, .xor = 0 }, .{ .g = 0, .xor = 0 });
    var shared = try hash_columns.Shared.initReserved(std.testing.allocator, .{ layout, layout }, .{ .{ .g = 3, .xor = 0 }, .{ .g = 2, .xor = 0 } });
    defer shared.deinit();
    const columns = try shared.partition(1);
    try std.testing.expectEqual(@as(usize, 4), columns.first[0]);
    var target = storage.Partition{ .allocator = a, .main = @splat(&.{}), .fixed = undefined, .input_count = 0, .first = columns.first, .capacity = columns.capacity };
    inline for (0..storage.Airs.len) |i| target.fixed[i] = &.{};
    target.main[0] = columns.main[0];
    target.main[1] = columns.main[1];
    defer target.deinit();
    target.fixed[0] = try a.alloc(storage.FixedRow(G), 1);
    target.fixed[0][0] = @splat(M.zero());
    for (shared.owner.main[0]) |column| @memset(@constCast(column.values), M.fromCanonical(7));
    var succeeded = false;
    defer if (!succeeded) {
        for (shared.owner.main[0]) |column| for (column.values) |value| std.debug.assert(value.toU32() == 7);
        std.debug.assert(target.fixed[0].len == 1);
    };
    const extra = [_]G.Row{ @splat(M.one()), @splat(M.fromCanonical(2)) };
    var chunks = append.init();
    defer append.deinit(std.testing.allocator, &chunks);
    try chunks[0].append(std.testing.allocator, .{ .live = &extra, .fixed = &extra });
    // A later invalid cohort must not publish already validated hash additions.
    const live_boundary = [_]boundary.Row{@splat(M.zero())};
    const bad_boundary = [_]boundary.Row{@splat(M.one())};
    try chunks[2].append(std.testing.allocator, .{ .live = &live_boundary, .fixed = &bad_boundary });
    if (append.append(&target, &chunks)) |_| return error.ExpectedInvalidAppend else |err| {
        if (err != error.InvalidParentAppend) return err;
    }
    for (shared.owner.main[0]) |column| for (column.values) |value| try std.testing.expectEqual(@as(u32, 7), value.toU32());
    chunks[2].clearRetainingCapacity();
    const pointer = target.main[0].ptr;
    try append.append(&target, &chunks);
    succeeded = true;
    try std.testing.expectEqual(pointer, target.main[0].ptr);
    try std.testing.expectEqual(@as(usize, 3), target.fixed[0].len);
    for (target.main[0]) |column| for (0..column.values.len) |logical| {
        const expected: u32 = if (logical == 5) 1 else if (logical == 6) 2 else 7;
        try std.testing.expectEqual(expected, column.values[committed(logical, column.log_size)].toU32());
    };
    // A second append would cross the reservation, even though padding exists.
    try std.testing.expectError(error.InvalidParentAppend, append.append(&target, &chunks));
    try std.testing.expectEqual(@as(usize, 3), target.fixed[0].len);
}
