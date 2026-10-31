const std = @import("std");
const core = @import("stwo_core");
const Native = @import("native_frontier.zig");
const T = @import("private_trace.zig");
const Owned = @import("openings.zig").Owned;
const values = @import("values.zig");
const Fixture = @import("native_frontier_test.zig").Fixture;
const M = core.fields.m31.M31;
const a = std.testing.allocator;
const Arena = struct {
    allocator: std.mem.Allocator,
    backing: []M,
    buffers: T.MainBuffers,
    fn init(allocator: std.mem.Allocator, preparation: *const T.Preparation) !Arena {
        const shapes = preparation.shapes;
        const policy_log = @max(4, std.math.log2_int_ceil(usize, @max(1, preparation.mappings.grants.len)));
        const policy_size = @as(usize, 1) << @intCast(policy_log);
        var total: usize = 303 * (@as(usize, 1) << @intCast(shapes.provider_log)) + policy_size + 256;
        for (T.TABLES) |table| total += T.mainWidth(table) * (@as(usize, 1) << @intCast(T.tableLog(shapes, table)));
        const backing = try allocator.alloc(M, total);
        @memset(backing, M.fromCanonical(77));
        var cursor: usize = 0;
        var buffers: T.MainBuffers = undefined;
        const provider_size = 303 * (@as(usize, 1) << @intCast(shapes.provider_log));
        buffers.provider = backing[0..provider_size];
        cursor += provider_size;
        for (T.TABLES) |table| {
            const size = T.mainWidth(table) * (@as(usize, 1) << @intCast(T.tableLog(shapes, table)));
            buffers.callers[@intFromEnum(table)] = backing[cursor..][0..size];
            cursor += size;
        }
        buffers.policy_tail = backing[cursor..][0..policy_size];
        cursor += policy_size;
        buffers.byte_tail = backing[cursor..][0..256];
        return .{ .allocator = allocator, .backing = backing, .buffers = buffers };
    }
    fn deinit(self: *Arena) void {
        self.allocator.free(self.backing);
        self.backing = &.{};
    }
};
test "detached RAM graph builds one identical wide witness after cache and native memory destruction" {
    for ([_]values.Geometry{ .chunk512, .page4096 }) |geometry| for ([_]bool{ false, true }) |borrowed| {
        var fixture = try Fixture.init(geometry);
        defer fixture.deinit();
        var owned = try Owned.copy(a, geometry, fixture.owned.chunks);
        defer owned.deinit();
        var native = try Native.Prepared.init(a, &fixture.cache, &owned);
        defer native.deinit();
        var preparation = try T.Preparation.init(a, geometry, &fixture.mappings, owned.chunks);
        defer preparation.deinit();
        var reference = try T.Trace.initOwned(a, &fixture.cache, &fixture.mappings, &fixture.owned);
        defer reference.deinit();
        // Only owned words, immutable policy and prepared graph remain live.
        fixture.cache.deinit();
        fixture.cache_alive = false;
        fixture.memory.deinit();
        fixture.memory_alive = false;
        var arena = if (borrowed) try Arena.init(a, &preparation) else null;
        defer if (arena) |*owner| owner.deinit();
        var detached = if (arena) |*owner| try T.Trace.initFromPreparedGraphBorrowedOwned(a, &native, &preparation, &owned, owner.buffers) else try T.Trace.initFromPreparedGraphOwned(a, &native, &preparation, &owned);
        defer detached.deinit();
        try std.testing.expectEqual(Native.Phase.consumed, native.phase);
        try std.testing.expectEqual(@as(usize, 0), native.io.len);
        try std.testing.expectEqual(@as(usize, 0), owned.words.len);
        try std.testing.expect(!preparation.available);
        try std.testing.expectEqualDeep(reference.witness.before, detached.witness.before);
        try std.testing.expectEqualDeep(reference.witness.after, detached.witness.after);
        try std.testing.expectEqualDeep(reference.recorder.calls.items, detached.recorder.calls.items);
        try std.testing.expectEqualDeep(reference.byte_counts, detached.byte_counts);
        try std.testing.expectEqualSlices(u64, reference.policy_counts, detached.policy_counts);
        try std.testing.expectEqualSlices(M, reference.provider, detached.provider);
        for (T.TABLES) |table| try std.testing.expectEqualSlices(M, T.mainData(&reference, table), T.mainData(&detached, table));
        if (arena) |*owner| {
            for (owner.buffers.policy_tail) |value| try std.testing.expectEqual(@as(u32, 77), value.v);
            for (owner.buffers.byte_tail) |value| try std.testing.expectEqual(@as(u32, 77), value.v);
            try detached.releaseBorrowedMain();
            owner.deinit();
        }
        var left: [256]M = undefined;
        var right: [256]M = undefined;
        for (T.TABLES) |table| {
            const width = T.mainWidth(table);
            const rows = @as(usize, 1) << @intCast(T.tableLog(detached.shapes, table));
            for (0..rows) |row| {
                try reference.restoreRow(table, row, left[0..width]);
                try detached.restoreRow(table, row, right[0..width]);
                try std.testing.expectEqualSlices(M, left[0..width], right[0..width]);
            }
        }
        try std.testing.expectError(error.InvalidNativeFrontierPhase, T.Trace.initFromPreparedGraphOwned(a, &native, &preparation, &owned));
    };
}
fn failure(allocator: std.mem.Allocator, fixture: *const Fixture) !void {
    var owned = try Owned.copy(allocator, .chunk512, fixture.owned.chunks);
    defer owned.deinit();
    var native = try Native.Prepared.init(allocator, &fixture.cache, &owned);
    defer native.deinit();
    var preparation = try T.Preparation.init(allocator, .chunk512, &fixture.mappings, owned.chunks);
    defer preparation.deinit();
    const io_pointer = native.io.ptr;
    const word_pointer = owned.words.ptr;
    var trace = T.Trace.initFromPreparedGraphOwned(allocator, &native, &preparation, &owned) catch |err| {
        try std.testing.expectEqual(Native.Phase.prepared, native.phase);
        try std.testing.expect(native.io.ptr == io_pointer);
        try std.testing.expect(owned.words.ptr == word_pointer);
        try std.testing.expect(preparation.available);
        return err;
    };
    defer trace.deinit();
}
test "detached RAM wide construction every OOM preserves all three source owners" {
    var fixture = try Fixture.init(.chunk512);
    defer fixture.deinit();
    const root = fixture.cache.root();
    try std.testing.checkAllAllocationFailures(a, failure, .{&fixture});
    try std.testing.expect(values.equal(root, fixture.cache.root()));
}

test "detached borrowed main excludes saved IO before any allocation or output writes" {
    var fixture = try Fixture.init(.chunk512);
    defer fixture.deinit();
    var fail = std.testing.FailingAllocator.init(a, .{});
    var owned = try Owned.copy(fail.allocator(), .chunk512, fixture.owned.chunks);
    defer owned.deinit();
    var native = try Native.Prepared.init(fail.allocator(), &fixture.cache, &owned);
    defer native.deinit();
    var preparation = try T.Preparation.init(fail.allocator(), .chunk512, &fixture.mappings, owned.chunks);
    defer preparation.deinit();
    var arena = try Arena.init(fail.allocator(), &preparation);
    defer arena.deinit();
    var aliased = arena.buffers;
    const which = @intFromEnum(T.Table.edge_permits);
    const data: [*]M = @ptrCast(native.io.ptr);
    try std.testing.expect(native.io.len * @sizeOf(values.PermutationIO) >= aliased.callers[which].len * @sizeOf(M));
    aliased.callers[which] = data[0..aliased.callers[which].len];
    var before: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(std.mem.sliceAsBytes(native.io), &before, .{});
    fail.fail_index = fail.alloc_index;
    try std.testing.expectError(error.OverlappingCryptoMainBuffers, T.Trace.initFromPreparedGraphBorrowedOwned(fail.allocator(), &native, &preparation, &owned, aliased));
    for (arena.backing) |value| try std.testing.expectEqual(@as(u32, 77), value.v);
    var after: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(std.mem.sliceAsBytes(native.io), &after, .{});
    try std.testing.expectEqualSlices(u8, &before, &after);
    try std.testing.expectEqual(Native.Phase.prepared, native.phase);
    fail.fail_index = std.math.maxInt(usize);
    @constCast(owned.chunks[0].after)[0] = 10;
    try std.testing.expectError(error.InvalidNativeFrontierIO, T.Trace.initFromPreparedGraphBorrowedOwned(fail.allocator(), &native, &preparation, &owned, arena.buffers));
    for (arena.backing) |value| try std.testing.expectEqual(@as(u32, 77), value.v);
}
