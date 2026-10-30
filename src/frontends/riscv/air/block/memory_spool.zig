//! Bounded external sort of real block-memory events. Witness transport only.
//! The shared sorter retains this original17-byte API and radix ordering.
const std = @import("std");
const event_mod = @import("memory_event.zig");
const Event = event_mod.Event;
const record_bytes = 17;
const Impl = @import("memory_sorter_v1.zig").For(Event, record_bytes, @import("memory_radix_sort.zig"), "memory");
pub const Statistics = Impl.Statistics;
pub const Reader = Impl.Reader;
pub const Spool = Impl.Spool;
const openRun = Impl.openRun;
test "memory spool heap merge carries singleton runs and records exact transport work" {
    const a = std.testing.allocator;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    var spool = try Spool.init(a, temporary.dir, 4);
    defer spool.deinit();
    const count = 129;
    var expected: [count]Event = undefined;
    for (&expected, 0..) |*event, index| {
        event.* = .{ .space = 1, .address = @intCast(0x2000 + 4 * (index % 17)), .clock = 4 * (count - index) + 1, .value = @intCast(index) };
        try spool.append(event.*);
    }
    std.sort.pdq(Event, &expected, {}, Event.lessThan);
    var reader = try spool.finish();
    defer reader.deinit();
    for (expected) |event| try std.testing.expectEqualDeep(event, (try reader.next()).?);
    try std.testing.expect((try reader.next()) == null);
    try std.testing.expectEqual(@as(u32, 33), spool.statistics.initial_runs);
    try std.testing.expectEqual(@as(u32, 2), spool.statistics.merge_passes);
    // First pass merges32 full runs; the one-record tail is carried. Second
    // pass merges all129 records, with no lost or surplus events.
    try std.testing.expectEqual(@as(u64, 128 + 129), spool.statistics.merged_records);
    try std.testing.expectEqual(@as(u64, (129 + 128 + 129) * record_bytes), spool.statistics.bytes_read);
    try std.testing.expectEqual(@as(u64, (129 * 2 + 128 + 129) * record_bytes), spool.statistics.bytes_written);
    var duplicate_dir = std.testing.tmpDir(.{});
    defer duplicate_dir.cleanup();
    var repeated = try Spool.init(a, duplicate_dir.dir, 4);
    defer repeated.deinit();
    for (expected[0 .. count - 1]) |event| try repeated.append(event);
    try repeated.append(expected[0]);
    try std.testing.expectError(error.DuplicateOrUnsortedMemoryEvent, repeated.finish());
    try std.testing.expectError(error.InvalidMemorySpoolPhase, repeated.reopenSorted());
}

test "bounded memory spool sorts across runs with exact coverage and rejects duplicate clocks" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var spool = try Spool.init(std.testing.allocator, tmp.dir, 1300);
    defer spool.deinit();
    // Both the raw-source reader and the merge readers cross their 1024-record
    // buffer boundary while sorting two independently committed runs.
    for (0..2113) |back| {
        const i: u32 = @intCast(2112 - back);
        try spool.append(.{ .space = 1, .address = (i % 3) * 4, .clock = @as(u64, i / 3) * 4 + 1, .value = i });
    }
    var reader = try spool.finish();
    defer reader.deinit();
    var previous: ?Event = null;
    var count: usize = 0;
    while (try reader.next()) |item| {
        if (previous) |before| try std.testing.expect(Event.lessThan({}, before, item));
        previous = item;
        count += 1;
    }
    try std.testing.expectEqual(@as(usize, 2113), count);
    var replay = try spool.reopenSorted();
    defer replay.deinit();
    count = 0;
    while (try replay.next()) |_| count += 1;
    try std.testing.expectEqual(@as(usize, 2113), count);
    try std.testing.expectError(error.InvalidMemorySpoolPhase, spool.append(.{ .space = 1, .address = 0, .clock = 1, .value = 0 }));
    try tmp.dir.makeDir("duplicate");
    var duplicate_dir = try tmp.dir.openDir("duplicate", .{});
    defer duplicate_dir.close();
    var duplicate = try Spool.init(std.testing.allocator, duplicate_dir, 2);
    defer duplicate.deinit();
    try duplicate.append(.{ .space = 1, .address = 0, .clock = 1, .value = 0 });
    try duplicate.append(.{ .space = 1, .address = 0, .clock = 1, .value = 0 });
    try std.testing.expectError(error.DuplicateOrUnsortedMemoryEvent, duplicate.finish());
}

test "spool accepts real segment accesses and globally orders leaf-local clocks" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var spool = try Spool.init(std.testing.allocator, tmp.dir, 2);
    defer spool.deinit();
    const Access = @import("../../runner/state_chain.zig").Access;
    const first = [_]Access{.{ .addr_space = 1, .addr = 4096, .clk = 5, .clk_prev = 0, .value = 7 }};
    const second = [_]Access{.{ .addr_space = 1, .addr = 4096, .clk = 1, .clk_prev = 0, .value = 8 }};
    try spool.appendSegment(.{ .clock_frame = .leaf_local, .global_first_cycle = 1, .cycle_count = 2 }, &first);
    try spool.appendSegment(.{ .clock_frame = .leaf_local, .global_first_cycle = 3, .cycle_count = 2 }, &second);
    var sorted = try spool.finish();
    defer sorted.deinit();
    try std.testing.expectEqual(@as(u64, 5), (try sorted.next()).?.clock);
    try std.testing.expectEqual(@as(u64, 9), (try sorted.next()).?.clock);
    try std.testing.expect((try sorted.next()) == null);
}

test "run admission rejects truncated and surplus records before merge" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const file = try tmp.dir.createFile("run.bin", .{});
    defer file.close();
    const item = Event{ .space = 1, .address = 4096, .clock = 1, .value = 7 };
    try file.writeAll(&item.encode());
    try std.testing.expectError(error.InvalidMemoryRunLength, openRun(tmp.dir, "run.bin", 2));
    var run = try openRun(tmp.dir, "run.bin", 1);
    defer run.deinit();
    try std.testing.expectEqualDeep(item, (try run.next()).?);
    try std.testing.expectEqual(@as(?Event, null), try run.next());
    try file.writeAll(&item.encode());
    try std.testing.expectError(error.InvalidMemoryRunLength, openRun(tmp.dir, "run.bin", 1));
}
