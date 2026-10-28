//! Same-event source transport comparison. Neither route grants proof authority;
//! the sorted table still needs a STARK permutation and state closure.
const std = @import("std");
const Event = @import("air/block/memory_event.zig").Event;
const Radix = @import("air/block/memory_radix_sort.zig");
const Spool = @import("air/block/memory_spool.zig").Spool;

fn event(index: usize) Event {
    return .{
        .space = 1,
        .address = 0x2000 + @as(u32, @intCast(index % 65536)) * 4,
        .clock = (@as(u64, 1) << 48) + @as(u64, index) * 4 + 1,
        .value = @intCast(index % 65536),
    };
}

test "block-v5 RAM transport in-memory versus external sorter" {
    const a = std.heap.page_allocator;
    const count: usize = if (std.process.hasEnvVarConstant("STWO_BLOCK_SORT_4M")) 1 << 22 else 1 << 20;
    var timer = try std.time.Timer.start();
    const events = try a.alloc(Event, count);
    defer a.free(events);
    const scratch = try a.alloc(Event, count);
    defer a.free(scratch);
    for (events, 0..) |*item, index| item.* = event(index);
    const in_memory_build_ns = timer.read();
    timer.reset();
    try Radix.sort(events, scratch);
    const in_memory_sort_ns = timer.read();
    for (events[1..], 1..) |item, index| try std.testing.expect(Event.lessThan({}, events[index - 1], item));

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var spool = try Spool.init(a, tmp.dir, 1 << 18);
    defer spool.deinit();
    timer.reset();
    for (0..count) |index| try spool.append(event(index));
    const external_append_ns = timer.read();
    timer.reset();
    var reader = try spool.finish();
    defer reader.deinit();
    const external_sort_ns = timer.read();
    timer.reset();
    for (events) |expected| try std.testing.expectEqualDeep(expected, (try reader.next()) orelse return error.TruncatedMemoryRun);
    try std.testing.expect((try reader.next()) == null);
    const external_read_ns = timer.read();
    std.debug.print("RAM_SORT_TRANSPORT events={d} event_size={d} in_memory_build_ns={d} in_memory_sort_ns={d} external_append_ns={d} external_sort_ns={d} external_read_ns={d} external_initial_runs={d} external_merge_passes={d} external_bytes_read={d} external_bytes_written={d} exact_sorted_events_equal=true scope=source_transport_only\n", .{ count, @sizeOf(Event), in_memory_build_ns, in_memory_sort_ns, external_append_ns, external_sort_ns, external_read_ns, spool.statistics.initial_runs, spool.statistics.merge_passes, spool.statistics.bytes_read, spool.statistics.bytes_written });
}
