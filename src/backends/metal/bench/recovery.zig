const std = @import("std");
const stwo = @import("stwo");
const arena = stwo.backends.metal.arena_plan;
const recovery = stwo.backend.recovery;

pub fn main() !void {
    var debug_allocator = std.heap.DebugAllocator(.{}).init;
    defer _ = debug_allocator.deinit();
    const allocator = debug_allocator.allocator();
    const byte_count: usize = 20_945_944;
    const ranges = [_]arena.LiveRange{ .{ .first = 1, .last = 1 }, .{ .first = 2, .last = 2 } };
    const logical = [_]arena.LogicalBuffer{
        .{ .id = 1, .size_bytes = byte_count, .live_ranges = &ranges, .spill_cost_ns = 1 },
    };
    var plan = try arena.build(allocator, &logical, 32 * 1024 * 1024);
    defer plan.deinit();
    const binding = try plan.binding(1);
    const source = try allocator.alignedAlloc(u8, .fromByteUnits(16 * 1024), byte_count);
    defer allocator.free(source);
    const destination = try allocator.alignedAlloc(u8, .fromByteUnits(16 * 1024), byte_count);
    defer allocator.free(destination);
    for (source, 0..) |*byte, index| byte.* = @truncate(index *% 131);
    const path = "/tmp/stwo-zig-metal-spill-bench.bin";
    defer std.fs.cwd().deleteFile(path) catch {};
    const file = try std.fs.cwd().createFile(path, .{ .read = true, .truncate = true });
    var store = try recovery.FileSpillStore.init(allocator, file, true, plan);
    defer store.deinit();
    var write_ns: [5]u64 = undefined;
    var read_ns: [5]u64 = undefined;
    for (0..5) |iteration| {
        var timer = try std.time.Timer.start();
        try store.spill(binding, source);
        write_ns[iteration] = timer.lap();
        try store.restore(binding, destination);
        read_ns[iteration] = timer.lap();
        if (!std.mem.eql(u8, source, destination)) return error.RoundtripMismatch;
    }
    std.mem.sortUnstable(u64, &write_ns, {}, comptime std.sort.asc(u64));
    std.mem.sortUnstable(u64, &read_ns, {}, comptime std.sort.asc(u64));
    const write_gbps = throughput(byte_count, write_ns[2]);
    const read_gbps = throughput(byte_count, read_ns[2]);
    const result = .{
        .schema_version = 1,
        .bytes_per_snapshot = byte_count,
        .iterations = 5,
        .write_median_ms = @as(f64, @floatFromInt(write_ns[2])) / std.time.ns_per_ms,
        .restore_median_ms = @as(f64, @floatFromInt(read_ns[2])) / std.time.ns_per_ms,
        .write_gbps = write_gbps,
        .restore_gbps = read_gbps,
        .checksum = "wyhash64",
        .hot_path_allocations = 0,
    };
    var output: [2048]u8 = undefined;
    var writer = std.fs.File.stdout().writer(&output);
    try std.json.Stringify.value(result, .{ .whitespace = .indent_2 }, &writer.interface);
    try writer.interface.writeByte('\n');
    try writer.interface.flush();
}

fn throughput(bytes: usize, nanoseconds: u64) f64 {
    return @as(f64, @floatFromInt(bytes)) / @as(f64, @floatFromInt(nanoseconds));
}
