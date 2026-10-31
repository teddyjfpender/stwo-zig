const std = @import("std");
const a = std.testing.allocator;
const opens = @import("openings.zig");
const values = @import("values.zig");
const policy = @import("policy.zig");
const Memory = @import("../../memory.zig").Memory;
fn failure(allocator: std.mem.Allocator, mappings: *const policy.Policy, memory: *const Memory, cells: []const opens.Cell) !void {
    var result = try opens.Owned.init(allocator, .chunk512, mappings, memory, cells);
    defer result.deinit();
}
test "RV64 private RAM capture: current chunks reverse first-before cells without copying untouched RAM" {
    var memory = Memory.init(a, .{});
    defer memory.deinit();
    const base: u64 = 0x1_0000_0000;
    try memory.map(.{ .start = base, .size = 4096, .permissions = .{ .read = true, .write = true } });
    try memory.store(base, 8, 17);
    try memory.store(base + 8, 8, 29);
    try memory.store(base + 512, 8, 31);
    var mappings = try policy.Policy.fromMemory(a, &memory);
    defer mappings.deinit();
    const cells = [_]opens.Cell{ .{ .address = base, .initial = 7, .final = 17, .terminal_clock = 4, .rights = 3 }, .{ .address = base + 512, .initial = 0, .final = 31, .terminal_clock = 8, .rights = 3 } };
    var result = try opens.Owned.init(a, .chunk512, &mappings, &memory, &cells);
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 2), result.chunks.len);
    try std.testing.expectEqual(@as(u64, 7), result.chunks[0].before[0]);
    try std.testing.expectEqual(@as(u64, 17), result.chunks[0].after[0]);
    try std.testing.expectEqual(@as(u64, 29), result.chunks[0].before[1]);
    try std.testing.expectEqual(@as(u64, 29), result.chunks[0].after[1]);
    try std.testing.expectEqual(@as(u32, 0), result.chunks[0].terminal_clocks[1]);
    try std.testing.expectEqual(@as(u64, base >> 9), result.chunks[0].index);
    // Capture may continue after this bounded owner returns: no image pointers
    // escape into chunk values, and lazy-zero neighbors remain canonical.
    try memory.store(base, 8, 99);
    try std.testing.expectEqual(@as(u64, 17), result.chunks[0].after[0]);
    try memory.store(base, 8, 17);
    try std.testing.checkAllAllocationFailures(a, failure, .{ &mappings, &memory, &cells });
    var bad = cells;
    bad[0].final ^= 1;
    try std.testing.expectError(error.PrivateRamFinalImageMismatch, opens.Owned.init(a, .chunk512, &mappings, &memory, &bad));
}

test "RV64 private RAM capture: partial-word mapping is explicitly rejected for the whole-word CPU policy" {
    var memory = Memory.init(a, .{});
    defer memory.deinit();
    try memory.map(.{ .start = 0x1001, .size = 6, .permissions = .{ .read = true, .write = true } });
    var mappings = try policy.Policy.fromMemory(a, &memory);
    defer mappings.deinit();
    const cells = [_]opens.Cell{.{ .address = 0x1000, .initial = 0, .final = 0, .terminal_clock = 4, .rights = 3 }};
    try std.testing.expectError(error.PrivateRamPermissionMismatch, opens.Owned.init(a, .chunk512, &mappings, &memory, &cells));
}
