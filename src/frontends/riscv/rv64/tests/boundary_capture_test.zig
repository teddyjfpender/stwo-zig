const std = @import("std");
const C = @import("../boundary_capture.zig");
const Memory = @import("../memory.zig").Memory;
const Secp = @import("../ethereum_services/session.zig");
const machine = @import("../machine.zig");
const a = std.testing.allocator;
const base: u64 = 0x200000000;
fn mapped() !Memory {
    var memory = Memory.init(a, .{});
    errdefer memory.deinit();
    try memory.map(.{ .start = base, .size = 4096, .permissions = .{ .read = true, .write = true } });
    return memory;
}
fn keccak(clock: u64, before: u64, after: u64) Secp.Event {
    return .{ .keccak = .{ .call_id = 1, .clock = clock, .pc = 4096, .pointer = base, .before = @splat(before), .after = @splat(after) } };
}
test "RV64 boundary capture first/last words, large clocks, typed services and reset" {
    var memory = try mapped();
    defer memory.deinit();
    const start: u64 = 1 << 40;
    var capture = try C.Capture.init(a, start, 5, 100);
    defer capture.deinit();
    try capture.appendEvent(keccak(start + 1, 0, 1), &memory);
    var add = Secp.SecpCall{ .kind = .add, .call_id = 1, .clock = start + 2, .pc = 4100, .pointer = base, .before = @splat(1), .after = @splat(1) };
    @memset(add.after[0..12], 2);
    try capture.appendEvent(.{ .secp = add }, &memory);
    const cells = try capture.sorted(a);
    defer a.free(cells);
    try std.testing.expectEqual(@as(usize, 25), cells.len);
    for (cells, 0..) |cell, i| {
        try std.testing.expectEqual(base + 8 * i, cell.address);
        try std.testing.expectEqual(@as(u64, 0), cell.initial);
        try std.testing.expectEqual(@as(u64, if (i < 12) 2 else 1), cell.final);
        try std.testing.expectEqual(@as(u32, if (i < 24) 8 else 4), cell.terminal_clock);
    }
    try capture.clearRetainingCapacity();
    try capture.appendEvent(keccak(start + 3, 1, 1), &memory);
    try std.testing.expectEqual(@as(u32, 4), capture.cells.get(base).?.terminal_clock);
}
test "RV64 boundary capture rejects partial publication and missing sidecars" {
    var memory = try mapped();
    defer memory.deinit();
    var capture = try C.Capture.init(a, 0, 5, 100);
    defer capture.deinit();
    try capture.appendEvent(keccak(1, 0, 1), &memory);
    var corrupt = keccak(2, 1, 2);
    corrupt.keccak.before[24] = 9;
    try std.testing.expectError(error.BoundaryWordDiscontinuity, capture.appendEvent(corrupt, &memory));
    try std.testing.expectEqual(@as(u32, 1), capture.steps);
    try std.testing.expectEqual(@as(u64, 1), capture.cells.get(base).?.final);
    try std.testing.expectError(error.MissingBoundaryService, capture.append(corrupt.retirement(), &memory));
    try std.testing.expectError(error.InvalidBoundaryClock, capture.appendEvent(keccak(3, 1, 2), &memory));
}
fn allocationCase(allocator: std.mem.Allocator) !void {
    var memory = try mapped();
    defer memory.deinit();
    var capture = try C.Capture.init(allocator, 0, 2, 100);
    defer capture.deinit();
    capture.appendEvent(keccak(1, 0, 1), &memory) catch |err| {
        try std.testing.expectEqual(@as(u32, 0), capture.steps);
        try std.testing.expectEqual(@as(u32, 0), capture.cells.count());
        return err;
    };
    const cells = try capture.sorted(allocator);
    defer allocator.free(cells);
}
test "RV64 boundary capture OOM is atomic and leak free" {
    try std.testing.checkAllAllocationFailures(a, allocationCase, .{});
}
test "RV64 boundary capture subword load/store share one RAM word" {
    var memory = try mapped();
    defer memory.deinit();
    try memory.map(.{ .start = 4096, .size = 8, .permissions = .{ .read = true, .execute = true } });
    var code: [8]u8 = undefined;
    std.mem.writeInt(u32, code[0..4], 0x00208023, .little);
    std.mem.writeInt(u32, code[4..8], 0x0000c183, .little);
    try memory.initialize(4096, &code);
    var cpu = machine.Cpu.init(4096, 0);
    cpu.regs[1] = base + 3;
    cpu.regs[2] = 0x42;
    var capture = try C.Capture.init(a, 0, 3, 4);
    defer capture.deinit();
    try capture.append(try cpu.step(&memory), &memory);
    try capture.append(try cpu.step(&memory), &memory);
    const cell = capture.cells.get(base).?;
    try std.testing.expectEqual(@as(u64, 0), cell.initial);
    try std.testing.expectEqual(@as(u64, 0x42000000), cell.final);
    try std.testing.expectEqual(@as(u32, 8), cell.terminal_clock);
    try std.testing.expectEqual(@as(u32, 1), capture.cells.count());
}
