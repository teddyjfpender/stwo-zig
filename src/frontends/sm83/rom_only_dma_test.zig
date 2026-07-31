const std = @import("std");
const dma = @import("runner/dma.zig");
const live_dma = @import("runner/live_dma.zig");
const Memory = @import("runner/flat_memory.zig").Memory;

test "ROM-only live DMA copies exactly 160 bytes in 163 M-cycles" {
    var memory = try Memory.init(std.testing.allocator);
    defer memory.deinit();
    for (0..dma.OAM_LENGTH) |index|
        memory.bytes[0xc000 + index] = @intCast(index);

    var controller = try live_dma.Controller.init(.{});
    try memory.attachDma(&controller);
    defer memory.detachDma();

    memory.write(dma.DMA_ADDRESS, 0xc0);
    memory.tickMcycle();
    for (1..163) |_| memory.tickMcycle();

    try std.testing.expectEqual(dma.Phase.idle, controller.state.phase);
    try std.testing.expectEqual(@as(u32, 163), controller.state.clock);
    try std.testing.expectEqualSlices(
        u8,
        memory.bytes[0xc000 .. 0xc000 + @as(usize, dma.OAM_LENGTH)],
        memory.bytes[dma.OAM_START .. @as(usize, dma.OAM_START) + dma.OAM_LENGTH],
    );
}

test "ROM-only live DMA drives blocked main-bus reads from its source" {
    var memory = try Memory.init(std.testing.allocator);
    defer memory.deinit();
    memory.bytes[0xc000] = 0x42;
    memory.bytes[0x1234] = 0x99;

    var controller = try live_dma.Controller.init(.{});
    try memory.attachDma(&controller);
    defer memory.detachDma();

    memory.write(dma.DMA_ADDRESS, 0xc0);
    memory.tickMcycle();
    memory.tickMcycle();
    try std.testing.expectEqual(@as(u8, 0x42), memory.read(0x1234));
    memory.tickMcycle();

    try std.testing.expectEqual(@as(u8, 0x42), memory.bytes[dma.OAM_START]);
    try std.testing.expectEqual(@as(u8, 0x99), memory.bytes[0x1234]);
}
