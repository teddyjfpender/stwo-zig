const std = @import("std");
const contract = @import("../ethereum_contract.zig");
const a = std.testing.allocator;
const symbols = contract.Symbols{ .input_start = 0x800000, .input_end = 0xc00000, .halt_flag = 0xc00000, .output_len = 0xc00004, .output_data = 0xc00008, .output_end = 0x1000000, .stack_bottom = 0x1000000, .stack_top = 0x2000000, .heap_start = 0x2100000, .heap_end = 0x2200000 };
fn image() [124]u8 {
    var bytes: [124]u8 = @splat(0);
    @memcpy(bytes[0..7], "\x7fELF\x02\x01\x01");
    std.mem.writeInt(u16, bytes[16..18], 2, .little);
    std.mem.writeInt(u16, bytes[18..20], 243, .little);
    std.mem.writeInt(u32, bytes[20..24], 1, .little);
    std.mem.writeInt(u64, bytes[24..32], 0x1000, .little);
    std.mem.writeInt(u64, bytes[32..40], 64, .little);
    std.mem.writeInt(u16, bytes[52..54], 64, .little);
    std.mem.writeInt(u16, bytes[54..56], 56, .little);
    std.mem.writeInt(u16, bytes[56..58], 1, .little);
    std.mem.writeInt(u32, bytes[64..68], 1, .little);
    std.mem.writeInt(u32, bytes[68..72], 5, .little);
    std.mem.writeInt(u64, bytes[72..80], 120, .little);
    std.mem.writeInt(u64, bytes[80..88], 0x1000, .little);
    std.mem.writeInt(u64, bytes[96..104], 4, .little);
    std.mem.writeInt(u64, bytes[104..112], 4, .little);
    std.mem.writeInt(u64, bytes[112..120], 4, .little);
    std.mem.writeInt(u32, bytes[120..124], 0x00000013, .little);
    return bytes;
}
fn exercise(allocator: std.mem.Allocator) !void {
    const bytes = image();
    var loaded = try contract.load(allocator, symbols, &bytes, &.{ 0x12, 0x34, 0x56 });
    defer loaded.deinit();
    try std.testing.expectEqual(@as(u64, 3), try loaded.memory.load(symbols.input_start, 4));
    try std.testing.expectEqual(@as(u64, 0x12), try loaded.memory.load(symbols.input_start + 4, 1));
    try std.testing.expectEqual(@as(u64, 0), try loaded.memory.load(symbols.input_start + 7, 1));
    try std.testing.expectError(error.AccessDenied, loaded.memory.store(symbols.input_start, 4, 0));
    try std.testing.expectEqual(@as(u64, 0), try loaded.memory.load(symbols.heap_start, 8));
    _ = try loaded.memory.store(symbols.heap_start, 8, 0x123456789abcdef0);
    try std.testing.expectEqual(@as(u64, 0x123456789abcdef0), try loaded.memory.load(symbols.heap_start, 8));
}
test "Ethereum ABI frames readonly input and maps sparse writable heap with complete failure cleanup" {
    try exercise(a);
    try std.testing.checkAllAllocationFailures(a, exercise, .{});
}
test "Ethereum ABI rejects invalid layouts before ELF allocation and rejects overlapping heap" {
    try std.testing.expectError(error.InvalidEthereumIoLayout, contract.load(a, symbols, &.{}, &.{}));
    var bad = symbols;
    bad.heap_start = symbols.stack_bottom;
    try std.testing.expectError(error.InvalidEthereumIoLayout, contract.load(a, bad, &.{}, &.{1}));
    bad = symbols;
    bad.output_data += 1;
    try std.testing.expectError(error.InvalidEthereumIoLayout, contract.load(a, bad, &.{}, &.{1}));
    bad = symbols;
    bad.heap_start = symbols.stack_top;
    // The heap overlaps a deliberately relocated ELF executable mapping.
    var bytes = image();
    std.mem.writeInt(u64, bytes[24..32], symbols.stack_top, .little);
    std.mem.writeInt(u64, bytes[80..88], symbols.stack_top, .little);
    try std.testing.expectError(error.OverlappingRegion, contract.load(a, bad, &bytes, &.{1}));
}

test "Ethereum immutable ROM profile rejects writable executable segments before allocation" {
    var bytes = image();
    std.mem.writeInt(u32, bytes[68..72], 7, .little);
    var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    try std.testing.expectError(error.MutableExecutable, contract.load(failing.allocator(), symbols, &bytes, &.{1}));
    try std.testing.expectEqual(@as(usize, 0), failing.alloc_index);
    // Generic execution still admits self-modifying RV64 code explicitly.
    var native = try @import("../elf.zig").loadImage(a, &bytes, .{});
    defer native.deinit();
    try native.memory.store(0x1000, 4, 0x00100093);
    try std.testing.expectEqual(@as(u32, 0x00100093), try native.memory.fetch(0x1000));
}
