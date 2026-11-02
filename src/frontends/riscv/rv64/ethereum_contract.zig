//! Software Ethereum guest ABI v0. Execution only; no proof capability.
const std = @import("std");
const elf = @import("elf.zig");
pub const Symbols = struct {
    input_start: u64,
    input_end: u64,
    halt_flag: u64,
    output_len: u64,
    output_data: u64,
    output_end: u64,
    stack_bottom: u64,
    stack_top: u64,
    heap_start: u64,
    heap_end: u64,
};
pub const OUTPUT_BYTES = 43;
/// Legacy (pinned round-five guest) input window.
pub const INPUT_CAPACITY = 4 * 1024 * 1024;
/// Largest admitted input window. A guest declares its window through the
/// `__input_start`/`__input_end` symbols; the window must be a power of two in
/// [INPUT_CAPACITY, INPUT_CAPACITY_MAX]. Guests linked with the legacy window
/// load exactly as before.
pub const INPUT_CAPACITY_MAX = 16 * 1024 * 1024;
pub fn inputWindow(s: Symbols) ?u64 {
    if (s.input_end <= s.input_start) return null;
    const window = s.input_end - s.input_start;
    if (window < INPUT_CAPACITY or window > INPUT_CAPACITY_MAX or !std.math.isPowerOfTwo(window)) return null;
    return window;
}
pub fn load(a: std.mem.Allocator, symbols: Symbols, bytes: []const u8, input: []const u8) !elf.LoadedImage {
    const s = symbols;
    const window = inputWindow(s) orelse return error.InvalidEthereumIoLayout;
    if (
        s.halt_flag != s.input_end or s.halt_flag > std.math.maxInt(u64) - 8 or
        s.output_len != s.halt_flag + 4 or s.output_data != s.halt_flag + 8 or
        s.output_end != s.stack_bottom or s.output_end < s.output_data or
        s.output_end - s.output_data < OUTPUT_BYTES or s.output_end - s.halt_flag > 4 * 1024 * 1024 or
        s.stack_top <= s.stack_bottom or s.stack_top - s.stack_bottom != 16 * 1024 * 1024 or
        s.stack_bottom & 15 != 0 or s.stack_top & 15 != 0 or s.halt_flag & 3 != 0 or
        s.heap_start < s.stack_top or s.heap_start & 15 != 0 or s.heap_end <= s.heap_start or
        s.heap_end - s.heap_start > 224 * 1024 * 1024 or input.len == 0 or input.len > window - 4) return error.InvalidEthereumIoLayout;
    var loaded = try elf.loadImmutableImage(a, bytes, .{});
    errdefer loaded.deinit();
    const m = &loaded.memory;
    try m.map(.{ .start = s.input_start, .size = window, .permissions = .{ .read = true } });
    try m.map(.{ .start = s.halt_flag, .size = s.output_end - s.halt_flag, .permissions = .{ .read = true, .write = true } });
    try m.map(.{ .start = s.stack_bottom, .size = s.stack_top - s.stack_bottom, .permissions = .{ .read = true, .write = true } });
    try m.map(.{ .start = s.heap_start, .size = s.heap_end - s.heap_start, .permissions = .{ .read = true, .write = true } });
    var prefix: [4]u8 = undefined;
    std.mem.writeInt(u32, &prefix, @intCast(input.len), .little);
    try m.initialize(s.input_start, &prefix);
    try m.initialize(s.input_start + 4, input);
    return loaded;
}

test "input window admits legacy and wide power-of-two windows only" {
    const base = Symbols{ .input_start = 0x00800000, .input_end = 0x00C00000, .halt_flag = 0x00C00000, .output_len = 0x00C00004, .output_data = 0x00C00008, .output_end = 0x01000000, .stack_bottom = 0x01000000, .stack_top = 0x02000000, .heap_start = 0x02100000, .heap_end = 0x10000000 };
    try std.testing.expectEqual(@as(?u64, INPUT_CAPACITY), inputWindow(base));
    var wide = base;
    wide.input_end = 0x01800000;
    try std.testing.expectEqual(@as(?u64, INPUT_CAPACITY_MAX), inputWindow(wide));
    var odd = base;
    odd.input_end = 0x00800000 + 6 * 1024 * 1024;
    try std.testing.expectEqual(@as(?u64, null), inputWindow(odd));
    var big = base;
    big.input_end = 0x00800000 + 32 * 1024 * 1024;
    try std.testing.expectEqual(@as(?u64, null), inputWindow(big));
    var small = base;
    small.input_end = 0x00800000 + 2 * 1024 * 1024;
    try std.testing.expectEqual(@as(?u64, null), inputWindow(small));
}
