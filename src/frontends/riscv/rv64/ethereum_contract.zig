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
pub const INPUT_CAPACITY = 4 * 1024 * 1024;
pub fn load(a: std.mem.Allocator, symbols: Symbols, bytes: []const u8, input: []const u8) !elf.LoadedImage {
    const s = symbols;
    if (s.input_end <= s.input_start or s.input_end - s.input_start != INPUT_CAPACITY or
        s.halt_flag != s.input_end or s.halt_flag > std.math.maxInt(u64) - 8 or
        s.output_len != s.halt_flag + 4 or s.output_data != s.halt_flag + 8 or
        s.output_end != s.stack_bottom or s.output_end < s.output_data or
        s.output_end - s.output_data < OUTPUT_BYTES or s.output_end - s.halt_flag > 4 * 1024 * 1024 or
        s.stack_top <= s.stack_bottom or s.stack_top - s.stack_bottom != 16 * 1024 * 1024 or
        s.stack_bottom & 15 != 0 or s.stack_top & 15 != 0 or s.halt_flag & 3 != 0 or
        s.heap_start < s.stack_top or s.heap_start & 15 != 0 or s.heap_end <= s.heap_start or
        s.heap_end - s.heap_start > 224 * 1024 * 1024 or input.len == 0 or input.len > INPUT_CAPACITY - 4) return error.InvalidEthereumIoLayout;
    var loaded = try elf.loadImmutableImage(a, bytes, .{});
    errdefer loaded.deinit();
    const m = &loaded.memory;
    try m.map(.{ .start = s.input_start, .size = INPUT_CAPACITY, .permissions = .{ .read = true } });
    try m.map(.{ .start = s.halt_flag, .size = s.output_end - s.halt_flag, .permissions = .{ .read = true, .write = true } });
    try m.map(.{ .start = s.stack_bottom, .size = s.stack_top - s.stack_bottom, .permissions = .{ .read = true, .write = true } });
    try m.map(.{ .start = s.heap_start, .size = s.heap_end - s.heap_start, .permissions = .{ .read = true, .write = true } });
    var prefix: [4]u8 = undefined;
    std.mem.writeInt(u32, &prefix, @intCast(input.len), .little);
    try m.initialize(s.input_start, &prefix);
    try m.initialize(s.input_start + 4, input);
    return loaded;
}
