//! Explicit software CSP fixture I/O contract, independent of proving.
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
};
pub const Config = struct {
    elf: []const u8,
    input: []const u8,
    expected_digest: []const u8,
    symbols: Symbols,
    samples: u8 = 7,
    max_steps: u64 = 10000000,
};

pub fn load(a: std.mem.Allocator, config: Config, bytes: []const u8, input: []const u8) !elf.LoadedImage {
    const symbols = config.symbols;
    // A narrow benchmark contract, not inference of an arbitrary guest ABI.
    if (symbols.input_end <= symbols.input_start or symbols.input_end - symbols.input_start != 4096 or
        symbols.halt_flag != symbols.input_end or symbols.halt_flag > std.math.maxInt(u64) - 8 or
        symbols.output_len != symbols.halt_flag + 4 or symbols.output_data != symbols.halt_flag + 8 or
        symbols.output_end != symbols.stack_bottom or symbols.output_end < symbols.output_data or
        symbols.output_end - symbols.output_data < 32 or symbols.stack_top <= symbols.stack_bottom or
        symbols.stack_top - symbols.stack_bottom < 256 or symbols.stack_top - symbols.stack_bottom > 1048576 or
        symbols.stack_bottom & 15 != 0 or symbols.stack_top & 15 != 0 or
        symbols.output_end - symbols.halt_flag > 1048576 or symbols.halt_flag & 3 != 0 or input.len > 4096) return error.InvalidIoLayout;
    var loaded = try elf.loadImage(a, bytes, .{});
    errdefer loaded.deinit();
    const memory = &loaded.memory;
    try memory.map(.{ .start = symbols.input_start, .size = 4096, .permissions = .{ .read = true } });
    try memory.map(.{ .start = symbols.halt_flag, .size = symbols.output_end - symbols.halt_flag, .permissions = .{ .read = true, .write = true } });
    try memory.map(.{ .start = symbols.stack_bottom, .size = symbols.stack_top - symbols.stack_bottom, .permissions = .{ .read = true, .write = true } });
    try memory.initialize(symbols.input_start, input);
    return loaded;
}
