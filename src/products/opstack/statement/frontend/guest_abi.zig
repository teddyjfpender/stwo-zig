//! OP Stack (Kona) RV64 guest ABI. The guest declares its input window through
//! `__input_start`/`__input_end`; the window is a power of two in
//! [INPUT_CAPACITY, INPUT_CAPACITY_MAX] (4..32 MiB). The halt flag sits at the
//! window end and the 43-byte output page follows at +8. Execution only: the
//! proof binding is the pipeline's terminal AIR over the same addresses.
const std = @import("std");
const elf = @import("stwo_riscv_rv64").execution.elf;
const statement = @import("statement.zig");

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
/// Smallest admitted input window (the legacy 4 MiB layout).
pub const INPUT_CAPACITY = 4 * 1024 * 1024;
/// Largest admitted input window. Kona transition witnesses exceed 16 MiB.
pub const INPUT_CAPACITY_MAX = 32 * 1024 * 1024;
/// Stack size every admitted guest links with.
pub const STACK_BYTES = 16 * 1024 * 1024;
/// Largest admitted heap.
pub const HEAP_MAX_BYTES = 224 * 1024 * 1024;
/// Largest admitted output control page (halt flag, length, data).
pub const OUTPUT_PAGE_MAX_BYTES = 4 * 1024 * 1024;

pub fn inputWindow(s: Symbols) ?u64 {
    if (s.input_end <= s.input_start) return null;
    const window = s.input_end - s.input_start;
    if (window < INPUT_CAPACITY or window > INPUT_CAPACITY_MAX or !std.math.isPowerOfTwo(window)) return null;
    return window;
}

/// Reject any layout the pipeline's terminal and RAM statements cannot bind.
pub fn validate(s: Symbols, input_len: usize) error{InvalidGuestIoLayout}!u64 {
    const window = inputWindow(s) orelse return error.InvalidGuestIoLayout;
    if (s.halt_flag != s.input_end or s.halt_flag > std.math.maxInt(u64) - 8 or
        s.output_len != s.halt_flag + 4 or s.output_data != s.halt_flag + 8 or
        s.output_end != s.stack_bottom or s.output_end < s.output_data or
        s.output_end - s.output_data < statement.OUTPUT_BYTES or s.output_end - s.halt_flag > OUTPUT_PAGE_MAX_BYTES or
        s.stack_top <= s.stack_bottom or s.stack_top - s.stack_bottom != STACK_BYTES or
        s.stack_bottom & 15 != 0 or s.stack_top & 15 != 0 or s.halt_flag & 3 != 0 or
        s.heap_start < s.stack_top or s.heap_start & 15 != 0 or s.heap_end <= s.heap_start or
        s.heap_end - s.heap_start > HEAP_MAX_BYTES or input_len == 0 or input_len > window - 4) return error.InvalidGuestIoLayout;
    return window;
}

/// Map ELF and length-prefixed input into the immutable initial image.
pub fn load(a: std.mem.Allocator, s: Symbols, bytes: []const u8, input: []const u8) !elf.LoadedImage {
    const window = try validate(s, input.len);
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
