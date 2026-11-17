//! Reference hooks of the pipeline's own tests: the shared RV64 guest layout
//! (input window, halt flag, output page, stack and heap) with a 4..16 MiB
//! power-of-two input window. Product lines supply their own hooks module.
const std = @import("std");
const rv = @import("stwo_riscv_rv64").execution;

pub const label = "reference";
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
pub const INPUT_CAPACITY_MIN = 4 * 1024 * 1024;
pub const INPUT_CAPACITY_MAX = 16 * 1024 * 1024;
pub const MAX_INPUT_BYTES = INPUT_CAPACITY_MAX - 4;
pub const service_families = .{};

pub fn admitsProfile(profile: rv.execution_profile.Profile) bool {
    return profile == .ethereum_services_v2 or rv.execution_profile.isV3(profile);
}

pub fn haltFlag(symbols: Symbols) u64 {
    return symbols.halt_flag;
}

pub fn inputWindow(s: Symbols) ?u64 {
    if (s.input_end <= s.input_start) return null;
    const window = s.input_end - s.input_start;
    if (window < INPUT_CAPACITY_MIN or window > INPUT_CAPACITY_MAX or !std.math.isPowerOfTwo(window)) return null;
    return window;
}

pub fn loadImage(a: std.mem.Allocator, s: Symbols, bytes: []const u8, input: []const u8) !rv.elf.LoadedImage {
    const window = inputWindow(s) orelse return error.InvalidGuestIoLayout;
    if (s.halt_flag != s.input_end or s.halt_flag > std.math.maxInt(u64) - 8 or
        s.output_len != s.halt_flag + 4 or s.output_data != s.halt_flag + 8 or
        s.output_end != s.stack_bottom or s.output_end < s.output_data or
        s.output_end - s.output_data < OUTPUT_BYTES or s.output_end - s.halt_flag > 4 * 1024 * 1024 or
        s.stack_top <= s.stack_bottom or s.stack_top - s.stack_bottom != 16 * 1024 * 1024 or
        s.stack_bottom & 15 != 0 or s.stack_top & 15 != 0 or s.halt_flag & 3 != 0 or
        s.heap_start < s.stack_top or s.heap_start & 15 != 0 or s.heap_end <= s.heap_start or
        s.heap_end - s.heap_start > 224 * 1024 * 1024 or input.len == 0 or input.len > window - 4) return error.InvalidGuestIoLayout;
    var loaded = try rv.elf.loadImmutableImage(a, bytes, .{});
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
