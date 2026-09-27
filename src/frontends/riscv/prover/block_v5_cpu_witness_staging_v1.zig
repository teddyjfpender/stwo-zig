//! Resource policy and deterministic names for first-pass witness proposals.
//! The independently retained roots, not these files, govern admission.
const std = @import("std");
const Native = @import("block_v5_native_columns_stage_v1.zig");
const Store = @import("block_v5_witness_columns_store_v1.zig");
const Caller = @import("block_v5_caller_columns_stage_v1.zig");
pub const Limits = struct {
    native: Native.Limits = .{
        .columns = .{ .max_columns = 2048, .max_log_size = 24, .max_file_bytes = 32 << 30, .max_loaded_bytes = 16 << 30 },
        .max_public_words = 32 << 20,
        .max_public_bytes = 256 << 20,
    },
    caller: Caller.Limits = .{},
    max_total_file_bytes: u64 = 512 << 30,
};
pub fn nativeName(index: u32, buffer: *[96]u8) ![]const u8 {
    return std.fmt.bufPrint(buffer, "native-witness-{d}.columns", .{index});
}
pub fn callerName(index: u32, buffer: *[96]u8) ![]const u8 {
    return std.fmt.bufPrint(buffer, "caller-witness-{d}.columns", .{index});
}
pub fn admitBytes(total: *u64, pin: Store.Pin, limits: Limits) !void {
    const next = try std.math.add(u64, total.*, pin.bytes);
    if (next > limits.max_total_file_bytes) return error.V5WitnessAggregateFileLimit;
    total.* = next;
}
