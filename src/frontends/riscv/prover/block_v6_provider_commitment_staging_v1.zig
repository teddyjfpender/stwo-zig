//! Explicit bounded retention policy and I/O accounting for global providers.
const std = @import("std");
const Store = @import("block_v6_provider_commitment_store_v1.zig");
pub const Policy = struct {
    storage: Store.Limits = .{},
    max_total_file_bytes: u64 = 128 << 30,
    pub fn validate(self: Policy) !void {
        if (self.max_total_file_bytes == 0 or self.storage.max_columns == 0 or self.storage.max_file_bytes == 0 or self.storage.max_loaded_bytes == 0 or self.storage.max_log_size > 30) return error.InvalidProviderCheckpointPolicy;
    }
    pub fn remaining(self: Policy, used: u64) !Store.Limits {
        try self.validate();
        if (used >= self.max_total_file_bytes) return error.ProviderCheckpointResourceLimit;
        var limits = self.storage;
        limits.max_file_bytes = @min(limits.max_file_bytes, self.max_total_file_bytes - used);
        return limits;
    }
};
pub const Statistics = struct {
    written_bytes: u64 = 0,
    column_bytes: u64 = 0,
    merkle_bytes: u64 = 0,
    coefficient_bytes: u64 = 0,
    read_bytes: u64 = 0,
    reused_first_rounds: u64 = 0,
    max_loaded_bytes: usize = 0,
    write_ns: u64 = 0,
    restore_ns: u64 = 0,
    pub fn wrote(self: *Statistics, pin: Store.Pin, ns: u64) !void {
        self.written_bytes = try std.math.add(u64, self.written_bytes, pin.bytes);
        self.column_bytes = try std.math.add(u64, self.column_bytes, pin.column_bytes);
        self.merkle_bytes = try std.math.add(u64, self.merkle_bytes, pin.merkle_bytes);
        self.coefficient_bytes = try std.math.add(u64, self.coefficient_bytes, pin.coefficient_bytes);
        self.max_loaded_bytes = @max(self.max_loaded_bytes, pin.loaded_bytes);
        self.write_ns = try std.math.add(u64, self.write_ns, ns);
    }
    pub fn restored(self: *Statistics, pin: Store.Pin, ns: u64) !void {
        self.read_bytes = try std.math.add(u64, self.read_bytes, pin.bytes);
        self.reused_first_rounds = try std.math.add(u64, self.reused_first_rounds, 1);
        self.restore_ns = try std.math.add(u64, self.restore_ns, ns);
    }
};
pub fn lookupName(index: u32, buffer: *[64]u8) ![]const u8 {
    return std.fmt.bufPrint(buffer, "lookup-{d}.checkpoint", .{index});
}
pub const PROGRAM_NAME = "global-program.checkpoint";

pub const LOOKUP_FIXED_NAME = "lookup-fixed.checkpoint";
