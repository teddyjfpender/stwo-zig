//! Independent bounded caller arithmetic/access cache policies and accounting.
const std = @import("std");
const Provider = @import("block_v6_provider_commitment_staging_v1.zig");
const External = @import("block_v6_external_commitment_store_v1.zig");
pub const Policy = struct {
    storage: @import("block_v6_caller_commitment_store_v1.zig").Limits = @import("block_v6_caller_commitment_store_v1.zig").DEFAULT_LIMITS,
    max_total_file_bytes: u64 = 128 << 30,
    pub fn validate(self: Policy) !void {
        return (Provider.Policy{ .storage = self.storage, .max_total_file_bytes = self.max_total_file_bytes }).validate();
    }
    pub fn remaining(self: Policy, used: u64) !@import("block_v6_caller_commitment_store_v1.zig").Limits {
        return (Provider.Policy{ .storage = self.storage, .max_total_file_bytes = self.max_total_file_bytes }).remaining(used);
    }
};
pub const Statistics = Provider.Statistics;
pub const ExternalPolicy = struct {
    storage: External.Limits = .{},
    max_total_file_bytes: u64 = 128 << 30,
    pub fn validate(self: ExternalPolicy) !void {
        try (Policy{ .storage = self.storage.storage, .max_total_file_bytes = self.max_total_file_bytes }).validate();
        if (self.storage.max_raw_bytes == 0 or self.storage.max_slots == 0) return error.InvalidExternalCheckpointPolicy;
    }
    pub fn remaining(self: ExternalPolicy, used: u64) !External.Limits {
        try self.validate();
        var result = self.storage;
        result.storage = try (Policy{ .storage = self.storage.storage, .max_total_file_bytes = self.max_total_file_bytes }).remaining(used);
        return result;
    }
};
pub const ExternalStatistics = struct {
    pcs: Statistics = .{},
    raw_written_bytes: u64 = 0,
    raw_read_bytes: u64 = 0,
    max_loaded_bytes: usize = 0,
    pub fn totalBytes(self: ExternalStatistics) !u64 {
        return std.math.add(u64, self.raw_written_bytes, self.pcs.written_bytes);
    }
    pub fn wrote(self: *ExternalStatistics, pin: External.Pin, ns: u64) !void {
        try self.pcs.wrote(pin.pcs, ns);
        self.raw_written_bytes = try std.math.add(u64, self.raw_written_bytes, pin.raw.bytes);
        self.max_loaded_bytes = @max(self.max_loaded_bytes, try std.math.add(usize, pin.raw_loaded_bytes, pin.pcs.loaded_bytes));
    }
};
pub fn name(index: u32, buffer: *[96]u8) ![]const u8 {
    return std.fmt.bufPrint(buffer, "caller-{d}.checkpoint", .{index});
}
pub fn externalName(index: u32, suffix: []const u8, buffer: *[96]u8) ![]const u8 {
    return std.fmt.bufPrint(buffer, "caller-access-{d}.{s}", .{ index, suffix });
}
