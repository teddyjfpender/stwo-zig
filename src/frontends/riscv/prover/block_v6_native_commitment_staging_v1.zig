//! Bounded, optional producer checkpoint storage. These files are proving
//! material, never verifier authority or a replacement for global closure.
const std = @import("std");
const Store = @import("block_v6_native_commitment_store_v1.zig");
pub const Policy = struct {
    store: Store.Limits = .{},
    max_total_file_bytes: u64 = 128 << 30,

    pub fn validate(self: Policy) !void {
        if (self.max_total_file_bytes == 0 or self.store.max_columns == 0 or
            self.store.max_file_bytes == 0 or self.store.max_loaded_bytes == 0)
            return error.InvalidNativeCommitmentStagingPolicy;
    }
    pub fn remaining(self: Policy, used: u64) !Store.Limits {
        try self.validate();
        if (used >= self.max_total_file_bytes) return error.NativeCommitmentStorageBudgetExceeded;
        var result = self.store;
        result.max_file_bytes = @min(result.max_file_bytes, self.max_total_file_bytes - used);
        return result;
    }
};
pub const Statistics = struct {
    written_bytes: u64 = 0,
    column_bytes: u64 = 0,
    merkle_bytes: u64 = 0,
    checkpoint_read_bytes: u64 = 0,
    raw_witness_read_bytes: u64 = 0,
    write_ns: u64 = 0,
    /// Includes raw witness reconstruction and either PCS restore or recommit.
    native_restore_ns: u64 = 0,
    reused_first_rounds: u64 = 0,
};
pub fn name(index: u32, buffer: *[96]u8) ![]const u8 {
    return std.fmt.bufPrint(buffer, "native-commitment-{d}.checkpoint", .{index});
}
