//! Optional bounded auxiliary-witness/PCS reuse. Independent original
//! proposals and fresh proof verification remain the only admission authority.
const std = @import("std");
pub const Policy = struct {
    storage: @import("block_v6_native_commitment_store_v1.zig").Limits = .{},
    max_total_file_bytes: u64 = 128 << 30,
    pub fn validate(self: Policy) !void {
        if (self.max_total_file_bytes == 0 or self.storage.max_columns == 0 or self.storage.max_file_bytes == 0 or self.storage.max_loaded_bytes == 0)
            return error.InvalidAccessCommitmentStagingPolicy;
    }
    pub fn remaining(self: Policy, used: u64) !@TypeOf(self.storage) {
        try self.validate();
        if (used >= self.max_total_file_bytes) return error.AccessCommitmentStorageBudgetExceeded;
        var result = self.storage;
        result.max_file_bytes = @min(result.max_file_bytes, self.max_total_file_bytes - used);
        return result;
    }
};
pub const Statistics = struct {
    written_bytes: u64 = 0,
    read_bytes: u64 = 0,
    raw_witness_payload_bytes: u64 = 0,
    column_bytes: u64 = 0,
    merkle_bytes: u64 = 0,
    write_ns: u64 = 0,
    restore_ns: u64 = 0,
    reused_access_trees: u64 = 0,
};
pub fn name(index: u32, buffer: *[96]u8) ![]const u8 {
    return std.fmt.bufPrint(buffer, "access-commitment-{d}.checkpoint", .{index});
}

/// Restore exact typed access material and lease it with the live native PCS.
/// The returned owner retains raw witness + three trees once; verification of
/// the newly produced proof remains independent of this untrusted cache.
pub fn restore(a: std.mem.Allocator, dir: std.fs.Dir, physical: *const @import("block_v5_cpu_native_root_proposal_v1.zig").Proposal, expected: *const @import("block_v5_native_memory_stage_v1.zig").Proposal, owner: *@import("blake3_execution_trace.zig").Owner, native: *@import("stwo_prover_engine").pcs.CommitmentSchemeProver(@import("stwo_cpu_backend").CpuBackend, @import("stwo_core").proof_suites.Blake3.Hasher, @import("stwo_core").proof_suites.Blake3.MerkleChannel), pin: @import("block_v6_access_commitment_store_v1.zig").Pin, source_limits: @import("block_v5_native_memory_stage_v1.zig").Limits, policy: Policy, statistics: *Statistics) !@import("block_v5_native_projection_fused_stage_v2.zig").RetainedForBackend(@import("stwo_cpu_backend").CpuBackend) {
    const Store = @import("block_v6_access_commitment_store_v1.zig");
    var buffer: [96]u8 = undefined;
    var timer = try std.time.Timer.start();
    var loaded = try Store.load(a, dir, try name(physical.index, &buffer), physical, expected, owner, pin, .{ .source = source_limits, .storage = policy.storage });
    errdefer loaded.deinit(a);
    var first = try @import("block_v5_native_memory_stage_v1.zig").ForBackend(@import("stwo_cpu_backend").CpuBackend).borrowRetained(a, native, &loaded.scheme, loaded.snapshots, expected);
    errdefer first.deinit(a);
    const restore_ns = try std.math.add(u64, statistics.restore_ns, timer.read());
    const read_bytes = try std.math.add(u64, statistics.read_bytes, pin.bytes);
    const reused = try std.math.add(u64, statistics.reused_access_trees, 1);
    loaded.scheme.deinit(a);
    a.free(loaded.snapshots);
    statistics.restore_ns = restore_ns;
    statistics.read_bytes = read_bytes;
    statistics.reused_access_trees = reused;
    return .{ .source = loaded.source, .first = first };
}
