//! Per-proof CUDA residency and transfer evidence.

pub const Counters = struct {
    allocations: u64 = 0,
    allocation_bytes: u64 = 0,
    frees: u64 = 0,
    h2d_bytes: u64 = 0,
    d2h_proof_bytes: u64 = 0,
    d2d_bytes: u64 = 0,
    memset_bytes: u64 = 0,
    fill_words: u64 = 0,
    sync_calls: u64 = 0,
    lane_joins: u64 = 0,
    kernel_launches: u64 = 0,
    graph_launches: u64 = 0,
    cpu_fallback_attempts: u64 = 0,
    cpu_fallbacks_completed: u64 = 0,
    live_bytes: u64 = 0,
    peak_live_bytes: u64 = 0,

    pub fn allocation(self: *Counters, bytes: usize) void {
        const amount: u64 = @intCast(bytes);
        self.allocations += 1;
        self.allocation_bytes += amount;
        self.live_bytes += amount;
        self.peak_live_bytes = @max(self.peak_live_bytes, self.live_bytes);
    }

    pub fn free(self: *Counters, bytes: usize) void {
        const amount: u64 = @intCast(bytes);
        std.debug.assert(amount <= self.live_bytes);
        self.frees += 1;
        self.live_bytes -= amount;
    }

    pub fn isResident(self: Counters) bool {
        return self.cpu_fallback_attempts == 0 and
            self.cpu_fallbacks_completed == 0 and
            self.live_bytes == 0 and
            self.kernel_launches != 0;
    }
};

const std = @import("std");

test "allocation telemetry carries a high-water mark and balances" {
    var counters = Counters{};
    counters.allocation(64);
    counters.allocation(32);
    counters.free(64);
    counters.free(32);
    try std.testing.expectEqual(@as(u64, 96), counters.peak_live_bytes);
    try std.testing.expectEqual(@as(u64, 0), counters.live_bytes);
}
