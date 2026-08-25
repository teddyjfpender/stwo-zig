//! Authenticated final residency evidence for one CUDA proof.

const types = @import("../abi/types.zig");
const provider_module = @import("provider.zig");
const telemetry = @import("telemetry.zig");

pub const Verdict = struct {
    provider: provider_module.Kind,
    device: types.DeviceSnapshot,
    platform: types.PlatformSnapshot,
    build_identity: [32]u8,
    aot_entries: usize,
    aot: types.NativeAotStats,
    lane_count: u32,
    counters: telemetry.Counters,
    pool_used_bytes: usize,
    pool_reserved_bytes: usize,
    graph_cache_hits_total: u64,
    graph_cache_misses_total: u64,
    prepared_cache_hits_total: u64,
    prepared_cache_misses_total: u64,
    prepared_cache_evictions_total: u64,
    runtime_proof_index: u64,

    pub fn isResident(self: Verdict) bool {
        return self.aot.isStrict() and
            self.lane_count != 0 and
            self.runtime_proof_index != 0 and
            self.counters.lane_joins == self.lane_count and
            self.counters.isResident();
    }
};
