//! Authenticated final residency evidence for one CUDA proof.

const types = @import("../abi/types.zig");
const provider_module = @import("provider.zig");
const telemetry = @import("telemetry.zig");

pub const ExecutionKind = enum { strict_aot, static_native };

pub const Verdict = struct {
    execution_kind: ExecutionKind = .strict_aot,
    static_code_identity: [32]u8 = [_]u8{0} ** 32,
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

    pub fn hasStrictExecution(self: Verdict) bool {
        return switch (self.execution_kind) {
            .strict_aot => self.aot.isStrict(),
            .static_native => !@import("std").mem.allEqual(u8, &self.build_identity, 0) and
                !@import("std").mem.allEqual(u8, &self.static_code_identity, 0) and
                self.aot.aot_loads == 0 and self.aot.aot_cache_hits == 0 and
                self.aot.aot_misses == 0 and self.aot.launches == 0 and self.aot.launch_failures == 0 and
                self.counters.kernel_launches != 0 and self.counters.stagesCompleteExactlyOnce(),
        };
    }

    pub fn isResident(self: Verdict) bool {
        return self.hasStrictExecution() and
            self.lane_count != 0 and
            self.runtime_proof_index != 0 and
            self.counters.lane_joins == self.lane_count and
            self.counters.isResident();
    }
};

test "static native verdict requires exact execution evidence without fabricated AOT activity" {
    const std = @import("std");
    var v: Verdict = undefined;
    v.execution_kind = .static_native;
    v.static_code_identity = [_]u8{1} ** 32;
    v.build_identity = [_]u8{2} ** 32;
    v.aot = .{};
    v.counters = .{};
    for (telemetry.all_stages) |stage| {
        if (stage.requiresKernel()) v.counters.kernels(stage, 1);
        v.counters.complete(stage);
    }
    try std.testing.expect(v.hasStrictExecution());
    v.execution_kind = .strict_aot;
    try std.testing.expect(!v.hasStrictExecution());
    v.execution_kind = .static_native;
    inline for (.{ "aot_loads", "aot_cache_hits", "aot_misses", "launches", "launch_failures" }) |field| {
        @field(v.aot, field) = 1;
        try std.testing.expect(!v.hasStrictExecution());
        @field(v.aot, field) = 0;
    }
    v.static_code_identity = [_]u8{0} ** 32;
    try std.testing.expect(!v.hasStrictExecution());
    v.static_code_identity = [_]u8{1} ** 32;
    v.build_identity = [_]u8{0} ** 32;
    try std.testing.expect(!v.hasStrictExecution());
    v.build_identity = [_]u8{2} ** 32;
    v.counters.stages[telemetry.Stage.quotient.index()].kernel_launches = 0;
    try std.testing.expect(!v.hasStrictExecution());
}
