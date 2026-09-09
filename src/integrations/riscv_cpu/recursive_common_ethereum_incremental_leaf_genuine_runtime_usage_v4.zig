//! Process-local resource receipts for the isolated genuine role-0 gate.
//! These values are diagnostics only and never enter proof or artifact bytes.

const std = @import("std");
const prover_engine = @import("stwo_prover_engine");
const process_usage = prover_engine.measurement.process_usage;

pub const RuntimePhaseV4 = enum(u8) {
    stage101_build = 0,
    cold_open = 1,
    campaign = 2,
    materialize = 3,
    materialize_cleanup = 4,
    role0_prove = 5,
    role0_reopen = 6,
    role0_postprocess = 7,
    stage102_cleanup = 8,
    total = 9,
};

pub const PhaseUsageReceiptV4 = struct {
    phase: RuntimePhaseV4,
    worker_count: u32,
    host_byte_budget: u64,
    source: process_usage.Source,
    wall_ns: u64,
    process_cpu_ns: ?u64,
    average_parallelism_milli: ?u64,
    lifetime_peak_physical_footprint_bytes: ?u64,
    energy_nj: ?u64,
    instructions: ?u64,
    cycles: ?u64,

    pub fn fromDelta(
        phase: RuntimePhaseV4,
        policy: anytype,
        wall_ns: u64,
        delta: process_usage.Delta,
    ) !PhaseUsageReceiptV4 {
        try policy.validate();
        if (wall_ns == 0) return error.InvalidRole0GenuinePhaseUsage;
        const average_parallelism_milli = if (delta.process_cpu_ns) |cpu_ns|
            std.math.cast(
                u64,
                (@as(u128, cpu_ns) * 1000) / wall_ns,
            ) orelse return error.Role0GenuinePhaseUsageOverflow
        else
            null;
        const result = PhaseUsageReceiptV4{
            .phase = phase,
            .worker_count = @intCast(policy.worker_count),
            .host_byte_budget = @intCast(policy.host_byte_budget),
            .source = delta.source,
            .wall_ns = wall_ns,
            .process_cpu_ns = delta.process_cpu_ns,
            .average_parallelism_milli = average_parallelism_milli,
            .lifetime_peak_physical_footprint_bytes = delta.lifetime_peak_physical_footprint_bytes,
            .energy_nj = delta.energy_nj,
            .instructions = delta.instructions,
            .cycles = delta.cycles,
        };
        try result.validate();
        return result;
    }

    pub fn validate(self: PhaseUsageReceiptV4) !void {
        if (self.worker_count == 0 or
            @as(usize, self.worker_count) > prover_engine.work_pool.MAX_WORKERS or
            self.host_byte_budget == 0 or self.wall_ns == 0)
        {
            return error.InvalidRole0GenuinePhaseUsage;
        }
        if (self.source == .unsupported) {
            if (self.process_cpu_ns != null or
                self.average_parallelism_milli != null or
                self.lifetime_peak_physical_footprint_bytes != null or
                self.energy_nj != null or self.instructions != null or
                self.cycles != null)
            {
                return error.InvalidRole0GenuinePhaseUsage;
            }
            return;
        }
        if (self.process_cpu_ns == null or
            self.average_parallelism_milli == null or
            self.lifetime_peak_physical_footprint_bytes == null or
            self.energy_nj == null or self.instructions == null or
            self.cycles == null)
        {
            return error.InvalidRole0GenuinePhaseUsage;
        }
        const expected_parallelism = std.math.cast(
            u64,
            (@as(u128, self.process_cpu_ns.?) * 1000) / self.wall_ns,
        ) orelse return error.Role0GenuinePhaseUsageOverflow;
        if (self.average_parallelism_milli.? != expected_parallelism)
            return error.InvalidRole0GenuinePhaseUsage;
    }
};

pub const PhaseUsageMeasurementV4 = struct {
    timer: std.time.Timer,
    before: process_usage.Snapshot,

    pub fn begin() !PhaseUsageMeasurementV4 {
        return .{
            .timer = try std.time.Timer.start(),
            .before = try process_usage.sample(),
        };
    }

    pub fn finish(
        self: *PhaseUsageMeasurementV4,
        phase: RuntimePhaseV4,
        policy: anytype,
    ) !PhaseUsageReceiptV4 {
        const after = try process_usage.sample();
        return PhaseUsageReceiptV4.fromDelta(
            phase,
            policy,
            self.timer.read(),
            try process_usage.difference(self.before, after),
        );
    }
};
