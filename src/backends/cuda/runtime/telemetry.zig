//! Per-proof CUDA residency and stage-scoped transfer evidence.

const std = @import("std");

/// Canonical order of a native Stwo proof on the resident CUDA product.
pub const Stage = enum(u8) {
    ingress,
    trace_generation,
    trace_commit,
    constraint_evaluation,
    oods,
    quotient,
    fri_commit,
    pow,
    decommit,
    proof_assembly,

    pub fn requiresKernel(self: Stage) bool {
        return switch (self) {
            .ingress, .proof_assembly => false,
            else => true,
        };
    }

    pub fn index(self: Stage) usize {
        return @intFromEnum(self);
    }
};

pub const stage_count = @typeInfo(Stage).@"enum".fields.len;
pub const all_stages: [stage_count]Stage = .{
    .ingress,
    .trace_generation,
    .trace_commit,
    .constraint_evaluation,
    .oods,
    .quotient,
    .fri_commit,
    .pow,
    .decommit,
    .proof_assembly,
};

pub const StageCounters = struct {
    allocations: u64 = 0,
    allocation_bytes: u64 = 0,
    frees: u64 = 0,
    h2d_bytes: u64 = 0,
    d2h_proof_bytes: u64 = 0,
    d2d_bytes: u64 = 0,
    memset_bytes: u64 = 0,
    memset_operations: u64 = 0,
    fill_words: u64 = 0,
    sync_calls: u64 = 0,
    lane_joins: u64 = 0,
    kernel_launches: u64 = 0,
    graph_launches: u64 = 0,
    completions: u64 = 0,
};

pub const Counters = struct {
    allocations: u64 = 0,
    allocation_bytes: u64 = 0,
    frees: u64 = 0,
    h2d_bytes: u64 = 0,
    d2h_proof_bytes: u64 = 0,
    d2d_bytes: u64 = 0,
    memset_bytes: u64 = 0,
    memset_operations: u64 = 0,
    fill_words: u64 = 0,
    sync_calls: u64 = 0,
    lane_joins: u64 = 0,
    kernel_launches: u64 = 0,
    graph_launches: u64 = 0,
    cpu_fallback_attempts: u64 = 0,
    cpu_fallbacks_completed: u64 = 0,
    live_bytes: u64 = 0,
    peak_live_bytes: u64 = 0,
    stages: [stage_count]StageCounters = [_]StageCounters{.{}} ** stage_count,

    pub fn allocation(self: *Counters, stage: ?Stage, bytes: usize) void {
        const amount: u64 = @intCast(bytes);
        self.allocations += 1;
        self.allocation_bytes += amount;
        self.live_bytes += amount;
        self.peak_live_bytes = @max(self.peak_live_bytes, self.live_bytes);
        if (stage) |value| {
            self.stages[value.index()].allocations += 1;
            self.stages[value.index()].allocation_bytes += amount;
        }
    }

    pub fn free(self: *Counters, stage: ?Stage, bytes: usize) void {
        const amount: u64 = @intCast(bytes);
        std.debug.assert(amount <= self.live_bytes);
        self.frees += 1;
        self.live_bytes -= amount;
        if (stage) |value| self.stages[value.index()].frees += 1;
    }

    pub fn h2d(self: *Counters, stage: ?Stage, bytes: usize) void {
        const amount: u64 = @intCast(bytes);
        self.h2d_bytes += amount;
        if (stage) |value| self.stages[value.index()].h2d_bytes += amount;
    }

    pub fn d2d(self: *Counters, stage: ?Stage, bytes: usize) void {
        const amount: u64 = @intCast(bytes);
        self.d2d_bytes += amount;
        if (stage) |value| self.stages[value.index()].d2d_bytes += amount;
    }

    pub fn memset(self: *Counters, stage: Stage, bytes: usize) void {
        const amount: u64 = @intCast(bytes);
        self.memset_bytes += amount;
        self.memset_operations += 1;
        self.stages[stage.index()].memset_bytes += amount;
        self.stages[stage.index()].memset_operations += 1;
    }

    pub fn proofRead(self: *Counters, stage: Stage, bytes: usize) void {
        const amount: u64 = @intCast(bytes);
        self.d2h_proof_bytes += amount;
        self.stages[stage.index()].d2h_proof_bytes += amount;
    }

    pub fn fill(self: *Counters, stage: ?Stage, words: usize) void {
        const amount: u64 = @intCast(words);
        self.fill_words += amount;
        if (stage) |value| self.stages[value.index()].fill_words += amount;
    }

    pub fn sync(self: *Counters, stage: ?Stage) void {
        self.sync_calls += 1;
        if (stage) |value| self.stages[value.index()].sync_calls += 1;
    }

    pub fn join(self: *Counters, stage: ?Stage) void {
        self.lane_joins += 1;
        if (stage) |value| self.stages[value.index()].lane_joins += 1;
    }

    pub fn kernels(self: *Counters, stage: Stage, count: u64) void {
        self.kernel_launches += count;
        self.stages[stage.index()].kernel_launches += count;
    }

    pub fn graphs(self: *Counters, stage: Stage, count: u64) void {
        self.graph_launches += count;
        self.stages[stage.index()].graph_launches += count;
    }

    pub fn complete(self: *Counters, stage: Stage) void {
        self.stages[stage.index()].completions += 1;
    }

    pub fn stagesCompleteExactlyOnce(self: Counters) bool {
        for (all_stages) |stage| {
            const counters = self.stages[stage.index()];
            if (counters.completions != 1) return false;
            if (stage.requiresKernel() and
                counters.kernel_launches == 0 and
                counters.graph_launches == 0)
            {
                return false;
            }
        }
        return true;
    }

    pub fn isResident(self: Counters) bool {
        return self.cpu_fallback_attempts == 0 and
            self.cpu_fallbacks_completed == 0 and
            self.live_bytes == 0 and
            self.kernel_launches != 0;
    }
};

test "allocation telemetry carries a high-water mark and balances" {
    var counters = Counters{};
    counters.allocation(.ingress, 64);
    counters.allocation(.ingress, 32);
    counters.free(.proof_assembly, 64);
    counters.free(.proof_assembly, 32);
    try std.testing.expectEqual(@as(u64, 96), counters.peak_live_bytes);
    try std.testing.expectEqual(@as(u64, 0), counters.live_bytes);
    try std.testing.expectEqual(
        @as(u64, 96),
        counters.stages[Stage.ingress.index()].allocation_bytes,
    );
}

test "stage evidence requires every ordered protocol stage" {
    var counters = Counters{};
    for (all_stages) |stage| {
        if (stage.requiresKernel()) counters.kernels(stage, 1);
        counters.complete(stage);
    }
    try std.testing.expect(counters.stagesCompleteExactlyOnce());
    counters.stages[Stage.quotient.index()].completions += 1;
    try std.testing.expect(!counters.stagesCompleteExactlyOnce());
}
