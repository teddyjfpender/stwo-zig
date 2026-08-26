//! Private adaptation of a public CPU composition request to prover workers.

const std = @import("std");
const api = @import("stwo_prover_api");
const secure_column = @import("../secure_column.zig");
const composition_work = @import("composition_work.zig");
const work_pool = @import("../work_pool.zig");

const StageRecorder = api.stage_profile.Recorder;

pub const Execution = struct {
    worker_budget: work_pool.WorkerBudget,
    pool: ?*work_pool.WorkPool,
    host_byte_budget: usize,
    contention_policy: api.CpuCompositionContentionPolicy,
    explicit: bool,
    /// Original request width. Compatibility fallback changes
    /// `worker_budget`, but never relabels the request in task telemetry.
    requested_worker_count: usize = 0,
    /// Capacity of the pool selected before any compatibility adjustment.
    /// A graph with no helper pool still has one coordinator slot.
    pool_capacity: usize = 0,
    /// Existing proof-stage recorder, borrowed for this composition call.
    /// The task graph reserves and publishes only when this is non-null.
    task_recorder: ?*StageRecorder = null,
    /// Optional fail-atomic exact-work handoff. Backends that cannot publish a
    /// complete receipt leave it empty; the proof boundary then fails profile
    /// completeness without changing ordinary proving behavior.
    composition_work_capture: ?*composition_work.Capture = null,

    pub fn resolve(request: ?api.CpuCompositionExecutionRequest) !Execution {
        return resolveWithRecorder(request, null);
    }

    pub fn resolveWithRecorder(
        request: ?api.CpuCompositionExecutionRequest,
        recorder: ?*StageRecorder,
    ) !Execution {
        if (request) |explicit| {
            const worker_budget = try work_pool.WorkerBudget.init(explicit.worker_count);
            const pool = if (worker_budget.count == 1) null else work_pool.getGlobalPool();
            try work_pool.observeProofPoolStageForTest(.composition, pool);
            return .{
                .worker_budget = worker_budget,
                .pool = pool,
                .host_byte_budget = explicit.host_byte_budget,
                .contention_policy = explicit.contention_policy,
                .explicit = true,
                .requested_worker_count = worker_budget.count,
                .pool_capacity = if (pool) |active| active.workerCount() else 1,
                .task_recorder = recorder,
            };
        }
        const pool = work_pool.getGlobalPool();
        try work_pool.observeProofPoolStageForTest(.composition, pool);
        const worker_budget = if (pool) |active|
            try work_pool.WorkerBudget.init(active.workerCount())
        else
            work_pool.WorkerBudget.serial();
        return .{
            .worker_budget = worker_budget,
            .pool = pool,
            .host_byte_budget = std.math.maxInt(usize),
            .contention_policy = .compatibility,
            .explicit = false,
            .requested_worker_count = worker_budget.count,
            .pool_capacity = if (pool) |active| active.workerCount() else 1,
            .task_recorder = recorder,
        };
    }

    pub fn requestedWorkerCount(self: Execution) usize {
        return if (self.requested_worker_count == 0)
            self.worker_budget.count
        else
            self.requested_worker_count;
    }

    pub fn poolCapacity(self: Execution) usize {
        if (self.pool_capacity != 0) return self.pool_capacity;
        return if (self.pool) |pool| pool.workerCount() else 1;
    }

    pub fn isStrict(self: Execution) bool {
        return self.contention_policy == .strict;
    }

    /// Rejects an impossible exact width without constructing a composition
    /// plan. Active lease contention remains an execute-time decision so plan
    /// preparation never monopolizes the shared pool.
    pub fn validateCapacity(self: Execution) !void {
        if (self.worker_budget.count > 1 and self.pool == null) {
            return error.WorkPoolRequired;
        }
        if (self.pool) |pool| {
            if (self.worker_budget.count > pool.workerCount()) {
                return error.WorkerBudgetUnavailable;
            }
        }
    }

    pub fn helperResidentBytes(self: Execution) !usize {
        const helper_count = self.worker_budget.helperCount();
        if (helper_count == 0) return 0;
        const pool = self.pool orelse return error.WorkPoolRequired;
        return pool.helperReservationBytes(self.worker_budget);
    }

    /// Compatibility requests may use the same prepared plan serially when
    /// the process pool cannot represent their requested width. Active lease
    /// contention is handled by the scheduler after planning.
    pub fn adjustedForAvailablePool(self: Execution) Execution {
        if (self.isStrict() or self.worker_budget.count == 1) return self;
        const pool = self.pool orelse return self.serial();
        if (self.worker_budget.count <= pool.workerCount()) return self;
        return self.serial();
    }

    pub fn serial(self: Execution) Execution {
        var result = self;
        // Materialize derived request truth before clearing the pool that
        // supplied it. This also keeps older internal struct literals honest.
        result.requested_worker_count = self.requestedWorkerCount();
        result.pool_capacity = self.poolCapacity();
        result.worker_budget = work_pool.WorkerBudget.serial();
        result.pool = null;
        return result;
    }
};

/// Adapts the additive execution-aware hook while retaining the established
/// backend ABI for device and third-party backends.
pub fn tryBackend(
    comptime B: type,
    allocator: std.mem.Allocator,
    components: anytype,
    random_coeff: anytype,
    trace: anytype,
    residency_handles: []const ?*anyopaque,
    composition_twiddles: anytype,
    request: ?api.CpuCompositionExecutionRequest,
    recorder: ?*StageRecorder,
    composition_work_capture: ?*composition_work.Capture,
    execution_out: *?Execution,
) anyerror!?secure_column.SecureColumnByCoords {
    if (comptime B == void) return null;
    if (comptime @hasDecl(B, "computeCompositionEvaluationWithExecution")) {
        var execution = try Execution.resolveWithRecorder(request, recorder);
        execution.composition_work_capture = composition_work_capture;
        execution_out.* = execution;
        return B.computeCompositionEvaluationWithExecution(
            allocator,
            components,
            random_coeff,
            trace,
            residency_handles,
            composition_twiddles,
            execution,
        );
    }
    if (comptime @hasDecl(B, "computeCompositionEvaluationWithWorkCapture")) {
        return B.computeCompositionEvaluationWithWorkCapture(
            allocator,
            components,
            random_coeff,
            trace,
            residency_handles,
            composition_twiddles,
            composition_work_capture,
        );
    }
    if (comptime @hasDecl(B, "computeCompositionEvaluation")) {
        return B.computeCompositionEvaluation(
            allocator,
            components,
            random_coeff,
            trace,
            residency_handles,
            composition_twiddles,
        );
    }
    return null;
}

test "explicit execution keeps request values without exposing a test pool" {
    const execution = try Execution.resolve(.{
        .worker_count = 4,
        .host_byte_budget = 4096,
        .contention_policy = .strict,
    });
    try std.testing.expect(execution.explicit);
    try std.testing.expectEqual(@as(usize, 4), execution.worker_budget.count);
    try std.testing.expectEqual(@as(usize, 4096), execution.host_byte_budget);
    try std.testing.expect(execution.pool == null);
    try std.testing.expect(execution.isStrict());
}

test "explicit serial execution never resolves a shared pool" {
    const execution = try Execution.resolve(.{
        .worker_count = 1,
        .host_byte_budget = 1024,
    });
    try std.testing.expect(execution.pool == null);
    try std.testing.expectEqual(@as(usize, 1), execution.worker_budget.count);
}

test "strict over-capacity stays exact while compatibility becomes serial" {
    var pool: work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 2 });
    defer pool.deinit();
    const strict = Execution{
        .worker_budget = try work_pool.WorkerBudget.init(4),
        .pool = &pool,
        .host_byte_budget = 4096,
        .contention_policy = .strict,
        .explicit = true,
    };
    try std.testing.expectEqual(
        @as(usize, 4),
        strict.adjustedForAvailablePool().worker_budget.count,
    );
    try std.testing.expectError(error.WorkerBudgetUnavailable, strict.validateCapacity());
    var compatible = strict;
    compatible.contention_policy = .compatibility;
    const adjusted = compatible.adjustedForAvailablePool();
    try std.testing.expectEqual(@as(usize, 1), adjusted.worker_budget.count);
    try std.testing.expectEqual(@as(usize, 4), adjusted.requestedWorkerCount());
    try std.testing.expectEqual(@as(usize, 2), adjusted.poolCapacity());
    try std.testing.expect(adjusted.pool == null);
    try adjusted.validateCapacity();
}

test "implicit execution preserves the serial compatibility path in tests" {
    const execution = try Execution.resolve(null);
    try std.testing.expect(!execution.explicit);
    try std.testing.expectEqual(@as(usize, 1), execution.worker_budget.count);
    try std.testing.expectEqual(std.math.maxInt(usize), execution.host_byte_budget);
    try std.testing.expectEqual(
        api.CpuCompositionContentionPolicy.compatibility,
        execution.contention_policy,
    );
}
