//! Retained-lease execution of the complete RISC-V Tree-1 epoch.
//!
//! Coordinator-only graph construction and validation live in the sibling
//! builder. This owner performs no post-prepare allocation: it acquires one
//! request lease, drains the seven exact waves, joins cancellation through all
//! remaining graphs, and publishes only after total canonical success.

const std = @import("std");
const prover_engine = @import("stwo_prover_engine");
const build = @import("main_trace_plan_execution_build.zig");
const types = @import("main_trace_plan_execution_types.zig");
const plan_mod = @import("main_trace_plan.zig");

const task_graph = prover_engine.task_graph;
const work_pool = prover_engine.work_pool;

pub const Wave = types.Wave;
pub const TaskKind = types.TaskKind;
pub const Task = types.Task;
pub const Kernel = types.Kernel;
pub const Admission = types.Admission;
pub const Lifecycle = types.Lifecycle;
pub const EpochReport = types.EpochReport;

const State = struct {
    allocator: std.mem.Allocator,
    plan: plan_mod.Plan,
    prepared: build.Prepared,
    wave_reports: [types.WAVE_COUNT]?task_graph.ExecutionReport =
        .{null} ** types.WAVE_COUNT,
    lifecycle: Lifecycle = .prepared,
    attempted: bool = false,
};

/// A non-copyable-by-convention owner for one exact-capacity Tree-1 epoch.
/// Every graph is prepared before any callback starts. Deinitialization is safe
/// on success, failure, cancellation, and lease-admission failure.
pub const PreparedEpoch = struct {
    state: *State,

    pub fn prepare(
        allocator: std.mem.Allocator,
        plan: *const plan_mod.Plan,
        kernel: Kernel,
    ) !PreparedEpoch {
        var prepared = try build.prepare(allocator, plan, kernel);
        errdefer prepared.deinit();

        const state = try allocator.create(State);
        state.* = .{
            .allocator = allocator,
            .plan = plan.*,
            .prepared = prepared,
        };
        return .{ .state = state };
    }

    pub fn deinit(self: *PreparedEpoch) void {
        const state = self.state;
        state.prepared.deinit();
        state.allocator.destroy(state);
        self.* = undefined;
    }

    /// Executes every non-empty wave under one retained request lease. Pool
    /// geometry must exactly match the pure plan; runtime discovery cannot
    /// widen, narrow, or resize the admitted request.
    pub fn execute(
        self: *PreparedEpoch,
        pool: ?*work_pool.WorkPool,
    ) anyerror!EpochReport {
        const state = self.state;
        if (state.lifecycle != .prepared) return error.Tree1EpochAlreadyAttempted;
        try validatePool(&state.plan, pool);

        state.lifecycle = .executing;
        state.attempted = true;
        const budget = try work_pool.WorkerBudget.init(
            state.plan.planned_worker_count,
        );
        var lease_storage: work_pool.WorkLease = undefined;
        const retained_lease: ?*work_pool.WorkLease = if (pool) |active_pool| lease: {
            lease_storage = active_pool.acquire(budget) catch |failure| {
                state.lifecycle = .failed;
                return failure;
            };
            break :lease &lease_storage;
        } else null;
        defer if (retained_lease) |lease| lease.deinit();

        for (0..types.WAVE_COUNT) |index| {
            if (state.prepared.task_ranges[index].len == 0) continue;
            const graph_report = state.prepared.graphs[index].execute(graphOptions(
                state,
                budget,
                retained_lease,
            )) catch |failure| {
                state.wave_reports[index] = state.prepared.graphs[index].report();
                drainCancelledWaves(state, index + 1, budget, retained_lease);
                state.lifecycle = .failed;
                return failure;
            };
            state.wave_reports[index] = graph_report;
            if (graph_report.failed_tasks != 0 or
                graph_report.cancelled_tasks != 0 or
                graph_report.unsubmitted_cancelled_tasks != 0)
            {
                drainCancelledWaves(state, index + 1, budget, retained_lease);
                state.lifecycle = .failed;
                return error.Tree1EpochCancelled;
            }
        }

        for (state.prepared.task_ranges, 0..) |range, wave_index| {
            for (
                state.prepared.tasks[range.start .. range.start + range.len],
                0..,
            ) |*record, local_index| {
                if (!record.completed.load(.acquire) or
                    state.prepared.graphs[wave_index].status(
                        @intCast(local_index),
                    ) != .done)
                {
                    state.lifecycle = .failed;
                    return error.Tree1TaskDidNotComplete;
                }
            }
        }

        // One epoch-wide transition follows all release-published completions.
        // No completion-order collection exists.
        state.lifecycle = .published;
        return aggregateReport(state);
    }

    /// Safe before or concurrently with execute. The active graph joins its
    /// running work; every later graph drains as unsubmitted cancellation.
    pub fn requestCancellation(self: *PreparedEpoch) bool {
        var won = false;
        for (&self.state.prepared.graphs) |*graph| {
            won = graph.cancellation.request() or won;
        }
        return won;
    }

    pub fn lifecycle(self: *const PreparedEpoch) Lifecycle {
        return self.state.lifecycle;
    }

    pub fn admission(self: *const PreparedEpoch) Admission {
        return self.state.prepared.admission;
    }

    pub fn plannedTaskCount(self: *const PreparedEpoch) usize {
        return self.state.prepared.tasks.len;
    }

    pub fn report(self: *const PreparedEpoch) ?EpochReport {
        return if (self.state.attempted) aggregateReport(self.state) else null;
    }

    pub fn waveReport(
        self: *const PreparedEpoch,
        wave: Wave,
    ) ?task_graph.ExecutionReport {
        return self.state.wave_reports[types.waveIndex(wave)];
    }

    /// Returns tasks only after total success, in ascending stable TaskKey
    /// order. The descriptor is borrowed from this prepared owner.
    pub fn publishedTask(self: *const PreparedEpoch, index: usize) !*const Task {
        if (self.state.lifecycle != .published) return error.Tree1EpochNotPublished;
        if (index >= self.state.prepared.tasks.len) {
            return error.InvalidTree1TaskIndex;
        }
        return &self.state.prepared.tasks[index].descriptor;
    }
};

/// Transitional source alias for the original generation-only seam. The owner
/// now executes the complete Tree-1 epoch under the same preparation contract.
pub const PreparedGeneration = PreparedEpoch;

fn graphOptions(
    state: *State,
    budget: work_pool.WorkerBudget,
    retained_lease: ?*work_pool.WorkLease,
) task_graph.ExecuteOptions {
    return .{
        .worker_budget = budget,
        .retained_lease = retained_lease,
        .byte_budget = state.plan.host_byte_budget,
        .ready_policy = .canonical,
        .requested_worker_count = state.plan.requested_worker_count,
        .pool_capacity = state.plan.pool_capacity,
    };
}

fn drainCancelledWaves(
    state: *State,
    start: usize,
    budget: work_pool.WorkerBudget,
    retained_lease: ?*work_pool.WorkLease,
) void {
    for (start..types.WAVE_COUNT) |index| {
        if (state.prepared.task_ranges[index].len == 0) continue;
        _ = state.prepared.graphs[index].cancellation.request();
        state.wave_reports[index] = state.prepared.graphs[index].execute(graphOptions(
            state,
            budget,
            retained_lease,
        )) catch state.prepared.graphs[index].report();
    }
}

fn aggregateReport(state: *const State) EpochReport {
    var result = EpochReport{
        .configured_workers = state.plan.planned_worker_count,
        .planned_tasks = state.prepared.tasks.len,
        .attempted_waves = 0,
        .submitted_tasks = 0,
        .succeeded_tasks = 0,
        .failed_tasks = 0,
        .cancelled_tasks = 0,
        .unsubmitted_cancelled_tasks = 0,
        .started_tasks = 0,
        .finished_tasks = 0,
        .duplicate_starts = 0,
        .duplicate_finishes = 0,
        .peak_active_tasks = 0,
        .peak_reserved_bytes = 0,
        .cancellation_winner = null,
    };
    for (state.wave_reports) |maybe_report| {
        const report = maybe_report orelse continue;
        result.attempted_waves += 1;
        result.submitted_tasks += report.submitted_tasks;
        result.succeeded_tasks += report.succeeded_tasks;
        result.failed_tasks += report.failed_tasks;
        result.cancelled_tasks += report.cancelled_tasks;
        result.unsubmitted_cancelled_tasks += report.unsubmitted_cancelled_tasks;
        result.started_tasks += report.started_tasks;
        result.finished_tasks += report.finished_tasks;
        result.duplicate_starts += report.duplicate_starts;
        result.duplicate_finishes += report.duplicate_finishes;
        result.peak_active_tasks = @max(
            result.peak_active_tasks,
            report.peak_active_tasks,
        );
        result.peak_reserved_bytes = @max(
            result.peak_reserved_bytes,
            report.peak_reserved_bytes,
        );
        if (report.cancellation_winner) |winner| {
            if (result.cancellation_winner == null or
                winner.lessThan(result.cancellation_winner.?))
            {
                result.cancellation_winner = winner;
            }
        }
    }
    return result;
}

fn validatePool(plan: *const plan_mod.Plan, pool: ?*work_pool.WorkPool) !void {
    if (plan.planned_worker_count > 1 and pool == null) {
        return error.WorkPoolRequired;
    }
    if (pool) |active_pool| {
        if (active_pool.workerCount() != @as(usize, plan.pool_capacity)) {
            return error.Tree1PoolCapacityMismatch;
        }
        if (active_pool.stackSize() != plan.worker_stack_bytes) {
            return error.Tree1PoolStackSizeMismatch;
        }
    }
}
