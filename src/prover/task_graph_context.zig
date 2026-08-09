//! Worker-visible task identity, cancellation, and nested-work boundary.

const std = @import("std");
const task_profile = @import("stwo_prover_api").task_profile;
const work_pool = @import("work_pool.zig");

/// Shared structural graph limits live here so the public model and private
/// executor cannot drift.
pub const MAX_COMPONENT_TASKS: usize = 1024;
pub const ComponentTaskId = u16;

pub const TaskClass = enum {
    leaf,
    pool_exclusive,
    coordinator,
};

pub const WorkUnit = enum {
    unspecified,
    rows,
    tiles,
};

pub const TaskKey = struct {
    epoch: u16,
    stage_rank: u16,
    component_registry_index: u32,
    shard_or_chunk_index: u32,

    pub fn lessThan(lhs: TaskKey, rhs: TaskKey) bool {
        if (lhs.epoch != rhs.epoch) return lhs.epoch < rhs.epoch;
        if (lhs.stage_rank != rhs.stage_rank) return lhs.stage_rank < rhs.stage_rank;
        if (lhs.component_registry_index != rhs.component_registry_index) {
            return lhs.component_registry_index < rhs.component_registry_index;
        }
        return lhs.shard_or_chunk_index < rhs.shard_or_chunk_index;
    }

    pub fn eql(lhs: TaskKey, rhs: TaskKey) bool {
        return lhs.epoch == rhs.epoch and
            lhs.stage_rank == rhs.stage_rank and
            lhs.component_registry_index == rhs.component_registry_index and
            lhs.shard_or_chunk_index == rhs.shard_or_chunk_index;
    }
};

pub const CancellationToken = struct {
    cancelled: std.atomic.Value(bool) = .init(false),

    pub fn isCancelled(self: *const CancellationToken) bool {
        return self.cancelled.load(.acquire);
    }

    pub fn request(self: *CancellationToken) bool {
        return self.cancelled.cmpxchgStrong(
            false,
            true,
            .acq_rel,
            .acquire,
        ) == null;
    }
};

pub const TaskContext = struct {
    user_context: *anyopaque,
    cancellation: *const CancellationToken,
    key: TaskKey,
    worker_budget: work_pool.WorkerBudget,
    task_class: TaskClass,
    exclusive_lease: ?*work_pool.WorkLease,
    child_wait_group: ?*std.Thread.WaitGroup,
    profile_event: ?*task_profile.TaskEvent = null,
    work_unit: WorkUnit = .unspecified,
    planned_work_units: u64 = 0,
    profile_completion_recorded: bool = false,
    child_wave_active: bool = false,

    pub fn isCancelled(self: *const TaskContext) bool {
        return self.cancellation.isCancelled();
    }

    /// Records coarse completed rows/tiles once per task. This is deliberately
    /// not an incrementing hot-loop counter. With profiling disabled the call
    /// validates the declared bound and otherwise performs no work.
    pub fn setCompletedWork(self: *TaskContext, units: u64) !void {
        if (units > self.planned_work_units) {
            return error.CompletedTaskWorkExceedsPlan;
        }
        if (self.profile_event) |event| {
            if (self.profile_completion_recorded) {
                return error.DuplicateCompletedTaskWork;
            }
            self.profile_completion_recorded = true;
            switch (self.work_unit) {
                .unspecified => {},
                .rows => event.completed_rows = units,
                .tiles => event.completed_tiles = units,
            }
        }
    }

    /// Nested work is legal only for a drained `pool_exclusive` task.
    pub fn spawnChild(
        self: *TaskContext,
        comptime func: anytype,
        args: anytype,
    ) !void {
        if (self.task_class != .pool_exclusive) {
            return error.NestedSubmissionRejected;
        }
        const lease = self.exclusive_lease orelse
            return error.NestedSubmissionRejected;
        const wait_group = self.child_wait_group orelse
            return error.NestedSubmissionRejected;
        try lease.spawnWg(wait_group, func, args);
        self.child_wave_active = true;
    }

    /// Joins the current child wave before an exclusive kernel consumes it.
    pub fn waitForChildren(self: *TaskContext) !void {
        if (self.task_class != .pool_exclusive) {
            return error.NestedSubmissionRejected;
        }
        self.joinChildren();
    }

    /// The executor invokes this after every callback, including error paths.
    pub fn joinChildren(self: *TaskContext) void {
        if (!self.child_wave_active) return;
        const wait_group = self.child_wait_group orelse return;
        self.child_wave_active = false;
        wait_group.wait();
        self.exclusive_lease.?.completeWave();
        wait_group.reset();
    }
};
