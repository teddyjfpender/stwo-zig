//! Bounded tree-pair preparation overlapped with the shared persistent worker.
const std = @import("std");
const shared = @import("blake3_parent_pipeline.zig");
const tree = @import("blake3_execution_tree.zig");
const aggregate = @import("blake3_execution_aggregate.zig");
const protocol = @import("blake3_execution_parent_protocol.zig");
const artifact = @import("blake3_native_parent_artifact.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
pub const Sizing = shared.Sizing;
pub const Report = shared.Report;
pub const Job = TreeJob;
const TreeJob = struct {
    left: *const tree.Node,
    right: *const tree.Node,
    admission: protocol.Admission,
    capacity: u32,
};
pub const Prepared = struct {
    fold: aggregate.Fold,
    budget: *Budget,
    pub fn retainedBytes(self: Prepared) !usize {
        return std.math.add(usize, self.budget.snapshot().live_bytes, @sizeOf(Budget) + @sizeOf(Prepared));
    }
    pub fn deinit(self: *Prepared) void {
        self.fold.deinit();
        self.budget.destroy();
        self.* = undefined;
    }
};
pub fn prepareBounded(a: std.mem.Allocator, job: TreeJob, limit: usize) !Prepared {
    return prepareBoundedWithPool(a, job, limit, null);
}
pub fn prepareBoundedWithPool(a: std.mem.Allocator, job: TreeJob, limit: usize, pool: ?*@import("stwo_prover_engine").work_pool.WorkPool) !Prepared {
    try job.admission.validate();
    const budget = try Budget.create(a, limit);
    errdefer budget.destroy();
    var fold = tree.preparePairWithPool(budget.allocator(), job.left, job.right, job.capacity, pool) catch |err| {
        if (err == error.OutOfMemory and budget.snapshot().exceeded) return error.PreparationHostBudgetExceeded;
        return err;
    };
    errdefer fold.deinit();
    if (!std.meta.eql(fold.prepared.context, job.admission.key.context)) return error.ParentPipelineKeyMismatch;
    return .{ .fold = fold, .budget = budget };
}
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Self = @This();
        pub const Worker = @import("blake3_native_parent_worker.zig").WorkerForProtocol(Backend, protocol);
        const Adapter = struct {
            pub const Worker = Self.Worker;
            pub const Job = TreeJob;
            pub const Prepared = @import("blake3_tree_pipeline.zig").Prepared;
            pub fn prepare(a: std.mem.Allocator, job: TreeJob, limit: usize) !@import("blake3_tree_pipeline.zig").Prepared {
                return prepareBounded(a, job, limit);
            }
            pub fn prepareWithPool(a: std.mem.Allocator, job: TreeJob, limit: usize, pool: *@import("stwo_prover_engine").work_pool.WorkPool) !@import("blake3_tree_pipeline.zig").Prepared {
                return prepareBoundedWithPool(a, job, limit, pool);
            }
            pub fn prove(worker: *Self.Worker.Lease, prepared: *const @import("blake3_tree_pipeline.zig").Prepared, job: TreeJob) !artifact.Owned {
                if (!std.meta.eql(prepared.fold.prepared.context, job.admission.key.context)) return error.ParentPipelineKeyMismatch;
                return worker.proveAdmitted(&prepared.fold.prepared.rows, job.admission);
            }
        };
        pub fn admit(policy: anytype, sizing: Sizing, count: usize) !shared.Admission {
            return shared.admit(Adapter, policy, sizing, count);
        }
        /// Inputs and worker outlive the call. Outputs retain budget leases and
        /// survive worker destruction; verification still requires each job's
        /// independently admitted key. A single run exclusively uses the worker.
        pub fn run(a: std.mem.Allocator, policy: anytype, sizing: Sizing, worker: *Worker, jobs: []const TreeJob) !Report {
            return shared.run(Adapter, a, policy, sizing, worker, jobs);
        }
    };
}
