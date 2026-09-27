//! Exclusive persistent CPU-pool, plan and workspace ownership for one key.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const producer = @import("blake3_native_parent_producer.zig");
const native_protocol = @import("blake3_native_parent_protocol.zig");
const artifact = @import("blake3_native_parent_artifact.zig");
const native = @import("air/blake3_native_parent_rows.zig");
const Budget = engine.host_budget_allocator.SharedHostBudget;
pub const Options = struct {
    /// Owned pool size; shared_pool instead uses the driver's global capacity.
    worker_count: usize,
    host_byte_limit: usize,
    retained_scratch_limit: usize,
    /// Borrowed only: the owner must join/destroy this worker before the pool.
    shared_pool: ?*engine.work_pool.WorkPool = null,
};

/// The cap covers routed allocations, including canonical host Merkle layers.
/// Thread stacks, allocator overhead and external backend allocations are separate.
/// Output artifacts retain the allocator budget and may outlive this worker.
pub fn Worker(comptime Backend: type) type {
    return WorkerForProtocol(Backend, native_protocol);
}
pub fn WorkerForProtocol(comptime Backend: type, comptime protocol: type) type {
    return WorkerKernel(Backend, protocol, false);
}
/// Explicit persistent-request contract: no current admission survives lease
/// teardown. The default Worker API retains its original borrowing semantics.
pub fn WorkerForProtocolScopedAdmission(comptime Backend: type, comptime protocol: type) type {
    return WorkerKernel(Backend, protocol, true);
}
fn WorkerKernel(comptime Backend: type, comptime protocol: type, comptime scoped_admission: bool) type {
    const Plan = if (scoped_admission) producer.PlanForProtocolScopedAdmission(Backend, protocol) else producer.PlanForProtocol(Backend, protocol);
    return struct {
        const Self = @This();
        allocator: std.mem.Allocator,
        budget: *Budget,
        plan: *Plan,
        workspace: producer.Workspace,
        pool: engine.work_pool.WorkPool,
        shared_pool: ?*engine.work_pool.WorkPool = null,
        busy: std.Thread.Mutex = .{},

        pub fn init(a: std.mem.Allocator, rows: *const native.Prepared, admission: protocol.Admission, options: Options) !*Self {
            _ = try engine.work_pool.WorkerBudget.init(options.worker_count);
            if (options.host_byte_limit == 0 or options.retained_scratch_limit > options.host_byte_limit) return error.InvalidParentWorkerLimits;
            const self = try a.create(Self);
            errdefer a.destroy(self);
            self.allocator = a;
            self.busy = .{};
            self.shared_pool = options.shared_pool;
            self.budget = try Budget.create(a, options.host_byte_limit);
            errdefer self.budget.destroy();
            const bounded = self.budget.allocator();
            self.workspace = producer.Workspace.init(bounded, options.retained_scratch_limit);
            errdefer self.workspace.deinit();
            if (self.shared_pool == null)
                try self.pool.initInPlaceWithOptions(.{ .worker_count = options.worker_count, .backing_allocator = bounded });
            errdefer if (self.shared_pool == null) self.pool.deinit();
            // Bind even the serial case so it cannot discover a global pool.
            var binding = try self.bindPool();
            defer if (binding) |*bound| bound.deinit();
            self.plan = try Plan.init(bounded, rows, admission);
            return self;
        }

        /// Caller must prevent new requests before destruction.
        pub fn deinit(self: *Self) void {
            if (!self.busy.tryLock()) @panic("destroying active parent worker");
            self.plan.deinit();
            self.workspace.deinit();
            if (self.shared_pool == null) self.pool.deinit();
            self.budget.destroy();
            const a = self.allocator;
            self.busy.unlock();
            a.destroy(self);
        }

        /// An exclusive request sequence. The owner must release this lease on
        /// its acquiring thread and must not copy it or destroy the worker.
        pub const Lease = struct {
            worker: *Self,
            pub fn deinit(self: *Lease) void {
                self.worker.plan.releaseAdmission();
                self.worker.busy.unlock();
                self.* = undefined;
            }
            pub fn prove(self: *Lease, rows: *const native.Prepared) !artifact.Owned {
                return self.worker.proveLocked(rows);
            }
            pub fn proveConsuming(self: *Lease, rows: *native.Prepared) !artifact.Owned {
                defer rows.releaseRows();
                return self.worker.proveLockedMode(rows, rows);
            }
            pub fn proveAdmittedConsuming(self: *Lease, rows: *native.Prepared, admission: protocol.Admission) !artifact.Owned {
                defer rows.releaseRows();
                try self.worker.rebindAdmission(rows, admission);
                return self.worker.proveLockedMode(rows, rows);
            }
            pub fn proveAdmitted(self: *Lease, rows: *const native.Prepared, admission: protocol.Admission) !artifact.Owned {
                return self.worker.proveAdmittedLocked(rows, admission);
            }
        };
        pub fn acquire(self: *Self) !Lease {
            if (!self.busy.tryLock()) return error.ParentWorkerAlreadyLeased;
            return .{ .worker = self };
        }
        pub fn prove(self: *Self, rows: *const native.Prepared) !artifact.Owned {
            var lease = try self.acquire();
            defer lease.deinit();
            return lease.prove(rows);
        }
        /// One-shot proving: releases source rows before the core proof, and
        /// on every error path. The preparation remains safe to deinitialize.
        pub fn proveConsuming(self: *Self, rows: *native.Prepared) !artifact.Owned {
            defer rows.releaseRows();
            var lease = try self.acquire();
            defer lease.deinit();
            return lease.proveConsuming(rows);
        }
        /// Retains pool, workspace and matching fixed structure across admitted keys.
        /// A failed rekey leaves the preceding immutable plan usable. Both plans
        /// count against the same host budget while the replacement is built.
        pub fn proveAdmitted(self: *Self, rows: *const native.Prepared, admission: protocol.Admission) !artifact.Owned {
            var lease = try self.acquire();
            defer lease.deinit();
            return lease.proveAdmitted(rows, admission);
        }
        /// Rebinds a persistent worker and consumes one-shot source rows on
        /// every path, including a failed lease acquisition or admission.
        pub fn proveAdmittedConsuming(self: *Self, rows: *native.Prepared, admission: protocol.Admission) !artifact.Owned {
            defer rows.releaseRows();
            var lease = try self.acquire();
            defer lease.deinit();
            return lease.proveAdmittedConsuming(rows, admission);
        }
        fn proveAdmittedLocked(self: *Self, rows: *const native.Prepared, admission: protocol.Admission) !artifact.Owned {
            try self.rebindAdmission(rows, admission);
            return self.proveLocked(rows);
        }
        fn rebindAdmission(self: *Self, rows: *const native.Prepared, admission: protocol.Admission) !void {
            try admission.validate();
            // Reusable protocols keep their setup ID while their public tuple
            // changes. Always authenticate rows and replace the admission,
            // including on a same-key request; never reuse transcript values.
            if (!try self.plan.tryRebindAdmission(rows, admission)) {
                var binding = try self.bindPool();
                defer if (binding) |*bound| bound.deinit();
                const replacement = Plan.init(self.budget.allocator(), rows, admission) catch |err| {
                    if (err == error.OutOfMemory and self.budget.snapshot().exceeded) return error.ParentWorkerHostBudgetExceeded;
                    return err;
                };
                self.plan.deinit();
                self.plan = replacement;
            }
        }
        fn proveLocked(self: *Self, rows: *const native.Prepared) !artifact.Owned {
            return self.proveLockedMode(rows, null);
        }
        fn proveLockedMode(self: *Self, rows: *const native.Prepared, consumed: ?*native.Prepared) !artifact.Owned {
            var binding = try self.bindPool();
            defer if (binding) |*bound| bound.deinit();
            std.debug.assert(engine.work_pool.getGlobalPool() == self.effectivePool());
            const pending = if (consumed) |source|
                self.plan.proveConsumingWithWorkspace(self.budget.allocator(), source, &self.workspace)
            else
                self.plan.proveWithWorkspace(self.budget.allocator(), rows, &self.workspace);
            var result = pending catch |err| {
                if (err == error.OutOfMemory and self.budget.snapshot().exceeded) return error.ParentWorkerHostBudgetExceeded;
                return err;
            };
            result.allocation_budget = self.budget.retain();
            return result;
        }
        fn effectivePool(self: *Self) *engine.work_pool.WorkPool {
            return self.shared_pool orelse &self.pool;
        }
        fn bindPool(self: *Self) !?engine.work_pool.ScopedPoolBinding {
            return engine.work_pool.ScopedPoolBinding.initIfNeeded(self.effectivePool());
        }
    };
}
