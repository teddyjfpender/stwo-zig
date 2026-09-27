//! Exclusive persistent CPU-pool, plan and workspace ownership for one key.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const producer = @import("blake3_native_parent_producer.zig");
const native_protocol = @import("blake3_native_parent_protocol.zig");
const artifact = @import("blake3_native_parent_artifact.zig");
const native = @import("air/blake3_native_parent_rows.zig");
const Budget = engine.host_budget_allocator.SharedHostBudget;
pub const Options = struct {
    worker_count: usize,
    host_byte_limit: usize,
    retained_scratch_limit: usize,
};

/// The cap covers routed allocations, including canonical host Merkle layers.
/// Thread stacks, allocator overhead and external backend allocations are separate.
/// Output artifacts retain the allocator budget and may outlive this worker.
pub fn Worker(comptime Backend: type) type {
    return WorkerForProtocol(Backend, native_protocol);
}
pub fn WorkerForProtocol(comptime Backend: type, comptime protocol: type) type {
    return struct {
        const Self = @This();
        allocator: std.mem.Allocator,
        budget: *Budget,
        plan: *producer.PlanForProtocol(Backend, protocol),
        workspace: producer.Workspace,
        pool: engine.work_pool.WorkPool,
        busy: std.Thread.Mutex = .{},

        pub fn init(a: std.mem.Allocator, rows: *const native.Prepared, admission: protocol.Admission, options: Options) !*Self {
            _ = try engine.work_pool.WorkerBudget.init(options.worker_count);
            if (options.host_byte_limit == 0 or options.retained_scratch_limit > options.host_byte_limit) return error.InvalidParentWorkerLimits;
            const self = try a.create(Self);
            errdefer a.destroy(self);
            self.allocator = a;
            self.busy = .{};
            self.budget = try Budget.create(a, options.host_byte_limit);
            errdefer self.budget.destroy();
            const bounded = self.budget.allocator();
            self.workspace = producer.Workspace.init(bounded, options.retained_scratch_limit);
            errdefer self.workspace.deinit();
            try self.pool.initInPlaceWithOptions(.{ .worker_count = options.worker_count, .backing_allocator = bounded });
            errdefer self.pool.deinit();
            // Bind even the serial case so it cannot discover a global pool.
            var binding = try engine.work_pool.ScopedPoolBinding.init(&self.pool);
            defer binding.deinit();
            self.plan = try producer.PlanForProtocol(Backend, protocol).init(bounded, rows, admission);
            return self;
        }

        /// Caller must prevent new requests before destruction.
        pub fn deinit(self: *Self) void {
            if (!self.busy.tryLock()) @panic("destroying active parent worker");
            self.plan.deinit();
            self.workspace.deinit();
            self.pool.deinit();
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
                self.worker.busy.unlock();
                self.* = undefined;
            }
            pub fn prove(self: *Lease, rows: *const native.Prepared) !artifact.Owned {
                return self.worker.proveLocked(rows);
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
            var binding = try engine.work_pool.ScopedPoolBinding.init(&self.pool);
            defer binding.deinit();
            var result = self.plan.proveConsumingWithWorkspace(self.budget.allocator(), rows, &self.workspace) catch |err| {
                if (err == error.OutOfMemory and self.budget.snapshot().exceeded) return error.ParentWorkerHostBudgetExceeded;
                return err;
            };
            result.allocation_budget = self.budget.retain();
            return result;
        }
        /// Retains pool, workspace and matching fixed structure across admitted keys.
        /// A failed rekey leaves the preceding immutable plan usable. Both plans
        /// count against the same host budget while the replacement is built.
        pub fn proveAdmitted(self: *Self, rows: *const native.Prepared, admission: protocol.Admission) !artifact.Owned {
            var lease = try self.acquire();
            defer lease.deinit();
            return lease.proveAdmitted(rows, admission);
        }
        fn proveAdmittedLocked(self: *Self, rows: *const native.Prepared, admission: protocol.Admission) !artifact.Owned {
            try admission.validate();
            if (!std.mem.eql(u8, &admission.expected_id, &self.plan.admission.expected_id) and
                !try self.plan.tryRebindAdmission(rows, admission))
            {
                var binding = try engine.work_pool.ScopedPoolBinding.init(&self.pool);
                defer binding.deinit();
                const replacement = producer.PlanForProtocol(Backend, protocol).init(self.budget.allocator(), rows, admission) catch |err| {
                    if (err == error.OutOfMemory and self.budget.snapshot().exceeded) return error.ParentWorkerHostBudgetExceeded;
                    return err;
                };
                self.plan.deinit();
                self.plan = replacement;
            }
            return self.proveLocked(rows);
        }
        fn proveLocked(self: *Self, rows: *const native.Prepared) !artifact.Owned {
            var binding = try engine.work_pool.ScopedPoolBinding.init(&self.pool);
            defer binding.deinit();
            std.debug.assert(engine.work_pool.getGlobalPool() == &self.pool);
            var result = self.plan.proveWithWorkspace(self.budget.allocator(), rows, &self.workspace) catch |err| {
                if (err == error.OutOfMemory and self.budget.snapshot().exceeded) return error.ParentWorkerHostBudgetExceeded;
                return err;
            };
            result.allocation_budget = self.budget.retain();
            return result;
        }
    };
}
