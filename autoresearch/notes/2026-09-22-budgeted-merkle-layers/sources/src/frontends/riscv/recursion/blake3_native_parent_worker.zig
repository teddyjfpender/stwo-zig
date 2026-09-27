//! Exclusive persistent CPU-pool, plan and workspace ownership for one key.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const producer = @import("blake3_native_parent_producer.zig");
const protocol = @import("blake3_native_parent_protocol.zig");
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
    return struct {
        const Self = @This();
        allocator: std.mem.Allocator,
        budget: *Budget,
        plan: *producer.Plan(Backend),
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
            self.plan = try producer.Plan(Backend).init(bounded, rows, admission);
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

        pub fn prove(self: *Self, rows: *const native.Prepared) !artifact.Owned {
            if (!self.busy.tryLock()) return error.ParentWorkerAlreadyLeased;
            defer self.busy.unlock();
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
