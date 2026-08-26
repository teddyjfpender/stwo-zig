const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const prover_pcs = @import("stwo_prover_engine").pcs;
const prover_work_pool = @import("stwo_prover_engine").work_pool;
const frontend = @import("stwo_riscv_frontend");

const manifest_mod = frontend.recursion.air.segment_outer_adapter_manifest_v2;

pub const ProofExecutionPool = struct {
    pool: prover_work_pool.WorkPool = undefined,
    binding: prover_work_pool.ScopedPoolBinding = undefined,
    requested_worker_count: usize = 1,
    pool_initialized: bool = false,
    binding_initialized: bool = false,

    pub fn initInPlace(
        self: *ProofExecutionPool,
        allocator: std.mem.Allocator,
        worker_count: usize,
    ) !void {
        self.* = .{};
        _ = try prover_work_pool.WorkerBudget.init(worker_count);
        self.requested_worker_count = worker_count;
        if (worker_count == 1) return;
        try self.pool.initInPlaceWithOptions(.{
            .worker_count = worker_count,
            .stack_size = prover_work_pool.WORKER_STACK_SIZE,
            .backing_allocator = allocator,
        });
        self.pool_initialized = true;
        errdefer {
            self.pool.deinit();
            self.pool_initialized = false;
        }
        self.binding = try prover_work_pool.ScopedPoolBinding.init(&self.pool);
        self.binding_initialized = true;
    }

    pub fn visibleWorkerCount(self: *ProofExecutionPool) !usize {
        if (self.requested_worker_count == 1) {
            if (self.pool_initialized or self.binding_initialized)
                return error.WorkerPoolMismatch;
            return 1;
        }
        if (!self.pool_initialized or !self.binding_initialized)
            return error.WorkerPoolMismatch;
        const visible = prover_work_pool.getGlobalPool() orelse
            return error.WorkerPoolMismatch;
        if (visible != &self.pool or
            visible.workerCount() != self.requested_worker_count)
        {
            return error.WorkerPoolMismatch;
        }
        return visible.workerCount();
    }

    pub fn deinit(self: *ProofExecutionPool) void {
        if (self.binding_initialized) {
            self.binding.deinit();
            self.binding_initialized = false;
        }
        if (self.pool_initialized) {
            self.pool.deinit();
            self.pool_initialized = false;
        }
    }
};

pub fn TreeStorageFor(comptime Engine: type) type {
    return struct {
        allocator: std.mem.Allocator,
        evaluations: []prover_pcs.ColumnEvaluation,
        columns: [][]M31,
        storage: []M31,
        backing: [][]M31,

        pub fn init(
            allocator: std.mem.Allocator,
            manifest: *const manifest_mod.Manifest,
            tree: usize,
        ) !@This() {
            const count = treeColumnCount(manifest, tree);
            const evaluations = try allocator.alloc(prover_pcs.ColumnEvaluation, count);
            errdefer allocator.free(evaluations);
            for (manifest.roster_rows[0..manifest.roster_count]) |row| {
                const placement = manifest.placements[row].?;
                const offset = treeOffset(placement, tree);
                const local_count = treeGeometryColumns(placement.geometry, tree);
                for (evaluations[offset..][0..local_count]) |*evaluation|
                    evaluation.log_size = placement.geometry.log_size;
            }
            var cells: usize = 0;
            for (evaluations) |evaluation|
                cells = std.math.add(
                    usize,
                    cells,
                    @as(usize, 1) << @intCast(evaluation.log_size),
                ) catch return error.ArithmeticOverflow;
            const storage = try allocator.alloc(M31, cells);
            errdefer allocator.free(storage);
            @memset(storage, M31.zero());
            var cursor: usize = 0;
            for (evaluations) |*evaluation| {
                const rows = @as(usize, 1) << @intCast(evaluation.log_size);
                evaluation.values = storage[cursor..][0..rows];
                cursor += rows;
            }
            const columns = try allocator.alloc([]M31, count);
            errdefer allocator.free(columns);
            for (evaluations, columns) |evaluation, *column|
                column.* = @constCast(evaluation.values);
            const backing = try allocator.alloc([]M31, 1);
            errdefer allocator.free(backing);
            backing[0] = storage;
            return .{
                .allocator = allocator,
                .evaluations = evaluations,
                .columns = columns,
                .storage = storage,
                .backing = backing,
            };
        }

        pub fn deinit(self: *@This()) void {
            if (self.evaluations.len != 0) self.allocator.free(self.evaluations);
            if (self.columns.len != 0) self.allocator.free(self.columns);
            if (self.backing.len != 0) self.allocator.free(self.backing);
            if (self.storage.len != 0) self.allocator.free(self.storage);
            self.* = undefined;
        }

        pub fn commit(
            self: *@This(),
            scheme: *Engine.Scheme,
            channel: *Engine.Channel,
        ) !void {
            const evaluations = self.evaluations;
            const backing = self.backing;
            self.evaluations = &.{};
            self.backing = &.{};
            self.storage = &.{};
            try Engine.commitWithBacking(
                scheme,
                self.allocator,
                evaluations,
                backing,
                null,
                channel,
            );
        }
    };
}

fn treeColumnCount(manifest: *const manifest_mod.Manifest, tree: usize) usize {
    return switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => manifest.total_preprocessed_columns,
        manifest_mod.MAIN_TREE_INDEX => manifest.total_main_columns,
        manifest_mod.INTERACTION_TREE_INDEX => manifest.total_interaction_columns,
        else => unreachable,
    };
}

fn treeOffset(placement: manifest_mod.Placement, tree: usize) usize {
    return switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => placement.preprocessed_offset,
        manifest_mod.MAIN_TREE_INDEX => placement.main_offset,
        manifest_mod.INTERACTION_TREE_INDEX => placement.interaction_offset,
        else => unreachable,
    };
}

fn treeGeometryColumns(geometry: manifest_mod.Geometry, tree: usize) usize {
    return switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => geometry.preprocessed_columns,
        manifest_mod.MAIN_TREE_INDEX => geometry.main_columns,
        manifest_mod.INTERACTION_TREE_INDEX => geometry.interaction_columns,
        else => unreachable,
    };
}
