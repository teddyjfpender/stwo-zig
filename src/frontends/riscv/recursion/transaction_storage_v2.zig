//! Shared recursive trace storage and scoped proof worker ownership.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const prover_pcs = @import("stwo_prover_engine").pcs;
const prover_work_pool = @import("stwo_prover_engine").work_pool;

const manifest_mod = @import("air/segment_outer_adapter_manifest_v2.zig");

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
    return TreeStorageForManifest(Engine, manifest_mod);
}

/// The admitted manifest owns column order; storage ownership and commit transfer
/// are identical for native-assisted and detached recursive circuits.
pub fn TreeStorageForManifest(comptime Engine: type, comptime Manifest: type) type {
    return struct {
        allocator: std.mem.Allocator,
        evaluations: []prover_pcs.ColumnEvaluation,
        columns: [][]M31,
        storage: []M31,
        backing: [][]M31,

        /// Exact evaluation payload, excluding column metadata and the PCS's
        /// later expansion/commitment buffers. Reads admitted geometry only.
        pub fn evaluationBytes(manifest: *const Manifest.Manifest, tree: usize) !usize {
            var cells: usize = 0;
            for (try activeRosterRows(Manifest, manifest)) |row| {
                const geometry = manifest.placements[row].?.geometry;
                const count = treeGeometryColumns(Manifest, geometry, tree);
                cells = try std.math.add(usize, cells, try std.math.mul(usize, count, @as(usize, 1) << @intCast(geometry.log_size)));
            }
            return std.math.mul(usize, cells, @sizeOf(M31));
        }

        pub fn init(
            allocator: std.mem.Allocator,
            manifest: *const Manifest.Manifest,
            tree: usize,
        ) !@This() {
            const cells = try evaluationBytes(manifest, tree) / @sizeOf(M31);
            const count = treeColumnCount(Manifest, manifest, tree);
            const evaluations = try allocator.alloc(prover_pcs.ColumnEvaluation, count);
            errdefer allocator.free(evaluations);
            for (try activeRosterRows(Manifest, manifest)) |row| {
                const placement = manifest.placements[row].?;
                const offset = treeOffset(Manifest, placement, tree);
                const local_count = treeGeometryColumns(Manifest, placement.geometry, tree);
                for (evaluations[offset..][0..local_count]) |*evaluation|
                    evaluation.log_size = placement.geometry.log_size;
            }
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

/// V2 manifests carry a bounded active prefix; the direct wrapper PlanV4
/// always commits its entire fixed roster. Validate the indexing before
/// either prover or verifier uses an optional placement.
pub fn activeRosterRows(comptime Manifest: type, manifest: *const Manifest.Manifest) ![]const u8 {
    const count = if (@hasField(Manifest.Manifest, "roster_count"))
        manifest.roster_count
    else
        manifest.roster_rows.len;
    if (count > manifest.roster_rows.len or
        manifest.placements.len != Manifest.COMPONENT_COUNT or
        (!@hasField(Manifest.Manifest, "roster_count") and count != Manifest.COMPONENT_COUNT))
        return error.InvalidManifestRoster;
    const rows = manifest.roster_rows[0..count];
    var seen = [_]bool{false} ** Manifest.COMPONENT_COUNT;
    for (rows) |row| {
        if (row >= manifest.placements.len or seen[row] or manifest.placements[row] == null)
            return error.InvalidManifestRoster;
        seen[row] = true;
    }
    for (manifest.placements, seen) |placement, expected| {
        if ((placement != null) != expected)
            return error.InvalidManifestRoster;
    }
    return rows;
}

test "direct fixed roster storage rejects missing and extra placement" {
    const Direct = struct {
        pub const COMPONENT_COUNT = 3;
        pub const Manifest = struct {
            roster_rows: [3]u8 = .{ 0, 1, 2 },
            placements: [3]?u8 = .{ 1, 2, 3 },
        };
    };
    var direct = Direct.Manifest{};
    try std.testing.expectEqualSlices(u8, &.{ 0, 1, 2 }, try activeRosterRows(Direct, &direct));
    direct.placements[1] = null;
    try std.testing.expectError(error.InvalidManifestRoster, activeRosterRows(Direct, &direct));

    const Prefix = struct {
        pub const COMPONENT_COUNT = 3;
        pub const Manifest = struct {
            roster_count: u8 = 2,
            roster_rows: [3]u8 = .{ 0, 1, 0 },
            placements: [3]?u8 = .{ 1, 2, null },
        };
    };
    var prefix = Prefix.Manifest{};
    try std.testing.expectEqualSlices(u8, &.{ 0, 1 }, try activeRosterRows(Prefix, &prefix));
    prefix.placements[2] = 3;
    try std.testing.expectError(error.InvalidManifestRoster, activeRosterRows(Prefix, &prefix));
    prefix.placements[2] = null;
    prefix.roster_count = 4;
    try std.testing.expectError(error.InvalidManifestRoster, activeRosterRows(Prefix, &prefix));
}

fn treeColumnCount(comptime Manifest: type, manifest: *const Manifest.Manifest, tree: usize) usize {
    return switch (tree) {
        Manifest.PREPROCESSED_TREE_INDEX => manifest.total_preprocessed_columns,
        Manifest.MAIN_TREE_INDEX => manifest.total_main_columns,
        Manifest.INTERACTION_TREE_INDEX => manifest.total_interaction_columns,
        else => unreachable,
    };
}

fn treeOffset(comptime Manifest: type, placement: Manifest.Placement, tree: usize) usize {
    return switch (tree) {
        Manifest.PREPROCESSED_TREE_INDEX => placement.preprocessed_offset,
        Manifest.MAIN_TREE_INDEX => placement.main_offset,
        Manifest.INTERACTION_TREE_INDEX => placement.interaction_offset,
        else => unreachable,
    };
}

fn treeGeometryColumns(comptime Manifest: type, geometry: Manifest.Geometry, tree: usize) usize {
    return switch (tree) {
        Manifest.PREPROCESSED_TREE_INDEX => geometry.preprocessed_columns,
        Manifest.MAIN_TREE_INDEX => geometry.main_columns,
        Manifest.INTERACTION_TREE_INDEX => geometry.interaction_columns,
        else => unreachable,
    };
}
