//! Native verification uses the declared request workers in executable and
//! test builds alike. Keep this resource at its initialized address.
const std = @import("std");
const work = @import("stwo_prover_engine").work_pool;

pub const ScopeV1 = struct {
    pool: work.WorkPool,
    binding: work.ScopedPoolBinding,

    pub fn initInPlace(self: *ScopeV1, worker_count: usize) !void {
        try self.pool.initInPlaceWithOptions(.{ .worker_count = worker_count });
        errdefer self.pool.deinit();
        self.binding = try work.ScopedPoolBinding.init(&self.pool);
    }

    pub fn deinit(self: *ScopeV1) void {
        self.binding.deinit();
        self.pool.deinit();
        self.* = undefined;
    }

    pub fn workerCount(self: *const ScopeV1) usize {
        return self.pool.workerCount();
    }
};

test "Ethereum native verification scoped workers preserve actual FFT and Merkle roots" {
    const Engine = @import("stwo_riscv_frontend").recursion.engine.ProverEngineForBackend(@import("stwo_cpu_backend").CpuBackend);
    const M31 = @import("stwo_core").fields.m31.M31;
    const allocator = std.testing.allocator;
    var expected: ?Engine.Hasher.Hash = null;
    for ([_]usize{ 1, 2, 1 }) |workers| {
        var scope: ScopeV1 = undefined;
        try scope.initInPlace(workers);
        defer scope.deinit();
        try std.testing.expectEqual(workers, scope.workerCount());
        try std.testing.expect(work.getGlobalPool().? == &scope.pool);
        try std.testing.expectEqual(workers > 1, scope.pool.pool_initialized);
        var nested: ScopeV1 = undefined;
        try std.testing.expectError(error.ScopedPoolAlreadyBound, nested.initInPlace(1));
        var scheme = try Engine.init(allocator, .{ .pow_bits = 0, .fri_config = .{ .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 3, .fold_step = 1 } });
        defer Engine.deinit(&scheme, allocator);
        scheme.setCoefficientRetentionPolicy(.never);
        const columns = try allocator.alloc(@import("stwo_prover_engine").pcs.ColumnEvaluation, 8);
        var initialized: usize = 0;
        var moved = false;
        defer if (!moved) {
            for (columns[0..initialized]) |column| allocator.free(column.values);
            allocator.free(columns);
        };
        for (columns, 0..) |*column, index| {
            const values = try allocator.alloc(M31, 4096);
            column.* = .{ .log_size = 12, .values = values };
            initialized += 1;
            for (values, 0..) |*value, row| value.* = M31.fromU64((index + 3) * (row + 1) + row * row);
        }
        var channel = Engine.Channel{};
        moved = true;
        try Engine.commit(&scheme, allocator, columns, null, &channel);
        try Engine.flushPendingCommit(&scheme, allocator, &channel);
        var roots = try scheme.roots(allocator);
        defer roots.deinit(allocator);
        try std.testing.expectEqual(@as(usize, 1), roots.items.len);
        if (expected) |root| try std.testing.expectEqualDeep(root, roots.items[0]) else expected = roots.items[0];
    }
    try std.testing.expect(work.getGlobalPool() == null);
    var invalid: ScopeV1 = undefined;
    try std.testing.expectError(error.InvalidWorkerBudget, invalid.initInPlace(0));
    try std.testing.expectError(error.InvalidWorkerBudget, invalid.initInPlace(work.MAX_WORKERS + 1));
}
