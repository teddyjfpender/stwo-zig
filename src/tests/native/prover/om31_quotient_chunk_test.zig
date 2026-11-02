const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const Point = core.circle.CirclePoint(O);
const Provider = engine.pcs.quotient_ops.ForField(O).LazyQuotientProvider;
const a = std.testing.allocator;
fn create(limit: ?usize) !Provider {
    return createFor(a, limit, 12);
}
fn createFor(allocator: std.mem.Allocator, limit: ?usize, log: u32) !Provider {
    const size = @as(usize, 1) << @intCast(log);
    const zero = try allocator.alloc(M, size);
    defer allocator.free(zero);
    @memset(zero, M.zero());
    if (log > 12) zero[0] = M.one();
    var ch = core.channel.raw_mod_m31.Om31Channel.init();
    var samples: [4]Point = undefined;
    for (&samples) |*p| p.* = try core.circle.randomSecureFieldPointFor(O, &ch);
    var vals = [_]O{O.zero()} ** 4;
    var cols = [_]engine.pcs.ColumnEvaluation{.{ .log_size = log, .values = &.{}, .coefficient_values = zero }};
    var trees = [_][]const engine.pcs.ColumnEvaluation{&cols};
    var cp = [_][]Point{&samples};
    var pts = [_][][]Point{&cp};
    var cv = [_][]O{&vals};
    var values = [_][][]O{&cv};
    return Provider.initForBackendWithWorkRecorderAndByteLimit(void, allocator, core.pcs.TreeVec([]const engine.pcs.ColumnEvaluation).initOwned(&trees), core.pcs.TreeVec([][]Point).initOwned(&pts), core.pcs.TreeVec([][]O).initOwned(&values), O.one(), log, null, limit);
}
test "wide quotient bounded chunks handle multi-tile partial rows and preserve zero numerator poles" {
    var provider = try create(null);
    defer provider.deinit(a);
    const plan = provider.scratch_plan;
    try std.testing.expectEqual(@as(usize, 1024), plan.rows);
    try std.testing.expectEqual(plan.total_bytes, provider.resourcePlan().inverse_chunk_scratch_bytes);
    try std.testing.expectError(error.QuotientScratchBudgetExceeded, create(plan.total_bytes - 1));
    var admitted = try create(plan.total_bytes);
    defer admitted.deinit(a);
    const planes = try a.alloc(M, 8 * 2053);
    defer a.free(planes);
    @memset(planes, M.one());
    var coordinates: [8][]M = undefined;
    for (&coordinates, 0..) |*c, i| c.* = planes[i * 2053 ..][0..2053];
    try provider.computeChunk(7, 2053, &coordinates);
    for (planes) |v| try std.testing.expect(v.isZero());
    try provider.computeChunk(4096, 0, &coordinates);
    try std.testing.expectError(error.ShapeMismatch, provider.computeChunk(4090, 20, &coordinates));
    const saved = provider.workspace.sample_point_components[0];
    provider.workspace.sample_point_components[0] = .{ .determinant = O.InnerField.zero(), .pix = O.InnerField.zero(), .piy = O.InnerField.zero() };
    try std.testing.expectError(error.DivisionByZero, provider.workspace.beginRow(provider.domain.at(0)));
    try std.testing.expectError(error.DivisionByZero, provider.computeChunk(0, 17, &coordinates));
    provider.workspace.sample_point_components[0] = saved;
    try provider.computeChunk(0, 17, &coordinates);
}
test "wide quotient no sampled batches returns zero without inverse scratch" {
    var columns = [_][]const engine.pcs.ColumnEvaluation{};
    var points = [_][][]Point{};
    var values = [_][][]O{};
    var provider = try Provider.init(a, core.pcs.TreeVec([]const engine.pcs.ColumnEvaluation).initOwned(&columns), core.pcs.TreeVec([][]Point).initOwned(&points), core.pcs.TreeVec([][]O).initOwned(&values), O.one(), 5);
    defer provider.deinit(a);
    try std.testing.expectEqual(@as(usize, 0), provider.scratch_plan.total_bytes);
    var data = [_]M{M.one()} ** (8 * 32);
    var coordinates: [8][]M = undefined;
    for (&coordinates, 0..) |*c, i| c.* = data[i * 32 ..][0..32];
    try provider.computeChunk(0, 32, &coordinates);
    for (data) |x| try std.testing.expect(x.isZero());
}

fn parallelLifecycle(allocator: std.mem.Allocator) !void {
    var provider = try createFor(allocator, null, 12);
    defer provider.deinit(allocator);
    // Exercise all per-shard allocations even without a scoped test pool.
    provider.parallel_shards = 4;
    var output = try engine.secure_column.SecureColumnByCoordsFor(O).uninitialized(allocator, provider.domain_size);
    defer output.deinit(allocator);
    try provider.computeAll(allocator, &output);
}
test "wide quotient shard scratch releases every partial allocation" {
    try std.testing.checkAllAllocationFailures(a, parallelLifecycle, .{});
}
test "wide quotient parallel rows preserve scalar bytes and zero-weight pole rejection" {
    const Column = engine.secure_column.SecureColumnByCoordsFor(O);
    var scalar = try createFor(a, null, 14);
    defer scalar.deinit(a);
    var expected = try Column.uninitialized(a, scalar.domain_size);
    defer expected.deinit(a);
    try scalar.computeAll(a, &expected);
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var provider = try createFor(a, null, 14);
    defer provider.deinit(a);
    try std.testing.expect(provider.parallel_shards > 1);
    try std.testing.expect(provider.resourcePlan().parallel_row_scratch_bytes > 0);
    var actual = try Column.uninitialized(a, provider.domain_size);
    defer actual.deinit(a);
    try provider.computeAll(a, &actual);
    for (expected.columns, actual.columns) |left, right| try std.testing.expectEqualSlices(M, left, right);
    // A saturated lease must execute the exact scalar fallback, without deadlock.
    var lease = try pool.acquire(try engine.work_pool.WorkerBudget.init(4));
    try provider.computeAll(a, &actual);
    lease.deinit();
    for (expected.columns, actual.columns) |left, right| try std.testing.expectEqualSlices(M, left, right);
    const only_primary = try createFor(a, provider.scratch_plan.total_bytes, 12);
    var cap_provider = only_primary;
    defer cap_provider.deinit(a);
    try std.testing.expectEqual(@as(usize, 1), cap_provider.parallel_shards);
    // A valid zero numerator still cannot mask a pole in either route.
    for (provider.workspace.sample_point_components) |*component| component.* = .{ .determinant = O.InnerField.zero(), .pix = O.InnerField.zero(), .piy = O.InnerField.zero() };
    // All worker workspaces must use the same challenge authority. Changing the
    // source batch point makes both their freshly built contexts and slot zero
    // reject, before a physical quotient can be returned.
    for (provider.batches) |*batch| batch.point = .{ .x = O.zero(), .y = O.zero() };
    try std.testing.expectError(error.DivisionByZero, provider.computeAll(a, &actual));
}
