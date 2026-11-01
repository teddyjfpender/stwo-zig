const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const Point = core.circle.CirclePoint(O);
const Provider = engine.pcs.quotient_ops.ForField(O).LazyQuotientProvider;
const a = std.testing.allocator;
fn create(limit: ?usize) !Provider {
    const zero = try a.alloc(M, 4096);
    defer a.free(zero);
    @memset(zero, M.zero());
    var ch = core.channel.raw_mod_m31.Om31Channel.init();
    var samples: [4]Point = undefined;
    for (&samples) |*p| p.* = try core.circle.randomSecureFieldPointFor(O, &ch);
    var vals = [_]O{O.zero()} ** 4;
    var cols = [_]engine.pcs.ColumnEvaluation{.{ .log_size = 12, .values = zero }};
    var trees = [_][]const engine.pcs.ColumnEvaluation{&cols};
    var cp = [_][]Point{&samples};
    var pts = [_][][]Point{&cp};
    var cv = [_][]O{&vals};
    var values = [_][][]O{&cv};
    return Provider.initForBackendWithWorkRecorderAndByteLimit(void, a, core.pcs.TreeVec([]const engine.pcs.ColumnEvaluation).initOwned(&trees), core.pcs.TreeVec([][]Point).initOwned(&pts), core.pcs.TreeVec([][]O).initOwned(&values), O.one(), 12, null, limit);
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
