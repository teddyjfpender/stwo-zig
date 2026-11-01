const std = @import("std");
const engine = @import("stwo_prover_engine");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const P = @import("protocol.zig");
const Store = @import("retained_main_store.zig").Store;
const a = std.testing.allocator;
fn scheme(allocator: std.mem.Allocator) !P.T.Scheme {
    var out = try P.T.Scheme.init(allocator, P.T.P.config());
    errdefer out.deinit(allocator);
    out.setCompactPolynomialStorage(5);
    var x: [32]M = undefined;
    var y: [64]M = undefined;
    for (&x, 0..) |*v, i| v.* = M.fromCanonical(@intCast(i * i + 7));
    for (&y, 0..) |*v, i| v.* = M.fromCanonical(@intCast(i * 19 + 31));
    const columns = [_]engine.pcs.ColumnEvaluation{ .{ .values = &x, .log_size = 5 }, .{ .values = &y, .log_size = 6 } };
    var ch = P.T.P.Channel{};
    try out.commitBorrowedStreaming(allocator, &columns, 8, &ch);
    return out;
}
fn layerDigest(tree: *const P.T.Scheme.CommittedTree) [32]u8 {
    var hash = std.crypto.hash.blake2.Blake2s256.init(.{});
    for (tree.commitment.layers) |layer| hash.update(std.mem.sliceAsBytes(layer));
    var result: [32]u8 = undefined;
    hash.final(&result);
    return result;
}
test "fully parked MAIN nodes preserve root shape and exact data with no resident payload" {
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(a, ".");
    defer a.free(path);
    var store = try Store.initFullyParked(path, 1 << 20);
    defer store.deinit();
    var s = try scheme(a);
    var s_alive = true;
    defer if (s_alive) s.deinit(a);
    const t = &s.trees.items[0];
    const root = t.root();
    const nodes = layerDigest(t);
    const plan = try store.parkingPlan(t);
    std.debug.print("MAIN_PARKING_BYTES coefficients={d} nodes={d} header={d} root={d} rounded={d}\n", .{ plan.coefficient_bytes, plan.merkle_bytes, plan.header_bytes, plan.resident_root_bytes, plan.rounded_total_bytes });
    const first = try a.dupe(M, t.coefficients.?[0].coeffs);
    defer a.free(first);
    try std.testing.expectEqual(plan.rounded_total_bytes, try store.spill(a, t));
    try std.testing.expect(store.stats().merkle_parking_enabled);
    try std.testing.expectEqual(plan.merkle_bytes, store.stats().parked_merkle_bytes);
    try std.testing.expectEqual(@as(usize, 0), store.stats().live_mapped_bytes);
    try std.testing.expect(t.commitment.layers_parked and t.commitment.layer_values_borrowed);
    try std.testing.expectEqualDeep(root, t.root());
    try std.testing.expectEqual(@as(usize, 1), t.commitment.layers[0].len);
    for (t.commitment.layers[1..]) |layer| try std.testing.expectEqual(@as(usize, 0), layer.len);
    try std.testing.expectError(error.InvalidColumnSize, t.commitment.readHashes(a, 1, &.{0}));
    try std.testing.expectError(error.InvalidColumnSize, t.commitment.decommit(a, &.{0}, &.{}));
    try std.testing.expectEqual(plan.rounded_total_bytes, try store.restore(t));
    try std.testing.expect(!t.commitment.layers_parked);
    try std.testing.expectEqualDeep(nodes, layerDigest(t));
    try std.testing.expectEqualDeep(first, t.coefficients.?[0].coeffs);
    try std.testing.expectEqual(@as(usize, 0), try store.restore(t));
    s.deinit(a);
    s_alive = false;
    try std.testing.expectEqual(@as(usize, 0), store.stats().live_bytes);
    try std.testing.expectEqual(@as(usize, 0), store.stats().parked_merkle_bytes);
    try std.testing.expectEqual(@as(usize, 0), store.stats().live_mapped_bytes);
}
test "fully parked restore refuses file header node and length tamper without publishing mappings" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(a, ".");
    defer a.free(path);
    var store = try Store.initFullyParked(path, 1 << 20);
    defer store.deinit();
    var s = try scheme(a);
    defer s.deinit(a);
    const t = &s.trees.items[0];
    _ = try store.spill(a, t);
    const owner = store.parking.head.?;
    const offsets = [_]u64{ 20, 128, @intCast(owner.merkle.?.offset + 32) };
    for (offsets) |offset| {
        var original: [1]u8 = undefined;
        try std.testing.expectEqual(@as(usize, 1), try owner.file.file.preadAll(&original, offset));
        const corrupt = [1]u8{original[0] ^ 1};
        try owner.file.file.pwriteAll(&corrupt, offset);
        try std.testing.expectError(error.RetainedMainFileIntegrityMismatch, store.restore(t));
        try std.testing.expect(t.commitment.layers_parked);
        try std.testing.expectEqual(@as(usize, 0), store.stats().live_mapped_bytes);
        try owner.file.file.pwriteAll(&original, offset);
    }
    try owner.file.file.setEndPos(owner.file.size + 1);
    try std.testing.expectError(error.RetainedMainFileIntegrityMismatch, store.restore(t));
    try owner.file.file.setEndPos(owner.file.size);
    t.commitment.layers[0].len = 0;
    try std.testing.expectError(error.RetainedMainShapeMismatch, store.restore(t));
    t.commitment.layers[0].len = 1;
    _ = try store.restore(t);
}
fn allocationCase(allocator: std.mem.Allocator, path: []const u8) !void {
    var store = try Store.initFullyParked(path, 1 << 20);
    defer store.deinit();
    var s = try scheme(allocator);
    defer s.deinit(allocator);
    const t = &s.trees.items[0];
    _ = try store.spill(allocator, t);
    _ = try store.restore(t);
}
test "fully parked complete owner lifecycle cleans every allocation failure and abort" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(a, ".");
    defer a.free(path);
    try std.testing.checkAllAllocationFailures(a, allocationCase, .{path});
    var store = try Store.initFullyParked(path, 1 << 20);
    defer store.deinit();
    {
        var s = try scheme(a);
        defer s.deinit(a);
        _ = try store.spill(a, &s.trees.items[0]);
    }
    try std.testing.expectEqual(@as(usize, 0), store.stats().live_bytes);
    try std.testing.expectEqual(@as(usize, 0), store.stats().parked_merkle_bytes);
}
test "fully parked combined disk limit refuses before coefficient or node ownership changes" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(a, ".");
    defer a.free(path);
    var store = try Store.initFullyParked(path, 1);
    defer store.deinit();
    var s = try scheme(a);
    defer s.deinit(a);
    const t = &s.trees.items[0];
    const coef = t.coefficients.?[0].coeffs.ptr;
    const nodes = layerDigest(t);
    try std.testing.expectError(error.RetainedMainBudgetExceeded, store.spill(a, t));
    try std.testing.expectEqual(coef, t.coefficients.?[0].coeffs.ptr);
    try std.testing.expectEqualDeep(nodes, layerDigest(t));
    try std.testing.expect(t.backing_teardown == null and !t.commitment.layer_values_borrowed);
}
test "actual CPU OM service shards fully parked and resident proofs are exact and fresh accepted" {
    const Fixture = @import("services/gkr_local/cpu_worker_test.zig");
    inline for (0..2) |shard| {
        const resident = try Fixture.exercise(shard, .normal, .resident);
        const parked = try Fixture.exercise(shard, .normal, .fully_parked);
        try std.testing.expectEqualSlices(u8, &resident, &parked);
        std.debug.print("FULL_MAIN_PARKING shard={d} proof_claims_sha256={x}\n", .{ shard, parked });
    }
}
test "actual CPU fully parked abort and later worker OOM release nodes without restore" {
    const Fixture = @import("services/gkr_local/cpu_worker_test.zig");
    _ = try Fixture.exercise(0, .parked_abort, .fully_parked);
    _ = try Fixture.exercise(0, .later_worker_oom, .fully_parked);
}

test "fully parked mappings reserve and release the same SharedHostBudget cap" {
    const Budget = engine.host_budget_allocator.SharedHostBudget;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(a, ".");
    defer a.free(path);
    const budget = try Budget.create(a, 1 << 20);
    defer budget.destroy();
    var store = try Store.initFullyParked(path, 1 << 20);
    defer store.deinit();
    var s = try scheme(budget.allocator());
    var alive = true;
    defer if (alive) s.deinit(budget.allocator());
    const tree = &s.trees.items[0];
    const bytes = try store.spill(budget.allocator(), tree);
    const original = budget.snapshot();
    const blocker_bytes = original.limit - original.live_bytes - (bytes - 1);
    const blocker = try budget.allocator().alloc(u8, blocker_bytes);
    var block_alive = true;
    defer if (block_alive) budget.allocator().free(blocker);
    try std.testing.expectError(error.OutOfMemory, store.restore(tree));
    try std.testing.expect(tree.commitment.layers_parked and store.stats().live_mapped_bytes == 0);
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().external_live_bytes);
    budget.allocator().free(blocker);
    block_alive = false;
    _ = try store.restore(tree);
    try std.testing.expectEqual(bytes, budget.snapshot().external_live_bytes);
    s.deinit(budget.allocator());
    alive = false;
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
}
