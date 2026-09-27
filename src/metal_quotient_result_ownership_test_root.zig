const std = @import("std");
const engine = @import("stwo_prover_engine");
const impl = @import("backends/metal/runtime/quotient_result_ownership_v1.zig");
const Budget = engine.host_budget_allocator.SharedHostBudget;
const Tree = struct {
    id: usize,
    destroyed: *[4]usize,
    charge: engine.shared_external_memory.Reservation,
    fn init(a: std.mem.Allocator, id: usize, destroyed: *[4]usize) !Tree {
        return .{ .id = id, .destroyed = destroyed, .charge = try engine.shared_external_memory.reserve(a, 96, .explicit_unbudgeted) };
    }
    pub fn deinit(self: *Tree) void {
        std.debug.assert(self.charge.active);
        self.destroyed[self.id] += 1;
        self.charge.deinit();
        self.* = undefined;
    }
};
const Provider = struct {
    reject: bool,
    calls: usize = 0,
    pub fn completeMetalRowExecution(self: *Provider, _: u32) !void {
        self.calls += 1;
        if (self.reject) return error.ReceiptRejected;
    }
};
fn make(a: std.mem.Allocator, destroyed: *[4]usize) !impl.Batch(Tree) {
    var initial = try Tree.init(a, 0, destroyed);
    errdefer initial.deinit();
    const rest = try a.alloc(Tree, 3);
    errdefer a.free(rest);
    var initialized: usize = 0;
    errdefer for (rest[0..initialized]) |*tree| tree.deinit();
    for (rest, 1..) |*tree, id| {
        tree.* = try Tree.init(a, id, destroyed);
        initialized += 1;
    }
    return impl.Batch(Tree).init(a, initial, rest);
}
fn adopt(raw: Tree, fail: bool) !Tree {
    var owned = raw;
    errdefer owned.deinit();
    if (fail) return error.RootReadRejected;
    return owned;
}

test "quotient result: receipt rejection consumes standalone published owner" {
    const owner = try Budget.create(std.testing.allocator, 4096);
    defer owner.destroy();
    var destroyed: [4]usize = @splat(0);
    var product = .{ .tree = try Tree.init(owner.allocator(), 0, &destroyed), .execution = @as(u32, 7) };
    var provider = Provider{ .reject = true };
    try std.testing.expectError(error.ReceiptRejected, impl.acceptReceipt(owner.allocator(), &provider, &product));
    try std.testing.expectEqual([_]usize{ 1, 0, 0, 0 }, destroyed);
    try std.testing.expectEqual(@as(usize, 0), owner.snapshot().external_live_bytes);
    try std.testing.expectEqual(@as(usize, 1), provider.calls);
}

test "quotient result: failed fused receipt frees every tree and heap after original owner release" {
    const owner = try Budget.create(std.testing.allocator, 4096);
    const a = owner.allocator();
    var destroyed: [4]usize = @splat(0);
    var batch = try make(a, &destroyed);
    var product = .{ .tree = try batch.takeInitial(), .fri = .{ .trees = batch.trees }, .execution = @as(u32, 7) };
    // Transfer the raw array; the receipt boundary acquires its own heap lease.
    batch.consumed = 0;
    batch.trees = &.{};
    owner.destroy();
    var provider = Provider{ .reject = true };
    try std.testing.expectError(error.ReceiptRejected, impl.acceptReceipt(a, &provider, &product));
    try std.testing.expectEqual([_]usize{ 1, 1, 1, 1 }, destroyed);
    batch.deinit();
}

test "quotient result: failed first adoption cannot double destroy or abandon tail trees" {
    const owner = try Budget.create(std.testing.allocator, 4096);
    defer owner.destroy();
    var destroyed: [4]usize = @splat(0);
    var batch = try make(owner.allocator(), &destroyed);
    try std.testing.expectError(error.RootReadRejected, adopt(try batch.takeInitial(), true));
    batch.deinit();
    batch.deinit();
    try std.testing.expectEqual([_]usize{ 1, 1, 1, 1 }, destroyed);
    try std.testing.expectEqual(@as(usize, 0), owner.snapshot().external_live_bytes);
}

test "quotient result: middle adoption failure preserves adopted owners and releases only remaining tail" {
    const owner = try Budget.create(std.testing.allocator, 4096);
    defer owner.destroy();
    var destroyed: [4]usize = @splat(0);
    var batch = try make(owner.allocator(), &destroyed);
    var initial = try adopt(try batch.takeInitial(), false);
    defer initial.deinit();
    var first = try adopt(try batch.takeNext(), false);
    defer first.deinit();
    try std.testing.expectError(error.RootReadRejected, adopt(try batch.takeNext(), true));
    batch.deinit();
    try std.testing.expectEqual([_]usize{ 0, 0, 1, 1 }, destroyed);
    try std.testing.expectEqual(@as(usize, 192), owner.snapshot().external_live_bytes);
}

test "quotient result: successful receipt transfers charge until final adopted owner" {
    const owner = try Budget.create(std.testing.allocator, 4096);
    var destroyed: [4]usize = @splat(0);
    var product = .{ .tree = try Tree.init(owner.allocator(), 0, &destroyed), .execution = @as(u32, 7) };
    var provider = Provider{ .reject = false };
    var accepted = try impl.acceptReceipt(owner.allocator(), &provider, &product);
    try std.testing.expectEqual([_]usize{ 0, 0, 0, 0 }, destroyed);
    owner.destroy();
    accepted.tree.deinit();
    try std.testing.expectEqual([_]usize{ 1, 0, 0, 0 }, destroyed);
}

test "quotient result: raw batch heap survives all resource transfers and original owner release" {
    const owner = try Budget.create(std.testing.allocator, 4096);
    var destroyed: [4]usize = @splat(0);
    var batch = try make(owner.allocator(), &destroyed);
    owner.destroy();
    var initial = try batch.takeInitial();
    initial.deinit();
    for (0..3) |_| {
        var tree = try batch.takeNext();
        tree.deinit();
    }
    try std.testing.expectError(error.QuotientResultUnavailable, batch.takeNext());
    try std.testing.expectError(error.QuotientInitialTreeConsumed, batch.takeInitial());
    batch.deinit();
    batch.deinit();
    try std.testing.expectEqual([_]usize{ 1, 1, 1, 1 }, destroyed);
}
