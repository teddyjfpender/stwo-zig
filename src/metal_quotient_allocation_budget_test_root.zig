const std = @import("std");
const budget = @import("stwo_prover_engine").host_budget_allocator;
const impl = @import("backends/metal/runtime/quotient_allocation_budget_v1.zig");
const Scope = impl.Scope;

test "quotient allocation: callback admits before factory and a failed growth is sticky" {
    const owner = try budget.SharedHostBudget.create(std.testing.allocator, 128);
    defer owner.destroy();
    var scope = try Scope.init(owner.allocator());
    defer scope.deinit();
    try std.testing.expect(!scope.retainsDomainCache());
    var constructed: usize = 0;
    if (Scope.callback(&scope, 96)) constructed += 1;
    if (Scope.callback(&scope, 33)) constructed += 1;
    if (Scope.callback(&scope, 1)) constructed += 1;
    try std.testing.expectEqual(@as(usize, 1), constructed);
    try std.testing.expectEqual(@as(usize, 96), owner.snapshot().external_live_bytes);
    try std.testing.expectError(error.OutOfMemory, scope.finish(2, false, 0));
}

test "quotient allocation: joined hash arena owns exactly its retained charge" {
    const owner = try budget.SharedHostBudget.create(std.testing.allocator, 2048);
    defer owner.destroy();
    var scope = try Scope.init(owner.allocator());
    defer scope.deinit();
    try scope.admit(1600);
    try std.testing.expectError(error.QuotientBudgetNotFinished, scope.take());
    try scope.finish(8, true, 800);
    var tree_charge = try scope.take();
    defer tree_charge.deinit();
    scope.deinit();
    try tree_charge.requireOwner(owner.allocator(), 800);
    try std.testing.expectEqual(@as(usize, 800), owner.snapshot().external_live_bytes);
    try std.testing.expectError(error.QuotientBudgetClosed, scope.admit(1));
    tree_charge.deinit();
    try std.testing.expectEqual(@as(usize, 0), owner.snapshot().external_live_bytes);
}

test "quotient allocation: uncommitted and discrete readback extents are distinct" {
    const owner = try budget.SharedHostBudget.create(std.testing.allocator, 2048);
    defer owner.destroy();
    var bare = try Scope.init(owner.allocator());
    defer bare.deinit();
    try bare.admit(1024);
    try bare.finish(8, false, 0);
    try std.testing.expectEqual(@as(usize, 0), owner.snapshot().external_live_bytes);
    var committed = try Scope.init(owner.allocator());
    defer committed.deinit();
    try committed.admit(1024);
    try committed.finish(8, true, 832);
    try std.testing.expectEqual(@as(usize, 832), owner.snapshot().external_live_bytes);
}

test "quotient allocation: malformed retention never releases the admitted envelope" {
    const owner = try budget.SharedHostBudget.create(std.testing.allocator, 2048);
    defer owner.destroy();
    var scope = try Scope.init(owner.allocator());
    defer scope.deinit();
    try scope.admit(1024);
    for ([_]usize{ 32, 768, 804, 864, 2048 }) |bad| try std.testing.expectError(error.InvalidQuotientRetainedExtent, scope.finish(8, true, bad));
    try std.testing.expectError(error.InvalidQuotientRetainedExtent, scope.finish(8, false, 800));
    try std.testing.expectEqual(@as(usize, 1024), owner.snapshot().external_live_bytes);
    var short = try Scope.init(owner.allocator());
    defer short.deinit();
    try short.admit(128);
    try std.testing.expectError(error.InvalidQuotientRetainedExtent, short.finish(8, true, 800));
}

test "quotient allocation: layer offsets retain ABI padding at small and large heights" {
    try std.testing.expectEqual(@as(usize, 32), try impl.hashArenaBytes(1));
    try std.testing.expectEqual(@as(usize, 288), try impl.hashArenaBytes(2));
    try std.testing.expectEqual(@as(usize, 800), try impl.hashArenaBytes(8));
    try std.testing.expectEqual(@as(usize, 1312), try impl.hashArenaBytes(16));
    for ([_]usize{ 0, 3, 1 << 30, (1 << 30) + 1 }) |bad| try std.testing.expectError(error.InvalidQuotientRetainedExtent, impl.hashArenaBytes(bad));
    // Large domains remain aligned; the final two layer gaps add80 words.
    try std.testing.expectEqual(@as(usize, ((1 << 25) * 2 - 1) * 32 + 320), try impl.hashArenaBytes(1 << 25));
}

test "quotient allocation: callback holds the allocator through original owner teardown" {
    const owner = try budget.SharedHostBudget.create(std.testing.allocator, 2048);
    var scope = try Scope.init(owner.allocator());
    defer scope.deinit();
    const heap = try owner.allocator().alloc(u8, 64);
    owner.destroy();
    try scope.admit(1024);
    try scope.finish(8, true, 800);
    const retained_owner = scope.reservation.owner.?;
    retained_owner.allocator().free(heap);
    try std.testing.expectEqual(@as(usize, 800), retained_owner.snapshot().external_live_bytes);
}

test "quotient allocation: explicit ordinary APIs preserve uncapped policy without overflow" {
    var scope = try Scope.init(std.testing.allocator);
    defer scope.deinit();
    try std.testing.expect(scope.retainsDomainCache());
    try scope.admit(std.math.maxInt(usize));
    try std.testing.expect(!Scope.callback(&scope, 1));
    try std.testing.expectError(error.Overflow, scope.finish(8, false, 0));
}

test "quotient allocation: concurrent dispatches compete for one supplied cap" {
    const owner = try budget.SharedHostBudget.create(std.testing.allocator, 256);
    defer owner.destroy();
    var first = try Scope.init(owner.allocator());
    defer first.deinit();
    var second = try Scope.init(owner.allocator());
    defer second.deinit();
    const Worker = struct {
        fn run(scope: *Scope, admitted: *bool) void {
            admitted.* = Scope.callback(scope, 160);
        }
    };
    var accepted: [2]bool = .{ false, false };
    const a = try std.Thread.spawn(.{}, Worker.run, .{ &first, &accepted[0] });
    const b = try std.Thread.spawn(.{}, Worker.run, .{ &second, &accepted[1] });
    a.join();
    b.join();
    try std.testing.expect(accepted[0] != accepted[1]);
    try std.testing.expectEqual(@as(usize, 160), owner.snapshot().external_live_bytes);
}

test "quotient allocation: canonical BLAKE3 is admitted by the direct quotient framing" {
    const protocol = @import("backends/metal/runtime/protocol_mode.zig");
    try std.testing.expect(protocol.validDirectCommitmentParameters(3, 0, @splat(0), @splat(0)));
    try std.testing.expect(protocol.validDirectCommitmentParameters(1, 64, @splat(123), @splat(456)));
    try std.testing.expect(protocol.validDirectCommitmentParameters(2, 0, @splat(0), @splat(0)));
    for ([_]u32{ 0, 4, std.math.maxInt(u32) }) |bad| try std.testing.expect(!protocol.validDirectCommitmentParameters(bad, 0, @splat(0), @splat(0)));
    try std.testing.expect(!protocol.validDirectCommitmentParameters(3, 64, @splat(0), @splat(0)));
    inline for (0..8) |index| {
        var seed: [8]u32 = @splat(0);
        seed[index] = 1;
        try std.testing.expect(!protocol.validDirectCommitmentParameters(3, 0, seed, @splat(0)));
        try std.testing.expect(!protocol.validDirectCommitmentParameters(3, 0, @splat(0), seed));
    }
}

test "quotient allocation: typed direct BLAKE3 selection does not admit unsupported staged state" {
    const domain = @import("backends/metal/hash_domain.zig");
    const Blake3 = @import("stwo_core").vcs_lifted.blake3_merkle.MerkleHasher;
    const selected = comptime domain.directParameters(Blake3).?;
    try std.testing.expectEqual(domain.FamilyV1.blake3, selected.family);
    try std.testing.expectEqual(@as(u32, 0), selected.domain_prefix_bytes);
    try std.testing.expectEqual([_]u32{0} ** 8, selected.leaf_seed);
    try std.testing.expectEqual([_]u32{0} ** 8, selected.node_seed);
    try std.testing.expect(domain.parameters(Blake3) == null);
}
