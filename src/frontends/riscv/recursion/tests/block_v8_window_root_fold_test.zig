const std = @import("std");
const P = @import("../block_v8_window_root_profile_v1.zig");
const Fold = @import("../block_v8_window_root_fold_v1.zig");
const Statement = @import("../block_v8_window_root_statement_v1.zig");
test "B8 upper refuses empty proof authority" {
    try std.testing.expectError(error.InvalidB8WindowSources, P.Owned.deriveJoin(std.testing.allocator, &.{}, &.{}, @splat(0), .{}));
    try std.testing.expectError(error.InvalidB8WindowFanIn, Fold.produce(std.testing.allocator, &.{}, &.{}));
}
test "B8 upper coverage rejects gap overlap snapshot CPU ELF and security substitutions" {
    const config = @import("../blake3_execution_parent_protocol.zig").Profile.csp_q70_pow26.config();
    const cpu = @import("../../runner/cpu.zig").Cpu.init(0x1000, 0x2000);
    const left = Statement.WindowSpan{ .elf_sha256 = @splat(1), .config = config, .first_cycle = 1, .cycles = 4, .incoming_snapshot_id = @splat(2), .outgoing_snapshot_id = @splat(3), .initial_cpu = cpu, .final_cpu = cpu };
    var right = left;
    right.first_cycle = 5;
    right.incoming_snapshot_id = left.outgoing_snapshot_id;
    right.outgoing_snapshot_id = @splat(4);
    const merged = try Statement.merge(&.{ left, right });
    try std.testing.expectEqual(@as(u64, 8), merged.cycles);
    var bad = right;
    bad.first_cycle += 1;
    try std.testing.expectError(error.NonAdjacentB8Windows, Statement.merge(&.{ left, bad }));
    bad = right;
    bad.first_cycle -= 1;
    try std.testing.expectError(error.NonAdjacentB8Windows, Statement.merge(&.{ left, bad }));
    bad = right;
    bad.incoming_snapshot_id[0] ^= 1;
    try std.testing.expectError(error.NonAdjacentB8Windows, Statement.merge(&.{ left, bad }));
    bad = right;
    bad.initial_cpu.regs[3] ^= 1;
    try std.testing.expectError(error.NonAdjacentB8Windows, Statement.merge(&.{ left, bad }));
    bad = right;
    bad.elf_sha256[0] ^= 1;
    try std.testing.expectError(error.NonAdjacentB8Windows, Statement.merge(&.{ left, bad }));
    bad = right;
    bad.config.pow_bits -= 1;
    try std.testing.expectError(error.InvalidB8WindowSpan, Statement.merge(&.{ left, bad }));
}

test "two genuine adjacent closed window roots fold with exact private public-supply closure q70" {
    const Engine = @import("stwo_prover_engine");
    const budget = try Engine.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 48 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    var pool: Engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    const Fixture = @import("block_v8_window_root_fold_fixture.zig");
    var left = try Fixture.produce(a, budget, &pool, 2);
    defer left.deinit();
    var right = try Fixture.produce(a, budget, &pool, 6);
    defer right.deinit();
    var binding = try Engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const children = [_]*const P.Owned{ left.profile, right.profile };
    const lc = P.Capture.borrow(&left.verified);
    const rc = P.Capture.borrow(&right.verified);
    var root = try Fold.produce(a, &children, &.{ &lc, &rc });
    defer root.deinit();
    // All child original producers are gone. Receiving independently rebuilds
    // the upper key from admitted metadata and consumes only root proof bytes.
    var received = try Fold.verify(a, root.bytes, &children, root.span);
    defer received.deinit();
    const root_main = received.capture.commitments[1];
    left.discardPrivate();
    right.discardPrivate();
    const tree = @import("../block_v8_window_root_receiver_v1.zig").Tree{ .branch = .{ .children = &.{ left.metadata, right.metadata }, .main_root = root_main } };
    var byte_received = try @import("../block_v8_window_root_receiver_v1.zig").verify(a, root.bytes, tree, root.span);
    defer byte_received.deinit();
    var bad = root.span;
    bad.cycles -= 1;
    try std.testing.expectError(error.UntrustedB8FoldCoverage, @import("../block_v8_window_root_receiver_v1.zig").verify(a, root.bytes, tree, bad));
    std.debug.print("B8_WINDOW_ROOT_FOLD queries=70 pow=26 child_roots=2 cycles={d} bytes={d} fresh_verified=true\n", .{ root.span.cycles, root.bytes.len });
}
