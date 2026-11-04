const std = @import("std");
const Execution = @import("stwo_riscv_cpu_integration").rv64_om31_execution_wrap;
const Engine = @import("stwo_prover_engine");
const Shared = Engine.host_budget_allocator.SharedHostBudget;

test "ready actual public API is semantically reached and rejects unowned or invalid admission" {
    // This real call forces every branch of runWithFactories through semantic
    // analysis. No invalid/undefined execution authority is touched on refusal.
    try std.testing.expectError(error.SharedRecursionBudgetRequired, Execution.runWithFactories(std.testing.allocator, &.{}, &.{}, undefined, undefined, undefined, null, undefined, false, .{ .lanes = &.{}, .pool_worker_budget = 0 }));
    const budget = try Shared.create(std.testing.allocator, 32 << 20);
    defer budget.destroy();
    try std.testing.expectError(error.InvalidRecursionAdmission, Execution.runWithFactories(budget.allocator(), &.{}, &.{}, undefined, undefined, undefined, null, undefined, false, .{ .lanes = &.{}, .pool_worker_budget = 0 }));
}

test "ready helper and coordinator stacks share budget without charging borrowed reservation twice" {
    const budget = try Shared.create(std.testing.allocator, 32 << 20);
    defer budget.destroy();
    var pool: Engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 3, .stack_size = 1 << 20, .backing_allocator = budget.allocator() });
    defer pool.deinit();
    const lanes = [_]Execution.Lane{.{ .physical_device = 0, .pool = &pool, .factory = undefined }};
    const before = budget.snapshot().external_live_bytes;
    var owned = try Execution.StackReservations.init(budget.allocator(), .{ .lanes = &lanes, .pool_worker_budget = 3 });
    try std.testing.expectEqual(before + (10 << 20), budget.snapshot().external_live_bytes);
    owned.deinit();
    try std.testing.expectEqual(before, budget.snapshot().external_live_bytes);
    var existing = try budget.reserveExternal(2 << 20);
    defer existing.deinit();
    var borrowed = try Execution.StackReservations.init(budget.allocator(), .{ .lanes = &lanes, .pool_worker_budget = 3, .pool_stack_reservation = &existing });
    try std.testing.expectEqual(before + (10 << 20), budget.snapshot().external_live_bytes);
    borrowed.deinit();
    try std.testing.expectEqual(before + (2 << 20), budget.snapshot().external_live_bytes);
    var small = try budget.reserveExternal(1 << 20);
    defer small.deinit();
    try std.testing.expectError(error.InsufficientRecursionPoolStackReservation, Execution.StackReservations.init(budget.allocator(), .{ .lanes = &lanes, .pool_worker_budget = 3, .pool_stack_reservation = &small }));
    const other = try Shared.create(std.testing.allocator, 32 << 20);
    defer other.destroy();
    var foreign = try other.reserveExternal(2 << 20);
    defer foreign.deinit();
    try std.testing.expectError(error.InvalidExternalReservationOwner, Execution.StackReservations.init(budget.allocator(), .{ .lanes = &lanes, .pool_worker_budget = 3, .pool_stack_reservation = &foreign }));
    const tight = try Shared.create(std.testing.allocator, 4 << 20);
    defer tight.destroy();
    // Helper reservation succeeds, coordinator admission fails, and cleanup
    // returns all external custody before the allocator's owner is destroyed.
    try std.testing.expectError(error.OutOfMemory, Execution.StackReservations.init(tight.allocator(), .{ .lanes = &lanes, .pool_worker_budget = 3 }));
    try std.testing.expectEqual(@as(usize, 0), tight.snapshot().external_live_bytes);
}

test "strict receiver public API refuses incomplete physical nodes before graph construction" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try std.testing.expectError(error.MissingRecursiveNodeProof, Execution.verifyExisting(std.testing.allocator, &.{undefined}, &.{}, undefined, undefined, undefined, null, temporary.dir));
}

test "ready actual API admits known recycler budget and validates borrowed stack owner" {
    const budget = try Shared.create(std.testing.allocator, 32 << 20);
    defer budget.destroy();
    var recycler = @import("stwo_riscv_cpu_integration").rv64_large_block_recycler.LargeBlockRecycler.init(budget.allocator(), 4 << 20);
    defer recycler.deinit();
    // Invalid lane admission is reached only after exact backing validation;
    // the absent execution authorities are never accessed by this refusal.
    try std.testing.expectError(error.InvalidRecursionAdmission, Execution.runWithFactories(recycler.allocator(), &.{}, &.{}, undefined, undefined, undefined, null, undefined, false, .{ .lanes = &.{}, .pool_worker_budget = 0 }));
    var pool: @import("stwo_prover_engine").work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 2, .stack_size = 1 << 20, .backing_allocator = recycler.allocator() });
    defer pool.deinit();
    const lanes = [_]Execution.Lane{.{ .physical_device = 0, .pool = &pool, .factory = undefined }};
    var existing = try budget.reserveExternal(1 << 20);
    defer existing.deinit();
    var stacks = try Execution.StackReservations.init(recycler.allocator(), .{ .lanes = &lanes, .pool_worker_budget = 2, .pool_stack_reservation = &existing });
    try std.testing.expectEqual(@as(usize, 9 << 20), budget.snapshot().external_live_bytes);
    stacks.deinit();
    try std.testing.expectEqual(@as(usize, 1 << 20), budget.snapshot().external_live_bytes);
}
