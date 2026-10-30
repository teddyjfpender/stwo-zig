//! Actual original-proof metadata, independent cold factories, no producer graph.
//! Parallel compilation changes scheduling only; assembly is canonical.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Fixture = @import("../prover/block_v7_execution_caller_test_v1.zig");
const Metadata = @import("block_v7_mixed_metadata_v1.zig");
const Cold = @import("block_v7_mixed_fixed_v1.zig");
const Bus = @import("block_v7_mixed_public_v1.zig");
const Parent = @import("blake3_execution_parent_proof.zig");
const Protocol = @import("block_v7_mixed_protocol_v1.zig");
const Storage = @import("air/blake3_parent_row_storage.zig");
const Capsule = @import("block_v7_caller_joint_compiler_capsule_v1.zig").Capsule;
const Budget = engine.host_budget_allocator.SharedHostBudget;
const Consumer = struct {
    pub const Result = *Metadata.Owned;
    pub fn consume(f: Fixture.Fixture) !Result {
        return Metadata.Owned.init(f.allocator, f.trusted, f.input);
    }
};
fn equal(expected: *const Cold.Owned, actual: *const Cold.Owned) !void {
    try std.testing.expectEqualDeep(expected.context, actual.context);
    try std.testing.expectEqualDeep(expected.wires, actual.wires);
    try std.testing.expectEqualDeep(expected.expected, actual.expected);
    inline for (0..Storage.Airs.len) |i| try std.testing.expectEqualDeep(expected.fixed[i], actual.fixed[i]);
    try std.testing.expectEqualDeep(try Bus.scheduleDigest(expected.wires), try Bus.scheduleDigest(actual.wires));
}
fn key(a: std.mem.Allocator, cold: *const Cold.Owned) !Protocol.Key {
    const base = try Parent.ForBackend(Cpu).deriveKeyFromFixed(a, cold.fixed, cold.context, .diagnostic_q8_pow0);
    return Protocol.Key.fromGeometry(base, cold.wires, cold.expected);
}
test "v7 parallel cold families preserve original rows keys wires and borrowed capsule authority" {
    const a = std.testing.allocator;
    const metadata = try Fixture.runFixture(true, true, Consumer);
    defer metadata.deinit();
    const input = metadata.input();
    try std.testing.expectEqual(@as(usize, 6), try input.count());
    try std.testing.expectEqual(@as(usize, 1), input.callers.len);
    const request = try Budget.create(a, 24 << 30);
    defer request.destroy();
    const allocator = request.allocator();
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = allocator });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const capsule = try Capsule.derive(allocator, input.callers[0].input(), .{ .transcript_capacity = 2 });
    defer capsule.deinit();
    const capsules = [_]?*const Capsule{capsule};
    var serial = try Cold.Owned.derive(allocator, input, 2, .{ .caller_compilers = &capsules });
    defer serial.deinit();
    const expected_key = try key(allocator, &serial);
    for ([_]usize{ 2, 4 }) |workers| {
        var parallel = try Cold.Owned.derive(allocator, input, 2, .{ .parallel_families = workers, .caller_compilers = &capsules });
        defer parallel.deinit();
        try equal(&serial, &parallel);
        const actual_key = try key(allocator, &parallel);
        try std.testing.expectEqualDeep(expected_key, actual_key);
        try std.testing.expectEqualDeep(try expected_key.identity(), try actual_key.identity());
        // Const compiler custody still matches the independently selected
        // request after parallel namespace mutation of fresh piece rows.
        try capsule.requireProfile(allocator, input.callers[0]);
    }
    // Borrowed metadata survives after all original proofs/producer rows were
    // destroyed by runFixture. A nested occupied pool must fall back safely.
    var small_serial = try Cold.Owned.deriveWindow(allocator, input, 3, 2, 64, 2, .{});
    defer small_serial.deinit();
    var held = try pool.acquire(try engine.work_pool.WorkerBudget.init(4));
    {
        defer held.deinit();
        var fallback = try Cold.Owned.deriveWindow(allocator, input, 3, 2, 64, 2, .{ .parallel_families = 4 });
        defer fallback.deinit();
        try equal(&small_serial, &fallback);
    }
    // Post-compilation row admission failure must release EVERY concurrently
    // completed piece, including pieces after the first failing append.
    const failure_budget = try Budget.create(a, 1 << 30);
    defer failure_budget.destroy();
    try std.testing.expectError(error.MixedDirectResourceLimit, Cold.Owned.deriveWindow(failure_budget.allocator(), input, 3, 2, 64, 2, .{ .parallel_families = 2, .max_row_log = 1 }));
    try std.testing.expectEqual(@as(usize, 0), failure_budget.snapshot().live_bytes);
    // Family-local allocation failure after shared public admission, with
    // another compiler submitted, still joins and releases all child budgets.
    try std.testing.expectError(error.OutOfMemory, Cold.Owned.deriveWindow(failure_budget.allocator(), input, 3, 2, 64, 2, .{ .parallel_families = 2, .family_max_bytes = 1 }));
    try std.testing.expectEqual(@as(usize, 0), failure_budget.snapshot().live_bytes);
    const small_budget = try Budget.create(a, 1 << 20);
    defer small_budget.destroy();
    try std.testing.expectError(error.OutOfMemory, Cold.Owned.deriveWindow(small_budget.allocator(), input, 3, 2, 64, 2, .{ .parallel_families = 2, .max_bytes = 8 << 30 }));
    try std.testing.expectEqual(@as(usize, 0), small_budget.snapshot().live_bytes);
    try std.testing.expect(small_budget.snapshot().exceeded);
    for ([_]usize{ 0, engine.work_pool.MAX_WORKERS + 1 }) |workers| {
        try std.testing.expectError(error.InvalidMixedDirectLimits, Cold.Owned.deriveWindow(a, input, 0, 1, 64, 2, .{ .parallel_families = workers }));
    }
}
