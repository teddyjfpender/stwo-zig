//! Bounded metadata-only compiler cohorts: original proofs have already died.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const Set = @import("block_v7_native_compiler_set_v1.zig");
const Fixture = @import("../prover/block_v7_execution_caller_test_v1.zig");
const Metadata = @import("block_v7_mixed_metadata_v1.zig");
const Cold = @import("block_v7_mixed_fixed_v1.zig");
const Storage = @import("air/blake3_parent_row_storage.zig");
const Consumer = struct {
    pub const Result = *Metadata.Owned;
    pub fn consume(f: Fixture.Fixture) !Result {
        return Metadata.Owned.init(f.allocator, f.trusted, f.input);
    }
};
test "native compiler bounded parallel set canonical cold parity and aggregate failure cleanup" {
    const a = std.testing.allocator;
    const metadata = try Fixture.runFixture(true, true, Consumer);
    defer metadata.deinit();
    const input = metadata.input();
    try std.testing.expectEqual(@as(usize, 2), input.natives.len);
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(a, 8 << 30);
    defer budget.destroy();
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 2, .backing_allocator = budget.allocator() });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var compiled = try Set.Owned.initWindow(budget.allocator(), input, 0, 2, 64, .{ .parallel_families = 2 });
    defer compiled.deinit();
    var serial = try Cold.Owned.deriveWindow(a, input, 0, 2, 64, 2, .{});
    defer serial.deinit();
    var reused = try Cold.Owned.deriveWindow(a, input, 0, 2, 64, 2, .{ .parallel_families = 2, .native_compilers = compiled.slots });
    defer reused.deinit();
    try std.testing.expectEqualDeep(serial.wires, reused.wires);
    try std.testing.expectEqualDeep(serial.context, reused.context);
    try std.testing.expectEqualDeep(serial.expected, reused.expected);
    inline for (0..Storage.Airs.len) |i| try std.testing.expectEqualDeep(serial.fixed[i], reused.fixed[i]);
    for (compiled.slots, input.natives) |capsule, native| try capsule.?.requireProfile(native.profile);
    // A non-native bounded window must not retain any native compiler.
    var empty = try Set.Owned.initWindow(a, input, 3, 1, 64, .{});
    defer empty.deinit();
    for (empty.slots) |slot| try std.testing.expect(slot == null);
    // Nested occupied lease runs coordinator serially, with identical authority.
    var lease = try pool.acquire(try engine.work_pool.WorkerBudget.init(2));
    {
        defer lease.deinit();
        var fallback = try Set.Owned.initWindow(a, input, 0, 1, 64, .{ .parallel_families = 2 });
        defer fallback.deinit();
        try fallback.slots[0].?.requireProfile(input.natives[0].profile);
        try std.testing.expect(fallback.slots[1] == null);
    }
    const constrained = try engine.host_budget_allocator.SharedHostBudget.create(a, 2 << 20);
    defer constrained.destroy();
    try std.testing.expectError(error.OutOfMemory, Set.Owned.initWindow(constrained.allocator(), input, 0, 2, 64, .{ .parallel_families = 2 }));
    try std.testing.expectEqual(@as(usize, 0), constrained.snapshot().live_bytes);
    compiled.clear();
    for (compiled.slots) |slot| try std.testing.expect(slot == null);
    // The now independent row outputs continue to carry their original identity.
    try std.testing.expectEqualDeep(serial.context, reused.context);
}
