//! Merkle layer policy must not escape an explicitly supplied host budget.
const std = @import("std");
const core = @import("stwo_core");
const Budget = @import("../host_budget_allocator.zig").SharedHostBudget;
const parameters = @import("../vcs_lifted/parameters.zig");
const H = core.vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
const Tree = @import("commitment_tree.zig").CommitmentTreeProver(H);
const M = core.fields.m31.M31;

test "budgeted Merkle small and mmap-sized layers honor explicit limit" {
    const owner = try Budget.create(std.testing.allocator, 32);
    defer owner.destroy();
    const a = owner.allocator();
    try std.testing.expect(Budget.isAllocator(a));
    try std.testing.expect(!Budget.isAllocator(std.testing.allocator));
    const selected = parameters.layerAllocator(a);
    try std.testing.expectEqual(a.ptr, selected.ptr);
    try std.testing.expectEqual(a.vtable, selected.vtable);
    const bytes = try selected.alloc(u8, 32);
    defer selected.free(bytes);
    try std.testing.expectError(error.OutOfMemory, selected.alloc(u8, 1));
    try std.testing.expectError(error.OutOfMemory, selected.alloc(u8, parameters.mmap_layer_threshold_bytes));
    try std.testing.expectEqual(@as(usize, 32), owner.snapshot().live_bytes);
}

test "budgeted Merkle commitment and openings retain allocator custody" {
    const owner = try Budget.create(std.testing.allocator, 1024 * 1024);
    defer owner.destroy();
    const a = owner.allocator();
    const values = [_]M{ M.one(), M.fromCanonical(2), M.fromCanonical(3), M.fromCanonical(4) };
    var expected = try Tree.init(std.testing.allocator, &.{.{ .log_size = 2, .values = &values }});
    defer expected.deinit(std.testing.allocator);
    {
        var tree = try Tree.init(a, &.{.{ .log_size = 2, .values = &values }});
        defer tree.deinit(a);
        try std.testing.expectEqual(expected.root(), tree.root());
        try std.testing.expectEqual(a.ptr, tree.commitment.layer_allocator.ptr);
        var opening = try tree.decommit(a, &.{ 0, 2 });
        defer opening.deinit(a);
        try std.testing.expect(owner.snapshot().live_bytes > 0);
    }
    try std.testing.expectEqual(@as(usize, 0), owner.snapshot().live_bytes);
}
