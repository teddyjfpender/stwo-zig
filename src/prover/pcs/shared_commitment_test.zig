//! Leases retain the complete owner across independent request lifetimes.
const std = @import("std");
const core = @import("stwo_core");
const tree_mod = @import("commitment_tree.zig");
const H = core.vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
const Tree = tree_mod.CommitmentTreeProver(H);
const M = core.fields.m31.M31;
const Poly = @import("../poly/circle/mod.zig").CircleCoefficients;

fn make(a: std.mem.Allocator) !Tree {
    const values = [_]M{ M.one(), M.fromCanonical(2), M.fromCanonical(3), M.fromCanonical(4) };
    var tree = try Tree.init(a, &.{.{ .log_size = 2, .values = &values }});
    errdefer tree.deinit(a);
    const coefficients = try a.alloc(Poly, 1);
    errdefer a.free(coefficients);
    coefficients[0] = try Poly.initOwned(try a.dupe(M, &values));
    tree.coefficients = coefficients;
    return tree;
}

test "PCS shared commitment retains coefficients and original allocator across leases" {
    const a = std.testing.allocator;
    var original = try make(a);
    var live = true;
    defer if (live) original.deinit(a);
    try original.share(a);
    const root = original.root();
    var first = original.retainShared();
    var second = original.retainShared();
    // This allocator cannot allocate or free the original tree's storage.
    var request_buffer: [1]u8 = undefined;
    var request = std.heap.FixedBufferAllocator.init(&request_buffer);
    first.releaseCoefficients(request.allocator());
    try std.testing.expect(first.coefficients == null);
    try std.testing.expect(second.coefficients != null);
    first.deinit(request.allocator());
    live = false;
    original.deinit(a);
    defer second.deinit(request.allocator());
    try std.testing.expectEqual(root, second.root());
    try std.testing.expectEqual(M.one(), second.coefficients.?[0].coefficients()[0]);
    var opening = try second.decommit(a, &.{ 0, 2 });
    defer opening.deinit(a);
    var third = second.retainShared();
    defer third.deinit(request.allocator());
    try std.testing.expectEqual(root, third.root());
}

test "PCS shared commitment failed promotion preserves original ownership" {
    const a = std.testing.allocator;
    var tree = try make(a);
    defer tree.deinit(a);
    var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, tree.share(failing.allocator()));
    try std.testing.expect(tree.shared_owner == null);
    try std.testing.expect(tree.coefficients != null);
}
