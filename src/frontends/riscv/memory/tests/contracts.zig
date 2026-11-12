//! Canonical nominal types and callable signatures consumed across owners.
const std = @import("std");
const api = @import("../mod.zig");

test "C3 canonical API identity: memory tree and leaf types" {
    try std.testing.expect(api.air.sparse_merkle.Tree == @import("../air/sparse_merkle.zig").Tree);
    try std.testing.expect(api.air.sparse_merkle.Leaf == @import("../air/sparse_merkle.zig").Leaf);
}
