//! Fixed finite placement for the new native/endpoint original proof. No
//! producer-selected relocation or shared private-tree aliases are admitted.
//! Sources retain their own equation authorities and must outlive this owner.
const std = @import("std");
const Placement = @import("block_v7_heterogeneous_components_v1.zig");
pub const TRACE_TREES: usize = 13;
pub const SOURCE_COUNT: usize = 6;
pub const native = [3]usize{ 0, 1, 7 };
pub const endpoints = [3]usize{ 0, 2, 8 };
pub const endpoint_range = [3]usize{ 0, 3, 9 };
pub const program = [3]usize{ 0, 4, 10 };
pub const lookup = [3]usize{ 0, 5, 11 };
pub const memory = [3]usize{ 0, 6, 12 };
pub const maps = .{ native, endpoints, endpoint_range, program, lookup, memory };
pub fn For(comptime proving: bool) type {
    return Placement.For(maps, TRACE_TREES, proving);
}
test "endpoint whole placement owns every private and interaction tree exactly once" {
    var seen: [TRACE_TREES]bool = @splat(false);
    inline for (maps) |map| {
        try std.testing.expectEqual(@as(usize, 0), map[0]);
        for (map[1..]) |tree| {
            try std.testing.expect(tree > 0 and tree < TRACE_TREES);
            try std.testing.expect(!seen[tree]);
            seen[tree] = true;
        }
    }
    for (seen[1..]) |used| try std.testing.expect(used);
}
