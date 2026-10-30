//! Five local parts, no global-memory tree or snapshot provider.
const Placement = @import("block_v7_heterogeneous_components_v1.zig");
pub const TRACE_TREES: usize = 11;
pub const SOURCE_COUNT: usize = 5;
pub const native = [3]usize{ 0, 1, 6 };
pub const endpoints = [3]usize{ 0, 2, 7 };
pub const endpoint_range = [3]usize{ 0, 3, 8 };
pub const program = [3]usize{ 0, 4, 9 };
pub const lookup = [3]usize{ 0, 5, 10 };
pub const maps = .{ native, endpoints, endpoint_range, program, lookup };
pub fn For(comptime proving: bool) type {
    return Placement.For(maps, TRACE_TREES, proving);
}
