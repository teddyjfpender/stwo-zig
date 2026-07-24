//! XOR aliases for the shared uniform proof topology.

const layout = @import("layout.zig");
const shared = @import("../common/uniform_topology.zig");

const Set = shared.TopologyFor(layout.Layout);

pub const Quotient = Set.Quotient;
pub const FriLayer = Set.FriLayer;
pub const Fri = Set.Fri;
pub const TraceOpening = Set.TraceOpening;
pub const FriOpening = Set.FriOpening;
pub const Decommit = Set.Decommit;

test "XOR topology opens all three trace trees and eleven columns" {
    const std = @import("std");
    const geometry_mod = @import("geometry.zig");
    const pcs = @import("stwo_core").pcs;
    const allocator = std.testing.allocator;
    const geometry = try geometry_mod.admit(
        .{ .log_size = 16, .log_step = 3, .offset = 5 },
        pcs.PcsConfig.default(),
    );
    var logical = try layout.Layout.init(allocator, geometry);
    defer logical.deinit(allocator);
    var quotient = try Quotient.init(allocator, logical);
    defer quotient.deinit(allocator);
    var fri = try Fri.init(allocator, logical);
    defer fri.deinit(allocator);
    var decommit = try Decommit.init(allocator, logical);
    defer decommit.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 11), quotient.prepared_terms.len);
    try std.testing.expectEqual(@as(u32, 11), quotient.source_count);
    try std.testing.expectEqual(@as(usize, 16), fri.layers.len);
    try std.testing.expectEqual(@as(usize, 3), decommit.trace_trees.len);
    try std.testing.expectEqual(@as(usize, 16), decommit.fri_trees.len);
    try std.testing.expectEqual(@as(usize, 11), decommit.column_log_sizes.len);
    try std.testing.expectEqual(@as(u32, 0), decommit.trace_trees[0].tree_index);
    try std.testing.expectEqual(@as(u32, 1), decommit.trace_trees[1].tree_index);
    try std.testing.expectEqual(@as(u32, 2), decommit.trace_trees[2].tree_index);
}
