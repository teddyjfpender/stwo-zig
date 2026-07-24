//! Native Poseidon aliases for the shared uniform proof topology.

const layout = @import("layout.zig");
const shared = @import("../common/uniform_topology.zig");

const Set = shared.TopologyFor(layout.Layout);

pub const Quotient = Set.Quotient;
pub const FriLayer = Set.FriLayer;
pub const Fri = Set.Fri;
pub const TraceOpening = Set.TraceOpening;
pub const FriOpening = Set.FriOpening;
pub const Decommit = Set.Decommit;

test "Poseidon topology opens main composition and every FRI tree" {
    const std = @import("std");
    const geometry_mod = @import("geometry.zig");
    const pcs = @import("stwo_core").pcs;
    const allocator = std.testing.allocator;
    const geometry = try geometry_mod.admit(
        .{ .log_n_instances = 13 },
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

    try std.testing.expectEqual(
        @as(usize, 1272),
        quotient.prepared_terms.len,
    );
    try std.testing.expectEqual(@as(u32, 1272), quotient.source_count);
    try std.testing.expectEqual(@as(usize, 10), fri.layers.len);
    try std.testing.expectEqual(
        @as(usize, 2),
        decommit.trace_trees.len,
    );
    try std.testing.expectEqual(
        @as(usize, 10),
        decommit.fri_trees.len,
    );
    try std.testing.expectEqual(
        @as(usize, 1272),
        decommit.column_log_sizes.len,
    );
    try std.testing.expectEqual(
        @as(u32, 0),
        decommit.trace_trees[0].tree_index,
    );
    try std.testing.expectEqual(
        @as(u32, 1),
        decommit.trace_trees[1].tree_index,
    );
}
