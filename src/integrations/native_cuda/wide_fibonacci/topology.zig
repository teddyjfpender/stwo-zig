//! Wide-Fibonacci aliases for shared uniform proof topology.

const std = @import("std");
const layout = @import("layout.zig");
const request = @import("request.zig");
const shared = @import("../common/uniform_topology.zig");

const Set = shared.TopologyFor(layout.Layout);

pub const Quotient = Set.Quotient;
pub const FriLayer = Set.FriLayer;
pub const Fri = Set.Fri;
pub const TraceOpening = Set.TraceOpening;
pub const FriOpening = Set.FriOpening;
pub const Decommit = Set.Decommit;

test "sealed topologies cover quotient and every opened tree" {
    const allocator = std.testing.allocator;
    const geometry = try request.admit(.{
        .statement = .{ .log_n_rows = 14, .sequence_len = 100 },
        .protocol = .{
            .pow_bits = 10,
            .log_blowup_factor = 1,
            .log_last_layer_degree_bound = 0,
            .n_queries = 3,
            .fold_step = 1,
            .lifting_log_size = null,
        },
    });
    var logical = try layout.Layout.init(allocator, geometry);
    defer logical.deinit(allocator);
    var quotient = try Quotient.init(allocator, logical);
    defer quotient.deinit(allocator);
    var fri = try Fri.init(allocator, logical);
    defer fri.deinit(allocator);
    var decommit = try Decommit.init(allocator, logical);
    defer decommit.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 108), quotient.prepared_terms.len);
    try std.testing.expectEqual(@as(usize, 14), fri.layers.len);
    try std.testing.expectEqual(@as(usize, 2), decommit.trace_trees.len);
    try std.testing.expectEqual(@as(usize, 14), decommit.fri_trees.len);
    try std.testing.expectEqual(@as(usize, 108), decommit.column_log_sizes.len);
    try std.testing.expect(decommit.assembly_words > 8 + 16 * 16);
}
