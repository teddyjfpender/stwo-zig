//! Pure envelope for ONLY the joined traversal callback. Original MAIN/FIXED,
//! classic INTER, projector parameters/status and twiddles must already be
//! physically observed. This cannot authorize classic preparation or binding.
const std = @import("std");
const G = @import("gkr.zig");
pub const Cost = struct {
    allocation_bytes: [2]u64,
    host_peak_bytes: u64,
    host_known: bool = true,
    covers_classic_preparation: bool = false,
    covers_binding_and_commit: bool = false,
};
/// Limits match the source-owned numerical ABI. Readback records, masks,
/// assembly and CPU replay are all bounded by this shape; no N-sized host
/// fraction/tree/Eq array is created by either current traversal mode.
pub fn traversal(variables: []const u32, mode: G.Mode) !Cost {
    const plan = try G.Plan.initMode(variables, std.math.maxInt(usize), mode);
    var readback: u64 = try std.math.mul(u64, 16 * variables.len, 4);
    for (plan.layer[0..plan.layers]) |layer| readback = try std.math.add(u64, readback, try std.math.mul(u64, 4, layer.records.words + layer.masks.words));
    // Includes a generous fixed bound for nested proof assembly, shape arrays,
    // polynomial views and CPU verifier artifacts, on top of raw D2H slabs.
    const host = try std.math.add(u64, 16 << 20, try std.math.mul(u64, 16, readback));
    return .{ .allocation_bytes = .{ try std.math.mul(u64, 4, plan.total_words), 9 * 4 }, .host_peak_bytes = host };
}
test "traversal admission keeps actual allocations separate and never claims neighboring stages" {
    const a = try traversal(&.{ 23, 22, 23, 21, 27, 26, 24, 24 }, .recomputed_frontier);
    try std.testing.expectEqual(@as(u64, 15046661376), a.allocation_bytes[0]);
    try std.testing.expectEqual(@as(u64, 36), a.allocation_bytes[1]);
    try std.testing.expect(a.host_known and a.host_peak_bytes < 64 << 20);
    try std.testing.expect(!a.covers_classic_preparation and !a.covers_binding_and_commit);
    const b = try traversal(&([_]u32{28} ** G.max_instances), .retained_tree);
    try std.testing.expect(b.host_peak_bytes < 64 << 20);
}
