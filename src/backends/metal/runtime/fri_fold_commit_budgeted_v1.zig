//! Allocator-bearing ownership for the existing folded-tree transaction.
const std = @import("std");
const runtime = @import("../runtime.zig");
const ffi = @import("bindings.zig");
const protocol = @import("protocol_mode.zig");
pub fn foldFriLineAndCommitForHash(a: std.mem.Allocator, self: *runtime.Runtime, source: *anyopaque, count: u32, inverse: []const u32, alphas: []const [4]u32, destination: *anyopaque, coordinates: *anyopaque, leaf_seed: [8]u32, node_seed: [8]u32, prefix: u32, family: u32) !runtime.FriFoldCommitResult {
    return foldFriLineAndCommitForHashWithPolicy(a, self, source, count, inverse, alphas, destination, coordinates, leaf_seed, node_seed, prefix, family, .require_shared_budget);
}
pub fn foldFriLineAndCommitForHashWithPolicy(a: std.mem.Allocator, self: *runtime.Runtime, source: *anyopaque, count: u32, inverse: []const u32, alphas: []const [4]u32, destination: *anyopaque, coordinates: *anyopaque, leaf_seed: [8]u32, node_seed: [8]u32, prefix: u32, family: u32, policy: @import("fri_allocation_policy_v1.zig").Policy) !runtime.FriFoldCommitResult {
    const binding = try @import("fri_allocation_policy_v1.zig").Binding.init(a, policy);
    const extents = @import("fri_budget_v1.zig");
    const inverse_count = try extents.inverseCount(count, alphas.len);
    if (inverse.len != inverse_count or !protocol.validDomainPrefixBytes(prefix) or (family < 1 or family > 3)) return error.InvalidFriBudgetGeometry;
    const extent = try extents.foldedCommit(count, alphas.len);
    var reservation = try binding.reserve(extent.peak_bytes);
    defer reservation.deinit();
    var stats: runtime.CommandEpochStats = undefined;
    var message: [1024]u8 = @splat(0);
    const handle = ffi.stwo_zig_metal_fri_fold_line_and_commit(self.handle, source, count, inverse.ptr, @intCast(inverse.len), @ptrCast(alphas.ptr), @intCast(alphas.len), destination, coordinates, &leaf_seed, &node_seed, prefix, family, &stats, &message, message.len) orelse return error.FriFoldCommitFailed;
    errdefer @import("resident_data.zig").stwo_zig_metal_tree_destroy(handle);
    try reservation.resize(extent.retained_bytes);
    return .{ .stats = stats, .tree = .{ .handle = handle, .runtime_handle = self.handle, .log_size = std.math.log2_int(u32, count >> @intCast(alphas.len)), .external_reservation = reservation.take() } };
}
