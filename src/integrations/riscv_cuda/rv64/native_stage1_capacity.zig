//! CPU0-only local static admission, while all other request GPU work is
//! deferred until the early helper joins. This is not whole-request admission
//! and does not establish the 28 GB driver-inclusive process peak.
const std = @import("std");
const A = @import("global_admission.zig");
const S = @import("admission_runtime.zig").Snapshot;
const Cost = @import("native_source_cost.zig");
pub const Envelope = struct {
    required: A.Footprint,
    capacity: A.Footprint,
    retained_ceiling: A.Footprint,
    largest_allocation: u64,
};
/// Snapshot must be obtained on the exact native owner, after previous request
/// teardown and before the first early Source allocation. No admission waits
/// occur inside the GPU callback. Count every prior physical owner as live.
pub fn assess(snapshot: S, device: u32, byte_cap: u64, plan: *const Cost.Plan) !Envelope {
    if (snapshot.version != 1 or snapshot.device != device or snapshot.chunk != A.chunk_bytes or snapshot.small_slab != A.small_slab_bytes or byte_cap == 0 or snapshot.free_device > snapshot.total_device) return error.InvalidEarlyStageSnapshot;
    const cap = @min(snapshot.capacity, byte_cap);
    if (cap <= snapshot.small_slab) return error.InvalidEarlyStageCapacity;
    const capacity = A.Footprint{ .large = cap - snapshot.small_slab, .small = snapshot.small_slab };
    const required = try snapshot.footprint().add(plan.peak);
    if (!capacity.contains(required)) return error.EarlyStageClassExceedsCapacity;
    var largest: u64 = 0;
    for (plan.list()) |allocation| {
        const footprint = try A.Footprint.allocation(try std.math.mul(u64, allocation.words, 4));
        largest = @max(largest, footprint.large);
    }
    if (largest > snapshot.largest_virtual_free) return error.EarlyStageVirtualCapacityUnavailable;
    return .{ .required = required, .capacity = capacity, .retained_ceiling = try snapshot.footprint().add(plan.after_main), .largest_allocation = largest };
}
pub fn checkJoined(before: S, after: S, envelope: Envelope) !void {
    if (after.version != before.version or after.device != before.device or after.capacity != before.capacity or after.chunk != before.chunk or after.small_slab != before.small_slab) return error.EarlyStageArenaChanged;
    if (!envelope.retained_ceiling.contains(after.footprint())) return error.EarlyStageUnexpectedRetention;
}

test "local stage1 sums existing native retention with separately rounded class peak" {
    const snapshot = S{ .device = 2, .capacity = 22 << 30, .chunk = A.chunk_bytes, .small_slab = A.small_slab_bytes, .live_large = 3 * A.chunk_bytes, .live_small = 1024, .largest_virtual_free = 64 << 30, .free_device = 8 << 30, .total_device = 32 << 30 };
    var plan = Cost.Plan{ .binding = @splat(7), .trace = undefined, .peak = .{ .large = 5 * A.chunk_bytes, .small = 512 }, .after_main = .{ .large = A.chunk_bytes, .small = 0 } };
    const e = try assess(snapshot, 2, 24 << 30, &plan);
    try std.testing.expectEqual(@as(u64, 8 * A.chunk_bytes), e.required.large);
    try std.testing.expectEqual(@as(u64, 1536), e.required.small);
    try std.testing.expectEqual(@as(u64, (22 << 30) - A.small_slab_bytes), e.capacity.large);
    var after = snapshot;
    after.live_large += A.chunk_bytes;
    try checkJoined(snapshot, after, e);
    after.live_large += A.chunk_bytes;
    try std.testing.expectError(error.EarlyStageUnexpectedRetention, checkJoined(snapshot, after, e));
}
test "local stage1 rejects device geometry capacity and fragmented virtual address space before work" {
    var s = S{ .device = 0, .capacity = 22 << 30, .chunk = A.chunk_bytes, .small_slab = A.small_slab_bytes, .largest_virtual_free = 64 << 30, .free_device = 8 << 30, .total_device = 32 << 30 };
    var p = Cost.Plan{ .binding = @splat(7), .trace = undefined, .peak = .{ .large = A.chunk_bytes, .small = 512 } };
    try std.testing.expectError(error.InvalidEarlyStageSnapshot, assess(s, 1, 22 << 30, &p));
    try std.testing.expectError(error.InvalidEarlyStageCapacity, assess(s, 0, 1, &p));
    s.live_small = A.small_slab_bytes;
    try std.testing.expectError(error.EarlyStageClassExceedsCapacity, assess(s, 0, 22 << 30, &p));
    s.live_small = 0;
    s.live_large = (22 << 30) - A.small_slab_bytes;
    try std.testing.expectError(error.EarlyStageClassExceedsCapacity, assess(s, 0, 22 << 30, &p));
    s.live_large = 0;
    s.largest_virtual_free = A.chunk_bytes - 1;
    p.allocations[0] = .{ .owner = .core_output, .words = 1 << 20, .kind = 1, .release = .main_adopt_join };
    p.count = 1;
    try std.testing.expectError(error.EarlyStageVirtualCapacityUnavailable, assess(s, 0, 22 << 30, &p));
}
