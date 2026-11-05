//! Additive read-only physical arena observation, covering every context.
const std = @import("std");
const A = @import("global_admission.zig");
pub const Snapshot = extern struct {
    version: u32 = 1,
    device: u32 = 0,
    capacity: u64 = 0,
    chunk: u64 = 0,
    small_slab: u64 = 0,
    live_large: u64 = 0,
    live_small: u64 = 0,
    largest_virtual_free: u64 = 0,
    free_device: u64 = 0,
    total_device: u64 = 0,
    pub fn available(self: Snapshot) !A.Footprint {
        if (self.version != 1 or self.chunk != A.chunk_bytes or self.small_slab != A.small_slab_bytes or self.capacity < self.small_slab or self.live_large > self.capacity - self.small_slab or self.live_small > self.small_slab) return error.InvalidPhysicalArenaSnapshot;
        return .{ .large = self.capacity - self.small_slab - self.live_large, .small = self.small_slab - self.live_small };
    }
};
comptime {
    if (@sizeOf(Snapshot) != 72) @compileError("physical snapshot ABI");
}
pub fn query(lib: *std.DynLib, raw: *anyopaque) !Snapshot {
    const Query = *const fn (*anyopaque, *Snapshot) callconv(.c) c_int;
    const call = lib.lookup(Query, "stwo_exec_context_arena_snapshot_v1") orelse return error.MissingWorkspaceArenaObservation;
    var result: Snapshot = .{};
    if (call(raw, &result) != 0) return error.PhysicalArenaObservationFailed;
    _ = try result.available();
    return result;
}
