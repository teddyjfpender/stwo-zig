//! Checked request region accounting. Pure word units; no GPU/runtime imports.
const std = @import("std");

pub fn addWords(a: u64, b: u64) error{ResourceSizeOverflow}!u64 {
    return std.math.add(u64, a, b) catch error.ResourceSizeOverflow;
}

pub fn alignedWords(words: u64) error{ResourceSizeOverflow}!u64 {
    const granule = @import("resources.zig").granule_words;
    return (try addWords(words, granule - 1)) & ~@as(u64, granule - 1);
}

/// One GPU's sequential MAIN allocation schedule. A failed reservation does
/// not advance the cursor. Budget checks and request views use this owner.
pub const MainCursor = struct {
    words: u64 = 0,
    pub const View = struct { offset: u64, words: u64 };
    pub fn take(self: *MainCursor, capacity: u64, requested: u64) !View {
        const words = try alignedWords(requested);
        const end = try addWords(self.words, words);
        if (end > capacity) return error.GpuNativeMainResidentOverflow;
        const view = View{ .offset = self.words, .words = words };
        self.words = end;
        return view;
    }
};

pub const RegionKind = enum(u8) {
    class_cache, // per-class constants (twiddles, FIXED trees, tapes): install-time
    graph_exec, // captured graph executables (driver budget)
    main_resident, // MAIN coefficients/trees of every segment on this GPU, witness -> PCS
    arena, // two-sided job arena (worker): one job in flight + one staged
    truth, // truth-job working set (inside the plan, never a lease)
    exchange_slab, // request slab segment + its pinned mirror size
    reserve, // driver/CUDA headroom
};

pub const Region = struct { kind: RegionKind, words: u64 };

/// Every request-path allocation comes from one of these regions; nothing on
/// the request path calls cudaMalloc outside them (`outside_words` == 0 is a
/// plan invariant the worker enforces).
pub const MemoryPlan = struct {
    device: u32,
    capacity_words: u64,
    regions: [std.meta.fields(RegionKind).len]u64 = @splat(0),

    pub fn set(self: *MemoryPlan, kind: RegionKind, words: u64) void {
        self.regions[@intFromEnum(kind)] = words;
    }
    pub fn get(self: *const MemoryPlan, kind: RegionKind) u64 {
        return self.regions[@intFromEnum(kind)];
    }
    pub fn total(self: *const MemoryPlan) error{ResourceSizeOverflow}!u64 {
        var n: u64 = 0;
        for (self.regions) |w| n = try addWords(n, w);
        return n;
    }
    pub fn validate(self: *const MemoryPlan) !void {
        const words = try self.total();
        _ = std.math.mul(u64, words, @sizeOf(u32)) catch return error.ResourceSizeOverflow;
        if (words > self.capacity_words) return error.GpuNativeMemoryPlanExceedsDevice;
        if (self.get(.arena) == 0) return error.GpuNativeMemoryPlanNoArena;
        if (self.get(.exchange_slab) == 0) return error.GpuNativeMemoryPlanNoSlab;
    }
    /// Region base offsets in a fixed order (class cache lowest: it outlives
    /// requests; arena last: it may grow into the reserve at install).
    pub fn offset(self: *const MemoryPlan, kind: RegionKind) error{ResourceSizeOverflow}!u64 {
        var at: u64 = 0;
        for (0..@intFromEnum(kind)) |k| at = try addWords(at, self.regions[k]);
        return at;
    }
};

test "region totals and offsets refuse wrapping word or byte sizes" {
    var p = MemoryPlan{ .device = 0, .capacity_words = std.math.maxInt(u64) };
    p.set(.arena, 1);
    p.set(.exchange_slab, 64);
    p.set(.class_cache, std.math.maxInt(u64));
    try std.testing.expectError(error.ResourceSizeOverflow, p.total());
    try std.testing.expectError(error.ResourceSizeOverflow, p.validate());
    p.set(.graph_exec, 64);
    try std.testing.expectError(error.ResourceSizeOverflow, p.offset(.arena));
    p.set(.class_cache, std.math.maxInt(u64) / 4);
    try std.testing.expectError(error.ResourceSizeOverflow, p.validate());
}

test "MAIN schedule refuses a reservation without consuming its capacity" {
    var cursor = MainCursor{};
    const first = try cursor.take(192, 1);
    try std.testing.expectEqual(MainCursor.View{ .offset = 0, .words = 64 }, first);
    try std.testing.expectError(error.GpuNativeMainResidentOverflow, cursor.take(192, 129));
    try std.testing.expectError(error.ResourceSizeOverflow, cursor.take(192, std.math.maxInt(u64)));
    const second = try cursor.take(192, 128);
    try std.testing.expectEqual(MainCursor.View{ .offset = 64, .words = 128 }, second);
}
