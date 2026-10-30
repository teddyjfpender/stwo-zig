//! Execution-storage policy only. This is absent from every statement, key and
//! transcript: both alternatives evaluate exactly the same original RAM AIR.
//! The request allocator remains the aggregate authority across all phases.
const std = @import("std");
const Tiles = @import("block_v7_word_quotient_tiles_v1.zig");
pub const Bounded = struct {
    /// The measured crossover experiment starts at trace log 18. Lowering this
    /// is explicit (for correctness fixtures or another machine's measurements).
    minimum_trace_log: u32 = 18,
    tile_log: u32 = 15,
    factor_range_pairs: bool = false,
    base_field_rows: bool = true,
    retained_large_tile_log: u32 = 18,
    /// Maximum prefold cache per current/prior owner. Small cohorts use a
    /// quarter (through log18) or half (log19); log20 uses the full target.
    group_bytes: usize = 128 << 20,
    /// Large-domain upper target. The planner minimizes coefficient reads
    /// within this capacity; it need not consume the full target. Actual
    /// caches are clamped after recovery.
    large_group_bytes: usize = 1 << 30,
    max_workspace_bytes: usize = 4 << 30,
};
pub const Policy = union(enum) {
    whole_domain,
    bounded_tiles: Bounded,
    pub fn validate(self: Policy) !void {
        switch (self) {
            .whole_domain => {},
            .bounded_tiles => |p| {
                if (p.minimum_trace_log < 4 or p.minimum_trace_log > 24 or p.tile_log < 3 or p.tile_log > 23 or p.retained_large_tile_log < p.tile_log or p.retained_large_tile_log > 23 or p.max_workspace_bytes == 0 or p.group_bytes > p.max_workspace_bytes or p.large_group_bytes > p.max_workspace_bytes) return error.InvalidV7RamQuotientPolicy;
            },
        }
    }
    /// Scratch is a child allocation scope, never extra memory outside the
    /// request's cap. A selected kernel fails closed if its actual storage does
    /// not fit; it does not fall back to an unbounded full-domain expansion.
    pub fn select(self: Policy, trace_log: u32, request_cap: usize) !?Tiles.Options {
        try self.validate();
        if (trace_log < 4 or trace_log > 24 or request_cap == 0) return error.InvalidV7RamQuotientPolicy;
        return switch (self) {
            .whole_domain => null,
            .bounded_tiles => |p| if (trace_log < p.minimum_trace_log) null else .{
                .tile_log = p.tile_log,
                .base_field_rows = p.base_field_rows,
                .factor_range_pairs = p.factor_range_pairs,
                .retained_tile_log = if (trace_log >= 22) p.retained_large_tile_log else null,
                .group_bytes = @min(if (trace_log >= 22) p.large_group_bytes else if (trace_log == 21) p.large_group_bytes / 2 else p.group_bytes >> @as(std.math.Log2Int(usize), @intCast(@min(@as(u32, 2), 20 -| trace_log))), request_cap),
                .max_workspace_bytes = @min(p.max_workspace_bytes, request_cap),
            },
        };
    }
};
test "v7 RAM tiled policy bounds automatic selection without changing small domains" {
    const selected: Policy = .{ .bounded_tiles = .{} };
    try std.testing.expect((try selected.select(17, 8 << 30)) == null);
    const large = (try selected.select(18, 8 << 30)).?;
    try std.testing.expect(large.base_field_rows);
    try std.testing.expectEqual(@as(usize, 4 << 30), large.max_workspace_bytes);
    try std.testing.expectEqual(@as(usize, 32 << 20), large.group_bytes);
    try std.testing.expectEqual(@as(usize, 64 << 20), (try selected.select(19, 8 << 30)).?.group_bytes);
    try std.testing.expectEqual(@as(usize, 128 << 20), (try selected.select(20, 8 << 30)).?.group_bytes);
    try std.testing.expectEqual(@as(usize, 512 << 20), (try selected.select(21, 8 << 30)).?.group_bytes);
    try std.testing.expectEqual(@as(usize, 1 << 30), (try selected.select(22, 8 << 30)).?.group_bytes);
    try std.testing.expect((try selected.select(21, 8 << 30)).?.retained_tile_log == null);
    try std.testing.expectEqual(@as(?u32, 18), (try selected.select(22, 8 << 30)).?.retained_tile_log);
    try std.testing.expectEqual(@as(usize, 64 << 20), (try selected.select(22, 64 << 20)).?.max_workspace_bytes);
    try std.testing.expect((try (@as(Policy, .whole_domain)).select(24, 1)) == null);
    try std.testing.expectError(error.InvalidV7RamQuotientPolicy, selected.select(25, 8 << 30));
    try std.testing.expectError(error.InvalidV7RamQuotientPolicy, selected.select(18, 0));
    try std.testing.expectError(error.InvalidV7RamQuotientPolicy, (Policy{ .bounded_tiles = .{ .minimum_trace_log = 3 } }).validate());
    try std.testing.expectError(error.InvalidV7RamQuotientPolicy, (Policy{ .bounded_tiles = .{ .group_bytes = 2, .max_workspace_bytes = 1 } }).validate());
}
