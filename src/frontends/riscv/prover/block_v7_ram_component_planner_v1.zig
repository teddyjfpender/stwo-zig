//! Recursion-aware RAM sizing. This selects geometry only; the original
//! independently admitted RAM equations, counts, transcript and PCS stay exact.
//! Larger components amortize verifier columns/openings, subject to explicit
//! row and per-matrix limits. The legacy fixed-shard route remains explicit.
const std = @import("std");
const Limits = @import("block_v7_memory_bundle_v1.zig").Limits;
pub const Policy = struct {
    target_components: u32 = 4,
    minimum_events: u32 = 1 << 15,
    maximum_events: u32 = 1 << 20,
    pub fn validate(self: Policy) !void {
        if (self.target_components == 0 or self.target_components > 4096 or self.minimum_events == 0 or self.maximum_events < self.minimum_events or self.maximum_events > 1 << 24 or !std.math.isPowerOfTwo(self.minimum_events) or !std.math.isPowerOfTwo(self.maximum_events)) return error.InvalidRamComponentPlanningPolicy;
    }
};
pub const Plan = struct {
    events: u32,
    events_per_component: u32,
    components: u32,
    padded_rows: u64,
    main_cells: u64,
    fixed_cells: u64,
    interaction_cells: u64,
    private_opening_columns: u64,
};
pub fn fixed(events: u32, per: u32) !Plan {
    if (per == 0) return error.InvalidRamComponentPlanningPolicy;
    const count = try std.math.divCeil(u32, events, per);
    var rows: u64 = 0;
    var remaining = events;
    for (0..count) |_| {
        const active = @min(remaining, per);
        const logical = try std.math.divCeil(u32, active, 2);
        const log = @max(@as(u5, 4), std.math.log2_int_ceil(u32, logical));
        rows = try std.math.add(u64, rows, @as(u64, 1) << log);
        remaining -= active;
    }
    return .{ .events = events, .events_per_component = per, .components = count, .padded_rows = rows, .main_cells = try std.math.mul(u64, rows, 88), .fixed_cells = try std.math.mul(u64, rows, 24), .interaction_cells = try std.math.mul(u64, rows, 124), .private_opening_columns = try std.math.mul(u64, count, 88 + 124) };
}
pub fn select(events: u32, policy: Policy, limits: Limits) !Plan {
    try policy.validate();
    if (events > limits.max_events or limits.max_row_log < 4 or limits.max_row_log > 24 or limits.max_matrix_bytes < 16 * 124 * 4) return error.RamComponentPlanningResourceLimit;
    // Both main/fixed witness storage and the larger interaction matrix must
    // fit. This is a geometry admission, not a claim about total process RSS.
    const matrix_rows = limits.max_matrix_bytes / (124 * 4);
    const matrix_log = std.math.log2_int(usize, matrix_rows);
    const max_log = @min(limits.max_row_log, matrix_log);
    const row_cap: u64 = @as(u64, 1) << @intCast(max_log);
    const event_cap: u32 = @intCast(@min(@as(u64, policy.maximum_events), row_cap * 2));
    if (event_cap < policy.minimum_events) return error.RamComponentPlanningResourceLimit;
    const wanted = @max(policy.minimum_events, try std.math.divCeil(u32, events, policy.target_components));
    const log = std.math.log2_int_ceil(u32, wanted);
    const candidate: u64 = @as(u64, 1) << log;
    const per: u32 = @intCast(@min(candidate, event_cap));
    const out = try fixed(events, per);
    if (out.components > limits.max_shards) return error.RamComponentPlanningResourceLimit;
    return out;
}
