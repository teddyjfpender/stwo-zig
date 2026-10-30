//! Cold-row admission model for CPU parent proving. This is a conservative
//! planning estimate, not a formal bound on every backend allocation. A shared
//! request allocator cap remains mandatory. Shared pool owners are charged
//! separately to their backing budget; neither counter bounds process RSS.
//! Record child/outer charged peaks and whole-process measurements separately.
const std = @import("std");
const core = @import("stwo_core");
const Storage = @import("air/blake3_parent_row_storage.zig");
const Schema = @import("../air/lookups/tables/schema.zig");
pub const Limits = struct {
    max_row_log: u32 = 25,
    max_retained_bytes: usize = 4 << 30,
    max_planned_bytes: usize = 24 << 30,
    scratch_headroom_bytes: usize = 512 << 20,
};
pub const Estimate = struct {
    largest_row_log: u32,
    fixed_bytes: usize,
    retained_rows_bytes: usize,
    committed_cells: usize,
    planned_peak_bytes: usize,
    pub fn require(self: Estimate, limits: Limits) !void {
        if (limits.max_row_log == 0 or limits.max_row_log > 25 or limits.max_retained_bytes == 0 or limits.max_planned_bytes == 0) return error.InvalidParentResourceLimits;
        if (self.largest_row_log > limits.max_row_log or self.retained_rows_bytes > limits.max_retained_bytes or self.planned_peak_bytes > limits.max_planned_bytes) return error.ParentWindowResourceLimit;
    }
};
fn add(a: usize, b: usize) !usize {
    return std.math.add(usize, a, b);
}
fn mul(a: usize, b: usize) !usize {
    return std.math.mul(usize, a, b);
}
fn domain(log: u32) !usize {
    if (log > 30) return error.ParentWindowResourceLimit;
    return @as(usize, 1) << @intCast(log);
}
pub fn estimate(fixed: Storage.FixedTuple(false), config: core.pcs.PcsConfig, limits: Limits) !Estimate {
    const logs = try @import("blake3_parent_fixed_key_v1.zig").rowLogs(fixed);
    var largest: u32 = 1;
    var fixed_bytes: usize = 0;
    var retained: usize = 0;
    var cells: usize = 0;
    inline for (Storage.Airs, 0..) |Air, i| {
        const n = try domain(logs[i]);
        largest = @max(largest, logs[i]);
        fixed_bytes = try add(fixed_bytes, try mul(fixed[i].len, @sizeOf(Storage.FixedRow(Air))));
        retained = try add(retained, try mul(n, 4 * Air.PHYSICAL_MAIN_COLUMN_COUNT));
        cells = try add(cells, try mul(n, Air.PREPROCESSED_COLUMN_COUNT + Air.PHYSICAL_MAIN_COLUMN_COUNT + Air.INTERACTION_COLUMN_COUNT));
    }
    retained = try add(retained, fixed_bytes);
    // Same two provider tables the original parent actually commits.
    for ([_]Schema.Kind{ .bitwise, .range_check_8_8 }) |kind| {
        const log = Schema.logSize(kind);
        largest = @max(largest, log);
        cells = try add(cells, try mul(try domain(log), 1 + Schema.arity(kind) + 1 + 4));
    }
    const blowup = config.fri_config.log_blowup_factor;
    const expanded = try mul(cells, try domain(blowup));
    // Three original trees retain extended values plus coefficients/workspace;
    // composition/FRI and Merkle buffers use deliberately explicit headroom.
    const pcs = try mul(4, try add(expanded, try mul(cells, 2)));
    const query_domain = try domain(try std.math.add(u32, largest, blowup));
    const trees = try mul(query_domain, 4 * 64);
    const composition = try mul(try domain(try std.math.add(u32, largest, 2)), 16 * 8);
    const joining = try add(try mul(retained, 2), fixed_bytes);
    const planned = try add(try add(joining, pcs), try add(try add(trees, composition), limits.scratch_headroom_bytes));
    return .{ .largest_row_log = largest, .fixed_bytes = fixed_bytes, .retained_rows_bytes = retained, .committed_cells = cells, .planned_peak_bytes = planned };
}
test "parent resource model has nonzero provider floor and rejects undersized cap" {
    var fixed: Storage.FixedTuple(false) = undefined;
    inline for (0..Storage.Airs.len) |i| fixed[i] = &.{};
    const e = try estimate(fixed, @import("blake3_execution_parent_protocol.zig").Profile.diagnostic_q8_pow0.config(), .{});
    try std.testing.expect(e.committed_cells > 0);
    try std.testing.expect(e.planned_peak_bytes > 512 << 20);
    try std.testing.expectError(error.ParentWindowResourceLimit, e.require(.{ .max_planned_bytes = 1 }));
    try std.testing.expectError(error.InvalidParentResourceLimits, e.require(.{ .max_row_log = 0 }));
}
