//! Complete source-row geometry only; no proof or witness acceptance authority.
const std = @import("std");
const L = @import("../layout.zig");
const R = @import("row.zig");
pub const Census = struct {
    raw: [6]u64,
    rows: [6]usize,
    logs: [6]u32,
    main_cells: u64 = 0,
    interaction_cells: u64 = 0,
    fixed_cells: u64 = 0,
    total_native_cells: u64 = 0,
};
pub fn derive(raw: [5]u64, native_calls: usize) !Census {
    var out: Census = .{ .raw = undefined, .rows = undefined, .logs = undefined };
    @memcpy(out.raw[0..5], &raw);
    out.raw[5] = native_calls;
    for (out.raw, 0..) |n, i| {
        out.rows[i] = try std.math.ceilPowerOfTwo(usize, @max(if (i == 4) @as(usize, 65536) else 16, std.math.cast(usize, n) orelse return error.InvalidR6Geometry));
        out.logs[i] = @intCast(std.math.log2_int(usize, out.rows[i]));
        const main = if (i == 5) R.MAIN else L.FACTS[i].main;
        const inter = if (i == 5) R.INTER else L.FACTS[i].classic_interaction;
        const fixed = if (i == 5) R.FIXED else L.FACTS[i].fixed;
        out.main_cells = try std.math.add(u64, out.main_cells, try std.math.mul(u64, out.rows[i], main));
        out.interaction_cells = try std.math.add(u64, out.interaction_cells, try std.math.mul(u64, out.rows[i], inter));
        out.fixed_cells = try std.math.add(u64, out.fixed_cells, try std.math.mul(u64, out.rows[i], fixed));
    }
    out.total_native_cells = try std.math.add(u64, out.fixed_cells, try std.math.add(u64, out.main_cells, out.interaction_cells));
    return out;
}
