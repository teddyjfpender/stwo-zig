//! Exact R6 source-column/padding census, not runtime or RSS prediction.
//! Includes FIXED/MAIN/INTER, excluding LDE, composition, scratch and setup.
const std = @import("std");
const C = @import("../../rv64_recursion/om31_poseidon/common.zig");
const L = @import("../layout.zig");
const Mul = @import("../native_omul/row.zig");
pub const Model = struct {
    raw: [6]usize,
    rows: [6]usize,
    logs: [6]u32,
    fixed_cells: u64 = 0,
    main_cells: u64 = 0,
    interaction_cells: u64 = 0,
    total_cells: u64 = 0,
    pub fn derive(owner: *const C.PoseidonContext) !Model {
        const raw = try owner.rawCounts();
        var out = Model{ .raw = undefined, .rows = undefined, .logs = undefined };
        for (raw, out.raw[0..5]) |n, *value| value.* = std.math.cast(usize, n) orelse return error.NativeGroupGeometry;
        out.raw[5] = owner.native_mul_calls.items.len;
        for (out.raw, &out.rows, &out.logs, 0..) |n, *rows, *log, role| {
            rows.* = try std.math.ceilPowerOfTwo(usize, @max(if (role == 4) @as(usize, 1) << 16 else 16, n));
            log.* = std.math.cast(u32, std.math.log2_int(usize, rows.*)) orelse return error.NativeGroupGeometry;
        }
        try out.countCells();
        return out;
    }
    pub fn fromKey(key: *const @import("../native_omul/authority.zig").Key) !Model {
        var out = Model{ .raw = undefined, .rows = undefined, .logs = undefined };
        @memcpy(out.raw[0..5], &key.base.raw);
        @memcpy(out.rows[0..5], &key.base.rows);
        @memcpy(out.logs[0..5], &key.base.logs);
        out.raw[5] = key.mul_raw;
        out.rows[5] = key.mul_rows;
        out.logs[5] = key.mul_log;
        try out.countCells();
        return out;
    }
    fn countCells(out: *Model) !void {
        const fixed = [_]u32{ L.FACTS[0].fixed, L.FACTS[1].fixed, L.FACTS[2].fixed, L.FACTS[3].fixed, L.FACTS[4].fixed, Mul.FIXED };
        const main = [_]u32{ L.FACTS[0].main, L.FACTS[1].main, L.FACTS[2].main, L.FACTS[3].main, L.FACTS[4].main, Mul.MAIN };
        const interaction = [_]u32{ L.FACTS[0].classic_interaction, L.FACTS[1].classic_interaction, L.FACTS[2].classic_interaction, L.FACTS[3].classic_interaction, L.FACTS[4].classic_interaction, Mul.INTER };
        for (out.rows, fixed, main, interaction) |rows, f, m, i| {
            out.fixed_cells = try std.math.add(u64, out.fixed_cells, try std.math.mul(u64, rows, f));
            out.main_cells = try std.math.add(u64, out.main_cells, try std.math.mul(u64, rows, m));
            out.interaction_cells = try std.math.add(u64, out.interaction_cells, try std.math.mul(u64, rows, i));
        }
        out.total_cells = try std.math.add(u64, out.fixed_cells, try std.math.add(u64, out.main_cells, out.interaction_cells));
    }
};
