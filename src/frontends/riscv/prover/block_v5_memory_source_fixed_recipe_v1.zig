//! Shared exact fixed recipe. The schedule is a typed independent grammar,
//! never selected from committed private cells or caller descriptors.
const std = @import("std");
const Source = @import("block_v5_memory_source_auth_protocol_v1.zig");
const M = @import("stwo_core").fields.m31.M31;
pub const FIXED = struct {
    pub const active = 0;
    pub const physical_ordinal = 1; // four LE16 limbs
    pub const kind = 5;
    pub const stream_or_edit = 6;
    pub const local_ordinal = 7; // four LE16 limbs
    pub const height = 11;
    pub const first = 12;
    pub const last = 13;
    pub const domain_last = 14;
};
fn putLimbs(out: []M, value: u64) void {
    for (out, 0..) |*v, i| v.* = M.fromCanonical(@intCast((value >> @intCast(16 * i)) & 65535));
}
pub fn ForSchedule(comptime Schedule: type) type {
    return struct {
        pub fn fixedAt(admitted: *const Source.Admitted, page: anytype, logical: usize) ![15]M {
            if (page.row_log < 1 or page.row_log > 12) return error.InvalidSourceFirstRow;
            const size = @as(usize, 1) << @intCast(page.row_log);
            if (page.chunks == 0 or page.chunks > size) return error.InvalidSourceFirstRow;
            if (logical >= size) return error.InvalidSourceFirstRow;
            var cells: [15]M = @splat(M.zero());
            cells[FIXED.domain_last] = M.fromCanonical(@intFromBool(logical + 1 == size));
            if (logical >= page.chunks) return cells;
            cells[FIXED.active] = M.one();
            cells[FIXED.first] = M.fromCanonical(@intFromBool(logical == 0));
            cells[FIXED.last] = M.fromCanonical(@intFromBool(logical + 1 == page.chunks));
            const index = std.math.add(u64, page.first_chunk, logical) catch return error.InvalidSourceFirstRow;
            putLimbs(cells[FIXED.physical_ordinal..][0..4], index);
            switch (try Schedule.kindAt(admitted, index)) {
                .sha => |v| {
                    cells[FIXED.kind] = M.fromCanonical(1);
                    cells[FIXED.stream_or_edit] = M.fromCanonical(@intFromEnum(v.stream));
                    putLimbs(cells[FIXED.local_ordinal..][0..4], v.block);
                },
                .record => |v| {
                    cells[FIXED.kind] = M.fromCanonical(2);
                    cells[FIXED.stream_or_edit] = M.fromCanonical(@intFromEnum(v.stream));
                    putLimbs(cells[FIXED.local_ordinal..][0..4], v.ordinal);
                },
                .leaf => |v| {
                    cells[FIXED.kind] = M.fromCanonical(3);
                    cells[FIXED.stream_or_edit] = M.fromCanonical(@intFromEnum(v.edit));
                    putLimbs(cells[FIXED.local_ordinal..][0..4], v.ordinal);
                },
                .node => |v| {
                    cells[FIXED.kind] = M.fromCanonical(4);
                    cells[FIXED.stream_or_edit] = M.fromCanonical(@intFromEnum(v.edit));
                    putLimbs(cells[FIXED.local_ordinal..][0..4], v.ordinal);
                    cells[FIXED.height] = M.fromCanonical(v.height);
                },
                .root => |v| {
                    cells[FIXED.kind] = M.fromCanonical(5);
                    cells[FIXED.stream_or_edit] = M.fromCanonical(@intFromEnum(v.edit));
                    putLimbs(cells[FIXED.local_ordinal..][0..4], v.ordinal);
                },
            }
            return cells;
        }
    };
}
