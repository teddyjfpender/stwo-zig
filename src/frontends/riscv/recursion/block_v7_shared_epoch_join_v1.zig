//! One allocation per output column for isolated children plus canonical
//! cross-namespace bridges. The caller constructs bridge rows independently;
//! this transport is not key admission or proof authority.
const std = @import("std");
const core = @import("stwo_core");
const Storage = @import("air/blake3_parent_row_storage.zig");
const Join = @import("air/blake3_parent_join.zig");
const Namespace = @import("air/blake3_parent_namespace.zig");
pub fn concatenate(a: std.mem.Allocator, sources: []const *Storage.Prepared, ranges: []const Join.Range, bridges: *Storage.Prepared) !Storage.Prepared {
    if (sources.len < 2 or sources.len > 65 or sources.len != ranges.len) return error.InvalidSharedEpochJoin;
    var owners: [66]*Storage.Prepared = undefined;
    var counts: [Storage.Airs.len]usize = @splat(0);
    var input_count: usize = 0;
    for (sources, ranges, 0..) |source, range, i| {
        if (range.first == 0 or range.first >= range.end or range.end >= core.fields.m31.Modulus or source == bridges) return error.InvalidSharedEpochJoin;
        if (i > 0 and ranges[i - 1].end != range.first) return error.InvalidSharedEpochJoin;
        try Join.validateColumns(source);
        try Namespace.rejectRange(source, 0, range.first);
        try Namespace.rejectRange(source, range.end, core.fields.m31.Modulus);
        for (sources[0..i]) |previous| if (previous == source) return error.InvalidSharedEpochJoin;
        owners[i] = source;
    }
    try Join.validateColumns(bridges);
    try Namespace.rejectRange(bridges, 0, ranges[0].first);
    try Namespace.rejectRange(bridges, ranges[ranges.len - 1].end, core.fields.m31.Modulus);
    owners[sources.len] = bridges;
    const all = owners[0 .. sources.len + 1];
    for (all) |owner| {
        input_count = try std.math.add(usize, input_count, owner.input_count);
        inline for (0..Storage.Airs.len) |slot| {
            counts[slot] = try std.math.add(usize, counts[slot], owner.fixed[slot].len);
            if (counts[slot] > 1 << 25) return error.SharedEpochResourceLimit;
        }
    }
    var result = Storage.Prepared{ .allocator = a, .main = @splat(&.{}), .fixed = undefined, .input_count = input_count };
    inline for (0..Storage.Airs.len) |slot| result.fixed[slot] = &.{};
    errdefer result.deinit();
    inline for (Storage.Airs, 0..) |Air, slot| {
        const log: u32 = if (counts[slot] <= 1) 1 else std.math.log2_int_ceil(usize, counts[slot]);
        var ends: [66]usize = undefined;
        var offset: usize = 0;
        result.fixed[slot] = try a.alloc(Storage.FixedRow(Air), counts[slot]);
        for (all, ends[0..all.len]) |owner, *end| {
            const next = offset + owner.fixed[slot].len;
            @memcpy(result.fixed[slot][offset..next], owner.fixed[slot]);
            owner.allocator.free(owner.fixed[slot]);
            owner.fixed[slot] = &.{};
            end.* = next;
            offset = next;
        }
        result.main[slot] = try a.alloc(@import("stwo_prover_engine").pcs.ColumnEvaluation, Air.PHYSICAL_MAIN_COLUMN_COUNT);
        for (result.main[slot]) |*column| column.* = .{ .log_size = log, .values = &.{} };
        var first: usize = 0;
        while (first < result.main[slot].len) {
            const end = @min(first + 8, result.main[slot].len);
            const output = result.main[slot][first..end];
            for (output) |*column| column.values = try a.alloc(core.fields.m31.M31, @as(usize, 1) << @intCast(log));
            Join.copyManyColumns(slot, all, ends[0..all.len], first, output);
            for (all) |owner| for (owner.main[slot][first..end]) |*column| {
                owner.allocator.free(column.values);
                column.values = &.{};
            };
            first = end;
        }
    }
    return result;
}
