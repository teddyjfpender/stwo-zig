//! Transactional extension of retained parent columns. Existing domains are
//! remapped only when growth changes their committed row permutation.
const std = @import("std");
const core = @import("stwo_core");
const storage = @import("blake3_parent_row_storage.zig");
const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
const M = core.fields.m31.M31;
const committed = @import("framework_interaction.zig").committedRow;
pub fn Chunk(comptime Air: type) type {
    return struct {
        live: []const Air.Row,
        fixed: []const Air.Row = &.{},
        fixed_compact: ?[]const storage.FixedRow(Air) = null,
        pub fn count(self: @This()) usize {
            return if (self.fixed_compact) |rows| rows.len else self.fixed.len;
        }
        pub fn trusted(self: @This(), index: usize) storage.FixedRow(Air) {
            return if (self.fixed_compact) |rows| rows[index] else storage.compactFixed(Air, self.fixed[index]);
        }
    };
}
pub const Chunks = blk: {
    var types: [storage.Airs.len]type = undefined;
    for (storage.Airs, &types) |Air, *T| T.* = std.ArrayList(Chunk(Air));
    break :blk std.meta.Tuple(&types);
};
pub fn init() Chunks {
    var result: Chunks = undefined;
    inline for (0..storage.Airs.len) |i| result[i] = .empty;
    return result;
}
pub fn deinit(a: std.mem.Allocator, chunks: *Chunks) void {
    inline for (0..storage.Airs.len) |i| chunks[i].deinit(a);
}
pub fn append(target: anytype, chunks: *const Chunks) !void {
    const a = target.allocator;
    var replacement = storage.Prepared{ .allocator = a, .main = @splat(&.{}), .fixed = undefined, .input_count = target.input_count };
    inline for (0..storage.Airs.len) |i| replacement.fixed[i] = &.{};
    defer replacement.deinit();
    inline for (storage.Airs, 0..) |Air, i| cohort: {
        var count = target.fixed[i].len;
        for (chunks[i].items) |chunk| {
            if (chunk.live.len != chunk.count() or (chunk.fixed_compact != null and chunk.fixed.len != 0)) return error.InvalidParentAppend;
            count = try std.math.add(usize, count, chunk.live.len);
            for (chunk.live, 0..) |live, index| for (live[Air.PHYSICAL_MAIN_COLUMN_COUNT..], chunk.trusted(index)) |value, trusted| {
                if (!value.eql(trusted)) return error.InvalidParentAppend;
            };
        }
        if (count == target.fixed[i].len) break :cohort;
        if (count > (1 << 30)) return error.InvalidParentAppend;
        const log: u32 = @max(1, std.math.log2_int_ceil(usize, count));
        const size = @as(usize, 1) << @intCast(log);
        if (target.main[i].len != Air.PHYSICAL_MAIN_COLUMN_COUNT) return error.InvalidParentAppend;
        if (@TypeOf(target.*) == storage.Partition and i < 2) {
            if (count > target.capacity[i]) return error.InvalidParentAppend;
            const end = try std.math.add(usize, target.first[i], target.capacity[i]);
            const shared_log = target.main[i][0].log_size;
            for (target.main[i]) |old| {
                if (old.log_size > 30 or old.log_size != shared_log or
                    old.values.len != @as(usize, 1) << @intCast(old.log_size) or end > old.values.len)
                    return error.InvalidParentAppend;
            }
        }
        replacement.fixed[i] = try a.alloc(storage.FixedRow(Air), count);
        @memcpy(replacement.fixed[i][0..target.fixed[i].len], target.fixed[i]);
        if (!(@TypeOf(target.*) == storage.Partition and i < 2)) {
            replacement.main[i] = try a.alloc(Column, Air.PHYSICAL_MAIN_COLUMN_COUNT);
            for (replacement.main[i]) |*column| column.* = .{ .log_size = log, .values = &.{} };
            for (replacement.main[i], target.main[i], 0..) |*column, old, col| {
                if (old.log_size > 30 or old.values.len != @as(usize, 1) << @intCast(old.log_size) or target.fixed[i].len > old.values.len) return error.InvalidParentAppend;
                const values = try a.alloc(M, size);
                column.values = values;
                if (log == old.log_size) {
                    @memcpy(values, old.values);
                } else {
                    @memset(values, M.zero());
                    for (0..target.fixed[i].len) |row| values[committed(row, log)] = old.values[committed(row, old.log_size)];
                }
                var at = target.fixed[i].len;
                for (chunks[i].items) |chunk| {
                    for (chunk.live) |row| {
                        values[committed(at, log)] = row[col];
                        at += 1;
                    }
                }
            }
        }
        var at = target.fixed[i].len;
        for (chunks[i].items) |chunk| {
            for (replacement.fixed[i][at..][0..chunk.count()], 0..) |*destination, index| destination.* = chunk.trusted(index);
            at += chunk.count();
        }
    }
    // Exchange only after every allocation, geometry and fixed-column check.
    inline for (0..storage.Airs.len) |i| if (replacement.fixed[i].len != 0) {
        if (@TypeOf(target.*) == storage.Partition and i < 2) {
            // No writes to shared backing until all cohorts have passed every
            // fallible operation. Only this partition's reserved suffix changes.
            for (target.main[i], 0..) |column, col| {
                var at = target.first[i] + target.fixed[i].len;
                for (chunks[i].items) |chunk| for (chunk.live) |row| {
                    @constCast(column.values)[committed(at, column.log_size)] = row[col];
                    at += 1;
                };
            }
        } else std.mem.swap([]Column, &target.main[i], &replacement.main[i]);
        std.mem.swap([]storage.FixedRow(storage.Airs[i]), &target.fixed[i], &replacement.fixed[i]);
    };
}
