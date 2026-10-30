//! Canonical global repartition of identical G AIRs. Values/wire IDs are unchanged.
//! Live relocation drains one physical column at a time; failure consumes rows.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Storage = @import("air/blake3_parent_row_storage.zig");
const G = @import("air/blake3_g_call.zig");
const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
const committed = @import("air/framework_interaction.zig").committedRow;
pub const SHARDS = @import("air/blake3_g_partition.zig").SHARDS;
pub const Plan = struct {
    old_counts: [SHARDS.len]usize,
    new_counts: [SHARDS.len]usize,
    old_logs: [SHARDS.len]u32,
    new_logs: [SHARDS.len]u32,
    pub fn init(fixed: Storage.FixedTuple(false)) !Plan {
        var p: Plan = undefined;
        var total: usize = 0;
        inline for (SHARDS, 0..) |slot, i| {
            p.old_counts[i] = fixed[slot].len;
            p.old_logs[i] = logRows(fixed[slot].len);
            total = try std.math.add(usize, total, fixed[slot].len);
        }
        if (total > SHARDS.len * (@as(usize, 1) << 24)) return error.GlobalGPartitionCapacityExceeded;
        var left = total;
        for (&p.new_counts, &p.new_logs, 0..) |*count, *log, i| {
            if (i + 1 == SHARDS.len or left <= 1) {
                count.* = left;
            } else {
                const target = try std.math.divCeil(usize, left, SHARDS.len - i);
                const size = @as(usize, 1) << @intCast(std.math.log2_int_ceil(usize, target));
                count.* = @min(left, size);
            }
            log.* = logRows(count.*);
            if (log.* > 24) return error.GlobalGPartitionCapacityExceeded;
            left -= count.*;
        }
        if (left != 0) return error.InvalidGlobalGPartition;
        return p;
    }
    pub fn identity(p: Plan) [32]u8 {
        var ch = core.proof_suites.Blake3.Channel{};
        ch.mixU32s(&.{ 0x42384750, 1 });
        ch.mixRoot(G.SEMANTIC_DIGEST);
        for (p.old_counts, p.new_counts, p.old_logs, p.new_logs) |old, new, ol, nl| {
            ch.mixU64(old);
            ch.mixU64(new);
            ch.mixU32s(&.{ ol, nl });
        }
        return ch.digestBytes();
    }
    fn oldFixed(p: Plan, fixed: Storage.FixedTuple(false)) ![SHARDS.len][]Storage.FixedRow(G) {
        var rows: [SHARDS.len][]Storage.FixedRow(G) = undefined;
        inline for (SHARDS, 0..) |slot, i| {
            if (fixed[slot].len != p.old_counts[i]) return error.InvalidGlobalGPartition;
            rows[i] = fixed[slot];
        }
        return rows;
    }
    fn copyFixed(p: Plan, a: std.mem.Allocator, old: [SHARDS.len][]Storage.FixedRow(G)) ![SHARDS.len][]Storage.FixedRow(G) {
        var out: [SHARDS.len][]Storage.FixedRow(G) = @splat(&.{});
        errdefer for (out) |rows| a.free(rows);
        var source: usize = 0;
        var at: usize = 0;
        for (&out, p.new_counts) |*rows, count| {
            rows.* = try a.alloc(Storage.FixedRow(G), count);
            var dst: usize = 0;
            while (dst < count) {
                while (source < SHARDS.len and at == old[source].len) {
                    source += 1;
                    at = 0;
                }
                if (source == SHARDS.len) return error.InvalidGlobalGPartition;
                const n = @min(count - dst, old[source].len - at);
                @memcpy(rows.*[dst..][0..n], old[source][at..][0..n]);
                dst += n;
                at += n;
            }
        }
        return out;
    }
    pub fn applyFixed(p: Plan, a: std.mem.Allocator, fixed: *Storage.FixedTuple(false)) !void {
        const old = try p.oldFixed(fixed.*);
        const next = try p.copyFixed(a, old);
        inline for (SHARDS, 0..) |slot, i| {
            a.free(fixed.*[slot]);
            fixed.*[slot] = next[i];
        }
    }
    /// Caller must destroy rows after failure. Partial drained columns cannot be reused.
    pub fn applyDraining(p: Plan, rows: *Storage.Prepared) !void {
        const a = rows.allocator;
        const old = try p.oldFixed(rows.fixed);
        inline for (SHARDS, 0..) |slot, i| {
            if (rows.main[slot].len != G.PHYSICAL_MAIN_COLUMN_COUNT) return error.InvalidGlobalGPartition;
            for (rows.main[slot]) |col| if (col.log_size != p.old_logs[i] or col.values.len != @as(usize, 1) << @intCast(p.old_logs[i])) return error.InvalidGlobalGPartition;
        }
        const next_fixed = try p.copyFixed(a, old);
        errdefer for (next_fixed) |f| a.free(f);
        var next_main: [SHARDS.len][]Column = @splat(&.{});
        errdefer for (next_main) |columns| {
            for (columns) |column| a.free(column.values);
            a.free(columns);
        };
        for (&next_main, p.new_logs) |*columns, log| {
            columns.* = try a.alloc(Column, G.PHYSICAL_MAIN_COLUMN_COUNT);
            for (columns.*) |*column| column.* = .{ .log_size = log, .values = &.{} };
        }
        // One compact permutation is shared by all82 physical columns.
        // It avoids billions of repeated bit reversals/source searches.
        var mapping: [SHARDS.len][]u32 = @splat(&.{});
        defer for (mapping) |indices| a.free(indices);
        var global_base: usize = 0;
        for (&mapping, p.new_counts, p.new_logs) |*indices, count, log| {
            indices.* = try a.alloc(u32, @as(usize, 1) << @intCast(log));
            for (indices.*, 0..) |*mapped, pos| {
                const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(pos, log), log);
                if (logical >= count) {
                    mapped.* = std.math.maxInt(u32);
                    continue;
                }
                var index = global_base + logical;
                var source: usize = 0;
                while (source < SHARDS.len and index >= p.old_counts[source]) {
                    index -= p.old_counts[source];
                    source += 1;
                }
                if (source == SHARDS.len or p.old_logs[source] > 30) return error.InvalidGlobalGPartition;
                const original = committed(index, p.old_logs[source]);
                mapped.* = (@as(u32, @intCast(source)) << 30) | @as(u32, @intCast(original));
            }
            global_base += count;
        }
        for (0..G.PHYSICAL_MAIN_COLUMN_COUNT) |column| {
            for (next_main, mapping) |columns, indices| {
                const values = try a.alloc(M, indices.len);
                columns[column].values = values;
                for (values, indices) |*value, index| value.* = if (index == std.math.maxInt(u32)) M.zero() else rows.main[SHARDS[index >> 30]][column].values[index & 0x3fffffff];
            }
            inline for (SHARDS) |slot| {
                a.free(rows.main[slot][column].values);
                rows.main[slot][column].values = &.{};
            }
        }
        inline for (SHARDS, 0..) |slot, i| {
            a.free(rows.main[slot]);
            a.free(rows.fixed[slot]);
            rows.main[slot] = next_main[i];
            rows.fixed[slot] = next_fixed[i];
        }
    }
};
fn logRows(n: usize) u32 {
    return if (n < 2) 1 else std.math.log2_int_ceil(usize, n);
}

fn fixture(a: std.mem.Allocator, total: usize) !Storage.Prepared {
    var rows = Storage.Prepared{ .allocator = a, .main = @splat(&.{}), .fixed = undefined, .input_count = 0 };
    inline for (0..Storage.Airs.len) |i| rows.fixed[i] = &.{};
    errdefer rows.deinit();
    var base: usize = 0;
    inline for (SHARDS, 0..) |slot, i| {
        const count = total / SHARDS.len + @intFromBool(i < total % SHARDS.len);
        const log = logRows(count);
        rows.fixed[slot] = try a.alloc(Storage.FixedRow(G), count);
        for (rows.fixed[slot], 0..) |*row, index| row.* = @splat(M.fromCanonical(@intCast(base + index + 1)));
        rows.main[slot] = try a.alloc(Column, G.PHYSICAL_MAIN_COLUMN_COUNT);
        for (rows.main[slot]) |*column| column.* = .{ .log_size = log, .values = &.{} };
        for (rows.main[slot], 0..) |*column, c| {
            const values = try a.alloc(M, @as(usize, 1) << @intCast(log));
            column.values = values;
            @memset(values, M.zero());
            for (0..count) |index| values[committed(index, log)] = M.fromCanonical(@intCast(1000 * c + base + index + 1));
        }
        base += count;
    }
    return rows;
}
test "global G canonical repartition preserves every fixed field main cell and padding" {
    const a = std.testing.allocator;
    for ([_]usize{ 0, 1, 2, 3, 17, 31, 32, 33, 63, 65 }) |n| {
        var rows = try fixture(a, n);
        defer rows.deinit();
        const plan = try Plan.init(rows.fixed);
        var fixed: Storage.FixedTuple(false) = undefined;
        inline for (0..Storage.Airs.len) |i| fixed[i] = &.{};
        defer inline for (0..Storage.Airs.len) |i| a.free(fixed[i]);
        inline for (SHARDS) |slot| fixed[slot] = try a.dupe(Storage.FixedRow(G), rows.fixed[slot]);
        try plan.applyFixed(a, &fixed);
        try plan.applyDraining(&rows);
        var base: usize = 0;
        inline for (SHARDS, 0..) |slot, i| {
            try std.testing.expectEqualDeep(fixed[slot], rows.fixed[slot]);
            try std.testing.expectEqual(plan.new_counts[i], rows.fixed[slot].len);
            for (rows.main[slot], 0..) |column, c| for (0..column.values.len) |index| {
                const expected = if (index < rows.fixed[slot].len) M.fromCanonical(@intCast(1000 * c + base + index + 1)) else M.zero();
                try std.testing.expect(expected.eql(column.values[committed(index, column.log_size)]));
            };
            base += rows.fixed[slot].len;
        }
        try std.testing.expectEqual(n, base);
    }
}
test "global G draining allocation failures remain safely destructible" {
    for ([_]usize{ 0, 2, 5, 9, 20, 50, 90, 150, 250 }) |failure| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        const a = failing.allocator();
        var rows = try fixture(a, 33);
        defer rows.deinit();
        const plan = try Plan.init(rows.fixed);
        failing.fail_index = failing.alloc_index + failure;
        try std.testing.expectError(error.OutOfMemory, plan.applyDraining(&rows));
    }
}
