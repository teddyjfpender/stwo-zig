//! Four-message native-height prefix caches for lifted BLAKE2s commitments.
const std = @import("std");
const stream = @import("blake2_stream4.zig");

pub fn cacheBytes(comptime H: type, comptime Column: type) usize {
    if (comptime !stream.supports(H)) return 0;
    return @sizeOf(Cache(H, Column));
}

fn Cache(comptime H: type, comptime Column: type) type {
    return struct {
        const Self = @This();
        const Group = struct { columns: []const Column, log: u32 };
        const Block = struct { states: [4]H, index: usize };
        groups: [@bitSizeOf(usize)]Group = undefined,
        blocks: [@bitSizeOf(usize)]Block = undefined,
        count: usize = 0,
        base: []const H,
        base_log: u32,
        absorptions: usize = 0,

        fn ensure(self: *Self, ordinal: usize, index: usize) void {
            const block_start = index & ~@as(usize, 3);
            const block = &self.blocks[ordinal];
            if (block.index == block_start) return;
            const group = self.groups[ordinal];
            const previous_log = if (ordinal == 0) self.base_log else self.groups[ordinal - 1].log;
            const shift: std.math.Log2Int(usize) = @intCast(group.log - previous_log + 1);
            for (0..4) |lane| {
                const row = block_start + lane;
                const parent = ((row >> shift) << 1) + (row & 1);
                if (ordinal == 0) {
                    block.states[lane] = self.base[parent];
                } else {
                    self.ensure(ordinal - 1, parent);
                    block.states[lane] = self.blocks[ordinal - 1].states[parent & 3];
                }
            }
            stream.updateM31Columns4(&block.states, group.columns, block_start);
            self.absorptions += 4 * group.columns.len;
            block.index = block_start;
        }

        fn stateAt(self: *Self, position: usize, final_log: u32) H {
            const previous_log = if (self.count == 0) self.base_log else self.groups[self.count - 1].log;
            const shift: std.math.Log2Int(usize) = @intCast(final_log - previous_log + 1);
            const index = ((position >> shift) << 1) + (position & 1);
            if (self.count == 0) return self.base[index];
            self.ensure(self.count - 1, index);
            return self.blocks[self.count - 1].states[index & 3];
        }
    };
}

/// Returns null before touching outputs if the native domain cannot form a
/// complete four-row block. The established scalar cache handles that case.
pub fn finalize(comptime H: type, range: anytype) ?usize {
    if (comptime !stream.supports(H)) return null;
    const Column = std.meta.Child(@TypeOf(range.tail_columns));
    var cache: Cache(H, Column) = .{ .base = range.base_hashers, .base_log = range.base_log_size };
    var begin: usize = 0;
    while (begin < range.tail_columns.len) {
        const log = range.tail_columns[begin].log_size;
        if (log == range.final_log_size) break;
        if (log < 2) return null;
        var end = begin + 1;
        while (end < range.tail_columns.len and range.tail_columns[end].log_size == log) : (end += 1) {}
        cache.groups[cache.count] = .{ .columns = range.tail_columns[begin..end], .log = log };
        cache.blocks[cache.count].index = std.math.maxInt(usize);
        cache.count += 1;
        begin = end;
    }
    const final_columns = range.tail_columns[begin..];
    var position = range.start;
    while (position < range.end) : (position += 4) {
        const count = @min(@as(usize, 4), range.end - position);
        var batch: [4]H = undefined;
        for (batch[0..count], 0..) |*hasher, lane| hasher.* = cache.stateAt(position + lane, range.final_log_size);
        if (count == 4) {
            stream.updateM31Columns4(&batch, final_columns, position);
            const hashes = stream.finalize4(&batch);
            @memcpy(range.leaves[position..][0..4], &hashes);
        } else {
            for (batch[0..count], 0..) |*hasher, lane| {
                for (final_columns) |column| hasher.updateLeaf(column.values[position + lane ..][0..1]);
                range.leaves[position + lane] = hasher.finalize();
            }
        }
        cache.absorptions += count * final_columns.len;
    }
    return cache.absorptions;
}
