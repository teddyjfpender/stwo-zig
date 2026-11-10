//! Bounded native-height four-state caches for lifted Merkle tails.
//! Only owned stack workspace; no final-domain state slab or heap allocation.
const std = @import("std");
const M = @import("stwo_core").fields.m31.M31;
pub fn For(comptime H: type, comptime Column: type) type {
    return struct {
        const LIMIT = @bitSizeOf(usize);
        const Group = struct { columns: []const Column, log: u32 };
        const Cache = struct {
            base: []const H,
            base_log: u32,
            groups: [LIMIT]Group = undefined,
            count: usize = 0,
            states: [LIMIT][4]H = undefined,
            keys: [LIMIT]usize = @splat(std.math.maxInt(usize)),
            absorptions: usize = 0,
            fn baseAt(self: *const Cache, log: u32, index: usize) H {
                std.debug.assert(log >= self.base_log);
                const shift: std.math.Log2Int(usize) = @intCast(log - self.base_log + 1);
                const p = ((index >> shift) << 1) + (index & 1);
                std.debug.assert(p < self.base.len);
                return self.base[p];
            }
            /// Return a VALUE snapshot. A later lane may evict this cache tile;
            /// no pointer into mutable cache storage escapes to the batch.
            fn at(self: *Cache, ordinal: usize, index: usize) H {
                const group = self.groups[ordinal];
                const width: usize = if (group.log == 1) 2 else 4;
                const key = index & ~(width - 1);
                if (self.keys[ordinal] != key) {
                    var batch: [4]H = undefined;
                    for (0..width) |lane| {
                        const source = key + lane;
                        if (ordinal == 0) {
                            batch[lane] = self.baseAt(group.log, source);
                        } else {
                            const parent_log = self.groups[ordinal - 1].log;
                            std.debug.assert(group.log > parent_log);
                            const shift: std.math.Log2Int(usize) = @intCast(group.log - parent_log + 1);
                            const parent = ((source >> shift) << 1) + (source & 1);
                            batch[lane] = self.at(ordinal - 1, parent);
                        }
                    }
                    if (width == 4) {
                        H.updateM31Columns4(&batch, group.columns, key);
                    } else {
                        // Two-row native columns are legal in the generic
                        // contract; do not read imaginary third/fourth rows.
                        for (batch[0..width], 0..) |*state, lane| {
                            var words: [64]M = undefined;
                            var first: usize = 0;
                            while (first < group.columns.len) {
                                const n = @min(words.len, group.columns.len - first);
                                for (group.columns[first..][0..n], words[0..n]) |column, *word| word.* = column.values[key + lane];
                                state.updateLeaf(words[0..n]);
                                first += n;
                            }
                        }
                    }
                    @memcpy(self.states[ordinal][0..width], batch[0..width]);
                    self.keys[ordinal] = key;
                    self.absorptions += width * group.columns.len;
                }
                return self.states[ordinal][index - key];
            }
            fn prefix(self: *Cache, final_log: u32, row: usize) H {
                if (self.count == 0) return self.baseAt(final_log, row);
                const log = self.groups[self.count - 1].log;
                const shift: std.math.Log2Int(usize) = @intCast(final_log - log + 1);
                return self.at(self.count - 1, ((row >> shift) << 1) + (row & 1));
            }
        };
        /// Explicit algorithm-owned workspace. Includes all cache storage,
        /// worst-case recursive [4]H batches, scalar fallback slabs, group/
        /// index bookkeeping, and final batch/digests.
        /// This is NOT a measured compiler frame/register-spill/worker-stack
        /// peak. Backend helper frames and thread stacks remain separate.
        pub const explicit_workspace_bytes = @sizeOf(Cache) +
            LIMIT * (4 * @sizeOf(H) + 64 * @sizeOf(M) + @sizeOf(Group) + 16 * @sizeOf(usize)) +
            4 * (@sizeOf(H) + @sizeOf(H.Hash));
        pub fn finish(range: anytype) usize {
            std.debug.assert(range.base_log_size >= 1);
            std.debug.assert(range.start <= range.end and range.end <= range.leaves.len);
            var cache = Cache{ .base = range.base_hashers, .base_log = range.base_log_size };
            var begin: usize = 0;
            while (begin < range.tail_columns.len and range.tail_columns[begin].log_size < range.final_log_size) {
                const log = range.tail_columns[begin].log_size;
                std.debug.assert(log >= range.base_log_size and log >= 1);
                var end = begin + 1;
                while (end < range.tail_columns.len and range.tail_columns[end].log_size == log) end += 1;
                std.debug.assert(cache.count < LIMIT);
                cache.groups[cache.count] = .{ .columns = range.tail_columns[begin..end], .log = log };
                cache.count += 1;
                begin = end;
            }
            const final = range.tail_columns[begin..];
            var position = range.start;
            while (position + 4 <= range.end) : (position += 4) {
                var batch: [4]H = undefined;
                inline for (0..4) |lane| batch[lane] = cache.prefix(range.final_log_size, position + lane);
                if (final.len != 0) H.updateM31Columns4(&batch, final, position);
                const hashes = H.finalize4(&batch);
                @memcpy(range.leaves[position..][0..4], &hashes);
                cache.absorptions += 4 * final.len;
            }
            for (position..range.end) |row| {
                var state = cache.prefix(range.final_log_size, row);
                for (final) |column| state.updateLeaf(column.values[row..][0..1]);
                range.leaves[row] = state.finalize();
                cache.absorptions += final.len;
            }
            return cache.absorptions;
        }
    };
}
