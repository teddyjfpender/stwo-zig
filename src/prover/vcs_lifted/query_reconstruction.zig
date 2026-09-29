//! Reconstruct a bounded lower Merkle subtree from committed columns. Host
//! and device trees share the same lifted leaf ordering and hash semantics.
const std = @import("std");
const columns_mod = @import("columns.zig");

pub fn Reader(comptime H: type, comptime Retained: type) type {
    return struct {
        retained: Retained,
        columns: []const columns_mod.ColumnRef,
        retained_log_size: u32,
        subtrees: []Subtree = &.{},
        subtree_count: usize = 0,

        const Self = @This();
        const four_way = @hasDecl(H, "hashDirectLiftedM31LeavesWithSeed4") and @hasDecl(H, "leafSeed");
        const Subtree = struct { block: usize, hashes: [32]H.Hash = undefined };

        /// Query paths reuse lower nodes at every level. Build each admitted
        /// (at most sixteen-leaf) block once, rather than hash it repeatedly.
        pub fn init(allocator: std.mem.Allocator, retained: Retained, columns: []const columns_mod.ColumnRef, retained_log: u32, queries: []const usize) !Self {
            var self: Self = .{ .retained = retained, .columns = columns, .retained_log_size = retained_log };
            const log = self.maxLogSize();
            if (retained_log > log) return error.InvalidColumnSize;
            const depth = log - retained_log;
            if (depth == 0 or depth > 4 or queries.len == 0) return self;
            self.subtrees = try allocator.alloc(Subtree, queries.len);
            errdefer allocator.free(self.subtrees);
            for (queries, self.subtrees) |position, *subtree| {
                if (position >= @as(usize, 1) << @intCast(log)) return error.InvalidColumnSize;
                subtree.block = position >> @intCast(depth);
            }
            const Order = struct {
                fn less(_: void, left: Subtree, right: Subtree) bool {
                    return left.block < right.block;
                }
            };
            std.sort.heap(Subtree, self.subtrees, {}, Order.less);
            for (0..self.subtrees.len) |index| {
                const block = self.subtrees[index].block;
                if (self.subtree_count != 0 and self.subtrees[self.subtree_count - 1].block == block) continue;
                self.subtrees[self.subtree_count].block = block;
                self.subtree_count += 1;
            }
            const leaves: usize = @as(usize, 1) << @intCast(depth);
            for (self.subtrees[0..self.subtree_count]) |*subtree| {
                const start = subtree.block * leaves;
                if (comptime four_way) {
                    if (leaves >= 4) {
                        var offset: usize = 0;
                        while (offset < leaves) : (offset += 4) {
                            const hashes = H.hashDirectLiftedM31LeavesWithSeed4(H.leafSeed(), columns, start + offset, log);
                            @memcpy(subtree.hashes[leaves + offset ..][0..4], &hashes);
                        }
                    } else {
                        for (0..leaves) |offset| subtree.hashes[leaves + offset] = self.node(log, start + offset);
                    }
                } else {
                    for (0..leaves) |offset| subtree.hashes[leaves + offset] = self.node(log, start + offset);
                }
                var parent = leaves - 1;
                while (parent != 0) : (parent -= 1) {
                    subtree.hashes[parent] = H.hashChildren(.{
                        .left = subtree.hashes[parent * 2],
                        .right = subtree.hashes[parent * 2 + 1],
                    });
                }
            }
            return self;
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            allocator.free(self.subtrees);
            self.* = undefined;
        }

        fn cachedNode(self: Self, layer: u32, index: usize) ?H.Hash {
            const depth = layer - self.retained_log_size;
            const block = index >> @intCast(depth);
            var low: usize = 0;
            var high = self.subtree_count;
            while (low < high) {
                const middle = low + (high - low) / 2;
                const subtree = &self.subtrees[middle];
                if (subtree.block < block) low = middle + 1 else if (subtree.block > block) high = middle else {
                    const width: usize = @as(usize, 1) << @intCast(depth);
                    return subtree.hashes[width + (index & (width - 1))];
                }
            }
            return null;
        }

        pub fn maxLogSize(self: Self) u32 {
            return self.retained.maxLogSize();
        }

        fn node(self: Self, layer: u32, index: usize) H.Hash {
            if (comptime four_way) {
                if (self.maxLogSize() >= 2 and layer == self.maxLogSize() - 2) {
                    const leaves = H.hashDirectLiftedM31LeavesWithSeed4(H.leafSeed(), self.columns, index * 4, self.maxLogSize());
                    return selectFour(leaves, 2, 0);
                }
            }
            if (layer == self.maxLogSize()) {
                var hash = H.defaultWithInitialState();
                for (self.columns) |column| {
                    const shift: std.math.Log2Int(usize) = @intCast(self.maxLogSize() - column.log_size + 1);
                    const at = ((index >> shift) << 1) + (index & 1);
                    hash.updateLeaf(column.values[at..][0..1]);
                }
                return hash.finalize();
            }
            return H.hashChildren(.{
                .left = self.node(layer + 1, index * 2),
                .right = self.node(layer + 1, index * 2 + 1),
            });
        }

        fn selectFour(leaves: [4]H.Hash, depth: u32, lane: usize) H.Hash {
            if (depth == 0) return leaves[lane];
            if (depth == 1) return H.hashChildren(.{ .left = leaves[lane], .right = leaves[lane + 1] });
            return H.hashChildren(.{
                .left = H.hashChildren(.{ .left = leaves[0], .right = leaves[1] }),
                .right = H.hashChildren(.{ .left = leaves[2], .right = leaves[3] }),
            });
        }

        pub fn readHashes(self: Self, allocator: std.mem.Allocator, layer: u32, indices: []const u32) ![]H.Hash {
            if (layer > self.maxLogSize()) return error.InvalidColumnSize;
            if (layer <= self.retained_log_size)
                return self.retained.readHashes(allocator, layer, indices);
            const result = try allocator.alloc(H.Hash, indices.len);
            errdefer allocator.free(result);
            var cached_start: usize = std.math.maxInt(usize);
            var cached_leaves: [4]H.Hash = undefined;
            for (indices, result) |index, *destination| {
                if (index >= @as(usize, 1) << @intCast(layer)) return error.InvalidColumnSize;
                if (self.cachedNode(layer, index)) |hash| {
                    destination.* = hash;
                    continue;
                }
                if (comptime four_way) {
                    const depth = self.maxLogSize() - layer;
                    if (self.maxLogSize() >= 2 and depth <= 2) {
                        const position = @as(usize, index) << @intCast(depth);
                        const start = position & ~@as(usize, 3);
                        if (cached_start != start) {
                            cached_leaves = H.hashDirectLiftedM31LeavesWithSeed4(H.leafSeed(), self.columns, start, self.maxLogSize());
                            cached_start = start;
                        }
                        destination.* = selectFour(cached_leaves, depth, position & 3);
                        continue;
                    }
                }
                destination.* = self.node(layer, index);
            }
            return result;
        }
    };
}
