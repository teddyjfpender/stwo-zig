//! Host-only XDM05 source tree for absent heights and H=1. All source columns
//! are borrowed in native bit-reversed row order; the Merkle tree is resident.
const std = @import("std");
const core = @import("stwo_core");
const sparse = core.pcs.transposed_merkle_sparse_heights_experimental;
const old_tree = core.pcs.transposed_merkle_cascade;
const topology = core.pcs.transposed_merkle;
const M31 = sparse.M31;
const Hash = sparse.Hash;

pub const Commitment = struct {
    allocator: std.mem.Allocator,
    profile: sparse.Profile,
    layers: [][]Hash,
    source_columns: []const []const []const M31,

    pub const MAX_RESIDENT_BYTES: usize = 384 * 1024 * 1024;

    pub fn estimatedHostBytes(k: u32, source_words: usize) !usize {
        if (k > sparse.MAX_LOG_SIZE) return error.InvalidCascadeProfile;
        const nodes = (@as(usize, 1) << @intCast(k + 1)) - 1;
        const hashes = std.math.mul(usize, nodes, @sizeOf(Hash)) catch
            return error.SparseHostMemoryBudgetExceeded;
        const columns = std.math.mul(usize, source_words, @sizeOf(M31)) catch
            return error.SparseHostMemoryBudgetExceeded;
        return std.math.add(usize, hashes, columns) catch
            return error.SparseHostMemoryBudgetExceeded;
    }

    pub fn deinit(self: *Commitment) void {
        for (self.layers) |layer| self.allocator.free(layer);
        self.allocator.free(self.layers);
        self.* = undefined;
    }

    pub fn root(self: Commitment) Hash {
        return self.layers[0][0];
    }

    pub fn commit(
        allocator: std.mem.Allocator,
        source_columns: []const []const []const M31,
        query_count: usize,
    ) !Commitment {
        if (source_columns.len == 0 or source_columns.len > sparse.MAX_HEIGHTS or
            source_columns[0].len == 0 or source_columns[0][0].len < 16 or
            !std.math.isPowerOfTwo(source_columns[0][0].len))
            return error.InvalidCascadeProfile;
        const k: u32 = @intCast(std.math.log2_int(usize, source_columns[0][0].len));
        var counts = [_]u16{0} ** sparse.MAX_HEIGHTS;
        var source_words: usize = 0;
        for (source_columns, 0..) |height, i| {
            if (i > k) return error.InvalidCascadeProfile;
            if (height.len > sparse.MAX_COLUMNS) return error.InvalidCascadeProfile;
            counts[i] = @intCast(height.len);
            for (height) |column| {
                if (column.len != (@as(usize, 1) << @intCast(k - @as(u32, @intCast(i)))))
                    return error.InvalidCascadeProfile;
                source_words = std.math.add(usize, source_words, column.len) catch
                    return error.SparseHostMemoryBudgetExceeded;
            }
        }
        const profile = sparse.Profile{
            .largest_log_size = k,
            .height_count = source_columns.len,
            .columns = counts,
            .query_count = query_count,
        };
        try profile.validate();
        if (try estimatedHostBytes(k, source_words) > MAX_RESIDENT_BYTES)
            return error.SparseHostMemoryBudgetExceeded;
        const layers = try allocator.alloc([]Hash, k + 1);
        var built: usize = 0;
        errdefer {
            for (layers[0..built]) |layer| allocator.free(layer);
            allocator.free(layers);
        }
        while (built < layers.len) : (built += 1)
            layers[built] = try allocator.alloc(Hash, @as(usize, 1) << @intCast(built));
        var row_values: [sparse.MAX_COLUMNS]M31 = undefined;
        for (layers[k], 0..) |*leaf, row| {
            for (source_columns[0], 0..) |column, col| row_values[col] = column[row];
            leaf.* = old_tree.hashLeaf(row_values[0..source_columns[0].len]);
        }
        var level = k - 1;
        while (true) {
            const height = k - level;
            for (layers[level], 0..) |*node, row| {
                const children = topology.children(level, row);
                const left = layers[level + 1][children[0]];
                const right = layers[level + 1][children[1]];
                if (height < source_columns.len and source_columns[height].len != 0) {
                    for (source_columns[height], 0..) |column, col| row_values[col] = column[row];
                    node.* = old_tree.hashInserted(left, right, row_values[0..source_columns[height].len]);
                } else node.* = old_tree.hashUpper(left, right);
            }
            if (level == 0) break;
            level -= 1;
        }
        return .{
            .allocator = allocator,
            .profile = profile,
            .layers = layers,
            .source_columns = source_columns,
        };
    }

    pub fn encodeOpenings(
        self: Commitment,
        allocator: std.mem.Allocator,
        raw_queries: []const usize,
    ) ![]u8 {
        var profile = self.profile;
        profile.query_count = raw_queries.len;
        try profile.validate();
        var fixed_bytes: usize = 8 + 2 + 2 + 4 + 4 + 2 + 2 + 4 +
            2 * profile.height_count + 32 + 4 + 4 * raw_queries.len;
        for (self.source_columns) |height|
            fixed_bytes += height.len * 2 * @sizeOf(M31) * raw_queries.len;
        if (fixed_bytes > sparse.MAX_WIRE_BYTES) return error.SparseProofTooLarge;
        for (raw_queries) |raw|
            if (raw >= (@as(usize, 1) << @intCast(profile.largest_log_size)))
                return error.QueryPositionOutOfRange;
        var witness = std.ArrayList(Hash).empty;
        defer witness.deinit(allocator);
        var known = std.AutoHashMap(u64, void).init(allocator);
        defer known.deinit();
        const k: usize = profile.largest_log_size;
        for (raw_queries) |raw| {
            const base = sparse.pairBase(raw, 0);
            try known.put(nodeKey(k, base), {});
            try known.put(nodeKey(k, base + 1), {});
        }
        for (1..profile.height_count) |height| {
            const level = k - height;
            for (raw_queries) |raw| {
                const base = sparse.pairBase(raw, height);
                for (0..2) |j| {
                    const index = base + j;
                    const children = topology.children(@intCast(level), index);
                    for (children) |child| {
                        const address = nodeKey(level + 1, child);
                        if (!known.contains(address)) {
                            if (witness.items.len >= (sparse.MAX_WIRE_BYTES - fixed_bytes) / @sizeOf(Hash))
                                return error.SparseProofTooLarge;
                            try witness.append(allocator, self.layers[level + 1][child]);
                            try known.put(address, {});
                        }
                    }
                    try known.put(nodeKey(level, index), {});
                }
            }
        }
        const bottom = k - profile.height_count + 1;
        var active = std.ArrayList(usize).empty;
        defer active.deinit(allocator);
        for (raw_queries) |raw| {
            const base = sparse.pairBase(raw, profile.height_count - 1);
            try active.append(allocator, base);
            try active.append(allocator, base + 1);
        }
        var level = bottom;
        while (level > 0) : (level -= 1) {
            std.sort.heap(usize, active.items, {}, std.sort.asc(usize));
            var next = std.ArrayList(usize).empty;
            errdefer next.deinit(allocator);
            for (active.items, 0..) |index, position| {
                if (position > 0 and index == active.items[position - 1]) continue;
                const sibling = topology.sibling(@intCast(level), index);
                const address = nodeKey(level, sibling);
                if (!known.contains(address)) {
                    if (witness.items.len >= (sparse.MAX_WIRE_BYTES - fixed_bytes) / @sizeOf(Hash))
                        return error.SparseProofTooLarge;
                    try witness.append(allocator, self.layers[level][sibling]);
                    try known.put(address, {});
                }
                const parent = topology.parent(@intCast(level), index);
                try known.put(nodeKey(level - 1, parent), {});
                try next.append(allocator, parent);
            }
            active.deinit(allocator);
            active = next;
        }
        const exact_bytes = fixed_bytes + witness.items.len * @sizeOf(Hash);
        var out = std.ArrayList(u8).empty;
        errdefer out.deinit(allocator);
        try out.ensureTotalCapacity(allocator, exact_bytes);
        const w = out.writer(allocator);
        try w.writeAll(sparse.MAGIC);
        try w.writeInt(u16, sparse.VERSION, .little);
        try w.writeInt(u16, 0, .little);
        try w.writeInt(u32, @intCast(exact_bytes), .little);
        try w.writeInt(u32, profile.largest_log_size, .little);
        try w.writeInt(u16, @intCast(profile.height_count), .little);
        try w.writeInt(u16, 0, .little);
        try w.writeInt(u32, @intCast(profile.query_count), .little);
        for (profile.columns[0..profile.height_count]) |count| try w.writeInt(u16, count, .little);
        const root_hash = self.root();
        try w.writeAll(&root_hash);
        for (raw_queries) |raw| {
            try w.writeInt(u32, @intCast(raw), .little);
            for (self.source_columns, 0..) |height, i| {
                const base = sparse.pairBase(raw, i);
                for (0..2) |j| for (height) |column|
                    try w.writeInt(u32, column[base + j].toU32(), .little);
            }
        }
        try w.writeInt(u32, @intCast(witness.items.len), .little);
        for (witness.items) |hash| try w.writeAll(&hash);
        std.debug.assert(out.items.len == exact_bytes);
        return out.toOwnedSlice(allocator);
    }
};

fn nodeKey(level: usize, index: usize) u64 {
    return (@as(u64, @intCast(level)) << 32) | @as(u64, @intCast(index));
}
