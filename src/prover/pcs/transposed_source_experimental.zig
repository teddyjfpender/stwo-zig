//! Experimental S31XDM02 two-height source committer. This is an isolated
//! reference implementation of the paper's transposed cross-domain topology;
//! production PCS never calls it. The opening codec deduplicates authentication
//! siblings across all query bundles.

const std = @import("std");
const core = @import("stwo_core");
const xdm = core.pcs.transposed_merkle;
const M31 = xdm.M31;
const Hash = xdm.Hash;

pub const Commitment = struct {
    allocator: std.mem.Allocator,
    profile: xdm.Profile,
    layers: [][]Hash,
    large_columns: []const []const M31,
    small_columns: []const []const M31,

    pub fn deinit(self: *Commitment) void {
        for (self.layers) |layer| self.allocator.free(layer);
        self.allocator.free(self.layers);
        self.* = undefined;
    }

    pub fn root(self: Commitment) Hash {
        return self.layers[0][0];
    }

    /// Columns are borrowed until deinit. All rows are in native bit-reversed
    /// circle order; the smaller domain is inserted at level `log_size-1`.
    pub fn commit(
        allocator: std.mem.Allocator,
        large_columns: []const []const M31,
        small_columns: []const []const M31,
    ) !Commitment {
        if (large_columns.len == 0 or small_columns.len == 0 or
            large_columns.len > xdm.MAX_COLUMNS or small_columns.len > xdm.MAX_COLUMNS)
            return error.InvalidCrossDomainProfile;
        const large_size = large_columns[0].len;
        if (large_size < 8 or !std.math.isPowerOfTwo(large_size))
            return error.InvalidCrossDomainProfile;
        const log_size: u32 = @intCast(std.math.log2_int(usize, large_size));
        const profile = xdm.Profile{
            .log_size = log_size,
            .large_columns = large_columns.len,
            .small_columns = small_columns.len,
            .query_count = 1,
        };
        try profile.validate();
        for (large_columns) |column| if (column.len != large_size) {
            return error.InvalidCrossDomainProfile;
        };
        for (small_columns) |column| if (column.len != large_size / 2) {
            return error.InvalidCrossDomainProfile;
        };

        const layers = try allocator.alloc([]Hash, @as(usize, log_size) + 1);
        var built: usize = 0;
        errdefer {
            for (layers[0..built]) |layer| allocator.free(layer);
            allocator.free(layers);
        }
        while (built < layers.len) : (built += 1)
            layers[built] = try allocator.alloc(Hash, @as(usize, 1) << @intCast(built));
        var large: [xdm.MAX_COLUMNS]M31 = undefined;
        for (layers[log_size], 0..) |*leaf, row| {
            for (large_columns, 0..) |column, col| large[col] = column[row];
            leaf.* = xdm.hashLeaf(large[0..large_columns.len]);
        }
        var small: [xdm.MAX_COLUMNS]M31 = undefined;
        var level = log_size - 1;
        while (true) {
            for (layers[level], 0..) |*node, row| {
                const pair = xdm.children(level, row);
                const left = layers[level + 1][pair[0]];
                const right = layers[level + 1][pair[1]];
                if (level == log_size - 1) {
                    for (small_columns, 0..) |column, col| small[col] = column[row];
                    node.* = xdm.hashInserted(left, right, small[0..small_columns.len]);
                } else {
                    node.* = xdm.hashUpper(left, right);
                }
            }
            if (level == 0) break;
            level -= 1;
        }
        return .{
            .allocator = allocator,
            .profile = profile,
            .layers = layers,
            .large_columns = large_columns,
            .small_columns = small_columns,
        };
    }

    /// Versioned source-opening proof. `raw_queries` must be the verifier's
    /// independently sampled largest-domain rows. Repeats are preserved.
    pub fn encodeOpenings(
        self: Commitment,
        allocator: std.mem.Allocator,
        raw_queries: []const usize,
    ) ![]u8 {
        var profile = self.profile;
        profile.query_count = raw_queries.len;
        try profile.validate();
        var out = std.ArrayList(u8).empty;
        errdefer out.deinit(allocator);
        const w = out.writer(allocator);
        try w.writeAll(xdm.MAGIC);
        try w.writeInt(u16, xdm.VERSION, .little);
        try w.writeInt(u16, 0, .little);
        try w.writeInt(u32, 0, .little);
        try w.writeInt(u32, profile.log_size, .little);
        try w.writeInt(u16, @intCast(profile.large_columns), .little);
        try w.writeInt(u16, @intCast(profile.small_columns), .little);
        try w.writeInt(u32, @intCast(profile.query_count), .little);
        const root_hash = self.root();
        try w.writeAll(&root_hash);
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const scratch = arena.allocator();
        const active = try scratch.alloc([]bool, profile.log_size);
        for (active, 0..) |*bits, level| {
            bits.* = try scratch.alloc(bool, @as(usize, 1) << @intCast(level));
            @memset(bits.*, false);
        }
        for (raw_queries) |raw| {
            if (raw >= (@as(usize, 1) << @intCast(profile.log_size)))
                return error.QueryPositionOutOfRange;
            try w.writeInt(u32, @intCast(raw), .little);
            const base = raw & ~@as(usize, 3);
            for (0..4) |j| {
                const position = base + j;
                for (self.large_columns) |column|
                    try w.writeInt(u32, column[position].toU32(), .little);
            }
            for (0..2) |j| {
                const small_row = ((base >> 2) << 1) + j;
                for (self.small_columns) |column|
                    try w.writeInt(u32, column[small_row].toU32(), .little);
                active[profile.log_size - 1][small_row] = true;
            }
        }
        const witness_count_offset = out.items.len;
        try w.writeInt(u32, 0, .little);
        var witness_count: u32 = 0;
        var level = profile.log_size - 1;
        while (level > 0) : (level -= 1) {
            for (active[level], 0..) |is_active, index| {
                if (!is_active) continue;
                const sibling_index = xdm.sibling(level, index);
                if (!active[level][sibling_index]) {
                    try w.writeAll(&self.layers[level][sibling_index]);
                    witness_count += 1;
                }
                active[level - 1][xdm.parent(level, index)] = true;
            }
        }
        if (out.items.len > xdm.MAX_WIRE_BYTES) return error.CrossDomainProofTooLarge;
        const encoded = try out.toOwnedSlice(allocator);
        std.mem.writeInt(u32, encoded[12..16], @intCast(encoded.len), .little);
        std.mem.writeInt(u32, encoded[witness_count_offset..][0..4], witness_count, .little);
        return encoded;
    }
};
