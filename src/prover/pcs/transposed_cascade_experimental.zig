//! Host reference for the experimental XDM03 multi-height transposed tree.
//! This is a source commitment/opening fragment, not production PCS.

const std = @import("std");
const core = @import("stwo_core");
const xdm = core.pcs.transposed_merkle_cascade;
const topology = core.pcs.transposed_merkle;
const M31 = xdm.M31;
const Hash = xdm.Hash;

pub const Commitment = struct {
    allocator: std.mem.Allocator,
    profile: xdm.Profile,
    layers: [][]Hash,
    source_columns: []const []const []const M31,

    pub fn deinit(self: *Commitment) void {
        for (self.layers) |layer| self.allocator.free(layer);
        self.allocator.free(self.layers);
        self.* = undefined;
    }
    pub fn root(self: Commitment) Hash {
        return self.layers[0][0];
    }

    /// All source columns are borrowed and use native bit-reversed row order.
    pub fn commit(
        allocator: std.mem.Allocator,
        source_columns: []const []const []const M31,
    ) !Commitment {
        if (source_columns.len < 2 or source_columns.len > xdm.MAX_HEIGHTS or
            source_columns[0].len == 0 or source_columns[0][0].len < 16 or
            !std.math.isPowerOfTwo(source_columns[0][0].len))
            return error.InvalidCascadeProfile;
        const k: u32 = @intCast(std.math.log2_int(usize, source_columns[0][0].len));
        if (k < source_columns.len + 2) return error.InvalidCascadeProfile;
        var columns = [_]u16{0} ** xdm.MAX_HEIGHTS;
        for (source_columns, 0..) |height, i| {
            if (height.len == 0 or height.len > xdm.MAX_COLUMNS)
                return error.InvalidCascadeProfile;
            columns[i] = @intCast(height.len);
            for (height) |column| {
                if (column.len != (@as(usize, 1) << @intCast(k - @as(u32, @intCast(i)))))
                    return error.InvalidCascadeProfile;
            }
        }
        const profile = xdm.Profile{
            .largest_log_size = k,
            .height_count = source_columns.len,
            .columns = columns,
            .query_count = 1,
        };
        try profile.validate();
        const layers = try allocator.alloc([]Hash, k + 1);
        var built: usize = 0;
        errdefer {
            for (layers[0..built]) |layer| allocator.free(layer);
            allocator.free(layers);
        }
        while (built < layers.len) : (built += 1)
            layers[built] = try allocator.alloc(Hash, @as(usize, 1) << @intCast(built));
        var values: [xdm.MAX_COLUMNS]M31 = undefined;
        for (layers[k], 0..) |*leaf, row| {
            for (source_columns[0], 0..) |column, col| values[col] = column[row];
            leaf.* = xdm.hashLeaf(values[0..source_columns[0].len]);
        }
        var level = k - 1;
        while (true) {
            const height = k - level;
            for (layers[level], 0..) |*node, row| {
                const pair = topology.children(level, row);
                const left = layers[level + 1][pair[0]];
                const right = layers[level + 1][pair[1]];
                if (height < source_columns.len) {
                    for (source_columns[height], 0..) |column, col| values[col] = column[row];
                    node.* = xdm.hashInserted(left, right, values[0..source_columns[height].len]);
                } else {
                    node.* = xdm.hashUpper(left, right);
                }
            }
            if (level == 0) break;
            level -= 1;
        }
        return .{ .allocator = allocator, .profile = profile, .layers = layers, .source_columns = source_columns };
    }

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
        try w.writeInt(u32, profile.largest_log_size, .little);
        try w.writeInt(u16, @intCast(profile.height_count), .little);
        try w.writeInt(u16, 0, .little);
        try w.writeInt(u32, @intCast(profile.query_count), .little);
        for (profile.columns[0..profile.height_count]) |count|
            try w.writeInt(u16, count, .little);
        const root_hash = self.root();
        try w.writeAll(&root_hash);
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const bottom = profile.bottomLevel();
        const active = try a.alloc([]bool, bottom + 1);
        for (active, 0..) |*bits, level| {
            bits.* = try a.alloc(bool, @as(usize, 1) << @intCast(level));
            @memset(bits.*, false);
        }
        for (raw_queries) |raw| {
            if (raw >= (@as(usize, 1) << @intCast(profile.largest_log_size)))
                return error.QueryPositionOutOfRange;
            try w.writeInt(u32, @intCast(raw), .little);
            const base = raw & ~(profile.width(0) - 1);
            for (self.source_columns, 0..) |height, i| {
                const width = profile.width(i);
                const row_base = base >> @intCast(i);
                for (0..width) |j| {
                    for (height) |column|
                        try w.writeInt(u32, column[row_base + j].toU32(), .little);
                    if (i + 1 == profile.height_count) active[bottom][row_base + j] = true;
                }
            }
        }
        const witness_offset = out.items.len;
        try w.writeInt(u32, 0, .little);
        var witness_count: u32 = 0;
        var level = bottom;
        while (level > 0) : (level -= 1) {
            for (active[level], 0..) |is_active, index| {
                if (!is_active) continue;
                const other = topology.sibling(@intCast(level), index);
                if (!active[level][other]) {
                    try w.writeAll(&self.layers[level][other]);
                    witness_count += 1;
                }
                active[level - 1][topology.parent(@intCast(level), index)] = true;
            }
        }
        if (out.items.len > xdm.MAX_WIRE_BYTES) return error.CascadeProofTooLarge;
        const encoded = try out.toOwnedSlice(allocator);
        std.mem.writeInt(u32, encoded[12..16], @intCast(encoded.len), .little);
        std.mem.writeInt(u32, encoded[witness_offset..][0..4], witness_count, .little);
        return encoded;
    }
};
