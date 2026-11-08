//! Compact native lifted-Merkle readback formatting, with no prover arithmetic.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
pub const H = @import("fri.zig").H;
const Merkle = core.vcs_lifted.verifier;
pub const Geometry = struct {
    tree_log: u32,
    lifting_log: u32,
    /// Ascending heights and their original PCS column ordinals.
    column_logs: []const u32,
    column_order: []const u32,
    pub fn validate(self: @This(), a: std.mem.Allocator) !void {
        if (self.tree_log < 1 or self.tree_log > 28 or self.lifting_log < 1 or self.lifting_log > 28 or self.column_logs.len == 0 or self.column_logs.len > 65536 or self.column_order.len != self.column_logs.len) return error.InvalidTraceGeometry;
        const seen = try a.alloc(bool, self.column_logs.len);
        defer a.free(seen);
        @memset(seen, false);
        var previous: u32 = 0;
        for (self.column_logs, self.column_order) |log, order| {
            if (log < 1 or log > self.tree_log or log < previous or order >= seen.len or seen[order]) return error.InvalidTraceGeometry;
            seen[order] = true;
            previous = log;
        }
    }
    pub fn treeWords(self: @This()) usize {
        return ((@as(usize, 2) << @intCast(self.tree_log)) - 1) * 8;
    }
};
pub const Readback = struct { root: [8]u32, values: []const u32, paths: []const u32 };
pub const Opening = struct {
    root: H.Hash,
    queried_values: [][]M,
    decommitment: Merkle.MerkleDecommitmentLifted(H),
    pub fn deinit(self: *@This(), a: std.mem.Allocator) void {
        for (self.queried_values) |v| a.free(v);
        a.free(self.queried_values);
        self.decommitment.deinit(a);
        self.* = undefined;
    }
};
pub fn position(row: usize, from: u32, to: u32) usize {
    return if (from >= to) ((row >> @intCast(from - to + 1)) << 1) | (row & 1) else ((row >> 1) << @intCast(to - from + 1)) | (row & 1);
}
fn digest(words: []const u32) H.Hash {
    var h: H.Hash = undefined;
    for (words, 0..) |v, i| std.mem.writeInt(u32, h[4 * i ..][0..4], v, .little);
    return h;
}
pub fn assemble(a: std.mem.Allocator, g: Geometry, raw: []const u32, data: Readback) !Opening {
    try g.validate(a);
    if (raw.len == 0 or raw.len > 1024 or data.values.len != raw.len * g.column_logs.len or data.paths.len != raw.len * g.tree_log * 8) return error.InvalidTraceReadback;
    const indices = try a.alloc(usize, raw.len);
    defer a.free(indices);
    const tree_positions = try a.alloc(usize, raw.len);
    defer a.free(tree_positions);
    for (raw, indices, tree_positions, 0..) |q, *index, *p, i| {
        if (q >= @as(u32, 1) << @intCast(g.lifting_log)) return error.InvalidTraceQuery;
        index.* = i;
        p.* = position(q, g.lifting_log, g.tree_log);
    }
    const Order = struct {
        raw: []const u32,
        fn less(self: @This(), lhs: usize, rhs: usize) bool {
            return self.raw[lhs] < self.raw[rhs] or (self.raw[lhs] == self.raw[rhs] and lhs < rhs);
        }
    };
    std.sort.heap(usize, indices, Order{ .raw = raw }, Order.less);
    var representatives: std.ArrayList(usize) = .empty;
    defer representatives.deinit(a);
    for (indices) |i| if (representatives.items.len == 0 or raw[representatives.items[representatives.items.len - 1]] != raw[i]) {
        try representatives.append(a, i);
    };
    const sorted_values = try a.alloc([]M, g.column_logs.len);
    defer a.free(sorted_values);
    var initialized: usize = 0;
    errdefer for (sorted_values[0..initialized]) |v| a.free(v);
    var seen = std.AutoHashMap(usize, u32).init(a);
    defer seen.deinit();
    for (g.column_logs, sorted_values, 0..) |log, *column, ci| {
        seen.clearRetainingCapacity();
        for (raw, 0..) |q, qi| {
            const value = data.values[ci * raw.len + qi];
            if (value >= core.fields.m31.Modulus) return error.NoncanonicalTraceValue;
            const p = position(position(q, g.lifting_log, g.tree_log), g.tree_log, log);
            if (seen.get(p)) |old| {
                if (old != value) return error.InconsistentTraceReadback;
            } else try seen.put(p, value);
        }
        column.* = try a.alloc(M, representatives.items.len);
        initialized += 1;
        for (representatives.items, column.*) |qi, *v| v.* = M.fromCanonical(data.values[ci * raw.len + qi]);
    }
    var hashes = std.AutoHashMap(u64, H.Hash).init(a);
    defer hashes.deinit();
    for (tree_positions, 0..) |p, qi| for (0..g.tree_log) |level| {
        const sibling = (p >> @intCast(level)) ^ 1;
        const key = (@as(u64, level) << 32) | sibling;
        const h = digest(data.paths[(qi * g.tree_log + level) * 8 ..][0..8]);
        if (hashes.get(key)) |old| {
            if (!std.mem.eql(u8, &old, &h)) return error.InconsistentTraceReadback;
        } else try hashes.put(key, h);
    };
    var current = try core.queries.sortedUniquePositions(a, tree_positions);
    defer a.free(current);
    var witness: std.ArrayList(H.Hash) = .empty;
    defer witness.deinit(a);
    for (0..g.tree_log) |level| {
        var next: std.ArrayList(usize) = .empty;
        defer next.deinit(a);
        var i: usize = 0;
        while (i < current.len) {
            const first = current[i];
            const paired = i + 1 < current.len and current[i + 1] == (first ^ 1);
            if (!paired) try witness.append(a, hashes.get((@as(u64, level) << 32) | (first ^ 1)) orelse return error.MissingTraceReadback);
            try next.append(a, first >> 1);
            i += if (paired) @as(usize, 2) else 1;
        }
        const owned = try next.toOwnedSlice(a);
        a.free(current);
        current = owned;
    }
    const hash_witness = try witness.toOwnedSlice(a);
    errdefer a.free(hash_witness);
    const output = try a.alloc([]M, sorted_values.len);
    for (sorted_values, g.column_order) |column, order| output[order] = column;
    return .{ .root = digest(&data.root), .queried_values = output, .decommitment = .{ .hash_witness = hash_witness } };
}
