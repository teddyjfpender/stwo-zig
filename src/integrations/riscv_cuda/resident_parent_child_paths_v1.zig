//! Cold canonical paths and private-word endpoint map. Values are supplied only
//! by raw packet / device FRI expansion; the CUDA kernel replays Merkle opening.
const std = @import("std");
const Packet = @import("resident_parent_child_packet_v1.zig");
const Profile = @import("../../frontends/riscv/recursion/block_v7_native_fixed_profile_v1.zig");
const Leaf = @import("../../frontends/riscv/recursion/air/blake3_lifted_leaf_plan.zig");
pub const Column = extern struct { first: u32, count: u32, log_size: u32 };
pub const Tree = extern struct { kind: u32, domain_log: u32, depth: u32, query_shift: u32, columns_first: u32 = 0, columns_count: u32 = 0, values_first: u32 = 0, leaf_width: u32 = 0, leaf_count: u32 = 1, hash_first: u32, hash_count: u32, root_first: u32, output_first: u32 = 0, ancestor_first: u32 = 0, frontier_first: u32 = 0 };
pub const Anchor = struct { circuit: u32, wire: u32, output: u32 };
pub const Limits = struct { max_output_words: usize = 1 << 24, max_trees: usize = 64 };
pub const Owned = struct {
    arena: std.heap.ArenaAllocator,
    trees: []const Tree,
    columns: []const Column,
    anchors: []const Anchor,
    output_words: u32,
    pub fn init(a: std.mem.Allocator, packet: *const Packet.Owned, profile: *const Profile.Owned, fri_expanded: []const Packet.Span, limits: Limits) !Owned {
        if (!std.meta.eql(packet.profile_id, profile.seal) or packet.query_count == 0 or packet.query_count > 128 or profile.shape.widths.len != fri_expanded.len) return error.InvalidResidentChildPaths;
        var arena = std.heap.ArenaAllocator.init(a);
        errdefer arena.deinit();
        const temp = arena.allocator();
        var b = Builder{ .a = temp, .limit = limits.max_output_words, .queries = packet.query_count };
        for (profile.shape.columns, 0..) |logs, index| {
            if (logs.len == 0) continue;
            var geometry = try Leaf.build(temp, logs);
            defer geometry.deinit();
            if (geometry.max_log > packet.domain_log) return error.UnqualifiedResidentPathHeight;
            const start = b.columns.items.len;
            for (geometry.order) |c| {
                const span = packet.queries[index][c];
                try b.columns.append(temp, .{ .first = span.first, .count = span.count, .log_size = geometry.logs[c] });
            }
            const h = packet.tree_hashes[index];
            try b.tree(.{ .kind = 0, .domain_log = packet.domain_log, .depth = geometry.max_log, .query_shift = packet.domain_log - geometry.max_log, .columns_first = @intCast(start), .columns_count = @intCast(logs.len), .hash_first = h.first, .hash_count = h.count, .root_first = packet.roots[index].first });
        }
        var remaining = packet.domain_log;
        for (profile.shape.widths, packet.layers, fri_expanded) |width, layer, span| {
            if (!std.math.isPowerOfTwo(width) or width < 2 or width > 1024) return error.InvalidResidentChildPaths;
            const step = std.math.log2_int(u32, width);
            if (step > remaining or span.count != @as(u64, packet.query_count) * width * 4) return error.InvalidResidentChildPaths;
            remaining -= step;
            const leaf_width: u32 = if (step > 1) 4 else 1;
            try b.tree(.{ .kind = 1, .domain_log = packet.domain_log, .depth = remaining, .query_shift = packet.domain_log - remaining, .values_first = span.first, .leaf_width = leaf_width * 4, .leaf_count = width / leaf_width, .hash_first = layer.hashes.first, .hash_count = layer.hashes.count, .root_first = layer.root.first });
        }
        if (b.trees.items.len == 0 or b.trees.items.len > limits.max_trees) return error.InvalidResidentChildPaths;
        return .{ .arena = arena, .trees = try b.trees.toOwnedSlice(temp), .columns = try b.columns.toOwnedSlice(temp), .anchors = try b.anchors.toOwnedSlice(temp), .output_words = @intCast(b.words) };
    }
    pub fn deinit(self: *Owned) void {
        self.arena.deinit();
        self.* = undefined;
    }
};
const Builder = struct {
    a: std.mem.Allocator,
    limit: usize,
    queries: u32,
    words: usize = 0,
    namespace: u32 = 2_000_000,
    trees: std.ArrayList(Tree) = .empty,
    columns: std.ArrayList(Column) = .empty,
    anchors: std.ArrayList(Anchor) = .empty,
    fn reserve(self: *Builder, n: usize) !u32 {
        const end = try std.math.add(usize, self.words, n);
        if (end > self.limit or end > std.math.maxInt(u32)) return error.ResidentChildPathLimit;
        const at = self.words;
        self.words = end;
        return @intCast(at);
    }
    fn add(self: *Builder, c: u32, w: u32, o: u32) !void {
        try self.anchors.append(self.a, .{ .circuit = c, .wire = w, .output = o });
    }
    fn tree(self: *Builder, template: Tree) !void {
        var t = template;
        if (t.depth > 30) return error.InvalidResidentChildPaths;
        t.output_first = try self.reserve(@as(usize, self.queries) * t.depth * 8);
        t.ancestor_first = try self.reserve(@as(usize, self.queries) * (t.depth + 1) * 8);
        t.frontier_first = try self.reserve(50);
        const frontier = t.depth >= 2 and self.queries > 1;
        if (frontier) {
            for (0..32) |w| try self.add(self.namespace, @intCast(w), t.frontier_first + 2 + @as(u32, @intCast(w)));
            for (0..2) |w| try self.add(self.namespace, 32 + @as(u32, @intCast(w)), t.frontier_first + @as(u32, @intCast(w)));
            for (0..16) |w| try self.add(self.namespace + 1, @intCast(w), t.frontier_first + 34 + @as(u32, @intCast(w)));
            self.namespace = try std.math.add(u32, self.namespace, 7 + self.queries);
        }
        const leaf_span = 2 * t.leaf_count - 1;
        const span = try std.math.add(u32, leaf_span, 3 * t.depth);
        for (0..self.queries) |q| {
            const levels = t.depth - @as(u32, @intFromBool(frontier));
            for (0..levels) |level| for (0..8) |word| {
                try self.add(self.namespace + leaf_span + 3 * @as(u32, @intCast(level)), @intCast(word), t.output_first + @as(u32, @intCast((q * t.depth + level) * 8 + word)));
            };
            self.namespace = try std.math.add(u32, self.namespace, span);
            if (self.namespace >= 3_000_000) return error.ResidentChildPathLimit;
        }
        try self.trees.append(self.a, t);
    }
};
