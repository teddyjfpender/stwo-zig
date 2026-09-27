//! Public-word restoration by aligned subtree replacements, sharing siblings
//! between the old/new paths. Public admission owns every replacement digest.
const std = @import("std");
const core = @import("stwo_core");
const tree = @import("../../air/memory_commitment/blake3_state_tree.zig");
const cover = @import("blake3_public_subtrees.zig");
const path = @import("blake3_public_subtree_path.zig");
pub const Edit = cover.Edit;
pub const STRIDE: u32 = 2 * (2 * tree.DEPTH + 1) + tree.DEPTH;
pub const Plan = struct {
    allocator: std.mem.Allocator,
    namespace: u32,
    source_circuit: u32,
    edits: []Edit,
    ranges: []cover.Range,
    roots: []tree.Digest,
    pub fn deinit(self: *Plan) void {
        self.allocator.free(self.edits);
        self.allocator.free(self.ranges);
        self.allocator.free(self.roots);
        self.* = undefined;
    }
    pub fn validate(self: *const Plan) !void {
        if (self.roots.len != self.ranges.len + 1 or self.namespace >= core.fields.m31.Modulus or self.source_circuit >= core.fields.m31.Modulus)
            return error.InvalidPublicSubtreeChain;
        const end = try std.math.add(u64, self.namespace, try std.math.mul(u64, self.ranges.len, STRIDE));
        if (end > core.fields.m31.Modulus or (self.source_circuit >= self.namespace and self.source_circuit < end)) return error.InvalidPublicSubtreeChain;
        var first: usize = 0;
        for (self.ranges) |range| {
            if (range.height > 28 or range.first_edit != first or range.count != @as(usize, 1) << range.height or range.count > self.edits.len - first or range.address % @as(u32, @intCast(range.count)) != 0)
                return error.InvalidPublicSubtreeChain;
            for (self.edits[first..][0..range.count], 0..) |edit, i| {
                if (edit.address >= tree.MEMORY_WORD_LIMIT or edit.address != @as(u64, range.address) + i or (first + i > 0 and self.edits[first + i - 1].address >= edit.address))
                    return error.InvalidPublicSubtreeChain;
            }
            first += range.count;
        }
        if (first != self.edits.len) return error.InvalidPublicSubtreeChain;
    }
    pub fn identity(self: *const Plan) ![32]u8 {
        try self.validate();
        var channel = core.channel.blake3.Channel{};
        channel.mixU32s(&.{ 0x42335053, 1, self.namespace, self.source_circuit, @intCast(self.edits.len), @intCast(self.ranges.len) });
        for (self.edits) |edit| channel.mixU32s(&.{ edit.address, edit.before, edit.after });
        const mix = @import("../../prover/blake3_execution_protocol.zig").mixDigest;
        for (self.ranges) |range| {
            channel.mixU32s(&.{ range.address, range.height });
            mix(&channel, range.before.bytes);
            mix(&channel, range.after.bytes);
        }
        for (self.roots) |root| mix(&channel, root.bytes);
        return channel.digestBytes();
    }
    pub fn admit(self: *const Plan, expected: [32]u8, before: tree.Digest, after: tree.Digest) !void {
        if (!std.mem.eql(u8, &try self.identity(), &expected) or !std.meta.eql(self.roots[0], before) or !std.meta.eql(self.roots[self.roots.len - 1], after))
            return error.UntrustedPublicSubtreeChain;
    }
    pub fn statements(self: *const Plan, index: usize) ![2]path.Statement {
        try self.validate();
        if (index >= self.ranges.len) return error.InvalidPublicSubtreeChain;
        const range = self.ranges[index];
        const namespace = self.namespace + @as(u32, @intCast(index)) * STRIDE;
        const width = 2 * tree.DEPTH + 1;
        const siblings = namespace + 2 * width;
        return .{
            .{ .namespace = namespace, .sibling_namespace = siblings, .address = range.address, .height = range.height, .subtree = range.before, .root = self.roots[index] },
            .{ .namespace = namespace + width, .sibling_namespace = siblings, .address = range.address, .height = range.height, .subtree = range.after, .root = self.roots[index + 1] },
        };
    }
};
pub fn planWitness(a: std.mem.Allocator, namespace: u32, source_circuit: u32, edits: []const Edit, initial: []const tree.Leaf) !Plan {
    const ranges = try cover.cover(a, edits);
    errdefer a.free(ranges);
    const owned = try a.dupe(Edit, edits);
    errdefer a.free(owned);
    const roots = try a.alloc(tree.Digest, ranges.len + 1);
    errdefer a.free(roots);
    const plan = Plan{ .allocator = a, .namespace = namespace, .source_circuit = source_circuit, .edits = owned, .ranges = ranges, .roots = roots };
    try plan.validate();
    const hasher = tree.TreeHasher.init(.memory);
    roots[0] = try hasher.root(initial);
    var leaves = try a.dupe(tree.Leaf, initial);
    defer a.free(leaves);
    for (ranges, 0..) |range, i| {
        const opening = try hasher.opening(leaves, range.address);
        if (!std.meta.eql(opening.root, roots[i])) return error.InvalidPublicSubtreeWitness;
        try checkSubtree(&hasher, leaves, range);
        roots[i + 1] = rootAfter(&hasher, range, &opening.siblings);
        const updated = try apply(a, leaves, edits[range.first_edit..][0..range.count]);
        a.free(leaves);
        leaves = updated;
    }
    if (!std.meta.eql(try hasher.root(leaves), roots[roots.len - 1])) return error.InvalidPublicSubtreeWitness;
    return plan;
}
fn rootAfter(hasher: *const tree.TreeHasher, range: cover.Range, siblings: *const [tree.DEPTH]tree.Digest) tree.Digest {
    var value = range.after;
    for (@as(usize, range.height)..tree.DEPTH) |level| {
        value = if ((range.address >> @as(u5, @intCast(level))) & 1 == 0) hasher.pair(value, siblings[level]) else hasher.pair(siblings[level], value);
    }
    return value;
}
fn checkSubtree(hasher: *const tree.TreeHasher, leaves: []const tree.Leaf, range: cover.Range) !void {
    var digest: [1]tree.Digest = undefined;
    try hasher.subtreeRoots(leaves, &.{.{ .level = range.height, .index = range.address >> range.height }}, &digest);
    if (!std.meta.eql(digest[0], range.before)) return error.InvalidPublicSubtreeWitness;
}
fn apply(a: std.mem.Allocator, leaves: []const tree.Leaf, edits: []const Edit) ![]tree.Leaf {
    var result: std.ArrayList(tree.Leaf) = .empty;
    errdefer result.deinit(a);
    try result.ensureTotalCapacity(a, try std.math.add(usize, leaves.len, edits.len));
    var i: usize = 0;
    for (edits) |edit| {
        while (i < leaves.len and leaves[i].index < edit.address) : (i += 1) result.appendAssumeCapacity(leaves[i]);
        const present = i < leaves.len and leaves[i].index == edit.address;
        if ((if (present) leaves[i].value else @as(u32, 0)) != edit.before) return error.InvalidPublicSubtreeWitness;
        if (present) i += 1;
        if (edit.after != 0) result.appendAssumeCapacity(.{ .index = edit.address, .value = edit.after });
    }
    try result.appendSlice(a, leaves[i..]);
    return result.toOwnedSlice(a);
}
pub const Pair = struct {
    before: path.Prepared,
    after: path.Prepared,
    pub fn deinit(self: *Pair) void {
        self.before.deinit();
        self.after.deinit();
        self.* = undefined;
    }
};
pub fn trusted(a: std.mem.Allocator, plan: *const Plan, index: usize) !Pair {
    return pair(a, try plan.statements(index), null);
}
fn pair(a: std.mem.Allocator, statements: [2]path.Statement, siblings: ?*const [tree.DEPTH]tree.Digest) !Pair {
    var before = if (siblings) |live| try path.prepare(a, statements[0], live) else try path.trusted(a, statements[0]);
    errdefer before.deinit();
    var after = if (siblings) |live| try path.prepare(a, statements[1], live) else try path.trusted(a, statements[1]);
    errdefer after.deinit();
    if (before.word_rows.len != after.word_rows.len) return error.InvalidPublicSubtreeWitness;
    for (before.word_rows, after.word_rows) |*source, duplicate| {
        for (source[0..7], duplicate[0..7]) |left, right| if (!left.eql(right)) return error.InvalidPublicSubtreeWitness;
        source[7] = core.fields.m31.M31.fromCanonical(try std.math.add(u32, source[7].toU32(), duplicate[7].toU32()));
    }
    after.word_rows = after.word_rows[0..0];
    return .{ .before = before, .after = after };
}
pub const Prepared = struct {
    allocator: std.mem.Allocator,
    updates: []Pair,
    pub fn deinit(self: *Prepared) void {
        for (self.updates) |*item| item.deinit();
        self.allocator.free(self.updates);
        self.* = undefined;
    }
};
pub fn prepare(a: std.mem.Allocator, plan: *const Plan, expected: [32]u8, before: tree.Digest, after: tree.Digest, initial: []const tree.Leaf) !Prepared {
    try plan.admit(expected, before, after);
    const hasher = tree.TreeHasher.init(.memory);
    if (!std.meta.eql(try hasher.root(initial), before)) return error.InvalidPublicSubtreeWitness;
    var leaves = try a.dupe(tree.Leaf, initial);
    defer a.free(leaves);
    const updates = try a.alloc(Pair, plan.ranges.len);
    errdefer a.free(updates);
    var count: usize = 0;
    errdefer for (updates[0..count]) |*item| item.deinit();
    for (plan.ranges, updates, 0..) |range, *item, i| {
        const opening = try hasher.opening(leaves, range.address);
        if (!std.meta.eql(opening.root, plan.roots[i]) or !std.meta.eql(rootAfter(&hasher, range, &opening.siblings), plan.roots[i + 1])) return error.InvalidPublicSubtreeWitness;
        try checkSubtree(&hasher, leaves, range);
        item.* = try pair(a, try plan.statements(i), &opening.siblings);
        count += 1;
        const updated = try apply(a, leaves, plan.edits[range.first_edit..][0..range.count]);
        a.free(leaves);
        leaves = updated;
    }
    return .{ .allocator = a, .updates = updates };
}
