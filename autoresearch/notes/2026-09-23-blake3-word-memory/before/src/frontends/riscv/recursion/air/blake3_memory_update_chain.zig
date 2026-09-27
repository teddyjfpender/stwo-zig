//! Canonical multi-byte root transition, reusing the shared-sibling byte update.
//! Admission owns edits and every root. Execution custody must authenticate the
//! endpoint roots and edit values before admitting this specialized plan.
const std = @import("std");
const core = @import("stwo_core");
const tree = @import("../../air/memory_commitment/blake3_byte_tree.zig");
const update = @import("blake3_memory_update.zig");
const boundary = @import("blake3_boundary.zig");
pub const Edit = struct { address: u32, before: u8, after: u8 };
pub const STRIDE: u32 = 2 * (2 * tree.DEPTH + 1) + tree.DEPTH;
pub const Plan = struct {
    allocator: std.mem.Allocator,
    namespace: u32,
    source_circuit: u32,
    edits: []Edit,
    roots: []tree.Digest,
    pub fn init(a: std.mem.Allocator, namespace: u32, source_circuit: u32, edits: []const Edit, roots: []const tree.Digest) !Plan {
        const owned = try a.dupe(Edit, edits);
        errdefer a.free(owned);
        const owned_roots = try a.dupe(tree.Digest, roots);
        errdefer a.free(owned_roots);
        const self = Plan{ .allocator = a, .namespace = namespace, .source_circuit = source_circuit, .edits = owned, .roots = owned_roots };
        try self.validate();
        return self;
    }
    pub fn deinit(self: *Plan) void {
        self.allocator.free(self.edits);
        self.allocator.free(self.roots);
        self.* = undefined;
    }
    pub fn validate(self: *const Plan) !void {
        if (self.edits.len >= core.fields.m31.Modulus / 2 or self.roots.len != self.edits.len + 1 or self.namespace >= core.fields.m31.Modulus or self.source_circuit >= core.fields.m31.Modulus) return error.InvalidMemoryUpdateChain;
        const end = try std.math.add(u64, self.namespace, try std.math.mul(u64, self.edits.len, STRIDE));
        if (end > core.fields.m31.Modulus or (self.source_circuit >= self.namespace and self.source_circuit < end)) return error.InvalidMemoryUpdateChain;
        for (self.edits, 0..) |edit, i| {
            if (edit.address >= tree.ADDRESS_LIMIT or (i > 0 and self.edits[i - 1].address >= edit.address)) return error.InvalidMemoryUpdateChain;
        }
    }
    pub fn identity(self: *const Plan) ![32]u8 {
        try self.validate();
        var channel = core.channel.blake3.Channel{};
        channel.mixU32s(&.{ 0x42334d55, 1, self.namespace, self.source_circuit, @intCast(self.edits.len) });
        for (self.edits) |edit| channel.mixU32s(&.{ edit.address, edit.before, edit.after });
        for (self.roots) |root| @import("../../prover/blake3_execution_protocol.zig").mixDigest(&channel, root.bytes);
        return channel.digestBytes();
    }
    pub fn admit(self: *const Plan, expected: [32]u8, before: tree.Digest, after: tree.Digest) !void {
        if (!std.mem.eql(u8, &try self.identity(), &expected) or !std.meta.eql(self.roots[0], before) or !std.meta.eql(self.roots[self.roots.len - 1], after)) return error.UntrustedMemoryUpdateChain;
    }
    pub fn statement(self: *const Plan, index: usize) !update.Statement {
        try self.validate();
        if (index >= self.edits.len) return error.InvalidMemoryUpdateChain;
        return .{ .namespace = self.namespace + @as(u32, @intCast(index)) * STRIDE, .kind = .memory, .address = self.edits[index].address, .before_source = .{ .circuit = self.source_circuit, .wire = @intCast(2 * index) }, .after_source = .{ .circuit = self.source_circuit, .wire = @intCast(2 * index + 1) }, .before_root = self.roots[index], .after_root = self.roots[index + 1] };
    }
};
/// Derive intermediate roots from a private snapshot. This is witness planning,
/// not admission: custody and span endpoints must be checked independently.
pub fn planWitness(a: std.mem.Allocator, namespace: u32, source_circuit: u32, edits: []const Edit, initial: []const tree.Leaf) !Plan {
    const roots = try a.alloc(tree.Digest, try std.math.add(usize, edits.len, 1));
    defer a.free(roots);
    // Validate shape/namespaces before constructing any tree paths.
    const shape = Plan{ .allocator = a, .namespace = namespace, .source_circuit = source_circuit, .edits = @constCast(edits), .roots = roots };
    try shape.validate();
    var leaves: std.ArrayList(tree.Leaf) = .empty;
    defer leaves.deinit(a);
    try leaves.appendSlice(a, initial);
    const hasher = tree.TreeHasher.init(.memory);
    roots[0] = try hasher.root(leaves.items);
    for (edits, 0..) |edit, i| {
        const opening = try hasher.opening(leaves.items, edit.address);
        if (opening.value != edit.before) return error.InvalidMemoryChainWitness;
        try apply(a, &leaves, edit);
        roots[i + 1] = try hasher.root(leaves.items);
    }
    return Plan.init(a, namespace, source_circuit, edits, roots);
}
pub const Prepared = struct {
    allocator: std.mem.Allocator,
    updates: []update.Prepared,
    /// Public byte producers. These values are admitted plan constants, not
    /// unauthenticated execution witnesses or a substitute for custody binding.
    sources: []boundary.Row,
    pub fn deinit(self: *Prepared) void {
        for (self.updates) |*item| item.deinit();
        self.allocator.free(self.updates);
        self.allocator.free(self.sources);
        self.* = undefined;
    }
};
/// Reconstruct fixed path geometry solely from a caller-pinned plan.
pub fn trusted(a: std.mem.Allocator, plan: *const Plan, expected: [32]u8, before: tree.Digest, after: tree.Digest) !Prepared {
    try plan.admit(expected, before, after);
    const updates = try a.alloc(update.Prepared, plan.edits.len);
    errdefer a.free(updates);
    var built: usize = 0;
    errdefer for (updates[0..built]) |*item| item.deinit();
    const sources = try a.alloc(boundary.Row, plan.edits.len * 2);
    errdefer a.free(sources);
    for (updates, 0..) |*item, index| {
        item.* = try update.trusted(a, try plan.statement(index));
        built += 1;
        try sourceRows(plan, sources, index);
    }
    return .{ .allocator = a, .updates = updates, .sources = sources };
}
fn sourceRows(plan: *const Plan, sources: []boundary.Row, index: usize) !void {
    const edit = plan.edits[index];
    sources[2 * index] = try boundary.logicalRow(plan.source_circuit, @intCast(2 * index), core.fields.m31.M31.one(), edit.before);
    sources[2 * index + 1] = try boundary.logicalRow(plan.source_circuit, @intCast(2 * index + 1), core.fields.m31.M31.one(), edit.after);
}
pub fn prepare(a: std.mem.Allocator, plan: *const Plan, expected: [32]u8, before: tree.Digest, after: tree.Digest, initial: []const tree.Leaf) !Prepared {
    try plan.admit(expected, before, after);
    const hasher = tree.TreeHasher.init(.memory);
    if (!std.meta.eql(try hasher.root(initial), before)) return error.InvalidMemoryChainWitness;
    var leaves: std.ArrayList(tree.Leaf) = .empty;
    defer leaves.deinit(a);
    try leaves.appendSlice(a, initial);
    const updates = try a.alloc(update.Prepared, plan.edits.len);
    errdefer a.free(updates);
    var built: usize = 0;
    errdefer for (updates[0..built]) |*item| item.deinit();
    const sources = try a.alloc(boundary.Row, plan.edits.len * 2);
    errdefer a.free(sources);
    for (plan.edits, updates, 0..) |edit, *item, index| {
        const opening = try hasher.opening(leaves.items, edit.address);
        if (opening.value != edit.before or !std.meta.eql(opening.root, plan.roots[index])) return error.InvalidMemoryChainWitness;
        try apply(a, &leaves, edit);
        if (!std.meta.eql(try hasher.root(leaves.items), plan.roots[index + 1])) return error.InvalidMemoryChainWitness;
        item.* = try update.prepare(a, try plan.statement(index), edit.before, edit.after, &opening.siblings);
        built += 1;
        try sourceRows(plan, sources, index);
    }
    return .{ .allocator = a, .updates = updates, .sources = sources };
}
fn apply(a: std.mem.Allocator, leaves: *std.ArrayList(tree.Leaf), edit: Edit) !void {
    var index: usize = 0;
    while (index < leaves.items.len and leaves.items[index].index < edit.address) : (index += 1) {}
    if (index < leaves.items.len and leaves.items[index].index == edit.address) {
        if (edit.after == 0) _ = leaves.orderedRemove(index) else leaves.items[index].value = edit.after;
    } else if (edit.after != 0) try leaves.insert(a, index, .{ .index = edit.address, .value = edit.after });
}
