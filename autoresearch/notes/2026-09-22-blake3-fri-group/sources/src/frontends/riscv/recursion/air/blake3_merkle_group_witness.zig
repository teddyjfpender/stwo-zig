//! Complete binary subtree from authenticated payload words, then an upper path.
//! Caller supplies canonical word producers with the returned payload use counts.
const std = @import("std");
const core = @import("stwo_core");
const frame = @import("blake3_frame_witness.zig");
const routing = @import("blake3_frame_route.zig");
const graph = @import("blake3_hash_plan.zig");
const path = @import("blake3_merkle_path_witness.zig");
pub const g = path.g;
pub const xor = path.xor;
pub const boundary = path.boundary;
pub const route = path.route;
pub const word = path.word;
const M31 = core.fields.m31.M31;
const Digest = [32]u8;
pub const Statement = struct {
    namespace: u32,
    payload: routing.Caller,
    leaf_count: u32,
    words_per_leaf: u32,
    index: u32,
    depth: u5,
    root: Digest,
};
pub const Prepared = struct {
    arena: std.heap.ArenaAllocator,
    g_rows: []g.Row,
    xor_rows: []xor.Row,
    boundary_rows: []boundary.Row,
    route_rows: []route.Row,
    word_rows: []word.Row,
    payload_uses: []u32,
    computed_root: ?Digest,
    pub fn deinit(self: *Prepared) void {
        self.arena.deinit();
        self.* = undefined;
    }
};
const Node = struct { data: frame.Prepared, caller: routing.Caller };
pub fn prepare(a: std.mem.Allocator, s: Statement, values: []const M31, siblings: []const Digest) !Prepared {
    if (siblings.len != s.depth) return error.InvalidBlake3MerkleGroup;
    return build(a, s, values, siblings);
}
pub fn trusted(a: std.mem.Allocator, s: Statement) !Prepared {
    return build(a, s, null, null);
}
fn build(backing: std.mem.Allocator, s: Statement, values: ?[]const M31, siblings: ?[]const Digest) !Prepared {
    const fail = error.InvalidBlake3MerkleGroup;
    if (s.leaf_count == 0 or !std.math.isPowerOfTwo(s.leaf_count) or s.words_per_leaf == 0 or
        @as(u64, s.index) >= @as(u64, 1) << @as(u6, s.depth)) return fail;
    const node_count = std.math.sub(u32, std.math.mul(u32, s.leaf_count, 2) catch return fail, 1) catch return fail;
    const total = std.math.add(u32, node_count, 2 * @as(u32, s.depth)) catch return fail;
    const end = std.math.add(u32, s.namespace, total) catch return fail;
    const word_count = std.math.mul(u32, s.leaf_count, s.words_per_leaf) catch return fail;
    const payload_end = std.math.add(u32, s.payload.first_wire, word_count) catch return fail;
    if (end > core.fields.m31.Modulus or payload_end > core.fields.m31.Modulus or
        s.payload.circuit >= core.fields.m31.Modulus or
        (s.payload.circuit >= s.namespace and s.payload.circuit < end)) return fail;
    if (values) |v| if (v.len != word_count) return fail;
    var arena = std.heap.ArenaAllocator.init(backing);
    errdefer arena.deinit();
    const a = arena.allocator();
    var nodes: std.ArrayList(Node) = .empty;
    const uses = try a.alloc(u32, word_count);
    const zeros = try a.alloc(M31, s.words_per_leaf);
    @memset(zeros, M31.zero());
    var next = s.namespace;
    for (0..s.leaf_count) |i| {
        const start = i * s.words_per_leaf;
        const input = if (values) |v| v[start..][0..s.words_per_leaf] else zeros;
        const f = core.channel.blake3.Frame{ .leaf = input };
        const payload = frame.PayloadBinding{ .role = .leaf, .caller = .{ .circuit = s.payload.circuit, .first_wire = s.payload.first_wire + @as(u32, @intCast(start)) }, .word_count = s.words_per_leaf };
        const claim: Digest = if (total == 1) s.root else @splat(0);
        const data = if (values != null) try frame.preparePayload(a, next, f, &.{}, payload, claim) else try frame.trustedPayload(a, next, f, &.{}, payload, claim);
        @memcpy(uses[start..][0..s.words_per_leaf], data.payload_uses);
        try nodes.append(a, .{ .data = data, .caller = try output(a, next, try f.encodedSize()) });
        next += 1;
    }
    var level_start: usize = 0;
    var count: usize = s.leaf_count;
    while (count > 1) {
        const parent_start = nodes.items.len;
        for (0..count / 2) |i| {
            const left = level_start + 2 * i;
            const right = left + 1;
            const claim: Digest = if (count == 2 and s.depth == 0) s.root else @splat(0);
            const parent = try merge(a, next, .{ nodes.items[left].caller, nodes.items[right].caller }, .{ nodes.items[left].data.digest orelse @splat(0), nodes.items[right].data.digest orelse @splat(0) }, claim, values != null);
            consume(&nodes.items[left], parent.data.source_uses[0]);
            consume(&nodes.items[right], parent.data.source_uses[1]);
            try nodes.append(a, parent);
            next += 1;
        }
        level_start = parent_start;
        count /= 2;
    }
    var words: std.ArrayList(word.Row) = .empty;
    for (0..s.depth) |level| {
        const current = nodes.items.len - 1;
        const side: usize = @intCast((s.index >> @as(u5, @intCast(level))) & 1);
        var callers: [2]routing.Caller = undefined;
        var digests: [2]Digest = undefined;
        callers[side] = nodes.items[current].caller;
        callers[1 - side] = .{ .circuit = next, .first_wire = 0 };
        digests[side] = nodes.items[current].data.digest orelse @splat(0);
        digests[1 - side] = if (siblings) |v| v[level] else @splat(0);
        const parent = try merge(a, next + 1, callers, digests, if (level + 1 == s.depth) s.root else @splat(0), values != null);
        consume(&nodes.items[current], parent.data.source_uses[side]);
        for (parent.data.source_uses[1 - side], 0..) |n, i| try words.append(a, try word.logicalRow(next, @intCast(i), n, std.mem.readInt(u32, digests[1 - side][4 * i ..][0..4], .little)));
        try nodes.append(a, parent);
        next += 2;
    }
    var gs: std.ArrayList(g.Row) = .empty;
    var xs: std.ArrayList(xor.Row) = .empty;
    var bs: std.ArrayList(boundary.Row) = .empty;
    var rs: std.ArrayList(route.Row) = .empty;
    for (nodes.items, 0..) |node, i| {
        try gs.appendSlice(a, node.data.rows.g_rows);
        try xs.appendSlice(a, node.data.rows.xor_rows);
        const boundaries = node.data.rows.boundary_rows;
        try bs.appendSlice(a, boundaries[0 .. boundaries.len - (if (i + 1 == nodes.items.len) @as(usize, 0) else 8)]);
        try rs.appendSlice(a, node.data.route_rows);
    }
    const g_rows = try gs.toOwnedSlice(a);
    const xor_rows = try xs.toOwnedSlice(a);
    const boundary_rows = try bs.toOwnedSlice(a);
    const route_rows = try rs.toOwnedSlice(a);
    const word_rows = try words.toOwnedSlice(a);
    return .{ .arena = arena, .g_rows = g_rows, .xor_rows = xor_rows, .boundary_rows = boundary_rows, .route_rows = route_rows, .word_rows = word_rows, .payload_uses = uses, .computed_root = nodes.items[nodes.items.len - 1].data.digest };
}
fn consume(node: *Node, uses: [8]u32) void {
    for (uses, 0..) |n, i| node.data.rows.xor_rows[node.data.rows.xor_rows.len - 16 + i][17] = M31.fromCanonical(n);
}
fn output(a: std.mem.Allocator, circuit: u32, len: usize) !routing.Caller {
    var plan = try graph.build(a, len);
    defer plan.deinit();
    for (plan.output, 0..) |wire, i| if (wire != plan.output[0] + i) return error.InvalidBlake3MerkleGroup;
    return .{ .circuit = circuit, .first_wire = plan.output[0] };
}
fn merge(a: std.mem.Allocator, circuit: u32, callers: [2]routing.Caller, digests: [2]Digest, claim: Digest, live: bool) !Node {
    const f = core.channel.blake3.Frame{ .node = .{ .left = digests[0], .right = digests[1] } };
    const bindings = [_]frame.Binding{ .{ .role = .left, .caller = callers[0] }, .{ .role = .right, .caller = callers[1] } };
    const data = if (live) try frame.prepare(a, circuit, f, &bindings, claim) else try frame.trusted(a, circuit, f, &bindings, claim);
    return .{ .data = data, .caller = try output(a, circuit, try f.encodedSize()) };
}
