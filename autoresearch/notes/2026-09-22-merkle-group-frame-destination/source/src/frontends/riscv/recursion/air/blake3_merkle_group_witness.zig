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
pub const select = @import("blake3_path_select.zig");
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
    /// Each canonical root word must be produced once for this opening.
    root_source: ?routing.Caller = null,
    directions: ?[]const select.Endpoint = null,
};
pub const Prepared = struct {
    arena: std.heap.ArenaAllocator,
    g_rows: []g.Row,
    xor_rows: []xor.Row,
    boundary_rows: []boundary.Row,
    route_rows: []route.Row,
    word_rows: []word.Row,
    select_rows: []select.Row,
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
    const total = std.math.add(u32, node_count, @as(u32, if (s.directions != null) 3 else 2) * @as(u32, s.depth)) catch return fail;
    const end = std.math.add(u32, s.namespace, total) catch return fail;
    const word_count = std.math.mul(u32, s.leaf_count, s.words_per_leaf) catch return fail;
    const payload_end = std.math.add(u32, s.payload.first_wire, word_count) catch return fail;
    if (end > core.fields.m31.Modulus or payload_end > core.fields.m31.Modulus or
        s.payload.circuit >= core.fields.m31.Modulus or
        (s.payload.circuit >= s.namespace and s.payload.circuit < end)) return fail;
    if (s.directions) |directions| {
        if (directions.len != s.depth) return fail;
        for (directions) |source| if (source.circuit >= core.fields.m31.Modulus or source.wire >= core.fields.m31.Modulus or (source.circuit >= s.namespace and source.circuit < end)) return fail;
    }
    if (s.root_source) |source| {
        if (source.circuit >= core.fields.m31.Modulus or
            @as(u64, source.first_wire) + 8 > core.fields.m31.Modulus or
            (source.circuit >= s.namespace and source.circuit < end)) return fail;
    }
    if (values) |v| if (v.len != word_count) return fail;
    var arena = std.heap.ArenaAllocator.init(backing);
    errdefer arena.deinit();
    const a = arena.allocator();
    var nodes: std.ArrayList(Node) = .empty;
    defer for (nodes.items) |*node| node.data.deinit();
    const uses = try a.alloc(u32, word_count);
    const zeros = try a.alloc(M31, s.words_per_leaf);
    @memset(zeros, M31.zero());
    const leaf_shape = try hashCounts(backing, try (core.channel.blake3.Frame{ .leaf = zeros }).encodedSize());
    const node_shape = try hashCounts(backing, try (core.channel.blake3.Frame{ .node = .{ .left = @splat(0), .right = @splat(0) } }).encodedSize());
    const merges = try std.math.add(usize, s.leaf_count - 1, s.depth);
    var destination = HashRows{
        .g_rows = try a.alloc(g.Row, try std.math.add(usize, try std.math.mul(usize, s.leaf_count, leaf_shape.g), try std.math.mul(usize, merges, node_shape.g))),
        .xor_rows = try a.alloc(xor.Row, try std.math.add(usize, try std.math.mul(usize, s.leaf_count, leaf_shape.xor), try std.math.mul(usize, merges, node_shape.xor))),
    };
    var next = s.namespace;
    for (0..s.leaf_count) |i| {
        const start = i * s.words_per_leaf;
        const input = if (values) |v| v[start..][0..s.words_per_leaf] else zeros;
        const f = core.channel.blake3.Frame{ .leaf = input };
        const payload = frame.PayloadBinding{ .role = .leaf, .caller = .{ .circuit = s.payload.circuit, .first_wire = s.payload.first_wire + @as(u32, @intCast(start)) }, .word_count = s.words_per_leaf };
        const claim: Digest = if (total == 1) s.root else @splat(0);
        const out = try destination.take(leaf_shape);
        var data = if (values != null) try frame.prepareInto(backing, next, f, &.{}, payload, claim, out) else try frame.trustedInto(backing, next, f, &.{}, payload, claim, out);
        errdefer data.deinit();
        @memcpy(uses[start..][0..s.words_per_leaf], data.payload_uses);
        try nodes.append(a, .{ .data = data, .caller = try output(backing, next, try f.encodedSize()) });
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
            var parent = try merge(backing, next, .{ nodes.items[left].caller, nodes.items[right].caller }, .{ nodes.items[left].data.digest orelse @splat(0), nodes.items[right].data.digest orelse @splat(0) }, claim, values != null, try destination.take(node_shape));
            errdefer parent.data.deinit();
            consume(&nodes.items[left], parent.data.source_uses[0]);
            consume(&nodes.items[right], parent.data.source_uses[1]);
            try nodes.append(a, parent);
            next += 1;
        }
        level_start = parent_start;
        count /= 2;
    }
    var words: std.ArrayList(word.Row) = .empty;
    var selections: std.ArrayList(select.Row) = .empty;
    for (0..s.depth) |level| {
        const current = nodes.items.len - 1;
        const side: usize = @intCast((s.index >> @as(u5, @intCast(level))) & 1);
        var callers: [2]routing.Caller = undefined;
        var digests: [2]Digest = undefined;
        callers[side] = nodes.items[current].caller;
        callers[1 - side] = .{ .circuit = next, .first_wire = 0 };
        digests[side] = nodes.items[current].data.digest orelse @splat(0);
        digests[1 - side] = if (siblings) |v| v[level] else @splat(0);
        if (s.directions) |directions| {
            const selected = [2]routing.Caller{ .{ .circuit = next + 1, .first_wire = 0 }, .{ .circuit = next + 1, .first_wire = 8 } };
            var parent = try merge(backing, next + 2, selected, digests, if (level + 1 == s.depth) s.root else @splat(0), values != null, try destination.take(node_shape));
            errdefer parent.data.deinit();
            consume(&nodes.items[current], @splat(1));
            const current_digest = digests[side];
            const sibling_digest = digests[1 - side];
            for (0..8) |i| {
                const sibling_word = std.mem.readInt(u32, sibling_digest[4 * i ..][0..4], .little);
                try words.append(a, try word.logicalRow(next, @intCast(i), 1, sibling_word));
                const schedule = select.Schedule{ .bit = directions[level], .current = .{ .circuit = nodes.items[current].caller.circuit, .wire = nodes.items[current].caller.first_wire + @as(u32, @intCast(i)) }, .sibling = .{ .circuit = next, .wire = @intCast(i) }, .destination_circuit = next + 1, .left_wire = @intCast(i), .right_wire = @intCast(8 + i), .left_uses = parent.data.source_uses[0][i], .right_uses = parent.data.source_uses[1][i] };
                try selections.append(a, if (values != null) try select.logicalRow(schedule, @intCast(side), std.mem.readInt(u32, current_digest[4 * i ..][0..4], .little), sibling_word) else try select.fixedRow(schedule));
            }
            try nodes.append(a, parent);
            next += 3;
        } else {
            var parent = try merge(backing, next + 1, callers, digests, if (level + 1 == s.depth) s.root else @splat(0), values != null, try destination.take(node_shape));
            errdefer parent.data.deinit();
            consume(&nodes.items[current], parent.data.source_uses[side]);
            for (parent.data.source_uses[1 - side], 0..) |n, i| try words.append(a, try word.logicalRow(next, @intCast(i), n, std.mem.readInt(u32, digests[1 - side][4 * i ..][0..4], .little)));
            try nodes.append(a, parent);
            next += 2;
        }
    }
    if (destination.g_used != destination.g_rows.len or destination.xor_used != destination.xor_rows.len) return error.InvalidBlake3MerkleGroup;
    var bs: std.ArrayList(boundary.Row) = .empty;
    var rs: std.ArrayList(route.Row) = .empty;
    for (nodes.items, 0..) |node, i| {
        const boundaries = node.data.rows.boundary_rows;
        try bs.appendSlice(a, boundaries[0 .. boundaries.len - (if (i + 1 == nodes.items.len and s.root_source == null) @as(usize, 0) else 8)]);
        try rs.appendSlice(a, node.data.route_rows);
    }
    if (s.root_source) |source| {
        const last = nodes.items[nodes.items.len - 1];
        const digest = last.data.digest orelse @as(Digest, @splat(0));
        for (0..8) |i| {
            const schedule = try rootEquality(last.caller, source, @intCast(i));
            try rs.append(a, if (values != null) try route.logicalRow(schedule, .{ std.mem.readInt(u32, digest[4 * i ..][0..4], .little), 0 }) else try route.fixedRow(schedule));
        }
    }
    const boundary_rows = try bs.toOwnedSlice(a);
    const route_rows = try rs.toOwnedSlice(a);
    const word_rows = try words.toOwnedSlice(a);
    return .{ .select_rows = try selections.toOwnedSlice(a), .arena = arena, .g_rows = destination.g_rows, .xor_rows = destination.xor_rows, .boundary_rows = boundary_rows, .route_rows = route_rows, .word_rows = word_rows, .payload_uses = uses, .computed_root = nodes.items[nodes.items.len - 1].data.digest };
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
fn merge(a: std.mem.Allocator, circuit: u32, callers: [2]routing.Caller, digests: [2]Digest, claim: Digest, live: bool, destination: frame.HashDestination) !Node {
    const f = core.channel.blake3.Frame{ .node = .{ .left = digests[0], .right = digests[1] } };
    const bindings = [_]frame.Binding{ .{ .role = .left, .caller = callers[0] }, .{ .role = .right, .caller = callers[1] } };
    var data = if (live) try frame.prepareInto(a, circuit, f, &bindings, null, claim, destination) else try frame.trustedInto(a, circuit, f, &bindings, null, claim, destination);
    errdefer data.deinit();
    return .{ .data = data, .caller = try output(a, circuit, try f.encodedSize()) };
}

/// Two consumes with identical bytes: computed digest and canonical root.
pub fn rootEquality(computed: routing.Caller, canonical: routing.Caller, word_index: u3) !route.Schedule {
    if (computed.circuit == canonical.circuit) return error.InvalidBlake3MerkleGroup;
    return .{ .sources = .{ .{ .circuit = computed.circuit, .wire = try std.math.add(u32, computed.first_wire, word_index) }, null }, .destination = .{ .circuit = canonical.circuit, .wire = try std.math.add(u32, canonical.first_wire, word_index) }, .uses = core.fields.m31.Modulus - 1, .bytes = .{ .{ .source = .{ .word = 0, .byte = 0 } }, .{ .source = .{ .word = 0, .byte = 1 } }, .{ .source = .{ .word = 0, .byte = 2 } }, .{ .source = .{ .word = 0, .byte = 3 } } } };
}

const HashCounts = struct { g: usize, xor: usize };
fn hashCounts(a: std.mem.Allocator, len: usize) !HashCounts {
    var plan = try graph.build(a, len);
    defer plan.deinit();
    return .{ .g = plan.g.len, .xor = plan.xor.len };
}
const HashRows = struct {
    g_rows: []g.Row,
    xor_rows: []xor.Row,
    g_used: usize = 0,
    xor_used: usize = 0,
    fn take(self: *@This(), count: HashCounts) !frame.HashDestination {
        if (count.g > self.g_rows.len - self.g_used or count.xor > self.xor_rows.len - self.xor_used) return error.InvalidBlake3MerkleGroup;
        const out = frame.HashDestination{ .g_rows = self.g_rows[self.g_used..][0..count.g], .xor_rows = self.xor_rows[self.xor_used..][0..count.xor] };
        self.g_used += count.g;
        self.xor_used += count.xor;
        return out;
    }
};
