//! Complete binary subtree from authenticated payload words, then an upper path.
//! Caller supplies canonical word producers with the returned payload use counts.
const std = @import("std");
const Nonhash = @import("blake3_nonhash_emission_v1.zig");
const DirectFrame = @import("blake3_frame_nonhash_v1.zig");
const core = @import("stwo_core");
const frame = @import("blake3_frame_witness.zig");
const routing = @import("blake3_frame_route.zig");
const graph = @import("blake3_hash_plan.zig");
pub const PlanCache = @import("blake3_merkle_plan_cache.zig").Cache;
const path = @import("blake3_merkle_path_witness.zig");
pub const g = path.g;
pub const xor = path.xor;
pub const boundary = path.boundary;
pub const route = path.route;
pub const word = path.word;
pub const select = @import("blake3_path_select.zig");
const shared = @import("blake3_shared_root_plan.zig");
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
    shared_root: ?shared.Sharing = null,
    frontier: ?@import("blake3_two_level_frontier.zig").Use = null,
};
pub const Prepared = struct {
    arena: std.heap.ArenaAllocator,
    /// Borrowed fixed tails in column mode; full hash-row slices are empty.
    hash_metadata: ?@import("blake3_hash_metadata.zig").Rows = null,
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
    return build(a, s, values, siblings, null, null, null);
}
pub fn trusted(a: std.mem.Allocator, s: Statement) !Prepared {
    return build(a, s, null, null, null, null, null);
}
pub const HashDestination = frame.HashDestination;
/// The caller owns these rows even after the returned receipt is destroyed.
pub fn prepareInto(a: std.mem.Allocator, s: Statement, values: []const M31, siblings: []const Digest, destination: HashDestination) !Prepared {
    if (siblings.len != s.depth) return error.InvalidBlake3MerkleGroup;
    return build(a, s, values, siblings, destination, null, null);
}
pub fn trustedInto(a: std.mem.Allocator, s: Statement, destination: HashDestination) !Prepared {
    return build(a, s, null, null, destination, null, null);
}
pub const MainColumns = frame.MainColumns;
pub fn prepareMainColumns(a: std.mem.Allocator, s: Statement, values: []const M31, siblings: []const Digest, columns: MainColumns) !Prepared {
    if (siblings.len != s.depth) return error.InvalidBlake3MerkleGroup;
    return build(a, s, values, siblings, null, columns, null);
}
/// Sizing only; build independently admits statement and destination geometry.
pub fn requiredHashRows(a: std.mem.Allocator, s: Statement) !HashCounts {
    var cache = PlanCache.init(a);
    defer cache.deinit();
    return requiredHashRowsCached(a, s, &cache);
}
pub fn requiredHashRowsCached(a: std.mem.Allocator, s: Statement, cache: *PlanCache) !HashCounts {
    if (s.leaf_count == 0 or !std.math.isPowerOfTwo(s.leaf_count) or s.words_per_leaf == 0) return error.InvalidBlake3MerkleGroup;
    const zeros = try a.alloc(M31, s.words_per_leaf);
    defer a.free(zeros);
    @memset(zeros, M31.zero());
    const shape = try hashShape(s, try cache.get(try (core.channel.blake3.Frame{ .leaf = zeros }).encodedSize()));
    return shape.total;
}
fn build(backing: std.mem.Allocator, s: Statement, values: ?[]const M31, siblings: ?[]const Digest, borrowed: ?HashDestination, columns: ?MainColumns, nonhash: ?Nonhash.Sink) !Prepared {
    var cache = PlanCache.init(backing);
    defer cache.deinit();
    return buildCached(backing, s, values, siblings, borrowed, columns, &cache, nonhash);
}
pub fn prepareIntoCached(a: std.mem.Allocator, s: Statement, values: []const M31, siblings: []const Digest, destination: HashDestination, cache: *PlanCache) !Prepared {
    if (siblings.len != s.depth) return error.InvalidBlake3MerkleGroup;
    return buildCached(a, s, values, siblings, destination, null, cache, null);
}
pub fn trustedIntoCached(a: std.mem.Allocator, s: Statement, destination: HashDestination, cache: *PlanCache) !Prepared {
    return buildCached(a, s, null, null, destination, null, cache, null);
}
pub fn prepareMainColumnsCached(a: std.mem.Allocator, s: Statement, values: []const M31, siblings: []const Digest, columns: MainColumns, cache: *PlanCache) !Prepared {
    if (siblings.len != s.depth) return error.InvalidBlake3MerkleGroup;
    return buildCached(a, s, values, siblings, null, columns, cache, null);
}
/// Stream nonhash rows into an independently owned count/column destination.
/// Hash ranges remain explicit and are admitted by the same canonical geometry.
pub fn prepareEmittingCached(a: std.mem.Allocator, s: Statement, values: ?[]const M31, siblings: ?[]const Digest, destination: ?HashDestination, columns: ?MainColumns, cache: *PlanCache, sink: Nonhash.Sink) !Prepared {
    if (values != null and (siblings == null or siblings.?.len != s.depth)) return error.InvalidBlake3MerkleGroup;
    return buildCached(a, s, values, siblings, destination, columns, cache, sink);
}
fn buildCached(backing: std.mem.Allocator, s: Statement, values: ?[]const M31, siblings: ?[]const Digest, borrowed: ?HashDestination, columns: ?MainColumns, cache: *PlanCache, nonhash: ?Nonhash.Sink) !Prepared {
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
    const plans = try cache.get(try (core.channel.blake3.Frame{ .leaf = zeros }).encodedSize());
    if (s.frontier) |frontier| try frontier.validate(s);
    const sharing = try shared.derive(s, (try output(0, plans.node)).first_wire);
    const shape = try hashShape(s, plans);
    const leaf_shape = shape.leaf;
    const node_shape = shape.node;
    const fixed_metadata = if (borrowed) |out| out.fixed else null;
    if (values != null and fixed_metadata != null) return error.InvalidBlake3WitnessDestination;
    if (borrowed) |out| try out.validate(shape.total.g, shape.total.xor);
    if (columns) |out| try out.validate(shape.total.g, shape.total.xor);
    var destination = HashRows{
        .nonhash = nonhash,
        .columns = columns,
        .fixed = fixed_metadata,
        .g_rows = if (columns != null) &.{} else if (borrowed) |out| out.g_rows else try a.alloc(g.Row, shape.total.g),
        .xor_rows = if (columns != null) &.{} else if (borrowed) |out| out.xor_rows else try a.alloc(xor.Row, shape.total.xor),
    };
    var next = s.namespace;
    for (0..s.leaf_count) |i| {
        const start = i * s.words_per_leaf;
        const input = if (values) |v| v[start..][0..s.words_per_leaf] else zeros;
        const f = core.channel.blake3.Frame{ .leaf = input };
        const payload = frame.PayloadBinding{ .role = .leaf, .caller = .{ .circuit = s.payload.circuit, .first_wire = s.payload.first_wire + @as(u32, @intCast(start)) }, .word_count = s.words_per_leaf };
        const claim: Digest = if (total == 1) s.root else @splat(0);
        const out = try destination.take(leaf_shape, s.leaf_count == 1 and s.depth == 0 and s.root_source == null);
        var data = try out.prepare(backing, next, f, &.{}, payload, claim, values != null, plans.leaf);
        errdefer data.deinit();
        @memcpy(uses[start..][0..s.words_per_leaf], data.payload_uses);
        try nodes.append(a, .{ .data = data, .caller = try output(next, plans.leaf) });
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
            var parent = try merge(backing, next, .{ nodes.items[left].caller, nodes.items[right].caller }, .{ nodes.items[left].data.digest orelse @splat(0), nodes.items[right].data.digest orelse @splat(0) }, claim, values != null, try destination.take(node_shape, count == 2 and s.depth == 0 and s.root_source == null), plans.node);
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
    // Only the last level contributes shared-root (16) or frontier (17)
    // equalities. Keep their exact tail order in bounded stack scratch.
    var shared_routes: [17]route.Row = undefined;
    var shared_route_count: usize = 0;
    var shared_digest: ?Digest = null;
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
            const final_shared = if (level + 1 == s.depth) sharing else null;
            const final_frontier = if (level + 2 == s.depth) s.frontier else null;
            const borrow_root = if (final_shared) |plan| !plan.owner else false;
            var parent: ?Node = if (borrow_root or final_frontier != null) null else try merge(backing, next + 2, selected, digests, if (level + 1 == s.depth) s.root else @splat(0), values != null, try destination.take(node_shape, level + 1 == s.depth and s.root_source == null), plans.node);
            errdefer if (parent) |*owned| owned.data.deinit();
            consume(&nodes.items[current], @splat(1));
            const current_digest = digests[side];
            const sibling_digest = digests[1 - side];
            for (0..8) |i| {
                const sibling_word = std.mem.readInt(u32, sibling_digest[4 * i ..][0..4], .little);
                const fixed_word = try word.logicalRow(next, @intCast(i), 1, 0);
                try Nonhash.append(9, nonhash, a, &words, try word.logicalRow(next, @intCast(i), 1, sibling_word), fixed_word);
                const extra = if (final_shared) |plan| if (plan.owner) plan.queries - 1 else @as(u32, 0) else 0;
                const left_uses = if (parent) |owned| try std.math.add(u32, owned.data.source_uses[0][i], extra) else 1;
                const right_uses = if (parent) |owned| try std.math.add(u32, owned.data.source_uses[1][i], extra) else 1;
                const schedule = select.Schedule{ .bit = directions[level], .current = .{ .circuit = nodes.items[current].caller.circuit, .wire = nodes.items[current].caller.first_wire + @as(u32, @intCast(i)) }, .sibling = .{ .circuit = next, .wire = @intCast(i) }, .destination_circuit = next + 1, .left_wire = @intCast(i), .right_wire = @intCast(8 + i), .left_uses = left_uses, .right_uses = right_uses };
                const fixed_select = try select.fixedRow(schedule);
                try Nonhash.append(13, nonhash, a, &selections, if (values != null) try select.logicalRow(schedule, @intCast(side), std.mem.readInt(u32, current_digest[4 * i ..][0..4], .little), sibling_word) else fixed_select, fixed_select);
                if (borrow_root) for (0..2) |branch| {
                    const equality = try rootEquality(selected[branch], final_shared.?.inputs[branch], @intCast(i));
                    if (shared_route_count >= shared_routes.len) return error.InvalidBlake3MerkleGroup;
                    shared_routes[shared_route_count] = if (values != null) try route.logicalRow(equality, .{ std.mem.readInt(u32, digests[branch][4 * i ..][0..4], .little), 0 }) else try route.fixedRow(equality);
                    shared_route_count += 1;
                };
            }
            if (final_frontier) |frontier| {
                const finish = try frontier.finish(s, selected, digests, if (siblings) |v| v[s.depth - 1] else null);
                if (nonhash) |sink| {
                    // The fixed frontier recipe is independently regenerated;
                    // query route rows stay bounded scratch to retain their
                    // original tail position after every frame route.
                    const frontier_fixed = try frontier.finish(s, selected, .{ @splat(0), @splat(0) }, null);
                    for (finish.rows.select_rows, frontier_fixed.rows.select_rows) |row, fixed| try sink.emit(13, &row, &fixed);
                } else try selections.appendSlice(a, &finish.rows.select_rows);
                if (shared_route_count != 0) return error.InvalidBlake3MerkleGroup;
                @memcpy(&shared_routes, &finish.rows.route_rows);
                shared_route_count = shared_routes.len;
                shared_digest = finish.root;
                break;
            }
            if (parent) |owned| {
                try nodes.append(a, owned);
                parent = null;
                if (final_shared) |plan| consume(&nodes.items[nodes.items.len - 1], @splat(plan.queries));
            } else if (values != null) {
                shared_digest = (core.channel.blake3.Frame{ .node = .{ .left = digests[0], .right = digests[1] } }).hash();
                if (!std.mem.eql(u8, &shared_digest.?, &s.root)) return error.InvalidBlake3MerkleGroup;
            }
            next += 3;
        } else {
            var parent = try merge(backing, next + 1, callers, digests, if (level + 1 == s.depth) s.root else @splat(0), values != null, try destination.take(node_shape, level + 1 == s.depth and s.root_source == null), plans.node);
            errdefer parent.data.deinit();
            consume(&nodes.items[current], parent.data.source_uses[side]);
            for (parent.data.source_uses[1 - side], 0..) |n, i| {
                const row = try word.logicalRow(next, @intCast(i), n, std.mem.readInt(u32, digests[1 - side][4 * i ..][0..4], .little));
                const fixed = try word.logicalRow(next, @intCast(i), n, 0);
                try Nonhash.append(9, nonhash, a, &words, row, fixed);
            }
            try nodes.append(a, parent);
            next += 2;
        }
    }
    if (destination.g_used != shape.total.g or destination.xor_used != shape.total.xor) return error.InvalidBlake3MerkleGroup;
    var bs: std.ArrayList(boundary.Row) = .empty;
    var rs: std.ArrayList(route.Row) = .empty;
    if (nonhash == null) for (nodes.items, 0..) |node, i| {
        const boundaries = node.data.rows.boundary_rows;
        try bs.appendSlice(a, boundaries[0 .. boundaries.len - (if (i + 1 == nodes.items.len and s.root_source == null) @as(usize, 0) else 8)]);
        try rs.appendSlice(a, node.data.route_rows);
    };
    if (nonhash) |sink| {
        for (shared_routes[0..shared_route_count]) |row| {
            // Root equalities/frontier recipes carry their entire schedule in
            // the fixed tail. Values occupy only the physical main prefix.
            var fixed = row;
            @memset(fixed[0..route.PHYSICAL_MAIN_COLUMN_COUNT], M31.zero());
            try sink.emit(7, &row, &fixed);
        }
    } else try rs.appendSlice(a, shared_routes[0..shared_route_count]);
    if (if (s.frontier == null) s.root_source else null) |source| {
        const last = nodes.items[nodes.items.len - 1];
        const digest = shared_digest orelse last.data.digest orelse @as(Digest, @splat(0));
        for (0..8) |i| {
            const schedule = try rootEquality(if (sharing) |plan| plan.output else last.caller, source, @intCast(i));
            const fixed = try route.fixedRow(schedule);
            try Nonhash.append(7, nonhash, a, &rs, if (values != null) try route.logicalRow(schedule, .{ std.mem.readInt(u32, digest[4 * i ..][0..4], .little), 0 }) else fixed, fixed);
        }
    }
    const boundary_rows = try bs.toOwnedSlice(a);
    const route_rows = try rs.toOwnedSlice(a);
    const word_rows = try words.toOwnedSlice(a);
    const select_rows = try selections.toOwnedSlice(a);
    return .{ .hash_metadata = if (columns) |out| out.metadata() else fixed_metadata, .select_rows = select_rows, .arena = arena, .g_rows = destination.g_rows, .xor_rows = destination.xor_rows, .boundary_rows = boundary_rows, .route_rows = route_rows, .word_rows = word_rows, .payload_uses = uses, .computed_root = shared_digest orelse nodes.items[nodes.items.len - 1].data.digest };
}
fn consume(node: *Node, uses: [8]u32) void {
    for (uses, 0..) |n, i| @import("blake3_hash_metadata.zig").xorUse(node.data.rows.xor_rows, node.data.hash_metadata, (if (node.data.hash_metadata) |m| m.xor_rows.len else node.data.rows.xor_rows.len) - 16 + i).* = M31.fromCanonical(n);
}
const output = shared.output;
fn merge(a: std.mem.Allocator, circuit: u32, callers: [2]routing.Caller, digests: [2]Digest, claim: Digest, live: bool, destination: HashPart, shape: *const graph.Plan) !Node {
    const f = core.channel.blake3.Frame{ .node = .{ .left = digests[0], .right = digests[1] } };
    const bindings = [_]frame.Binding{ .{ .role = .left, .caller = callers[0] }, .{ .role = .right, .caller = callers[1] } };
    var data = try destination.prepare(a, circuit, f, &bindings, null, claim, live, shape);
    errdefer data.deinit();
    return .{ .data = data, .caller = try output(circuit, shape) };
}

/// Two consumes with identical bytes: computed digest and canonical root.
pub const rootEquality = shared.rootEquality;
pub const HashCounts = shared.HashCounts;
const hashShape = shared.hashShape;
const HashPart = struct {
    nonhash: ?Nonhash.Sink,
    retain_output: bool,
    rows: ?frame.HashDestination,
    columns: ?MainColumns,
    fn prepare(self: @This(), a: std.mem.Allocator, circuit: u32, value: core.channel.blake3.Frame, bindings: []const frame.Binding, payload: ?frame.PayloadBinding, claim: Digest, live: bool, shape: *const graph.Plan) !frame.Prepared {
        if (self.nonhash) |sink| return DirectFrame.prepare(a, circuit, value, bindings, payload, claim, live, self.rows, self.columns, shape, .{ .sink = sink, .retain_output = self.retain_output });
        return frame.destinationWithPlan(a, circuit, value, bindings, payload, claim, live, self.rows, self.columns, shape);
    }
};
const HashRows = struct {
    nonhash: ?Nonhash.Sink = null,
    columns: ?MainColumns = null,
    fixed: ?frame.Metadata = null,
    g_rows: []g.Row,
    xor_rows: []xor.Row,
    g_used: usize = 0,
    xor_used: usize = 0,
    fn take(self: *@This(), count: HashCounts, retain_output: bool) !HashPart {
        const g_len = if (self.columns) |c| c.g_rows.metadata.len else if (self.fixed) |m| m.g_rows.len else self.g_rows.len;
        const xor_len = if (self.columns) |c| c.xor_rows.metadata.len else if (self.fixed) |m| m.xor_rows.len else self.xor_rows.len;
        if (self.g_used > g_len or count.g > g_len - self.g_used or self.xor_used > xor_len or count.xor > xor_len - self.xor_used) return error.InvalidBlake3MerkleGroup;
        const out = HashPart{ .nonhash = self.nonhash, .retain_output = retain_output, .rows = if (self.columns != null) null else if (self.fixed) |m| .{ .fixed = try m.slice(self.g_used, count.g, self.xor_used, count.xor) } else .{ .g_rows = self.g_rows[self.g_used..][0..count.g], .xor_rows = self.xor_rows[self.xor_used..][0..count.xor] }, .columns = if (self.columns) |columns| try columns.slice(self.g_used, count.g, self.xor_used, count.xor) else null };
        self.g_used += count.g;
        self.xor_used += count.xor;
        return out;
    }
};
