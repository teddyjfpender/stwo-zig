//! Binary Merkle path witness with public index/depth and private siblings.
//! Production recursive queries must bind these statement coordinates to their
//! own constrained challenge source before using this path assembly.
const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const graph = @import("blake3_hash_plan.zig");
const hash = @import("blake3_hash_witness.zig");
const node = @import("blake3_node_route.zig");
pub const g = @import("blake3_g_call.zig");
pub const xor = @import("blake3_xor_call.zig");
pub const boundary = @import("blake3_boundary.zig");
pub const route = @import("blake3_byte_route.zig");
pub const word = @import("blake3_private_word.zig");
pub const Digest = [32]u8;
pub const Statement = struct { namespace: u32, leaf: []const M31, index: u32, depth: u5, root: Digest };
pub const Prepared = struct {
    arena: std.heap.ArenaAllocator,
    g_rows: []g.Row,
    xor_rows: []xor.Row,
    boundary_rows: []boundary.Row,
    route_rows: []route.Row,
    word_rows: []word.Row,
    computed_root: ?Digest,
    pub fn deinit(self: *Prepared) void {
        self.arena.deinit();
        self.* = undefined;
    }
    pub fn logs(self: *const Prepared) [5]u32 {
        return .{ log(self.g_rows.len), log(self.xor_rows.len), log(self.boundary_rows.len), log(self.route_rows.len), log(self.word_rows.len) };
    }
    fn log(n: usize) u32 {
        return if (n <= 1) 1 else std.math.log2_int_ceil(usize, n);
    }
};
pub fn prepare(a: std.mem.Allocator, statement: Statement, siblings: []const Digest) !Prepared {
    if (siblings.len != statement.depth) return error.InvalidBlake3MerklePath;
    return build(a, statement, siblings);
}
pub fn trusted(a: std.mem.Allocator, statement: Statement) !Prepared {
    return build(a, statement, null);
}
fn build(backing: std.mem.Allocator, s: Statement, siblings: ?[]const Digest) !Prepared {
    const namespace_end = std.math.add(u32, s.namespace, 2 * @as(u32, s.depth)) catch return error.InvalidBlake3MerklePath;
    if (namespace_end >= core.fields.m31.Modulus or @as(u64, s.index) >= @as(u64, 1) << @as(u6, s.depth)) return error.InvalidBlake3MerklePath;
    var arena = std.heap.ArenaAllocator.init(backing);
    errdefer arena.deinit();
    const a = arena.allocator();
    var gs: std.ArrayList(g.Row) = .empty;
    var xs: std.ArrayList(xor.Row) = .empty;
    var bs: std.ArrayList(boundary.Row) = .empty;
    var rs: std.ArrayList(route.Row) = .empty;
    var ws: std.ArrayList(word.Row) = .empty;
    const leaf_bytes = try (core.channel.blake3.Frame{ .leaf = s.leaf }).encode(a);
    var current_len = leaf_bytes.len;
    var current_digest: Digest = undefined;
    var current: hash.Rows = undefined;
    const leaf_claim: Digest = if (s.depth == 0) s.root else @splat(0);
    if (siblings != null) {
        const live = try hash.prepare(a, s.namespace, leaf_bytes, leaf_claim);
        current = live.rows;
        current_digest = live.digest;
    } else current = try hash.trustedRows(a, s.namespace, leaf_bytes, leaf_claim);
    for (0..s.depth) |level| {
        const namespace = s.namespace + @as(u32, @intCast(2 * level));
        var current_plan = try graph.build(a, current_len);
        defer current_plan.deinit();
        for (current_plan.output, 0..) |wire, i| if (wire != current_plan.output[0] + i) return error.InvalidBlake3MerklePath;
        const side: usize = @intCast((s.index >> @as(u5, @intCast(level))) & 1);
        var callers: [2]node.Caller = undefined;
        callers[side] = .{ .circuit = namespace, .first_wire = current_plan.output[0] };
        callers[1 - side] = .{ .circuit = namespace + 1, .first_wire = 0 };
        var routing = try node.build(a, namespace + 2, callers);
        defer routing.deinit();
        for (routing.child_uses[side], 0..) |count, i| current.xor_rows[current.xor_rows.len - 16 + i][17] = M31.fromCanonical(count);
        try gs.appendSlice(a, current.g_rows);
        try xs.appendSlice(a, current.xor_rows);
        try bs.appendSlice(a, current.boundary_rows[0 .. current.boundary_rows.len - 8]);
        var digests: [2]Digest = undefined;
        if (siblings) |values| {
            digests[side] = current_digest;
            digests[1 - side] = values[level];
        }
        for (routing.child_uses[1 - side], 0..) |count, i| {
            const value = if (siblings != null) std.mem.readInt(u32, digests[1 - side][i * 4 ..][0..4], .little) else 0;
            try ws.append(a, try word.logicalRow(namespace + 1, @intCast(i), count, value));
        }
        for (routing.schedules) |schedule| try rs.append(a, if (siblings != null) try node.witnessRow(schedule, callers, digests) else try route.fixedRow(schedule));
        const claim: Digest = if (level + 1 == s.depth) s.root else @splat(0);
        if (siblings != null) {
            const bytes = try (core.channel.blake3.Frame{ .node = .{ .left = digests[0], .right = digests[1] } }).encode(a);
            const live = try hash.prepare(a, namespace + 2, bytes, claim);
            current = live.rows;
            current_digest = live.digest;
        } else current = try hash.trustedShapeRows(a, namespace + 2, node.frameLength(), claim);
        // The router, not a public boundary, emits every parent message word.
        var parent_plan = try graph.build(a, node.frameLength());
        defer parent_plan.deinit();
        var fixed: std.ArrayList(boundary.Row) = .empty;
        for (parent_plan.sources, current.boundary_rows[0..parent_plan.sources.len]) |source, row| if (source.value == .constant) try fixed.append(a, row);
        try fixed.appendSlice(a, current.boundary_rows[parent_plan.sources.len..]);
        current.boundary_rows = try fixed.toOwnedSlice(a);
        current_len = node.frameLength();
    }
    try gs.appendSlice(a, current.g_rows);
    try xs.appendSlice(a, current.xor_rows);
    try bs.appendSlice(a, current.boundary_rows);
    const g_rows = try gs.toOwnedSlice(a);
    const xor_rows = try xs.toOwnedSlice(a);
    const boundary_rows = try bs.toOwnedSlice(a);
    const route_rows = try rs.toOwnedSlice(a);
    const word_rows = try ws.toOwnedSlice(a);
    return .{ .arena = arena, .g_rows = g_rows, .xor_rows = xor_rows, .boundary_rows = boundary_rows, .route_rows = route_rows, .word_rows = word_rows, .computed_root = if (siblings != null) current_digest else null };
}
