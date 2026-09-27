//! Authenticated path above a fixed public subtree. The subtree digest must be
//! independently derived from admitted public words; siblings remain private.
const std = @import("std");
const core = @import("stwo_core");
const tree = @import("../../air/memory_commitment/blake3_state_tree.zig");
const framed = @import("blake3_frame_witness.zig");
const graph = @import("blake3_hash_plan.zig");
const G = @import("blake3_g_call.zig");
const Xor = @import("blake3_xor_call.zig");
const Boundary = @import("blake3_boundary.zig");
const Route = @import("blake3_byte_route.zig");
const Word = @import("blake3_private_word.zig");
const M = core.fields.m31.M31;
pub const Statement = struct {
    namespace: u32,
    sibling_namespace: u32,
    address: u32,
    height: u5,
    subtree: tree.Digest,
    root: tree.Digest,
};
pub const Prepared = struct {
    arena: std.heap.ArenaAllocator,
    g_rows: []G.Row,
    xor_rows: []Xor.Row,
    boundary_rows: []Boundary.Row,
    route_rows: []Route.Row,
    word_rows: []Word.Row,
    pub fn deinit(self: *Prepared) void {
        self.arena.deinit();
        self.* = undefined;
    }
};
pub fn prepare(a: std.mem.Allocator, s: Statement, siblings: *const [tree.DEPTH]tree.Digest) !Prepared {
    return build(a, s, siblings);
}
pub fn trusted(a: std.mem.Allocator, s: Statement) !Prepared {
    return build(a, s, null);
}
fn build(backing: std.mem.Allocator, s: Statement, siblings: ?*const [tree.DEPTH]tree.Digest) !Prepared {
    if (s.height > 28 or s.address >= tree.MEMORY_WORD_LIMIT or s.address % (@as(u32, 1) << s.height) != 0)
        return error.InvalidPublicSubtreePath;
    const end = @as(u64, s.namespace) + 2 * tree.DEPTH;
    const sibling_end = @as(u64, s.sibling_namespace) + tree.DEPTH - 1;
    if (end >= core.fields.m31.Modulus or sibling_end >= core.fields.m31.Modulus or
        (s.sibling_namespace <= end and sibling_end >= s.namespace)) return error.InvalidPublicSubtreePath;
    var arena = std.heap.ArenaAllocator.init(backing);
    errdefer arena.deinit();
    const a = arena.allocator();
    var gs: std.ArrayList(G.Row) = .empty;
    var xs: std.ArrayList(Xor.Row) = .empty;
    var bs: std.ArrayList(Boundary.Row) = .empty;
    var rs: std.ArrayList(Route.Row) = .empty;
    var ws: std.ArrayList(Word.Row) = .empty;
    var shape = try graph.build(a, 108);
    defer shape.deinit();
    var previous: ?framed.Prepared = null;
    var digest = s.subtree;
    const hasher = tree.TreeHasher.init(.memory);
    const zero = tree.Digest{ .bytes = @splat(0) };
    for (@as(usize, s.height)..tree.DEPTH) |level| {
        const offset: u32 = @intCast(level - s.height);
        const circuit = s.namespace + 2 * offset;
        const side: usize = @intCast((s.address >> @as(u5, @intCast(level))) & 1);
        const sibling_circuit = s.sibling_namespace + @as(u32, @intCast(level));
        const fixed_empty = tree.outsideIndexRange(.memory, @intCast(level), (s.address >> @as(u5, @intCast(level))) ^ 1);
        var children: [2]tree.Digest = .{ zero, zero };
        children[side] = digest;
        children[1 - side] = if (fixed_empty) hasher.defaults[tree.DEPTH - level] else if (siblings) |live| live[level] else zero;
        if (fixed_empty) if (siblings) |live| if (!std.meta.eql(live[level], children[1 - side])) return error.InvalidPublicSubtreeSibling;
        var bindings: [2]framed.Binding = undefined;
        bindings[side] = .{ .role = if (side == 0) .left else .right, .caller = .{ .circuit = circuit, .first_wire = if (previous == null) 0 else shape.output[0] } };
        bindings[1 - side] = .{ .role = if (side == 0) .right else .left, .caller = .{ .circuit = sibling_circuit, .first_wire = 0 } };
        const frame = tree.Frame{ .node = .{ .kind = .memory, .left = children[0], .right = children[1] } };
        const claim = if (level + 1 == tree.DEPTH) s.root else zero;
        const next = if (siblings != null) try framed.prepareDigestFrame(a, circuit + 2, frame, &bindings, claim.bytes) else try framed.trustedDigestFrame(a, circuit + 2, frame, &bindings, claim.bytes);
        if (previous) |*current| {
            for (next.source_uses[side], 0..) |uses, i| {
                const row = &current.rows.xor_rows[current.rows.xor_rows.len - 16 + i];
                if (row[16].toU32() != shape.output[i]) return error.InvalidPublicSubtreePath;
                row[17] = M.fromCanonical(uses);
            }
            try gs.appendSlice(a, current.rows.g_rows);
            try xs.appendSlice(a, current.rows.xor_rows);
            try bs.appendSlice(a, current.rows.boundary_rows[0 .. current.rows.boundary_rows.len - 8]);
        } else {
            for (next.source_uses[side], 0..) |uses, i| try bs.append(a, try Boundary.logicalRow(circuit, @intCast(i), M.fromCanonical(uses), std.mem.readInt(u32, s.subtree.bytes[i * 4 ..][0..4], .little)));
        }
        for (next.source_uses[1 - side], 0..) |uses, i| {
            const value = std.mem.readInt(u32, children[1 - side].bytes[i * 4 ..][0..4], .little);
            if (fixed_empty) try bs.append(a, try Boundary.logicalRow(sibling_circuit, @intCast(i), M.fromCanonical(uses), value)) else try ws.append(a, try Word.logicalRow(sibling_circuit, @intCast(i), uses, value));
        }
        try rs.appendSlice(a, next.route_rows);
        digest = if (next.digest) |bytes| .{ .bytes = bytes } else zero;
        previous = next;
    }
    const last = previous.?;
    try gs.appendSlice(a, last.rows.g_rows);
    try xs.appendSlice(a, last.rows.xor_rows);
    try bs.appendSlice(a, last.rows.boundary_rows);
    if (siblings != null and !std.meta.eql(digest, s.root)) return error.InvalidPublicSubtreeRoot;
    return .{ .arena = arena, .g_rows = try gs.toOwnedSlice(a), .xor_rows = try xs.toOwnedSlice(a), .boundary_rows = try bs.toOwnedSlice(a), .route_rows = try rs.toOwnedSlice(a), .word_rows = try ws.toOwnedSlice(a) };
}
