//! Fixed-depth byte-memory opening. Address/kind/root are verifier-owned;
//! the byte source must be authenticated by the production memory component.
const std = @import("std");
const core = @import("stwo_core");
const tree = @import("../../air/memory_commitment/blake3_byte_tree.zig");
const leaf = @import("blake3_memory_leaf.zig");
const framed = @import("blake3_frame_witness.zig");
const graph = @import("blake3_hash_plan.zig");
const hash = @import("blake3_hash_witness.zig");
const g = @import("blake3_g_call.zig");
const xor = @import("blake3_xor_call.zig");
const boundary = @import("blake3_boundary.zig");
const route = @import("blake3_byte_route.zig");
const word = @import("blake3_private_word.zig");
const M = core.fields.m31.M31;
pub const Statement = struct { sibling_namespace: ?u32 = null, namespace: u32, source: leaf.Caller, kind: tree.Kind, address: u32, root: tree.Digest };
pub const Prepared = struct {
    arena: std.heap.ArenaAllocator,
    g_rows: []g.Row,
    xor_rows: []xor.Row,
    boundary_rows: []boundary.Row,
    route_rows: []route.Row,
    word_rows: []word.Row,
    input: @import("blake3_input_bridge.zig").Row,
    computed_root: ?tree.Digest,
    pub fn deinit(self: *Prepared) void {
        self.arena.deinit();
        self.* = undefined;
    }
};
pub fn prepare(a: std.mem.Allocator, statement: Statement, value: u32, siblings: *const [tree.DEPTH]tree.Digest) !Prepared {
    return build(a, statement, .{ .value = value, .siblings = siblings });
}
pub fn trusted(a: std.mem.Allocator, statement: Statement) !Prepared {
    return build(a, statement, null);
}
const Witness = struct { value: u32, siblings: *const [tree.DEPTH]tree.Digest };
fn build(backing: std.mem.Allocator, s: Statement, witness: ?Witness) !Prepared {
    const end = @as(u64, s.namespace) + 2 * tree.DEPTH;
    if (end >= core.fields.m31.Modulus or s.address >= tree.ADDRESS_LIMIT or
        (s.source.circuit >= s.namespace and s.source.circuit <= end)) return error.InvalidMemoryPath;
    if (s.sibling_namespace) |base| {
        const sibling_end = @as(u64, base) + tree.DEPTH - 1;
        if (sibling_end >= core.fields.m31.Modulus or
            (@as(u64, base) <= end and sibling_end >= s.namespace) or
            (s.source.circuit >= base and s.source.circuit <= sibling_end)) return error.InvalidMemoryPath;
    }
    var arena = std.heap.ArenaAllocator.init(backing);
    errdefer arena.deinit();
    const a = arena.allocator();
    const zero = tree.Digest{ .bytes = @splat(0) };
    const initial = if (witness) |w| try leaf.prepare(a, s.kind, s.source, s.namespace, w.value, zero) else try leaf.trusted(a, s.kind, s.source, s.namespace, zero);
    var current = initial.rows;
    var digest = if (initial.digest) |bytes| tree.Digest{ .bytes = bytes } else zero;
    var gs: std.ArrayList(g.Row) = .empty;
    var xs: std.ArrayList(xor.Row) = .empty;
    var bs: std.ArrayList(boundary.Row) = .empty;
    var rs: std.ArrayList(route.Row) = .empty;
    var ws: std.ArrayList(word.Row) = .empty;
    var length: usize = 45;
    for (0..tree.DEPTH) |level| {
        const namespace = s.namespace + @as(u32, @intCast(2 * level));
        var shape = try graph.build(a, length);
        defer shape.deinit();
        for (shape.output, 0..) |wire, i| if (wire != shape.output[0] + i) return error.InvalidMemoryPath;
        const sibling_circuit = if (s.sibling_namespace) |base| base + @as(u32, @intCast(level)) else namespace + 1;
        const side: usize = @intCast((s.address >> @as(u5, @intCast(level))) & 1);
        var children: [2]tree.Digest = .{ zero, zero };
        children[side] = digest;
        if (witness) |w| children[1 - side] = w.siblings[level];
        var bindings: [2]framed.Binding = undefined;
        bindings[side] = .{ .role = if (side == 0) .left else .right, .caller = .{ .circuit = namespace, .first_wire = shape.output[0] } };
        bindings[1 - side] = .{ .role = if (side == 0) .right else .left, .caller = .{ .circuit = sibling_circuit, .first_wire = 0 } };
        const frame = tree.Frame{ .node = .{ .kind = s.kind, .left = children[0], .right = children[1] } };
        const claim = if (level + 1 == tree.DEPTH) s.root else zero;
        const next = if (witness != null) try framed.prepareDigestFrame(a, namespace + 2, frame, &bindings, claim.bytes) else try framed.trustedDigestFrame(a, namespace + 2, frame, &bindings, claim.bytes);
        // Replace the eight public digest sinks with exact parent fanout.
        for (next.source_uses[side], 0..) |uses, i| {
            const row = &current.xor_rows[current.xor_rows.len - 16 + i];
            if (row[16].toU32() != shape.output[i]) return error.InvalidMemoryPath;
            row[17] = M.fromCanonical(uses);
        }
        try gs.appendSlice(a, current.g_rows);
        try xs.appendSlice(a, current.xor_rows);
        try bs.appendSlice(a, current.boundary_rows[0 .. current.boundary_rows.len - 8]);
        for (next.source_uses[1 - side], 0..) |uses, i| {
            const value = if (witness != null) std.mem.readInt(u32, children[1 - side].bytes[i * 4 ..][0..4], .little) else 0;
            try ws.append(a, try word.logicalRow(sibling_circuit, @intCast(i), uses, value));
        }
        try rs.appendSlice(a, next.route_rows);
        current = .{ .allocator = a, .g_rows = next.rows.g_rows, .xor_rows = next.rows.xor_rows, .boundary_rows = next.rows.boundary_rows };
        digest = if (next.digest) |bytes| .{ .bytes = bytes } else zero;
        length = 108;
    }
    try gs.appendSlice(a, current.g_rows);
    try xs.appendSlice(a, current.xor_rows);
    try bs.appendSlice(a, current.boundary_rows);
    const g_rows = try gs.toOwnedSlice(a);
    const xor_rows = try xs.toOwnedSlice(a);
    const boundary_rows = try bs.toOwnedSlice(a);
    const route_rows = try rs.toOwnedSlice(a);
    const word_rows = try ws.toOwnedSlice(a);
    return .{ .arena = arena, .g_rows = g_rows, .xor_rows = xor_rows, .boundary_rows = boundary_rows, .route_rows = route_rows, .word_rows = word_rows, .input = initial.input, .computed_root = if (witness != null) digest else null };
}
