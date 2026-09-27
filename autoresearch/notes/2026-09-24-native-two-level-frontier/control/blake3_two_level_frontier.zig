//! Three shared hashes for a fixed two-level frontier. Private activity flags
//! select opaque unqueried branches; each query proves its branch is active.
const std = @import("std");
const core = @import("stwo_core");
const frame = @import("blake3_frame_witness.zig");
const group = @import("blake3_merkle_group_witness.zig");
const scalar = @import("blake3_path_select.zig");
const Caller = @import("blake3_frame_route.zig").Caller;
const Digest = [32]u8;
const M = core.fields.m31.M31;
pub const Airs = .{ group.g, group.xor, group.boundary, group.route, group.word, group.select };
pub const Plan = struct {
    namespace: u32,
    queries: u32,
    root_source: Caller,
    pub fn validate(self: Plan) !void {
        const end = @as(u64, self.namespace) + 7 + self.queries;
        if (self.queries < 2 or self.queries > core.fields.m31.Modulus - 16 or end > core.fields.m31.Modulus or self.root_source.circuit >= core.fields.m31.Modulus or @as(u64, self.root_source.first_wire) + 8 > core.fields.m31.Modulus or (self.root_source.circuit >= self.namespace and self.root_source.circuit < end)) return error.InvalidTwoLevelFrontier;
    }
    fn input(self: Plan, branch: usize, side: usize) Caller {
        return .{ .circuit = self.namespace, .first_wire = @intCast(branch * 16 + side * 8) };
    }
    fn flag(self: Plan, branch: usize) scalar.Endpoint {
        return .{ .circuit = self.namespace, .wire = @intCast(32 + branch) };
    }
};
pub const Witness = struct { inputs: [2][2]Digest, opaque_digests: [2]Digest, active: [2]u1 };
pub const Prepared = struct {
    arena: std.heap.ArenaAllocator,
    g_rows: []group.g.Row,
    xor_rows: []group.xor.Row,
    boundary_rows: []group.boundary.Row,
    route_rows: []group.route.Row,
    word_rows: []group.word.Row,
    select_rows: []group.select.Row,
    root: Digest,
    pub fn deinit(self: *Prepared) void {
        self.arena.deinit();
        self.* = undefined;
    }
};
fn word(d: Digest, i: usize) u32 {
    return std.mem.readInt(u32, d[4 * i ..][0..4], .little);
}
fn endpoint(c: Caller, i: usize) scalar.Endpoint {
    return .{ .circuit = c.circuit, .wire = c.first_wire + @as(u32, @intCast(i)) };
}
fn output(circuit: u32, hash: *const @import("blake3_hash_plan.zig").Plan) Caller {
    return .{ .circuit = circuit, .first_wire = hash.output[0] };
}
fn useOutput(p: *frame.Prepared, count: u32) void {
    for (0..8) |i| @import("blake3_hash_metadata.zig").xorUse(p.rows.xor_rows, p.hash_metadata, p.rows.xor_rows.len - 16 + i).* = M.fromCanonical(count);
}
/// Query sources are external producers: 17 high-bit uses and one use of each
/// ordered input word. The caller must bind the latter to its lower path.
pub const Query = struct { high_bit: scalar.Endpoint, inputs: [2]Caller };
pub const QueryRows = struct { select_rows: [17]group.select.Row, route_rows: [17]group.route.Row };
pub fn queryRows(plan: Plan, q: u32, sources: Query, values: [2]Digest, high_bit: u1, w: Witness) !QueryRows {
    try plan.validate();
    if (q >= plan.queries) return error.InvalidTwoLevelFrontier;
    const end = plan.namespace + 7 + plan.queries;
    if (sources.high_bit.circuit >= plan.namespace and sources.high_bit.circuit < end) return error.InvalidTwoLevelFrontier;
    for (sources.inputs) |c| if (c.circuit >= plan.namespace and c.circuit < end) return error.InvalidTwoLevelFrontier;
    var result: QueryRows = undefined;
    const dest = plan.namespace + 7 + q;
    for (0..2) |side| for (0..8) |i| {
        const at = side * 8 + i;
        const schedule = scalar.Schedule{ .bit = sources.high_bit, .current = endpoint(plan.input(0, side), i), .sibling = endpoint(plan.input(1, side), i), .destination_circuit = dest, .left_wire = @intCast(at), .right_wire = @intCast(16 + at), .left_uses = 1, .right_uses = 0 };
        result.select_rows[at] = try scalar.logicalRow(schedule, high_bit, word(w.inputs[0][side], i), word(w.inputs[1][side], i));
        const equality = try group.rootEquality(sources.inputs[side], .{ .circuit = dest, .first_wire = @intCast(side * 8) }, @intCast(i));
        result.route_rows[at] = try group.route.logicalRow(equality, .{ word(values[side], i), 0 });
    };
    const membership = scalar.Schedule{ .bit = sources.high_bit, .current = plan.flag(0), .sibling = plan.flag(1), .destination_circuit = dest, .left_wire = 32, .right_wire = 33, .left_uses = 1, .right_uses = 0 };
    result.select_rows[16] = try scalar.logicalRow(membership, high_bit, w.active[0], w.active[1]);
    const equality = try group.rootEquality(.{ .circuit = dest, .first_wire = 32 }, .{ .circuit = plan.namespace, .first_wire = 34 }, 0);
    result.route_rows[16] = try group.route.logicalRow(equality, .{ w.active[high_bit], 0 });
    return result;
}
pub fn prepare(backing: std.mem.Allocator, plan: Plan, w: Witness) !Prepared {
    try plan.validate();
    var arena = std.heap.ArenaAllocator.init(backing);
    errdefer arena.deinit();
    const a = arena.allocator();
    var gs: std.ArrayList(group.g.Row) = .empty;
    var xs: std.ArrayList(group.xor.Row) = .empty;
    var bs: std.ArrayList(group.boundary.Row) = .empty;
    var rs: std.ArrayList(group.route.Row) = .empty;
    var ws: std.ArrayList(group.word.Row) = .empty;
    var ss: std.ArrayList(group.select.Row) = .empty;
    const zero: Digest = @splat(0);
    const node_len = try (core.channel.blake3.Frame{ .node = .{ .left = zero, .right = zero } }).encodedSize();
    var hash = try @import("blake3_hash_plan.zig").build(backing, node_len);
    defer hash.deinit();
    var selected: [2]Digest = undefined;
    var adopted: [2]Caller = undefined;
    // Compute parent source-use counts from the authenticated canonical frame plan.
    const root_bindings = [2]frame.Binding{ .{ .role = .left, .caller = .{ .circuit = plan.namespace + 4, .first_wire = 0 } }, .{ .role = .right, .caller = .{ .circuit = plan.namespace + 5, .first_wire = 0 } } };
    var root_shape = try frame.destinationWithPlan(backing, plan.namespace + 6, core.channel.blake3.Frame{ .node = .{ .left = zero, .right = zero } }, &root_bindings, null, zero, false, null, null, &hash);
    defer root_shape.deinit();
    for (0..2) |branch| {
        const bindings = [2]frame.Binding{ .{ .role = .left, .caller = plan.input(branch, 0) }, .{ .role = .right, .caller = plan.input(branch, 1) } };
        var node = try frame.destinationWithPlan(backing, plan.namespace + 2 + @as(u32, @intCast(branch)), core.channel.blake3.Frame{ .node = .{ .left = w.inputs[branch][0], .right = w.inputs[branch][1] } }, &bindings, null, zero, true, null, null, &hash);
        defer node.deinit();
        useOutput(&node, 1);
        try gs.appendSlice(a, node.rows.g_rows);
        try xs.appendSlice(a, node.rows.xor_rows);
        try bs.appendSlice(a, node.rows.boundary_rows[0 .. node.rows.boundary_rows.len - 8]);
        try rs.appendSlice(a, node.route_rows);
        const computed = node.digest.?;
        adopted[branch] = .{ .circuit = plan.namespace + 4 + @as(u32, @intCast(branch)), .first_wire = 0 };
        selected[branch] = if (w.active[branch] == 1) computed else w.opaque_digests[branch];
        for (0..2) |side| for (0..8) |i| try ws.append(a, try group.word.logicalRow(plan.namespace, @intCast(branch * 16 + side * 8 + i), try std.math.add(u32, plan.queries, node.source_uses[side][i]), word(w.inputs[branch][side], i)));
        try ws.append(a, try group.word.logicalRow(plan.namespace, @intCast(32 + branch), plan.queries + 8, w.active[branch]));
        for (0..8) |i| {
            const opaque_source = Caller{ .circuit = plan.namespace + 1, .first_wire = @intCast(branch * 8) };
            try ws.append(a, try group.word.logicalRow(opaque_source.circuit, opaque_source.first_wire + @as(u32, @intCast(i)), 1, word(w.opaque_digests[branch], i)));
            const schedule = scalar.Schedule{ .bit = plan.flag(branch), .current = endpoint(opaque_source, i), .sibling = endpoint(output(plan.namespace + 2 + @as(u32, @intCast(branch)), &hash), i), .destination_circuit = adopted[branch].circuit, .left_wire = @intCast(i), .right_wire = @intCast(8 + i), .left_uses = root_shape.source_uses[branch][i], .right_uses = 0 };
            try ss.append(a, try scalar.logicalRow(schedule, w.active[branch], word(w.opaque_digests[branch], i), word(computed, i)));
        }
    }
    try bs.append(a, try group.boundary.logicalRow(plan.namespace, 34, M.fromCanonical(plan.queries), 1));
    var root = try frame.destinationWithPlan(backing, plan.namespace + 6, core.channel.blake3.Frame{ .node = .{ .left = selected[0], .right = selected[1] } }, &root_bindings, null, zero, true, null, null, &hash);
    defer root.deinit();
    useOutput(&root, plan.queries);
    try gs.appendSlice(a, root.rows.g_rows);
    try xs.appendSlice(a, root.rows.xor_rows);
    try bs.appendSlice(a, root.rows.boundary_rows[0 .. root.rows.boundary_rows.len - 8]);
    try rs.appendSlice(a, root.route_rows);
    for (0..plan.queries) |_| for (0..8) |i| {
        const equality = try group.rootEquality(output(plan.namespace + 6, &hash), plan.root_source, @intCast(i));
        try rs.append(a, try group.route.logicalRow(equality, .{ word(root.digest.?, i), 0 }));
    };
    return .{ .arena = arena, .g_rows = try gs.toOwnedSlice(a), .xor_rows = try xs.toOwnedSlice(a), .boundary_rows = try bs.toOwnedSlice(a), .route_rows = try rs.toOwnedSlice(a), .word_rows = try ws.toOwnedSlice(a), .select_rows = try ss.toOwnedSlice(a), .root = root.digest.? };
}
