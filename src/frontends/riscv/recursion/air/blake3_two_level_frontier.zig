//! Three shared hashes for a fixed two-level frontier. Private activity flags
//! select opaque unqueried branches; each query proves its branch is active.
const std = @import("std");
const Nonhash = @import("blake3_nonhash_emission_v1.zig");
const DirectFrame = @import("blake3_frame_nonhash_v1.zig");
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
pub const empty_witness = Witness{ .inputs = @splat(@splat(@splat(0))), .opaque_digests = @splat(@splat(0)), .active = @splat(0) };
pub const Context = struct { plan: Plan, witness: Witness };
pub const Use = struct {
    context: *const Context,
    query: u32,
    pub fn validate(self: Use, s: anytype) !void {
        const plan = self.context.plan;
        try plan.validate();
        if (s.shared_root != null or s.depth < 2 or s.directions == null or s.root_source == null or self.query >= plan.queries or plan.namespace + 7 + plan.queries > s.namespace or !std.meta.eql(plan.root_source, s.root_source.?)) return error.InvalidTwoLevelFrontier;
    }
    pub fn finish(self: Use, s: anytype, sources: [2]Caller, values: [2]Digest, last_sibling: ?Digest) !struct { rows: QueryRows, root: ?Digest } {
        const high: u1 = @intCast((s.index >> @intCast(s.depth - 1)) & 1);
        const live = last_sibling != null;
        const rows = try queryRows(self.context.plan, self.query, .{ .high_bit = s.directions.?[s.depth - 1], .inputs = sources }, values, if (live) high else 0, if (live) self.context.witness else empty_witness);
        var root: ?Digest = null;
        if (last_sibling) |sibling| {
            var pair: [2]Digest = undefined;
            pair[high] = (core.channel.blake3.Frame{ .node = .{ .left = values[0], .right = values[1] } }).hash();
            pair[high ^ 1] = sibling;
            root = (core.channel.blake3.Frame{ .node = .{ .left = pair[0], .right = pair[1] } }).hash();
            if (!std.mem.eql(u8, &root.?, &s.root)) return error.InvalidTwoLevelFrontier;
        }
        return .{ .rows = rows, .root = root };
    }
};
pub const Prepared = struct {
    arena: std.heap.ArenaAllocator,
    g_rows: []group.g.Row,
    xor_rows: []group.xor.Row,
    boundary_rows: []group.boundary.Row,
    route_rows: []group.route.Row,
    word_rows: []group.word.Row,
    select_rows: []group.select.Row,
    root: Digest,
    hash_metadata: ?@import("blake3_hash_metadata.zig").Rows = null,
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
    for (0..8) |i| @import("blake3_hash_metadata.zig").xorUse(p.rows.xor_rows, p.hash_metadata, (if (p.hash_metadata) |m| m.xor_rows.len else p.rows.xor_rows.len) - 16 + i).* = M.fromCanonical(count);
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
    return build(backing, plan, w, true, null, null, null, null);
}
pub fn emit(backing: std.mem.Allocator, context: Context, live: bool, destination: ?frame.HashDestination, columns: ?frame.MainColumns) !Prepared {
    return build(backing, context.plan, if (live) context.witness else empty_witness, live, destination, columns, null, null);
}
pub fn emitWithPlan(backing: std.mem.Allocator, context: Context, live: bool, destination: ?frame.HashDestination, columns: ?frame.MainColumns, hash: *const @import("blake3_hash_plan.zig").Plan) !Prepared {
    return build(backing, context.plan, if (live) context.witness else empty_witness, live, destination, columns, hash, null);
}
pub fn emitWithPlanEmitting(backing: std.mem.Allocator, context: Context, live: bool, destination: ?frame.HashDestination, columns: ?frame.MainColumns, hash: *const @import("blake3_hash_plan.zig").Plan, sink: Nonhash.Sink) !Prepared {
    return build(backing, context.plan, if (live) context.witness else empty_witness, live, destination, columns, hash, sink);
}
fn part(destination: ?frame.HashDestination, columns: ?frame.MainColumns, index: usize, gs: usize, xs: usize) !struct { rows: ?frame.HashDestination, columns: ?frame.MainColumns } {
    return .{ .columns = if (columns) |out| try out.slice(index * gs, gs, index * xs, xs) else null, .rows = if (destination) |out| if (out.fixed) |fixed| .{ .fixed = try fixed.slice(index * gs, gs, index * xs, xs) } else .{ .g_rows = out.g_rows[index * gs ..][0..gs], .xor_rows = out.xor_rows[index * xs ..][0..xs] } else null };
}
fn build(backing: std.mem.Allocator, plan: Plan, w: Witness, live: bool, destination: ?frame.HashDestination, columns: ?frame.MainColumns, borrowed: ?*const @import("blake3_hash_plan.zig").Plan, nonhash: ?Nonhash.Sink) !Prepared {
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
    var owned = if (borrowed == null) try @import("blake3_hash_plan.zig").build(backing, node_len) else null;
    defer if (owned) |*value| value.deinit();
    const hash = borrowed orelse &owned.?;
    if (hash.input_len != node_len) return error.InvalidBlake3Input;
    if (columns != null and destination != null) return error.InvalidBlake3WitnessDestination;
    if (columns) |out| try out.validate(3 * hash.g.len, 3 * hash.xor.len);
    if (destination) |out| try out.validate(3 * hash.g.len, 3 * hash.xor.len);
    var selected: [2]Digest = undefined;
    var adopted: [2]Caller = undefined;
    // Compute parent source-use counts from the authenticated canonical frame plan.
    const root_bindings = [2]frame.Binding{ .{ .role = .left, .caller = .{ .circuit = plan.namespace + 4, .first_wire = 0 } }, .{ .role = .right, .caller = .{ .circuit = plan.namespace + 5, .first_wire = 0 } } };
    var root_shape = try @import("blake3_frame_route.zig").buildWithPayloadPlan(backing, plan.namespace + 6, core.channel.blake3.Frame{ .node = .{ .left = zero, .right = zero } }, &root_bindings, null, hash);
    const root_source_uses = root_shape.child_uses;
    root_shape.deinit();
    for (0..2) |branch| {
        const bindings = [2]frame.Binding{ .{ .role = .left, .caller = plan.input(branch, 0) }, .{ .role = .right, .caller = plan.input(branch, 1) } };
        const target = try part(destination, columns, branch, hash.g.len, hash.xor.len);
        var node = if (nonhash) |sink| try DirectFrame.prepare(backing, plan.namespace + 2 + @as(u32, @intCast(branch)), core.channel.blake3.Frame{ .node = .{ .left = w.inputs[branch][0], .right = w.inputs[branch][1] } }, &bindings, null, zero, live, target.rows, target.columns, hash, .{ .sink = sink, .retain_output = false }) else try frame.destinationWithPlan(backing, plan.namespace + 2 + @as(u32, @intCast(branch)), core.channel.blake3.Frame{ .node = .{ .left = w.inputs[branch][0], .right = w.inputs[branch][1] } }, &bindings, null, zero, live, target.rows, target.columns, hash);
        defer node.deinit();
        useOutput(&node, 1);
        try gs.appendSlice(a, node.rows.g_rows);
        try xs.appendSlice(a, node.rows.xor_rows);
        if (nonhash == null) {
            try bs.appendSlice(a, node.rows.boundary_rows[0 .. node.rows.boundary_rows.len - 8]);
            try rs.appendSlice(a, node.route_rows);
        }
        const computed = node.digest orelse zero;
        adopted[branch] = .{ .circuit = plan.namespace + 4 + @as(u32, @intCast(branch)), .first_wire = 0 };
        selected[branch] = if (w.active[branch] == 1) computed else w.opaque_digests[branch];
        for (0..2) |side| for (0..8) |i| {
            const uses = try std.math.add(u32, plan.queries, node.source_uses[side][i]);
            const row = try group.word.logicalRow(plan.namespace, @intCast(branch * 16 + side * 8 + i), uses, word(w.inputs[branch][side], i));
            const fixed = try group.word.logicalRow(plan.namespace, @intCast(branch * 16 + side * 8 + i), uses, 0);
            try Nonhash.append(9, nonhash, a, &ws, row, fixed);
        };
        try Nonhash.append(9, nonhash, a, &ws, try group.word.logicalRow(plan.namespace, @intCast(32 + branch), plan.queries + 8, w.active[branch]), try group.word.logicalRow(plan.namespace, @intCast(32 + branch), plan.queries + 8, 0));
        for (0..8) |i| {
            const opaque_source = Caller{ .circuit = plan.namespace + 1, .first_wire = @intCast(branch * 8) };
            try Nonhash.append(9, nonhash, a, &ws, try group.word.logicalRow(opaque_source.circuit, opaque_source.first_wire + @as(u32, @intCast(i)), 1, word(w.opaque_digests[branch], i)), try group.word.logicalRow(opaque_source.circuit, opaque_source.first_wire + @as(u32, @intCast(i)), 1, 0));
            const schedule = scalar.Schedule{ .bit = plan.flag(branch), .current = endpoint(opaque_source, i), .sibling = endpoint(output(plan.namespace + 2 + @as(u32, @intCast(branch)), hash), i), .destination_circuit = adopted[branch].circuit, .left_wire = @intCast(i), .right_wire = @intCast(8 + i), .left_uses = root_source_uses[branch][i], .right_uses = 0 };
            try Nonhash.append(13, nonhash, a, &ss, try scalar.logicalRow(schedule, w.active[branch], word(w.opaque_digests[branch], i), word(computed, i)), try scalar.fixedRow(schedule));
        }
    }
    const public_one = try group.boundary.logicalRow(plan.namespace, 34, M.fromCanonical(plan.queries), 1);
    try Nonhash.append(2, nonhash, a, &bs, public_one, public_one);
    const root_target = try part(destination, columns, 2, hash.g.len, hash.xor.len);
    var root = if (nonhash) |sink| try DirectFrame.prepare(backing, plan.namespace + 6, core.channel.blake3.Frame{ .node = .{ .left = selected[0], .right = selected[1] } }, &root_bindings, null, zero, live, root_target.rows, root_target.columns, hash, .{ .sink = sink, .retain_output = false }) else try frame.destinationWithPlan(backing, plan.namespace + 6, core.channel.blake3.Frame{ .node = .{ .left = selected[0], .right = selected[1] } }, &root_bindings, null, zero, live, root_target.rows, root_target.columns, hash);
    defer root.deinit();
    useOutput(&root, plan.queries);
    try gs.appendSlice(a, root.rows.g_rows);
    try xs.appendSlice(a, root.rows.xor_rows);
    if (nonhash == null) {
        try bs.appendSlice(a, root.rows.boundary_rows[0 .. root.rows.boundary_rows.len - 8]);
        try rs.appendSlice(a, root.route_rows);
    }
    for (0..plan.queries) |_| for (0..8) |i| {
        const equality = try group.rootEquality(output(plan.namespace + 6, hash), plan.root_source, @intCast(i));
        try Nonhash.append(7, nonhash, a, &rs, try group.route.logicalRow(equality, .{ word(root.digest orelse zero, i), 0 }), try group.route.fixedRow(equality));
    };
    const g_rows = try gs.toOwnedSlice(a);
    const xor_rows = try xs.toOwnedSlice(a);
    const boundary_rows = try bs.toOwnedSlice(a);
    const route_rows = try rs.toOwnedSlice(a);
    const word_rows = try ws.toOwnedSlice(a);
    const select_rows = try ss.toOwnedSlice(a);
    return .{ .arena = arena, .g_rows = g_rows, .xor_rows = xor_rows, .boundary_rows = boundary_rows, .route_rows = route_rows, .word_rows = word_rows, .select_rows = select_rows, .root = root.digest orelse zero, .hash_metadata = if (columns) |out| out.metadata() else if (destination) |out| out.fixed else null };
}
