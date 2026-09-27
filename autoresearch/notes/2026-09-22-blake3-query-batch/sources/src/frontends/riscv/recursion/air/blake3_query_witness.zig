//! Native raw query batches from one authenticated state producer.
const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const frame_hash = @import("blake3_frame_witness.zig");
const graph = @import("blake3_hash_plan.zig");
pub const g = @import("blake3_g_call.zig");
pub const xor = @import("blake3_xor_call.zig");
pub const boundary = @import("blake3_boundary.zig");
pub const mask = @import("blake3_query_mask.zig");
pub const route = frame_hash.route;
pub const Statement = struct {
    namespace: u32,
    state: [32]u8,
    state_source: @import("blake3_frame_route.zig").Caller,
    start: u64,
    log_domain_size: u32,
    values: []const u32,
};
pub const Prepared = struct {
    arena: std.heap.ArenaAllocator,
    g_rows: []g.Row,
    xor_rows: []xor.Row,
    boundary_rows: []boundary.Row,
    mask_rows: []mask.Row,
    route_rows: []route.Row,
    state_uses: [8]u32,
    next_draw: u64,
    pub fn deinit(self: *Prepared) void {
        self.arena.deinit();
        self.* = undefined;
    }
    pub fn logs(self: *const Prepared) [5]u32 {
        return .{ log(self.g_rows.len), log(self.xor_rows.len), log(self.boundary_rows.len), log(self.mask_rows.len), log(self.route_rows.len) };
    }
    fn log(n: usize) u32 {
        return if (n <= 1) 1 else std.math.log2_int_ceil(usize, n);
    }
};
pub fn prepare(a: std.mem.Allocator, s: Statement) !Prepared {
    return build(a, s, true);
}
pub fn trusted(a: std.mem.Allocator, s: Statement) !Prepared {
    return build(a, s, false);
}
fn build(backing: std.mem.Allocator, s: Statement, live: bool) !Prepared {
    if (s.log_domain_size > 31 or s.namespace >= core.fields.m31.Modulus) return error.InvalidBlake3Queries;
    const blocks = s.values.len / 8 + @intFromBool(s.values.len % 8 != 0);
    const end = std.math.add(u64, s.namespace, std.math.mul(u64, blocks, 2) catch return error.InvalidBlake3Queries) catch return error.InvalidBlake3Queries;
    if (end > core.fields.m31.Modulus or (s.state_source.circuit >= s.namespace and s.state_source.circuit < end)) return error.InvalidBlake3Queries;
    const next = std.math.add(u64, s.start, blocks) catch return error.InvalidBlake3Queries;
    const query_mask = (@as(u32, 1) << @as(u5, @intCast(s.log_domain_size))) - 1;
    for (s.values) |value| if (value > query_mask) return error.InvalidBlake3Queries;
    var arena = std.heap.ArenaAllocator.init(backing);
    errdefer arena.deinit();
    const a = arena.allocator();
    var gs: std.ArrayList(g.Row) = .empty;
    var xs: std.ArrayList(xor.Row) = .empty;
    var bs: std.ArrayList(boundary.Row) = .empty;
    var ms: std.ArrayList(mask.Row) = .empty;
    var rs: std.ArrayList(route.Row) = .empty;
    var state_uses: [8]u32 = @splat(0);
    for (0..blocks) |block| {
        const circuit = s.namespace + @as(u32, @intCast(block * 2));
        const frame = core.channel.blake3.Frame{ .draw = .{ .state = s.state, .index = s.start + block } };
        const bindings = [_]frame_hash.Binding{.{ .role = .state, .caller = s.state_source }};
        var hash = if (live) try frame_hash.prepare(a, circuit, frame, &bindings, @splat(0)) else try frame_hash.trusted(a, circuit, frame, &bindings, @splat(0));
        defer hash.deinit();
        const count = @min(8, s.values.len - block * 8);
        for (0..8) |i| hash.rows.xor_rows[hash.rows.xor_rows.len - 16 + i][17] = M31.fromCanonical(if (i < count) 1 else 0);
        try gs.appendSlice(a, hash.rows.g_rows);
        try xs.appendSlice(a, hash.rows.xor_rows);
        try bs.appendSlice(a, hash.rows.boundary_rows[0 .. hash.rows.boundary_rows.len - 8]);
        try rs.appendSlice(a, hash.route_rows);
        for (&state_uses, hash.source_uses[0]) |*total, use| {
            total.* = std.math.add(u32, total.*, use) catch return error.InvalidBlake3Queries;
            if (total.* >= core.fields.m31.Modulus) return error.InvalidBlake3Queries;
        }
        var plan = try graph.build(a, try frame.encodedSize());
        defer plan.deinit();
        for (0..count) |i| {
            const schedule = mask.Schedule{ .source_circuit = circuit, .source_wire = plan.output[i], .destination_circuit = circuit + 1, .destination_wire = @intCast(i), .uses = 1, .log_domain_size = s.log_domain_size };
            const row = if (live) try mask.logicalRow(schedule, std.mem.readInt(u32, hash.digest.?[4 * i ..][0..4], .little)) else try mask.fixedRow(schedule);
            try ms.append(a, row);
            var output = try boundary.logicalRow(circuit + 1, @intCast(i), M31.one().neg(), s.values[block * 8 + i]);
            if (live) output[0..4].* = row[4..8].*;
            try bs.append(a, output);
        }
    }
    const g_rows = try gs.toOwnedSlice(a);
    const xor_rows = try xs.toOwnedSlice(a);
    const boundary_rows = try bs.toOwnedSlice(a);
    const mask_rows = try ms.toOwnedSlice(a);
    const route_rows = try rs.toOwnedSlice(a);
    return .{ .arena = arena, .g_rows = g_rows, .xor_rows = xor_rows, .boundary_rows = boundary_rows, .mask_rows = mask_rows, .route_rows = route_rows, .state_uses = state_uses, .next_draw = next };
}
