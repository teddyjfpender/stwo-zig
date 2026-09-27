//! Native raw query batches from one authenticated state producer.
const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const frame_hash = @import("blake3_frame_witness.zig");
const layout = @import("blake3_draw_hash_layout.zig");
pub const g = @import("blake3_g_call.zig");
pub const xor = @import("blake3_xor_call.zig");
pub const boundary = @import("blake3_boundary.zig");
pub const mask = @import("blake3_query_mask.zig");
pub const route = frame_hash.route;
pub const counter_step = @import("blake3_counter_step.zig");
const Caller = @import("blake3_frame_route.zig").Caller;
pub const Statement = struct {
    namespace: u32,
    state: [32]u8,
    state_source: @import("blake3_frame_route.zig").Caller,
    start: u64,
    log_domain_size: u32,
    values: []const u32,
    export_outputs: bool = false,
    counter_source: ?Caller = null,
    final_counter_uses: [2]u32 = .{ 1, 1 },
};
pub const Prepared = struct {
    arena: std.heap.ArenaAllocator,
    /// Borrowed fixed tails in column mode; full hash-row slices are empty.
    hash_metadata: ?@import("blake3_hash_metadata.zig").Rows = null,
    g_rows: []g.Row,
    xor_rows: []xor.Row,
    boundary_rows: []boundary.Row,
    mask_rows: []mask.Row,
    route_rows: []route.Row,
    state_uses: [8]u32,
    next_draw: u64,
    counter_rows: []counter_step.Row,
    counter_uses: [2]u32,
    final_counter: ?Caller,
    outputs: []const @import("blake3_byte_route.zig").Endpoint,
    pub fn deinit(self: *Prepared) void {
        self.arena.deinit();
        self.* = undefined;
    }
    pub fn logs(self: *const Prepared) [5]u32 {
        return .{ log(if (self.hash_metadata) |m| m.g_rows.len else self.g_rows.len), log(if (self.hash_metadata) |m| m.xor_rows.len else self.xor_rows.len), log(self.boundary_rows.len), log(self.mask_rows.len), log(self.route_rows.len) };
    }
    fn log(n: usize) u32 {
        return if (n <= 1) 1 else std.math.log2_int_ceil(usize, n);
    }
};
pub fn prepare(a: std.mem.Allocator, s: Statement) !Prepared {
    return build(a, s, true, null, null);
}
pub fn trusted(a: std.mem.Allocator, s: Statement) !Prepared {
    return build(a, s, false, null, null);
}
pub const HashDestination = frame_hash.HashDestination;
pub const HashCounts = layout.Counts;
pub fn requiredHashRows(a: std.mem.Allocator, query_count: usize) !HashCounts {
    return layout.required(a, query_count / 8 + @intFromBool(query_count % 8 != 0));
}
pub fn prepareInto(a: std.mem.Allocator, s: Statement, destination: HashDestination) !Prepared {
    return build(a, s, true, destination, null);
}
pub fn trustedInto(a: std.mem.Allocator, s: Statement, destination: HashDestination) !Prepared {
    return build(a, s, false, destination, null);
}
pub const MainColumns = frame_hash.MainColumns;
pub fn prepareMainColumns(a: std.mem.Allocator, s: Statement, columns: MainColumns) !Prepared {
    return build(a, s, true, null, columns);
}
fn build(backing: std.mem.Allocator, s: Statement, live: bool, borrowed: ?HashDestination, columns: ?MainColumns) !Prepared {
    if (s.log_domain_size > 31 or s.namespace >= core.fields.m31.Modulus) return error.InvalidBlake3Queries;
    const blocks = s.values.len / 8 + @intFromBool(s.values.len % 8 != 0);
    const counter_circuit = std.math.add(u64, s.namespace, std.math.mul(u64, blocks, 2) catch return error.InvalidBlake3Queries) catch return error.InvalidBlake3Queries;
    const end = counter_circuit + @as(u64, @intFromBool(s.counter_source != null and blocks > 0));
    if (end > core.fields.m31.Modulus or (s.state_source.circuit >= s.namespace and s.state_source.circuit < end)) return error.InvalidBlake3Queries;
    if (s.counter_source) |source| if (source.circuit >= s.namespace and source.circuit < end) return error.InvalidBlake3Queries;
    const next = std.math.add(u64, s.start, blocks) catch return error.InvalidBlake3Queries;
    const query_mask = (@as(u32, 1) << @as(u5, @intCast(s.log_domain_size))) - 1;
    for (s.values) |value| if (value > query_mask) return error.InvalidBlake3Queries;
    var arena = std.heap.ArenaAllocator.init(backing);
    errdefer arena.deinit();
    const a = arena.allocator();
    var outputs: std.ArrayList(@import("blake3_byte_route.zig").Endpoint) = .empty;
    var counters: std.ArrayList(counter_step.Row) = .empty;
    var initial_counter_uses: [2]u32 = @splat(0);
    var final_counter = s.counter_source;
    var plan = try layout.build(backing);
    defer plan.deinit();
    const counts = try layout.counts(&plan, blocks);
    if (borrowed) |out| if (out.g_rows.len != counts.g or out.xor_rows.len != counts.xor) return error.InvalidBlake3WitnessDestination;
    if (columns) |out| try out.validate(counts.g, counts.xor);
    const g_rows: []g.Row = if (columns != null) &.{} else if (borrowed) |out| out.g_rows else try a.alloc(g.Row, counts.g);
    const xor_rows: []xor.Row = if (columns != null) &.{} else if (borrowed) |out| out.xor_rows else try a.alloc(xor.Row, counts.xor);
    var bs: std.ArrayList(boundary.Row) = .empty;
    var ms: std.ArrayList(mask.Row) = .empty;
    var rs: std.ArrayList(route.Row) = .empty;
    var state_uses: [8]u32 = @splat(0);
    for (0..blocks) |block| {
        const circuit = s.namespace + @as(u32, @intCast(block * 2));
        const frame = core.channel.blake3.Frame{ .draw = .{ .state = s.state, .index = s.start + block } };
        const bindings = [_]frame_hash.Binding{.{ .role = .state, .caller = s.state_source }};
        const payload: ?frame_hash.PayloadBinding = if (final_counter) |source| .{ .role = .draw_index, .caller = source, .word_count = 2 } else null;
        const out = if (columns != null) HashDestination{ .g_rows = &.{}, .xor_rows = &.{} } else HashDestination{ .g_rows = g_rows[block * plan.g.len ..][0..plan.g.len], .xor_rows = xor_rows[block * plan.xor.len ..][0..plan.xor.len] };
        var hash = if (columns) |target| try frame_hash.prepareMainColumns(backing, circuit, frame, &bindings, payload, @splat(0), try target.slice(block * plan.g.len, plan.g.len, block * plan.xor.len, plan.xor.len)) else if (live) try frame_hash.prepareInto(backing, circuit, frame, &bindings, payload, @splat(0), out) else try frame_hash.trustedInto(backing, circuit, frame, &bindings, payload, @splat(0), out);
        defer hash.deinit();
        if (payload) |binding| {
            var uses: [2]u32 = undefined;
            for (&uses, hash.payload_uses) |*total, read| total.* = try std.math.add(u32, read, 1);
            if (block == 0) initial_counter_uses = uses else if (!std.mem.eql(u32, &initial_counter_uses, &uses)) return error.InvalidBlake3Queries;
            const destination = Caller{ .circuit = @intCast(counter_circuit), .first_wire = @intCast(2 * block) };
            const schedule = counter_step.Schedule{ .source = binding.caller, .increment = .{ .circuit = @intCast(counter_circuit), .wire = @intCast(2 * blocks) }, .destination = destination, .uses = if (block + 1 == blocks) s.final_counter_uses else uses };
            try counters.append(a, if (live) try counter_step.logicalRow(schedule, s.start + block, 1) else try counter_step.fixedRow(schedule));
            final_counter = destination;
        }
        const count = @min(8, s.values.len - block * 8);
        for (0..8) |i| @import("blake3_hash_metadata.zig").xorUse(hash.rows.xor_rows, hash.hash_metadata, plan.xor.len - 16 + i).* = M31.fromCanonical(if (i < count) 1 else 0);
        try bs.appendSlice(a, hash.rows.boundary_rows[0 .. hash.rows.boundary_rows.len - 8]);
        try rs.appendSlice(a, hash.route_rows);
        for (&state_uses, hash.source_uses[0]) |*total, use| {
            total.* = std.math.add(u32, total.*, use) catch return error.InvalidBlake3Queries;
            if (total.* >= core.fields.m31.Modulus) return error.InvalidBlake3Queries;
        }
        for (0..count) |i| {
            const schedule = mask.Schedule{ .source_circuit = circuit, .source_wire = plan.output[i], .destination_circuit = circuit + 1, .destination_wire = @intCast(i), .uses = 1, .log_domain_size = s.log_domain_size };
            const row = if (live) try mask.logicalRow(schedule, std.mem.readInt(u32, hash.digest.?[4 * i ..][0..4], .little)) else try mask.fixedRow(schedule);
            try ms.append(a, row);
            if (s.export_outputs) {
                try outputs.append(a, .{ .circuit = circuit + 1, .wire = @intCast(i) });
            } else {
                var output = try boundary.logicalRow(circuit + 1, @intCast(i), M31.one().neg(), s.values[block * 8 + i]);
                if (live) output[0..4].* = row[4..8].*;
                try bs.append(a, output);
            }
        }
    }
    if (s.counter_source != null and blocks > 0) try bs.append(a, try boundary.logicalCoordinates(@intCast(counter_circuit), @intCast(2 * blocks), M31.fromCanonical(@intCast(blocks)), .{ M31.one(), M31.zero(), M31.zero(), M31.zero() }));
    const boundary_rows = try bs.toOwnedSlice(a);
    const mask_rows = try ms.toOwnedSlice(a);
    const route_rows = try rs.toOwnedSlice(a);
    return .{ .hash_metadata = if (columns) |out| out.metadata() else null, .counter_rows = try counters.toOwnedSlice(a), .counter_uses = initial_counter_uses, .final_counter = final_counter, .outputs = try outputs.toOwnedSlice(a), .arena = arena, .g_rows = g_rows, .xor_rows = xor_rows, .boundary_rows = boundary_rows, .mask_rows = mask_rows, .route_rows = route_rows, .state_uses = state_uses, .next_draw = next };
}
