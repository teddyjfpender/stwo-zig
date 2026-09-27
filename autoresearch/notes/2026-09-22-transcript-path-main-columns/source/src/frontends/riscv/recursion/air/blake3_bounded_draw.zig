//! Fixed-capacity native retry fragment with authenticated private u64 counters.
const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const frame = @import("blake3_frame_witness.zig");
const layout = @import("blake3_draw_hash_layout.zig");
pub const draw = @import("blake3_draw_witness.zig");
pub const control = @import("blake3_retry_control.zig");
pub const counter = @import("blake3_counter_step.zig");
pub const Statement = struct { namespace: u32, capacity: u32, state: [32]u8, state_source: control.Caller, start: u64, counter_source: control.Caller, consumption: draw.Consumption = .two, final_counter_uses: [2]u32 = .{ 1, 1 } };
pub const Rows = struct { g_rows: []draw.g.Row, xor_rows: []draw.xor.Row, boundary_rows: []draw.boundary.Row, challenge_rows: []draw.challenge.Row, route_rows: []draw.route.Row, control_rows: []control.Row, counter_rows: []counter.Row };
pub const Prepared = struct {
    arena: std.heap.ArenaAllocator,
    /// Main values live in caller columns when true; G/XOR rows hold witness metadata.
    hash_rows_are_metadata: bool = false,
    rows: Rows,
    state_uses: [8]u32,
    counter_uses: [2]u32,
    output: control.Caller,
    final_counter: control.Caller,
    next_counter: ?u64,
    selected: ?[8]M31,
    pub fn deinit(self: *Prepared) void {
        self.arena.deinit();
    }
};
const Lists = struct {
    boundary_rows: std.ArrayList(draw.boundary.Row) = .empty,
    challenge_rows: std.ArrayList(draw.challenge.Row) = .empty,
    route_rows: std.ArrayList(draw.route.Row) = .empty,
    control_rows: std.ArrayList(control.Row) = .empty,
    counter_rows: std.ArrayList(counter.Row) = .empty,
    fn finish(self: *Lists, a: std.mem.Allocator, destination: HashDestination) !Rows {
        var out: Rows = undefined;
        out.g_rows = destination.g_rows;
        out.xor_rows = destination.xor_rows;
        inline for (std.meta.fields(Lists)) |field| @field(out, field.name) = try @field(self, field.name).toOwnedSlice(a);
        return out;
    }
};
pub fn prepare(a: std.mem.Allocator, s: Statement) !Prepared {
    return build(a, s, true, null, null);
}
pub fn trusted(a: std.mem.Allocator, s: Statement) !Prepared {
    return build(a, s, false, null, null);
}
pub const HashDestination = frame.HashDestination;
pub fn requiredHashRows(a: std.mem.Allocator, capacity: u32) !layout.Counts {
    if (capacity == 0) return error.InvalidBoundedBlake3Draw;
    return layout.required(a, capacity);
}
pub fn prepareInto(a: std.mem.Allocator, s: Statement, destination: HashDestination) !Prepared {
    return build(a, s, true, destination, null);
}
pub fn trustedInto(a: std.mem.Allocator, s: Statement, destination: HashDestination) !Prepared {
    return build(a, s, false, destination, null);
}
pub const MainColumns = frame.MainColumns;
pub fn prepareMainColumns(a: std.mem.Allocator, s: Statement, columns: MainColumns) !Prepared {
    return build(a, s, true, .{ .g_rows = columns.g_rows.metadata, .xor_rows = columns.xor_rows.metadata }, columns);
}
fn build(backing: std.mem.Allocator, s: Statement, live: bool, borrowed: ?HashDestination, columns: ?MainColumns) !Prepared {
    const p = core.fields.m31.Modulus;
    const end = @as(u64, s.namespace) + 2 * @as(u64, s.capacity) + 3;
    if (s.capacity == 0 or end > p or @as(u64, s.capacity) * 2 >= p) return error.InvalidBoundedBlake3Draw;
    for ([_]control.Caller{ s.state_source, s.counter_source }) |source| if (source.circuit >= s.namespace and source.circuit < end) return error.InvalidBoundedBlake3Draw;
    if (s.state_source.circuit == s.counter_source.circuit) return error.InvalidBoundedBlake3Draw;
    const counter_circuit: u32 = @intCast(end - 3);
    const pending_circuit: u32 = @intCast(end - 2);
    const output = control.Caller{ .circuit = @intCast(end - 1), .first_wire = 0 };
    var arena = std.heap.ArenaAllocator.init(backing);
    errdefer arena.deinit();
    const a = arena.allocator();
    var plan = try layout.build(backing);
    defer plan.deinit();
    for (plan.output, 0..) |wire, j| if (wire != plan.output[0] + j) return error.InvalidBoundedBlake3Draw;
    const counts = try layout.counts(&plan, s.capacity);
    if (borrowed) |out| if (out.g_rows.len != counts.g or out.xor_rows.len != counts.xor) return error.InvalidBlake3WitnessDestination;
    if (columns) |out| try out.validate(counts.g, counts.xor);
    const hash_rows = HashDestination{
        .g_rows = if (borrowed) |out| out.g_rows else try a.alloc(draw.g.Row, counts.g),
        .xor_rows = if (borrowed) |out| out.xor_rows else try a.alloc(draw.xor.Row, counts.xor),
    };
    var lists = Lists{};
    var state_uses: [8]u32 = @splat(0);
    var initial_counter_uses: [2]u32 = @splat(0);
    var pending: u1 = 1;
    var current = s.start;
    var selected: [8]M31 = @splat(M31.zero());
    var consumed: u32 = 0;
    for (0..s.capacity) |i| {
        const ordinal: u32 = @intCast(i);
        const hash_circuit = s.namespace + 2 * ordinal;
        const source = if (i == 0) s.counter_source else control.Caller{ .circuit = counter_circuit, .first_wire = 2 * (ordinal - 1) };
        const destination = control.Caller{ .circuit = counter_circuit, .first_wire = 2 * ordinal };
        const message = core.channel.blake3.Frame{ .draw = .{ .state = s.state, .index = current } };
        const bindings = [_]frame.Binding{.{ .role = .state, .caller = s.state_source }};
        const payload = frame.PayloadBinding{ .role = .draw_index, .caller = source, .word_count = 2 };
        const out = HashDestination{ .g_rows = hash_rows.g_rows[i * plan.g.len ..][0..plan.g.len], .xor_rows = hash_rows.xor_rows[i * plan.xor.len ..][0..plan.xor.len] };
        var hash = if (columns) |target| try frame.prepareMainColumns(backing, hash_circuit, message, &bindings, payload, @splat(0), try target.slice(i * plan.g.len, plan.g.len, i * plan.xor.len, plan.xor.len)) else if (live) try frame.prepareInto(backing, hash_circuit, message, &bindings, payload, @splat(0), out) else try frame.trustedInto(backing, hash_circuit, message, &bindings, payload, @splat(0), out);
        defer hash.deinit();
        for (&state_uses, hash.source_uses[0]) |*sum, uses| {
            sum.* = try std.math.add(u32, sum.*, uses);
            if (sum.* >= p) return error.InvalidBoundedBlake3Draw;
        }
        var next_uses: [2]u32 = undefined;
        for (&next_uses, hash.payload_uses) |*sum, uses| sum.* = try std.math.add(u32, uses, 1);
        if (i == 0) initial_counter_uses = next_uses else if (!std.mem.eql(u32, &initial_counter_uses, &next_uses)) return error.InvalidBoundedBlake3Draw;
        var value_uses: [8]u32 = @splat(0);
        @memset(value_uses[0..s.consumption.words()], 1);
        const challenge_schedule = draw.challenge.Schedule{ .source_circuit = hash_circuit, .source_first = plan.output[0], .destination_circuit = hash_circuit + 1, .destination_first = 0, .uses = value_uses, .status_wire = 8, .status_uses = 1 };
        var candidate = try draw.challenge.fixedRow(challenge_schedule);
        if (live) {
            var words: [8]u32 = undefined;
            for (&words, 0..) |*word, j| word.* = std.mem.readInt(u32, hash.digest.?[4 * j ..][0..4], .little);
            candidate = try draw.challenge.logicalRow(challenge_schedule, words);
        }
        var values: [8]M31 = undefined;
        for (&values, 0..) |*value, j| value.* = candidate[j * 8 + 7];
        const status: u1 = @intCast(candidate[70].v);
        const control_schedule = control.Schedule{ .pending = .{ .circuit = pending_circuit, .wire = ordinal }, .status = .{ .circuit = hash_circuit + 1, .wire = 8 }, .next_pending = .{ .circuit = pending_circuit, .wire = ordinal + 1 }, .next_uses = if (i + 1 == s.capacity) 1 else 2, .values = .{ .circuit = hash_circuit + 1, .first_wire = 0 }, .destination = output, .count_wire = 8, .ordinal = ordinal + 1, .words = @intCast(s.consumption.words()) };
        const counter_schedule = counter.Schedule{ .source = source, .increment = control_schedule.pending, .destination = destination, .uses = if (i + 1 == s.capacity) s.final_counter_uses else next_uses };
        try lists.control_rows.append(a, if (live) try control.logicalRow(control_schedule, pending, status, values) else try control.fixedRow(control_schedule));
        try lists.counter_rows.append(a, if (live) try counter.logicalRow(counter_schedule, current, pending) else try counter.fixedRow(counter_schedule));
        if (live) {
            current = try std.math.add(u64, current, pending);
            if (pending == 1 and status == 1) {
                selected = values;
                consumed = ordinal + 1;
                pending = 0;
            }
        }
        try lists.boundary_rows.appendSlice(a, hash.rows.boundary_rows[0 .. hash.rows.boundary_rows.len - 8]);
        try lists.route_rows.appendSlice(a, hash.route_rows);
        try lists.challenge_rows.append(a, candidate);
    }
    if (live and pending != 0) return error.Blake3RetryCapacityExhausted;
    try lists.boundary_rows.append(a, try draw.boundary.logicalCoordinates(pending_circuit, 0, M31.fromCanonical(2), .{ M31.one(), M31.zero(), M31.zero(), M31.zero() }));
    try lists.boundary_rows.append(a, try draw.boundary.logicalCoordinates(pending_circuit, s.capacity, M31.one().neg(), @splat(M31.zero())));
    try lists.boundary_rows.append(a, try draw.boundary.privateCoordinates(output.circuit, 8, M31.one().neg(), .{ M31.fromCanonical(consumed), M31.zero(), M31.zero(), M31.zero() }));
    const rows = try lists.finish(a, hash_rows);
    return .{ .hash_rows_are_metadata = columns != null, .arena = arena, .rows = rows, .state_uses = state_uses, .counter_uses = initial_counter_uses, .output = output, .final_counter = .{ .circuit = counter_circuit, .first_wire = 2 * (s.capacity - 1) }, .next_counter = if (live) current else null, .selected = if (live) selected else null };
}
