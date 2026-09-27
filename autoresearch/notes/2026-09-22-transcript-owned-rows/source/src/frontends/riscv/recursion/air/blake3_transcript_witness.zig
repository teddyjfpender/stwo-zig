//! Compile native absorption and secure draws into authenticated dataflow.
//! Operation order determines state links, draw counters and absorption resets.
const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const frame_hash = @import("blake3_frame_witness.zig");
const draw = @import("blake3_draw_witness.zig");
const bounded = @import("blake3_bounded_draw.zig");
pub const retry_control = bounded.control;
pub const counter_step = bounded.counter;
const queries = @import("blake3_query_witness.zig");
pub const query_mask = queries.mask;
const graph = @import("blake3_hash_plan.zig");
pub const g = draw.g;
pub const xor = draw.xor;
pub const boundary = draw.boundary;
pub const challenge = draw.challenge;
pub const route = draw.route;
pub const Caller = @import("blake3_frame_route.zig").Caller;
/// Exact external reads, in operation order. Storage belongs to Prepared.
pub const PayloadReads = struct { operation: usize, source: Caller, uses: []const u32 };
/// Semantic identity assigned by the protocol operation builder.
pub const OutputRole = union(enum) { universal: usize, composition, oods, deep, fri: usize, riscv_relation: usize };
pub const DrawOutput = struct { operation: usize, role: OutputRole, source: Caller, words: usize };
pub const QueryOutput = struct { operation: usize, query: usize, source: @import("blake3_byte_route.zig").Endpoint };
pub const RootReads = struct { operation: usize, source: Caller, uses: [8]u32 };
pub const Operation = union(enum) {
    integer: u64,
    routed_integer: struct { value: u64, source: Caller },
    /// Caller supplies bounded raw word bytes with the returned multiplicities.
    routed_words: struct { values: []const u32, source: Caller },
    /// Caller supplies canonical M31 encodings (e.g. field_bytes AIR), not
    /// arbitrary byte witnesses. Four consecutive words per secure field.
    routed_felts: struct { values: []const core.fields.qm31.QM31, source: Caller },
    words: []const u32,
    felts: []const core.fields.qm31.QM31,
    root: [32]u8,
    routed_root: struct { value: [32]u8, source: Caller },
    pow: struct { bits: u32, nonce: u64, nonce_source: ?Caller = null },
    queries: struct { log_domain_size: u32, values: []const u32, export_outputs: bool = false },
    secure: struct { output: ?OutputRole = null, attempts: u32, consumption: draw.Consumption = .one, values: [8]M31 },
};
pub const Prepared = struct {
    row_allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    g_rows: []g.Row,
    xor_rows: []xor.Row,
    boundary_rows: []boundary.Row,
    challenge_rows: []challenge.Row,
    route_rows: []route.Row,
    query_rows: []query_mask.Row,
    control_rows: []retry_control.Row,
    counter_rows: []counter_step.Row,
    next_draw: u64,
    payload_reads: []const PayloadReads,
    draw_outputs: []const DrawOutput,
    root_reads: []const RootReads,
    query_outputs: []const QueryOutput,
    final_digest: ?[32]u8,
    pub fn deinit(self: *Prepared) void {
        self.row_allocator.free(self.g_rows);
        self.row_allocator.free(self.xor_rows);
        self.row_allocator.free(self.boundary_rows);
        self.row_allocator.free(self.challenge_rows);
        self.row_allocator.free(self.route_rows);
        self.row_allocator.free(self.query_rows);
        self.row_allocator.free(self.control_rows);
        self.row_allocator.free(self.counter_rows);
        self.arena.deinit();
        self.* = undefined;
    }
    pub fn logs(self: *const Prepared) [6]u32 {
        return .{ log(self.g_rows.len), log(self.xor_rows.len), log(self.boundary_rows.len), log(self.challenge_rows.len), log(self.route_rows.len), log(self.query_rows.len) };
    }
    fn log(n: usize) u32 {
        return if (n <= 1) 1 else std.math.log2_int_ceil(usize, n);
    }
};
pub fn prepare(a: std.mem.Allocator, namespace: u32, operations: []const Operation) !Prepared {
    return build(a, namespace, operations, true, null);
}
pub fn trusted(a: std.mem.Allocator, namespace: u32, operations: []const Operation) !Prepared {
    return build(a, namespace, operations, false, null);
}
/// Capacity is verifier-owned; recorded attempt counts are ignored in this mode.
pub fn prepareBounded(a: std.mem.Allocator, namespace: u32, operations: []const Operation, capacity: u32) !Prepared {
    return build(a, namespace, operations, true, capacity);
}
pub fn trustedBounded(a: std.mem.Allocator, namespace: u32, operations: []const Operation, capacity: u32) !Prepared {
    return build(a, namespace, operations, false, capacity);
}
fn build(backing: std.mem.Allocator, namespace: u32, operations: []const Operation, live: bool, capacity: ?u32) !Prepared {
    if (capacity != null and capacity.? == 0) return error.InvalidBlake3Transcript;
    var end: u64 = @as(u64, namespace) + @intFromBool(capacity != null);
    for (operations) |op| {
        const count: u64 = switch (op) {
            .integer, .routed_integer, .words, .felts, .routed_words, .routed_felts => 1,
            .root, .routed_root => 2,
            .pow => |pow| blk: {
                if (pow.bits > core.channel.blake3.MAX_POW_BITS) return error.InvalidBlake3Transcript;
                break :blk 2;
            },
            .queries => |q| blk: {
                const blocks = q.values.len / 8 + @intFromBool(q.values.len % 8 != 0);
                const slots = std.math.mul(u64, blocks, 2) catch return error.InvalidBlake3Transcript;
                break :blk slots + @intFromBool(capacity != null and blocks > 0);
            },
            .secure => |s| blk: {
                if (capacity) |limit| break :blk 2 * @as(u64, limit) + 3;
                if (s.attempts == 0) return error.InvalidBlake3Transcript;
                break :blk 2 * @as(u64, s.attempts);
            },
        };
        end = std.math.add(u64, end, count) catch return error.InvalidBlake3Transcript;
    }
    if (end >= core.fields.m31.Modulus) return error.InvalidBlake3Transcript;
    for (operations) |op| {
        const source: ?Caller = switch (op) {
            .routed_root => |value| value.source,
            .routed_integer => |value| value.source,
            .pow => |value| value.nonce_source,
            .routed_words => |value| value.source,
            .routed_felts => |value| value.source,
            else => null,
        };
        if (source) |value| if (value.circuit >= namespace and value.circuit <= end)
            return error.InvalidBlake3Transcript;
    }
    var arena = std.heap.ArenaAllocator.init(backing);
    errdefer arena.deinit();
    const a = arena.allocator();
    var reads: std.ArrayList(PayloadReads) = .empty;
    var roots: std.ArrayList(RootReads) = .empty;
    var query_outputs: std.ArrayList(QueryOutput) = .empty;
    var outputs: std.ArrayList(DrawOutput) = .empty;
    var gs: std.ArrayList(g.Row) = .empty;
    defer gs.deinit(backing);
    var xs: std.ArrayList(xor.Row) = .empty;
    defer xs.deinit(backing);
    var bs: std.ArrayList(boundary.Row) = .empty;
    defer bs.deinit(backing);
    var cs: std.ArrayList(challenge.Row) = .empty;
    defer cs.deinit(backing);
    var rs: std.ArrayList(route.Row) = .empty;
    defer rs.deinit(backing);
    var qs: std.ArrayList(query_mask.Row) = .empty;
    defer qs.deinit(backing);
    var controls: std.ArrayList(retry_control.Row) = .empty;
    defer controls.deinit(backing);
    var counters: std.ArrayList(counter_step.Row) = .empty;
    defer counters.deinit(backing);
    const zero_counter = Caller{ .circuit = namespace + 1, .first_wire = 0 };
    var counter_source = zero_counter;
    var counter_producer: ?usize = null;
    var zero_counter_uses: [2]u32 = @splat(0);
    const initial = (core.channel.blake3.Channel{}).digestBytes();
    var state = initial;
    var caller = @import("blake3_frame_route.zig").Caller{ .circuit = namespace, .first_wire = 0 };
    var producer: ?usize = null;
    var initial_uses: [8]u32 = @splat(0);
    var counter: u64 = 0;
    var circuit = namespace + 1 + @as(u32, @intFromBool(capacity != null));
    for (operations, 0..) |op, ordinal| switch (op) {
        .integer, .routed_integer, .words, .felts, .root, .routed_root, .routed_words, .routed_felts => {
            const frame: core.channel.blake3.Frame = switch (op) {
                .integer => |value| .{ .integer = .{ .state = state, .value = value } },
                .routed_integer => |value| .{ .integer = .{ .state = state, .value = value.value } },
                .words => |values| .{ .words = .{ .state = state, .values = values } },
                .felts => |values| .{ .felts = .{ .state = state, .values = values } },
                .root => |value| .{ .root = .{ .state = state, .value = value } },
                .routed_root => |value| .{ .root = .{ .state = state, .value = value.value } },
                .routed_words => |value| .{ .words = .{ .state = state, .values = value.values } },
                .routed_felts => |value| .{ .felts = .{ .state = state, .values = value.values } },
                else => unreachable,
            };
            const has_root = op == .root or op == .routed_root;
            const hash_circuit = circuit + @as(u32, if (has_root) 1 else 0);
            const bindings = [_]frame_hash.Binding{
                .{ .role = .state, .caller = caller },
                .{ .role = .root, .caller = if (op == .routed_root) op.routed_root.source else .{ .circuit = circuit, .first_wire = 0 } },
            };
            const active = bindings[0..if (has_root) @as(usize, 2) else 1];
            const payload: ?frame_hash.PayloadBinding = switch (op) {
                .routed_integer => |value| .{ .role = .integer, .caller = value.source, .word_count = 2 },
                .routed_words => |value| .{ .role = .words, .caller = value.source, .word_count = value.values.len },
                .routed_felts => |value| .{ .role = .felts, .caller = value.source, .word_count = try std.math.mul(usize, value.values.len, 4) },
                else => null,
            };
            var prepared = if (payload) |binding|
                (if (live) try frame_hash.preparePayload(a, hash_circuit, frame, active, binding, @splat(0)) else try frame_hash.trustedPayload(a, hash_circuit, frame, active, binding, @splat(0)))
            else
                (if (live) try frame_hash.prepare(a, hash_circuit, frame, active, @splat(0)) else try frame_hash.trusted(a, hash_circuit, frame, active, @splat(0)));
            defer prepared.deinit();
            if (payload) |binding| try reads.append(a, .{ .operation = ordinal, .source = binding.caller, .uses = try a.dupe(u32, prepared.payload_uses) });
            try addUses(xs.items, producer, &initial_uses, prepared.source_uses[0]);
            if (op == .routed_root) try roots.append(a, .{ .operation = ordinal, .source = op.routed_root.source, .uses = prepared.source_uses[1] });
            if (op == .root) for (prepared.source_uses[1], 0..) |uses, i| {
                try bs.append(backing, try boundary.logicalRow(circuit, @intCast(i), M31.fromCanonical(uses), std.mem.readInt(u32, op.root[4 * i ..][0..4], .little)));
            };
            try gs.appendSlice(backing, prepared.rows.g_rows);
            try xs.appendSlice(backing, prepared.rows.xor_rows);
            try bs.appendSlice(backing, prepared.rows.boundary_rows[0 .. prepared.rows.boundary_rows.len - 8]);
            try rs.appendSlice(backing, prepared.route_rows);
            producer = xs.items.len - 16;
            for (0..8) |i| xs.items[producer.? + i][17] = M31.zero();
            var plan = try graph.build(a, try frame.encodedSize());
            defer plan.deinit();
            for (plan.output, 0..) |wire, i| if (wire != plan.output[0] + i) return error.InvalidBlake3Transcript;
            caller = .{ .circuit = hash_circuit, .first_wire = plan.output[0] };
            state = prepared.digest orelse @splat(0);
            counter = 0;
            counter_source = zero_counter;
            counter_producer = null;
            circuit = hash_circuit + 1;
        },
        .pow => |pow| {
            const frame = core.channel.blake3.Frame{ .pow = .{ .state = state, .bits = pow.bits, .nonce = pow.nonce } };
            const bindings = [_]frame_hash.Binding{.{ .role = .state, .caller = caller }};
            const payload: ?frame_hash.PayloadBinding = if (pow.nonce_source) |source| .{ .role = .nonce, .caller = source, .word_count = 2 } else null;
            var prepared = if (payload) |binding|
                (if (live) try frame_hash.preparePayload(a, circuit, frame, &bindings, binding, @splat(0)) else try frame_hash.trustedPayload(a, circuit, frame, &bindings, binding, @splat(0)))
            else
                (if (live) try frame_hash.prepare(a, circuit, frame, &bindings, @splat(0)) else try frame_hash.trusted(a, circuit, frame, &bindings, @splat(0)));
            if (payload) |binding| try reads.append(a, .{ .operation = ordinal, .source = binding.caller, .uses = try a.dupe(u32, prepared.payload_uses) });
            defer prepared.deinit();
            try addUses(xs.items, producer, &initial_uses, prepared.source_uses[0]);
            for (0..8) |i| prepared.rows.xor_rows[prepared.rows.xor_rows.len - 16 + i][17] = M31.fromCanonical(if (i == 0) 1 else 0);
            try gs.appendSlice(backing, prepared.rows.g_rows);
            try xs.appendSlice(backing, prepared.rows.xor_rows);
            try bs.appendSlice(backing, prepared.rows.boundary_rows[0 .. prepared.rows.boundary_rows.len - 8]);
            try rs.appendSlice(backing, prepared.route_rows);
            var plan = try graph.build(a, try frame.encodedSize());
            defer plan.deinit();
            const schedule = query_mask.Schedule{ .source_circuit = circuit, .source_wire = plan.output[0], .destination_circuit = circuit + 1, .destination_wire = 0, .uses = 1, .log_domain_size = pow.bits };
            const row = if (live) try query_mask.logicalLowBitsRow(schedule, std.mem.readInt(u32, prepared.digest.?[0..4], .little)) else try query_mask.fixedLowBitsRow(schedule);
            try qs.append(backing, row);
            var output = try boundary.logicalRow(circuit + 1, 0, M31.one().neg(), 0);
            if (live) output[0..4].* = row[4..8].*;
            try bs.append(backing, output);
            circuit += 2;
        },
        .queries => |q| {
            const statement = queries.Statement{ .namespace = circuit, .state = state, .state_source = caller, .start = counter, .log_domain_size = q.log_domain_size, .values = q.values, .export_outputs = q.export_outputs, .counter_source = if (capacity != null) counter_source else null, .final_counter_uses = .{ 0, 0 } };
            var prepared = if (live) try queries.prepare(a, statement) else try queries.trusted(a, statement);
            defer prepared.deinit();
            try addUses(xs.items, producer, &initial_uses, prepared.state_uses);
            try gs.appendSlice(backing, prepared.g_rows);
            try xs.appendSlice(backing, prepared.xor_rows);
            try bs.appendSlice(backing, prepared.boundary_rows);
            try rs.appendSlice(backing, prepared.route_rows);
            try qs.appendSlice(backing, prepared.mask_rows);
            for (prepared.outputs, 0..) |source, i| try query_outputs.append(a, .{ .operation = ordinal, .query = i, .source = source });
            if (prepared.counter_rows.len > 0) {
                try addCounterUses(counters.items, counter_producer, &zero_counter_uses, prepared.counter_uses);
                try counters.appendSlice(backing, prepared.counter_rows);
                counter_producer = counters.items.len - 1;
                counter_source = prepared.final_counter.?;
            }
            counter = prepared.next_draw;
            const blocks = q.values.len / 8 + @intFromBool(q.values.len % 8 != 0);
            circuit += @intCast(2 * blocks + @intFromBool(capacity != null and blocks > 0));
        },
        .secure => |s| {
            if (capacity) |limit| {
                const statement = bounded.Statement{ .namespace = circuit, .capacity = limit, .state = state, .state_source = caller, .start = counter, .counter_source = counter_source, .consumption = s.consumption, .final_counter_uses = .{ 0, 0 } };
                var prepared = if (live) try bounded.prepare(a, statement) else try bounded.trusted(a, statement);
                defer prepared.deinit();
                try addUses(xs.items, producer, &initial_uses, prepared.state_uses);
                try addCounterUses(counters.items, counter_producer, &zero_counter_uses, prepared.counter_uses);
                try gs.appendSlice(backing, prepared.rows.g_rows);
                try xs.appendSlice(backing, prepared.rows.xor_rows);
                try bs.appendSlice(backing, prepared.rows.boundary_rows);
                try cs.appendSlice(backing, prepared.rows.challenge_rows);
                try rs.appendSlice(backing, prepared.rows.route_rows);
                try controls.appendSlice(backing, prepared.rows.control_rows);
                try counters.appendSlice(backing, prepared.rows.counter_rows);
                counter_producer = counters.items.len - 1;
                counter_source = prepared.final_counter;
                if (s.output) |role| {
                    try outputs.append(a, .{ .operation = ordinal, .role = role, .source = prepared.output, .words = s.consumption.words() });
                } else for (s.values[0..s.consumption.words()], 0..) |expected, i| {
                    var row = try boundary.logicalCoordinates(prepared.output.circuit, @intCast(i), M31.one().neg(), .{ expected, M31.zero(), M31.zero(), M31.zero() });
                    if (live) row[0] = prepared.selected.?[i];
                    try bs.append(backing, row);
                }
                counter = prepared.next_counter orelse 0;
                circuit += 2 * limit + 3;
            } else {
                const statement = draw.Statement{ .namespace = circuit, .state = state, .start = counter, .attempts = s.attempts, .values = s.values, .consumption = s.consumption, .export_outputs = s.output != null, .state_source = caller };
                var prepared = if (live) try draw.prepare(a, statement) else try draw.trusted(a, statement);
                defer prepared.deinit();
                try addUses(xs.items, producer, &initial_uses, prepared.state_uses);
                try gs.appendSlice(backing, prepared.g_rows);
                try xs.appendSlice(backing, prepared.xor_rows);
                try bs.appendSlice(backing, prepared.boundary_rows);
                try cs.appendSlice(backing, prepared.challenge_rows);
                try rs.appendSlice(backing, prepared.route_rows);
                if (s.output) |role| try outputs.append(a, .{ .operation = ordinal, .role = role, .source = prepared.output_source, .words = s.consumption.words() });
                counter = prepared.next_draw;
                circuit += 2 * s.attempts;
            }
        },
    };
    for (initial_uses, 0..) |uses, i| if (uses != 0) try bs.append(backing, try boundary.logicalRow(namespace, @intCast(i), M31.fromCanonical(uses), std.mem.readInt(u32, initial[4 * i ..][0..4], .little)));
    if (capacity != null) for (zero_counter_uses, 0..) |uses, i| if (uses != 0) try bs.append(backing, try boundary.logicalRow(zero_counter.circuit, @intCast(i), M31.fromCanonical(uses), 0));
    const g_rows = try gs.toOwnedSlice(backing);
    errdefer backing.free(g_rows);
    const xor_rows = try xs.toOwnedSlice(backing);
    errdefer backing.free(xor_rows);
    const boundary_rows = try bs.toOwnedSlice(backing);
    errdefer backing.free(boundary_rows);
    const challenge_rows = try cs.toOwnedSlice(backing);
    errdefer backing.free(challenge_rows);
    const route_rows = try rs.toOwnedSlice(backing);
    errdefer backing.free(route_rows);
    const query_rows = try qs.toOwnedSlice(backing);
    errdefer backing.free(query_rows);
    const control_rows = try controls.toOwnedSlice(backing);
    errdefer backing.free(control_rows);
    const counter_rows = try counters.toOwnedSlice(backing);
    errdefer backing.free(counter_rows);
    return .{ .row_allocator = backing, .control_rows = control_rows, .counter_rows = counter_rows, .query_outputs = try query_outputs.toOwnedSlice(a), .root_reads = try roots.toOwnedSlice(a), .draw_outputs = try outputs.toOwnedSlice(a), .payload_reads = try reads.toOwnedSlice(a), .final_digest = if (live) state else null, .query_rows = query_rows, .arena = arena, .g_rows = g_rows, .xor_rows = xor_rows, .boundary_rows = boundary_rows, .challenge_rows = challenge_rows, .route_rows = route_rows, .next_draw = counter };
}
fn addUses(rows: []xor.Row, producer: ?usize, initial: *[8]u32, counts: [8]u32) !void {
    for (counts, 0..) |count, i| {
        const previous = if (producer) |offset| rows[offset + i][17].toU32() else initial[i];
        const sum = std.math.add(u32, previous, count) catch return error.InvalidBlake3Transcript;
        if (sum >= core.fields.m31.Modulus) return error.InvalidBlake3Transcript;
        if (producer) |offset| rows[offset + i][17] = M31.fromCanonical(sum) else initial[i] = sum;
    }
}

fn addCounterUses(rows: []counter_step.Row, producer: ?usize, initial: *[2]u32, counts: [2]u32) !void {
    for (counts, 0..) |count, i| {
        const previous = if (producer) |offset| rows[offset][31 + i].v else initial[i];
        const sum = try std.math.add(u32, previous, count);
        if (sum >= core.fields.m31.Modulus) return error.InvalidBlake3Transcript;
        if (producer) |offset| rows[offset][31 + i] = M31.fromCanonical(sum) else initial[i] = sum;
    }
}
