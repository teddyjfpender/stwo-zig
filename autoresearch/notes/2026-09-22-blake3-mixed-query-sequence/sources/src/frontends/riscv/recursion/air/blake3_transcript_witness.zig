//! Compile native absorption and secure draws into authenticated dataflow.
//! Operation order determines state links, draw counters and absorption resets.
const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const frame_hash = @import("blake3_frame_witness.zig");
const draw = @import("blake3_draw_witness.zig");
const queries = @import("blake3_query_witness.zig");
pub const query_mask = queries.mask;
const graph = @import("blake3_hash_plan.zig");
pub const g = draw.g;
pub const xor = draw.xor;
pub const boundary = draw.boundary;
pub const challenge = draw.challenge;
pub const route = draw.route;
pub const Operation = union(enum) {
    integer: u64,
    words: []const u32,
    felts: []const core.fields.qm31.QM31,
    root: [32]u8,
    queries: struct { log_domain_size: u32, values: []const u32 },
    secure: struct { attempts: u32, consumption: draw.Consumption = .one, values: [8]M31 },
};
pub const Prepared = struct {
    arena: std.heap.ArenaAllocator,
    g_rows: []g.Row,
    xor_rows: []xor.Row,
    boundary_rows: []boundary.Row,
    challenge_rows: []challenge.Row,
    route_rows: []route.Row,
    query_rows: []query_mask.Row,
    next_draw: u64,
    pub fn deinit(self: *Prepared) void {
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
    return build(a, namespace, operations, true);
}
pub fn trusted(a: std.mem.Allocator, namespace: u32, operations: []const Operation) !Prepared {
    return build(a, namespace, operations, false);
}
fn build(backing: std.mem.Allocator, namespace: u32, operations: []const Operation, live: bool) !Prepared {
    var end: u64 = namespace;
    for (operations) |op| {
        const count: u64 = switch (op) {
            .integer, .words, .felts => 1,
            .root => 2,
            .queries => |q| std.math.mul(u64, q.values.len / 8 + @intFromBool(q.values.len % 8 != 0), 2) catch return error.InvalidBlake3Transcript,
            .secure => |s| blk: {
                if (s.attempts == 0) return error.InvalidBlake3Transcript;
                break :blk 2 * @as(u64, s.attempts);
            },
        };
        end = std.math.add(u64, end, count) catch return error.InvalidBlake3Transcript;
    }
    if (end >= core.fields.m31.Modulus) return error.InvalidBlake3Transcript;
    var arena = std.heap.ArenaAllocator.init(backing);
    errdefer arena.deinit();
    const a = arena.allocator();
    var gs: std.ArrayList(g.Row) = .empty;
    var xs: std.ArrayList(xor.Row) = .empty;
    var bs: std.ArrayList(boundary.Row) = .empty;
    var cs: std.ArrayList(challenge.Row) = .empty;
    var rs: std.ArrayList(route.Row) = .empty;
    var qs: std.ArrayList(query_mask.Row) = .empty;
    const initial = (core.channel.blake3.Channel{}).digestBytes();
    var state = initial;
    var caller = @import("blake3_frame_route.zig").Caller{ .circuit = namespace, .first_wire = 0 };
    var producer: ?usize = null;
    var initial_uses: [8]u32 = @splat(0);
    var counter: u64 = 0;
    var circuit = namespace + 1;
    for (operations) |op| switch (op) {
        .integer, .words, .felts, .root => {
            const frame: core.channel.blake3.Frame = switch (op) {
                .integer => |value| .{ .integer = .{ .state = state, .value = value } },
                .words => |values| .{ .words = .{ .state = state, .values = values } },
                .felts => |values| .{ .felts = .{ .state = state, .values = values } },
                .root => |value| .{ .root = .{ .state = state, .value = value } },
                else => unreachable,
            };
            const has_root = op == .root;
            const hash_circuit = circuit + @as(u32, if (has_root) 1 else 0);
            const bindings = [_]frame_hash.Binding{
                .{ .role = .state, .caller = caller },
                .{ .role = .root, .caller = .{ .circuit = circuit, .first_wire = 0 } },
            };
            const active = bindings[0..if (has_root) @as(usize, 2) else 1];
            var prepared = if (live) try frame_hash.prepare(a, hash_circuit, frame, active, @splat(0)) else try frame_hash.trusted(a, hash_circuit, frame, active, @splat(0));
            defer prepared.deinit();
            try addUses(xs.items, producer, &initial_uses, prepared.source_uses[0]);
            if (has_root) for (prepared.source_uses[1], 0..) |uses, i| {
                try bs.append(a, try boundary.logicalRow(circuit, @intCast(i), M31.fromCanonical(uses), std.mem.readInt(u32, op.root[4 * i ..][0..4], .little)));
            };
            try gs.appendSlice(a, prepared.rows.g_rows);
            try xs.appendSlice(a, prepared.rows.xor_rows);
            try bs.appendSlice(a, prepared.rows.boundary_rows[0 .. prepared.rows.boundary_rows.len - 8]);
            try rs.appendSlice(a, prepared.route_rows);
            producer = xs.items.len - 16;
            for (0..8) |i| xs.items[producer.? + i][17] = M31.zero();
            var plan = try graph.build(a, try frame.encodedSize());
            defer plan.deinit();
            for (plan.output, 0..) |wire, i| if (wire != plan.output[0] + i) return error.InvalidBlake3Transcript;
            caller = .{ .circuit = hash_circuit, .first_wire = plan.output[0] };
            state = prepared.digest orelse @splat(0);
            counter = 0;
            circuit = hash_circuit + 1;
        },
        .queries => |q| {
            const statement = queries.Statement{ .namespace = circuit, .state = state, .state_source = caller, .start = counter, .log_domain_size = q.log_domain_size, .values = q.values };
            var prepared = if (live) try queries.prepare(a, statement) else try queries.trusted(a, statement);
            defer prepared.deinit();
            try addUses(xs.items, producer, &initial_uses, prepared.state_uses);
            try gs.appendSlice(a, prepared.g_rows);
            try xs.appendSlice(a, prepared.xor_rows);
            try bs.appendSlice(a, prepared.boundary_rows);
            try rs.appendSlice(a, prepared.route_rows);
            try qs.appendSlice(a, prepared.mask_rows);
            counter = prepared.next_draw;
            circuit += @intCast(2 * (q.values.len / 8 + @intFromBool(q.values.len % 8 != 0)));
        },
        .secure => |s| {
            const statement = draw.Statement{ .namespace = circuit, .state = state, .start = counter, .attempts = s.attempts, .values = s.values, .consumption = s.consumption, .state_source = caller };
            var prepared = if (live) try draw.prepare(a, statement) else try draw.trusted(a, statement);
            defer prepared.deinit();
            try addUses(xs.items, producer, &initial_uses, prepared.state_uses);
            try gs.appendSlice(a, prepared.g_rows);
            try xs.appendSlice(a, prepared.xor_rows);
            try bs.appendSlice(a, prepared.boundary_rows);
            try cs.appendSlice(a, prepared.challenge_rows);
            try rs.appendSlice(a, prepared.route_rows);
            counter = prepared.next_draw;
            circuit += 2 * s.attempts;
        },
    };
    for (initial_uses, 0..) |uses, i| if (uses != 0) try bs.append(a, try boundary.logicalRow(namespace, @intCast(i), M31.fromCanonical(uses), std.mem.readInt(u32, initial[4 * i ..][0..4], .little)));
    const g_rows = try gs.toOwnedSlice(a);
    const xor_rows = try xs.toOwnedSlice(a);
    const boundary_rows = try bs.toOwnedSlice(a);
    const challenge_rows = try cs.toOwnedSlice(a);
    const route_rows = try rs.toOwnedSlice(a);
    const query_rows = try qs.toOwnedSlice(a);
    return .{ .query_rows = query_rows, .arena = arena, .g_rows = g_rows, .xor_rows = xor_rows, .boundary_rows = boundary_rows, .challenge_rows = challenge_rows, .route_rows = route_rows, .next_draw = counter };
}
fn addUses(rows: []xor.Row, producer: ?usize, initial: *[8]u32, counts: [8]u32) !void {
    for (counts, 0..) |count, i| {
        const previous = if (producer) |offset| rows[offset + i][17].toU32() else initial[i];
        const sum = std.math.add(u32, previous, count) catch return error.InvalidBlake3Transcript;
        if (sum >= core.fields.m31.Modulus) return error.InvalidBlake3Transcript;
        if (producer) |offset| rows[offset + i][17] = M31.fromCanonical(sum) else initial[i] = sum;
    }
}
