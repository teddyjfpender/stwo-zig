//! Exact ORIGINAL Frame.words chunk0 plus authenticated canonical right CVs.
//! This is the actual hash-witness replacement: no tail graph, full message
//! allocation, private full-input inventory or scalar full-input hash occurs.
//! Public caller supplies MUST come from a genuine carrier/ancestor statement.
const std = @import("std");
const core = @import("stwo_core");
const Tail = @import("../blake3_words_tail_v1.zig");
const Plan = @import("blake3_hash_plan.zig");
const Hash = @import("blake3_hash_witness.zig");
const Route = @import("blake3_byte_route.zig");
const Boundary = @import("blake3_boundary.zig");
pub const Caller = @import("blake3_frame_route.zig").Caller;
pub const Sources = struct { state: Caller, prefix: Caller, frontier: []const Caller };
pub const Statement = struct {
    circuit: u32,
    word_count: usize,
    state: [32]u8,
    claim: [32]u8,
    sources: Sources,
    pub fn require(self: Statement) !Tail.Geometry {
        const geometry = try Tail.Geometry.init(self.word_count);
        if (self.circuit >= core.fields.m31.Modulus or self.sources.frontier.len != geometry.range_count) return error.InvalidInputTailConsumer;
        try extent(self.sources.state, 8, self.circuit);
        try extent(self.sources.prefix, @min(self.word_count, Tail.FIRST_INPUT_BYTES / 4), self.circuit);
        if (overlap(self.sources.state, 8, self.sources.prefix, @min(self.word_count, Tail.FIRST_INPUT_BYTES / 4))) return error.InvalidInputTailConsumer;
        for (self.sources.frontier, 0..) |caller, i| {
            try extent(caller, 8, self.circuit);
            if (overlap(caller, 8, self.sources.state, 8) or overlap(caller, 8, self.sources.prefix, @min(self.word_count, Tail.FIRST_INPUT_BYTES / 4))) return error.InvalidInputTailConsumer;
            for (self.sources.frontier[0..i]) |previous| if (overlap(caller, 8, previous, 8)) return error.InvalidInputTailConsumer;
        }
        return geometry;
    }
};
pub const Prepared = struct {
    arena: std.heap.ArenaAllocator,
    rows: Hash.Rows,
    route_rows: []Route.Row,
    schedules: []Route.Schedule,
    state_uses: [8]u32,
    prefix_uses: []u32,
    frontier_uses: [][8]u32,
    digest: [32]u8,
    compression_calls: usize,
    /// No producer admission or job/source completeness is implied here.
    pub const complete_source_authority = false;
    pub fn deinit(self: *Prepared) void {
        self.arena.deinit();
        self.* = undefined;
    }
};
fn extent(caller: Caller, count: usize, circuit: u32) !void {
    if (caller.circuit >= core.fields.m31.Modulus or caller.circuit == circuit or caller.first_wire >= core.fields.m31.Modulus or count > core.fields.m31.Modulus - caller.first_wire) return error.InvalidInputTailConsumer;
}
fn overlap(a: Caller, an: usize, b: Caller, bn: usize) bool {
    return an != 0 and bn != 0 and a.circuit == b.circuit and @as(u64, a.first_wire) < @as(u64, b.first_wire) + bn and @as(u64, b.first_wire) < @as(u64, a.first_wire) + an;
}
pub fn prepare(a: std.mem.Allocator, statement: Statement, prefix: []const u32, frontier: []const [8]u32) !Prepared {
    return build(a, statement, prefix, frontier, true);
}
/// Fixed routing and absolute original length/flags/counters are regenerated
/// without a full input or any compression. Witness values never fix routing.
pub fn trusted(a: std.mem.Allocator, statement: Statement) !Prepared {
    return build(a, statement, &.{}, &.{}, false);
}
fn build(backing: std.mem.Allocator, statement: Statement, prefix: []const u32, frontier: []const [8]u32, live: bool) !Prepared {
    const geometry = try statement.require();
    const prefix_count = @min(statement.word_count, Tail.FIRST_INPUT_BYTES / 4);
    if (live and (prefix.len != prefix_count or frontier.len != geometry.range_count)) return error.InvalidInputTailConsumer;
    var plan = try Plan.buildPrefixFold(backing, geometry.frame_bytes);
    defer plan.deinit();
    var arena = std.heap.ArenaAllocator.init(backing);
    errdefer arena.deinit();
    const a = arena.allocator();
    const bytes = try a.alloc(u8, plan.input_len);
    @memset(bytes, 0);
    const label = core.channel.blake3.framing.PROTOCOL_ID;
    @memcpy(bytes[0..label.len], label);
    bytes[label.len] = @intFromEnum(core.channel.blake3.framing.Domain.words);
    @memcpy(bytes[label.len + 1 ..][0..32], &statement.state);
    std.mem.writeInt(u64, bytes[Tail.HEADER_BYTES - 8 ..][0..8], @intCast(statement.word_count), .little);
    const first = @min(geometry.frame_bytes, 1024);
    if (live) {
        for (prefix, 0..) |value, i| std.mem.writeInt(u32, bytes[Tail.HEADER_BYTES + 4 * i ..][0..4], value, .little);
        for (frontier, 0..) |cv, i| @memcpy(bytes[first + 32 * i ..][0..32], &Tail.digest(cv));
    }
    const evaluated: ?Hash.Prepared = if (live) try Hash.prepareWithPlan(a, statement.circuit, bytes, statement.claim, &plan) else null;
    const rows: Hash.Rows = if (evaluated) |value| value.rows else blk: {
        const placeholder = Hash.Rows{ .allocator = a, .g_rows = try a.alloc(@import("blake3_g_call.zig").Row, plan.g.len), .xor_rows = try a.alloc(@import("blake3_xor_call.zig").Row, plan.xor.len), .boundary_rows = try a.alloc(Boundary.Row, plan.sources.len + 8) };
        try Hash.trustedShapeIntoWithPlan(statement.circuit, plan.input_len, statement.claim, &plan, .{ .g_rows = placeholder.g_rows, .xor_rows = placeholder.xor_rows, .boundary_rows = placeholder.boundary_rows });
        break :blk placeholder;
    };
    var boundaries: std.ArrayList(Boundary.Row) = .empty;
    var routes: std.ArrayList(Route.Row) = .empty;
    var schedules: std.ArrayList(Route.Schedule) = .empty;
    var state_uses: [8]u32 = @splat(0);
    const prefix_uses = try a.alloc(u32, prefix_count);
    @memset(prefix_uses, 0);
    const frontier_uses = try a.alloc([8]u32, geometry.range_count);
    @memset(frontier_uses, @splat(0));
    for (plan.sources, rows.boundary_rows[0..plan.sources.len]) |source, row| switch (source.value) {
        .constant => try boundaries.append(a, row),
        .input => |input| {
            var schedule = Route.Schedule{ .sources = .{ null, null }, .destination = .{ .circuit = statement.circuit, .wire = source.wire }, .uses = plan.uses[source.wire], .bytes = @splat(.{ .constant = 0 }) };
            var values: [2]u32 = @splat(0);
            for (0..input.len) |part| {
                const byte = input.offset + part;
                const state_first = label.len + 1;
                const ref: ?struct { caller: Caller, word: usize, value: u32 } = if (byte >= state_first and byte < state_first + 32)
                    .{ .caller = statement.sources.state, .word = (byte - state_first) / 4, .value = std.mem.readInt(u32, statement.state[(byte - state_first) / 4 * 4 ..][0..4], .little) }
                else if (byte >= Tail.HEADER_BYTES and byte < first)
                    .{ .caller = statement.sources.prefix, .word = (byte - Tail.HEADER_BYTES) / 4, .value = if (live) prefix[(byte - Tail.HEADER_BYTES) / 4] else 0 }
                else if (byte >= first)
                    .{ .caller = statement.sources.frontier[(byte - first) / 32], .word = (byte - first) % 32 / 4, .value = if (live) frontier[(byte - first) / 32][(byte - first) % 32 / 4] else 0 }
                else
                    null;
                if (ref) |item| {
                    const endpoint = Route.Endpoint{ .circuit = item.caller.circuit, .wire = item.caller.first_wire + @as(u32, @intCast(item.word)) };
                    var slot: ?u1 = null;
                    for (schedule.sources, 0..) |existing, j| if (existing) |e| if (std.meta.eql(e, endpoint)) {
                        slot = @intCast(j);
                        break;
                    };
                    if (slot == null) for (&schedule.sources, 0..) |*existing, j| if (existing.* == null) {
                        existing.* = endpoint;
                        values[j] = item.value;
                        slot = @intCast(j);
                        break;
                    };
                    const source_byte: u2 = @intCast(if (byte >= first) (byte - first) % 4 else if (byte >= Tail.HEADER_BYTES) (byte - Tail.HEADER_BYTES) % 4 else (byte - state_first) % 4);
                    schedule.bytes[part] = .{ .source = .{ .word = slot orelse return error.Blake3RouteTooWide, .byte = source_byte } };
                } else schedule.bytes[part] = .{ .constant = bytes[byte] };
            }
            for (schedule.sources) |maybe| if (maybe) |endpoint| {
                if (endpoint.circuit == statement.sources.state.circuit and endpoint.wire >= statement.sources.state.first_wire and endpoint.wire - statement.sources.state.first_wire < 8) state_uses[endpoint.wire - statement.sources.state.first_wire] += 1 else if (endpoint.circuit == statement.sources.prefix.circuit and endpoint.wire >= statement.sources.prefix.first_wire and endpoint.wire - statement.sources.prefix.first_wire < prefix_count) prefix_uses[endpoint.wire - statement.sources.prefix.first_wire] += 1 else {
                    var found = false;
                    for (statement.sources.frontier, 0..) |caller, i| if (endpoint.circuit == caller.circuit and endpoint.wire >= caller.first_wire and endpoint.wire - caller.first_wire < 8) {
                        frontier_uses[i][endpoint.wire - caller.first_wire] += 1;
                        found = true;
                        break;
                    };
                    if (!found) return error.InvalidInputTailConsumer;
                }
            };
            try schedules.append(a, schedule);
            try routes.append(a, if (live) try Route.logicalRow(schedule, values) else try Route.fixedRow(schedule));
        },
    };
    try boundaries.appendSlice(a, rows.boundary_rows[plan.sources.len..]);
    const actual = if (evaluated) |value| value.digest else statement.claim;
    return .{ .arena = arena, .rows = .{ .allocator = a, .g_rows = rows.g_rows, .xor_rows = rows.xor_rows, .boundary_rows = try boundaries.toOwnedSlice(a) }, .route_rows = try routes.toOwnedSlice(a), .schedules = try schedules.toOwnedSlice(a), .state_uses = state_uses, .prefix_uses = prefix_uses, .frontier_uses = frontier_uses, .digest = actual, .compression_calls = plan.calls.len };
}
