//! One original-message tail feeds a domain-bound input root and <=4 original
//! input frames in the SAME authenticated BLAKE3/byte-routing AIR. There is no
//! host CV boundary supplying a tail. External state endpoints remain required
//! original-transcript producers; a caller cannot publish this graph alone.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Tail = @import("../blake3_words_tail_v1.zig");
const Schedule = @import("blake3_words_tail_plan_v1.zig");
const Hash = @import("blake3_hash_witness.zig");
const HashPlan = @import("blake3_hash_plan.zig");
const G = @import("blake3_g_call.zig");
const Xor = @import("blake3_xor_call.zig");
const Boundary = @import("blake3_boundary.zig");
const Route = @import("blake3_byte_route.zig");
const Word = @import("blake3_private_word.zig");
const Frame = core.channel.blake3.framing.Frame;
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
pub const Caller = @import("blake3_frame_route.zig").Caller;
pub const Original = struct { state: [32]u8, claim: [32]u8, source: Caller };
pub const Statement = struct {
    namespace: u32,
    word_count: usize,
    /// Independently expected B5TI/v1 ORIGINAL Frame.words(DOMAIN_STATE,input).
    /// This must never be filled from B5WM/v1's different input-root recipe.
    expected_input_root: [32]u8,
    originals: []const Original,
    pub fn require(self: Statement, limits: Schedule.Limits) !void {
        try limits.require(self.word_count, self.originals.len);
        const shape = try Tail.Geometry.init(self.word_count);
        const end = @as(u64, self.namespace) + 1 + shape.range_count + self.originals.len;
        if (end >= core.fields.m31.Modulus or self.word_count >= core.fields.m31.Modulus) return error.InvalidBlake3TailNamespace;
        for (self.originals, 0..) |original, i| {
            const source = original.source;
            if (source.circuit >= core.fields.m31.Modulus or source.first_wire >= core.fields.m31.Modulus - 7 or (source.circuit >= self.namespace and source.circuit <= end)) return error.InvalidBlake3TailNamespace;
            for (self.originals[0..i]) |earlier| if (earlier.source.circuit == source.circuit and earlier.source.first_wire < source.first_wire + 8 and source.first_wire < earlier.source.first_wire + 8) return error.InvalidBlake3TailNamespace;
        }
    }
};
pub const Prepared = struct {
    arena: std.heap.ArenaAllocator,
    budget: ?*Budget,
    rows: Hash.Rows,
    route_rows: []Route.Row,
    word_rows: []Word.Row,
    route_schedules: []Route.Schedule,
    /// Exact additions to authenticated ORIGINAL incoming-state producer uses.
    /// The owner must remove its previous public sink and supply these counts.
    external_uses: [][8]u32,
    /// Every frontier output is a hash producer, never an input constant.
    tail_outputs: [][8]Route.Endpoint,
    input_root: [32]u8,
    original_digests: [][32]u8,
    input_digest_link_proved: bool = false,
    pub fn deinit(self: *Prepared) void {
        const budget = self.budget;
        self.arena.deinit();
        self.* = undefined;
        if (budget) |owner| owner.destroy();
    }
};
pub fn prepare(a: std.mem.Allocator, statement: Statement, words: []const u32, limits: Schedule.Limits) !Prepared {
    if (words.len != statement.word_count) return error.InvalidBlake3TailExtent;
    return build(a, statement, words, limits);
}
/// Independently regenerated preprocessing. It evaluates no compression rounds
/// and reads no witness CV. Only fixed projections of these placeholder rows
/// may be retained by setup; all original states/claims are admission inputs.
pub fn trusted(a: std.mem.Allocator, statement: Statement, limits: Schedule.Limits) !Prepared {
    return build(a, statement, null, limits);
}
const ByteRef = union(enum) { constant: u8, source: struct { endpoint: Route.Endpoint, byte: u2, word: u32 } };
const Builder = struct {
    allocator: std.mem.Allocator,
    statement: Statement,
    plan: *const Schedule.Plan,
    words: ?[]const u32,
    cvs: []const [8]u32,
    gs: std.ArrayList(G.Row) = .empty,
    xs: std.ArrayList(Xor.Row) = .empty,
    bs: std.ArrayList(Boundary.Row) = .empty,
    routes: std.ArrayList(Route.Row) = .empty,
    schedules: std.ArrayList(Route.Schedule) = .empty,
    word_uses: []u32,
    external_uses: [][8]u32,
    fn tailCircuit(self: *const Builder, i: usize) u32 {
        return self.statement.namespace + 1 + @as(u32, @intCast(i));
    }
    fn prefixCircuit(self: *const Builder, i: usize) u32 {
        return self.statement.namespace + 1 + @as(u32, @intCast(self.plan.tail.len + i));
    }
    fn message(self: *const Builder, byte: usize) ByteRef {
        const wire: u32 = @intCast(byte / 4);
        return .{ .source = .{ .endpoint = .{ .circuit = self.statement.namespace, .wire = wire }, .byte = @intCast(byte % 4), .word = if (self.words) |words| words[wire] else 0 } };
    }
    fn originalByte(self: *const Builder, offset: usize, original_index: ?usize, header: *const [Tail.HEADER_BYTES]u8) ByteRef {
        const state_start = core.channel.blake3.framing.PROTOCOL_ID.len + 1;
        if (offset >= state_start and offset < state_start + 32) if (original_index) |index| {
            const byte = offset - state_start;
            const original = self.statement.originals[index];
            return .{ .source = .{ .endpoint = .{ .circuit = original.source.circuit, .wire = original.source.first_wire + @as(u32, @intCast(byte / 4)) }, .byte = @intCast(byte % 4), .word = std.mem.readInt(u32, original.state[byte / 4 * 4 ..][0..4], .little) } };
        };
        if (offset < Tail.HEADER_BYTES) return .{ .constant = header[offset] };
        return self.message(offset - Tail.HEADER_BYTES);
    }
    fn ref(self: *const Builder, offset: usize, prefix: bool, original_index: ?usize, header: *const [Tail.HEADER_BYTES]u8) !ByteRef {
        if (!prefix) {
            if (offset < 1024 or offset >= self.plan.geometry.frame_bytes) return error.InvalidBlake3TailRoute;
            return self.message(offset - Tail.HEADER_BYTES);
        }
        const first_len = @min(1024, self.plan.geometry.frame_bytes);
        if (offset < first_len) return self.originalByte(offset, original_index, header);
        const frontier_byte = offset - first_len;
        const index = frontier_byte / 32;
        if (index >= self.plan.tail.len) return error.InvalidBlake3TailRoute;
        const word = frontier_byte % 32 / 4;
        return .{ .source = .{ .endpoint = .{ .circuit = self.tailCircuit(index), .wire = self.plan.tail[index].output[word] }, .byte = @intCast(frontier_byte % 4), .word = self.cvs[index][word] } };
    }
    fn count(self: *Builder, endpoint: Route.Endpoint) !void {
        if (endpoint.circuit == self.statement.namespace) {
            self.word_uses[endpoint.wire] = try std.math.add(u32, self.word_uses[endpoint.wire], 1);
            return;
        }
        for (self.statement.originals, 0..) |original, i| if (endpoint.circuit == original.source.circuit and endpoint.wire >= original.source.first_wire and endpoint.wire - original.source.first_wire < 8) {
            const word = endpoint.wire - original.source.first_wire;
            self.external_uses[i][word] = try std.math.add(u32, self.external_uses[i][word], 1);
            return;
        };
        // Canonical frontier output counts were independently assigned by Plan.
        for (self.plan.tail, 0..) |part, i| if (endpoint.circuit == self.tailCircuit(i)) {
            for (part.output) |wire| if (endpoint.wire == wire) return;
        };
        return error.InvalidBlake3TailRoute;
    }
    fn route(self: *Builder, circuit: u32, source: HashPlan.Source, plan: *const HashPlan.Plan, prefix: bool, original_index: ?usize, header: *const [Tail.HEADER_BYTES]u8) !void {
        const part = source.value.input;
        var scheduled = Route.Schedule{ .sources = .{ null, null }, .destination = .{ .circuit = circuit, .wire = source.wire }, .uses = plan.uses[source.wire], .bytes = @splat(.{ .constant = 0 }) };
        var values: [2]u32 = @splat(0);
        for (0..part.len) |i| switch (try self.ref(part.offset + i, prefix, original_index, header)) {
            .constant => |byte| scheduled.bytes[i] = .{ .constant = byte },
            .source => |item| {
                var slot: ?u1 = null;
                for (scheduled.sources, 0..) |existing, j| if (existing) |endpoint| if (std.meta.eql(endpoint, item.endpoint)) {
                    if (values[j] != item.word) return error.InvalidBlake3TailRoute;
                    slot = @intCast(j);
                    break;
                };
                if (slot == null) for (&scheduled.sources, 0..) |*existing, j| if (existing.* == null) {
                    existing.* = item.endpoint;
                    values[j] = item.word;
                    slot = @intCast(j);
                    break;
                };
                scheduled.bytes[i] = .{ .source = .{ .word = slot orelse return error.Blake3RouteTooWide, .byte = item.byte } };
            },
        };
        for (scheduled.sources) |maybe| if (maybe) |endpoint| try self.count(endpoint);
        try self.schedules.append(self.allocator, scheduled);
        try self.routes.append(self.allocator, if (self.words != null) try Route.logicalRow(scheduled, values) else try Route.fixedRow(scheduled));
    }
    fn append(self: *Builder, circuit: u32, plan: *const HashPlan.Plan, rows: *const Hash.Rows, prefix: bool, original_index: ?usize, header: *const [Tail.HEADER_BYTES]u8) !void {
        try self.gs.appendSlice(self.allocator, rows.g_rows);
        try self.xs.appendSlice(self.allocator, rows.xor_rows);
        for (plan.sources, rows.boundary_rows[0..plan.sources.len]) |source, row| switch (source.value) {
            .constant => try self.bs.append(self.allocator, row),
            .input => try self.route(circuit, source, plan, prefix, original_index, header),
        };
        // Tail CV sinks are removed: their exact positive hash supplies feed all
        // prefix graphs through byte routes. Actual root/claim sinks remain.
        if (prefix) try self.bs.appendSlice(self.allocator, rows.boundary_rows[plan.sources.len..]);
    }
};
fn build(backing: std.mem.Allocator, statement: Statement, words: ?[]const u32, limits: Schedule.Limits) !Prepared {
    try statement.require(limits);
    const budget = if (Budget.fromAllocator(backing)) |owner| owner.retain() else null;
    errdefer if (budget) |owner| owner.destroy();
    var shape = try Schedule.Plan.init(backing, statement.word_count, statement.originals.len, limits);
    defer shape.deinit();
    var arena = std.heap.ArenaAllocator.init(backing);
    errdefer arena.deinit();
    const a = arena.allocator();
    const cvs = try a.alloc([8]u32, shape.tail.len);
    @memset(cvs, @splat(0));
    const frame_bytes = if (words) |payload| try (Frame{ .words = .{ .state = Tail.DOMAIN_STATE, .values = payload } }).encode(a) else null;
    defer if (frame_bytes) |bytes| a.free(bytes);
    var scalar: ?Tail.ScalarTail = if (words) |payload| try Tail.ScalarTail.init(a, payload) else null;
    defer if (scalar) |*value| value.deinit();
    if (scalar) |value| @memcpy(cvs, value.cvs);
    const uses = try a.alloc(u32, statement.word_count);
    @memset(uses, 0);
    const external = try a.alloc([8]u32, statement.originals.len);
    @memset(external, @splat(0));
    var builder = Builder{ .allocator = a, .statement = statement, .plan = &shape, .words = words, .cvs = cvs, .word_uses = uses, .external_uses = external };
    // Only the fixed original header is needed in preprocessing; fake payload
    // bytes are never admitted as public/hash authority.
    const header = headerFor(statement.word_count);
    for (shape.tail, 0..) |*part, i| {
        const circuit = builder.tailCircuit(i);
        const claim = Tail.digest(cvs[i]);
        var rows = if (frame_bytes) |bytes| (try Hash.prepareWithPlan(a, circuit, bytes, claim, part)).rows else try trustedRows(a, circuit, claim, part);
        defer rows.deinit();
        try builder.append(circuit, part, &rows, false, null, &header);
    }
    const prefix_bytes = try a.alloc(u8, shape.prefix.input_len);
    defer a.free(prefix_bytes);
    @memset(prefix_bytes, 0);
    const digests = try a.alloc([32]u8, statement.originals.len);
    var input_root: [32]u8 = @splat(0);
    for (0..statement.originals.len + 1) |i| {
        const original_index: ?usize = if (i == 0) null else i - 1;
        const circuit = builder.prefixCircuit(i);
        const claim = if (original_index) |index| statement.originals[index].claim else statement.expected_input_root;
        if (words) |payload| {
            const view = try Tail.WordsView.init(if (original_index) |index| statement.originals[index].state else Tail.DOMAIN_STATE, payload);
            const first = @min(1024, view.length);
            try view.read(0, prefix_bytes[0..first]);
            for (cvs, 0..) |cv, j| @memcpy(prefix_bytes[first + 32 * j ..][0..32], &Tail.digest(cv));
        }
        const live: ?Hash.Prepared = if (words != null) try Hash.prepareWithPlan(a, circuit, prefix_bytes, claim, &shape.prefix) else null;
        var rows = if (live) |value| value.rows else try trustedRows(a, circuit, claim, &shape.prefix);
        defer rows.deinit();
        try builder.append(circuit, &shape.prefix, &rows, true, original_index, &header);
        const computed = if (live) |value| value.digest else claim;
        if (original_index) |index| digests[index] = computed else input_root = computed;
    }
    const private_words = try a.alloc(Word.Row, statement.word_count);
    for (private_words, uses, 0..) |*row, count, i| {
        if (count == 0) return error.InvalidBlake3TailRoute;
        row.* = try Word.logicalRow(statement.namespace, @intCast(i), count, if (words) |payload| payload[i] else 0);
    }
    const outputs = try a.alloc([8]Route.Endpoint, shape.tail.len);
    for (outputs, shape.tail, 0..) |*output, part, i| {
        for (output, part.output) |*endpoint, wire| {
            endpoint.* = .{ .circuit = builder.tailCircuit(i), .wire = wire };
        }
    }
    return .{ .arena = arena, .budget = budget, .rows = .{ .allocator = a, .g_rows = try builder.gs.toOwnedSlice(a), .xor_rows = try builder.xs.toOwnedSlice(a), .boundary_rows = try builder.bs.toOwnedSlice(a) }, .route_rows = try builder.routes.toOwnedSlice(a), .word_rows = private_words, .route_schedules = try builder.schedules.toOwnedSlice(a), .external_uses = external, .tail_outputs = outputs, .input_root = input_root, .original_digests = digests };
}
fn headerFor(word_count: usize) [Tail.HEADER_BYTES]u8 {
    var header: [Tail.HEADER_BYTES]u8 = undefined;
    const prefix = core.channel.blake3.framing.PROTOCOL_ID;
    @memcpy(header[0..prefix.len], prefix);
    header[prefix.len] = @intFromEnum(core.channel.blake3.framing.Domain.words);
    @memcpy(header[prefix.len + 1 ..][0..32], &Tail.DOMAIN_STATE);
    std.mem.writeInt(u64, header[Tail.HEADER_BYTES - 8 ..][0..8], @intCast(word_count), .little);
    return header;
}

fn trustedRows(a: std.mem.Allocator, circuit: u32, claim: [32]u8, plan: *const HashPlan.Plan) !Hash.Rows {
    var rows = Hash.Rows{
        .allocator = a,
        .g_rows = try a.alloc(G.Row, plan.g.len),
        .xor_rows = &.{},
        .boundary_rows = &.{},
    };
    errdefer rows.deinit();
    rows.xor_rows = try a.alloc(Xor.Row, plan.xor.len);
    rows.boundary_rows = try a.alloc(Boundary.Row, plan.sources.len + 8);
    try Hash.trustedShapeIntoWithPlan(circuit, plan.input_len, claim, plan, .{ .g_rows = rows.g_rows, .xor_rows = rows.xor_rows, .boundary_rows = rows.boundary_rows });
    return rows;
}
