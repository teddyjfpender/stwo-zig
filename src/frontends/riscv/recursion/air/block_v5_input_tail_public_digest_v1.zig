//! ORIGINAL B5PD channel reconstruction with only the input-frame hash replaced.
//! All other original frames, order, state transitions and final bytes remain
//! exact. The caller must bind field/prefix/frontier/final-digest requests to
//! genuine independently admitted original child/provider public byte cells.
const std = @import("std");
const core = @import("stwo_core");
const Fields = @import("../block_v5_global_public_fields_v1.zig");
const Public = @import("../block_v5_input_tail_public_v1.zig");
const Tail = @import("../blake3_words_tail_v1.zig");
const Consumer = @import("block_v5_input_tail_consumer_v1.zig");
const FrameWitness = @import("blake3_frame_witness.zig");
const HashPlan = @import("blake3_hash_plan.zig");
const Hash = @import("blake3_hash_witness.zig");
const Boundary = @import("blake3_boundary.zig");
const Route = @import("blake3_byte_route.zig");
const M = core.fields.m31.M31;
pub const Statement = struct {
    namespace: u32,
    fields: *const Fields.Fields,
    carrier: *const Public.Owned,
    expected_input: Public.Pin,
    /// Raw public-field source coordinates retain exact canonical Fields.word
    /// ordinals. The large input coordinates are never read on this route.
    field_source: Consumer.Caller,
    prefix_source: Consumer.Caller,
    frontier_sources: []const Consumer.Caller,
    pub fn require(self: Statement) !void {
        try self.carrier.require(self.expected_input);
        const fields = self.fields;
        if (fields.hashed_chunks < 13 or fields.hashed_chunks > 1 << 16 or fields.hashed_chunks + 2 != fields.chunks.len or fields.chunks[12].words.len != self.carrier.pin.word_count or fields.chunks[12].words.ptr != fields.borrowed_input.ptr or fields.borrowed_input.ptr != self.carrier.job.expected().input_words.ptr or fields.borrowed_input.len != self.carrier.pin.word_count or self.frontier_sources.len != self.carrier.geometry.range_count) return error.UntrustedInputTailPublicDigest;
        const end = try std.math.add(u64, self.namespace, 2 * fields.hashed_chunks);
        if (end >= core.fields.m31.Modulus or self.field_source.circuit >= core.fields.m31.Modulus or self.field_source.first_wire >= core.fields.m31.Modulus or fields.word_count > core.fields.m31.Modulus - self.field_source.first_wire) return error.UntrustedInputTailPublicDigest;
        if (sourceOverlap(self.field_source, fields.word_count, self.prefix_source, self.carrier.prefix_count)) return error.UntrustedInputTailPublicDigest;
        var cursor: u32 = 0;
        for (fields.chunks) |chunk| {
            if (chunk.first != cursor) return error.UntrustedInputTailPublicDigest;
            cursor = std.math.add(u32, cursor, std.math.cast(u32, chunk.words.len) orelse return error.UntrustedInputTailPublicDigest) catch return error.UntrustedInputTailPublicDigest;
        }
        if (cursor != fields.word_count) return error.UntrustedInputTailPublicDigest;
        for (self.frontier_sources) |source| {
            if (source.circuit >= self.namespace and source.circuit < end) return error.UntrustedInputTailPublicDigest;
            if (sourceOverlap(self.field_source, fields.word_count, source, 8)) return error.UntrustedInputTailPublicDigest;
        }
        if ((self.field_source.circuit >= self.namespace and self.field_source.circuit < end) or (self.prefix_source.circuit >= self.namespace and self.prefix_source.circuit < end)) return error.UntrustedInputTailPublicDigest;
    }
};
fn sourceOverlap(a: Consumer.Caller, an: usize, b: Consumer.Caller, bn: usize) bool {
    return an != 0 and bn != 0 and a.circuit == b.circuit and @as(u64, a.first_wire) < @as(u64, b.first_wire) + bn and @as(u64, b.first_wire) < @as(u64, a.first_wire) + an;
}
pub const FieldUse = struct { coordinate: u32, uses: u32 };
pub const Prepared = struct {
    arena: std.heap.ArenaAllocator,
    rows: Hash.Rows,
    route_rows: []Route.Row,
    field_uses: []FieldUse,
    prefix_uses: []u32,
    frontier_uses: [][8]u32,
    digest: [32]u8,
    compression_calls: usize,
    /// The final output is constrained to Fields.source_digest, but a higher
    /// parent must still pair those bytes to the original native instance.
    pub const native_digest_pairing_pending = true;
    pub const complete_source_authority = false;
    pub fn deinit(self: *Prepared) void {
        self.arena.deinit();
        self.* = undefined;
    }
};
pub fn prepare(a: std.mem.Allocator, statement: Statement) !Prepared {
    return build(a, statement, true);
}
pub fn trusted(a: std.mem.Allocator, statement: Statement) !Prepared {
    return build(a, statement, false);
}
fn build(backing: std.mem.Allocator, statement: Statement, live: bool) !Prepared {
    try statement.require();
    var arena = std.heap.ArenaAllocator.init(backing);
    errdefer arena.deinit();
    const a = arena.allocator();
    var gs: std.ArrayList(@import("blake3_g_call.zig").Row) = .empty;
    var xs: std.ArrayList(@import("blake3_xor_call.zig").Row) = .empty;
    var bs: std.ArrayList(Boundary.Row) = .empty;
    var routes: std.ArrayList(Route.Row) = .empty;
    var uses: std.ArrayList(FieldUse) = .empty;
    const initial_state = (core.channel.blake3.Channel{}).digestBytes();
    var state: [32]u8 = initial_state;
    var previous_output: [8]u32 = undefined;
    var previous_circuit: u32 = undefined;
    var prefix_uses: []u32 = &.{};
    var frontier_uses: [][8]u32 = &.{};
    var calls: usize = 0;
    for (statement.fields.chunks[0..statement.fields.hashed_chunks], 0..) |chunk, ordinal| {
        const incoming_state = state;
        const circuit = statement.namespace + @as(u32, @intCast(2 * ordinal));
        const bridge = Consumer.Caller{ .circuit = circuit + 1, .first_wire = 0 };
        var plan = if (ordinal == 12) try HashPlan.buildPrefixFold(a, statement.carrier.geometry.frame_bytes) else try HashPlan.build(a, try (core.channel.blake3.framing.Frame{ .words = .{ .state = state, .values = chunk.words } }).encodedSize());
        defer plan.deinit();
        calls = try std.math.add(usize, calls, plan.calls.len);
        var current_state_uses: [8]u32 = undefined;
        if (ordinal == 12) {
            // The only input values read are the bounded carrier prefix/CVs.
            const proposal = Consumer.Statement{ .circuit = circuit, .word_count = statement.carrier.pin.word_count, .state = state, .claim = @splat(0), .sources = .{ .state = bridge, .prefix = statement.prefix_source, .frontier = statement.frontier_sources } };
            var frame = if (live) try Consumer.prepare(a, proposal, statement.carrier.prefix(), statement.carrier.frontier) else try Consumer.trusted(a, proposal);
            defer frame.deinit();
            try gs.appendSlice(a, frame.rows.g_rows);
            try xs.appendSlice(a, frame.rows.xor_rows);
            try bs.appendSlice(a, frame.rows.boundary_rows[0 .. frame.rows.boundary_rows.len - 8]);
            try routes.appendSlice(a, frame.route_rows);
            current_state_uses = frame.state_uses;
            prefix_uses = try a.dupe(u32, frame.prefix_uses);
            frontier_uses = try a.dupe([8]u32, frame.frontier_uses);
            state = frame.digest;
        } else {
            const frame_value = core.channel.blake3.framing.Frame{ .words = .{ .state = state, .values = chunk.words } };
            const computed = if (live) frame_value.hash() else @as([32]u8, @splat(0));
            const binding = [_]FrameWitness.Binding{.{ .role = .state, .caller = bridge }};
            const payload = FrameWitness.PayloadBinding{ .role = .words, .caller = .{ .circuit = statement.field_source.circuit, .first_wire = statement.field_source.first_wire + chunk.first }, .word_count = chunk.words.len };
            var frame = try FrameWitness.destinationWithPlan(a, circuit, frame_value, &binding, payload, computed, live, null, null, &plan);
            defer frame.deinit();
            try gs.appendSlice(a, frame.rows.g_rows);
            try xs.appendSlice(a, frame.rows.xor_rows);
            try bs.appendSlice(a, frame.rows.boundary_rows[0 .. frame.rows.boundary_rows.len - 8]);
            try routes.appendSlice(a, frame.route_rows);
            current_state_uses = frame.source_uses[0];
            for (frame.payload_uses, 0..) |count, word| if (count != 0) try uses.append(a, .{ .coordinate = chunk.first + @as(u32, @intCast(word)), .uses = count });
            state = computed;
        }
        if (ordinal == 0) {
            for (current_state_uses, 0..) |count, word| if (count != 0) try bs.append(a, try Boundary.logicalRow(bridge.circuit, @intCast(word), M.fromCanonical(count), std.mem.readInt(u32, initial_state[4 * word ..][0..4], .little)));
        } else {
            // Remove each preceding public output sink and route the ACTUAL
            // original compression output into this frame's state. The source
            // output had use1; the destination has the next exact read count.
            for (previous_output, current_state_uses, 0..) |wire, count, word| {
                if (count == 0) return error.UntrustedInputTailPublicDigest;
                const schedule = Route.Schedule{ .sources = .{ .{ .circuit = previous_circuit, .wire = wire }, null }, .destination = .{ .circuit = bridge.circuit, .wire = @intCast(word) }, .uses = count, .bytes = .{ .{ .source = .{ .word = 0, .byte = 0 } }, .{ .source = .{ .word = 0, .byte = 1 } }, .{ .source = .{ .word = 0, .byte = 2 } }, .{ .source = .{ .word = 0, .byte = 3 } } } };
                try routes.append(a, if (live) try Route.logicalRow(schedule, .{ std.mem.readInt(u32, incoming_state[4 * word ..][0..4], .little), 0 }) else try Route.fixedRow(schedule));
            }
        }
        previous_output = plan.output;
        previous_circuit = circuit;
    }
    for (previous_output, 0..) |wire, word| try bs.append(a, try Boundary.logicalRow(previous_circuit, wire, M.one().neg(), std.mem.readInt(u32, statement.fields.source_digest[4 * word ..][0..4], .little)));
    if (live and !std.meta.eql(state, statement.fields.source_digest)) return error.UntrustedInputTailPublicDigest;
    return .{ .arena = arena, .rows = .{ .allocator = a, .g_rows = try gs.toOwnedSlice(a), .xor_rows = try xs.toOwnedSlice(a), .boundary_rows = try bs.toOwnedSlice(a) }, .route_rows = try routes.toOwnedSlice(a), .field_uses = try uses.toOwnedSlice(a), .prefix_uses = prefix_uses, .frontier_uses = frontier_uses, .digest = if (live) state else statement.fields.source_digest, .compression_calls = calls };
}

pub const Request = struct {
    circuit: u32,
    wire: u32,
    uses: u32,
    source: union(enum) { public_field: u32, input_prefix: u32, frontier: struct { ordinal: u32, word: u32 } },
};
pub const ColumnPrepared = struct {
    budget: *@import("stwo_prover_engine").host_budget_allocator.SharedHostBudget,
    backing_owner: ?*@import("stwo_prover_engine").host_budget_allocator.SharedHostBudget,
    recursive: @import("../blake3_execution_parent_preparation.zig").Prepared,
    requests: []Request,
    pub fn deinit(self: *ColumnPrepared) void {
        self.recursive.rows.allocator.free(self.requests);
        self.recursive.deinit();
        self.budget.destroy();
        if (self.backing_owner) |owner| owner.destroy();
        self.* = undefined;
    }
};
/// Actual column producer for a bounded window parent's selected B5PD route.
/// Requests must be supplied by its typed public bus and linked at the common
/// ancestor. It deliberately has no standalone acceptance/closure API.
pub fn prepareColumns(backing: std.mem.Allocator, statement: Statement, config: core.pcs.PcsConfig, max_bytes: usize) !ColumnPrepared {
    if (max_bytes == 0) return error.InputTailResourceLimit;
    const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
    const Storage = @import("blake3_parent_row_storage.zig");
    const Direct = @import("blake3_direct_cohort_columns_v1.zig");
    const backing_owner = if (Budget.fromAllocator(backing)) |owner| owner.retain() else null;
    errdefer if (backing_owner) |owner| owner.destroy();
    const budget = try Budget.create(backing, max_bytes);
    errdefer budget.destroy();
    const a = budget.allocator();
    var live = try prepare(a, statement);
    defer live.deinit();
    var fixed = try trusted(a, statement);
    defer fixed.deinit();
    var rows = Storage.Prepared{ .allocator = a, .main = @splat(&.{}), .fixed = undefined, .input_count = 0 };
    inline for (0..Storage.Airs.len) |i| rows.fixed[i] = &.{};
    errdefer rows.deinit();
    inline for (Storage.Airs, 0..) |Air, i| {
        const actual = if (comptime i == 0) live.rows.g_rows else if (comptime i == 1) live.rows.xor_rows else if (comptime i == 2) live.rows.boundary_rows else if (comptime i == 7) live.route_rows else &[_]Air.Row{};
        const expected = if (comptime i == 0) fixed.rows.g_rows else if (comptime i == 1) fixed.rows.xor_rows else if (comptime i == 2) fixed.rows.boundary_rows else if (comptime i == 7) fixed.route_rows else &[_]Air.Row{};
        if (actual.len != expected.len) return error.UntrustedInputTailRows;
        var emitter = try Direct.ForAir(Air).init(a, actual.len);
        defer emitter.deinit();
        for (actual, expected) |row, admitted| {
            for (row[Air.PHYSICAL_MAIN_COLUMN_COUNT..], admitted[Air.PHYSICAL_MAIN_COLUMN_COUNT..]) |value, normative| if (!value.eql(normative)) return error.UntrustedInputTailRows;
            try emitter.append(row);
        }
        const taken = try emitter.take();
        rows.main[i] = taken.main;
        rows.fixed[i] = taken.fixed;
    }
    try rows.partitionHashRows();
    var requests: std.ArrayList(Request) = .empty;
    errdefer requests.deinit(a);
    for (live.field_uses) |field| try requests.append(a, .{ .circuit = statement.field_source.circuit, .wire = statement.field_source.first_wire + field.coordinate, .uses = field.uses, .source = .{ .public_field = field.coordinate } });
    for (live.prefix_uses, 0..) |count, word| if (count != 0) try requests.append(a, .{ .circuit = statement.prefix_source.circuit, .wire = statement.prefix_source.first_wire + @as(u32, @intCast(word)), .uses = count, .source = .{ .input_prefix = @intCast(word) } });
    for (live.frontier_uses, statement.frontier_sources, 0..) |words, source, ordinal| for (words, 0..) |count, word| {
        if (count != 0) try requests.append(a, .{ .circuit = source.circuit, .wire = source.first_wire + @as(u32, @intCast(word)), .uses = count, .source = .{ .frontier = .{ .ordinal = @intCast(ordinal), .word = @intCast(word) } } });
    };
    var identity = core.channel.blake3.Channel{};
    identity.mixU32s(&.{ 0x42355444, 1, statement.namespace, statement.carrier.pin.word_count, @intCast(statement.fields.hashed_chunks) });
    identity.mixRoot(statement.carrier.statement_id);
    identity.mixRoot(statement.fields.source_digest);
    inline for (.{ @embedFile("block_v5_input_tail_public_digest_v1.zig"), @embedFile("block_v5_input_tail_consumer_v1.zig") }) |source| {
        var digest: [32]u8 = undefined;
        std.crypto.hash.Blake3.hash(source, &digest, .{});
        identity.mixRoot(digest);
    }
    for (requests.items) |request| {
        identity.mixU32s(&.{ request.circuit, request.wire, request.uses, @intFromEnum(std.meta.activeTag(request.source)) });
        switch (request.source) {
            .public_field, .input_prefix => |coordinate| identity.mixU32s(&.{coordinate}),
            .frontier => |v| identity.mixU32s(&.{ v.ordinal, v.word }),
        }
    }
    const graph_id = identity.digestBytes();
    const owned = try requests.toOwnedSlice(a);
    return .{ .budget = budget, .backing_owner = backing_owner, .requests = owned, .recursive = .{ .rows = rows, .context = .{ .child_key_id = statement.carrier.statement_id, .child_config = config, .graph_ids = @splat(graph_id), .transcript_plan_id = graph_id } } };
}
