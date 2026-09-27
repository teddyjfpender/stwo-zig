//! Compile native absorption and secure draws into authenticated dataflow.
//! Operation order determines state links, draw counters and absorption resets.
const std = @import("std");
const Nonhash = @import("blake3_nonhash_emission_v1.zig");
const DirectFrame = @import("blake3_frame_nonhash_v1.zig");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const Metadata = @import("blake3_hash_metadata.zig");
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
    /// Start another independently specified channel from its canonical zero
    /// state/counter. Routing and preceding exports remain in the same graph.
    restart: u32,
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
    nonhash: ?Nonhash.Owner = null,
    nonhash_fixed: ?Nonhash.FixedOwner = null,
    /// Live column metadata is borrowed; compact trusted metadata is owned below.
    hash_metadata: ?@import("blake3_hash_metadata.zig").Rows = null,
    owns_hash_metadata: bool = false,
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
        if (self.nonhash) |*owner| owner.deinit();
        if (self.nonhash_fixed) |*owner| owner.deinit();
        if (self.owns_hash_metadata) self.hash_metadata.?.free(self.row_allocator);
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
    pub fn cohortRows(self: *const Prepared, comptime slot: usize) []const @import("blake3_parent_row_storage.zig").Airs[slot].Row {
        return switch (slot) {
            2 => self.boundary_rows,
            6 => self.challenge_rows,
            7 => self.route_rows,
            8 => self.query_rows,
            9, 13 => &.{},
            14 => self.control_rows,
            15 => self.counter_rows,
            else => @compileError("not a transcript nonhash cohort"),
        };
    }
    pub fn cohortCount(self: *const Prepared, comptime slot: usize) usize {
        if (self.nonhash) |*owner| return owner.rowCount(slot);
        if (self.nonhash_fixed) |*owner| return owner.fixed[
            comptime blk: {
                for (Nonhash.slots, 0..) |candidate, i| if (candidate == slot) break :blk i;
                @compileError("invalid transcript cohort");
            }
        ].len;
        return self.cohortRows(slot).len;
    }
    pub fn appendCohort(self: *const Prepared, comptime slot: usize, expected: *const Prepared, target: anytype) !void {
        if (self.nonhash) |*owner| {
            if (self.cohortRows(slot).len != 0 or expected.cohortRows(slot).len != 0 or expected.nonhash_fixed == null) return error.InvalidNativeParentRows;
            const view = try owner.columns.view(slot);
            const fixed_rows = try expected.nonhash_fixed.?.rows(slot);
            if (view.rowCount() != fixed_rows.len) return error.InvalidNativeParentRows;
            for (view.fixed, fixed_rows) |row, fixed| for (row, fixed) |actual, word| if (!actual.eql(word)) return error.InvalidNativeParentRows;
            try owner.appendTo(slot, target);
        } else {
            if (expected.nonhash_fixed != null) return error.InvalidNativeParentRows;
            try target.append(slot, self.cohortRows(slot), expected.cohortRows(slot));
        }
    }
    pub fn hashCounts(self: *const Prepared) @import("blake3_draw_hash_layout.zig").Counts {
        return .{ .g = if (self.hash_metadata) |m| m.g_rows.len else self.g_rows.len, .xor = if (self.hash_metadata) |m| m.xor_rows.len else self.xor_rows.len };
    }
    pub fn logs(self: *const Prepared) [6]u32 {
        return .{ log(if (self.hash_metadata) |m| m.g_rows.len else self.g_rows.len), log(if (self.hash_metadata) |m| m.xor_rows.len else self.xor_rows.len), log(self.cohortCount(2)), log(self.cohortCount(6)), log(self.cohortCount(7)), log(self.cohortCount(8)) };
    }
    fn log(n: usize) u32 {
        return if (n <= 1) 1 else std.math.log2_int_ceil(usize, n);
    }
};
pub fn prepare(a: std.mem.Allocator, namespace: u32, operations: []const Operation) !Prepared {
    return build(a, namespace, operations, true, null, null, false, null);
}
pub fn trusted(a: std.mem.Allocator, namespace: u32, operations: []const Operation) !Prepared {
    return build(a, namespace, operations, false, null, null, false, null);
}
/// Capacity is verifier-owned; recorded attempt counts are ignored in this mode.
pub fn prepareBounded(a: std.mem.Allocator, namespace: u32, operations: []const Operation, capacity: u32) !Prepared {
    return build(a, namespace, operations, true, capacity, null, false, null);
}
pub fn trustedBounded(a: std.mem.Allocator, namespace: u32, operations: []const Operation, capacity: u32) !Prepared {
    return build(a, namespace, operations, false, capacity, null, false, null);
}
pub fn trustedBoundedCompact(a: std.mem.Allocator, namespace: u32, operations: []const Operation, capacity: u32) !Prepared {
    return build(a, namespace, operations, false, capacity, null, true, null);
}
pub const MainColumns = frame_hash.MainColumns;
/// Caller owns columns/metadata. Later operation errors may leave unpublished
/// output partially written. Plan.prepareMainColumns admits exact fixed counts.
pub fn prepareBoundedMainColumns(a: std.mem.Allocator, namespace: u32, operations: []const Operation, capacity: u32, columns: MainColumns) !Prepared {
    return build(a, namespace, operations, true, capacity, columns, false, null);
}
/// Trusted source preprocessing stores only compact fixed tails. The shape
/// pass runs no compression and is destroyed before output owner allocation.
pub fn trustedBoundedDirect(a: std.mem.Allocator, namespace: u32, operations: []const Operation, capacity: u32) !Prepared {
    var counts = Nonhash.Counts{};
    var counted = try build(a, namespace, operations, false, capacity, null, true, counts.sink());
    counted.deinit();
    var fixed = try Nonhash.FixedOwner.init(a, counts);
    errdefer fixed.deinit();
    var result = try build(a, namespace, operations, false, capacity, null, true, fixed.sink());
    errdefer result.deinit();
    try fixed.finish();
    result.nonhash_fixed = fixed;
    return result;
}
pub fn prepareBoundedDirect(a: std.mem.Allocator, namespace: u32, operations: []const Operation, capacity: u32, expected: *const Prepared, columns: ?MainColumns) !Prepared {
    if (expected.nonhash_fixed == null) return error.CorruptBlake3TranscriptPlan;
    var counts = Nonhash.Counts{};
    inline for (Nonhash.slots, 0..) |slot, i| counts.rows[i] = expected.cohortCount(slot);
    var owned = try Nonhash.Owner.init(a, counts);
    errdefer owned.deinit();
    var result = try build(a, namespace, operations, true, capacity, columns, false, owned.sink());
    errdefer result.deinit();
    try owned.finish();
    result.nonhash = owned;
    return result;
}
fn build(backing: std.mem.Allocator, namespace: u32, operations: []const Operation, live: bool, capacity: ?u32, columns: ?MainColumns, compact: bool, nonhash: ?Nonhash.Sink) !Prepared {
    if (nonhash != null and capacity == null) return error.InvalidBlake3Transcript;
    if (compact and (live or capacity == null or columns != null)) return error.InvalidBlake3Transcript;
    if (capacity != null and capacity.? == 0) return error.InvalidBlake3Transcript;
    var end: u64 = @as(u64, namespace) + @intFromBool(capacity != null);
    for (operations) |op| {
        const count: u64 = switch (op) {
            .restart => |version| if (version == 1) 0 else return error.InvalidBlake3Transcript,
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
    if (columns) |out| try out.validate(out.g_rows.metadata.len, out.xor_rows.metadata.len);
    var g_used: usize = 0;
    var xor_used: usize = 0;
    var fixed_g: std.ArrayList(Metadata.Row(g)) = .empty;
    defer fixed_g.deinit(backing);
    var fixed_x: std.ArrayList(Metadata.Row(xor)) = .empty;
    defer fixed_x.deinit(backing);
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
        .restart => {
            state = initial;
            caller = .{ .circuit = namespace, .first_wire = 0 };
            producer = null;
            counter = 0;
            counter_source = zero_counter;
            counter_producer = null;
        },
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
            var plan = try graph.build(backing, try frame.encodedSize());
            defer plan.deinit();
            // Legacy cohort2 order puts public root producers before this
            // frame's constant boundary rows. Derive their use counts without
            // materializing or evaluating the frame, then stream in that order.
            if (nonhash) |sink| if (op == .root) {
                var recipe = try @import("blake3_frame_route.zig").buildWithPayloadPlan(backing, hash_circuit, frame, active, payload, &plan);
                defer recipe.deinit();
                for (recipe.child_uses[1], 0..) |uses, i| {
                    const row = try boundary.logicalRow(circuit, @intCast(i), M31.fromCanonical(uses), std.mem.readInt(u32, op.root[4 * i ..][0..4], .little));
                    try sink.emit(2, &row, &row);
                }
            };
            const destination = try reserveHash(backing, &gs, &xs, if (compact) &fixed_g else null, &fixed_x, columns, g_used, xor_used, plan.g.len, plan.xor.len);
            var prepared = if (nonhash) |sink| try DirectFrame.prepare(backing, hash_circuit, frame, active, payload, @splat(0), live, if (columns != null) null else destination, if (columns) |out| try out.slice(g_used, plan.g.len, xor_used, plan.xor.len) else null, &plan, .{ .sink = sink, .retain_output = false }) else if (columns) |out| try frame_hash.prepareMainColumns(backing, hash_circuit, frame, active, payload, @splat(0), try out.slice(g_used, plan.g.len, xor_used, plan.xor.len)) else if (live) try frame_hash.prepareInto(backing, hash_circuit, frame, active, payload, @splat(0), destination) else try frame_hash.trustedInto(backing, hash_circuit, frame, active, payload, @splat(0), destination);
            defer prepared.deinit();
            if (payload) |binding| try reads.append(a, .{ .operation = ordinal, .source = binding.caller, .uses = try a.dupe(u32, prepared.payload_uses) });
            try addUses(xs.items, if (columns) |c| c.metadata() else if (compact) Metadata.Rows{ .g_rows = fixed_g.items, .xor_rows = fixed_x.items } else null, producer, &initial_uses, prepared.source_uses[0]);
            if (op == .routed_root) try roots.append(a, .{ .operation = ordinal, .source = op.routed_root.source, .uses = prepared.source_uses[1] });
            if (op == .root and nonhash == null) for (prepared.source_uses[1], 0..) |uses, i| {
                const row = try boundary.logicalRow(circuit, @intCast(i), M31.fromCanonical(uses), std.mem.readInt(u32, op.root[4 * i ..][0..4], .little));
                try Nonhash.append(2, nonhash, backing, &bs, row, row);
            };
            g_used += plan.g.len;
            if (columns == null and !compact) gs.items.len = g_used;
            xor_used += plan.xor.len;
            if (columns == null and !compact) xs.items.len = xor_used;
            if (nonhash == null) {
                try bs.appendSlice(backing, prepared.rows.boundary_rows[0 .. prepared.rows.boundary_rows.len - 8]);
                try rs.appendSlice(backing, prepared.route_rows);
            }
            producer = xor_used - 16;
            for (0..8) |i| @import("blake3_hash_metadata.zig").xorUse(xs.items, if (columns) |c| c.metadata() else if (compact) Metadata.Rows{ .g_rows = fixed_g.items, .xor_rows = fixed_x.items } else null, producer.? + i).* = M31.zero();
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
            var plan = try graph.build(backing, try frame.encodedSize());
            defer plan.deinit();
            const destination = try reserveHash(backing, &gs, &xs, if (compact) &fixed_g else null, &fixed_x, columns, g_used, xor_used, plan.g.len, plan.xor.len);
            var prepared = if (nonhash) |sink| try DirectFrame.prepare(backing, circuit, frame, &bindings, payload, @splat(0), live, if (columns != null) null else destination, if (columns) |out| try out.slice(g_used, plan.g.len, xor_used, plan.xor.len) else null, &plan, .{ .sink = sink, .retain_output = false }) else if (columns) |out| try frame_hash.prepareMainColumns(backing, circuit, frame, &bindings, payload, @splat(0), try out.slice(g_used, plan.g.len, xor_used, plan.xor.len)) else if (live) try frame_hash.prepareInto(backing, circuit, frame, &bindings, payload, @splat(0), destination) else try frame_hash.trustedInto(backing, circuit, frame, &bindings, payload, @splat(0), destination);
            defer prepared.deinit();
            if (payload) |binding| try reads.append(a, .{ .operation = ordinal, .source = binding.caller, .uses = try a.dupe(u32, prepared.payload_uses) });
            try addUses(xs.items, if (columns) |c| c.metadata() else if (compact) Metadata.Rows{ .g_rows = fixed_g.items, .xor_rows = fixed_x.items } else null, producer, &initial_uses, prepared.source_uses[0]);
            for (0..8) |i| @import("blake3_hash_metadata.zig").xorUse(prepared.rows.xor_rows, prepared.hash_metadata, plan.xor.len - 16 + i).* = M31.fromCanonical(if (i == 0) 1 else 0);
            g_used += plan.g.len;
            if (columns == null and !compact) gs.items.len = g_used;
            xor_used += plan.xor.len;
            if (columns == null and !compact) xs.items.len = xor_used;
            if (nonhash == null) {
                try bs.appendSlice(backing, prepared.rows.boundary_rows[0 .. prepared.rows.boundary_rows.len - 8]);
                try rs.appendSlice(backing, prepared.route_rows);
            }
            const schedule = query_mask.Schedule{ .source_circuit = circuit, .source_wire = plan.output[0], .destination_circuit = circuit + 1, .destination_wire = 0, .uses = 1, .log_domain_size = pow.bits };
            const row = if (live) try query_mask.logicalLowBitsRow(schedule, std.mem.readInt(u32, prepared.digest.?[0..4], .little)) else try query_mask.fixedLowBitsRow(schedule);
            try Nonhash.append(8, nonhash, backing, &qs, row, try query_mask.fixedLowBitsRow(schedule));
            const fixed_output = try boundary.logicalRow(circuit + 1, 0, M31.one().neg(), 0);
            var output = fixed_output;
            if (live) output[0..4].* = row[4..8].*;
            try Nonhash.append(2, nonhash, backing, &bs, output, fixed_output);
            circuit += 2;
        },
        .queries => |q| {
            const statement = queries.Statement{ .namespace = circuit, .state = state, .state_source = caller, .start = counter, .log_domain_size = q.log_domain_size, .values = q.values, .export_outputs = q.export_outputs, .counter_source = if (capacity != null) counter_source else null, .final_counter_uses = .{ 0, 0 } };
            const counts = try queries.requiredHashRows(backing, q.values.len);
            const destination = try reserveHash(backing, &gs, &xs, if (compact) &fixed_g else null, &fixed_x, columns, g_used, xor_used, counts.g, counts.xor);
            var prepared = if (nonhash) |sink| try queries.prepareEmitting(backing, statement, live, if (columns != null) null else destination, if (columns) |out| try out.slice(g_used, counts.g, xor_used, counts.xor) else null, sink) else if (columns) |out| try queries.prepareMainColumns(backing, statement, try out.slice(g_used, counts.g, xor_used, counts.xor)) else if (live) try queries.prepareInto(backing, statement, destination) else try queries.trustedInto(backing, statement, destination);
            defer prepared.deinit();
            try addUses(xs.items, if (columns) |c| c.metadata() else if (compact) Metadata.Rows{ .g_rows = fixed_g.items, .xor_rows = fixed_x.items } else null, producer, &initial_uses, prepared.state_uses);
            g_used += counts.g;
            if (columns == null and !compact) gs.items.len = g_used;
            xor_used += counts.xor;
            if (columns == null and !compact) xs.items.len = xor_used;
            if (nonhash == null) {
                try bs.appendSlice(backing, prepared.boundary_rows);
                try rs.appendSlice(backing, prepared.route_rows);
                try qs.appendSlice(backing, prepared.mask_rows);
            }
            for (prepared.outputs, 0..) |source, i| try query_outputs.append(a, .{ .operation = ordinal, .query = i, .source = source });
            if (statement.counter_source != null and statement.values.len > 0) {
                try addCounterUsesEmitting(nonhash, counters.items, counter_producer, &zero_counter_uses, prepared.counter_uses);
                if (nonhash == null) try counters.appendSlice(backing, prepared.counter_rows);
                counter_producer = if (nonhash) |sink| sink.rowCount(15) - 1 else counters.items.len - 1;
                counter_source = prepared.final_counter.?;
            }
            counter = prepared.next_draw;
            const blocks = q.values.len / 8 + @intFromBool(q.values.len % 8 != 0);
            circuit += @intCast(2 * blocks + @intFromBool(capacity != null and blocks > 0));
        },
        .secure => |s| {
            if (capacity) |limit| {
                const statement = bounded.Statement{ .namespace = circuit, .capacity = limit, .state = state, .state_source = caller, .start = counter, .counter_source = counter_source, .consumption = s.consumption, .final_counter_uses = .{ 0, 0 } };
                const counts = try bounded.requiredHashRows(backing, limit);
                const destination = try reserveHash(backing, &gs, &xs, if (compact) &fixed_g else null, &fixed_x, columns, g_used, xor_used, counts.g, counts.xor);
                var prepared = if (nonhash) |sink| try bounded.prepareEmitting(backing, statement, live, if (columns != null) null else destination, if (columns) |out| try out.slice(g_used, counts.g, xor_used, counts.xor) else null, sink) else if (columns) |out| try bounded.prepareMainColumns(backing, statement, try out.slice(g_used, counts.g, xor_used, counts.xor)) else if (live) try bounded.prepareInto(backing, statement, destination) else try bounded.trustedInto(backing, statement, destination);
                defer prepared.deinit();
                try addUses(xs.items, if (columns) |c| c.metadata() else if (compact) Metadata.Rows{ .g_rows = fixed_g.items, .xor_rows = fixed_x.items } else null, producer, &initial_uses, prepared.state_uses);
                try addCounterUsesEmitting(nonhash, counters.items, counter_producer, &zero_counter_uses, prepared.counter_uses);
                g_used += counts.g;
                if (columns == null and !compact) gs.items.len = g_used;
                xor_used += counts.xor;
                if (columns == null and !compact) xs.items.len = xor_used;
                if (nonhash == null) {
                    try bs.appendSlice(backing, prepared.rows.boundary_rows);
                    try cs.appendSlice(backing, prepared.rows.challenge_rows);
                    try rs.appendSlice(backing, prepared.rows.route_rows);
                    try controls.appendSlice(backing, prepared.rows.control_rows);
                    try counters.appendSlice(backing, prepared.rows.counter_rows);
                }
                counter_producer = if (nonhash) |sink| sink.rowCount(15) - 1 else counters.items.len - 1;
                counter_source = prepared.final_counter;
                if (s.output) |role| {
                    try outputs.append(a, .{ .operation = ordinal, .role = role, .source = prepared.output, .words = s.consumption.words() });
                } else for (s.values[0..s.consumption.words()], 0..) |expected, i| {
                    const fixed_row = try boundary.logicalCoordinates(prepared.output.circuit, @intCast(i), M31.one().neg(), .{ expected, M31.zero(), M31.zero(), M31.zero() });
                    var row = fixed_row;
                    if (live) row[0] = prepared.selected.?[i];
                    try Nonhash.append(2, nonhash, backing, &bs, row, fixed_row);
                }
                counter = prepared.next_counter orelse 0;
                circuit += 2 * limit + 3;
            } else {
                const statement = draw.Statement{ .namespace = circuit, .state = state, .start = counter, .attempts = s.attempts, .values = s.values, .consumption = s.consumption, .export_outputs = s.output != null, .state_source = caller };
                const counts = try draw.requiredHashRows(backing, s.attempts);
                const destination = try reserveHash(backing, &gs, &xs, if (compact) &fixed_g else null, &fixed_x, columns, g_used, xor_used, counts.g, counts.xor);
                var prepared = if (columns) |out| try draw.prepareMainColumns(backing, statement, try out.slice(g_used, counts.g, xor_used, counts.xor)) else if (live) try draw.prepareInto(backing, statement, destination) else try draw.trustedInto(backing, statement, destination);
                defer prepared.deinit();
                try addUses(xs.items, if (columns) |c| c.metadata() else if (compact) Metadata.Rows{ .g_rows = fixed_g.items, .xor_rows = fixed_x.items } else null, producer, &initial_uses, prepared.state_uses);
                g_used += counts.g;
                if (columns == null and !compact) gs.items.len = g_used;
                xor_used += counts.xor;
                if (columns == null and !compact) xs.items.len = xor_used;
                try bs.appendSlice(backing, prepared.boundary_rows);
                try cs.appendSlice(backing, prepared.challenge_rows);
                try rs.appendSlice(backing, prepared.route_rows);
                if (s.output) |role| try outputs.append(a, .{ .operation = ordinal, .role = role, .source = prepared.output_source, .words = s.consumption.words() });
                counter = prepared.next_draw;
                circuit += 2 * s.attempts;
            }
        },
    };
    for (initial_uses, 0..) |uses, i| if (uses != 0) {
        const row = try boundary.logicalRow(namespace, @intCast(i), M31.fromCanonical(uses), std.mem.readInt(u32, initial[4 * i ..][0..4], .little));
        try Nonhash.append(2, nonhash, backing, &bs, row, row);
    };
    if (capacity != null) for (zero_counter_uses, 0..) |uses, i| if (uses != 0) {
        const row = try boundary.logicalRow(zero_counter.circuit, @intCast(i), M31.fromCanonical(uses), 0);
        try Nonhash.append(2, nonhash, backing, &bs, row, row);
    };
    if (columns) |out| if (g_used != out.g_rows.metadata.len or xor_used != out.xor_rows.metadata.len) return error.InvalidBlake3WitnessDestination;
    const owned_metadata: ?Metadata.Rows = if (compact) blk: {
        const g_tail = try fixed_g.toOwnedSlice(backing);
        errdefer backing.free(g_tail);
        break :blk .{ .g_rows = g_tail, .xor_rows = try fixed_x.toOwnedSlice(backing) };
    } else null;
    errdefer if (owned_metadata) |m| m.free(backing);
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
    const query_receipts = try query_outputs.toOwnedSlice(a);
    const root_receipts = try roots.toOwnedSlice(a);
    const draw_receipts = try outputs.toOwnedSlice(a);
    const payload_receipts = try reads.toOwnedSlice(a);
    return .{ .hash_metadata = if (columns) |out| out.metadata() else owned_metadata, .owns_hash_metadata = compact, .row_allocator = backing, .control_rows = control_rows, .counter_rows = counter_rows, .query_outputs = query_receipts, .root_reads = root_receipts, .draw_outputs = draw_receipts, .payload_reads = payload_receipts, .final_digest = if (live) state else null, .query_rows = query_rows, .arena = arena, .g_rows = g_rows, .xor_rows = xor_rows, .boundary_rows = boundary_rows, .challenge_rows = challenge_rows, .route_rows = route_rows, .next_draw = counter };
}
fn addUses(rows: []xor.Row, compact: ?@import("blake3_hash_metadata.zig").Rows, producer: ?usize, initial: *[8]u32, counts: [8]u32) !void {
    for (counts, 0..) |count, i| {
        const previous = if (producer) |offset| @import("blake3_hash_metadata.zig").xorUse(rows, compact, offset + i).toU32() else initial[i];
        const sum = std.math.add(u32, previous, count) catch return error.InvalidBlake3Transcript;
        if (sum >= core.fields.m31.Modulus) return error.InvalidBlake3Transcript;
        if (producer) |offset| @import("blake3_hash_metadata.zig").xorUse(rows, compact, offset + i).* = M31.fromCanonical(sum) else initial[i] = sum;
    }
}

fn addCounterUsesEmitting(sink: ?Nonhash.Sink, rows: []counter_step.Row, producer: ?usize, initial: *[2]u32, counts: [2]u32) !void {
    if (sink) |out| {
        if (producer) |index| {
            try out.addUses(15, index, 31, counts[0]);
            try out.addUses(15, index, 32, counts[1]);
        } else for (initial, counts) |*value, increment| {
            const sum = try std.math.add(u32, value.*, increment);
            if (sum >= core.fields.m31.Modulus) return error.InvalidBlake3Transcript;
            value.* = sum;
        }
    } else try addCounterUses(rows, producer, initial, counts);
}
fn addCounterUses(rows: []counter_step.Row, producer: ?usize, initial: *[2]u32, counts: [2]u32) !void {
    for (counts, 0..) |count, i| {
        const previous = if (producer) |offset| rows[offset][31 + i].v else initial[i];
        const sum = try std.math.add(u32, previous, count);
        if (sum >= core.fields.m31.Modulus) return error.InvalidBlake3Transcript;
        if (producer) |offset| rows[offset][31 + i] = M31.fromCanonical(sum) else initial[i] = sum;
    }
}

fn reserveHash(a: std.mem.Allocator, gs: *std.ArrayList(g.Row), xs: *std.ArrayList(xor.Row), fixed_g: ?*std.ArrayList(Metadata.Row(g)), fixed_x: *std.ArrayList(Metadata.Row(xor)), columns: ?MainColumns, g_used: usize, xor_used: usize, g_count: usize, xor_count: usize) !frame_hash.HashDestination {
    if (columns) |target| {
        _ = try target.slice(g_used, g_count, xor_used, xor_count);
        return .{ .g_rows = &.{}, .xor_rows = &.{} };
    }
    if (fixed_g) |fg| {
        try fg.resize(a, try std.math.add(usize, g_used, g_count));
        try fixed_x.resize(a, try std.math.add(usize, xor_used, xor_count));
        return .{ .fixed = .{ .g_rows = fg.items[g_used..], .xor_rows = fixed_x.items[xor_used..] } };
    }
    try gs.ensureUnusedCapacity(a, g_count);
    try xs.ensureUnusedCapacity(a, xor_count);
    return .{ .g_rows = gs.unusedCapacitySlice()[0..g_count], .xor_rows = xs.unusedCapacitySlice()[0..xor_count] };
}
