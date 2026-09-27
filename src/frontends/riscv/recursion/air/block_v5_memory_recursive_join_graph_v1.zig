//! Real original child byte coordinates lowered to one memory join graph.
//! No claims are embedded as constants; only independently admitted counts are.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const R = @import("composition_graph_recorder.zig");
const Arena = @import("stable_graph_arena_v1.zig").Owned;
const Public = @import("../block_v5_memory_recursive_join_public_v1.zig");
const A = @import("block_v5_memory_recursive_join_algebra_v1.zig");
const I = @import("../../prover/block_v5_ram_lanes_interaction_v1.zig");
const F = @import("../block_v5_memory_source_page_forest_algebra_v1.zig");
const G = @import("block_v5_heterogeneous_scoped_graph_rows_v1.zig").Graph;
pub const Prepared = struct {
    arena: Arena,
    circuit: R.Circuit,
    inputs: []Q,
    values: []Q,
    sources: []Public.Wire,
    pub const complete_block_authority = false;
    pub fn deinit(self: *@This()) void {
        self.circuit.deinit();
        self.arena.deinit();
        self.* = undefined;
    }
    pub fn graph(self: *const @This()) G {
        return .{ .circuit = &self.circuit, .inputs = self.inputs, .values = self.values, .sources = self.sources };
    }
};
const Reader = struct {
    a: std.mem.Allocator,
    builder: *R.Builder,
    values: Public.Values,
    inputs: std.ArrayList(Q) = .empty,
    sources: std.ArrayList(Public.Wire) = .empty,
    fn word(self: *@This(), kind: @FieldType(Public.Wire, "kind"), child: u32, coordinate: u32) ![4]R.Scalar {
        var symbols: [4]R.Scalar = undefined;
        for (&symbols, 0..) |*symbol, part| {
            const wire = Public.Wire{ .circuit = 0, .wire = 0, .uses = 1, .kind = kind, .child = child, .coordinate = coordinate, .part = @intCast(part) };
            symbol.* = (try self.builder.input()).value;
            try self.inputs.append(self.a, Q.fromM31Array(try self.values.at(wire)));
            try self.sources.append(self.a, wire);
        }
        return symbols;
    }
    fn secure(self: *@This(), kind: @FieldType(Public.Wire, "kind"), child: u32, coordinate: u32) ![4][4]R.Scalar {
        var symbols: [4][4]R.Scalar = undefined;
        for (&symbols, 0..) |*parts, limb| parts.* = try self.word(kind, child, coordinate + @as(u32, @intCast(limb)));
        return symbols;
    }
};
fn word(bytes: [4]R.Scalar) R.Scalar {
    var value = R.Scalar.zero();
    for (bytes, 0..) |byte, part| value = value.add(byte.mul(R.Scalar.fromBase(M.fromCanonical(@as(u32, 1) << @as(u5, @intCast(8 * part))))));
    return value;
}
fn secure(bytes: [4][4]R.Scalar) R.Scalar {
    var limbs: [4]R.Scalar = undefined;
    for (&limbs, bytes) |*limb, b| limb.* = word(b);
    return R.fromPartialEvals(limbs);
}
const Sink = struct {
    builder: *R.Builder,
    pub fn zero(self: *@This(), value: R.Scalar) !void {
        try self.builder.constrainZero(value);
    }
};
const LaneBytes = struct { sums: [4 + I.RANGE_PLANES][4][4]R.Scalar, counts: [3][2][4]R.Scalar };
const RangeBytes = struct { sum: [4][4]R.Scalar, count: [2][4]R.Scalar };
pub fn prepare(backing: std.mem.Allocator, public: *const Public.Owner) !Prepared {
    try public.validate();
    var arena = try Arena.init(backing);
    errdefer arena.deinit();
    const a = arena.allocator();
    var builder = R.Builder.init(a);
    defer builder.deinit();
    var reader = Reader{ .a = a, .builder = &builder, .values = .{ .public = public } };
    const context = public.policy.source.fresh.public.policy.forest.context;
    var source_bytes: [F.CLAIM_COUNT][4][4]R.Scalar = undefined;
    for (&source_bytes, 0..) |*bytes, index| bytes.* = try reader.secure(.child_cell, 0, (try public.policy.source.claim(@intCast(index))).first_cell);
    const coords = try public.policy.source.rangeCoordinates();
    var root_census: [6][4]R.Scalar = undefined;
    const positions = [_]u32{ coords.first, coords.count, coords.raw_pages, coords.fold_pages, coords.raw_rows, coords.fold_rows };
    for (&root_census, positions) |*bytes, position| bytes.* = try reader.word(.child_cell, 0, position);
    const lane_bytes = try a.alloc(LaneBytes, public.ram.len);
    for (lane_bytes, public.ram, 0..) |*bytes, *child, index| {
        const ordinal: u32 = @intCast(index + 1);
        for (&bytes.sums, 0..) |*sum, kind| sum.* = try reader.secure(.child_cell, ordinal, try child.sumFirst(@intCast(kind)));
        for (&bytes.counts, 0..) |*count, kind| {
            const position = try child.countFirst(@intCast(kind));
            count.* = .{ try reader.word(.child_cell, ordinal, position), try reader.word(.child_cell, ordinal, position + 1) };
        }
    }
    const range_bytes = try a.alloc(RangeBytes, public.range.len);
    for (range_bytes, public.range, 0..) |*bytes, *child, index| {
        const ordinal: u32 = @intCast(1 + public.ram.len + index);
        bytes.* = .{ .sum = try reader.secure(.child_cell, ordinal, try child.sumFirst(0)), .count = .{ try reader.word(.child_cell, ordinal, try child.countFirst(0)), try reader.word(.child_cell, ordinal, (try child.countFirst(0)) + 1) } };
    }
    const output = try reader.secure(.output_slot, 0, Public.OUTPUT_TRANSITION);
    const lanes = try a.alloc(A.Lane(R.Scalar), public.ram.len);
    const events = try a.alloc(u64, public.ram.len);
    const requests = try a.alloc(u64, public.ram.len);
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    var sink = Sink{ .builder = &builder };
    const expected_census = [_]u64{ 0, context.raw.len + context.fold.len, context.raw.len, context.fold.len, context.raw_plan.total_chunks, try context.fold_plan.census.operations() };
    for (root_census, expected_census) |bytes, count| try sink.zero(word(bytes).sub(try A.base(R.Scalar, count)));
    var source: [F.CLAIM_COUNT]R.Scalar = undefined;
    for (&source, source_bytes) |*value, bytes| value.* = secure(bytes);
    for (lanes, lane_bytes, public.policy.memory.pins, events, requests) |*lane, bytes, pin, *event_count, *request_count| {
        lane.* = .{ .event_count = word(bytes.counts[0][0]), .transition = secure(bytes.sums[0]), .predecessor = secure(bytes.sums[1]), .initial = secure(bytes.sums[2]), .endpoint = secure(bytes.sums[3]), .endpoint_count = word(bytes.counts[1][0]), .range_count = word(bytes.counts[2][0]), .ranges = undefined };
        for (&lane.ranges, bytes.sums[4..]) |*range, parts| range.* = secure(parts);
        for (bytes.counts) |count| for (count[1]) |byte| try sink.zero(byte);
        event_count.* = pin.claim.events;
        request_count.* = pin.request_count;
    }
    for (range_bytes, public.plan.shards) |bytes, shard| {
        for (bytes.count[1]) |byte| try sink.zero(byte);
        try A.rangeGroup(R.Scalar, &sink, shard, .{ .sum = secure(bytes.sum), .count = word(bytes.count[0]) }, lanes[shard.first_instance..][0..shard.instance_count]);
    }
    const transition = try A.close(R.Scalar, &sink, &context.admitted, source, lanes, events, requests);
    try sink.zero(transition.sub(secure(output)));
    try builder.check();
    var circuit = try builder.finish();
    errdefer circuit.deinit();
    const inputs = try reader.inputs.toOwnedSlice(a);
    const sources = try reader.sources.toOwnedSlice(a);
    const values = try a.alloc(Q, circuit.nodes.len);
    try circuit.evaluateInto(inputs, values);
    return .{ .arena = arena, .circuit = circuit, .inputs = inputs, .values = values, .sources = sources };
}
