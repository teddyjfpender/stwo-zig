//! Canonical frame hash with immediate nonhash emission. The source constructor
//! retains only small digest/use receipts; no boundary or routing row roster.
//! Bounded transcript/group/frontier builders select this canonical path.
//! The returned construction receipts are not proof authority.
const std = @import("std");
const core = @import("stwo_core");
const Frame = @import("blake3_frame_witness.zig");
const Routing = @import("blake3_frame_route.zig");
const Hash = @import("blake3_hash_witness.zig");
const Graph = @import("blake3_hash_plan.zig");
const Nonhash = @import("blake3_nonhash_emission_v1.zig");
pub const Emission = struct { sink: Nonhash.Sink, retain_output: bool };
const HashSink = struct {
    shape: *const Graph.Plan,
    emission: Emission,
    destination: ?Frame.HashDestination,
    columns: ?Hash.MainColumnSink,
    pub fn write(self: *@This(), comptime kind: usize, index: usize, row: anytype) !void {
        if (comptime kind < 2) {
            if (self.columns) |*columns| {
                columns.write(kind, index, row);
            } else if (self.destination) |out| {
                if (out.fixed) |metadata| {
                    if (comptime kind == 0) metadata.g_rows[index] = row[@import("blake3_g_call.zig").PHYSICAL_MAIN_COLUMN_COUNT..].* else metadata.xor_rows[index] = row[@import("blake3_xor_call.zig").PHYSICAL_MAIN_COLUMN_COUNT..].*;
                } else if (comptime kind == 0) out.g_rows[index] = row else out.xor_rows[index] = row;
            }
        } else {
            if (index < self.shape.sources.len) {
                if (self.shape.sources[index].value != .constant) return;
            } else if (!self.emission.retain_output) return;
            // Hash source constants and public output coordinates have the
            // same canonical logical recipe in live/fixed evaluation.
            try self.emission.sink.emit(2, &row, &row);
        }
    }
};
const Digests = struct {
    bindings: []const Frame.Binding,
    values: [2][32]u8 = undefined,
    payload: ?Frame.PayloadBinding,
    payload_values: []u32,
    pub fn protocolWord(self: *@This(), role: core.channel.blake3.framing.PayloadRole, index: usize, value: u32) void {
        if (self.payload) |binding| {
            if (role == binding.role) self.payload_values[index] = value;
        }
    }
    pub fn update(_: *@This(), _: []const u8) void {}
    pub fn protocolDigest(self: *@This(), role: core.channel.blake3.framing.DigestRole, value: [32]u8) void {
        for (self.bindings, 0..) |binding, index| {
            if (binding.role == role) self.values[index] = value;
        }
    }
};
/// Null hash destinations are permitted only for shape counting. A live hash
/// always targets independently shaped owned PCS columns or hash row ranges.
/// Any late error invalidates the caller's unpublished nonhash owner; it must
/// be discarded, never reused as a completed source.
pub fn prepare(a: std.mem.Allocator, circuit: u32, frame: anytype, bindings: []const Frame.Binding, payload: ?Frame.PayloadBinding, claim: [32]u8, live: bool, destination: ?Frame.HashDestination, columns: ?Frame.MainColumns, shape: *const Graph.Plan, emission: Emission) !Frame.Prepared {
    if (shape.input_len != try frame.encodedSize() or (live and destination == null and columns == null) or (destination != null and columns != null) or (!live and columns != null)) return error.InvalidBlake3WitnessDestination;
    if (destination) |out| {
        try out.validate(shape.g.len, shape.xor.len);
        if (live and out.fixed != null) return error.InvalidBlake3WitnessDestination;
    }
    if (columns) |out| try out.validate(shape.g.len, shape.xor.len);
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    // Routing/use arrays are real scratch, not part of the published arena.
    var routing = try Routing.buildWithPayloadPlan(a, circuit, frame, bindings, payload, shape);
    defer routing.deinit();
    var sink = HashSink{ .shape = shape, .emission = emission, .destination = destination, .columns = if (columns) |out| .{ .destination = .{ .g_rows = out.g_rows, .xor_rows = out.xor_rows, .boundary_rows = &.{} } } else null };
    var digest: ?[32]u8 = null;
    if (live) {
        const bytes = try frame.encode(a);
        defer a.free(bytes);
        digest = try Hash.emitLiveWithPlan(a, circuit, bytes, claim, shape, &sink);
    } else try Hash.emitFixedWithPlan(circuit, null, claim, shape, &sink);
    const payload_values = try a.alloc(u32, if (live and payload != null) payload.?.word_count else 0);
    defer a.free(payload_values);
    var digests = Digests{ .bindings = bindings, .payload = payload, .payload_values = payload_values };
    if (live) frame.write(&digests);
    var callers: [2]Routing.Caller = undefined;
    for (bindings, 0..) |binding, index| callers[index] = binding.caller;
    for (routing.schedules) |schedule| {
        const fixed = try Frame.route.fixedRow(schedule);
        const row = if (live) try Routing.witnessRowWithPayload(schedule, callers[0..bindings.len], digests.values[0..bindings.len], payload, payload_values) else fixed;
        try emission.sink.emit(7, &row, &fixed);
    }
    const payload_uses = try arena.allocator().dupe(u32, routing.payload_uses);
    // Construct every fallible field before publishing the completed owner.
    return .{ .arena = arena, .hash_metadata = if (columns) |out| out.metadata() else if (destination) |out| out.fixed else null, .rows = .{ .g_rows = if (destination) |out| out.g_rows else &.{}, .xor_rows = if (destination) |out| out.xor_rows else &.{}, .boundary_rows = &.{} }, .route_rows = &.{}, .source_uses = routing.child_uses, .payload_uses = payload_uses, .digest = digest };
}
