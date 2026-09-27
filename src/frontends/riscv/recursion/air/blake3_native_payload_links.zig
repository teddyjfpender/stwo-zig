//! Scalar native composition inputs -> QM31 packing -> transcript felt bytes.
const std = @import("std");
const vm = @import("../vm_air_composition_circuit.zig");
const native = @import("blake3_native_transcript.zig");
const recorder = @import("blake3_native_recorder.zig");
const claims = @import("../../air/transcript/claims.zig");
const scalar = @import("scalar_wire_source.zig");
const pack = @import("qm31_pack_wire.zig");
const encoding = @import("blake3_field_bytes.zig");
const lower = @import("verifier_arithmetic_lowering.zig");
const payload_rows = @import("blake3_scalar_payload_rows.zig");
pub const PACK_CIRCUIT: u32 = 5_000_010;
pub const Columns = @import("blake3_upstream_source_columns_v1.zig").ForSlots(.{ 12, 11, 10 });
pub const Prepared = struct {
    arena: std.heap.ArenaAllocator,
    nodes: [][4]u32,
    scalars: []scalar.Row,
    fixed_scalars: []scalar.Row,
    packing: []pack.Row,
    fixed_packing: []pack.Row,
    encoded: []encoding.Row,
    fixed_encoded: []encoding.Row,
    columns: ?Columns = null,
    node_allocator: ?std.mem.Allocator = null,
    pub fn scalarCount(self: *const Prepared) usize {
        return if (self.columns) |*columns| columns.count(12) else self.scalars.len;
    }
    pub fn scalarAt(self: *const Prepared, index: usize) !scalar.Row {
        if (self.columns) |*columns| {
            if (self.scalars.len != 0 or self.fixed_scalars.len != 0) return error.InvalidNativePayloadLink;
            return columns.rowAt(12, index);
        }
        if (index >= self.scalars.len) return error.InvalidNativePayloadLink;
        return self.scalars[index];
    }
    pub fn fixedScalarAt(self: *const Prepared, index: usize) !scalar.Row {
        if (self.columns != null) {
            var row = try self.scalarAt(index);
            row[0] = @import("stwo_core").fields.m31.M31.zero();
            return row;
        }
        if (index >= self.fixed_scalars.len) return error.InvalidNativePayloadLink;
        return self.fixed_scalars[index];
    }
    pub fn appendPacking(self: *const Prepared, b: anytype) !void {
        if (self.columns) |*columns| {
            if (self.packing.len != 0 or self.fixed_packing.len != 0) return error.InvalidNativePayloadLink;
            try columns.appendTo(11, b);
        } else try b.append(11, self.packing, self.fixed_packing);
    }
    pub fn appendEncoded(self: *const Prepared, b: anytype) !void {
        if (self.columns) |*columns| {
            if (self.encoded.len != 0 or self.fixed_encoded.len != 0) return error.InvalidNativePayloadLink;
            try columns.appendTo(10, b);
        } else try b.append(10, self.encoded, self.fixed_encoded);
    }
    pub fn deinit(self: *Prepared) void {
        if (self.columns) |*columns| columns.deinit();
        if (self.node_allocator) |a| a.free(self.nodes);
        self.arena.deinit();
        self.* = undefined;
    }
    /// Nodes are needed by the subsequent sample/public joins only. The parent
    /// releases this immutable mapping after both joins, before assembly.
    pub fn releaseNodeMap(self: *Prepared) !void {
        const a = self.node_allocator orelse return error.InvalidNativePayloadLink;
        a.free(self.nodes);
        self.nodes = &.{};
    }
};

/// Returned rows must be included with the native arithmetic and transcript AIRs.
/// Other consumers of sampled values require explicit additional fanout counts.
pub fn prepare(backing: std.mem.Allocator, composition: *const vm.Prepared, transcript: *const native.Prepared, circuit: u32) !Prepared {
    return prepareMode(false, backing, composition, transcript, circuit);
}
pub fn prepareColumns(backing: std.mem.Allocator, composition: *const vm.Prepared, transcript: *const native.Prepared, circuit: u32) !Prepared {
    return prepareMode(true, backing, composition, transcript, circuit);
}
fn prepareMode(comptime direct: bool, backing: std.mem.Allocator, composition: *const vm.Prepared, transcript: *const native.Prepared, circuit: u32) !Prepared {
    try composition.validate();
    try transcript.plan.validate();
    if (circuit == PACK_CIRCUIT or composition.circuit.input_profile.transcript_claimed_sum_count != claims.COMPONENT_COUNT) return error.InvalidNativePayloadLink;
    const samples: usize = composition.circuit.input_profile.sampled_value_count;
    const count = try std.math.add(usize, samples, claims.COMPONENT_COUNT);
    var arena = std.heap.ArenaAllocator.init(backing);
    errdefer arena.deinit();
    const a = arena.allocator();
    const scalar_count = try std.math.mul(usize, count, 4);
    var columns: ?Columns = null;
    errdefer if (columns) |*owned| owned.deinit();
    if (direct) columns = try Columns.init(backing, .{ scalar_count, count, count });
    var scratch_arena = std.heap.ArenaAllocator.init(backing);
    defer scratch_arena.deinit();
    const scratch = scratch_arena.allocator();
    const nodes = try (if (direct) backing else a).alloc([4]u32, count);
    errdefer if (direct) backing.free(nodes);
    const missing = std.math.maxInt(u32);
    @memset(nodes, @splat(missing));
    for (composition.circuit.bindings) |binding| {
        const coordinate, const offset, const limit = switch (binding.source) {
            .transcript_claimed_sum => |c| .{ c, @as(usize, 0), @as(usize, claims.COMPONENT_COUNT) },
            .sampled_value => |c| .{ c, @as(usize, claims.COMPONENT_COUNT), samples },
            else => continue,
        };
        if (coordinate.item_index >= limit or coordinate.word_index >= 4 or binding.node_id >= composition.circuit.nodes.len or composition.circuit.nodes[binding.node_id].op != .input) return error.InvalidNativePayloadLink;
        const slot = &nodes[offset + coordinate.item_index][coordinate.word_index];
        if (slot.* != missing) return error.InvalidNativePayloadLink;
        slot.* = binding.node_id;
    }
    for (nodes) |tuple| for (tuple) |node| if (node == missing) return error.InvalidNativePayloadLink;
    const uses = try lower.computeUseCountsInto(composition.circuit.graph(), try scratch.alloc(u32, composition.circuit.nodes.len));
    const result = Prepared{
        .arena = undefined,
        .nodes = nodes,
        .scalars = if (direct) &.{} else try a.alloc(scalar.Row, scalar_count),
        .fixed_scalars = if (direct) &.{} else try a.alloc(scalar.Row, scalar_count),
        .packing = if (direct) &.{} else try a.alloc(pack.Row, count),
        .fixed_packing = if (direct) &.{} else try a.alloc(pack.Row, count),
        .encoded = if (direct) &.{} else try a.alloc(encoding.Row, count),
        .fixed_encoded = if (direct) &.{} else try a.alloc(encoding.Row, count),
    };
    const seen = try scratch.alloc(bool, count);
    @memset(seen, false);
    const trusted = transcript.plan.fixed.payload_reads;
    if (trusted.len != transcript.live.payload_reads.len) return error.InvalidNativePayloadLink;
    for (trusted, transcript.live.payload_reads) |receipt, live| {
        if (receipt.operation != live.operation or !std.meta.eql(receipt.source, live.source) or !std.mem.eql(u32, receipt.uses, live.uses)) return error.InvalidNativePayloadLink;
        const is_claim = receipt.source.circuit == recorder.CLAIM_CIRCUIT;
        const is_sample = receipt.source.circuit == native.SAMPLE_SOURCE.circuit;
        if (!is_claim and !is_sample) continue;
        if (receipt.operation >= transcript.operations.len or transcript.operations[receipt.operation] != .routed_felts) return error.InvalidNativePayloadLink;
        const payload = transcript.operations[receipt.operation].routed_felts;
        if (!std.meta.eql(payload.source, receipt.source) or receipt.uses.len != payload.values.len * 4) return error.InvalidNativePayloadLink;
        const start: usize = if (is_claim) receipt.source.first_wire / 4 else claims.COMPONENT_COUNT;
        if (is_claim) {
            if (receipt.source.first_wire % 4 != 0 or start >= claims.COMPONENT_COUNT or payload.values.len != 1) return error.InvalidNativePayloadLink;
        } else if (receipt.source.first_wire != native.SAMPLE_SOURCE.first_wire or payload.values.len != samples) return error.InvalidNativePayloadLink;
        for (payload.values, 0..) |value, i| {
            const item = start + i;
            if (seen[item]) return error.InvalidNativePayloadLink;
            seen[item] = true;
            const rows = payload_rows.build(nodes[item], composition.evaluation.values, uses, circuit, .{ .circuit = PACK_CIRCUIT, .first_wire = @intCast(item) }, .{ .circuit = receipt.source.circuit, .first_wire = try std.math.add(u32, receipt.source.first_wire, @intCast(i * 4)) }, receipt.uses[i * 4 ..][0..4].*, value) catch |err| switch (err) {
                error.InvalidScalarPayload => return error.InvalidNativePayloadLink,
                else => return err,
            };
            if (direct) {
                for (rows.scalars, 0..) |row, word| try columns.?.put(12, item * 4 + word, row);
                try columns.?.put(11, item, rows.packing);
                try columns.?.put(10, item, rows.encoded);
            } else {
                result.scalars[item * 4 ..][0..4].* = rows.scalars;
                result.fixed_scalars[item * 4 ..][0..4].* = rows.fixed_scalars;
                result.packing[item] = rows.packing;
                result.fixed_packing[item] = rows.fixed_packing;
                result.encoded[item] = rows.encoded;
                result.fixed_encoded[item] = rows.fixed_encoded;
            }
        }
    }
    for (seen) |present| if (!present) return error.InvalidNativePayloadLink;
    if (columns) |*owned| try owned.finish();
    var owned = result;
    owned.columns = columns;
    owned.node_allocator = if (direct) backing else null;
    owned.arena = arena;
    return owned;
}
