//! Detailed execution claims and DEEP samples share their secure composition
//! wires with the transcript's canonical field-byte encoding.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const composition_mod = @import("blake3_execution_composition.zig");
const transcript_mod = @import("blake3_native_transcript.zig");
const recorder = @import("blake3_native_recorder.zig");
const deep_mod = @import("blake3_native_deep.zig");
const samples_mod = @import("blake3_execution_sample_links.zig");
const scalar = @import("scalar_wire_source.zig");
const pack = @import("qm31_pack_wire.zig");
const encoding = @import("blake3_field_bytes.zig");
const lower = @import("verifier_arithmetic_lowering.zig");
pub const Columns = @import("blake3_upstream_source_columns_v1.zig").ForSlots(.{ 12, 11, 10 });
pub const NestedColumns = @import("blake3_upstream_source_columns_v1.zig").ForSlots(.{ 12, 11 });
pub const Prepared = struct {
    arena: std.heap.ArenaAllocator,
    samples: samples_mod.Prepared,
    claim_sources: []scalar.Row,
    fixed_claim_sources: []scalar.Row,
    claim_packs: []pack.Row,
    fixed_claim_packs: []pack.Row,
    encoded: []encoding.Row,
    fixed_encoded: []encoding.Row,
    columns: ?Columns = null,
    nested_columns: ?NestedColumns = null,
    pub fn appendClaims(self: *const Prepared, b: anytype) !void {
        if (self.columns) |*columns| {
            if (self.claim_sources.len != 0 or self.fixed_claim_sources.len != 0 or self.claim_packs.len != 0 or self.fixed_claim_packs.len != 0) return error.InvalidExecutionPayload;
            try columns.appendTo(12, b);
            try columns.appendTo(11, b);
        } else {
            try b.append(12, self.claim_sources, self.fixed_claim_sources);
            try b.append(11, self.claim_packs, self.fixed_claim_packs);
        }
        if (self.nested_columns) |*columns| {
            try columns.appendTo(12, b);
            try columns.appendTo(11, b);
        }
    }
    pub fn appendEncoded(self: *const Prepared, b: anytype) !void {
        if (self.columns) |*columns| {
            if (self.encoded.len != 0 or self.fixed_encoded.len != 0) return error.InvalidExecutionPayload;
            try columns.appendTo(10, b);
        } else try b.append(10, self.encoded, self.fixed_encoded);
    }
    pub fn claimPackCount(self: *const Prepared) usize {
        return (if (self.columns) |*columns| columns.count(11) else self.claim_packs.len) + (if (self.nested_columns) |*columns| columns.count(11) else 0);
    }
    pub fn encodedCount(self: *const Prepared) usize {
        return if (self.columns) |*columns| columns.count(10) else self.encoded.len;
    }
    pub fn deinit(self: *Prepared) void {
        if (self.columns) |*columns| columns.deinit();
        if (self.nested_columns) |*columns| columns.deinit();
        self.samples.deinit();
        self.arena.deinit();
        self.* = undefined;
    }
};
pub fn prepare(a: std.mem.Allocator, composition: *const composition_mod.Prepared, transcript: *const transcript_mod.Planned, deep: *const deep_mod.Prepared, composition_circuit: u32, deep_circuit: u32, claim_circuit: u32) !Prepared {
    return prepareMode(true, a, composition, transcript, deep, composition_circuit, deep_circuit, claim_circuit);
}
/// Explicit dense row oracle for parity fixtures.
pub fn prepareRows(a: std.mem.Allocator, composition: *const composition_mod.Prepared, transcript: *const transcript_mod.Planned, deep: *const deep_mod.Prepared, composition_circuit: u32, deep_circuit: u32, claim_circuit: u32) !Prepared {
    return prepareMode(false, a, composition, transcript, deep, composition_circuit, deep_circuit, claim_circuit);
}
fn prepareMode(comptime direct: bool, a: std.mem.Allocator, composition: *const composition_mod.Prepared, transcript: *const transcript_mod.Planned, deep: *const deep_mod.Prepared, composition_circuit: u32, deep_circuit: u32, claim_circuit: u32) !Prepared {
    try transcript.plan.validate();
    if (claim_circuit == composition_circuit or claim_circuit == deep_circuit) return error.InvalidExecutionPayload;
    var samples = if (direct) try samples_mod.prepareColumns(a, composition, deep, composition_circuit, deep_circuit, 1) else try samples_mod.prepare(a, composition, deep, composition_circuit, deep_circuit, 1);
    errdefer samples.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const temp = arena.allocator();
    var scratch_arena = std.heap.ArenaAllocator.init(a);
    defer scratch_arena.deinit();
    const scratch = scratch_arena.allocator();
    var claim_nodes: std.ArrayList(u32) = .empty;
    var sample_nodes: std.ArrayList(u32) = .empty;
    for (composition.sources, 0..) |source, node| switch (source) {
        .claim => |index| {
            if (index != claim_nodes.items.len) return error.InvalidExecutionPayload;
            try claim_nodes.append(scratch, @intCast(node));
        },
        .sample => |index| {
            if (index != sample_nodes.items.len) return error.InvalidExecutionPayload;
            try sample_nodes.append(scratch, @intCast(node));
        },
        else => {},
    };
    const uses = try lower.computeUseCountsInto(composition.circuit.graph(), try scratch.alloc(u32, composition.circuit.nodes.len));
    const claim_words = try std.math.mul(usize, claim_nodes.items.len, 4);
    const count = try std.math.add(usize, claim_nodes.items.len, sample_nodes.items.len);
    var columns: ?Columns = null;
    errdefer if (columns) |*owned| owned.deinit();
    if (direct) columns = try Columns.init(a, .{ claim_words, claim_nodes.items.len, count });
    const claim_sources: []scalar.Row = if (direct) &.{} else try temp.alloc(scalar.Row, claim_words);
    const fixed_claim_sources: []scalar.Row = if (direct) &.{} else try temp.alloc(scalar.Row, claim_words);
    const claim_packs: []pack.Row = if (direct) &.{} else try temp.alloc(pack.Row, claim_nodes.items.len);
    const fixed_claim_packs: []pack.Row = if (direct) &.{} else try temp.alloc(pack.Row, claim_packs.len);
    for (claim_nodes.items, 0..) |node, claim| {
        const first: u32 = @intCast(claim * 4);
        const nodes: [4]u32 = .{ first, first + 1, first + 2, first + 3 };
        const value = composition.inputs[node];
        const weight = try std.math.add(u32, uses[node], 1);
        for (nodes, value.toM31Array(), 0..) |source, coordinate, word| {
            const row = try scalar.logicalRow(claim_circuit, source, weight, coordinate);
            if (direct) try columns.?.append(12, row) else {
                claim_sources[claim * 4 + word] = row;
                fixed_claim_sources[claim * 4 + word] = try scalar.logicalRow(claim_circuit, source, weight, M.zero());
            }
        }
        const schedule = pack.Schedule{ .source_circuit = claim_circuit, .source_nodes = nodes, .destination_circuit = composition_circuit, .destination_wire = node };
        const row = try pack.weightedLogicalRow(schedule, value, weight);
        if (direct) try columns.?.append(11, row) else {
            claim_packs[claim] = row;
            fixed_claim_packs[claim] = try pack.weightedFixedRow(schedule, weight);
        }
    }
    const encoded: []encoding.Row = if (direct) &.{} else try temp.alloc(encoding.Row, count);
    const fixed_encoded: []encoding.Row = if (direct) &.{} else try temp.alloc(encoding.Row, count);
    const seen = try scratch.alloc(bool, count);
    @memset(seen, false);
    for (transcript.plan.fixed.payload_reads) |receipt| {
        const is_claim = receipt.source.circuit == recorder.CLAIM_CIRCUIT;
        const is_sample = receipt.source.circuit == transcript_mod.SAMPLE_SOURCE.circuit;
        if (!is_claim and !is_sample) continue;
        for ([_]u32{ composition_circuit, deep_circuit, claim_circuit }) |id| if (id == receipt.source.circuit) return error.InvalidExecutionPayload;
        if (receipt.operation >= transcript.operations.len or transcript.operations[receipt.operation] != .routed_felts or receipt.source.first_wire % 4 != 0) return error.InvalidExecutionPayload;
        const payload = transcript.operations[receipt.operation].routed_felts;
        if (!std.meta.eql(payload.source, receipt.source) or receipt.uses.len != payload.values.len * 4) return error.InvalidExecutionPayload;
        const nodes = if (is_claim) claim_nodes.items else sample_nodes.items;
        const offset: usize = receipt.source.first_wire / 4;
        if (offset > nodes.len or payload.values.len > nodes.len - offset) return error.InvalidExecutionPayload;
        for (payload.values, 0..) |value, i| {
            const node = nodes[offset + i];
            const item = (if (is_claim) @as(usize, 0) else claim_nodes.items.len) + offset + i;
            if (seen[item] or !composition.inputs[node].eql(value)) return error.InvalidExecutionPayload;
            seen[item] = true;
            const schedule = encoding.Schedule{ .source_circuit = composition_circuit, .source_wire = node, .destination_circuit = receipt.source.circuit, .destination_first = try std.math.add(u32, receipt.source.first_wire, @intCast(4 * i)), .uses = receipt.uses[4 * i ..][0..4].* };
            const row = try encoding.logicalRow(schedule, value);
            if (direct) try columns.?.put(10, item, row) else {
                encoded[item] = row;
                fixed_encoded[item] = try encoding.fixedRow(schedule);
            }
        }
    }
    for (seen) |found| if (!found) return error.InvalidExecutionPayload;
    if (columns) |*owned| try owned.finish();
    return .{ .columns = columns, .arena = arena, .samples = samples, .claim_sources = claim_sources, .fixed_claim_sources = fixed_claim_sources, .claim_packs = claim_packs, .fixed_claim_packs = fixed_claim_packs, .encoded = encoded, .fixed_encoded = fixed_encoded };
}
