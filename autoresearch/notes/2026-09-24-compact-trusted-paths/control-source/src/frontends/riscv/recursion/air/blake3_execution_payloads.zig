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
pub const Prepared = struct {
    arena: std.heap.ArenaAllocator,
    samples: samples_mod.Prepared,
    claim_sources: []scalar.Row,
    fixed_claim_sources: []scalar.Row,
    claim_packs: []pack.Row,
    fixed_claim_packs: []pack.Row,
    encoded: []encoding.Row,
    fixed_encoded: []encoding.Row,
    pub fn deinit(self: *Prepared) void {
        self.samples.deinit();
        self.arena.deinit();
        self.* = undefined;
    }
};
pub fn prepare(a: std.mem.Allocator, composition: *const composition_mod.Prepared, transcript: *const transcript_mod.Planned, deep: *const deep_mod.Prepared, composition_circuit: u32, deep_circuit: u32, claim_circuit: u32) !Prepared {
    try transcript.plan.validate();
    if (claim_circuit == composition_circuit or claim_circuit == deep_circuit) return error.InvalidExecutionPayload;
    var samples = try samples_mod.prepare(a, composition, deep, composition_circuit, deep_circuit, 1);
    errdefer samples.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const temp = arena.allocator();
    var claim_nodes: std.ArrayList(u32) = .empty;
    var sample_nodes: std.ArrayList(u32) = .empty;
    for (composition.sources, 0..) |source, node| switch (source) {
        .claim => |index| {
            if (index != claim_nodes.items.len) return error.InvalidExecutionPayload;
            try claim_nodes.append(temp, @intCast(node));
        },
        .sample => |index| {
            if (index != sample_nodes.items.len) return error.InvalidExecutionPayload;
            try sample_nodes.append(temp, @intCast(node));
        },
        else => {},
    };
    const uses = try lower.computeUseCountsInto(composition.circuit.graph(), try temp.alloc(u32, composition.circuit.nodes.len));
    const claim_sources = try temp.alloc(scalar.Row, claim_nodes.items.len * 4);
    const fixed_claim_sources = try temp.alloc(scalar.Row, claim_sources.len);
    const claim_packs = try temp.alloc(pack.Row, claim_nodes.items.len);
    const fixed_claim_packs = try temp.alloc(pack.Row, claim_packs.len);
    for (claim_nodes.items, 0..) |node, claim| {
        const first: u32 = @intCast(claim * 4);
        const nodes: [4]u32 = .{ first, first + 1, first + 2, first + 3 };
        const value = composition.inputs[node];
        const weight = try std.math.add(u32, uses[node], 1);
        for (nodes, value.toM31Array(), 0..) |source, coordinate, word| {
            claim_sources[claim * 4 + word] = try scalar.logicalRow(claim_circuit, source, weight, coordinate);
            fixed_claim_sources[claim * 4 + word] = try scalar.logicalRow(claim_circuit, source, weight, M.zero());
        }
        const schedule = pack.Schedule{ .source_circuit = claim_circuit, .source_nodes = nodes, .destination_circuit = composition_circuit, .destination_wire = node };
        claim_packs[claim] = try pack.weightedLogicalRow(schedule, value, weight);
        fixed_claim_packs[claim] = try pack.weightedFixedRow(schedule, weight);
    }
    const count = claim_nodes.items.len + sample_nodes.items.len;
    const encoded = try temp.alloc(encoding.Row, count);
    const fixed_encoded = try temp.alloc(encoding.Row, count);
    const seen = try temp.alloc(bool, count);
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
            encoded[item] = try encoding.logicalRow(schedule, value);
            fixed_encoded[item] = try encoding.fixedRow(schedule);
        }
    }
    for (seen) |found| if (!found) return error.InvalidExecutionPayload;
    return .{ .arena = arena, .samples = samples, .claim_sources = claim_sources, .fixed_claim_sources = fixed_claim_sources, .claim_packs = claim_packs, .fixed_claim_packs = fixed_claim_packs, .encoded = encoded, .fixed_encoded = fixed_encoded };
}
