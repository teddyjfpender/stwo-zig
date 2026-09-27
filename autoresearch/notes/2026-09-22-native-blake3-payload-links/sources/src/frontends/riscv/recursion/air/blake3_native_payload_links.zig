//! Scalar native composition inputs -> QM31 packing -> transcript felt bytes.
const std = @import("std");
const core = @import("stwo_core");
const vm = @import("../vm_air_composition_circuit.zig");
const native = @import("blake3_native_transcript.zig");
const recorder = @import("blake3_native_recorder.zig");
const claims = @import("../../air/transcript/claims.zig");
const scalar = @import("scalar_wire_source.zig");
const pack = @import("qm31_pack_wire.zig");
const encoding = @import("blake3_field_bytes.zig");
const lower = @import("verifier_arithmetic_lowering.zig");
const M31 = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
pub const PACK_CIRCUIT: u32 = 5_000_010;
pub const Prepared = struct {
    arena: std.heap.ArenaAllocator,
    nodes: [][4]u32,
    scalars: []scalar.Row,
    fixed_scalars: []scalar.Row,
    packing: []pack.Row,
    fixed_packing: []pack.Row,
    encoded: []encoding.Row,
    fixed_encoded: []encoding.Row,
    pub fn deinit(self: *Prepared) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

/// Returned rows must be included with the native arithmetic and transcript AIRs.
/// Other consumers of sampled values require explicit additional fanout counts.
pub fn prepare(backing: std.mem.Allocator, composition: *const vm.Prepared, transcript: *const native.Prepared, circuit: u32) !Prepared {
    try composition.validate();
    try transcript.plan.validate();
    if (circuit == PACK_CIRCUIT or composition.circuit.input_profile.transcript_claimed_sum_count != claims.COMPONENT_COUNT) return error.InvalidNativePayloadLink;
    const samples: usize = composition.circuit.input_profile.sampled_value_count;
    const count = try std.math.add(usize, samples, claims.COMPONENT_COUNT);
    var arena = std.heap.ArenaAllocator.init(backing);
    errdefer arena.deinit();
    const a = arena.allocator();
    const nodes = try a.alloc([4]u32, count);
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
    const uses = try lower.computeUseCountsInto(composition.circuit.graph(), try a.alloc(u32, composition.circuit.nodes.len));
    const result = Prepared{
        .arena = undefined,
        .nodes = nodes,
        .scalars = try a.alloc(scalar.Row, count * 4),
        .fixed_scalars = try a.alloc(scalar.Row, count * 4),
        .packing = try a.alloc(pack.Row, count),
        .fixed_packing = try a.alloc(pack.Row, count),
        .encoded = try a.alloc(encoding.Row, count),
        .fixed_encoded = try a.alloc(encoding.Row, count),
    };
    const seen = try a.alloc(bool, count);
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
            for (nodes[item], value.toM31Array(), 0..) |node, word, j| {
                if (!composition.evaluation.values[node].eql(Q.fromBase(word))) return error.InvalidNativePayloadLink;
                const weight = try std.math.add(u32, uses[node], 1);
                result.scalars[item * 4 + j] = try scalar.logicalRow(circuit, node, weight, word);
                result.fixed_scalars[item * 4 + j] = try scalar.logicalRow(circuit, node, weight, M31.zero());
            }
            const packing = pack.Schedule{ .source_circuit = circuit, .source_nodes = nodes[item], .destination_circuit = PACK_CIRCUIT, .destination_wire = @intCast(item) };
            result.packing[item] = try pack.logicalRow(packing, value);
            result.fixed_packing[item] = try pack.fixedRow(packing);
            const bytes = encoding.Schedule{ .source_circuit = PACK_CIRCUIT, .source_wire = @intCast(item), .destination_circuit = receipt.source.circuit, .destination_first = try std.math.add(u32, receipt.source.first_wire, @intCast(i * 4)), .uses = receipt.uses[i * 4 ..][0..4].* };
            result.encoded[item] = try encoding.logicalRow(bytes, value);
            result.fixed_encoded[item] = try encoding.fixedRow(bytes);
        }
    }
    for (seen) |present| if (!present) return error.InvalidNativePayloadLink;
    var owned = result;
    owned.arena = arena;
    return owned;
}
