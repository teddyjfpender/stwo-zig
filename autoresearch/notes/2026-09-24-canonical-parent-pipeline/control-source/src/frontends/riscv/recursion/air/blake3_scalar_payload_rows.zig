//! Shared scalar producer / QM31 pack / canonical byte encoding row construction.
const std = @import("std");
const core = @import("stwo_core");
const scalar = @import("scalar_wire_source.zig");
const pack = @import("qm31_pack_wire.zig");
const encoding = @import("blake3_field_bytes.zig");
const t = @import("blake3_transcript_witness.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
pub const Rows = struct {
    scalars: [4]scalar.Row,
    fixed_scalars: [4]scalar.Row,
    packing: pack.Row,
    fixed_packing: pack.Row,
    encoded: encoding.Row,
    fixed_encoded: encoding.Row,
};
pub fn build(nodes: [4]u32, evaluations: []const Q, use_counts: []const u32, circuit: u32, packed_source: t.Caller, destination: t.Caller, reads: [4]u32, value: Q) !Rows {
    var result: Rows = undefined;
    for (nodes, value.toM31Array(), 0..) |node, coordinate, word| {
        if (node >= evaluations.len or node >= use_counts.len or !evaluations[node].eql(Q.fromBase(coordinate))) return error.InvalidScalarPayload;
        const weight = try std.math.add(u32, use_counts[node], 1);
        result.scalars[word] = try scalar.logicalRow(circuit, node, weight, coordinate);
        result.fixed_scalars[word] = try scalar.logicalRow(circuit, node, weight, M.zero());
    }
    const packing = pack.Schedule{ .source_circuit = circuit, .source_nodes = nodes, .destination_circuit = packed_source.circuit, .destination_wire = packed_source.first_wire };
    result.packing = try pack.logicalRow(packing, value);
    result.fixed_packing = try pack.fixedRow(packing);
    const bytes = encoding.Schedule{ .source_circuit = packed_source.circuit, .source_wire = packed_source.first_wire, .destination_circuit = destination.circuit, .destination_first = destination.first_wire, .uses = reads };
    result.encoded = try encoding.logicalRow(bytes, value);
    result.fixed_encoded = try encoding.fixedRow(bytes);
    return result;
}
