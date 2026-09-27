//! One scalar source shared by composition, transcript encoding and DEEP.
const std = @import("std");
const core = @import("stwo_core");
const claims = @import("../../air/transcript/claims.zig");
const vm = @import("../vm_air_composition_circuit.zig");
const payload = @import("blake3_native_payload_links.zig");
const native_deep = @import("blake3_native_deep.zig");
const links = @import("blake3_sample_links.zig");
const scalar = @import("scalar_wire_source.zig");
const lower = @import("verifier_arithmetic_lowering.zig");
const M31 = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
pub const Prepared = struct {
    arena: std.heap.ArenaAllocator,
    /// Replace payload's scalar rows with these; do not include both producers.
    sources: []scalar.Row,
    fixed_sources: []scalar.Row,
    destinations: []scalar.Row,
    fixed_destinations: []scalar.Row,
    pub fn deinit(self: *Prepared) void {
        self.arena.deinit();
        self.* = undefined;
    }
};
pub fn prepare(backing: std.mem.Allocator, composition: *const vm.Prepared, encoded: *const payload.Prepared, pcs: *const native_deep.Prepared, source_circuit: u32, deep_circuit: u32) !Prepared {
    try composition.validate();
    try pcs.graph.validateEvaluation(&pcs.evaluation);
    const count: usize = composition.circuit.input_profile.sampled_value_count;
    const total = count + claims.COMPONENT_COUNT;
    if (try pcs.graph.profile().sampleCount() != count or encoded.nodes.len != total or encoded.scalars.len != total * 4 or encoded.fixed_scalars.len != total * 4) return error.InvalidNativeSampleLink;
    var arena = std.heap.ArenaAllocator.init(backing);
    errdefer arena.deinit();
    const a = arena.allocator();
    const native_nodes = try a.alloc([4]u32, count);
    const missing = std.math.maxInt(u32);
    @memset(native_nodes, @splat(missing));
    for (composition.circuit.bindings) |binding| switch (binding.source) {
        .sampled_value => |coordinate| {
            if (coordinate.item_index >= count or coordinate.word_index >= 4 or native_nodes[coordinate.item_index][coordinate.word_index] != missing) return error.InvalidNativeSampleLink;
            native_nodes[coordinate.item_index][coordinate.word_index] = binding.node_id;
        },
        else => {},
    };
    for (native_nodes, 0..) |nodes, sample| {
        for (nodes) |node| if (node == missing) return error.InvalidNativeSampleLink;
        if (!std.meta.eql(nodes, encoded.nodes[claims.COMPONENT_COUNT + sample])) return error.InvalidNativeSampleLink;
    }
    const mapped = try links.build(a, &pcs.graph, count, 0);
    const use_counts = try lower.computeUseCountsInto(pcs.graph.graph(), try a.alloc(u32, pcs.graph.nodes.len));
    const vm_uses = try lower.computeUseCountsInto(composition.circuit.graph(), try a.alloc(u32, composition.circuit.nodes.len));
    const sources = try a.dupe(scalar.Row, encoded.scalars);
    const fixed_sources = try a.dupe(scalar.Row, encoded.fixed_scalars);
    const destinations = try a.alloc(scalar.Row, count * 4);
    const fixed_destinations = try a.alloc(scalar.Row, count * 4);
    for (mapped, 0..) |link, sample| {
        const item = claims.COMPONENT_COUNT + sample;
        for (encoded.nodes[item], link.deep, 0..) |vm_node, deep_node, word| {
            if (vm_node >= composition.circuit.nodes.len or composition.circuit.nodes[vm_node].op != .input) return error.InvalidNativeSampleLink;
            const value = pcs.evaluation.values[deep_node];
            const base = value.toM31Array()[0];
            if (!value.eql(Q.fromBase(base)) or !composition.evaluation.values[vm_node].eql(value)) return error.InvalidNativeSampleLink;
            const slot = item * 4 + word;
            const old_weight = try std.math.add(u32, vm_uses[vm_node], 1);
            const expected = try scalar.logicalRow(source_circuit, vm_node, old_weight, base);
            const expected_fixed = try scalar.logicalRow(source_circuit, vm_node, old_weight, M31.zero());
            if (!std.meta.eql(expected, sources[slot]) or !std.meta.eql(expected_fixed, fixed_sources[slot])) return error.InvalidNativeSampleLink;
            const weight = try std.math.add(u32, old_weight, 1);
            sources[slot] = try scalar.logicalRow(source_circuit, vm_node, weight, base);
            fixed_sources[slot] = try scalar.logicalRow(source_circuit, vm_node, weight, M31.zero());
            destinations[sample * 4 + word] = try scalar.routedRow(deep_circuit, deep_node, use_counts[deep_node], source_circuit, vm_node, base);
            fixed_destinations[sample * 4 + word] = try scalar.routedRow(deep_circuit, deep_node, use_counts[deep_node], source_circuit, vm_node, M31.zero());
        }
    }
    return .{ .arena = arena, .sources = sources, .fixed_sources = fixed_sources, .destinations = destinations, .fixed_destinations = fixed_destinations };
}
