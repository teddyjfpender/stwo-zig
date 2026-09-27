//! One DEEP scalar source per sample coordinate feeds both DEEP arithmetic and
//! secure composition inputs. The parent must bind these sources to the
//! transcript encoding; these rows alone do not authenticate sampled values.
//! encoding_uses adds explicit secure consumers such as field-byte encoding.
const std = @import("std");
const core = @import("stwo_core");
const composition_mod = @import("blake3_execution_composition.zig");
const deep_mod = @import("blake3_native_deep.zig");
const sample_links = @import("blake3_sample_links.zig");
const lower = @import("verifier_arithmetic_lowering.zig");
const pack = @import("qm31_pack_wire.zig");
const scalar = @import("scalar_wire_source.zig");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
pub const Prepared = struct {
    arena: std.heap.ArenaAllocator,
    packs: []pack.Row,
    fixed_packs: []pack.Row,
    /// Replace the DEEP sample-input producer rows, not additional producers.
    sources: []scalar.Row,
    fixed_sources: []scalar.Row,
    pub fn deinit(self: *Prepared) void {
        self.arena.deinit();
        self.* = undefined;
    }
};
pub fn prepare(a: std.mem.Allocator, composition: *const composition_mod.Prepared, deep: *const deep_mod.Prepared, composition_circuit: u32, deep_circuit: u32, encoding_uses: u32) !Prepared {
    try composition.circuit.validate();
    try deep.graph.validateEvaluation(&deep.evaluation);
    if (composition.sources.len != composition.circuit.input_count or composition.inputs.len != composition.sources.len) return error.InvalidExecutionSampleLink;
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const temp = arena.allocator();
    const count = try deep.graph.profile().sampleCount();
    const mapped = try sample_links.build(temp, &deep.graph, count, 0);
    const composition_uses = try lower.computeUseCountsInto(composition.circuit.graph(), try temp.alloc(u32, composition.circuit.nodes.len));
    const deep_uses = try lower.computeUseCountsInto(deep.graph.graph(), try temp.alloc(u32, deep.graph.nodes.len));
    const sources = try temp.alloc(scalar.Row, count * 4);
    const fixed_sources = try temp.alloc(scalar.Row, count * 4);
    var packs: std.ArrayList(pack.Row) = .empty;
    var fixed_packs: std.ArrayList(pack.Row) = .empty;
    const seen = try temp.alloc(bool, count);
    @memset(seen, false);
    for (composition.sources, 0..) |source, node| switch (source) {
        .sample => |sample| {
            if (sample >= count or seen[sample]) return error.InvalidExecutionSampleLink;
            seen[sample] = true;
            const nodes = mapped[sample].deep;
            const value = composition.inputs[node];
            const weight = try std.math.add(u32, composition_uses[node], encoding_uses);
            for (nodes, value.toM31Array(), 0..) |deep_node, coordinate, word| {
                if (!deep.evaluation.values[deep_node].eql(Q.fromBase(coordinate))) return error.InvalidExecutionSampleLink;
                const uses = try std.math.add(u32, deep_uses[deep_node], weight);
                sources[sample * 4 + word] = try scalar.logicalRow(deep_circuit, deep_node, uses, coordinate);
                fixed_sources[sample * 4 + word] = try scalar.logicalRow(deep_circuit, deep_node, uses, M.zero());
            }
            // Unused composition samples still feed DEEP, but need no pack row.
            if (weight != 0) {
                const schedule = pack.Schedule{ .source_circuit = deep_circuit, .source_nodes = nodes, .destination_circuit = composition_circuit, .destination_wire = @intCast(node) };
                try packs.append(temp, try pack.weightedLogicalRow(schedule, value, weight));
                try fixed_packs.append(temp, try pack.weightedFixedRow(schedule, weight));
            }
        },
        else => {},
    };
    for (seen) |found| if (!found) return error.InvalidExecutionSampleLink;
    return .{ .arena = arena, .packs = packs.items, .fixed_packs = fixed_packs.items, .sources = sources, .fixed_sources = fixed_sources };
}
