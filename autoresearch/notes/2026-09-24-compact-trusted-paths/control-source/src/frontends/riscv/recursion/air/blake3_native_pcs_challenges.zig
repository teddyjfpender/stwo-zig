//! Role-indexed transcript challenge routing across native VM, DEEP and FRI.
const std = @import("std");
const core = @import("stwo_core");
const vm = @import("../vm_air_composition_circuit.zig");
const native = @import("blake3_native_transcript.zig");
const vm_links = @import("blake3_native_challenge_links.zig");
const deep_mod = @import("blake3_native_deep.zig");
const fri_mod = @import("blake3_native_fri.zig");
const t = @import("blake3_transcript_witness.zig");
const scalar = @import("scalar_wire_source.zig");
const lower = @import("verifier_arithmetic_lowering.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
pub const Prepared = struct {
    arena: std.heap.ArenaAllocator,
    /// Replaces the composition-only challenge routes, adding OODS fanout.
    composition: vm_links.Prepared,
    rows: []scalar.Row,
    fixed: []scalar.Row,
    pub fn deinit(self: *Prepared) void {
        self.arena.deinit();
        self.* = undefined;
    }
};
pub fn prepare(a: std.mem.Allocator, composition: *const vm.Prepared, transcript: *const native.Prepared, deep: *const deep_mod.Prepared, fri: *const fri_mod.Prepared, circuits: [3]u32) !Prepared {
    try transcript.plan.validate();
    try deep.graph.validateEvaluation(&deep.evaluation);
    try fri.evaluation.validateAgainst(&fri.graph);
    var composed = try vm_links.prepare(a, composition, transcript.live.draw_outputs, circuits[0]);
    for (circuits, 0..) |c, i| {
        if (c >= core.fields.m31.Modulus) return error.InvalidNativePcsChallenge;
        for (circuits[0..i]) |other| if (c == other) return error.InvalidNativePcsChallenge;
    }
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const temp = arena.allocator();
    const layers = fri.graph.profile().fold_widths.len;
    const count = 8 + 4 * layers;
    const sources = try temp.alloc(?t.Caller, count);
    @memset(sources, null);
    const values = try temp.alloc(M, count);
    @memset(values, M.zero());
    const outputs = transcript.live.draw_outputs;
    if (outputs.len != (vm_links.COUNT - 8) / 8 + 3 + layers) return error.InvalidNativePcsChallenge;
    for (outputs, 0..) |output, index| {
        const end = try std.math.add(usize, output.source.first_wire, output.words);
        if (end > core.fields.m31.Modulus or output.source.circuit >= core.fields.m31.Modulus) return error.InvalidNativePcsChallenge;
        for (outputs[0..index]) |previous| {
            if (previous.source.circuit == output.source.circuit and output.source.first_wire < @as(usize, previous.source.first_wire) + previous.words and previous.source.first_wire < end) return error.InvalidNativePcsChallenge;
        }
        if (output.operation >= transcript.operations.len or transcript.operations[output.operation] != .secure) return error.InvalidNativePcsChallenge;
        const draw = transcript.operations[output.operation].secure;
        if (draw.output == null or !std.meta.eql(draw.output.?, output.role) or draw.consumption.words() != output.words) return error.InvalidNativePcsChallenge;
        const start: usize = switch (output.role) {
            .oods => 0,
            .deep => 4,
            .fri => |layer| if (layer < layers) 8 + layer * 4 else return error.InvalidNativePcsChallenge,
            .riscv_relation, .composition => continue,
            .universal => return error.InvalidNativePcsChallenge,
        };
        if (output.words != 4) return error.InvalidNativePcsChallenge;
        for (0..4) |word| {
            if (sources[start + word] != null) return error.InvalidNativePcsChallenge;
            sources[start + word] = .{ .circuit = output.source.circuit, .first_wire = try std.math.add(u32, output.source.first_wire, @intCast(word)) };
            values[start + word] = draw.values[word];
        }
    }
    const nodes = try temp.alloc(u32, count);
    const missing = std.math.maxInt(u32);
    @memset(nodes, missing);
    for (deep.graph.bindings) |binding| switch (binding.source) {
        .oods_seed_word => |word| try assign(nodes, word, binding.node_id),
        .deep_randomness_word => |word| {
            if (word >= 4) return error.InvalidNativePcsChallenge;
            try assign(nodes, 4 + word, binding.node_id);
        },
        else => {},
    };
    for (fri.graph.bindings) |binding| switch (binding.source) {
        .fri_alpha_word => |c| {
            if (c.layer >= layers or c.word >= 4) return error.InvalidNativePcsChallenge;
            try assign(nodes, 8 + c.layer * 4 + c.word, binding.node_id);
        },
        else => {},
    };
    const deep_uses = try lower.computeUseCountsInto(deep.graph.graph(), try temp.alloc(u32, deep.graph.nodes.len));
    const fri_uses = try lower.computeUseCountsInto(fri.graph.graph(), try temp.alloc(u32, fri.graph.nodes.len));
    const rows = try temp.alloc(scalar.Row, count);
    const fixed = try temp.alloc(scalar.Row, count);
    for (nodes, sources, values, rows, fixed, 0..) |node, source_optional, value, *row, *fixed_row, i| {
        var source = source_optional orelse return error.InvalidNativePcsChallenge;
        if (node == missing) return error.InvalidNativePcsChallenge;
        const evaluation = if (i < 8) deep.evaluation.values else fri.evaluation.values;
        const uses = if (i < 8) deep_uses else fri_uses;
        if (node >= evaluation.len or !evaluation[node].eql(Q.fromBase(value))) return error.InvalidNativePcsChallenge;
        if (i < 4) {
            const slot = vm_links.COUNT - 4 + i;
            if (!std.meta.eql(source, composed.links[slot].source) or !composed.rows[slot][0].eql(value)) return error.InvalidNativePcsChallenge;
            const weight = try std.math.add(u32, composed.rows[slot][3].v, 1);
            if (weight >= core.fields.m31.Modulus) return error.InvalidNativePcsChallenge;
            composed.rows[slot][3] = M.fromCanonical(weight);
            composed.fixed[slot][3] = M.fromCanonical(weight);
            source = .{ .circuit = circuits[0], .first_wire = composed.links[slot].node };
        }
        const destination = circuits[if (i < 8) @as(usize, 1) else 2];
        row.* = try scalar.routedRow(destination, node, uses[node], source.circuit, source.first_wire, value);
        fixed_row.* = try scalar.routedRow(destination, node, uses[node], source.circuit, source.first_wire, M.zero());
    }
    return .{ .arena = arena, .composition = composed, .rows = rows, .fixed = fixed };
}
fn assign(nodes: []u32, index: usize, node: u32) !void {
    if (index >= nodes.len or nodes[index] != std.math.maxInt(u32)) return error.InvalidNativePcsChallenge;
    nodes[index] = node;
}
