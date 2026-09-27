//! Shared public relation draws and exact native LogUp aggregate cancellation.
const std = @import("std");
const core = @import("stwo_core");
const vm = @import("../vm_air_composition_circuit.zig");
const boundary_mod = @import("blake3_native_public_boundary.zig");
const challenges_mod = @import("blake3_native_pcs_challenges.zig");
const vm_links = @import("blake3_native_challenge_links.zig");
const payload_mod = @import("blake3_native_payload_links.zig");
const claims = @import("../../air/transcript/claims.zig");
const scalar = @import("scalar_wire_source.zig");
const arithmetic = @import("../arithmetic_circuit.zig");
const authority = @import("../segment_public_native_sum_authority_v2.zig");
const lower = @import("verifier_arithmetic_lowering.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const CLAIM_WORDS = claims.COMPONENT_COUNT * 4;
pub const TOTAL_INPUTS = CLAIM_WORDS + 4;
pub const BOUNDARY_CIRCUIT: u32 = 1506;
pub const TOTAL_CIRCUIT: u32 = 1508;
pub const Prepared = struct {
    /// Replaces PCS composition challenge rows; OODS sharing is preserved.
    composition: vm_links.Prepared,
    challenge_rows: [32]scalar.Row,
    fixed_challenges: [32]scalar.Row,
    /// Replaces the aggregate-claim prefix of payload scalar producers.
    claim_sources: [CLAIM_WORDS]scalar.Row,
    fixed_claims: [CLAIM_WORDS]scalar.Row,
    total_sources: [4]scalar.Row,
    fixed_total_sources: [4]scalar.Row,
    destinations: [TOTAL_INPUTS]scalar.Row,
    fixed_destinations: [TOTAL_INPUTS]scalar.Row,
    circuit: arithmetic.Circuit,
    graph: authority.NativeOwnedGraph,
    evaluation: arithmetic.Evaluation,
    inputs: [TOTAL_INPUTS]Q,
    pub fn deinit(self: *Prepared) void {
        self.evaluation.deinit();
        self.graph.deinit();
        self.circuit.deinit();
        self.* = undefined;
    }
    pub fn evaluate(self: *const Prepared, a: std.mem.Allocator, inputs: []const Q) !arithmetic.Evaluation {
        return checked(a, &self.circuit, inputs);
    }
};
pub fn prepare(a: std.mem.Allocator, composition: *const vm.Prepared, boundary: *const boundary_mod.Prepared, challenges: *const challenges_mod.Prepared, payloads: *const payload_mod.Prepared) !Prepared {
    try composition.validate();
    try boundary.validate(a);
    const missing = std.math.maxInt(u32);
    var vm_challenges: [32]u32 = @splat(missing);
    for (composition.circuit.bindings) |binding| switch (binding.source) {
        .relation_challenge => |c| {
            if (c.challenge >= 4) continue;
            if (c.word_index >= 8) return error.InvalidNativePublicLink;
            const slot = c.challenge * 8 + c.word_index;
            if (vm_challenges[slot] != missing) return error.InvalidNativePublicLink;
            vm_challenges[slot] = binding.node_id;
        },
        else => {},
    };
    for (vm_challenges) |node| if (node == missing) return error.InvalidNativePublicLink;
    var public_challenges: [32]u32 = @splat(missing);
    var public_total: [4]u32 = @splat(missing);
    for (boundary.bindings, boundary.circuit.inputNodes()) |binding, node| switch (binding) {
        .native_challenge_word => |c| {
            const slot = @as(usize, @intFromEnum(c.relation)) * 8 + c.limb;
            if (slot >= public_challenges.len or public_challenges[slot] != missing) return error.InvalidNativePublicLink;
            public_challenges[slot] = node;
        },
        .published_total_word => |c| {
            if (public_total[c.limb] != missing) return error.InvalidNativePublicLink;
            public_total[c.limb] = node;
        },
        else => {},
    };
    for (public_challenges) |node| if (node == missing) return error.InvalidNativePublicLink;
    for (public_total) |node| if (node == missing) return error.InvalidNativePublicLink;
    var claim_nodes: [claims.COMPONENT_COUNT][4]u32 = @splat(@splat(missing));
    for (composition.circuit.bindings) |binding| switch (binding.source) {
        .transcript_claimed_sum => |c| {
            if (c.item_index >= claim_nodes.len or c.word_index >= 4 or claim_nodes[c.item_index][c.word_index] != missing) return error.InvalidNativePublicLink;
            claim_nodes[c.item_index][c.word_index] = binding.node_id;
        },
        else => {},
    };
    if (payloads.nodes.len < claim_nodes.len or payloads.scalars.len < CLAIM_WORDS) return error.InvalidNativePublicLink;
    const scratch = try a.alloc(u32, composition.circuit.nodes.len);
    defer a.free(scratch);
    const vm_uses = try lower.computeUseCountsInto(composition.circuit.graph(), scratch);
    const public_uses = boundary.circuit.useCounts();
    var out: Prepared = undefined;
    out.composition = challenges.composition;
    for (public_challenges, 0..) |node, i| {
        const source = out.composition.links[i].node;
        if (source != vm_challenges[i] or source >= composition.evaluation.values.len or !composition.evaluation.values[source].eql(boundary.evaluation.values[node])) return error.InvalidNativePublicLink;
        const value = try base(boundary.evaluation.values[node]);
        const old = try scalar.routedRow(1500, source, vm_uses[source], out.composition.links[i].source.circuit, out.composition.links[i].source.first_wire, value);
        if (!std.meta.eql(old, out.composition.rows[i])) return error.InvalidNativePublicLink;
        const weight = try std.math.add(u32, vm_uses[source], 1);
        out.composition.rows[i] = try scalar.routedRow(1500, source, weight, out.composition.links[i].source.circuit, out.composition.links[i].source.first_wire, value);
        out.composition.fixed[i] = try scalar.routedRow(1500, source, weight, out.composition.links[i].source.circuit, out.composition.links[i].source.first_wire, M.zero());
        out.challenge_rows[i] = try scalar.routedRow(BOUNDARY_CIRCUIT, node, public_uses[node], 1500, source, value);
        out.fixed_challenges[i] = try scalar.routedRow(BOUNDARY_CIRCUIT, node, public_uses[node], 1500, source, M.zero());
    }
    for (claim_nodes, 0..) |nodes, claim| {
        if (!std.meta.eql(nodes, payloads.nodes[claim])) return error.InvalidNativePublicLink;
        for (nodes, 0..) |node, word| {
            if (node == missing) return error.InvalidNativePublicLink;
            const i = claim * 4 + word;
            const value = try base(composition.evaluation.values[node]);
            const old_weight = try std.math.add(u32, vm_uses[node], 1);
            if (!std.meta.eql(try scalar.logicalRow(1500, node, old_weight, value), payloads.scalars[i])) return error.InvalidNativePublicLink;
            out.claim_sources[i] = try scalar.logicalRow(1500, node, try std.math.add(u32, old_weight, 1), value);
            out.fixed_claims[i] = try scalar.logicalRow(1500, node, try std.math.add(u32, old_weight, 1), M.zero());
            out.inputs[i] = Q.fromBase(value);
            out.destinations[i] = try scalar.routedRow(TOTAL_CIRCUIT, @intCast(i), 1, 1500, node, value);
            out.fixed_destinations[i] = try scalar.routedRow(TOTAL_CIRCUIT, @intCast(i), 1, 1500, node, M.zero());
        }
    }
    for (public_total, 0..) |node, word| {
        const value = try base(boundary.evaluation.values[node]);
        const uses = try std.math.add(u32, public_uses[node], 1);
        out.total_sources[word] = try scalar.logicalRow(BOUNDARY_CIRCUIT, node, uses, value);
        out.fixed_total_sources[word] = try scalar.logicalRow(BOUNDARY_CIRCUIT, node, uses, M.zero());
        const i = CLAIM_WORDS + word;
        out.inputs[i] = Q.fromBase(value);
        out.destinations[i] = try scalar.routedRow(TOTAL_CIRCUIT, @intCast(i), 1, BOUNDARY_CIRCUIT, node, value);
        out.fixed_destinations[i] = try scalar.routedRow(TOTAL_CIRCUIT, @intCast(i), 1, BOUNDARY_CIRCUIT, node, M.zero());
    }
    var builder = arithmetic.Builder.initDefault(a);
    defer builder.deinit();
    var inputs: [TOTAL_INPUTS]arithmetic.Value = undefined;
    for (&inputs, 0..) |*input, i| input.* = try builder.input(@intCast(i));
    for (0..4) |word| {
        var sum = inputs[CLAIM_WORDS + word];
        for (0..claims.COMPONENT_COUNT) |claim| sum = try builder.add(sum, inputs[claim * 4 + word]);
        _ = try builder.markOutput(sum);
    }
    out.circuit = try builder.finish();
    errdefer out.circuit.deinit();
    out.graph = try authority.NativeOwnedGraph.init(a, &out.circuit);
    errdefer out.graph.deinit();
    out.evaluation = try checked(a, &out.circuit, &out.inputs);
    return out;
}
fn base(value: Q) !M {
    const word = value.toM31Array()[0];
    if (!value.eql(Q.fromBase(word))) return error.InvalidNativePublicLink;
    return word;
}
fn checked(a: std.mem.Allocator, circuit: *const arithmetic.Circuit, inputs: []const Q) !arithmetic.Evaluation {
    try circuit.validate();
    var result = try circuit.evaluate(a, inputs);
    errdefer result.deinit();
    if (!try circuit.outputsAreZero(result.values)) return error.InvalidNativePublicLink;
    return result;
}
