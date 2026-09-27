//! Native V2 scalar challenge routing; no fixture universal-relation aliases.
const std = @import("std");
const core = @import("stwo_core");
const vm = @import("../vm_air_composition_circuit.zig");
const graph = @import("composition_circuit.zig");
const relations = @import("../../air/relation_challenges.zig");
const t = @import("blake3_transcript_witness.zig");
const scalar = @import("scalar_wire_source.zig");
const lower = @import("verifier_arithmetic_lowering.zig");
const M31 = core.fields.m31.M31;
const relation_words = relations.RELATION_COUNT * 8;
pub const COUNT = relation_words + 8;
pub const Link = struct { source: t.Caller, node: u32 };
pub const Prepared = struct {
    links: [COUNT]Link,
    rows: [COUNT]scalar.Row,
    fixed: [COUNT]scalar.Row,
};

/// Pure schedule join. The authenticated circuit owns input shape and node IDs.
pub fn schedule(circuit: *const vm.Circuit, outputs: []const t.DrawOutput) ![COUNT]Link {
    try circuit.validate();
    if (circuit.input_profile.relation_challenge_count != relations.RELATION_COUNT)
        return error.InvalidNativeChallengeLink;
    var sources: [COUNT]?t.Caller = @splat(null);
    for (outputs) |output| {
        const start: usize = switch (output.role) {
            .riscv_relation => |i| blk: {
                if (i >= relations.RELATION_COUNT or output.words != 8) return error.InvalidNativeChallengeLink;
                break :blk i * 8;
            },
            .composition => relation_words,
            .oods => relation_words + 4,
            .universal => return error.InvalidNativeChallengeLink,
            .deep, .fri => continue,
        };
        if (output.role != .riscv_relation and output.words != 4) return error.InvalidNativeChallengeLink;
        if (output.source.circuit >= core.fields.m31.Modulus) return error.InvalidNativeChallengeLink;
        for (0..output.words) |i| {
            const wire = try std.math.add(u32, output.source.first_wire, @intCast(i));
            if (wire >= core.fields.m31.Modulus or sources[start + i] != null) return error.InvalidNativeChallengeLink;
            const source = t.Caller{ .circuit = output.source.circuit, .first_wire = wire };
            for (sources) |existing| if (existing) |other| {
                if (std.meta.eql(source, other)) return error.InvalidNativeChallengeLink;
            };
            sources[start + i] = source;
        }
    }
    var nodes: [COUNT]?u32 = @splat(null);
    for (circuit.bindings) |binding| {
        const slot = try coordinate(binding.source) orelse continue;
        if (nodes[slot] != null or binding.node_id >= circuit.nodes.len or circuit.nodes[binding.node_id].op != .input) return error.InvalidNativeChallengeLink;
        nodes[slot] = binding.node_id;
    }
    var result: [COUNT]Link = undefined;
    for (&result, sources, nodes) |*link, source, node|
        link.* = .{ .source = source orelse return error.InvalidNativeChallengeLink, .node = node orelse return error.InvalidNativeChallengeLink };
    return result;
}

/// Rows consume each exported transcript scalar once. Their emission weight is
/// exactly the shared arithmetic graph's number of consumers of that input.
/// Include these rows with the transcript and arithmetic AIRs in the parent.
pub fn prepare(a: std.mem.Allocator, composition: *const vm.Prepared, outputs: []const t.DrawOutput, destination_circuit: u32) !Prepared {
    try composition.validate();
    var result: Prepared = undefined;
    result.links = try schedule(&composition.circuit, outputs);
    const scratch = try a.alloc(u32, composition.circuit.nodes.len);
    defer a.free(scratch);
    const uses = try lower.computeUseCountsInto(composition.circuit.graph(), scratch);
    for (result.links, &result.rows, &result.fixed) |link, *row, *fixed| {
        const value = composition.evaluation.values[link.node];
        const words = value.toM31Array();
        if (!value.eql(core.fields.qm31.QM31.fromBase(words[0]))) return error.InvalidNativeChallengeLink;
        row.* = try scalar.routedRow(destination_circuit, link.node, uses[link.node], link.source.circuit, link.source.first_wire, words[0]);
        fixed.* = try scalar.routedRow(destination_circuit, link.node, uses[link.node], link.source.circuit, link.source.first_wire, M31.zero());
    }
    return result;
}
fn coordinate(source: graph.VmSource) !?usize {
    return switch (source) {
        .relation_challenge => |c| blk: {
            if (c.challenge >= relations.RELATION_COUNT or c.word_index >= 8) return error.InvalidNativeChallengeLink;
            break :blk @as(usize, c.challenge) * 8 + c.word_index;
        },
        .composition_randomness => |i| if (i < 4) relation_words + @as(usize, i) else error.InvalidNativeChallengeLink,
        .oods_point => |i| if (i < 4) relation_words + 4 + @as(usize, i) else error.InvalidNativeChallengeLink,
        else => null,
    };
}
