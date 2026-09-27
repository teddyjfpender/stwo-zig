//! Transcript-exported scalar challenges feed secure composition and scalar
//! DEEP/FRI inputs. Each export is consumed once before explicit fanout.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const composition_mod = @import("blake3_execution_composition.zig");
const transcript_mod = @import("blake3_native_transcript.zig");
const deep_mod = @import("blake3_native_deep.zig");
const fri_mod = @import("blake3_native_fri.zig");
const links_mod = @import("blake3_challenge_links.zig");
const lower = @import("verifier_arithmetic_lowering.zig");
const scalar = @import("scalar_wire_source.zig");
const pack = @import("qm31_pack_wire.zig");
const universal = @import("universal_challenges.zig");
pub const Prepared = struct {
    arena: std.heap.ArenaAllocator,
    rows: []scalar.Row,
    fixed: []scalar.Row,
    packs: []pack.Row,
    fixed_packs: []pack.Row,
    pub fn deinit(self: *Prepared) void {
        self.arena.deinit();
        self.* = undefined;
    }
};
pub fn prepare(a: std.mem.Allocator, composition: *const composition_mod.Prepared, transcript: *const transcript_mod.Planned, deep: *const deep_mod.Prepared, fri: *const fri_mod.Prepared, circuits: [3]u32, bridge: u32) !Prepared {
    return prepareForRelations(universal.RELATION_COUNT, a, composition, transcript, deep, fri, circuits, bridge);
}
pub fn prepareEthereum(a: std.mem.Allocator, composition: *const composition_mod.Prepared, transcript: *const transcript_mod.Planned, deep: *const deep_mod.Prepared, fri: *const fri_mod.Prepared, circuits: [3]u32, bridge: u32) !Prepared {
    return prepareForRelations(universal.RELATION_COUNT + 13, a, composition, transcript, deep, fri, circuits, bridge);
}
fn prepareForRelations(comptime relation_count: usize, a: std.mem.Allocator, composition: *const composition_mod.Prepared, transcript: *const transcript_mod.Planned, deep: *const deep_mod.Prepared, fri: *const fri_mod.Prepared, circuits: [3]u32, bridge: u32) !Prepared {
    try composition.circuit.validate();
    try transcript.plan.validate();
    try deep.graph.validateEvaluation(&deep.evaluation);
    try fri.evaluation.validateAgainst(&fri.graph);
    const ids = circuits ++ .{bridge};
    for (ids, 0..) |id, i| {
        if (id >= core.fields.m31.Modulus) return error.InvalidExecutionChallenge;
        for (ids[0..i]) |other| if (other == id) return error.InvalidExecutionChallenge;
    }
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const temp = arena.allocator();
    const missing = std.math.maxInt(u32);
    var sources = links_mod.Sources{ .sample_start = 0, .claim_start = 0, .composition = missing, .oods = missing, .universal_start = missing };
    var challenge_count: usize = 0;
    for (composition.sources, 0..) |source, node| switch (source) {
        .challenge => |index| {
            if (index != challenge_count) return error.InvalidExecutionChallenge;
            if (index == 0) sources.universal_start = @intCast(node);
            if (node != sources.universal_start + index) return error.InvalidExecutionChallenge;
            challenge_count += 1;
        },
        .composition => {
            if (sources.composition != missing) return error.InvalidExecutionChallenge;
            sources.composition = @intCast(node);
        },
        .oods => {
            if (sources.oods != missing) return error.InvalidExecutionChallenge;
            sources.oods = @intCast(node);
        },
        else => {},
    };
    if (challenge_count != relation_count * 2 or sources.composition == missing or sources.oods == missing) return error.InvalidExecutionChallenge;
    const outputs = transcript.plan.fixed.draw_outputs;
    // Validate operation provenance and reject overlapping export addresses.
    for (outputs, 0..) |output, i| {
        if (output.operation >= transcript.operations.len or transcript.operations[output.operation] != .secure) return error.InvalidExecutionChallenge;
        const draw = transcript.operations[output.operation].secure;
        if (draw.output == null or !std.meta.eql(draw.output.?, output.role) or draw.consumption.words() != output.words) return error.InvalidExecutionChallenge;
        const end = try std.math.add(usize, output.source.first_wire, output.words);
        if (end > core.fields.m31.Modulus) return error.InvalidExecutionChallenge;
        for (outputs[0..i]) |previous| if (previous.source.circuit == output.source.circuit and output.source.first_wire < @as(usize, previous.source.first_wire) + previous.words and previous.source.first_wire < end) return error.InvalidExecutionChallenge;
        for (ids) |id| if (id == output.source.circuit) return error.InvalidExecutionChallenge;
    }
    const links = try links_mod.build(temp, outputs, sources, &deep.graph, &fri.graph, relation_count, fri.graph.profile().fold_widths.len);
    const graphs = [3]@import("composition_circuit.zig").CircuitGraph{ composition.circuit.graph(), deep.graph.graph(), fri.graph.graph() };
    const values = [3][]const Q{ composition.values, deep.evaluation.values, fri.evaluation.values };
    var uses: [3][]const u32 = undefined;
    for (graphs, &uses) |graph, *counts| counts.* = try lower.computeUseCountsInto(graph, try temp.alloc(u32, graph.nodes.len));
    var rows: std.ArrayList(scalar.Row) = .empty;
    var fixed: std.ArrayList(scalar.Row) = .empty;
    var packs: std.ArrayList(pack.Row) = .empty;
    var fixed_packs: std.ArrayList(pack.Row) = .empty;
    for (links, 0..) |link, index| {
        var coordinates: [4]M = undefined;
        var weight: u32 = 0;
        const first: u32 = @intCast(index * 4);
        const nodes: [4]u32 = .{ first, first + 1, first + 2, first + 3 };
        if (link.composition) |node| {
            if (node >= composition.inputs.len or !values[0][node].eql(composition.inputs[node])) return error.InvalidExecutionChallenge;
            coordinates = composition.inputs[node].toM31Array();
            weight = uses[0][node];
            if (weight != 0) {
                const schedule = pack.Schedule{ .source_circuit = bridge, .source_nodes = nodes, .destination_circuit = circuits[0], .destination_wire = node };
                try packs.append(temp, try pack.weightedLogicalRow(schedule, composition.inputs[node], weight));
                try fixed_packs.append(temp, try pack.weightedFixedRow(schedule, weight));
            }
        }
        if (link.scalar) |destination| {
            const lane = destination.lane;
            for (destination.nodes, 0..) |node, word| {
                const value = values[lane][node];
                const base = value.toM31Array()[0];
                if (!value.eql(Q.fromBase(base)) or (link.composition != null and !coordinates[word].eql(base))) return error.InvalidExecutionChallenge;
                coordinates[word] = base;
                try rows.append(temp, try scalar.routedRow(circuits[lane], node, uses[lane][node], bridge, nodes[word], base));
                try fixed.append(temp, try scalar.routedRow(circuits[lane], node, uses[lane][node], bridge, nodes[word], M.zero()));
            }
            weight = try std.math.add(u32, weight, 1);
        }
        // Check exported live values, not just matching role tags/schedules.
        var matched = false;
        for (outputs) |output| {
            if (output.source.circuit != link.source.circuit or link.source.first_wire < output.source.first_wire) continue;
            const offset = link.source.first_wire - output.source.first_wire;
            if (offset + 4 > output.words) continue;
            const draw = transcript.operations[output.operation].secure;
            for (coordinates, draw.values[offset..][0..4]) |actual, expected| if (!actual.eql(expected)) return error.InvalidExecutionChallenge;
            matched = true;
        }
        if (!matched) return error.InvalidExecutionChallenge;
        for (coordinates, nodes, 0..) |value, node, word| {
            const source = try std.math.add(u32, link.source.first_wire, @intCast(word));
            try rows.append(temp, try scalar.routedRow(bridge, node, weight, link.source.circuit, source, value));
            try fixed.append(temp, try scalar.routedRow(bridge, node, weight, link.source.circuit, source, M.zero()));
        }
    }
    return .{ .arena = arena, .rows = rows.items, .fixed = fixed.items, .packs = packs.items, .fixed_packs = fixed_packs.items };
}
