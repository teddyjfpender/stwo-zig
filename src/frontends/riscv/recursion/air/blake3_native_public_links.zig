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
pub const CLAIM_WORDS = claims.COMPONENT_COUNT * 4;
pub const TOTAL_INPUTS = CLAIM_WORDS + 4;
pub const BOUNDARY_CIRCUIT: u32 = 1506;
pub const TOTAL_CIRCUIT: u32 = 1508;
pub const Columns = @import("blake3_upstream_source_columns_v1.zig").ForSlots(.{12});
const TOTAL_ROWS = vm_links.COUNT + 32 + CLAIM_WORDS + 4 + TOTAL_INPUTS;
pub const Prepared = struct {
    arena: std.heap.ArenaAllocator,
    columns: ?Columns = null,
    /// Replaces PCS composition challenge rows; OODS sharing is preserved.
    composition_rows: []scalar.Row,
    fixed_composition: []scalar.Row,
    challenge_rows: []scalar.Row,
    fixed_challenges: []scalar.Row,
    /// Replaces the aggregate-claim prefix of payload scalar producers.
    claim_sources: []scalar.Row,
    fixed_claims: []scalar.Row,
    total_sources: []scalar.Row,
    fixed_total_sources: []scalar.Row,
    destinations: []scalar.Row,
    fixed_destinations: []scalar.Row,
    circuit: arithmetic.Circuit,
    graph: authority.NativeOwnedGraph,
    evaluation: arithmetic.Evaluation,
    inputs: [TOTAL_INPUTS]Q,
    pub const Part = enum { composition, challenges, claims, totals, destinations };
    pub fn appendPart(self: *const Prepared, comptime part: Part, b: anytype) !void {
        const first, const count = comptime switch (part) {
            .composition => .{ 0, vm_links.COUNT },
            .challenges => .{ vm_links.COUNT, 32 },
            .claims => .{ vm_links.COUNT + 32, CLAIM_WORDS },
            .totals => .{ vm_links.COUNT + 32 + CLAIM_WORDS, 4 },
            .destinations => .{ vm_links.COUNT + 32 + CLAIM_WORDS + 4, TOTAL_INPUTS },
        };
        if (self.columns) |*columns| {
            if (self.composition_rows.len != 0 or self.fixed_composition.len != 0 or self.challenge_rows.len != 0 or self.fixed_challenges.len != 0 or self.claim_sources.len != 0 or self.fixed_claims.len != 0 or self.total_sources.len != 0 or self.fixed_total_sources.len != 0 or self.destinations.len != 0 or self.fixed_destinations.len != 0) return error.InvalidNativePublicLink;
            try b.appendBorrowed(12, try (try columns.view(12)).subview(first, count));
        } else switch (part) {
            .composition => try b.append(12, self.composition_rows, self.fixed_composition),
            .challenges => try b.append(12, self.challenge_rows, self.fixed_challenges),
            .claims => try b.append(12, self.claim_sources, self.fixed_claims),
            .totals => try b.append(12, self.total_sources, self.fixed_total_sources),
            .destinations => try b.append(12, self.destinations, self.fixed_destinations),
        }
    }
    pub fn deinit(self: *Prepared) void {
        if (self.columns) |*columns| columns.deinit();
        self.arena.deinit();
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
    return prepareMode(true, a, composition, boundary, challenges, payloads);
}
/// Explicit dense-source parity oracle.
pub fn prepareRows(a: std.mem.Allocator, composition: *const vm.Prepared, boundary: *const boundary_mod.Prepared, challenges: *const challenges_mod.Prepared, payloads: *const payload_mod.Prepared) !Prepared {
    return prepareMode(false, a, composition, boundary, challenges, payloads);
}
fn prepareMode(comptime direct: bool, a: std.mem.Allocator, composition: *const vm.Prepared, boundary: *const boundary_mod.Prepared, challenges: *const challenges_mod.Prepared, payloads: *const payload_mod.Prepared) !Prepared {
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
    if (payloads.nodes.len < claim_nodes.len or payloads.scalarCount() < CLAIM_WORDS) return error.InvalidNativePublicLink;
    const scratch = try a.alloc(u32, composition.circuit.nodes.len);
    defer a.free(scratch);
    const vm_uses = try lower.computeUseCountsInto(composition.circuit.graph(), scratch);
    const public_uses = boundary.circuit.useCounts();
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const output = arena.allocator();
    var columns: ?Columns = null;
    errdefer if (columns) |*owned| owned.deinit();
    if (direct) columns = try Columns.init(a, .{TOTAL_ROWS});
    var out: Prepared = undefined;
    out.columns = null;
    out.composition_rows = if (direct) &.{} else try output.alloc(scalar.Row, vm_links.COUNT);
    out.fixed_composition = if (direct) &.{} else try output.alloc(scalar.Row, vm_links.COUNT);
    out.challenge_rows = if (direct) &.{} else try output.alloc(scalar.Row, 32);
    out.fixed_challenges = if (direct) &.{} else try output.alloc(scalar.Row, 32);
    out.claim_sources = if (direct) &.{} else try output.alloc(scalar.Row, CLAIM_WORDS);
    out.fixed_claims = if (direct) &.{} else try output.alloc(scalar.Row, CLAIM_WORDS);
    out.total_sources = if (direct) &.{} else try output.alloc(scalar.Row, 4);
    out.fixed_total_sources = if (direct) &.{} else try output.alloc(scalar.Row, 4);
    out.destinations = if (direct) &.{} else try output.alloc(scalar.Row, TOTAL_INPUTS);
    out.fixed_destinations = if (direct) &.{} else try output.alloc(scalar.Row, TOTAL_INPUTS);

    for (public_challenges, 0..) |node, i| {
        const source = challenges.composition_links[i].node;
        if (source != vm_challenges[i] or source >= composition.evaluation.values.len or !composition.evaluation.values[source].eql(boundary.evaluation.values[node])) return error.InvalidNativePublicLink;
        const value = try base(boundary.evaluation.values[node]);
        const old = try scalar.routedRow(1500, source, vm_uses[source], challenges.composition_links[i].source.circuit, challenges.composition_links[i].source.first_wire, value);
        if (!std.meta.eql(old, try challenges.compositionRowAt(i))) return error.InvalidNativePublicLink;
        const weight = try std.math.add(u32, vm_uses[source], 1);
        const producer = try scalar.routedRow(1500, source, weight, challenges.composition_links[i].source.circuit, challenges.composition_links[i].source.first_wire, value);
        const consumer = try scalar.routedRow(BOUNDARY_CIRCUIT, node, public_uses[node], 1500, source, value);
        if (direct) {
            try columns.?.put(12, i, producer);
            try columns.?.put(12, vm_links.COUNT + i, consumer);
        } else {
            out.composition_rows[i] = producer;
            out.fixed_composition[i] = try scalar.routedRow(1500, source, weight, challenges.composition_links[i].source.circuit, challenges.composition_links[i].source.first_wire, M.zero());
            out.challenge_rows[i] = consumer;
            out.fixed_challenges[i] = try scalar.routedRow(BOUNDARY_CIRCUIT, node, public_uses[node], 1500, source, M.zero());
        }
    }
    for (32..vm_links.COUNT) |index| {
        const row = try challenges.compositionRowAt(index);
        if (direct) try columns.?.put(12, index, row) else {
            out.composition_rows[index] = row;
            var fixed = row;
            fixed[0] = M.zero();
            out.fixed_composition[index] = fixed;
        }
    }
    for (claim_nodes, 0..) |nodes, claim| {
        if (!std.meta.eql(nodes, payloads.nodes[claim])) return error.InvalidNativePublicLink;
        for (nodes, 0..) |node, word| {
            if (node == missing) return error.InvalidNativePublicLink;
            const i = claim * 4 + word;
            const value = try base(composition.evaluation.values[node]);
            const old_weight = try std.math.add(u32, vm_uses[node], 1);
            if (!std.meta.eql(try scalar.logicalRow(1500, node, old_weight, value), try payloads.scalarAt(i))) return error.InvalidNativePublicLink;
            const producer = try scalar.logicalRow(1500, node, try std.math.add(u32, old_weight, 1), value);
            const consumer = try scalar.routedRow(TOTAL_CIRCUIT, @intCast(i), 1, 1500, node, value);
            out.inputs[i] = Q.fromBase(value);
            if (direct) {
                try columns.?.put(12, vm_links.COUNT + 32 + i, producer);
                try columns.?.put(12, vm_links.COUNT + 32 + CLAIM_WORDS + 4 + i, consumer);
            } else {
                out.claim_sources[i] = producer;
                out.fixed_claims[i] = try scalar.logicalRow(1500, node, try std.math.add(u32, old_weight, 1), M.zero());
                out.destinations[i] = consumer;
                out.fixed_destinations[i] = try scalar.routedRow(TOTAL_CIRCUIT, @intCast(i), 1, 1500, node, M.zero());
            }
        }
    }
    for (public_total, 0..) |node, word| {
        const value = try base(boundary.evaluation.values[node]);
        const uses = try std.math.add(u32, public_uses[node], 1);
        const producer = try scalar.logicalRow(BOUNDARY_CIRCUIT, node, uses, value);
        const i = CLAIM_WORDS + word;
        out.inputs[i] = Q.fromBase(value);
        const consumer = try scalar.routedRow(TOTAL_CIRCUIT, @intCast(i), 1, BOUNDARY_CIRCUIT, node, value);
        if (direct) {
            try columns.?.put(12, vm_links.COUNT + 32 + CLAIM_WORDS + word, producer);
            try columns.?.put(12, vm_links.COUNT + 32 + CLAIM_WORDS + 4 + i, consumer);
        } else {
            out.total_sources[word] = producer;
            out.fixed_total_sources[word] = try scalar.logicalRow(BOUNDARY_CIRCUIT, node, uses, M.zero());
            out.destinations[i] = consumer;
            out.fixed_destinations[i] = try scalar.routedRow(TOTAL_CIRCUIT, @intCast(i), 1, BOUNDARY_CIRCUIT, node, M.zero());
        }
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
    errdefer out.evaluation.deinit();
    if (columns) |*owned| try owned.finish();
    out.arena = arena;
    out.columns = columns;
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
