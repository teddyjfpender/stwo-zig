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
pub const Columns = @import("blake3_upstream_source_columns_v1.zig").ForSlots(.{12});
pub const Prepared = struct {
    arena: std.heap.ArenaAllocator,
    /// Replaces the composition-only challenge routes, adding OODS fanout.
    composition: ?*vm_links.Prepared = null,
    composition_links: [vm_links.COUNT]vm_links.Link,
    composition_columns: ?Columns = null,
    columns: ?Columns = null,
    rows: []scalar.Row,
    fixed: []scalar.Row,
    pub fn compositionRowAt(self: *const Prepared, index: usize) !scalar.Row {
        if (self.composition_columns) |*columns| {
            if (self.composition != null) return error.InvalidNativePcsChallenge;
            return columns.rowAt(12, index);
        }
        const rows = self.composition orelse return error.InvalidNativePcsChallenge;
        if (index >= rows.rows.len) return error.InvalidNativePcsChallenge;
        return rows.rows[index];
    }
    pub fn appendInputs(self: *const Prepared, b: anytype) !void {
        if (self.columns) |*columns| {
            if (self.rows.len != 0 or self.fixed.len != 0) return error.InvalidNativePcsChallenge;
            try columns.appendTo(12, b);
        } else try b.append(12, self.rows, self.fixed);
    }
    pub fn deinit(self: *Prepared) void {
        if (self.composition_columns) |*columns| columns.deinit();
        if (self.columns) |*columns| columns.deinit();
        self.arena.deinit();
        self.* = undefined;
    }
};
pub fn prepare(a: std.mem.Allocator, composition: *const vm.Prepared, transcript: *const native.Prepared, deep: *const deep_mod.Prepared, fri: *const fri_mod.Prepared, circuits: [3]u32) !Prepared {
    return prepareMode(false, a, composition, transcript, deep, fri, circuits);
}
pub fn prepareColumns(a: std.mem.Allocator, composition: *const vm.Prepared, transcript: *const native.Prepared, deep: *const deep_mod.Prepared, fri: *const fri_mod.Prepared, circuits: [3]u32) !Prepared {
    return prepareMode(true, a, composition, transcript, deep, fri, circuits);
}
fn prepareMode(comptime direct: bool, a: std.mem.Allocator, composition: *const vm.Prepared, transcript: *const native.Prepared, deep: *const deep_mod.Prepared, fri: *const fri_mod.Prepared, circuits: [3]u32) !Prepared {
    try transcript.plan.validate();
    try deep.graph.validateEvaluation(&deep.evaluation);
    try fri.evaluation.validateAgainst(&fri.graph);
    try composition.validate();
    const composition_links = try vm_links.schedule(&composition.circuit, transcript.live.draw_outputs);
    for (circuits, 0..) |c, i| {
        if (c >= core.fields.m31.Modulus) return error.InvalidNativePcsChallenge;
        for (circuits[0..i]) |other| if (c == other) return error.InvalidNativePcsChallenge;
    }
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const output_allocator = arena.allocator();
    var scratch_arena = std.heap.ArenaAllocator.init(a);
    defer scratch_arena.deinit();
    const temp = scratch_arena.allocator();
    var composed: ?*vm_links.Prepared = null;
    var composition_columns: ?Columns = null;
    errdefer if (composition_columns) |*owned| owned.deinit();
    if (direct) {
        var owner = try Columns.init(a, .{vm_links.COUNT});
        errdefer owner.deinit();
        const uses = try lower.computeUseCountsInto(composition.circuit.graph(), try temp.alloc(u32, composition.circuit.nodes.len));
        for (composition_links, 0..) |link, index| {
            const value = composition.evaluation.values[link.node];
            const base = value.toM31Array()[0];
            if (!value.eql(Q.fromBase(base))) return error.InvalidNativePcsChallenge;
            const weight = try std.math.add(u32, uses[link.node], if (index >= vm_links.COUNT - 4) @as(u32, 1) else 0);
            try owner.append(12, try scalar.routedRow(circuits[0], link.node, weight, link.source.circuit, link.source.first_wire, base));
        }
        try owner.finish();
        composition_columns = owner;
    } else {
        const value = try vm_links.prepare(a, composition, transcript.live.draw_outputs, circuits[0]);
        const owned = try output_allocator.create(vm_links.Prepared);
        owned.* = value;
        composed = owned;
    }
    const layers = fri.graph.profile().fold_widths.len;
    const count = try std.math.add(usize, 8, try std.math.mul(usize, 4, layers));
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
    var columns: ?Columns = null;
    errdefer if (columns) |*owned| owned.deinit();
    if (direct) columns = try Columns.init(a, .{count});
    const rows: []scalar.Row = if (direct) &.{} else try output_allocator.alloc(scalar.Row, count);
    const fixed: []scalar.Row = if (direct) &.{} else try output_allocator.alloc(scalar.Row, count);
    for (nodes, sources, values, 0..) |node, source_optional, value, i| {
        var source = source_optional orelse return error.InvalidNativePcsChallenge;
        if (node == missing) return error.InvalidNativePcsChallenge;
        const evaluation = if (i < 8) deep.evaluation.values else fri.evaluation.values;
        const uses = if (i < 8) deep_uses else fri_uses;
        if (node >= evaluation.len or !evaluation[node].eql(Q.fromBase(value))) return error.InvalidNativePcsChallenge;
        if (i < 4) {
            const slot = vm_links.COUNT - 4 + i;
            const old = if (direct) try composition_columns.?.rowAt(12, slot) else composed.?.rows[slot];
            if (!std.meta.eql(source, composition_links[slot].source) or !old[0].eql(value)) return error.InvalidNativePcsChallenge;
            if (!direct) {
                const weight = try std.math.add(u32, old[3].v, 1);
                if (weight >= core.fields.m31.Modulus) return error.InvalidNativePcsChallenge;
                composed.?.rows[slot][3] = M.fromCanonical(weight);
                composed.?.fixed[slot][3] = M.fromCanonical(weight);
            }
            source = .{ .circuit = circuits[0], .first_wire = composition_links[slot].node };
        }
        const destination = circuits[if (i < 8) @as(usize, 1) else 2];
        const row = try scalar.routedRow(destination, node, uses[node], source.circuit, source.first_wire, value);
        if (direct) try columns.?.append(12, row) else {
            rows[i] = row;
            fixed[i] = try scalar.routedRow(destination, node, uses[node], source.circuit, source.first_wire, M.zero());
        }
    }
    if (columns) |*owned| try owned.finish();
    return .{ .composition_columns = composition_columns, .composition_links = composition_links, .columns = columns, .arena = arena, .composition = composed, .rows = rows, .fixed = fixed };
}
fn assign(nodes: []u32, index: usize, node: u32) !void {
    if (index >= nodes.len or nodes[index] != std.math.maxInt(u32)) return error.InvalidNativePcsChallenge;
    nodes[index] = node;
}
