//! Circuit lowering for S31 relation IR v1. Public and private inputs use
//! identical constrained guesses; visibility changes only the public ABI.

const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const relation = @import("relation.zig");
const canonical = @import("canonical.zig");
const poseidon2 = @import("poseidon2.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Var = circuit.builder.Var;
const Simd = circuit.builder.simd.Simd;
const N_RESERVED = circuit.common.component_list.N_RESERVED;

const Entry = struct {
    shape: relation.Shape,
    lanes: Simd,
    raw: ?[]Var = null,
    boolean: bool = false,
};

pub fn compileRaw(comptime V: type, allocator: std.mem.Allocator, program: relation.Program, assignment: ?relation.Assignment) !circuit.builder.Context(V) {
    try program.validate(allocator);
    if (comptime V == QM31) {
        if (assignment == null) return error.MissingAssignment;
    }
    var ctx = try circuit.builder.Context(V).init(allocator, N_RESERVED);
    errdefer ctx.deinit();
    const scratch = ctx.scratch();
    var values = std.StringHashMapUnmanaged(Entry){};
    defer values.deinit(scratch);

    for (program.inputs) |input| {
        const length: usize = input.length;
        const source_values: ?[]M31 = if (comptime V == QM31) try relation.inputValues(allocator, assignment.?, input) else null;
        defer if (source_values) |owned| allocator.free(owned);
        const raw = try scratch.alloc(Var, length);
        const wrappers = try scratch.alloc(circuit.builder.wrappers.M31Wrapper(Var), length);
        for (raw, wrappers, 0..) |*wire, *wrapped, i| {
            const value = if (source_values) |provided| provided[i] else M31.zero();
            const hint = circuit.builder.ivalue.fromQm31(V, QM31.fromBase(value));
            wire.* = switch (input.kind) {
                .u16 => (try circuit.builder.wrappers.guessU16(V, &ctx, .newUnsafe(hint))).get(),
                .m31 => (try circuit.builder.wrappers.guessM31(V, &ctx, .newUnsafe(hint))).get(),
            };
            wrapped.* = .newUnsafe(wire.*);
        }
        const lanes = try circuit.builder.simd.pack(V, &ctx, wrappers);
        try values.put(scratch, input.name, .{
            .shape = .{ .kind = input.kind, .length = length },
            .lanes = lanes,
            .raw = raw,
        });
    }

    for (program.nodes) |node| {
        const lhs: ?Entry = if (node.lhs) |name| values.get(name) orelse return error.UnknownOperand else null;
        const rhs: ?Entry = if (node.rhs) |name| values.get(name) orelse return error.UnknownOperand else null;
        const selector: ?Entry = if (node.selector) |name| values.get(name) orelse return error.UnknownOperand else null;
        const length: usize = if (node.op == .constant) node.length.? else if (node.op == .sum_lanes) 1 else if (node.op == .hash_blake2s or node.op == .hash_blake2s_leaf or node.op == .hash_blake2s_pair or node.op == .hash_poseidon2_leaf or node.op == .hash_poseidon2_pair) 8 else lhs.?.shape.length;
        const entry: Entry = switch (node.op) {
            .constant => .{ .shape = .{ .kind = .m31, .length = length }, .lanes = try circuit.builder.simd.repeat(V, &ctx, M31.fromCanonical(node.constant.?), length) },
            .cast_m31 => .{ .shape = .{ .kind = .m31, .length = length }, .lanes = lhs.?.lanes, .raw = lhs.?.raw },
            .add => .{ .shape = .{ .kind = .m31, .length = length }, .lanes = try circuit.builder.simd.add(V, &ctx, lhs.?.lanes, rhs.?.lanes) },
            .mul => .{ .shape = .{ .kind = .m31, .length = length }, .lanes = try circuit.builder.simd.mul(V, &ctx, lhs.?.lanes, rhs.?.lanes) },
            .add_const => .{ .shape = .{ .kind = .m31, .length = length }, .lanes = try circuit.builder.simd.add(V, &ctx, lhs.?.lanes, try circuit.builder.simd.repeat(V, &ctx, M31.fromCanonical(node.constant.?), length)) },
            .mul_const => .{ .shape = .{ .kind = .m31, .length = length }, .lanes = try circuit.builder.simd.mul(V, &ctx, lhs.?.lanes, try circuit.builder.simd.repeat(V, &ctx, M31.fromCanonical(node.constant.?), length)) },
            .sum_lanes => .{ .shape = .{ .kind = .m31, .length = 1 }, .lanes = try sumLanes(V, &ctx, lhs.?.lanes) },
            .repeat => blk: {
                const constants = try scratch.alloc(?Simd, node.body.?.len);
                for (node.body.?, constants) |step, *slot| slot.* = if (step.constant) |value| try circuit.builder.simd.repeat(V, &ctx, M31.fromCanonical(value), length) else null;
                var current = lhs.?.lanes;
                for (0..node.rounds.?) |_| for (node.body.?, constants) |step, constant| {
                    current = switch (step.op) {
                        .square => try circuit.builder.simd.mul(V, &ctx, current, current),
                        .add_const => try circuit.builder.simd.add(V, &ctx, current, constant.?),
                        .mul_const => try circuit.builder.simd.mul(V, &ctx, current, constant.?),
                    };
                };
                break :blk .{ .shape = .{ .kind = .m31, .length = length }, .lanes = current };
            },
            .hash_blake2s => .{ .shape = .{ .kind = .m31, .length = 8 }, .lanes = try hashBlake2s(V, &ctx, lhs.?.lanes, lhs.?.shape.length) },
            .hash_blake2s_leaf => .{ .shape = .{ .kind = .m31, .length = 8 }, .lanes = try hashBlake2sPersonalized(V, &ctx, lhs.?.lanes, lhs.?.shape.length, relation.leaf_personalization) },
            .hash_blake2s_pair => .{ .shape = .{ .kind = .m31, .length = 8 }, .lanes = try hashBlake2sPair(V, &ctx, lhs.?.lanes, rhs.?.lanes) },
            .select => .{ .shape = .{ .kind = .m31, .length = length }, .lanes = try selectByBit(V, &ctx, lhs.?.lanes, rhs.?.lanes, selector.?.lanes, null) },
            .hash_poseidon2_leaf => .{ .shape = .{ .kind = .m31, .length = 8 }, .lanes = try poseidon2.leafCircuit(V, &ctx, lhs.?.lanes) },
            .hash_poseidon2_pair => .{ .shape = .{ .kind = .m31, .length = 8 }, .lanes = try poseidon2.pairCircuit(V, &ctx, lhs.?.lanes, rhs.?.lanes) },
        };
        try values.put(scratch, node.name, entry);
    }

    for (program.assertions) |assertion| {
        const lhs = values.get(assertion.lhs) orelse return error.UnknownOperand;
        const rhs = values.get(assertion.rhs) orelse return error.UnknownOperand;
        try circuit.builder.simd.eq(V, &ctx, lhs.lanes, rhs.lanes);
    }

    var outputs = [_]Var{ctx.zero()} ** N_RESERVED;
    var at: usize = 0;
    for (program.inputs) |input| {
        if (input.visibility != .public) continue;
        const value = values.get(input.name) orelse return error.UnknownOperand;
        for (0..value.shape.length) |i| {
            outputs[at] = try outputWord(V, &ctx, value, i, false);
            at += 1;
        }
    }
    for (program.public_outputs) |name| {
        const value = values.get(name) orelse return error.UnknownOutput;
        for (0..value.shape.length) |i| {
            outputs[at] = try outputWord(V, &ctx, value, i, false);
            at += 1;
        }
    }
    try ctx.setOutputs(&outputs);
    try ctx.finalize(false);
    return ctx;
}

pub const Span = struct {
    id: u32,
    qm31_start: usize,
    qm31_end: usize,
    eq_start: usize,
    eq_end: usize,
    triple_xor_start: usize,
    triple_xor_end: usize,
    m31_to_u32_start: usize,
    m31_to_u32_end: usize,
    blake_g_start: usize,
    blake_g_end: usize,
};

pub const AssertionSpan = struct { index: usize, qm31_start: usize, qm31_end: usize, eq_start: usize, eq_end: usize };
pub const BindingSpan = struct {
    name: []const u8,
    word_start: usize,
    word_count: usize,
    conversion_qm31_start: usize,
    conversion_qm31_end: usize,
    conversion_m31_to_u32_start: usize,
    conversion_m31_to_u32_end: usize,
    binding_qm31_start: usize = 0,
    binding_qm31_end: usize = 0,
};
pub const FinalizationSpan = struct { qm31_start: usize, qm31_end: usize, m31_to_u32_start: usize, m31_to_u32_end: usize };
pub const Maps = struct {
    nodes: std.ArrayListUnmanaged(Span) = .empty,
    assertions: std.ArrayListUnmanaged(AssertionSpan) = .empty,
    bindings: std.ArrayListUnmanaged(BindingSpan) = .empty,
    finalization: ?FinalizationSpan = null,

    pub fn deinit(self: *Maps, allocator: std.mem.Allocator) void {
        self.nodes.deinit(allocator);
        self.assertions.deinit(allocator);
        self.bindings.deinit(allocator);
        self.* = undefined;
    }
};

pub fn compile(comptime V: type, allocator: std.mem.Allocator, program: relation.Program, assignment: ?relation.Assignment) !circuit.builder.Context(V) {
    return compileWithSpans(V, allocator, program, assignment, null);
}

pub fn compileWithSpans(comptime V: type, allocator: std.mem.Allocator, program: relation.Program, assignment: ?relation.Assignment, maps: ?*Maps) !circuit.builder.Context(V) {
    return compileWithSpansMode(V, allocator, program, assignment, maps, false, false);
}

pub fn compileChip(comptime V: type, allocator: std.mem.Allocator, program: relation.Program, assignment: ?relation.Assignment) !circuit.builder.Context(V) {
    return compileWithSpansMode(V, allocator, program, assignment, null, true, false);
}

pub fn compileChipWithSpans(comptime V: type, allocator: std.mem.Allocator, program: relation.Program, assignment: ?relation.Assignment, maps: ?*Maps) !circuit.builder.Context(V) {
    return compileWithSpansMode(V, allocator, program, assignment, maps, true, false);
}

pub fn compileDirect(comptime V: type, allocator: std.mem.Allocator, program: relation.Program, assignment: ?relation.Assignment, chip_mode: bool) !circuit.builder.Context(V) {
    return compileWithSpansMode(V, allocator, program, assignment, null, chip_mode, true);
}

pub fn compileDirectWithSpans(comptime V: type, allocator: std.mem.Allocator, program: relation.Program, assignment: ?relation.Assignment, maps: ?*Maps, chip_mode: bool) !circuit.builder.Context(V) {
    return compileWithSpansMode(V, allocator, program, assignment, maps, chip_mode, true);
}

fn compileWithSpansMode(comptime V: type, allocator: std.mem.Allocator, program: relation.Program, assignment: ?relation.Assignment, maps: ?*Maps, chip_mode: bool, direct_output: bool) !circuit.builder.Context(V) {
    if (chip_mode and program.repeatedStepChip() == null) return error.UnsupportedChipRelation;
    if (direct_output) for (program.inputs) |input| {
        if (input.kind != .m31) return error.UnsupportedDirectRelation;
    };
    if (comptime V == QM31) {
        if (assignment == null) return error.MissingAssignment;
    }
    var ir = try canonical.build(allocator, program);
    defer ir.deinit();
    var ctx = try circuit.builder.Context(V).init(allocator, N_RESERVED);
    errdefer ctx.deinit();
    const scratch = ctx.scratch();
    const entries = try scratch.alloc(Entry, ir.nodes.len);
    for (ir.nodes, entries, 0..) |node, *entry, id| {
        const qm31_start = ctx.circuit.nQm31OpsRows();
        const eq_start = ctx.circuit.eq.items.len;
        const xor_start = ctx.circuit.triple_xor.items.len;
        const conversion_start = ctx.circuit.m31_to_u32.items.len;
        const blake_start = ctx.circuit.blake_g_gate.items.len;
        entry.* = switch (node.tag) {
            .input => blk: {
                const input: relation.Input = .{
                    .name = node.input_name.?,
                    .kind = node.kind,
                    .length = node.length,
                    .visibility = node.visibility.?,
                };
                const source_values: ?[]M31 = if (comptime V == QM31) try relation.inputValues(allocator, assignment.?, input) else null;
                defer if (source_values) |owned| allocator.free(owned);
                const boolean = direct_output and isSelectorInput(ir.nodes, id);
                // A QM31 witness is already four M31 coordinates. For a
                // private array, guessing the packed wire directly avoids
                // four scalar guesses and their six packing gates. Public
                // inputs retain scalar wires for their ABI bindings; direct
                // selectors retain the self-product that proves b² = b.
                if (node.kind == .m31 and node.visibility.? == .private and !boolean) {
                    const packed_wires = try scratch.alloc(Var, (node.length + 3) / 4);
                    for (packed_wires, 0..) |*wire, chunk| {
                        var coordinates = [_]M31{M31.zero()} ** 4;
                        for (&coordinates, 0..) |*coordinate, offset| {
                            const lane = 4 * chunk + offset;
                            if (lane < node.length and source_values != null) coordinate.* = source_values.?[lane];
                        }
                        wire.* = try ctx.guess(circuit.builder.ivalue.fromQm31(V, QM31.fromM31Array(coordinates)));
                    }
                    break :blk .{ .shape = .{ .kind = .m31, .length = node.length }, .lanes = Simd.fromPacked(packed_wires, node.length) };
                }
                const raw = try scratch.alloc(Var, node.length);
                const wrappers = try scratch.alloc(circuit.builder.wrappers.M31Wrapper(Var), node.length);
                for (raw, wrappers, 0..) |*wire, *wrapped, i| {
                    const value = if (source_values) |provided| provided[i] else M31.zero();
                    const hint = circuit.builder.ivalue.fromQm31(V, QM31.fromBase(value));
                    wire.* = if (boolean) bit: {
                        // A circuit wire has one producing gate. For a direct
                        // selector the self-product is that producer, and
                        // b² = b also forces a canonical base-field bit.
                        const bit_wire = try ctx.newVar(hint);
                        try ctx.mulInto(bit_wire, bit_wire, bit_wire);
                        break :bit bit_wire;
                    } else switch (node.kind) {
                        .u16 => (try circuit.builder.wrappers.guessU16(V, &ctx, .newUnsafe(hint))).get(),
                        .m31 => (try circuit.builder.wrappers.guessM31(V, &ctx, .newUnsafe(hint))).get(),
                    };
                    wrapped.* = .newUnsafe(wire.*);
                }
                break :blk .{ .shape = .{ .kind = node.kind, .length = node.length }, .lanes = try circuit.builder.simd.pack(V, &ctx, wrappers), .raw = raw, .boolean = boolean };
            },
            .constant => .{ .shape = .{ .kind = .m31, .length = node.length }, .lanes = try circuit.builder.simd.repeat(V, &ctx, M31.fromCanonical(node.constant.?), node.length) },
            .cast_m31 => .{ .shape = .{ .kind = .m31, .length = node.length }, .lanes = entries[node.lhs.?].lanes, .raw = entries[node.lhs.?].raw, .boolean = entries[node.lhs.?].boolean },
            .add => .{ .shape = .{ .kind = .m31, .length = node.length }, .lanes = try circuit.builder.simd.add(V, &ctx, entries[node.lhs.?].lanes, entries[node.rhs.?].lanes) },
            .mul => .{ .shape = .{ .kind = .m31, .length = node.length }, .lanes = try circuit.builder.simd.mul(V, &ctx, entries[node.lhs.?].lanes, entries[node.rhs.?].lanes) },
            .add_const => .{ .shape = .{ .kind = .m31, .length = node.length }, .lanes = try circuit.builder.simd.add(V, &ctx, entries[node.lhs.?].lanes, try circuit.builder.simd.repeat(V, &ctx, M31.fromCanonical(node.constant.?), node.length)) },
            .mul_const => .{ .shape = .{ .kind = .m31, .length = node.length }, .lanes = try circuit.builder.simd.mul(V, &ctx, entries[node.lhs.?].lanes, try circuit.builder.simd.repeat(V, &ctx, M31.fromCanonical(node.constant.?), node.length)) },
            .sum_lanes => .{ .shape = .{ .kind = .m31, .length = 1 }, .lanes = try sumLanes(V, &ctx, entries[node.lhs.?].lanes) },
            .repeat => blk: {
                if (chip_mode) {
                    const spec = program.repeatedStepChip().?;
                    const input_raw = entries[node.lhs.?].raw orelse return error.UnsupportedChipRelation;
                    if (node.length != 4 or input_raw.len != 4) return error.UnsupportedChipRelation;
                    const raw = try scratch.alloc(Var, 4);
                    const wrappers = try scratch.alloc(circuit.builder.wrappers.M31Wrapper(Var), 4);
                    for (raw, wrappers, 0..) |*wire, *wrapped, lane| {
                        var result = if (comptime V == QM31)
                            ctx.get(input_raw[lane]).toM31Array()[0]
                        else
                            M31.zero();
                        for (0..spec.rounds) |_|
                            result = result.mul(result).add(M31.fromCanonical(spec.constant));
                        const hint = circuit.builder.ivalue.fromQm31(V, QM31.fromBase(result));
                        wire.* = (try circuit.builder.wrappers.guessM31(V, &ctx, .newUnsafe(hint))).get();
                        wrapped.* = .newUnsafe(wire.*);
                    }
                    break :blk .{ .shape = .{ .kind = .m31, .length = 4 }, .lanes = try circuit.builder.simd.pack(V, &ctx, wrappers), .raw = raw };
                }
                const constants = try scratch.alloc(?Simd, node.body.?.len);
                for (node.body.?, constants) |step, *slot| slot.* = if (step.constant) |value| try circuit.builder.simd.repeat(V, &ctx, M31.fromCanonical(value), node.length) else null;
                var current = entries[node.lhs.?].lanes;
                for (0..node.rounds.?) |_| for (node.body.?, constants) |step, constant| {
                    current = switch (step.op) {
                        .square => try circuit.builder.simd.mul(V, &ctx, current, current),
                        .add_const => try circuit.builder.simd.add(V, &ctx, current, constant.?),
                        .mul_const => try circuit.builder.simd.mul(V, &ctx, current, constant.?),
                    };
                };
                break :blk .{ .shape = .{ .kind = .m31, .length = node.length }, .lanes = current };
            },
            .hash_blake2s => .{ .shape = .{ .kind = .m31, .length = 8 }, .lanes = try hashBlake2s(V, &ctx, entries[node.lhs.?].lanes, entries[node.lhs.?].shape.length) },
            .hash_blake2s_leaf => .{ .shape = .{ .kind = .m31, .length = 8 }, .lanes = try hashBlake2sPersonalized(V, &ctx, entries[node.lhs.?].lanes, entries[node.lhs.?].shape.length, relation.leaf_personalization) },
            .hash_blake2s_pair => .{ .shape = .{ .kind = .m31, .length = 8 }, .lanes = try hashBlake2sPair(V, &ctx, entries[node.lhs.?].lanes, entries[node.rhs.?].lanes) },
            .select => blk: {
                const selector_entry = entries[node.selector.?];
                if (direct_output and !selector_entry.boolean) return error.UnsupportedDirectSelector;
                break :blk .{ .shape = .{ .kind = .m31, .length = node.length }, .lanes = try selectByBit(
                    V,
                    &ctx,
                    entries[node.lhs.?].lanes,
                    entries[node.rhs.?].lanes,
                    selector_entry.lanes,
                    if (direct_output) selector_entry.raw.?[0] else null,
                ) };
            },
            .hash_poseidon2_leaf => .{ .shape = .{ .kind = .m31, .length = 8 }, .lanes = try poseidon2.leafCircuit(V, &ctx, entries[node.lhs.?].lanes) },
            .hash_poseidon2_pair => .{ .shape = .{ .kind = .m31, .length = 8 }, .lanes = try poseidon2.pairCircuit(V, &ctx, entries[node.lhs.?].lanes, entries[node.rhs.?].lanes) },
        };
        if (maps) |out| try out.nodes.append(allocator, .{
            .id = @intCast(id),
            .qm31_start = qm31_start,
            .qm31_end = ctx.circuit.nQm31OpsRows(),
            .eq_start = eq_start,
            .eq_end = ctx.circuit.eq.items.len,
            .triple_xor_start = xor_start,
            .triple_xor_end = ctx.circuit.triple_xor.items.len,
            .m31_to_u32_start = conversion_start,
            .m31_to_u32_end = ctx.circuit.m31_to_u32.items.len,
            .blake_g_start = blake_start,
            .blake_g_end = ctx.circuit.blake_g_gate.items.len,
        });
    }

    for (ir.assertions, 0..) |assertion, index| {
        const qm31_start = ctx.circuit.nQm31OpsRows();
        const eq_start = ctx.circuit.eq.items.len;
        try circuit.builder.simd.eq(V, &ctx, entries[assertion.lhs].lanes, entries[assertion.rhs].lanes);
        if (maps) |out| try out.assertions.append(allocator, .{
            .index = index,
            .qm31_start = qm31_start,
            .qm31_end = ctx.circuit.nQm31OpsRows(),
            .eq_start = eq_start,
            .eq_end = ctx.circuit.eq.items.len,
        });
    }
    var outputs = [_]Var{ctx.zero()} ** N_RESERVED;
    var at: usize = 0;
    for (ir.nodes, entries) |node, entry| {
        if (node.tag != .input or node.visibility.? != .public) continue;
        const word_start = at;
        const conversion_qm31_start = ctx.circuit.nQm31OpsRows();
        const conversion_m31_start = ctx.circuit.m31_to_u32.items.len;
        for (0..entry.shape.length) |i| {
            outputs[at] = try outputWord(V, &ctx, entry, i, direct_output);
            at += 1;
        }
        if (maps) |out| try out.bindings.append(allocator, .{
            .name = node.input_name.?,
            .word_start = word_start,
            .word_count = at - word_start,
            .conversion_qm31_start = conversion_qm31_start,
            .conversion_qm31_end = ctx.circuit.nQm31OpsRows(),
            .conversion_m31_to_u32_start = conversion_m31_start,
            .conversion_m31_to_u32_end = ctx.circuit.m31_to_u32.items.len,
        });
    }
    for (ir.public_outputs) |output| {
        const entry = entries[output.id];
        const word_start = at;
        const conversion_qm31_start = ctx.circuit.nQm31OpsRows();
        const conversion_m31_start = ctx.circuit.m31_to_u32.items.len;
        for (0..entry.shape.length) |i| {
            outputs[at] = try outputWord(V, &ctx, entry, i, direct_output);
            at += 1;
        }
        if (maps) |out| try out.bindings.append(allocator, .{
            .name = output.name,
            .word_start = word_start,
            .word_count = at - word_start,
            .conversion_qm31_start = conversion_qm31_start,
            .conversion_qm31_end = ctx.circuit.nQm31OpsRows(),
            .conversion_m31_to_u32_start = conversion_m31_start,
            .conversion_m31_to_u32_end = ctx.circuit.m31_to_u32.items.len,
        });
    }
    const binding_base = ctx.circuit.nQm31OpsRows();
    try ctx.setOutputs(&outputs);
    if (maps) |out| for (out.bindings.items) |*binding| {
        binding.binding_qm31_start = binding_base + binding.word_start;
        binding.binding_qm31_end = binding.binding_qm31_start + binding.word_count;
    };
    const finalize_qm31_start = ctx.circuit.nQm31OpsRows();
    const finalize_m31_start = ctx.circuit.m31_to_u32.items.len;
    try ctx.finalize(false);
    if (maps) |out| out.finalization = .{
        .qm31_start = finalize_qm31_start,
        .qm31_end = ctx.circuit.nQm31OpsRows(),
        .m31_to_u32_start = finalize_m31_start,
        .m31_to_u32_end = ctx.circuit.m31_to_u32.items.len,
    };
    return ctx;
}

fn outputWord(comptime V: type, ctx: *circuit.builder.Context(V), entry: Entry, index: usize, direct_output: bool) !Var {
    const base = if (entry.raw) |raw| raw[index] else try circuit.builder.simd.unpackIdx(V, ctx, entry.lanes, index);
    return if (direct_output or entry.shape.kind == .u16) base else (try circuit.builder.blake.m31ToU32(V, ctx, base)).get();
}

/// Sum packed M31 coordinates with a QM31 linear functional. In the basis
/// (1, i, u, iu), where i² = -1 and u² = 2 + i, the base coordinate of
/// x * (1 - i + u/5 - 3iu/5) is a + b + c + d for
/// x = a + bi + cu + diu. A pointwise multiply by (1, 0, 0, 0) then extracts
/// that coordinate. These are ordinary constrained multiplication gates.
///
/// The final wire can have arbitrary unused coordinates, so mask them before
/// adding packed wires. The result is a one-lane base-field Simd.
fn sumLanes(comptime V: type, ctx: *circuit.builder.Context(V), input: Simd) !Simd {
    if (input.len == 1) return input;
    const wires = try ctx.scratch().dupe(Var, input.data);
    if (input.len % 4 != 0) {
        const n = input.len % 4;
        const mask = try ctx.constant(QM31.fromU32Unchecked(1, @intFromBool(n > 1), @intFromBool(n > 2), 0));
        wires[wires.len - 1] = try ctx.pointwiseMul(wires[wires.len - 1], mask);
    }
    var width = wires.len;
    while (width > 1) {
        var next: usize = 0;
        var index: usize = 0;
        while (index + 1 < width) : (index += 2) {
            wires[next] = try ctx.add(wires[index], wires[index + 1]);
            next += 1;
        }
        if (index < width) {
            wires[next] = wires[index];
            next += 1;
        }
        width = next;
    }
    const dual = try ctx.constant(QM31.fromU32Unchecked(1, 2147483646, 858993459, 1717986917));
    const projected = try ctx.mul(wires[0], dual);
    const base_mask = try ctx.constant(QM31.fromU32Unchecked(1, 0, 0, 0));
    const result = try ctx.pointwiseMul(projected, base_mask);
    const wire = try ctx.scratch().alloc(Var, 1);
    wire[0] = result;
    return Simd.fromPacked(wire, 1);
}

fn hashBlake2s(comptime V: type, ctx: *circuit.builder.Context(V), input: Simd, length: usize) !Simd {
    const digest = try circuit.builder.blake.blake2sM31(V, ctx, input.data, length * 4);
    const words = try ctx.scratch().alloc(Var, 2);
    words[0] = digest.low;
    words[1] = digest.high;
    return Simd.fromPacked(words, 8);
}

fn hashBlake2sPersonalized(comptime V: type, ctx: *circuit.builder.Context(V), input: Simd, length: usize, personalization: [8]u8) !Simd {
    const digest = try circuit.builder.blake.blake2sM31Personalized(V, ctx, input.data, length * 4, personalization);
    const words = try ctx.scratch().alloc(Var, 2);
    words[0] = digest.low;
    words[1] = digest.high;
    return Simd.fromPacked(words, 8);
}

fn hashBlake2sPair(comptime V: type, ctx: *circuit.builder.Context(V), lhs: Simd, rhs: Simd) !Simd {
    const input = try ctx.scratch().alloc(Var, lhs.data.len + rhs.data.len);
    @memcpy(input[0..lhs.data.len], lhs.data);
    @memcpy(input[lhs.data.len..], rhs.data);
    return hashBlake2sPersonalized(V, ctx, Simd.fromPacked(input, 16), 16, relation.pair_personalization);
}

fn isSelectorInput(nodes: []const canonical.Node, input_id: usize) bool {
    for (nodes) |node| if (node.tag == .select and node.selector.? == input_id) return true;
    return false;
}

fn selectByBit(comptime V: type, ctx: *circuit.builder.Context(V), lhs: Simd, rhs: Simd, selector: Simd, direct_bit: ?Var) !Simd {
    const bit = if (direct_bit) |raw| raw else try circuit.builder.simd.unpackIdx(V, ctx, selector, 0);
    if (direct_bit == null) try circuit.builder.simd.assertBits(V, ctx, selector);
    const left = try circuit.builder.simd.scalarMul(V, ctx, lhs, .newUnsafe(try ctx.sub(ctx.one(), bit)));
    const right = try circuit.builder.simd.scalarMul(V, ctx, rhs, .newUnsafe(bit));
    return circuit.builder.simd.add(V, ctx, left, right);
}

test "private preimage relation has a constrained witness and static topology" {
    var program = try relation.parseProgram(std.testing.allocator, @embedFile("examples/preimage4.s31.json"));
    defer program.deinit();
    var valid = try relation.parseAssignment(std.testing.allocator, @embedFile("examples/preimage4.valid.json"));
    defer valid.deinit();
    var invalid = try relation.parseAssignment(std.testing.allocator, @embedFile("examples/preimage4.invalid.json"));
    defer invalid.deinit();

    const words = try relation.evaluate(std.testing.allocator, program.value, valid.value);
    try std.testing.expectEqualSlices(u32, &.{ 8, 11, 16, 1771, 1, 4, 9, 1764 }, &words);
    try std.testing.expectError(error.AssertionFailed, relation.evaluate(std.testing.allocator, program.value, invalid.value));

    var with_values = try compile(QM31, std.testing.allocator, program.value, valid.value);
    defer with_values.deinit();
    var topology = try compile(circuit.builder.NoValue, std.testing.allocator, program.value, null);
    defer topology.deinit();
    try std.testing.expectEqual(with_values.circuit.n_vars, topology.circuit.n_vars);
    try std.testing.expect(std.meta.eql(with_values.gate_counts, topology.gate_counts));
    try std.testing.expect(try with_values.isCircuitValid());

    const invalid_ctx = compile(QM31, std.testing.allocator, program.value, invalid.value);
    if (invalid_ctx) |got| {
        var bad = got;
        defer bad.deinit();
        try std.testing.expect(!try bad.isCircuitValid());
    } else |err| {
        try std.testing.expectEqual(error.EqFailedOnEval, err);
    }
}

test "sum_lanes constrains partial and multiple packed wires" {
    const allocator = std.testing.allocator;
    for ([_]u32{ 1, 3, 4, 5, 8 }) |length| {
        var inputs = [_]relation.Input{.{ .name = "x", .kind = .m31, .length = length, .visibility = .private }};
        var nodes = [_]relation.Node{.{ .name = "total", .op = .sum_lanes, .lhs = "x" }};
        var outputs = [_][]const u8{"total"};
        const program: relation.Program = .{
            .version = 1,
            .name = "reduce",
            .inputs = &inputs,
            .nodes = &nodes,
            .assertions = &.{},
            .public_outputs = &outputs,
        };
        const selected: [2][]const u8 = switch (length) {
            1 => .{ "[2147483646]", "2147483646" },
            3 => .{ "[2147483646,2,3]", "4" },
            4 => .{ "[2147483646,2,3,4]", "8" },
            5 => .{ "[2147483646,2,3,4,5]", "13" },
            8 => .{ "[2147483646,2,3,4,5,6,7,8]", "34" },
            else => unreachable,
        };
        const input_json = selected[0];
        const expected = selected[1];
        const source = try std.fmt.allocPrint(allocator, "{{\"public_inputs\":{{}},\"private_inputs\":{{\"x\":{s}}},\"public_outputs\":{{\"total\":[{s}]}}}}", .{ input_json, expected });
        defer allocator.free(source);
        var assignment = try relation.parseAssignment(allocator, source);
        defer assignment.deinit();
        try std.testing.expectEqual(@as(u32, @intCast(try std.fmt.parseInt(u32, expected, 10))), (try relation.evaluate(allocator, program, assignment.value))[0]);
        var values = try compile(QM31, allocator, program, assignment.value);
        defer values.deinit();
        var topology = try compile(circuit.builder.NoValue, allocator, program, null);
        defer topology.deinit();
        try std.testing.expect(try values.isCircuitValid());
        // The private input needs exactly one QM31 witness per four lanes.
        // The final partial wire is masked by sumLanes before projection.
        try std.testing.expectEqual((length + 3) / 4, values.stats.guess);
        try std.testing.expectEqual(values.circuit.n_vars, topology.circuit.n_vars);
        try std.testing.expect(std.meta.eql(values.gate_counts, topology.gate_counts));
        var direct = try compileDirect(QM31, allocator, program, assignment.value, false);
        defer direct.deinit();
        try std.testing.expect(try direct.isCircuitValid());
    }
}

test "sum_lanes packed linear functional masks unused coordinates and reduces gates" {
    const dual = QM31.fromU32Unchecked(1, 2147483646, 858993459, 1717986917);
    for (0..4) |coordinate| {
        var basis = [_]u32{0} ** 4;
        basis[coordinate] = 1;
        const image = QM31.fromU32Unchecked(basis[0], basis[1], basis[2], basis[3]).mul(dual);
        try std.testing.expectEqual(@as(u32, 1), image.toM31Array()[0].v);
    }

    for ([_]struct { len: usize, expected: u32, gates: usize }{
        .{ .len = 1, .expected = 2147483646, .gates = 0 },
        .{ .len = 3, .expected = 4, .gates = 3 },
        .{ .len = 4, .expected = 8, .gates = 2 },
        .{ .len = 5, .expected = 13, .gates = 4 },
        .{ .len = 8, .expected = 34, .gates = 3 },
    }) |case| {
        var ctx = try circuit.builder.Context(QM31).init(std.testing.allocator, 0);
        defer ctx.deinit();
        const first = try ctx.guess(QM31.fromU32Unchecked(2147483646, 2, 3, 4));
        const second = try ctx.guess(QM31.fromU32Unchecked(5, 6, 7, 8));
        const data = [_]Var{ first, second };
        const before = ctx.circuit.nQm31OpsRows();
        const reduced = try sumLanes(QM31, &ctx, Simd.fromPacked(data[0 .. (case.len + 3) / 4], case.len));
        try std.testing.expectEqual(case.gates, ctx.circuit.nQm31OpsRows() - before);
        try std.testing.expectEqual(case.expected, ctx.get(reduced.data[0]).toM31Array()[0].v);
        try ctx.finalize(false);
        try std.testing.expect(try ctx.isCircuitValid());
    }
}

test "Poseidon2 path direct circuit satisfies both branch directions" {
    var program = try relation.parseProgram(std.testing.allocator, @embedFile("examples/merkle_path1_poseidon.s31.json"));
    defer program.deinit();
    var assignment = try relation.parseAssignment(std.testing.allocator, @embedFile("examples/merkle_path1_poseidon.valid.json"));
    defer assignment.deinit();
    var with_values = try compileDirect(QM31, std.testing.allocator, program.value, assignment.value, false);
    defer with_values.deinit();
    try std.testing.expect(try with_values.isCircuitValid());
}

test "random fixed relations agree with reference and have identical value and topology gates" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x5333_31a1);
    const random = prng.random();
    for (0..24) |_| {
        const offset = random.intRangeAtMost(u32, 1, 100);
        const scale = random.intRangeAtMost(u32, 2, 9);
        const rounds = random.intRangeAtMost(u32, 1, 3);
        var body = [_]relation.Step{ .{ .op = .square }, .{ .op = .add_const, .constant = 3 } };
        var inputs = [_]relation.Input{
            .{ .name = "target", .kind = .m31, .length = 4, .visibility = .public },
            .{ .name = "secret", .kind = .u16, .length = 4, .visibility = .private },
        };
        var nodes = [_]relation.Node{
            .{ .name = "field", .op = .cast_m31, .lhs = "secret" },
            .{ .name = "offset", .op = .add_const, .lhs = "field", .constant = offset },
            .{ .name = "scaled", .op = .mul_const, .lhs = "offset", .constant = scale },
            .{ .name = "final", .op = .repeat, .lhs = "scaled", .rounds = rounds, .body = &body },
        };
        var assertions = [_]relation.Assertion{.{ .lhs = "final", .rhs = "target" }};
        var outputs = [_][]const u8{"final"};
        const program: relation.Program = .{ .version = 1, .name = "random_relation", .inputs = &inputs, .nodes = &nodes, .assertions = &assertions, .public_outputs = &outputs };
        var secret: [4]u32 = undefined;
        var target: [4]u32 = undefined;
        for (&secret, &target) |*s, *t| {
            s.* = random.intRangeAtMost(u32, 0, 65535);
            var v = M31.fromCanonical(s.*).add(M31.fromCanonical(offset)).mul(M31.fromCanonical(scale));
            for (0..rounds) |_| v = v.mul(v).add(M31.fromCanonical(3));
            t.* = v.toU32();
        }
        const assignment_json = try std.fmt.allocPrint(allocator, "{{\"public_inputs\":{{\"target\":[{d},{d},{d},{d}]}},\"private_inputs\":{{\"secret\":[{d},{d},{d},{d}]}},\"public_outputs\":{{\"final\":[{d},{d},{d},{d}]}}}}", .{ target[0], target[1], target[2], target[3], secret[0], secret[1], secret[2], secret[3], target[0], target[1], target[2], target[3] });
        defer allocator.free(assignment_json);
        var assignment = try relation.parseAssignment(allocator, assignment_json);
        defer assignment.deinit();
        const expected = try relation.evaluate(allocator, program, assignment.value);
        try std.testing.expectEqualSlices(u32, &target, expected[4..8]);
        var value = try compile(QM31, allocator, program, assignment.value);
        defer value.deinit();
        var topology_ctx = try compile(circuit.builder.NoValue, allocator, program, null);
        defer topology_ctx.deinit();
        try std.testing.expect(try value.isCircuitValid());
        try std.testing.expectEqual(value.circuit.n_vars, topology_ctx.circuit.n_vars);
        inline for (.{ "add", "sub", "mul", "pointwise_mul", "eq", "triple_xor", "m31_to_u32", "blake_g_gate", "output" }) |field|
            try std.testing.expectEqualSlices(@TypeOf(@field(value.circuit, field).items[0]), @field(value.circuit, field).items, @field(topology_ctx.circuit, field).items);
        try std.testing.expectEqualSlices(@TypeOf(value.circuit.permutation.ends.items[0]), value.circuit.permutation.ends.items, topology_ctx.circuit.permutation.ends.items);
        try std.testing.expectEqualSlices(@TypeOf(value.circuit.permutation.inputs.items[0]), value.circuit.permutation.inputs.items, topology_ctx.circuit.permutation.inputs.items);
        try std.testing.expectEqualSlices(@TypeOf(value.circuit.permutation.outputs.items[0]), value.circuit.permutation.outputs.items, topology_ctx.circuit.permutation.outputs.items);
        var unoptimized = try compileRaw(QM31, allocator, program, assignment.value);
        defer unoptimized.deinit();
        try std.testing.expect(try unoptimized.isCircuitValid());
        try std.testing.expect(value.circuit.nQm31OpsRows() <= unoptimized.circuit.nQm31OpsRows());
    }
}

test "Blake2s relation matches the reference evaluator" {
    var program = try relation.parseProgram(std.testing.allocator, @embedFile("examples/hash4.s31.json"));
    defer program.deinit();
    var assignment = try relation.parseAssignment(std.testing.allocator, @embedFile("examples/hash4.valid.json"));
    defer assignment.deinit();
    _ = try relation.evaluate(std.testing.allocator, program.value, assignment.value);
    var ctx = try compile(QM31, std.testing.allocator, program.value, assignment.value);
    defer ctx.deinit();
    try std.testing.expect(try ctx.isCircuitValid());
}
