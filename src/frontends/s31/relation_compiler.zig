//! Circuit lowering for S31 relation IR v1. Public and private inputs use
//! identical constrained guesses; visibility changes only the public ABI.

const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const relation = @import("relation.zig");
const canonical = @import("canonical.zig");
const poseidon2 = @import("poseidon2.zig");
const sha256d = @import("sha256d.zig");
const bitcoin_target = @import("bitcoin_target.zig");
const bitcoin_work = @import("bitcoin_work.zig");

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
        const length: usize = if (node.op == .constant or node.op == .array_slice) node.length.? else if (node.op == .array_get or node.op == .sum_lanes or node.op == .u256_le or node.op == .u32_lt or node.op == .bool_not or node.op == .bool_and or node.op == .bool_or or node.op == .bool_xor or node.op == .bool_select) 1 else if (node.op == .array_concat) lhs.?.shape.length + rhs.?.shape.length else if (node.op == .bitcoin_genesis_hash_mainnet) 16 else if (node.op == .hash_blake2s or node.op == .hash_blake2s_leaf or node.op == .hash_blake2s_pair or node.op == .hash_poseidon2_leaf or node.op == .hash_poseidon2_pair) 8 else lhs.?.shape.length;
        const entry: Entry = switch (node.op) {
            .array_get => try arrayGet(V, &ctx, lhs.?, node.index.?),
            .array_slice => try arraySlice(V, &ctx, lhs.?, node.index.?, node.length.?),
            .array_concat => try arrayConcat(V, &ctx, lhs.?, rhs.?),
            .constant => .{ .shape = .{ .kind = .m31, .length = length }, .lanes = try circuit.builder.simd.repeat(V, &ctx, M31.fromCanonical(node.constant.?), length) },
            .bitcoin_genesis_hash_mainnet => try mainnetGenesisHash(V, &ctx),
            .cast_m31 => .{ .shape = .{ .kind = .m31, .length = length }, .lanes = lhs.?.lanes, .raw = lhs.?.raw },
            .add => .{ .shape = .{ .kind = .m31, .length = length }, .lanes = try circuit.builder.simd.add(V, &ctx, lhs.?.lanes, rhs.?.lanes) },
            .mul => .{ .shape = .{ .kind = .m31, .length = length }, .lanes = try circuit.builder.simd.mul(V, &ctx, lhs.?.lanes, rhs.?.lanes) },
            .inv => .{ .shape = .{ .kind = .m31, .length = length }, .lanes = try inverseLanes(V, &ctx, lhs.?.lanes) },
            .is_zero => try isZeroWord(V, &ctx, lhs.?),
            .bool_not => try booleanNode(V, &ctx, .not, lhs.?, null, null),
            .bool_and => try booleanNode(V, &ctx, .and_, lhs.?, rhs.?, null),
            .bool_or => try booleanNode(V, &ctx, .or_, lhs.?, rhs.?, null),
            .bool_xor => try booleanNode(V, &ctx, .xor_, lhs.?, rhs.?, null),
            .bool_select => try booleanNode(V, &ctx, .select, lhs.?, rhs.?, selector.?),
            .add_const => .{ .shape = .{ .kind = .m31, .length = length }, .lanes = try circuit.builder.simd.add(V, &ctx, lhs.?.lanes, try circuit.builder.simd.repeat(V, &ctx, M31.fromCanonical(node.constant.?), length)) },
            .mul_const => .{ .shape = .{ .kind = .m31, .length = length }, .lanes = try circuit.builder.simd.mul(V, &ctx, lhs.?.lanes, try circuit.builder.simd.repeat(V, &ctx, M31.fromCanonical(node.constant.?), length)) },
            .sum_lanes => .{ .shape = .{ .kind = .m31, .length = 1 }, .lanes = try sumLanes(V, &ctx, lhs.?.lanes) },
            .u256_add => try u256Binary(V, &ctx, lhs.?, rhs.?, .add),
            .u256_le => try u256Binary(V, &ctx, lhs.?, rhs.?, .le),
            .u32_lt => try u32Less(V, &ctx, lhs.?, rhs.?),
            .u256_add_checked => try u256Binary(V, &ctx, lhs.?, rhs.?, .add_checked),
            .u256_sub => try u256Binary(V, &ctx, lhs.?, rhs.?, .sub),
            .u256_sub_checked => try u256Binary(V, &ctx, lhs.?, rhs.?, .sub_checked),
            .hash_sha256d_header => try sha256dHeader(V, &ctx, lhs.?),
            .bitcoin_target_mainnet => try mainnetTarget(V, &ctx, lhs.?),
            .bitcoin_block_work => try blockWorkEntry(V, &ctx, lhs.?),
            .bitcoin_prev_hash => try headerSlice(V, &ctx, lhs.?, 2, 16),
            .bitcoin_header_bits => try headerSlice(V, &ctx, lhs.?, 36, 2),
            .bitcoin_header_time => try headerSlice(V, &ctx, lhs.?, 34, 2),
            .repeat => blk: {
                const constants = try scratch.alloc(?Simd, node.body.?.len);
                for (node.body.?, constants) |step, *slot| slot.* = if (step.constant) |value| try circuit.builder.simd.repeat(V, &ctx, M31.fromCanonical(value), length) else null;
                var current = lhs.?.lanes;
                for (0..node.rounds.?) |_| for (node.body.?, constants) |step, constant| {
                    current = switch (step.op) {
                        .square => try circuit.builder.simd.mul(V, &ctx, current, current),
                        .add_const => try circuit.builder.simd.add(V, &ctx, current, constant.?),
                        .mul_const => try circuit.builder.simd.mul(V, &ctx, current, constant.?),
                        .mix4 => try mix4(V, &ctx, current),
                    };
                };
                break :blk .{ .shape = .{ .kind = .m31, .length = length }, .lanes = current };
            },
            .hash_blake2s => .{ .shape = .{ .kind = .m31, .length = 8 }, .lanes = try hashBlake2s(V, &ctx, lhs.?.lanes, lhs.?.shape.length) },
            .hash_blake2s_leaf => .{ .shape = .{ .kind = .m31, .length = 8 }, .lanes = try hashBlake2sPersonalized(V, &ctx, lhs.?.lanes, lhs.?.shape.length, relation.leaf_personalization) },
            .hash_blake2s_pair => .{ .shape = .{ .kind = .m31, .length = 8 }, .lanes = try hashBlake2sPair(V, &ctx, lhs.?.lanes, rhs.?.lanes) },
            .select => if (lhs.?.shape.kind == .u16)
                try selectU16ByBit(V, &ctx, lhs.?, rhs.?, selector.?)
            else
                .{ .shape = .{ .kind = .m31, .length = length }, .lanes = try selectByBit(V, &ctx, lhs.?.lanes, rhs.?.lanes, selector.?.lanes, if (selector.?.boolean) selector.?.raw.?[0] else null) },
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
/// Canonical circuit Gate addresses consumed by one SHA caller AIR instance.
/// The first 40 belong to the byte-exact header, the final 16 to its digest.
pub const ShaBoundaryMap = struct { node_id: u32, addresses: [56]u32 };
pub const Maps = struct {
    nodes: std.ArrayListUnmanaged(Span) = .empty,
    assertions: std.ArrayListUnmanaged(AssertionSpan) = .empty,
    bindings: std.ArrayListUnmanaged(BindingSpan) = .empty,
    sha_boundaries: std.ArrayListUnmanaged(ShaBoundaryMap) = .empty,
    finalization: ?FinalizationSpan = null,

    pub fn deinit(self: *Maps, allocator: std.mem.Allocator) void {
        self.nodes.deinit(allocator);
        self.assertions.deinit(allocator);
        self.bindings.deinit(allocator);
        self.sha_boundaries.deinit(allocator);
        self.* = undefined;
    }
};

pub fn compile(comptime V: type, allocator: std.mem.Allocator, program: relation.Program, assignment: ?relation.Assignment) !circuit.builder.Context(V) {
    return compileWithSpans(V, allocator, program, assignment, null);
}

pub fn compileWithSpans(comptime V: type, allocator: std.mem.Allocator, program: relation.Program, assignment: ?relation.Assignment, maps: ?*Maps) !circuit.builder.Context(V) {
    return compileWithSpansMode(V, allocator, program, assignment, maps, false, false, false);
}

pub fn compileChip(comptime V: type, allocator: std.mem.Allocator, program: relation.Program, assignment: ?relation.Assignment) !circuit.builder.Context(V) {
    return compileWithSpansMode(V, allocator, program, assignment, null, true, false, false);
}

pub fn compileChipWithSpans(comptime V: type, allocator: std.mem.Allocator, program: relation.Program, assignment: ?relation.Assignment, maps: ?*Maps) !circuit.builder.Context(V) {
    return compileWithSpansMode(V, allocator, program, assignment, maps, true, false, false);
}

pub fn compileDirect(comptime V: type, allocator: std.mem.Allocator, program: relation.Program, assignment: ?relation.Assignment, chip_mode: bool) !circuit.builder.Context(V) {
    return compileWithSpansMode(V, allocator, program, assignment, null, chip_mode, true, false);
}

pub fn compileDirectWithSpans(comptime V: type, allocator: std.mem.Allocator, program: relation.Program, assignment: ?relation.Assignment, maps: ?*Maps, chip_mode: bool) !circuit.builder.Context(V) {
    return compileWithSpansMode(V, allocator, program, assignment, maps, chip_mode, true, false);
}

/// Replace generic SHA gates with 16 range-constrained digest witnesses and
/// report the exact private circuit addresses for an external SHA caller AIR.
/// This circuit is sound only as one component of the joint SHA proof.
pub fn compileShaChipWithSpans(comptime V: type, allocator: std.mem.Allocator, program: relation.Program, assignment: ?relation.Assignment, maps: *Maps) !circuit.builder.Context(V) {
    return compileWithSpansMode(V, allocator, program, assignment, maps, false, false, true);
}

fn compileWithSpansMode(comptime V: type, allocator: std.mem.Allocator, program: relation.Program, assignment: ?relation.Assignment, maps: ?*Maps, chip_mode: bool, direct_output: bool, sha_chip_mode: bool) !circuit.builder.Context(V) {
    if (chip_mode and program.repeatedStepChip() == null) return error.UnsupportedChipRelation;
    if (sha_chip_mode and (chip_mode or direct_output or maps == null)) return error.InvalidShaChipCompilerMode;
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
    const bit_sources = try scratch.alloc(bool, ir.nodes.len);
    @memset(bit_sources, false);
    for (ir.nodes) |node| {
        if (node.tag == .select or node.tag == .bool_select) bit_sources[node.selector.?] = true;
        if (node.tag == .bool_not or node.tag == .bool_and or node.tag == .bool_or or node.tag == .bool_xor or node.tag == .bool_select) {
            bit_sources[node.lhs.?] = true;
            if (node.rhs) |rhs| bit_sources[rhs] = true;
        }
    }
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
                const boolean = direct_output and bit_sources[id];
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
            .constant => blk: {
                if (direct_output and node.length == 1 and node.constant.? <= 1 and bit_sources[id]) {
                    const raw = try scratch.alloc(Var, 1);
                    raw[0] = try ctx.constant(QM31.fromBase(M31.fromCanonical(node.constant.?)));
                    break :blk .{ .shape = .{ .kind = .m31, .length = 1 }, .lanes = Simd.fromPacked(raw, 1), .raw = raw, .boolean = true };
                }
                break :blk .{ .shape = .{ .kind = .m31, .length = node.length }, .lanes = try circuit.builder.simd.repeat(V, &ctx, M31.fromCanonical(node.constant.?), node.length) };
            },
            .bitcoin_genesis_hash_mainnet => try mainnetGenesisHash(V, &ctx),
            .array_get => try arrayGet(V, &ctx, entries[node.lhs.?], node.index.?),
            .array_slice => try arraySlice(V, &ctx, entries[node.lhs.?], node.index.?, node.length),
            .array_concat => try arrayConcat(V, &ctx, entries[node.lhs.?], entries[node.rhs.?]),
            .cast_m31 => .{ .shape = .{ .kind = .m31, .length = node.length }, .lanes = entries[node.lhs.?].lanes, .raw = entries[node.lhs.?].raw, .boolean = entries[node.lhs.?].boolean },
            .add => .{ .shape = .{ .kind = .m31, .length = node.length }, .lanes = try circuit.builder.simd.add(V, &ctx, entries[node.lhs.?].lanes, entries[node.rhs.?].lanes) },
            .mul => .{ .shape = .{ .kind = .m31, .length = node.length }, .lanes = try circuit.builder.simd.mul(V, &ctx, entries[node.lhs.?].lanes, entries[node.rhs.?].lanes) },
            .inv => .{ .shape = .{ .kind = .m31, .length = node.length }, .lanes = try inverseLanes(V, &ctx, entries[node.lhs.?].lanes) },
            .is_zero => try isZeroWord(V, &ctx, entries[node.lhs.?]),
            .bool_not => try booleanNode(V, &ctx, .not, entries[node.lhs.?], null, null),
            .bool_and => try booleanNode(V, &ctx, .and_, entries[node.lhs.?], entries[node.rhs.?], null),
            .bool_or => try booleanNode(V, &ctx, .or_, entries[node.lhs.?], entries[node.rhs.?], null),
            .bool_xor => try booleanNode(V, &ctx, .xor_, entries[node.lhs.?], entries[node.rhs.?], null),
            .bool_select => try booleanNode(V, &ctx, .select, entries[node.lhs.?], entries[node.rhs.?], entries[node.selector.?]),
            .add_const => .{ .shape = .{ .kind = .m31, .length = node.length }, .lanes = try circuit.builder.simd.add(V, &ctx, entries[node.lhs.?].lanes, try circuit.builder.simd.repeat(V, &ctx, M31.fromCanonical(node.constant.?), node.length)) },
            .mul_const => .{ .shape = .{ .kind = .m31, .length = node.length }, .lanes = try circuit.builder.simd.mul(V, &ctx, entries[node.lhs.?].lanes, try circuit.builder.simd.repeat(V, &ctx, M31.fromCanonical(node.constant.?), node.length)) },
            .sum_lanes => .{ .shape = .{ .kind = .m31, .length = 1 }, .lanes = try sumLanes(V, &ctx, entries[node.lhs.?].lanes) },
            .u256_add => try u256Binary(V, &ctx, entries[node.lhs.?], entries[node.rhs.?], .add),
            .u256_le => try u256Binary(V, &ctx, entries[node.lhs.?], entries[node.rhs.?], .le),
            .u32_lt => try u32Less(V, &ctx, entries[node.lhs.?], entries[node.rhs.?]),
            .u256_add_checked => try u256Binary(V, &ctx, entries[node.lhs.?], entries[node.rhs.?], .add_checked),
            .u256_sub => try u256Binary(V, &ctx, entries[node.lhs.?], entries[node.rhs.?], .sub),
            .u256_sub_checked => try u256Binary(V, &ctx, entries[node.lhs.?], entries[node.rhs.?], .sub_checked),
            .hash_sha256d_header => blk: {
                if (!sha_chip_mode) break :blk try sha256dHeader(V, &ctx, entries[node.lhs.?]);
                const input = entries[node.lhs.?];
                const digest = try shaChipHeaderHint(V, &ctx, input);
                const header_raw = input.raw orelse return error.InvalidHeaderOperand;
                const digest_raw = digest.raw orelse unreachable;
                var addresses: [56]u32 = undefined;
                for (header_raw, 0..) |wire, i| addresses[i] = wire.idx;
                for (digest_raw, 0..) |wire, i| addresses[40 + i] = wire.idx;
                try maps.?.sha_boundaries.append(allocator, .{ .node_id = @intCast(id), .addresses = addresses });
                break :blk digest;
            },
            .bitcoin_target_mainnet => try mainnetTarget(V, &ctx, entries[node.lhs.?]),
            .bitcoin_block_work => try blockWorkEntry(V, &ctx, entries[node.lhs.?]),
            .bitcoin_prev_hash => try headerSlice(V, &ctx, entries[node.lhs.?], 2, 16),
            .bitcoin_header_bits => try headerSlice(V, &ctx, entries[node.lhs.?], 36, 2),
            .bitcoin_header_time => try headerSlice(V, &ctx, entries[node.lhs.?], 34, 2),
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
                        .mix4 => try mix4(V, &ctx, current),
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
                if (entries[node.lhs.?].shape.kind == .u16) break :blk try selectU16ByBit(
                    V,
                    &ctx,
                    entries[node.lhs.?],
                    entries[node.rhs.?],
                    selector_entry,
                );
                break :blk .{ .shape = .{ .kind = .m31, .length = node.length }, .lanes = try selectByBit(
                    V,
                    &ctx,
                    entries[node.lhs.?].lanes,
                    entries[node.rhs.?].lanes,
                    selector_entry.lanes,
                    if (selector_entry.boolean) selector_entry.raw.?[0] else null,
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
    if (sha_chip_mode and (maps.?.sha_boundaries.items.len == 0 or maps.?.sha_boundaries.items.len > 2))
        return error.UnsupportedShaChipRelation;
    if (direct_output and try ctx.circuit.firstYieldViolation(allocator) != null)
        return error.InvalidDirectYieldTopology;
    if (maps) |out| out.finalization = .{
        .qm31_start = finalize_qm31_start,
        .qm31_end = ctx.circuit.nQm31OpsRows(),
        .m31_to_u32_start = finalize_m31_start,
        .m31_to_u32_end = ctx.circuit.m31_to_u32.items.len,
    };
    return ctx;
}

fn arrayLane(comptime V: type, ctx: *circuit.builder.Context(V), entry: Entry, index: usize) !Var {
    if (entry.raw) |raw| return raw[index];
    return circuit.builder.simd.unpackIdx(V, ctx, entry.lanes, index);
}

fn arrayGet(comptime V: type, ctx: *circuit.builder.Context(V), entry: Entry, index: u32) !Entry {
    if (entry.raw) |raw| {
        const one = raw[index..][0..1];
        return .{ .shape = .{ .kind = entry.shape.kind, .length = 1 }, .lanes = Simd.fromPacked(one, 1), .raw = one, .boolean = entry.boolean };
    }
    if (index % 4 == 0) {
        const one = entry.lanes.data[index / 4 ..][0..1];
        return .{ .shape = .{ .kind = entry.shape.kind, .length = 1 }, .lanes = Simd.fromPacked(one, 1) };
    }
    const raw = try ctx.scratch().alloc(Var, 1);
    raw[0] = try arrayLane(V, ctx, entry, index);
    return .{ .shape = .{ .kind = entry.shape.kind, .length = 1 }, .lanes = Simd.fromPacked(raw, 1), .raw = raw };
}

fn arraySlice(comptime V: type, ctx: *circuit.builder.Context(V), entry: Entry, start: usize, length: usize) !Entry {
    const raw: ?[]Var = if (entry.raw) |words| words[start..][0..length] else null;
    if (start % 4 == 0) {
        const packed_wires = entry.lanes.data[start / 4 ..][0 .. (length + 3) / 4];
        return .{ .shape = .{ .kind = entry.shape.kind, .length = length }, .lanes = Simd.fromPacked(packed_wires, length), .raw = raw, .boolean = entry.boolean and length == 1 };
    }
    // A shifted view cannot borrow QM31 coordinates as a packed word. Unpack
    // the selected source coordinates and constrain their new packing.
    const wrappers = try ctx.scratch().alloc(circuit.builder.wrappers.M31Wrapper(Var), length);
    for (wrappers, 0..) |*wrapped, i| wrapped.* = .newUnsafe(try arrayLane(V, ctx, entry, start + i));
    return .{
        .shape = .{ .kind = entry.shape.kind, .length = length },
        .lanes = try circuit.builder.simd.pack(V, ctx, wrappers),
        .raw = raw,
        .boolean = entry.boolean and length == 1,
    };
}

fn arrayConcat(comptime V: type, ctx: *circuit.builder.Context(V), lhs: Entry, rhs: Entry) !Entry {
    const len = lhs.shape.length + rhs.shape.length;
    const raw: ?[]Var = if (lhs.raw != null and rhs.raw != null) blk: {
        const words = try ctx.scratch().alloc(Var, len);
        @memcpy(words[0..lhs.shape.length], lhs.raw.?);
        @memcpy(words[lhs.shape.length..], rhs.raw.?);
        break :blk words;
    } else null;
    if (lhs.shape.length % 4 == 0) {
        const packed_wires = try ctx.scratch().alloc(Var, lhs.lanes.data.len + rhs.lanes.data.len);
        @memcpy(packed_wires[0..lhs.lanes.data.len], lhs.lanes.data);
        @memcpy(packed_wires[lhs.lanes.data.len..], rhs.lanes.data);
        return .{ .shape = .{ .kind = lhs.shape.kind, .length = len }, .lanes = Simd.fromPacked(packed_wires, len), .raw = raw };
    }
    // Complete left-hand QM31 words are already in the right position. Only
    // the partial boundary word and the shifted right side need repacking.
    const prefix_wires = lhs.shape.length / 4;
    const prefix_lanes = prefix_wires * 4;
    const suffix_len = len - prefix_lanes;
    const wrappers = try ctx.scratch().alloc(circuit.builder.wrappers.M31Wrapper(Var), suffix_len);
    for (wrappers, 0..) |*wrapped, i| {
        const source_index = prefix_lanes + i;
        const lane = if (source_index < lhs.shape.length)
            try arrayLane(V, ctx, lhs, source_index)
        else
            try arrayLane(V, ctx, rhs, source_index - lhs.shape.length);
        wrapped.* = .newUnsafe(lane);
    }
    const suffix = try circuit.builder.simd.pack(V, ctx, wrappers);
    const packed_wires = try ctx.scratch().alloc(Var, prefix_wires + suffix.data.len);
    @memcpy(packed_wires[0..prefix_wires], lhs.lanes.data[0..prefix_wires]);
    @memcpy(packed_wires[prefix_wires..], suffix.data);
    return .{ .shape = .{ .kind = lhs.shape.kind, .length = len }, .lanes = Simd.fromPacked(packed_wires, len), .raw = raw };
}

fn outputWord(comptime V: type, ctx: *circuit.builder.Context(V), entry: Entry, index: usize, direct_output: bool) !Var {
    const base = if (entry.raw) |raw| raw[index] else try circuit.builder.simd.unpackIdx(V, ctx, entry.lanes, index);
    return if (direct_output or entry.shape.kind == .u16) base else (try circuit.builder.blake.m31ToU32(V, ctx, base)).get();
}

fn sha256dHeader(comptime V: type, ctx: *circuit.builder.Context(V), input: Entry) !Entry {
    const header = input.raw orelse return error.InvalidHeaderOperand;
    const digest = try sha256d.hashHeader(V, ctx, header);
    const raw = try ctx.scratch().dupe(Var, &digest);
    const wrappers = try ctx.scratch().alloc(circuit.builder.wrappers.M31Wrapper(Var), 16);
    for (raw, wrappers) |wire, *wrapped| wrapped.* = .newUnsafe(wire);
    return .{ .shape = .{ .kind = .u16, .length = 16 }, .lanes = try circuit.builder.simd.pack(V, ctx, wrappers), .raw = raw };
}

fn shaChipHeaderHint(comptime V: type, ctx: *circuit.builder.Context(V), input: Entry) !Entry {
    if (input.shape.kind != .u16 or input.shape.length != 40) return error.InvalidHeaderOperand;
    const header_raw = input.raw orelse return error.InvalidHeaderOperand;
    var digest: [32]u8 = @splat(0);
    if (comptime V == QM31) {
        var header: [80]u8 = undefined;
        for (header_raw, 0..) |wire, i| {
            const limbs = ctx.get(wire).toM31Array();
            if (!limbs[1].isZero() or !limbs[2].isZero() or !limbs[3].isZero() or limbs[0].toU32() >= 65536)
                return error.InvalidHeaderWitness;
            std.mem.writeInt(u16, header[2 * i ..][0..2], @intCast(limbs[0].toU32()), .little);
        }
        var first: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&header, &first, .{});
        std.crypto.hash.sha2.Sha256.hash(&first, &digest, .{});
    }
    const raw = try ctx.scratch().alloc(Var, 16);
    const wrappers = try ctx.scratch().alloc(circuit.builder.wrappers.M31Wrapper(Var), 16);
    for (raw, wrappers, 0..) |*wire, *wrapped, i| {
        const word = std.mem.readInt(u16, digest[2 * i ..][0..2], .little);
        const hint = circuit.builder.ivalue.fromQm31(V, QM31.fromBase(M31.fromCanonical(word)));
        wire.* = (try circuit.builder.wrappers.guessU16(V, ctx, .newUnsafe(hint))).get();
        wrapped.* = .newUnsafe(wire.*);
    }
    return .{ .shape = .{ .kind = .u16, .length = 16 }, .lanes = try circuit.builder.simd.pack(V, ctx, wrappers), .raw = raw };
}

fn mainnetTarget(comptime V: type, ctx: *circuit.builder.Context(V), input: Entry) !Entry {
    const header = input.raw orelse return error.InvalidHeaderOperand;
    const target = try bitcoin_target.mainnetTarget(V, ctx, header);
    const raw = try ctx.scratch().dupe(Var, &target);
    const wrappers = try ctx.scratch().alloc(circuit.builder.wrappers.M31Wrapper(Var), 16);
    for (raw, wrappers) |wire, *wrapped| wrapped.* = .newUnsafe(wire);
    return .{ .shape = .{ .kind = .u16, .length = 16 }, .lanes = try circuit.builder.simd.pack(V, ctx, wrappers), .raw = raw };
}

fn blockWorkEntry(comptime V: type, ctx: *circuit.builder.Context(V), input: Entry) !Entry {
    const raw_input = input.raw orelse return error.InvalidBlockWorkOperand;
    if (raw_input.len != 16) return error.InvalidBlockWorkOperand;
    var target: bitcoin_work.Words = undefined;
    @memcpy(&target, raw_input);
    const work = try bitcoin_work.blockWork(V, ctx, target);
    const raw = try ctx.scratch().dupe(Var, &work);
    const wrappers = try ctx.scratch().alloc(circuit.builder.wrappers.M31Wrapper(Var), 16);
    for (raw, wrappers) |wire, *wrapped| wrapped.* = .newUnsafe(wire);
    return .{ .shape = .{ .kind = .u16, .length = 16 }, .lanes = try circuit.builder.simd.pack(V, ctx, wrappers), .raw = raw };
}

fn headerSlice(comptime V: type, ctx: *circuit.builder.Context(V), input: Entry, start: usize, length: usize) !Entry {
    const header = input.raw orelse return error.InvalidHeaderOperand;
    if (header.len != 40 or start + length > header.len) return error.InvalidHeaderOperand;
    const raw = header[start .. start + length];
    const wrappers = try ctx.scratch().alloc(circuit.builder.wrappers.M31Wrapper(Var), length);
    for (raw, wrappers) |wire, *wrapped| wrapped.* = .newUnsafe(wire);
    return .{ .shape = .{ .kind = .u16, .length = length }, .lanes = try circuit.builder.simd.pack(V, ctx, wrappers), .raw = raw };
}

fn mainnetGenesisHash(comptime V: type, ctx: *circuit.builder.Context(V)) !Entry {
    const raw = try ctx.scratch().alloc(Var, 16);
    const wrappers = try ctx.scratch().alloc(circuit.builder.wrappers.M31Wrapper(Var), 16);
    for (raw, wrappers, 0..) |*wire, *wrapped, i| {
        const value = std.mem.readInt(u16, relation.mainnet_genesis_hash_raw[2 * i ..][0..2], .little);
        wire.* = try ctx.constant(QM31.fromBase(M31.fromCanonical(value)));
        wrapped.* = .newUnsafe(wire.*);
    }
    return .{ .shape = .{ .kind = .u16, .length = 16 }, .lanes = try circuit.builder.simd.pack(V, ctx, wrappers), .raw = raw };
}

/// Little-endian 16-bit limbs. Every output digit is range checked and every
/// carry/borrow is Boolean. Since each integer equation has magnitude below
/// 2^18 < p, equality in M31 is also equality over the integers.
const U256Mode = enum { add, add_checked, sub, sub_checked, le };

fn u256Binary(comptime V: type, ctx: *circuit.builder.Context(V), lhs: Entry, rhs: Entry, mode: U256Mode) !Entry {
    const left = lhs.raw orelse return error.InvalidU256Operand;
    const right = rhs.raw orelse return error.InvalidU256Operand;
    if (left.len != 16 or right.len != 16) return error.InvalidU256Operand;
    const base = try ctx.constant(QM31.fromBase(M31.fromCanonical(1 << 16)));
    const digits = try ctx.scratch().alloc(Var, 16);
    var incoming = ctx.zero();
    var carry_value: u32 = 0;
    const compare = mode == .le;
    const borrowing = compare or mode == .sub or mode == .sub_checked;
    for (left, right, digits) |a, b, *digit| {
        const av: u32 = if (comptime V == QM31) ctx.get(a).toM31Array()[0].v else 0;
        const bv: u32 = if (comptime V == QM31) ctx.get(b).toM31Array()[0].v else 0;
        const first = if (compare) bv else av;
        const second = if (compare) av else bv;
        const value: u32 = if (borrowing)
            (first + (1 << 16) - second - carry_value) & 0xffff
        else
            (av + bv + carry_value) & 0xffff;
        const next: u32 = if (borrowing)
            @intFromBool(first < second + carry_value)
        else
            (av + bv + carry_value) >> 16;
        digit.* = try ctx.guessU16(circuit.builder.ivalue.fromQm31(V, QM31.fromBase(M31.fromCanonical(value))));
        const outgoing = try ctx.guess(circuit.builder.ivalue.fromQm31(V, QM31.fromBase(M31.fromCanonical(next))));
        try ctx.eq(try ctx.mul(outgoing, outgoing), outgoing);
        const scaled = try ctx.mul(outgoing, base);
        if (borrowing) {
            const first_wire = if (compare) b else a;
            const second_wire = if (compare) a else b;
            try ctx.eq(try ctx.add(first_wire, scaled), try ctx.add(try ctx.add(second_wire, incoming), digit.*));
        } else {
            try ctx.eq(try ctx.add(try ctx.add(a, b), incoming), try ctx.add(digit.*, scaled));
        }
        incoming = outgoing;
        carry_value = next;
    }
    if (compare) {
        const result = try ctx.sub(ctx.one(), incoming);
        const output_wires = try ctx.scratch().alloc(Var, 1);
        output_wires[0] = result;
        return .{ .shape = .{ .kind = .m31, .length = 1 }, .lanes = Simd.fromPacked(output_wires, 1), .raw = output_wires, .boolean = true };
    }
    if (mode == .add_checked or mode == .sub_checked) try assertZeroArithmetic(V, ctx, incoming);
    const wrappers = try ctx.scratch().alloc(circuit.builder.wrappers.M31Wrapper(Var), 16);
    for (wrappers, digits) |*wrapped, digit| wrapped.* = .newUnsafe(digit);
    return .{ .shape = .{ .kind = .u16, .length = 16 }, .lanes = try circuit.builder.simd.pack(V, ctx, wrappers), .raw = digits };
}

/// Strict unsigned comparison of little-endian u16 limbs. We subtract
/// `lhs + 1` from `rhs`; a final borrow of zero is exactly `lhs < rhs`.
/// All intermediate integer equations are smaller than the M31 modulus.
fn u32Less(comptime V: type, ctx: *circuit.builder.Context(V), lhs: Entry, rhs: Entry) !Entry {
    const left = lhs.raw orelse return error.InvalidU32Operand;
    const right = rhs.raw orelse return error.InvalidU32Operand;
    if (left.len != 2 or right.len != 2) return error.InvalidU32Operand;
    const base = try ctx.constant(QM31.fromBase(M31.fromCanonical(1 << 16)));
    var incoming = ctx.one();
    var borrow_value: u32 = 1;
    for (left, right) |a, b| {
        const av: u32 = if (comptime V == QM31) ctx.get(a).toM31Array()[0].v else 0;
        const bv: u32 = if (comptime V == QM31) ctx.get(b).toM31Array()[0].v else 0;
        const digit_value = (bv + (1 << 16) - av - borrow_value) & 0xffff;
        const next: u32 = @intFromBool(bv < av + borrow_value);
        const digit = try ctx.guessU16(circuit.builder.ivalue.fromQm31(V, QM31.fromBase(M31.fromCanonical(digit_value))));
        const outgoing = try ctx.guess(circuit.builder.ivalue.fromQm31(V, QM31.fromBase(M31.fromCanonical(next))));
        try ctx.eq(try ctx.mul(outgoing, outgoing), outgoing);
        try ctx.eq(try ctx.add(b, try ctx.mul(outgoing, base)), try ctx.add(try ctx.add(a, incoming), digit));
        incoming = outgoing;
        borrow_value = next;
    }
    const result = try ctx.sub(ctx.one(), incoming);
    const wires = try ctx.scratch().alloc(Var, 1);
    wires[0] = result;
    return .{ .shape = .{ .kind = .m31, .length = 1 }, .lanes = Simd.fromPacked(wires, 1), .raw = wires, .boolean = true };
}

/// Enforce `value = 0` with one fresh self-loop: `anchor + value = anchor`.
/// The anchor has exactly one producing gate and its address is used as both
/// input and output of that gate. This preserves the direct AIR's LogUp
/// single-producer invariant while making the equation non-optional.
fn assertZeroArithmetic(comptime V: type, ctx: *circuit.builder.Context(V), value: Var) !void {
    const anchor = try ctx.newVar(circuit.builder.ivalue.fromQm31(V, QM31.zero()));
    try ctx.addInto(anchor, value, anchor);
}

/// A scalar zero test: x * inverse = 1 - z and x * z = 0. If x is zero,
/// z must be one; otherwise z must be zero and inverse is uniquely fixed.
/// Booleanity follows, without a separate bit AIR component.
fn isZeroWord(comptime V: type, ctx: *circuit.builder.Context(V), input: Entry) !Entry {
    if (input.shape.kind != .m31 or input.shape.length != 1) return error.InvalidZeroTestOperand;
    const word = if (input.raw) |raw| raw[0] else try circuit.builder.simd.unpackIdx(V, ctx, input.lanes, 0);
    const value = if (comptime V == QM31) try ctx.get(word).tryIntoM31() else M31.zero();
    const zero = value.isZero();
    const inverse_hint = if (zero) M31.zero() else try value.inv();
    const z = try ctx.guess(circuit.builder.ivalue.fromQm31(V, QM31.fromBase(M31.fromCanonical(@intFromBool(zero)))));
    const inverse = try ctx.guess(circuit.builder.ivalue.fromQm31(V, QM31.fromBase(inverse_hint)));
    const product = try ctx.mul(word, inverse);
    const one_minus_z = try ctx.sub(ctx.one(), z);
    try assertZeroArithmetic(V, ctx, try ctx.sub(product, one_minus_z));
    try assertZeroArithmetic(V, ctx, try ctx.mul(word, z));
    const raw = try ctx.scratch().alloc(Var, 1);
    raw[0] = z;
    return .{ .shape = .{ .kind = .m31, .length = 1 }, .lanes = Simd.fromPacked(raw, 1), .raw = raw, .boolean = true };
}

const BooleanKind = enum { not, and_, or_, xor_, select };

/// An arbitrary normalized m31 scalar is not a typed bit. If its producer has
/// not already proved Booleanity, bind b²-b=0 with an arithmetic self-loop.
/// The self-loop keeps the direct profile's one-producer lookup invariant.
fn checkedBitWord(comptime V: type, ctx: *circuit.builder.Context(V), input: Entry) !Var {
    if (input.shape.kind != .m31 or input.shape.length != 1) return error.InvalidBooleanOperand;
    const bit = if (input.raw) |raw| raw[0] else try circuit.builder.simd.unpackIdx(V, ctx, input.lanes, 0);
    if (!input.boolean) try assertZeroArithmetic(V, ctx, try ctx.sub(try ctx.mul(bit, bit), bit));
    return bit;
}

/// Boolean closure is algebraic once all operands are proved bits. The output
/// wire itself is an ordinary gate result, so no extra Boolean witness is
/// introduced and select can reuse it directly as a constrained selector.
fn booleanNode(comptime V: type, ctx: *circuit.builder.Context(V), kind: BooleanKind, lhs: Entry, rhs: ?Entry, selector: ?Entry) !Entry {
    const a = try checkedBitWord(V, ctx, lhs);
    const b = if (rhs) |entry| try checkedBitWord(V, ctx, entry) else ctx.zero();
    const s = if (selector) |entry| try checkedBitWord(V, ctx, entry) else ctx.zero();
    const result = switch (kind) {
        .not => try ctx.sub(ctx.one(), a),
        .and_ => try ctx.mul(a, b),
        .or_ => try ctx.sub(try ctx.add(a, b), try ctx.mul(a, b)),
        .xor_ => try ctx.sub(try ctx.add(a, b), try ctx.mul(try ctx.constant(QM31.fromBase(M31.fromCanonical(2))), try ctx.mul(a, b))),
        .select => try ctx.add(try ctx.mul(try ctx.sub(ctx.one(), s), a), try ctx.mul(s, b)),
    };
    const raw = try ctx.scratch().alloc(Var, 1);
    raw[0] = result;
    return .{ .shape = .{ .kind = .m31, .length = 1 }, .lanes = Simd.fromPacked(raw, 1), .raw = raw, .boolean = true };
}

/// Each packed group proves x * x_inv = 1 on active M31 lanes, while inactive
/// coordinates are zero. The self-loop assertion is required for the direct
/// profile's lookup closure; writing into the constant mask would give that
/// variable two producers and would not safely constrain the product.
fn inverseLanes(comptime V: type, ctx: *circuit.builder.Context(V), input: Simd) !Simd {
    const inverse = try circuit.builder.simd.guessInvOrZero(V, ctx, input);
    for (input.data, inverse.data, 0..) |x, inv, group| {
        const active = @min(@as(usize, 4), input.len - 4 * group);
        const expected = try ctx.constant(QM31.fromU32Unchecked(
            1,
            if (active > 1) 1 else 0,
            if (active > 2) 1 else 0,
            if (active > 3) 1 else 0,
        ));
        const product = try ctx.pointwiseMul(x, inv);
        try assertZeroArithmetic(V, ctx, try ctx.sub(product, expected));
    }
    return inverse;
}

/// Add the sum of all four lanes to each lane using one packed broadcast.
fn mix4(comptime V: type, ctx: *circuit.builder.Context(V), input: Simd) !Simd {
    if (input.len != 4) return error.InvalidMix4Length;
    const total = try sumLanes(V, ctx, input);
    const broadcast_factor = try ctx.constant(QM31.fromU32Unchecked(1, 1, 1, 1));
    const broadcast = try ctx.mul(total.data[0], broadcast_factor);
    const words = try ctx.scratch().alloc(Var, 1);
    words[0] = broadcast;
    return circuit.builder.simd.add(V, ctx, input, Simd.fromPacked(words, 4));
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

fn selectByBit(comptime V: type, ctx: *circuit.builder.Context(V), lhs: Simd, rhs: Simd, selector: Simd, direct_bit: ?Var) !Simd {
    const bit = if (direct_bit) |raw| raw else try circuit.builder.simd.unpackIdx(V, ctx, selector, 0);
    if (direct_bit == null) try circuit.builder.simd.assertBits(V, ctx, selector);
    const left = try circuit.builder.simd.scalarMul(V, ctx, lhs, .newUnsafe(try ctx.sub(ctx.one(), bit)));
    const right = try circuit.builder.simd.scalarMul(V, ctx, rhs, .newUnsafe(bit));
    return circuit.builder.simd.add(V, ctx, left, right);
}

/// A selected u16 is one of two range-checked input digits because the
/// selector is Boolean. The same constrained output wires remain available to
/// subsequent wide arithmetic; no fresh range witness is necessary.
fn selectU16ByBit(comptime V: type, ctx: *circuit.builder.Context(V), lhs: Entry, rhs: Entry, selector: Entry) !Entry {
    if (lhs.shape.length != rhs.shape.length) return error.InvalidU16Selection;
    const bit = try checkedBitWord(V, ctx, selector);
    const complement = try ctx.sub(ctx.one(), bit);
    const raw = try ctx.scratch().alloc(Var, lhs.shape.length);
    const wrappers = try ctx.scratch().alloc(circuit.builder.wrappers.M31Wrapper(Var), lhs.shape.length);
    for (raw, wrappers, 0..) |*wire, *wrapped, i| {
        const a = try arrayLane(V, ctx, lhs, i);
        const b = try arrayLane(V, ctx, rhs, i);
        wire.* = try ctx.add(try ctx.mul(complement, a), try ctx.mul(bit, b));
        wrapped.* = .newUnsafe(wire.*);
    }
    return .{ .shape = lhs.shape, .lanes = try circuit.builder.simd.pack(V, ctx, wrappers), .raw = raw };
}

test "direct Boolean operations constrain typed inputs and reject a field alias" {
    const allocator = std.testing.allocator;
    const source =
        \\{"version":1,"name":"bool_alias","inputs":[{"name":"a","kind":"m31","length":1,"visibility":"public"},{"name":"b","kind":"m31","length":1,"visibility":"private"}],"nodes":[{"name":"both","op":"bool_and","lhs":"a","rhs":"b"},{"name":"opposite","op":"bool_not","lhs":"both"},{"name":"result","op":"bool_select","selector":"a","lhs":"both","rhs":"opposite"}],"assertions":[],"public_outputs":["result"]}
    ;
    const good_json =
        \\{"public_inputs":{"a":[1]},"private_inputs":{"b":[1]},"public_outputs":{"result":[0]}}
    ;
    const alias_json =
        \\{"public_inputs":{"a":[1]},"private_inputs":{"b":[2]},"public_outputs":{"result":[0]}}
    ;
    var program = try relation.parseProgram(allocator, source);
    defer program.deinit();
    var good = try relation.parseAssignment(allocator, good_json);
    defer good.deinit();
    var alias = try relation.parseAssignment(allocator, alias_json);
    defer alias.deinit();
    var circuit_values = try compileDirect(QM31, allocator, program.value, good.value, false);
    defer circuit_values.deinit();
    var generic = try compile(QM31, allocator, program.value, good.value);
    defer generic.deinit();
    var raw = try compileRaw(QM31, allocator, program.value, good.value);
    defer raw.deinit();
    var topology = try compileDirect(circuit.builder.NoValue, allocator, program.value, null, false);
    defer topology.deinit();
    try std.testing.expect(try circuit_values.isCircuitValid());
    try std.testing.expect(try generic.isCircuitValid());
    try std.testing.expect(try raw.isCircuitValid());
    try std.testing.expectEqual(circuit_values.circuit.n_vars, topology.circuit.n_vars);
    try std.testing.expect(std.meta.eql(circuit_values.gate_counts, topology.gate_counts));
    try std.testing.expectEqual(@as(usize, 0), circuit_values.circuit.eq.items.len);
    try std.testing.expectError(error.InvalidBooleanOperand, relation.evaluate(allocator, program.value, alias.value));
    const bad_result = compileDirect(QM31, allocator, program.value, alias.value, false);
    if (bad_result) |bad| {
        var invalid = bad;
        defer invalid.deinit();
        try std.testing.expect(!try invalid.isCircuitValid());
    } else |err| {
        try std.testing.expect(err == error.EqFailedOnEval or err == error.MulFailedOnEval);
    }
}

test "Boolean library example has stable direct arithmetic geometry" {
    const allocator = std.testing.allocator;
    var baseline_program = try relation.parseProgram(allocator, @embedFile("examples/computed_choice.s31.json"));
    defer baseline_program.deinit();
    var baseline_assignment = try relation.parseAssignment(allocator, @embedFile("examples/computed_choice.valid.json"));
    defer baseline_assignment.deinit();
    var baseline = try compileDirect(QM31, allocator, baseline_program.value, baseline_assignment.value, false);
    defer baseline.deinit();
    var program = try relation.parseProgram(allocator, @embedFile("examples/bool_computed_choice.s31.json"));
    defer program.deinit();
    var assignment = try relation.parseAssignment(allocator, @embedFile("examples/bool_computed_choice.valid.json"));
    defer assignment.deinit();
    var boolean = try compileDirect(QM31, allocator, program.value, assignment.value, false);
    defer boolean.deinit();
    try std.testing.expect(try baseline.isCircuitValid());
    try std.testing.expect(try boolean.isCircuitValid());
    try std.testing.expectEqual(@as(usize, 0), boolean.circuit.eq.items.len);
    std.debug.print("S31_BOOLEAN_GEOMETRY baseline_qm31_rows={d} boolean_qm31_rows={d} boolean_eq_rows={d}\n", .{
        baseline.circuit.nQm31OpsRows(), boolean.circuit.nQm31OpsRows(), boolean.circuit.eq.items.len,
    });
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

test "SHA chip lowering identifies stable private wires and charges 56 Gate yields" {
    const allocator = std.testing.allocator;
    var program = try relation.parseProgram(allocator, @embedFile("examples/bitcoin_header_pow.s31.json"));
    defer program.deinit();
    var assignment = try relation.parseAssignment(allocator, @embedFile("examples/bitcoin_header_pow.valid.json"));
    defer assignment.deinit();

    var value_maps = Maps{};
    defer value_maps.deinit(allocator);
    var values = try compileShaChipWithSpans(QM31, allocator, program.value, assignment.value, &value_maps);
    defer values.deinit();
    try std.testing.expect(try values.isCircuitValid());
    try std.testing.expectEqual(@as(usize, 1), value_maps.sha_boundaries.items.len);

    var topology_maps = Maps{};
    defer topology_maps.deinit(allocator);
    var topology = try compileShaChipWithSpans(circuit.builder.NoValue, allocator, program.value, null, &topology_maps);
    defer topology.deinit();
    try std.testing.expectEqual(@as(usize, 1), topology_maps.sha_boundaries.items.len);
    const addresses = value_maps.sha_boundaries.items[0].addresses;
    try std.testing.expectEqualSlices(u32, &addresses, &topology_maps.sha_boundaries.items[0].addresses);
    try std.testing.expectEqual(values.circuit.n_vars, topology.circuit.n_vars);
    try std.testing.expect(std.meta.eql(values.gate_counts, topology.gate_counts));

    const source = circuit.common.preprocessed.CircuitView.fromBuilder(&topology.circuit);
    try (circuit.common.sparse_arithmetic.ShaBoundary{ .addresses = addresses }).validate(source);
    var duplicate = addresses;
    duplicate[1] = duplicate[0];
    try std.testing.expectError(
        error.DuplicateShaPrivateBoundary,
        (circuit.common.sparse_arithmetic.ShaBoundary{ .addresses = duplicate }).validate(source),
    );
    var public_address = addresses;
    var found_public: ?u32 = null;
    for (source.output) |address| {
        if (address > 2 and address < source.n_vars) {
            found_public = address;
            break;
        }
    }
    public_address[0] = found_public orelse return error.MissingPublicOutputForTest;
    try std.testing.expectError(
        error.PublicShaPrivateBoundary,
        (circuit.common.sparse_arithmetic.ShaBoundary{ .addresses = public_address }).validate(source),
    );
    const raw = circuit.common.finalize.rawComponentSizes(source);
    // The generic genesis-header circuit uses 356,882 raw QM31 rows. This
    // bound catches an accidental fallback to generic SHA during chip lowering.
    try std.testing.expect(raw.qm31_ops < 10_000);
    try circuit.common.finalize.padToTargets(circuit.builder.NoValue, &topology, .{
        .eq = circuit.common.finalize.paddedSize(raw.eq),
        .qm31_ops = circuit.common.finalize.paddedSize(raw.qm31_ops),
        .m31_to_u32 = circuit.common.finalize.paddedSize(raw.m31_to_u32),
        .triple_xor = 0,
        .blake_g_gate = 0,
    });
    var ordinary = try circuit.common.sparse_wide.Circuit.fromBuilderCircuit(allocator, &topology.circuit);
    defer ordinary.deinit(allocator);
    var linked = try circuit.common.sparse_wide.Circuit.fromBuilderCircuitWithShaBoundary(
        allocator,
        &topology.circuit,
        .{ .addresses = addresses },
    );
    defer linked.deinit(allocator);
    try std.testing.expect(linked.sha_boundary != null);

    var extra_yields: usize = 0;
    inline for (.{ "qm31_ops_mults", "m31_to_u32_multiplicity" }) |id| {
        const before = ordinary.columnValues(id).?;
        const after = linked.columnValues(id).?;
        for (before, after) |old, new| {
            const delta = new.sub(old).toU32();
            try std.testing.expect(delta <= 1);
            extra_yields += delta;
        }
    }
    try std.testing.expectEqual(@as(usize, 56), extra_yields);
}

test "two-header SHA chip lowering charges two disjoint private caller boundaries" {
    const allocator = std.testing.allocator;
    var program = try relation.parseProgram(allocator, @embedFile("examples/bitcoin_header_pair.s31.json"));
    defer program.deinit();
    var assignment = try relation.parseAssignment(allocator, @embedFile("examples/bitcoin_header_pair.valid.json"));
    defer assignment.deinit();

    var value_maps = Maps{};
    defer value_maps.deinit(allocator);
    var values = try compileShaChipWithSpans(QM31, allocator, program.value, assignment.value, &value_maps);
    defer values.deinit();
    try std.testing.expect(try values.isCircuitValid());
    try std.testing.expectEqual(@as(usize, 2), value_maps.sha_boundaries.items.len);

    var topology_maps = Maps{};
    defer topology_maps.deinit(allocator);
    var topology = try compileShaChipWithSpans(circuit.builder.NoValue, allocator, program.value, null, &topology_maps);
    defer topology.deinit();
    try std.testing.expectEqual(@as(usize, 2), topology_maps.sha_boundaries.items.len);
    try std.testing.expectEqual(values.circuit.n_vars, topology.circuit.n_vars);
    try std.testing.expect(std.meta.eql(values.gate_counts, topology.gate_counts));
    const pair = circuit.common.sparse_arithmetic.ShaBoundaryPair{
        .first = .{ .addresses = value_maps.sha_boundaries.items[0].addresses },
        .second = .{ .addresses = value_maps.sha_boundaries.items[1].addresses },
    };
    for (value_maps.sha_boundaries.items, topology_maps.sha_boundaries.items) |value, shape|
        try std.testing.expectEqualSlices(u32, &value.addresses, &shape.addresses);
    const source = circuit.common.preprocessed.CircuitView.fromBuilder(&topology.circuit);
    try pair.validate(source);
    var alias = pair;
    alias.second.addresses[0] = alias.first.addresses[0];
    try std.testing.expectError(error.DuplicateShaPrivateBoundary, alias.validate(source));

    const raw = circuit.common.finalize.rawComponentSizes(source);
    try std.testing.expect(raw.qm31_ops < 20_000);
    try circuit.common.finalize.padToTargets(circuit.builder.NoValue, &topology, .{
        .eq = circuit.common.finalize.paddedSize(raw.eq),
        .qm31_ops = circuit.common.finalize.paddedSize(raw.qm31_ops),
        .m31_to_u32 = circuit.common.finalize.paddedSize(raw.m31_to_u32),
        .triple_xor = 0,
        .blake_g_gate = 0,
    });
    var ordinary = try circuit.common.sparse_wide.Circuit.fromBuilderCircuit(allocator, &topology.circuit);
    defer ordinary.deinit(allocator);
    var linked = try circuit.common.sparse_wide.Circuit.fromBuilderCircuitWithShaBoundaryPair(allocator, &topology.circuit, pair);
    defer linked.deinit(allocator);
    try std.testing.expect(linked.sha_boundary == null);
    try std.testing.expect(linked.sha_boundary_pair != null);

    var extra_yields: usize = 0;
    inline for (.{ "qm31_ops_mults", "m31_to_u32_multiplicity" }) |id| {
        const before = ordinary.columnValues(id).?;
        const after = linked.columnValues(id).?;
        for (before, after) |old, new| {
            const delta = new.sub(old).toU32();
            try std.testing.expect(delta <= 1);
            extra_yields += delta;
        }
    }
    try std.testing.expectEqual(@as(usize, 112), extra_yields);
}

test "computed zero test has single-yield direct circuit topology" {
    var program = try relation.parseProgram(std.testing.allocator, @embedFile("examples/computed_choice.s31.json"));
    defer program.deinit();
    var assignment = try relation.parseAssignment(std.testing.allocator, @embedFile("examples/computed_choice.valid.json"));
    defer assignment.deinit();
    var value_ctx = try compileDirect(QM31, std.testing.allocator, program.value, assignment.value, false);
    defer value_ctx.deinit();
    try std.testing.expect(try value_ctx.isCircuitValid());
    const violation = try value_ctx.circuit.firstYieldViolation(std.testing.allocator);
    if (violation) |item| std.debug.print("computed zero yield violation: {any}\n", .{item});
    try std.testing.expect(violation == null);
}

test "checked inverse has single-yield direct circuit topology" {
    var program = try relation.parseProgram(std.testing.allocator, @embedFile("examples/field_div4.s31.json"));
    defer program.deinit();
    var assignment = try relation.parseAssignment(std.testing.allocator, @embedFile("examples/field_div4.valid.json"));
    defer assignment.deinit();
    var value_ctx = try compileDirect(QM31, std.testing.allocator, program.value, assignment.value, false);
    defer value_ctx.deinit();
    try std.testing.expect(try value_ctx.isCircuitValid());
    try std.testing.expect((try value_ctx.circuit.firstYieldViolation(std.testing.allocator)) == null);
}

test "constant zero bit selects in the direct profile" {
    const source =
        \\{"version":1,"name":"constant_choice","inputs":[{"name":"left","kind":"m31","length":1,"visibility":"public"},{"name":"right","kind":"m31","length":1,"visibility":"public"}],"nodes":[{"name":"zero","op":"constant","constant":1,"length":1},{"name":"result","op":"select","lhs":"left","rhs":"right","selector":"zero"}],"assertions":[],"public_outputs":["result"]}
    ;
    const assigned =
        \\{"public_inputs":{"left":[17],"right":[23]},"private_inputs":{},"public_outputs":{"result":[23]}}
    ;
    var program = try relation.parseProgram(std.testing.allocator, source);
    defer program.deinit();
    var assignment = try relation.parseAssignment(std.testing.allocator, assigned);
    defer assignment.deinit();
    var ctx = try compileDirect(QM31, std.testing.allocator, program.value, assignment.value, false);
    defer ctx.deinit();
    try std.testing.expect(try ctx.isCircuitValid());
    try std.testing.expect((try ctx.circuit.firstYieldViolation(std.testing.allocator)) == null);
}

test "packed lane reductions retain single-yield direct topology" {
    var program = try relation.parseProgram(std.testing.allocator, @embedFile("examples/lane_stats4.s31.json"));
    defer program.deinit();
    var assignment = try relation.parseAssignment(std.testing.allocator, @embedFile("examples/lane_stats4.valid.json"));
    defer assignment.deinit();
    var ctx = try compileDirect(QM31, std.testing.allocator, program.value, assignment.value, false);
    defer ctx.deinit();
    try std.testing.expect(try ctx.isCircuitValid());
    try std.testing.expect((try ctx.circuit.firstYieldViolation(std.testing.allocator)) == null);
}

test "array indexing and concatenation preserve packed alignment and constrain shifted lanes" {
    const aligned_source =
        \\{"version":1,"name":"aligned_array","inputs":[{"name":"a","kind":"m31","length":4,"visibility":"private"},{"name":"b","kind":"m31","length":4,"visibility":"private"}],"nodes":[{"name":"joined","op":"array_concat","lhs":"a","rhs":"b"},{"name":"chosen","op":"array_get","lhs":"joined","index":4}],"assertions":[],"public_outputs":["chosen"]}
    ;
    const shifted_source =
        \\{"version":1,"name":"shifted_array","inputs":[{"name":"a","kind":"m31","length":3,"visibility":"private"},{"name":"b","kind":"m31","length":4,"visibility":"private"}],"nodes":[{"name":"joined","op":"array_concat","lhs":"a","rhs":"b"},{"name":"chosen","op":"array_get","lhs":"joined","index":5}],"assertions":[],"public_outputs":["chosen"]}
    ;
    const aligned_assignment =
        \\{"public_inputs":{},"private_inputs":{"a":[1,2,3,4],"b":[5,6,7,8]},"public_outputs":{"chosen":[5]}}
    ;
    const shifted_assignment =
        \\{"public_inputs":{},"private_inputs":{"a":[1,2,3],"b":[4,5,6,7]},"public_outputs":{"chosen":[6]}}
    ;
    for ([_][]const u8{ aligned_source, shifted_source }, [_][]const u8{ aligned_assignment, shifted_assignment }, 0..) |source, assigned, case_index| {
        var program = try relation.parseProgram(std.testing.allocator, source);
        defer program.deinit();
        var assignment = try relation.parseAssignment(std.testing.allocator, assigned);
        defer assignment.deinit();
        _ = try relation.evaluate(std.testing.allocator, program.value, assignment.value);
        var maps = Maps{};
        defer maps.deinit(std.testing.allocator);
        var ctx = try compileDirectWithSpans(QM31, std.testing.allocator, program.value, assignment.value, &maps, false);
        defer ctx.deinit();
        try std.testing.expect(try ctx.isCircuitValid());
        try std.testing.expect((try ctx.circuit.firstYieldViolation(std.testing.allocator)) == null);
        // Two input spans precede concat and get. Aligned operations borrow
        // existing packed wires; the shifted case must constrain extraction.
        try std.testing.expectEqual(@as(usize, 4), maps.nodes.items.len);
        const concat = maps.nodes.items[2];
        const get = maps.nodes.items[3];
        if (case_index == 0) {
            try std.testing.expectEqual(concat.qm31_start, concat.qm31_end);
            try std.testing.expectEqual(get.qm31_start, get.qm31_end);
        } else {
            try std.testing.expect(concat.qm31_end > concat.qm31_start);
            try std.testing.expect(get.qm31_end > get.qm31_start);
        }
        // The selected value is copied into the public output from a wire
        // produced by the source-lane extraction. Corrupt that intermediate
        // witness while retaining the original source and output values.
        const public_wire = ctx.circuit.output.items[ctx.circuit.output.items.len - 1];
        var selected_wire: ?u32 = null;
        for (ctx.circuit.add.items) |gate| if (gate.out == public_wire) {
            selected_wire = gate.in0;
            break;
        };
        const selected = selected_wire orelse return error.MissingArrayOutputBinding;
        const original = ctx.value_table.items[selected];
        ctx.value_table.items[selected] = original.add(core.fields.qm31.QM31.one());
        try std.testing.expect(!try ctx.isCircuitValid());
        ctx.value_table.items[selected] = original;
        try std.testing.expect(try ctx.isCircuitValid());
    }
}

test "runtime slices borrow aligned packed words and constrain shifted words" {
    const cases = .{
        .{ "array_slice_aligned", @embedFile("examples/array_slice_aligned.s31.json"), @embedFile("examples/array_slice_aligned.valid.json") },
        .{ "array_slice_shifted", @embedFile("examples/array_slice_shifted.s31.json"), @embedFile("examples/array_slice_shifted.valid.json") },
        .{ "array_matrix_runtime", @embedFile("examples/array_matrix_runtime.s31.json"), @embedFile("examples/array_matrix_runtime.valid.json") },
        .{ "array_slice_u16", @embedFile("examples/array_slice_u16.s31.json"), @embedFile("examples/array_slice_u16.valid.json") },
    };
    inline for (cases) |case| {
        var program = try relation.parseProgram(std.testing.allocator, case[1]);
        defer program.deinit();
        var assignment = try relation.parseAssignment(std.testing.allocator, case[2]);
        defer assignment.deinit();
        _ = try relation.evaluate(std.testing.allocator, program.value, assignment.value);
        var maps = Maps{};
        defer maps.deinit(std.testing.allocator);
        var ctx = if (std.mem.eql(u8, case[0], "array_slice_u16"))
            try compileWithSpansMode(QM31, std.testing.allocator, program.value, assignment.value, &maps, false, false, false)
        else
            try compileDirectWithSpans(QM31, std.testing.allocator, program.value, assignment.value, &maps, false);
        defer ctx.deinit();
        try std.testing.expect(try ctx.isCircuitValid());
        try std.testing.expect((try ctx.circuit.firstYieldViolation(std.testing.allocator)) == null);
        const source_span = maps.nodes.items[1];
        if (std.mem.eql(u8, case[0], "array_slice_shifted") or std.mem.eql(u8, case[0], "array_slice_u16")) {
            try std.testing.expect(source_span.qm31_end > source_span.qm31_start);
        } else {
            try std.testing.expectEqual(source_span.qm31_start, source_span.qm31_end);
        }
    }
}

test "u16 array views keep bounded words in the generic circuit" {
    const source =
        \\{"version":1,"name":"u16_array","inputs":[{"name":"a","kind":"u16","length":2,"visibility":"private"},{"name":"b","kind":"u16","length":2,"visibility":"private"}],"nodes":[{"name":"joined","op":"array_concat","lhs":"a","rhs":"b"},{"name":"picked","op":"array_get","lhs":"joined","index":2}],"assertions":[],"public_outputs":["picked"]}
    ;
    const assigned =
        \\{"public_inputs":{},"private_inputs":{"a":[1,65535],"b":[32768,7]},"public_outputs":{"picked":[32768]}}
    ;
    var program = try relation.parseProgram(std.testing.allocator, source);
    defer program.deinit();
    var assignment = try relation.parseAssignment(std.testing.allocator, assigned);
    defer assignment.deinit();
    _ = try relation.evaluate(std.testing.allocator, program.value, assignment.value);
    var values = try compile(QM31, std.testing.allocator, program.value, assignment.value);
    defer values.deinit();
    var topology = try compile(circuit.builder.NoValue, std.testing.allocator, program.value, null);
    defer topology.deinit();
    try std.testing.expect(try values.isCircuitValid());
    try std.testing.expectEqual(values.circuit.n_vars, topology.circuit.n_vars);
    try std.testing.expect(std.meta.eql(values.gate_counts, topology.gate_counts));
}

test "strict u32 comparison constrains equality, borrow, and limb boundary" {
    const source =
        \\{"version":1,"name":"strict_u32","inputs":[{"name":"a","kind":"u16","length":2,"visibility":"private"},{"name":"b","kind":"u16","length":2,"visibility":"private"}],"nodes":[{"name":"less","op":"u32_lt","lhs":"a","rhs":"b"}],"assertions":[],"public_outputs":["less"]}
    ;
    var program = try relation.parseProgram(std.testing.allocator, source);
    defer program.deinit();
    const cases = [_]struct { a: [2]u32, b: [2]u32, less: u32 }{
        .{ .a = .{ 0, 0 }, .b = .{ 1, 0 }, .less = 1 },
        .{ .a = .{ 65535, 0 }, .b = .{ 0, 1 }, .less = 1 },
        .{ .a = .{ 0, 1 }, .b = .{ 65535, 0 }, .less = 0 },
        .{ .a = .{ 65535, 65535 }, .b = .{ 65535, 65535 }, .less = 0 },
    };
    var topology = try compile(circuit.builder.NoValue, std.testing.allocator, program.value, null);
    defer topology.deinit();
    for (cases) |case| {
        const assignment_json = try std.fmt.allocPrint(std.testing.allocator, "{{\"public_inputs\":{{}},\"private_inputs\":{{\"a\":[{d},{d}],\"b\":[{d},{d}]}},\"public_outputs\":{{\"less\":[{d}]}}}}", .{ case.a[0], case.a[1], case.b[0], case.b[1], case.less });
        defer std.testing.allocator.free(assignment_json);
        var assignment = try relation.parseAssignment(std.testing.allocator, assignment_json);
        defer assignment.deinit();
        const words = try relation.evaluate(std.testing.allocator, program.value, assignment.value);
        try std.testing.expectEqual(case.less, words[0]);
        var values = try compile(QM31, std.testing.allocator, program.value, assignment.value);
        defer values.deinit();
        try std.testing.expectEqual(topology.circuit.n_vars, values.circuit.n_vars);
        try std.testing.expect(try values.isCircuitValid());
    }
}

test "wide integer carries and borrows are constrained with stable topology" {
    var program = try relation.parseProgram(std.testing.allocator, @embedFile("examples/wide_order.s31.json"));
    defer program.deinit();
    var valid = try relation.parseAssignment(std.testing.allocator, @embedFile("examples/wide_order.valid.json"));
    defer valid.deinit();

    const words = try relation.evaluate(std.testing.allocator, program.value, valid.value);
    try std.testing.expectEqualSlices(u32, &.{ 1516562408, 720678098, 331586352, 1266462312, 857462184, 360942592, 889867968, 271788129 }, &words);
    var values = try compile(QM31, std.testing.allocator, program.value, valid.value);
    defer values.deinit();
    var topology = try compile(circuit.builder.NoValue, std.testing.allocator, program.value, null);
    defer topology.deinit();
    try std.testing.expectEqual(values.circuit.n_vars, topology.circuit.n_vars);
    try std.testing.expect(std.meta.eql(values.gate_counts, topology.gate_counts));
    try std.testing.expect(try values.isCircuitValid());

    // A different target still has valid u16 digits, but it breaks the
    // constrained 256-bit addition before a proof can be produced.
    var private = &valid.value.private_inputs.?;
    private.object.getPtr("target").?.array.items[1] = .{ .integer = 2 };
    try std.testing.expectError(error.AssertionFailed, relation.evaluate(std.testing.allocator, program.value, valid.value));
    const invalid_ctx = compile(QM31, std.testing.allocator, program.value, valid.value);
    if (invalid_ctx) |got| {
        var bad = got;
        defer bad.deinit();
        try std.testing.expect(!try bad.isCircuitValid());
    } else |err| {
        try std.testing.expectEqual(error.EqFailedOnEval, err);
    }

    program.value.nodes[0].op = .u256_add_checked;
    var overflow = try relation.parseAssignment(std.testing.allocator, @embedFile("examples/wide_order.valid.json"));
    defer overflow.deinit();
    var overflow_private = &overflow.value.private_inputs.?;
    for (overflow_private.object.getPtr("digest_bytes").?.array.items) |*limb| {
        limb.* = .{ .integer = 65535 };
    }
    try std.testing.expectError(error.U256Overflow, relation.evaluate(std.testing.allocator, program.value, overflow.value));
    const overflow_ctx = compile(QM31, std.testing.allocator, program.value, overflow.value);
    if (overflow_ctx) |got| {
        var bad = got;
        defer bad.deinit();
        try std.testing.expect(!try bad.isCircuitValid());
    } else |err| {
        try std.testing.expectEqual(error.EqFailedOnEval, err);
    }
}

test "u256 subtraction constrains cross-limb borrows and checked underflow" {
    const allocator = std.testing.allocator;
    const source =
        \\{"version":1,"name":"subtract256","inputs":[{"name":"a","kind":"u16","length":16,"visibility":"private"},{"name":"b","kind":"u16","length":16,"visibility":"private"}],"nodes":[{"name":"difference","op":"u256_sub","lhs":"a","rhs":"b"},{"name":"recovered","op":"u256_add","lhs":"difference","rhs":"b"},{"name":"less","op":"u256_le","lhs":"difference","rhs":"a"}],"assertions":[{"lhs":"recovered","rhs":"a"}],"public_outputs":["less"]}
    ;
    var program = try relation.parseProgram(allocator, source);
    defer program.deinit();
    var topology = try compile(circuit.builder.NoValue, allocator, program.value, null);
    defer topology.deinit();
    const zero = [_]u32{0} ** 16;
    const one = [1]u32{1} ++ [_]u32{0} ** 15;
    const across = [2]u32{ 0, 1 } ++ [_]u32{0} ** 14;
    const near = [2]u32{ 65535, 0 } ++ [_]u32{0} ** 14;
    const max = [_]u32{65535} ** 16;
    const cases = [_]struct { a: [16]u32, b: [16]u32, less: u32 }{
        .{ .a = zero, .b = one, .less = 0 },
        .{ .a = across, .b = one, .less = 1 },
        .{ .a = across, .b = near, .less = 1 },
        .{ .a = max, .b = max, .less = 1 },
    };
    for (cases) |case| {
        const a_json = try std.json.Stringify.valueAlloc(allocator, case.a, .{});
        defer allocator.free(a_json);
        const b_json = try std.json.Stringify.valueAlloc(allocator, case.b, .{});
        defer allocator.free(b_json);
        const assigned = try std.fmt.allocPrint(allocator, "{{\"public_inputs\":{{}},\"private_inputs\":{{\"a\":{s},\"b\":{s}}},\"public_outputs\":{{\"less\":[{d}]}}}}", .{ a_json, b_json, case.less });
        defer allocator.free(assigned);
        var assignment = try relation.parseAssignment(allocator, assigned);
        defer assignment.deinit();
        const result = try relation.evaluate(allocator, program.value, assignment.value);
        try std.testing.expectEqual(case.less, result[0]);
        var values = try compile(QM31, allocator, program.value, assignment.value);
        defer values.deinit();
        try std.testing.expectEqual(topology.circuit.n_vars, values.circuit.n_vars);
        try std.testing.expect(std.meta.eql(topology.gate_counts, values.gate_counts));
        try std.testing.expect(try values.isCircuitValid());
        if (case.less == 0) {
            program.value.nodes[0].op = .u256_sub_checked;
            try std.testing.expectError(error.U256Underflow, relation.evaluate(allocator, program.value, assignment.value));
            const checked = compile(QM31, allocator, program.value, assignment.value);
            if (checked) |got| {
                var invalid = got;
                defer invalid.deinit();
                try std.testing.expect(!try invalid.isCircuitValid());
            } else |err| try std.testing.expectEqual(error.EqFailedOnEval, err);
            program.value.nodes[0].op = .u256_sub;
        }
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

test "mix4 packed diffusion matches scalar M31 at field boundaries" {
    const p = core.fields.m31.Modulus;
    for ([_][4]u32{
        .{ 0, 0, 0, 0 },
        .{ 1, 2, 3, 4 },
        .{ p - 1, 0, 1, p - 1 },
        .{ p - 1, p - 1, p - 1, p - 1 },
        .{ 1073741823, 1073741824, 2147483646, 17 },
    }) |words| {
        var ctx = try circuit.builder.Context(QM31).init(std.testing.allocator, 0);
        defer ctx.deinit();
        const input = try ctx.guess(QM31.fromU32Unchecked(words[0], words[1], words[2], words[3]));
        const input_wires = [_]Var{input};
        const before = ctx.circuit.nQm31OpsRows();
        const output = try mix4(QM31, &ctx, Simd.fromPacked(&input_wires, 4));
        try std.testing.expectEqual(@as(usize, 4), ctx.circuit.nQm31OpsRows() - before);
        var expected: [4]M31 = undefined;
        for (words, &expected) |word, *slot| slot.* = M31.fromCanonical(word);
        try relation.applyStep(&expected, .{ .op = .mix4 });
        for (ctx.get(output.data[0]).toM31Array(), expected) |actual, wanted|
            try std.testing.expectEqual(wanted.v, actual.v);
        try ctx.finalize(false);
        try std.testing.expect(try ctx.isCircuitValid());
    }
}

test "inverse constrains each active lane including a partial packed group" {
    const source =
        \\{"version":1,"name":"inverse5","inputs":[{"name":"denominator","kind":"m31","length":5,"visibility":"private"}],"nodes":[{"name":"inverse","op":"inv","lhs":"denominator"}],"assertions":[],"public_outputs":["inverse"]}
    ;
    const valid =
        \\{"public_inputs":{},"private_inputs":{"denominator":[2,3,5,7,11]},"public_outputs":{"inverse":[1073741824,1431655765,858993459,1840700269,1952257861]}}
    ;
    const zero_last_lane =
        \\{"public_inputs":{},"private_inputs":{"denominator":[2,3,5,7,0]},"public_outputs":{"inverse":[1073741824,1431655765,858993459,1840700269,1952257861]}}
    ;
    var program = try relation.parseProgram(std.testing.allocator, source);
    defer program.deinit();
    var assignment = try relation.parseAssignment(std.testing.allocator, valid);
    defer assignment.deinit();
    var values = try compileDirect(QM31, std.testing.allocator, program.value, assignment.value, false);
    defer values.deinit();
    var topology_ctx = try compileDirect(circuit.builder.NoValue, std.testing.allocator, program.value, null, false);
    defer topology_ctx.deinit();
    try std.testing.expect(try values.isCircuitValid());
    try std.testing.expectEqual(@as(usize, 0), values.circuit.eq.items.len);
    try std.testing.expectEqual(values.circuit.n_vars, topology_ctx.circuit.n_vars);
    // Two packed inversion constraints plus five public-word bindings.
    try std.testing.expectEqual(@as(usize, 7), values.stats.pointwise_mul);
    var bad = try relation.parseAssignment(std.testing.allocator, zero_last_lane);
    defer bad.deinit();
    try std.testing.expectError(error.DivisionByZero, relation.evaluate(std.testing.allocator, program.value, bad.value));
    var invalid = try compileDirect(QM31, std.testing.allocator, program.value, bad.value, false);
    defer invalid.deinit();
    try std.testing.expect(!try invalid.isCircuitValid());
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
