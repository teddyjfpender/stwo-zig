//! Typed, proof-independent arithmetic for a leaf-local V3 wrapper.
//!
//! Four scheduled rows join V3 metadata to a verified local V2 statement:
//! two M31 continuation roots to their canonical u16 wire limbs, one V3
//! completion-presence bit to the V2 75/76 tag, and one checked 64-bit
//! global start + local count = end relation. Source and statement tuples
//! must be supplied by a future verifier-owned wrapper cohort; building this
//! AIR alone does not activate a recursive proof.

const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../../air/lang/definition.zig");
const effects = @import("relation_effect.zig");
const relation_interaction = @import("relation_interaction.zig");
const source_air = @import("ethereum_leaf_link_source_v1.zig");
const link_program = @import("../ethereum_leaf_link_program_v1.zig");
const leaf_v2 = @import("../segment_leaf_authority_v2.zig");
const segment_v2 = @import("../segment_statement_v2.zig");

const M31 = core.fields.m31.M31;
const Id = lang.types.ValueId;
const Span = lang.source.SourceSpan;

pub const STABLE_NAME = "recursion.ethereum_leaf_link.arithmetic.v1";
pub const PHYSICAL_MAIN_COLUMN_COUNT: usize = 44;
pub const PREPROCESSED_COLUMN_COUNT: usize = 5;
pub const LOGICAL_INPUT_COUNT: usize = PHYSICAL_MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT;
pub const DIRECT_CONSTRAINT_COUNT: usize = 31;
pub const RELATION_EVENT_COUNT: usize = 28;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const INTERACTION_BATCH_COUNT: usize = 14;
pub const INTERACTION_COLUMN_COUNT: usize = 56;
pub const MAXIMUM_CONSTRAINT_DEGREE: u32 = 3;
pub const Row = [LOGICAL_INPUT_COUNT]M31;
pub const Runtime = relation_interaction.Runtime(LOGICAL_INPUT_COUNT, RELATION_EVENT_COUNT, LOOKUP_BATCH_SIZE);
pub const Plan = Runtime.Plan;
pub const SEMANTIC_DIGEST_HEX = "243e18c518f53e3343b12cead79de625b1ffa21bc50b8f75f5cbc498a17d7352";
/// Required by the generic typed-component proof adapter. The semantic
/// program remains pinned by `Definition.validate`; this is its byte form.
pub const SEMANTIC_DIGEST: [32]u8 = blk: {
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, SEMANTIC_DIGEST_HEX) catch
        @compileError("invalid V3 arithmetic semantic digest");
    break :blk result;
};

pub const ROOT = 0;
pub const ROOT_LOW = 1;
pub const ROOT_HIGH = 2;
pub const ROOT_BYTES = 3;
pub const ROOT_DOUBLED_HIGH = 7;
pub const ROOT_GAP_INVERSE = 8;
pub const PRESENCE = 9;
pub const TAG = 10;
pub const START = 11;
pub const END = 15;
pub const COUNT = 19;
pub const CARRY = 21;
pub const POSITION_BYTES = 24;
pub const ACTIVE = PHYSICAL_MAIN_COLUMN_COUNT;
pub const ROOT_MASK = ACTIVE + 1;
pub const COMPLETION_MASK = ACTIVE + 2;
pub const POSITION_MASK = ACTIVE + 3;
pub const SIDE = ACTIVE + 4;

pub const Kind = enum { entry_root, exit_root, completion, position };

pub const Definition = struct {
    arena: lang.ir.Arena,
    roots: [DIRECT_CONSTRAINT_COUNT]Id,
    events: [RELATION_EVENT_COUNT]lang.types.EffectId,

    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const Definition) !void {
        try lang.validate.validate(&self.arena);
        if (self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or
            self.arena.effectsView().len != RELATION_EVENT_COUNT)
            return error.InvalidEthereumLeafArithmeticDefinition;
        const actual = try lang.digest.computeIdentity(&self.arena);
        var expected: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&expected, SEMANTIC_DIGEST_HEX) catch
            return error.InvalidEthereumLeafArithmeticDefinition;
        if (!std.mem.eql(u8, &actual.bytes, &expected))
            return error.InvalidEthereumLeafArithmeticDefinition;
        for (self.roots, 0..) |root, index| {
            const constraint = self.arena.constraintsView()[index];
            if (constraint.root != root or constraint.gate != null or
                constraint.category != .semantic)
                return error.InvalidEthereumLeafArithmeticDefinition;
        }
        for (self.events, 0..) |event, index| {
            if (lang.types.idIndex(event) != index)
                return error.InvalidEthereumLeafArithmeticDefinition;
        }
    }
};

pub fn authenticate(definition: *const Definition) !Plan {
    try definition.validate();
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, SEMANTIC_DIGEST_HEX);
    return Runtime.authenticate(&definition.arena, expected, definition.events);
}

pub fn computeSemanticDigest(allocator: std.mem.Allocator) ![32]u8 {
    var definition = try buildRaw(allocator);
    defer definition.deinit();
    return (try lang.digest.computeIdentity(&definition.arena)).bytes;
}

pub fn build(allocator: std.mem.Allocator) !Definition {
    var definition = try buildRaw(allocator);
    errdefer definition.deinit();
    try definition.validate();
    return definition;
}

fn buildRaw(allocator: std.mem.Allocator) !Definition {
    var arena = lang.ir.Arena.init(allocator);
    errdefer arena.deinit();
    const span = Span.generated();
    var ids: [LOGICAL_INPUT_COUNT]Id = undefined;
    for (&ids, 0..) |*id, index| {
        var name: [80]u8 = undefined;
        const input_type: lang.types.Type = if (index == ROOT_DOUBLED_HIGH or
            (index >= ROOT_BYTES and index < ROOT_BYTES + 4) or
            (index >= POSITION_BYTES and index < POSITION_BYTES + 20))
            .byte
        else if (index >= ACTIVE and index <= POSITION_MASK)
            .selector
        else
            .felt;
        id.* = try arena.input(
            try std.fmt.bufPrint(&name, "ethereum_leaf_arithmetic.value_{d}", .{index}),
            input_type,
            span,
        );
    }
    const zero = try arena.constantField(0, span);
    const one = try arena.constantField(1, span);
    const two = try arena.constantField(2, span);
    const byte_base = try arena.constantField(256, span);
    const limb_base = try arena.constantField(65536, span);
    const max_low = try arena.constantField(65535, span);
    const max_high = try arena.constantField(32767, span);
    const root = ids[ROOT_MASK];
    const completion = ids[COMPLETION_MASK];
    const position = ids[POSITION_MASK];

    var roots: [DIRECT_CONSTRAINT_COUNT]Id = undefined;
    var at: usize = 0;
    inline for (.{ ACTIVE, ROOT_MASK, COMPLETION_MASK, POSITION_MASK, SIDE }) |index| {
        roots[at] = try boolean(&arena, ids[index], one, span);
        at += 1;
    }
    roots[at] = try arena.sub(ids[ACTIVE], try arena.add(try arena.add(root, completion, span), position, span), span);
    at += 1;
    roots[at] = try arena.mul(ids[SIDE], try arena.sub(one, root, span), span);
    at += 1;

    const low = try fromBytes(&arena, ids[ROOT_BYTES], ids[ROOT_BYTES + 1], byte_base, span);
    const high = try fromBytes(&arena, ids[ROOT_BYTES + 2], ids[ROOT_BYTES + 3], byte_base, span);
    roots[at] = try gatedEqual(&arena, root, ids[ROOT_LOW], low, span);
    at += 1;
    roots[at] = try gatedEqual(&arena, root, ids[ROOT_HIGH], high, span);
    at += 1;
    roots[at] = try gatedEqual(&arena, root, ids[ROOT], try arena.add(ids[ROOT_LOW], try arena.mul(limb_base, ids[ROOT_HIGH], span), span), span);
    at += 1;
    roots[at] = try gatedEqual(&arena, root, ids[ROOT_DOUBLED_HIGH], try arena.mul(two, ids[ROOT_BYTES + 3], span), span);
    at += 1;
    const gap = try arena.add(try arena.sub(max_low, ids[ROOT_LOW], span), try arena.sub(max_high, ids[ROOT_HIGH], span), span);
    roots[at] = try arena.mul(root, try arena.sub(try arena.mul(gap, ids[ROOT_GAP_INVERSE], span), one, span), span);
    at += 1;

    roots[at] = try arena.mul(completion, try boolean(&arena, ids[PRESENCE], one, span), span);
    at += 1;
    const absent_tag = try arena.constantField(@intFromEnum(segment_v2.Tag.completion_absent), span);
    roots[at] = try gatedEqual(&arena, completion, ids[TAG], try arena.add(absent_tag, ids[PRESENCE], span), span);
    at += 1;

    for (0..10) |i| {
        const limb_index = if (i < 4) START + i else if (i < 8) END + i - 4 else COUNT + i - 8;
        const reconstructed = try fromBytes(&arena, ids[POSITION_BYTES + 2 * i], ids[POSITION_BYTES + 2 * i + 1], byte_base, span);
        roots[at] = try gatedEqual(&arena, position, ids[limb_index], reconstructed, span);
        at += 1;
    }
    for (0..3) |i| {
        roots[at] = try arena.mul(position, try boolean(&arena, ids[CARRY + i], one, span), span);
        at += 1;
    }
    for (0..4) |i| {
        const count_limb = if (i < 2) ids[COUNT + i] else zero;
        const carry_in = if (i == 0) zero else ids[CARRY + i - 1];
        const carry_out = if (i == 3) zero else ids[CARRY + i];
        const lhs = try arena.add(try arena.add(ids[START + i], count_limb, span), carry_in, span);
        const rhs = try arena.add(ids[END + i], try arena.mul(limb_base, carry_out, span), span);
        roots[at] = try gatedEqual(&arena, position, lhs, rhs, span);
        at += 1;
    }
    std.debug.assert(at == roots.len);
    for (roots, 0..) |constraint_root, index| {
        var name: [80]u8 = undefined;
        _ = try arena.assertZero(
            try std.fmt.bufPrint(&name, "ethereum_leaf_arithmetic.constraint_{d}", .{index}),
            constraint_root,
            null,
            .semantic,
            span,
        );
    }

    const metadata_scope = try arena.constantField(source_air.METADATA_SCOPE, span);
    const wire_scope = try arena.constantField(leaf_v2.WIRE_SCOPE, span);
    const root_metadata_base = try arena.constantField(link_program.METADATA_ENTRY_CONTINUATION_ROOT, span);
    const root_wire_base = try arena.constantField(segment_v2.fixed_layout.entry_continuation_root, span);
    const root_metadata_index = try arena.add(root_metadata_base, try arena.mul(ids[SIDE], try arena.constantField(link_program.METADATA_EXIT_CONTINUATION_ROOT - link_program.METADATA_ENTRY_CONTINUATION_ROOT, span), span), span);
    const root_wire_index = try arena.add(root_wire_base, try arena.mul(ids[SIDE], try arena.constantField(segment_v2.fixed_layout.exit_continuation_root - segment_v2.fixed_layout.entry_continuation_root, span), span), span);
    const root_wire_next = try arena.add(root_wire_index, one, span);

    var events: [RELATION_EVENT_COUNT]lang.types.EffectId = undefined;
    at = 0;
    events[at] = try rawConsume(&arena, metadata_scope, root_metadata_index, ids[ROOT], root, span);
    at += 1;
    events[at] = try statementConsume(&arena, wire_scope, root_wire_index, ids[ROOT_LOW], root, span);
    at += 1;
    events[at] = try statementConsume(&arena, wire_scope, root_wire_next, ids[ROOT_HIGH], root, span);
    at += 1;
    events[at] = try rawConsume(&arena, metadata_scope, try arena.constantField(link_program.METADATA_COMPLETION_START, span), ids[PRESENCE], completion, span);
    at += 1;
    events[at] = try statementConsume(&arena, wire_scope, try arena.constantField(segment_v2.fixed_layout.completion, span), ids[TAG], completion, span);
    at += 1;
    for (0..4) |i| {
        events[at] = try rawConsume(&arena, metadata_scope, try arena.constantField(@intCast(link_program.METADATA_GLOBAL_START + i), span), ids[START + i], position, span);
        at += 1;
    }
    for (0..4) |i| {
        events[at] = try rawConsume(&arena, metadata_scope, try arena.constantField(@intCast(link_program.METADATA_GLOBAL_END + i), span), ids[END + i], position, span);
        at += 1;
    }
    for (0..2) |i| {
        events[at] = try rawConsume(&arena, metadata_scope, try arena.constantField(@intCast(link_program.METADATA_LOCAL_COUNT_START + i), span), ids[COUNT + i], position, span);
        at += 1;
    }
    events[at] = try rangeRequest(&arena, ids[ROOT_BYTES], ids[ROOT_BYTES + 1], root, span);
    at += 1;
    events[at] = try rangeRequest(&arena, ids[ROOT_BYTES + 2], ids[ROOT_BYTES + 3], root, span);
    at += 1;
    events[at] = try rangeRequest(&arena, ids[ROOT_DOUBLED_HIGH], ids[ROOT_BYTES], root, span);
    at += 1;
    for (0..10) |i| {
        events[at] = try rangeRequest(&arena, ids[POSITION_BYTES + 2 * i], ids[POSITION_BYTES + 2 * i + 1], position, span);
        at += 1;
    }
    std.debug.assert(at == events.len);
    return .{ .arena = arena, .roots = roots, .events = events };
}

fn boolean(arena: *lang.ir.Arena, value: Id, one: Id, span: Span) !Id {
    return arena.mul(value, try arena.sub(value, one, span), span);
}
fn gatedEqual(arena: *lang.ir.Arena, gate: Id, left: Id, right: Id, span: Span) !Id {
    return arena.mul(gate, try arena.sub(left, right, span), span);
}
fn fromBytes(arena: *lang.ir.Arena, low: Id, high: Id, radix: Id, span: Span) !Id {
    return arena.add(low, try arena.mul(radix, high, span), span);
}
fn rawConsume(arena: *lang.ir.Arena, scope: Id, index: Id, value: Id, weight: Id, span: Span) !lang.types.EffectId {
    return (try effects.appendGroup(1, arena, .{.{ .domain = .recursion_vm_public_claim_word, .role = .consume, .values = &.{ scope, index, value }, .weight = weight }}, span))[0];
}
fn statementConsume(arena: *lang.ir.Arena, scope: Id, index: Id, value: Id, weight: Id, span: Span) !lang.types.EffectId {
    return (try effects.appendGroup(1, arena, .{.{ .domain = .recursion_statement_word, .role = .consume, .values = &.{ scope, index, value }, .weight = weight }}, span))[0];
}
fn rangeRequest(arena: *lang.ir.Arena, low: Id, high: Id, weight: Id, span: Span) !lang.types.EffectId {
    return (try effects.appendGroup(1, arena, .{.{ .domain = .range_check_8_8, .role = .request, .values = &.{ low, high }, .weight = weight }}, span))[0];
}
