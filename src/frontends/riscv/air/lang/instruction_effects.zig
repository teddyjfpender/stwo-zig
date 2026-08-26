//! Closed opcode-level effects that carry fixed proof obligations.

const std = @import("std");
const effects = @import("effects.zig");
const ir = @import("ir.zig");
const machine_validation = @import("machine_derived_validation.zig");
const program = @import("program.zig");
const relation = @import("relation.zig");
const source = @import("source.zig");
const types = @import("types.zig");

pub const Error = effects.Error || relation.Error;

pub const SequentialRetirement = struct {
    events: effects.Retirement,
    after: effects.MachineState,
};

/// Emit the exact non-control-flow transition `(pc + 4, clock + 1)`.
pub fn retireSequential(
    arena: *ir.Arena,
    before: effects.MachineState,
    active: types.ValueId,
    span: source.SourceSpan,
) Error!SequentialRetirement {
    const checkpoint = arena.nodeCheckpoint();
    errdefer arena.rollbackToNodeCheckpoint(checkpoint);
    const after = effects.MachineState{
        .pc = try arena.instructionNextPc(before.pc, span),
        .clock = try arena.instructionNextClock(before.clock, span),
    };
    return .{
        .events = try effects.retire(arena, before, after, active, span),
        .after = after,
    };
}

pub const RangeCheck884Input = struct {
    first_byte: types.ValueId,
    second_byte: types.ValueId,
    low_nibble: types.ValueId,

    pub fn values(self: RangeCheck884Input) [3]types.ValueId {
        return .{ self.first_byte, self.second_byte, self.low_nibble };
    }
};

/// Request exactly `range_check_8_8_4@1`; callers cannot select a domain.
pub fn rangeCheck884(
    arena: *ir.Arena,
    input: RangeCheck884Input,
    active: types.ValueId,
    span: source.SourceSpan,
) Error!types.EffectId {
    try arena.validateSpan(span);
    const active_node = arena.node(active) orelse return error.UnknownValue;
    if (!active_node.key.ty.isSelector()) return error.InvalidEffectLiveness;
    const values = input.values();
    const expected = [_]types.Type{
        .byte,
        .byte,
        try types.Type.boundedField(4),
    };
    for (values, expected) |value, ty| {
        const node = arena.node(value) orelse return error.UnknownValue;
        if (!std.meta.eql(node.key.ty, ty)) return error.InvalidFieldType;
        if (machine_validation.isDerived(arena, value))
            return error.UnexpectedMachineDerivedUse;
    }
    const schema = relation.get(.range_check_8_8_4);
    const binding = program.RelationBinding{
        .schema = schema.id,
        .schema_version = schema.version,
        .role = .request,
    };
    try relation.validateEvent(schema.id, .request, &expected, null);
    return arena.addBoundEffectUnchecked(
        .range_request,
        binding,
        &values,
        active,
        null,
        span,
    );
}

pub const RangeCheck811Input = struct {
    low_byte: types.ValueId,
    high_shifted: types.ValueId,

    pub fn values(self: RangeCheck811Input) [2]types.ValueId {
        return .{ self.low_byte, self.high_shifted };
    }
};

/// Request exactly `range_check_8_11@1` for the compatibility-shifted
/// immediate coordinates.
pub fn rangeCheck811(
    arena: *ir.Arena,
    input: RangeCheck811Input,
    active: types.ValueId,
    span: source.SourceSpan,
) Error!types.EffectId {
    const values = input.values();
    const expected = [_]types.Type{ .byte, try types.Type.boundedField(11) };
    const binding = try preflightRequest(
        arena,
        .range_check_8_11,
        &values,
        &expected,
        active,
        span,
    );
    return arena.addBoundEffectUnchecked(
        .range_request,
        binding,
        &values,
        active,
        null,
        span,
    );
}

pub const BitwiseInput = struct {
    lhs: types.ValueId,
    rhs: types.ValueId,
    result: types.ValueId,
    operation_id: types.ValueId,

    pub fn values(self: BitwiseInput) [4]types.ValueId {
        return .{ self.lhs, self.rhs, self.result, self.operation_id };
    }
};

/// Append the four byte-lane `bitwise@1` requests as one transactional word
/// operation. All schemas and types are checked before the first visible
/// effect, and allocation failure restores both effect pools exactly.
pub fn bitwiseWord(
    arena: *ir.Arena,
    inputs: [4]BitwiseInput,
    active: types.ValueId,
    span: source.SourceSpan,
) Error![4]types.EffectId {
    const expected = [_]types.Type{
        .byte,
        .byte,
        .byte,
        try types.Type.boundedField(2),
    };
    var values: [4][4]types.ValueId = undefined;
    var request_binding: program.RelationBinding = undefined;
    for (inputs, 0..) |input, lane| {
        values[lane] = input.values();
        request_binding = try preflightRequest(
            arena,
            .bitwise,
            &values[lane],
            &expected,
            active,
            span,
        );
    }

    const checkpoint = arena.effectCheckpoint();
    errdefer arena.rollbackToEffectCheckpoint(checkpoint);
    var result: [4]types.EffectId = undefined;
    for (&result, &values) |*effect, *lane_values| {
        effect.* = try arena.addBoundEffectUnchecked(
            .bitwise_request,
            request_binding,
            lane_values,
            active,
            null,
            span,
        );
    }
    return result;
}

pub const RangeCheck88Input = struct {
    first_byte: types.ValueId,
    second_byte: types.ValueId,

    pub fn values(self: RangeCheck88Input) [2]types.ValueId {
        return .{ self.first_byte, self.second_byte };
    }
};

/// Append the two result-limb `range_check_8_8@1` requests atomically.
pub fn rangeCheck88Pairs(
    arena: *ir.Arena,
    inputs: [2]RangeCheck88Input,
    active: types.ValueId,
    span: source.SourceSpan,
) Error![2]types.EffectId {
    const expected = [_]types.Type{ .byte, .byte };
    var values: [2][2]types.ValueId = undefined;
    var request_binding: program.RelationBinding = undefined;
    for (inputs, 0..) |input, pair| {
        values[pair] = input.values();
        request_binding = try preflightRequest(
            arena,
            .range_check_8_8,
            &values[pair],
            &expected,
            active,
            span,
        );
    }

    const checkpoint = arena.effectCheckpoint();
    errdefer arena.rollbackToEffectCheckpoint(checkpoint);
    var result: [2]types.EffectId = undefined;
    for (&result, &values) |*effect, *pair_values| {
        effect.* = try arena.addBoundEffectUnchecked(
            .range_request,
            request_binding,
            pair_values,
            active,
            null,
            span,
        );
    }
    return result;
}

fn preflightRequest(
    arena: *ir.Arena,
    domain: relation.Domain,
    values: []const types.ValueId,
    expected: []const types.Type,
    active: types.ValueId,
    span: source.SourceSpan,
) Error!program.RelationBinding {
    try arena.validateSpan(span);
    const active_node = arena.node(active) orelse return error.UnknownValue;
    if (!active_node.key.ty.isSelector()) return error.InvalidEffectLiveness;
    if (values.len != expected.len) return error.InvalidArity;
    for (values, expected) |value, ty| {
        const node = arena.node(value) orelse return error.UnknownValue;
        if (!std.meta.eql(node.key.ty, ty)) return error.InvalidFieldType;
        if (machine_validation.isDerived(arena, value))
            return error.UnexpectedMachineDerivedUse;
    }
    const schema = relation.get(domain);
    const request_binding = program.RelationBinding{
        .schema = schema.id,
        .schema_version = schema.version,
        .role = .request,
    };
    try relation.validateEvent(schema.id, .request, expected, null);
    return request_binding;
}
