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
