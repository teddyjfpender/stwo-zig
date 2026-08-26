//! Compiler-owned `wire(6)` relation ABI for recursion arithmetic circuits.
//!
//! A wire tuple is `(circuit_id, node_id, value[0..4])`. Multiplication owns
//! one atomic effect group: consume its two operands and emit its result with
//! the schedule-owned `uses * in_circuit` weight. This module is the only
//! authoring path for that group; interaction lowering reads the resulting
//! typed effects rather than transcribing relation entries independently.

const std = @import("std");
const ir = @import("../../air/lang/ir.zig");
const program = @import("../../air/lang/program.zig");
const relation = @import("../../air/lang/relation.zig");
const source = @import("../../air/lang/source.zig");
const types = @import("../../air/lang/types.zig");

pub const ARITY: usize = 6;
pub const EVENT_COUNT: usize = 3;
pub const DOMAIN = relation.Domain.recursion_wire;

pub const Tuple = struct {
    circuit_id: types.ValueId,
    node_id: types.ValueId,
    value: [4]types.ValueId,

    pub fn values(self: Tuple) [ARITY]types.ValueId {
        return .{ self.circuit_id, self.node_id } ++ self.value;
    }
};

pub const Events = struct {
    lhs_consume: types.EffectId,
    rhs_consume: types.EffectId,
    result_emit: types.EffectId,
    result_weight: types.ValueId,

    pub fn ordered(self: Events) [EVENT_COUNT]types.EffectId {
        return .{ self.lhs_consume, self.rhs_consume, self.result_emit };
    }
};

pub const EventSpec = struct {
    role: relation.Role,
};

pub const WeightedEvent = struct {
    role: relation.Role,
    tuple: Tuple,
    weight: types.ValueId,
};

pub const EVENT_SPECS = [EVENT_COUNT]EventSpec{
    .{ .role = .consume },
    .{ .role = .consume },
    .{ .role = .emit },
};

pub const Error = ir.Error || relation.Error || error{
    InvalidWireLiveness,
    InvalidWireValue,
};

/// Append an arbitrary fixed-size wire event group after validating every
/// tuple and weight. Both effect pools are reserved before the first logical
/// append, so failure cannot expose a prefix of the group.
pub fn appendGroup(
    comptime count: usize,
    arena: *ir.Arena,
    events: [count]WeightedEvent,
    span: source.SourceSpan,
) Error![count]types.EffectId {
    comptime if (count == 0)
        @compileError("wire event group cannot be empty");
    try arena.validateSpan(span);
    const field_types = [_]types.Type{.felt} ** ARITY;
    const schema = relation.get(DOMAIN);
    for (events) |event| {
        for (event.tuple.values()) |value| {
            const node = arena.node(value) orelse return error.UnknownValue;
            if (!std.meta.eql(node.key.ty, types.Type.felt))
                return error.InvalidWireValue;
        }
        const weight = arena.node(event.weight) orelse return error.UnknownValue;
        if (!weight.key.ty.isFieldScalar()) return error.InvalidWireLiveness;
        try relation.validateEvent(schema.id, event.role, &field_types, null);
    }

    try arena.ensureUnusedEffectCapacity(count, count * ARITY);
    const checkpoint = arena.effectCheckpoint();
    errdefer arena.rollbackToEffectCheckpoint(checkpoint);
    var result: [count]types.EffectId = undefined;
    for (&result, events) |*effect, event| {
        const values = event.tuple.values();
        effect.* = try arena.addBoundEffectUnchecked(
            .component_call,
            binding(event.role),
            &values,
            event.weight,
            null,
            span,
        );
    }
    return result;
}

/// Append the three multiplication wire events as one failure-atomic group.
pub fn appendMultiplication(
    arena: *ir.Arena,
    lhs: Tuple,
    rhs: Tuple,
    result: Tuple,
    uses: types.ValueId,
    in_circuit: types.ValueId,
    span: source.SourceSpan,
) Error!Events {
    try arena.validateSpan(span);
    const in_circuit_node = arena.node(in_circuit) orelse
        return error.UnknownValue;
    if (!in_circuit_node.key.ty.isSelector())
        return error.InvalidWireLiveness;
    const uses_node = arena.node(uses) orelse return error.UnknownValue;
    if (!std.meta.eql(uses_node.key.ty, types.Type.felt))
        return error.InvalidWireLiveness;

    const node_checkpoint = arena.nodeCheckpoint();
    errdefer arena.rollbackToNodeCheckpoint(node_checkpoint);
    const result_weight = try arena.mul(uses, in_circuit, span);
    const effects = try appendGroup(EVENT_COUNT, arena, .{
        .{ .role = .consume, .tuple = lhs, .weight = in_circuit },
        .{ .role = .consume, .tuple = rhs, .weight = in_circuit },
        .{ .role = .emit, .tuple = result, .weight = result_weight },
    }, span);
    return .{
        .lhs_consume = effects[0],
        .rhs_consume = effects[1],
        .result_emit = effects[2],
        .result_weight = result_weight,
    };
}

pub fn binding(role: relation.Role) program.RelationBinding {
    const schema = relation.get(DOMAIN);
    return .{
        .schema = schema.id,
        .schema_version = schema.version,
        .role = role,
    };
}

comptime {
    const schema = relation.get(DOMAIN);
    if (schema.fields.len != ARITY or schema.version != 1 or
        schema.multiplicity != .role_signed_weight or
        schema.access_ordinal != .forbidden)
    {
        @compileError("recursion wire relation schema drifted");
    }
}
