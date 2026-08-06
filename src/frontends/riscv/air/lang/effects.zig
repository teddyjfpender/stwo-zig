//! Reviewed typed machine-effect constructors.
//!
//! This is the semantic boundary between a machine operation and the relation
//! ABI that proves it.  Construction performs full type/schema validation once;
//! validated consumers use the allocation-free views in `lower_effects.zig`.

const std = @import("std");
const ir = @import("ir.zig");
const program = @import("program.zig");
const relation = @import("relation.zig");
const source = @import("source.zig");
const types = @import("types.zig");

pub const MAX_ARITY: usize = 32;

pub const Error = ir.Error || relation.Error || error{
    BindingKindMismatch,
    BindingVersionMismatch,
    MissingRelationBinding,
    MissingRelationLiveness,
    RelationArityTooLarge,
    UnexpectedRelationBinding,
    UnknownEffect,
};

/// Canonical decoded five-field program relation tuple.
pub const ProgramTuple = struct {
    pc: types.ValueId,
    opcode_id: types.ValueId,
    rd: types.ValueId,
    rs1: types.ValueId,
    operand: types.ValueId,

    pub fn values(self: ProgramTuple) [5]types.ValueId {
        return .{ self.pc, self.opcode_id, self.rd, self.rs1, self.operand };
    }
};

pub const MachineState = struct {
    pc: types.ValueId,
    clock: types.ValueId,

    pub fn values(self: MachineState) [2]types.ValueId {
        return .{ self.pc, self.clock };
    }
};

pub const Retirement = struct {
    consume: types.EffectId,
    produce: types.EffectId,
};

pub fn programFetch(
    arena: *ir.Arena,
    tuple: ProgramTuple,
    active: types.ValueId,
    span: source.SourceSpan,
) Error!types.EffectId {
    const values = tuple.values();
    return append(
        arena,
        .program_fetch,
        binding(.program_access, .request),
        &values,
        active,
        null,
        span,
    );
}

pub fn stateConsume(
    arena: *ir.Arena,
    state: MachineState,
    active: types.ValueId,
    span: source.SourceSpan,
) Error!types.EffectId {
    const values = state.values();
    return append(
        arena,
        .state_consume,
        binding(.registers_state, .consume),
        &values,
        active,
        null,
        span,
    );
}

pub fn stateProduce(
    arena: *ir.Arena,
    state: MachineState,
    active: types.ValueId,
    span: source.SourceSpan,
) Error!types.EffectId {
    const values = state.values();
    return append(
        arena,
        .state_produce,
        binding(.registers_state, .emit),
        &values,
        active,
        null,
        span,
    );
}

/// Append one adjacent consume/produce state transition atomically.
pub fn retire(
    arena: *ir.Arena,
    before: MachineState,
    after: MachineState,
    active: types.ValueId,
    span: source.SourceSpan,
) Error!Retirement {
    const before_values = before.values();
    const after_values = after.values();
    const consume_binding = binding(.registers_state, .consume);
    const produce_binding = binding(.registers_state, .emit);

    // Complete both semantic preflights before the first append.  The
    // checkpoint then covers the only remaining failure class: allocation.
    try preflight(
        arena,
        .state_consume,
        consume_binding,
        &before_values,
        active,
        null,
        span,
    );
    try preflight(
        arena,
        .state_produce,
        produce_binding,
        &after_values,
        active,
        null,
        span,
    );

    const checkpoint = arena.effectCheckpoint();
    errdefer arena.rollbackToEffectCheckpoint(checkpoint);
    return .{
        .consume = try arena.addBoundEffectUnchecked(
            .state_consume,
            consume_binding,
            &before_values,
            active,
            null,
            span,
        ),
        .produce = try arena.addBoundEffectUnchecked(
            .state_produce,
            produce_binding,
            &after_values,
            active,
            null,
            span,
        ),
    };
}

/// Allocation-free full-schema validation for every stored relation effect.
/// This is called after the arena's structural ranges have been validated.
pub fn validateProgram(arena: *const ir.Arena) Error!void {
    const typed_mode = hasRelationBinding(arena);
    // Preserve the provisional language exactly and avoid a redundant second
    // effect scan for legacy programs.
    if (!typed_mode) return;

    for (arena.effectsView(), 0..) |effect, index| {
        const effect_id = types.idFromIndex(types.EffectId, index) catch
            return error.UnknownEffect;
        const values = arena.effectValues(effect_id) orelse
            return error.UnknownEffect;
        const relation_binding = effect.binding orelse {
            // An entirely unbound program is the provisional legacy language
            // and retains its historical validation and identity. Once one
            // reviewed binding is present, relation-bearing effects may not be
            // silently mixed back into that legacy representation.
            if (requiresTypedBinding(effect.kind))
                return error.MissingRelationBinding;
            continue;
        };
        const active = effect.liveness orelse
            return error.MissingRelationLiveness;
        try preflight(
            arena,
            effect.kind,
            relation_binding,
            values,
            active,
            effect.access_ordinal,
            effect.source_span,
        );
    }

    // State retirement is a single semantic operation even though the relation
    // protocol carries two adjacent events.
    for (arena.effectsView(), 0..) |effect, index| switch (effect.kind) {
        .state_consume => {
            if (index + 1 >= arena.effectsView().len)
                return error.BindingKindMismatch;
            const produced = arena.effectsView()[index + 1];
            if (produced.kind != .state_produce or
                produced.liveness != effect.liveness)
            {
                return error.BindingKindMismatch;
            }
        },
        .state_produce => {
            if (index == 0 or arena.effectsView()[index - 1].kind != .state_consume)
                return error.BindingKindMismatch;
        },
        else => {},
    };
}

fn binding(
    domain: relation.Domain,
    role: relation.Role,
) program.RelationBinding {
    const schema = relation.get(domain);
    return .{
        .schema = schema.id,
        .schema_version = schema.version,
        .role = role,
    };
}

fn append(
    arena: *ir.Arena,
    kind: program.EffectKind,
    relation_binding: program.RelationBinding,
    values: []const types.ValueId,
    active: types.ValueId,
    access_ordinal: ?u8,
    span: source.SourceSpan,
) Error!types.EffectId {
    try preflight(
        arena,
        kind,
        relation_binding,
        values,
        active,
        access_ordinal,
        span,
    );
    return arena.addBoundEffectUnchecked(
        kind,
        relation_binding,
        values,
        active,
        access_ordinal,
        span,
    );
}

fn preflight(
    arena: *const ir.Arena,
    kind: program.EffectKind,
    relation_binding: program.RelationBinding,
    values: []const types.ValueId,
    active: types.ValueId,
    access_ordinal: ?u8,
    span: source.SourceSpan,
) Error!void {
    try arena.validateSpan(span);
    const active_node = arena.node(active) orelse return error.UnknownValue;
    if (!active_node.key.ty.isSelector()) return error.InvalidEffectLiveness;
    if (values.len > MAX_ARITY) return error.RelationArityTooLarge;

    const schema = relation.getById(relation_binding.schema) orelse
        return error.UnknownSchema;
    if (schema.version != relation_binding.schema_version)
        return error.BindingVersionMismatch;
    try validateKindBinding(kind, schema.domain, relation_binding.role, access_ordinal);

    var field_types: [MAX_ARITY]types.Type = undefined;
    for (values, field_types[0..values.len]) |value, *field_type| {
        const node = arena.node(value) orelse return error.UnknownValue;
        field_type.* = node.key.ty;
    }
    try relation.validateEvent(
        relation_binding.schema,
        relation_binding.role,
        field_types[0..values.len],
        access_ordinal,
    );
}

fn validateKindBinding(
    kind: program.EffectKind,
    domain: relation.Domain,
    role: relation.Role,
    access_ordinal: ?u8,
) Error!void {
    const matches = switch (kind) {
        .program_fetch => domain == .program_access and role == .request and access_ordinal == null,
        .state_consume => domain == .registers_state and role == .consume and access_ordinal == null,
        .state_produce => domain == .registers_state and role == .emit and access_ordinal == null,
        // Their enum cases and schema registry entries are storage groundwork,
        // not authoring authority. E-002/E-003 and the component milestone must
        // install instruction-local group validators before these can validate.
        .register_read,
        .register_write,
        .memory_read,
        .memory_write,
        .range_request,
        .component_call,
        => return error.UnexpectedRelationBinding,
        .public_consume, .public_produce => return error.UnexpectedRelationBinding,
    };
    if (!matches) return error.BindingKindMismatch;
}

fn requiresTypedBinding(kind: program.EffectKind) bool {
    return switch (kind) {
        .program_fetch,
        .register_read,
        .register_write,
        .memory_read,
        .memory_write,
        .range_request,
        .state_consume,
        .state_produce,
        .component_call,
        => true,
        .public_consume, .public_produce => false,
    };
}

fn hasRelationBinding(arena: *const ir.Arena) bool {
    for (arena.effectsView()) |effect| {
        if (effect.binding != null) return true;
    }
    return false;
}

comptime {
    var maximum: usize = 0;
    for (relation.schemas) |schema| maximum = @max(maximum, schema.fields.len);
    if (maximum != MAX_ARITY)
        @compileError("typed effect arity must track the relation registry");
}
