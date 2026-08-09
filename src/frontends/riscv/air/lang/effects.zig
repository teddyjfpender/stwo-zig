//! Reviewed typed machine-effect constructors.
//!
//! This is the semantic boundary between a machine operation and the relation
//! ABI that proves it.  Construction performs full type/schema validation once;
//! validated consumers use the allocation-free views in `lower_effects.zig`.

const std = @import("std");
const access_schedule = @import("access_schedule.zig");
const expr = @import("expr.zig");
const ir = @import("ir.zig");
const memory_access = @import("memory_access_validation.zig");
const program = @import("program.zig");
const relation = @import("relation.zig");
const source = @import("source.zig");
const types = @import("types.zig");

pub const MAX_ARITY: usize = 32;
pub const MAX_ACCESS_GROUPS = access_schedule.MAX_ACCESS_GROUPS;

pub const Error = ir.Error || relation.Error || access_schedule.Error ||
    memory_access.Error || error{
    BindingKindMismatch,
    BindingVersionMismatch,
    InvalidAccessGroup,
    MissingRelationBinding,
    MissingRelationLiveness,
    MultipleAccessSchedules,
    OrphanedMachineDerived,
    RelationArityTooLarge,
    UnexpectedMachineDerivedUse,
    UnexpectedRelationBinding,
    UnknownEffect,
};

pub const RegisterReadInput = access_schedule.RegisterReadInput;
pub const RegisterWriteInput = access_schedule.RegisterWriteInput;
pub const RegisterAccessGroup = access_schedule.RegisterAccessGroup;
pub const AccessSchedule = access_schedule.AccessSchedule;
pub const MemoryReadInput = access_schedule.MemoryReadInput;
pub const MemoryWriteInput = access_schedule.MemoryWriteInput;
pub const LoadAccessInput = access_schedule.LoadAccessInput;
pub const StoreAccessInput = access_schedule.StoreAccessInput;
pub const AccessPlanKind = access_schedule.AccessPlanKind;
pub const LoadStoreAccessPlan = access_schedule.LoadStoreAccessPlan;
pub const PreparedAccessPlan = memory_access.PreparedPlan;

pub fn prepareAccessPlan(arena: *const ir.Arena) Error!PreparedAccessPlan {
    return memory_access.prepare(arena);
}

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
    const typed_mode = hasRelationBinding(arena) or hasMachineDerivedNode(arena);
    // Preserve the provisional language exactly and avoid a redundant second
    // effect scan for legacy programs.
    if (!typed_mode) return;

    const memory_mode = memory_access.hasMemoryCapability(arena);
    const memory_plan = if (memory_mode)
        try memory_access.prepare(arena)
    else
        null;
    var groups = ValidatedAccessGroups{};
    var index: usize = 0;
    while (index < arena.effectsView().len) {
        const effect = arena.effectsView()[index];
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
            index += 1;
            continue;
        };
        const active = effect.liveness orelse
            return error.MissingRelationLiveness;

        if (memory_mode and memory_access.isAccessKind(effect.kind)) {
            index += 3;
            continue;
        }
        if (isRegisterKind(effect.kind)) {
            if (groups.len >= groups.items.len)
                return error.AccessScheduleExhausted;
            const expected_ordinal: u8 = @intCast(groups.len + 1);
            groups.items[groups.len] = try validateRegisterGroup(
                arena,
                index,
                expected_ordinal,
            );
            groups.len += 1;
            index += 3;
            continue;
        }

        if (memory_plan) |prepared| {
            if (index == types.idIndex(prepared.aligned_range)) {
                index += 1;
                continue;
            }
        }

        // E-003 must compose with the opcode body's independent mask, sign,
        // and carry ranges. Keep standalone range authoring fail-closed, but
        // validate every non-plan range normally inside a reviewed memory plan.
        if (memory_mode and effect.kind == .range_request) {
            try preflightRelation(
                arena,
                relation_binding,
                values,
                active,
                effect.access_ordinal,
                effect.source_span,
            );
            const schema = relation.getById(relation_binding.schema) orelse
                return error.UnknownSchema;
            if (!isRangeDomain(schema.domain) or
                relation_binding.role != .request or
                effect.access_ordinal != null)
            {
                return error.BindingKindMismatch;
            }
            index += 1;
            continue;
        }

        try preflight(
            arena,
            effect.kind,
            relation_binding,
            values,
            active,
            effect.access_ordinal,
            effect.source_span,
        );
        // State retirement is a single semantic operation even though the
        // relation protocol carries two adjacent events.
        switch (effect.kind) {
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
                if (index == 0 or
                    arena.effectsView()[index - 1].kind != .state_consume)
                {
                    return error.BindingKindMismatch;
                }
            },
            else => {},
        }
        index += 1;
    }

    if (!memory_mode and groups.len != 0) {
        const first = groups.items[0];
        for (groups.items[1..groups.len]) |group| {
            if (group.instruction_clock != first.instruction_clock or
                group.active != first.active)
            {
                return error.MultipleAccessSchedules;
            }
        }
    }
    if (!memory_mode) try validateMachineDerivedUses(arena, groups);
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
    try preflightRelation(
        arena,
        relation_binding,
        values,
        active,
        access_ordinal,
        span,
    );
    const schema = relation.getById(relation_binding.schema) orelse
        return error.UnknownSchema;
    try validateKindBinding(kind, schema.domain, relation_binding.role, access_ordinal);
}

fn preflightRelation(
    arena: *const ir.Arena,
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

const ValidatedAccessGroup = struct {
    first_effect: usize,
    address: types.ValueId,
    current_clock: types.ValueId,
    gap: types.ValueId,
    instruction_clock: types.ValueId,
    active: types.ValueId,
};

const ValidatedAccessGroups = struct {
    items: [MAX_ACCESS_GROUPS]ValidatedAccessGroup = undefined,
    len: usize = 0,
};

fn validateRegisterGroup(
    arena: *const ir.Arena,
    first_index: usize,
    expected_ordinal: u8,
) Error!ValidatedAccessGroup {
    if (first_index + 3 > arena.effectsView().len)
        return error.InvalidAccessGroup;
    const group_effects = arena.effectsView()[first_index .. first_index + 3];
    const consume = group_effects[0];
    const emitted = group_effects[1];
    const gap_effect = group_effects[2];
    if (!isRegisterKind(consume.kind) or
        emitted.kind != consume.kind or
        gap_effect.kind != consume.kind)
    {
        return error.InvalidAccessGroup;
    }
    const active = consume.liveness orelse return error.MissingRelationLiveness;
    if (emitted.liveness != active or gap_effect.liveness != active)
        return error.InvalidAccessGroup;
    if (consume.access_ordinal != expected_ordinal or
        emitted.access_ordinal != expected_ordinal or
        gap_effect.access_ordinal != expected_ordinal)
    {
        return error.InvalidAccessGroup;
    }

    const consume_binding = binding(.memory_access, .consume);
    const emit_binding = binding(.memory_access, .emit);
    const gap_binding = binding(.range_check_20, .request);
    if (!bindingEqual(consume.binding, consume_binding) or
        !bindingEqual(emitted.binding, emit_binding) or
        !bindingEqual(gap_effect.binding, gap_binding))
    {
        return error.InvalidAccessGroup;
    }

    const consume_id = types.idFromIndex(types.EffectId, first_index) catch
        return error.UnknownEffect;
    const emit_id = types.idFromIndex(types.EffectId, first_index + 1) catch
        return error.UnknownEffect;
    const gap_id = types.idFromIndex(types.EffectId, first_index + 2) catch
        return error.UnknownEffect;
    const consume_values = arena.effectValues(consume_id) orelse
        return error.UnknownEffect;
    const emit_values = arena.effectValues(emit_id) orelse
        return error.UnknownEffect;
    const gap_values = arena.effectValues(gap_id) orelse
        return error.UnknownEffect;
    try preflightRelation(
        arena,
        consume_binding,
        consume_values,
        active,
        expected_ordinal,
        consume.source_span,
    );
    try preflightRelation(
        arena,
        emit_binding,
        emit_values,
        active,
        expected_ordinal,
        emitted.source_span,
    );
    try preflightRelation(
        arena,
        gap_binding,
        gap_values,
        active,
        expected_ordinal,
        gap_effect.source_span,
    );

    if (consume_values.len != 7 or emit_values.len != 7 or gap_values.len != 1)
        return error.InvalidAccessGroup;
    if (consume_values[0] != emit_values[0] or
        !isCanonicalFeltZero(arena, consume_values[0]) or
        consume_values[1] != emit_values[1])
    {
        return error.InvalidAccessGroup;
    }
    const address_node = arena.node(consume_values[1]) orelse
        return error.UnknownValue;
    _ = switch (address_node.key.op) {
        .machine_derived => |derived| switch (derived) {
            .register_address => |address| address,
            else => return error.InvalidAccessGroup,
        },
        else => return error.InvalidAccessGroup,
    };

    const ordinal: types.AccessOrdinal = @enumFromInt(expected_ordinal);
    const phase = phaseForOrdinal(ordinal);
    const current_node = arena.node(emit_values[2]) orelse
        return error.UnknownValue;
    const current = switch (current_node.key.op) {
        .machine_derived => |derived| switch (derived) {
            .access_clock => |clock| clock,
            else => return error.InvalidAccessGroup,
        },
        else => return error.InvalidAccessGroup,
    };
    if (current.phase != phase) return error.InvalidAccessGroup;

    const gap_node = arena.node(gap_values[0]) orelse return error.UnknownValue;
    const gap = switch (gap_node.key.op) {
        .machine_derived => |derived| switch (derived) {
            .strict_clock_gap => |clock_gap| clock_gap,
            else => return error.InvalidAccessGroup,
        },
        else => return error.InvalidAccessGroup,
    };
    if (gap.current_clock != emit_values[2] or
        gap.previous_clock != consume_values[2] or
        gap.active != active or
        gap.phase != phase)
    {
        return error.InvalidAccessGroup;
    }

    if (consume.kind == .register_read) {
        for (consume_values[3..7], emit_values[3..7]) |previous, next| {
            if (previous != next) return error.InvalidAccessGroup;
        }
    }

    return .{
        .first_effect = first_index,
        .address = consume_values[1],
        .current_clock = emit_values[2],
        .gap = gap_values[0],
        .instruction_clock = current.instruction_clock,
        .active = active,
    };
}

fn validateMachineDerivedUses(
    arena: *const ir.Arena,
    groups: ValidatedAccessGroups,
) Error!void {
    // Derived values may not leak into generic expression construction. The
    // only node-to-node edge is the current clock carried by its strict gap.
    for (arena.nodesView()) |node| switch (node.key.op) {
        .constant, .input, .hint_output, .call_output => {},
        .add, .sub, .mul => |binary| {
            try rejectMachineDerived(arena, binary.lhs);
            try rejectMachineDerived(arena, binary.rhs);
        },
        .neg => |value| try rejectMachineDerived(arena, value),
        .select => |selection| {
            try rejectMachineDerived(arena, selection.selector);
            try rejectMachineDerived(arena, selection.when_true);
            try rejectMachineDerived(arena, selection.when_false);
        },
        .machine_derived => |derived| switch (derived) {
            .register_address => |address| {
                try rejectMachineDerived(arena, address.index);
            },
            .aligned_word_address => |address| {
                try rejectMachineDerived(arena, address.word_index);
            },
            .access_clock => |clock| {
                try rejectMachineDerived(arena, clock.instruction_clock);
            },
            .strict_clock_gap => |gap| {
                try rejectMachineDerived(arena, gap.previous_clock);
                try rejectMachineDerived(arena, gap.active);
                const current = machineDerived(arena, gap.current_clock) orelse
                    return error.UnexpectedMachineDerivedUse;
                switch (current) {
                    .access_clock => {},
                    else => return error.UnexpectedMachineDerivedUse,
                }
            },
        },
    };

    for (arena.constraintsView()) |constraint| {
        try rejectMachineDerived(arena, constraint.root);
        if (constraint.gate) |gate| try rejectMachineDerived(arena, gate);
    }
    inline for (.{
        arena.hint_inputs.items,
        arena.hint_outputs.items,
        arena.hint_binding_values.items,
        arena.function_inputs.items,
        arena.function_outputs.items,
        arena.call_arguments.items,
        arena.call_outputs.items,
    }) |values| {
        for (values) |value| try rejectMachineDerived(arena, value);
    }

    for (arena.effectsView(), 0..) |_, effect_index| {
        const effect_id = types.idFromIndex(types.EffectId, effect_index) catch
            return error.UnknownEffect;
        const values = arena.effectValues(effect_id) orelse
            return error.UnknownEffect;
        for (values, 0..) |value, field_index| {
            if (machineDerived(arena, value) == null) continue;
            if (!allowedEffectUse(groups, effect_index, field_index, value))
                return error.UnexpectedMachineDerivedUse;
        }
    }

    for (arena.nodesView(), 0..) |node, node_index| switch (node.key.op) {
        .machine_derived => |derived| {
            const id = types.idFromIndex(types.ValueId, node_index) catch
                return error.UnknownValue;
            var matched = false;
            for (groups.items[0..groups.len]) |group| {
                matched = matched or switch (derived) {
                    .register_address => id == group.address,
                    .aligned_word_address => false,
                    .access_clock => id == group.current_clock,
                    .strict_clock_gap => id == group.gap,
                };
            }
            if (!matched) return error.OrphanedMachineDerived;
        },
        else => {},
    };
}

fn allowedEffectUse(
    groups: ValidatedAccessGroups,
    effect_index: usize,
    field_index: usize,
    value: types.ValueId,
) bool {
    for (groups.items[0..groups.len]) |group| {
        if (value == group.address and
            (effect_index == group.first_effect or
                effect_index == group.first_effect + 1) and
            field_index == 1)
        {
            return true;
        }
        if (value == group.current_clock and
            effect_index == group.first_effect + 1 and
            field_index == 2)
        {
            return true;
        }
        if (value == group.gap and
            effect_index == group.first_effect + 2 and
            field_index == 0)
        {
            return true;
        }
    }
    return false;
}

fn machineDerived(
    arena: *const ir.Arena,
    value: types.ValueId,
) ?expr.MachineDerived {
    const node = arena.node(value) orelse return null;
    return switch (node.key.op) {
        .machine_derived => |derived| derived,
        else => null,
    };
}

fn rejectMachineDerived(
    arena: *const ir.Arena,
    value: types.ValueId,
) Error!void {
    if (machineDerived(arena, value) != null)
        return error.UnexpectedMachineDerivedUse;
}

fn isCanonicalFeltZero(arena: *const ir.Arena, value: types.ValueId) bool {
    const node = arena.node(value) orelse return false;
    if (!std.meta.eql(node.key.ty, types.Type.felt)) return false;
    return switch (node.key.op) {
        .constant => |constant| switch (constant) {
            .field => |field| field == 0,
            .unsigned => false,
        },
        else => false,
    };
}

fn bindingEqual(
    actual: ?program.RelationBinding,
    expected: program.RelationBinding,
) bool {
    const present = actual orelse return false;
    return present.schema == expected.schema and
        present.schema_version == expected.schema_version and
        present.role == expected.role;
}

fn requireType(
    arena: *const ir.Arena,
    value: types.ValueId,
    expected: types.Type,
) Error!void {
    const node = arena.node(value) orelse return error.UnknownValue;
    if (!std.meta.eql(node.key.ty, expected)) return error.InvalidFieldType;
    if (machineDerived(arena, value) != null)
        return error.UnexpectedMachineDerivedUse;
}

fn isRegisterKind(kind: program.EffectKind) bool {
    return kind == .register_read or kind == .register_write;
}

fn isRangeDomain(domain: relation.Domain) bool {
    return switch (domain) {
        .range_check_20,
        .range_check_8_11,
        .range_check_8_8_4,
        .range_check_8_8,
        .range_check_m31,
        => true,
        else => false,
    };
}

fn phaseForOrdinal(ordinal: types.AccessOrdinal) types.AccessPhase {
    return switch (ordinal) {
        .first => .first,
        .second => .second,
        .third => .third,
    };
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

fn hasMachineDerivedNode(arena: *const ir.Arena) bool {
    for (arena.nodesView()) |node| switch (node.key.op) {
        .machine_derived => return true,
        else => {},
    };
    return false;
}

comptime {
    var maximum: usize = 0;
    for (relation.schemas) |schema| maximum = @max(maximum, schema.fields.len);
    if (maximum != MAX_ARITY)
        @compileError("typed effect arity must track the relation registry");
}
