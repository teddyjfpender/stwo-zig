//! Closed proof for the production load/store component's conditional access
//! schedule. Relation tuples remain byte-for-byte identical to production;
//! semantic aliases own no columns and are admitted only at named effect fields.

const evidence = @import("conditional_access_evidence.zig");
const expr = @import("expr.zig");
const ir = @import("ir.zig");
const machine_validation = @import("machine_derived_validation.zig");
const program = @import("program.zig");
const relation = @import("relation.zig");
const source = @import("source.zig");
const types = @import("types.zig");

pub const EFFECT_COUNT: usize = 11;
pub const ALIAS_COUNT: usize = 6;

pub const Error = ir.Error || relation.Error || evidence.Error || error{
    DuplicateConditionalAccessPlan,
    InvalidConditionalAccessAlias,
    InvalidConditionalAccessEffect,
    InvalidConditionalAccessOrder,
    InvalidConditionalAccessProof,
    OrphanedMachineDerived,
    UnexpectedMachineDerivedUse,
    UnexpectedConditionalAccessUse,
    UnknownEffect,
};

pub const Prepared = struct {
    first_effect: usize,

    pub fn owns(self: Prepared, index: usize) bool {
        return index >= self.first_effect and index < self.first_effect + EFFECT_COUNT;
    }
};

pub fn hasCapability(arena: *const ir.Arena) bool {
    return arena.conditional_access_plans.items.len != 0;
}

pub fn sourceForTarget(
    arena: *const ir.Arena,
    target: types.ValueId,
) ?types.ValueId {
    for (arena.conditional_access_plans.items) |proof| {
        for (aliases(proof)) |item| if (item.target == target) return item.source;
    }
    return null;
}

pub fn isAliasTarget(arena: *const ir.Arena, value: types.ValueId) bool {
    return sourceForTarget(arena, value) != null;
}

pub fn internAlias(
    arena: *ir.Arena,
    source_value: types.ValueId,
    target_type: types.Type,
    span: source.SourceSpan,
) Error!program.SemanticAlias {
    try arena.validateSpan(span);
    const source_node = arena.node(source_value) orelse return error.UnknownValue;
    if (isAliasTarget(arena, source_value)) return error.InvalidConditionalAccessAlias;
    const key = expr.Key{ .ty = target_type, .op = source_node.key.op };
    if (arena.interned_nodes.get(key) != null)
        return error.InvalidConditionalAccessAlias;
    return .{
        .source = source_value,
        .target = try arena.internTypedNode(key, span),
    };
}

/// Validate and prepare the single closed conditional plan without allocation.
pub fn prepare(arena: *const ir.Arena) Error!?Prepared {
    if (arena.conditional_access_plans.items.len == 0) return null;
    if (arena.conditional_access_plans.items.len != 1)
        return error.DuplicateConditionalAccessPlan;
    const proof = arena.conditional_access_plans.items[0];
    try arena.validateSpan(proof.source_span);
    const first = types.idIndex(proof.first_effect);
    if (first + EFFECT_COUNT > arena.effectsView().len or
        types.idIndex(proof.aligned_range) != first + 3 or
        types.idIndex(proof.base_range) != first + 4)
    {
        return error.InvalidConditionalAccessOrder;
    }

    try evidence.validate(arena, proof);

    var machine_groups = machine_validation.AccessGroups{ .len = 1 };
    machine_groups.items[0] = try validateFirstGroup(arena, proof, first);
    try validateConditionalGroup(arena, proof, first + 5, true);
    try validateConditionalGroup(arena, proof, first + 8, false);
    try validateAliasUses(arena, proof, first);
    try machine_validation.validate(arena, machine_groups);
    return .{ .first_effect = first };
}

fn validateFirstGroup(
    arena: *const ir.Arena,
    proof: program.ConditionalAccessPlanProof,
    first: usize,
) Error!machine_validation.AccessGroup {
    const values = try validateGroupEnvelope(
        arena,
        first,
        .register_read,
        1,
        proof.active,
    );
    if (!evidence.isZero(arena, values.consume[0]) or
        values.consume[0] != values.emit[0] or
        values.consume[1] != values.emit[1])
    {
        return error.InvalidConditionalAccessEffect;
    }
    const address = machine(arena, values.consume[1]) orelse
        return error.InvalidConditionalAccessEffect;
    switch (address) {
        .register_address => {},
        else => return error.InvalidConditionalAccessEffect,
    }
    for (values.consume[3..7], values.emit[3..7]) |before, after|
        if (before != after) return error.InvalidConditionalAccessEffect;
    const current = machine(arena, values.emit[2]) orelse
        return error.InvalidConditionalAccessEffect;
    const access_clock = switch (current) {
        .access_clock => |clock| clock,
        else => return error.InvalidConditionalAccessEffect,
    };
    if (access_clock.instruction_clock != proof.instruction_clock or
        access_clock.phase != .first)
    {
        return error.InvalidConditionalAccessEffect;
    }
    const gap = machine(arena, values.gap[0]) orelse
        return error.InvalidConditionalAccessEffect;
    const strict = switch (gap) {
        .strict_clock_gap => |item| item,
        else => return error.InvalidConditionalAccessEffect,
    };
    if (strict.current_clock != values.emit[2] or
        strict.previous_clock != values.consume[2] or
        strict.active != proof.active or strict.phase != .first)
    {
        return error.InvalidConditionalAccessEffect;
    }
    return .{
        .first_effect = first,
        .address = values.consume[1],
        .current_clock = values.emit[2],
        .gap = values.gap[0],
        .instruction_clock = proof.instruction_clock,
        .active = proof.active,
    };
}

fn validateConditionalGroup(
    arena: *const ir.Arena,
    proof: program.ConditionalAccessPlanProof,
    first: usize,
    is_source: bool,
) Error!void {
    const kind: program.EffectKind = if (is_source) .memory_read else .memory_write;
    const ordinal: u8 = if (is_source) 2 else 3;
    const values = try validateGroupEnvelope(arena, first, kind, ordinal, proof.active);
    const address_space = if (is_source) proof.is_load else proof.store_source;
    const address = if (is_source) proof.source_address else proof.destination_address;
    const clock = if (is_source) proof.source_clock else proof.destination_clock;
    const gap = if (is_source) proof.source_gap else proof.destination_gap;
    if (values.consume[0] != address_space or values.emit[0] != address_space or
        values.consume[1] != address.target or values.emit[1] != address.target or
        values.emit[2] != clock.target or values.gap[0] != gap.target or
        !evidence.isStrictGap(arena, gap.source, clock.source, values.consume[2]))
    {
        return error.InvalidConditionalAccessEffect;
    }
    if (is_source) for (values.consume[3..7], values.emit[3..7]) |before, after|
        if (before != after) return error.InvalidConditionalAccessEffect;
}

const GroupValues = struct {
    consume: []const types.ValueId,
    emit: []const types.ValueId,
    gap: []const types.ValueId,
};

fn validateGroupEnvelope(
    arena: *const ir.Arena,
    first: usize,
    kind: program.EffectKind,
    ordinal: u8,
    active: types.ValueId,
) Error!GroupValues {
    if (first + 3 > arena.effectsView().len)
        return error.InvalidConditionalAccessOrder;
    const consume = arena.effectsView()[first];
    const emit = arena.effectsView()[first + 1];
    const gap = arena.effectsView()[first + 2];
    if (consume.kind != kind or emit.kind != kind or gap.kind != kind or
        consume.liveness != active or emit.liveness != active or gap.liveness != active or
        consume.access_ordinal != ordinal or emit.access_ordinal != ordinal or
        gap.access_ordinal != ordinal or
        !bindingIs(consume.binding, .memory_access, .consume) or
        !bindingIs(emit.binding, .memory_access, .emit) or
        !bindingIs(gap.binding, .range_check_20, .request))
    {
        return error.InvalidConditionalAccessEffect;
    }
    const consume_values = try valuesAt(arena, first);
    const emit_values = try valuesAt(arena, first + 1);
    const gap_values = try valuesAt(arena, first + 2);
    if (consume_values.len != 7 or emit_values.len != 7 or gap_values.len != 1)
        return error.InvalidConditionalAccessEffect;
    try validateRelation(arena, consume.binding.?, consume_values, ordinal);
    try validateRelation(arena, emit.binding.?, emit_values, ordinal);
    try validateRelation(arena, gap.binding.?, gap_values, ordinal);
    return .{ .consume = consume_values, .emit = emit_values, .gap = gap_values };
}

fn validateAliasUses(
    arena: *const ir.Arena,
    proof: program.ConditionalAccessPlanProof,
    first: usize,
) Error!void {
    for (arena.nodesView()) |node| switch (node.key.op) {
        .constant, .input, .hint_output, .call_output => {},
        .add, .sub, .mul => |operation| {
            try rejectAlias(arena, operation.lhs);
            try rejectAlias(arena, operation.rhs);
        },
        .neg => |value| try rejectAlias(arena, value),
        .select => |selection| {
            try rejectAlias(arena, selection.selector);
            try rejectAlias(arena, selection.when_true);
            try rejectAlias(arena, selection.when_false);
        },
        .machine_derived => |derived| switch (derived) {
            .register_address => |item| try rejectAlias(arena, item.index),
            .aligned_word_address => |item| try rejectAlias(arena, item.word_index),
            .access_clock => |item| try rejectAlias(arena, item.instruction_clock),
            .strict_clock_gap => |item| {
                try rejectAlias(arena, item.current_clock);
                try rejectAlias(arena, item.previous_clock);
                try rejectAlias(arena, item.active);
            },
            .instruction_next_pc => |item| try rejectAlias(arena, item.current),
            .instruction_next_clock => |item| try rejectAlias(arena, item.current),
        },
    };
    for (arena.constraintsView()) |constraint| {
        try rejectAlias(arena, constraint.root);
        if (constraint.gate) |gate| try rejectAlias(arena, gate);
    }
    inline for (.{
        arena.hint_inputs.items,
        arena.hint_outputs.items,
        arena.hint_binding_values.items,
        arena.function_inputs.items,
        arena.function_outputs.items,
        arena.call_arguments.items,
        arena.call_outputs.items,
    }) |items| for (items) |value| try rejectAlias(arena, value);

    const expected = [_]struct { alias: program.SemanticAlias, uses: [2]?struct { effect: usize, field: usize } }{
        .{ .alias = proof.source_address, .uses = .{ .{ .effect = first + 5, .field = 1 }, .{ .effect = first + 6, .field = 1 } } },
        .{ .alias = proof.source_clock, .uses = .{ .{ .effect = first + 6, .field = 2 }, null } },
        .{ .alias = proof.source_gap, .uses = .{ .{ .effect = first + 7, .field = 0 }, null } },
        .{ .alias = proof.destination_address, .uses = .{ .{ .effect = first + 8, .field = 1 }, .{ .effect = first + 9, .field = 1 } } },
        .{ .alias = proof.destination_clock, .uses = .{ .{ .effect = first + 9, .field = 2 }, null } },
        .{ .alias = proof.destination_gap, .uses = .{ .{ .effect = first + 10, .field = 0 }, null } },
    };
    for (expected) |entry| {
        var seen: usize = 0;
        for (arena.effectsView(), 0..) |effect, effect_index| {
            if (effect.liveness == entry.alias.target)
                return error.UnexpectedConditionalAccessUse;
            const values = try valuesAt(arena, effect_index);
            for (values, 0..) |value, field| if (value == entry.alias.target) {
                var permitted = false;
                for (entry.uses) |maybe_use| {
                    if (maybe_use) |use| {
                        permitted = permitted or
                            (use.effect == effect_index and use.field == field);
                    }
                }
                if (!permitted) return error.UnexpectedConditionalAccessUse;
                seen += 1;
            };
        }
        var wanted: usize = 0;
        for (entry.uses) |item| wanted += @intFromBool(item != null);
        if (seen != wanted) return error.UnexpectedConditionalAccessUse;
    }
}

fn aliases(proof: program.ConditionalAccessPlanProof) [ALIAS_COUNT]program.SemanticAlias {
    return .{
        proof.source_address,
        proof.source_clock,
        proof.source_gap,
        proof.destination_address,
        proof.destination_clock,
        proof.destination_gap,
    };
}

fn validateRelation(
    arena: *const ir.Arena,
    binding_value: program.RelationBinding,
    values: []const types.ValueId,
    ordinal: ?u8,
) Error!void {
    const schema = relation.getById(binding_value.schema) orelse
        return error.UnknownSchema;
    if (schema.version != binding_value.schema_version)
        return error.InvalidConditionalAccessEffect;
    var field_types: [7]types.Type = undefined;
    if (values.len > field_types.len) return error.InvalidConditionalAccessEffect;
    for (values, field_types[0..values.len]) |value, *ty|
        ty.* = (arena.node(value) orelse return error.UnknownValue).key.ty;
    try relation.validateEvent(binding_value.schema, binding_value.role, field_types[0..values.len], ordinal);
}

fn valuesAt(arena: *const ir.Arena, index: usize) Error![]const types.ValueId {
    const id = types.idFromIndex(types.EffectId, index) catch return error.UnknownEffect;
    return arena.effectValues(id) orelse error.UnknownEffect;
}

fn bindingIs(
    actual: ?program.RelationBinding,
    domain: relation.Domain,
    role: relation.Role,
) bool {
    const present = actual orelse return false;
    const schema = relation.get(domain);
    return present.schema == schema.id and present.schema_version == schema.version and
        present.role == role;
}

fn machine(arena: *const ir.Arena, value: types.ValueId) ?expr.MachineDerived {
    const node = arena.node(value) orelse return null;
    return switch (node.key.op) {
        .machine_derived => |item| item,
        else => null,
    };
}

fn rejectAlias(arena: *const ir.Arena, value: types.ValueId) Error!void {
    if (isAliasTarget(arena, value)) return error.UnexpectedConditionalAccessUse;
}
