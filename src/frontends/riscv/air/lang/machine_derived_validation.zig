//! Allocation-free use validation for closed machine-derived AIR values.

const expr = @import("expr.zig");
const ir = @import("ir.zig");
const range_refinement = @import("range_refinement.zig");
const types = @import("types.zig");

pub const Error = error{
    OrphanedMachineDerived,
    UnexpectedMachineDerivedUse,
    UnknownEffect,
    UnknownValue,
};

pub const AccessGroup = struct {
    first_effect: usize,
    address: types.ValueId,
    current_clock: types.ValueId,
    gap: types.ValueId,
    instruction_clock: types.ValueId,
    active: types.ValueId,
};

pub const AccessGroups = struct {
    items: [3]AccessGroup = undefined,
    len: usize = 0,
};

pub fn validate(arena: *const ir.Arena, groups: AccessGroups) Error!void {
    // Closed values cannot leak into generic expressions. The sole legal node
    // edge is the access clock carried by its strict-gap derivation.
    for (arena.nodesView(), 0..) |node, node_index| {
        const parent = types.idFromIndex(types.ValueId, node_index) catch
            return error.UnknownValue;
        switch (node.key.op) {
            .constant, .input, .hint_output, .call_output => {},
            .add, .sub, .mul => |binary| {
                try rejectClosedEdge(arena, parent, binary.lhs);
                try rejectClosedEdge(arena, parent, binary.rhs);
            },
            .neg => |value| try rejectClosedEdge(arena, parent, value),
            .select => |selection| {
                try rejectClosedEdge(arena, parent, selection.selector);
                try rejectClosedEdge(arena, parent, selection.when_true);
                try rejectClosedEdge(arena, parent, selection.when_false);
            },
            .machine_derived => |derived| switch (derived) {
                .register_address => |address| try rejectClosedEdge(arena, parent, address.index),
                .aligned_word_address => |address| try rejectClosedEdge(arena, parent, address.word_index),
                .access_clock => |clock| try rejectClosedEdge(arena, parent, clock.instruction_clock),
                .strict_clock_gap => |gap| {
                    try rejectClosedEdge(arena, parent, gap.previous_clock);
                    try rejectClosedEdge(arena, parent, gap.active);
                    const current = get(arena, gap.current_clock) orelse
                        return error.UnexpectedMachineDerivedUse;
                    switch (current) {
                        .access_clock => {},
                        else => return error.UnexpectedMachineDerivedUse,
                    }
                },
                .instruction_next_pc => |next| try rejectClosedEdge(arena, parent, next.current),
                .instruction_next_clock => |next| try rejectClosedEdge(arena, parent, next.current),
            },
        }
    }

    for (arena.constraintsView(), 0..) |constraint, constraint_index| {
        const constraint_id = types.idFromIndex(
            types.ConstraintId,
            constraint_index,
        ) catch return error.UnknownValue;
        if (!range_refinement.isCommittedControlConstraint(arena, constraint_id))
            try rejectClosed(arena, constraint.root);
        if (constraint.gate) |gate| try rejectClosed(arena, gate);
    }
    inline for (.{
        arena.hint_inputs.items,
        arena.hint_outputs.items,
        arena.hint_binding_values.items,
        arena.function_inputs.items,
        arena.function_outputs.items,
        arena.call_arguments.items,
        arena.call_outputs.items,
    }) |values| for (values) |value| try rejectClosed(arena, value);

    for (arena.effectsView(), 0..) |_, effect_index| {
        const effect_id = types.idFromIndex(types.EffectId, effect_index) catch
            return error.UnknownEffect;
        const values = arena.effectValues(effect_id) orelse
            return error.UnknownEffect;
        try validateSequentialPair(arena, effect_index, values);
        for (values, 0..) |value, field_index| {
            if (get(arena, value) == null and
                !isControlTarget(arena, value) and
                range_refinement.committedControlExpressionRole(arena, value) == null)
            {
                continue;
            }
            if (!allowedEffectUse(arena, groups, effect_index, field_index, value))
                return error.UnexpectedMachineDerivedUse;
        }
    }

    for (arena.nodesView(), 0..) |node, node_index| switch (node.key.op) {
        .machine_derived => {
            const id = types.idFromIndex(types.ValueId, node_index) catch
                return error.UnknownValue;
            if (!hasAllowedUse(arena, groups, id))
                return error.OrphanedMachineDerived;
        },
        else => {},
    };
    for (arena.committed_program_control_targets.items, 0..) |proof, proof_index| {
        // A committed next-PC value has exactly one proof owner.  Do not rely
        // on the terminal refinement-order pass to reject duplicate records:
        // machine-use closure is the earlier authority for singular ownership.
        for (arena.committed_program_control_targets.items[0..proof_index]) |prior| {
            if (prior.committed_target == proof.committed_target)
                return error.OrphanedMachineDerived;
        }
        if (committedTargetUseCount(arena, groups, proof.committed_target) != 1)
            return error.OrphanedMachineDerived;
    }
}

fn validateSequentialPair(
    arena: *const ir.Arena,
    effect_index: usize,
    values: []const types.ValueId,
) Error!void {
    const effect = arena.effectsView()[effect_index];
    if (effect.kind != .state_produce or values.len != 2) return;
    const maybe_next_pc = if (get(arena, values[0])) |derived|
        switch (derived) {
            .instruction_next_pc => |next| next,
            else => null,
        }
    else
        null;
    const maybe_next_clock = if (get(arena, values[1])) |derived|
        switch (derived) {
            .instruction_next_clock => |next| next,
            else => null,
        }
    else
        null;
    const aligned_next_pc = if (effect.liveness) |liveness|
        range_refinement.hasAlignedControlTargetPremise(arena, values[0], liveness)
    else
        false;
    const program_next_pc = if (effect.liveness) |liveness|
        range_refinement.programControlTargetPremise(arena, values[0], liveness)
    else
        null;
    const committed_next_pc = if (effect.liveness) |liveness|
        range_refinement.committedProgramControlTargetPremise(
            arena,
            values[0],
            liveness,
        )
    else
        null;
    if (maybe_next_pc == null and maybe_next_clock == null and
        !aligned_next_pc and program_next_pc == null and
        committed_next_pc == null) return;
    const next_clock = maybe_next_clock orelse return error.UnexpectedMachineDerivedUse;
    if (effect_index == 0) return error.UnexpectedMachineDerivedUse;
    const consume = arena.effectsView()[effect_index - 1];
    const before = consume.values.slice(arena.effectValuesView()) orelse
        return error.UnknownEffect;
    const program_matches = if (program_next_pc) |proof|
        proof.current_pc == before[0] and
            types.idIndex(proof.program_effect) < effect_index - 1
    else
        false;
    const committed_matches = if (committed_next_pc) |proof|
        proof.current_pc == before[0] and
            types.idIndex(proof.program_effect) < effect_index - 1
    else
        false;
    if (consume.kind != .state_consume or consume.liveness != effect.liveness or
        before.len != 2 or next_clock.current != before[1] or
        (!aligned_next_pc and !program_matches and !committed_matches and
            (maybe_next_pc == null or maybe_next_pc.?.current != before[0])))
        return error.UnexpectedMachineDerivedUse;
}

fn hasAllowedUse(
    arena: *const ir.Arena,
    groups: AccessGroups,
    id: types.ValueId,
) bool {
    for (arena.effectsView(), 0..) |effect, effect_index| {
        const values = effect.values.slice(arena.effectValuesView()) orelse
            return false;
        for (values, 0..) |value, field_index| {
            if (value == id and
                allowedEffectUse(arena, groups, effect_index, field_index, value))
            {
                return true;
            }
        }
    }
    return false;
}

fn allowedEffectUse(
    arena: *const ir.Arena,
    groups: AccessGroups,
    effect_index: usize,
    field_index: usize,
    value: types.ValueId,
) bool {
    for (groups.items[0..groups.len]) |group| {
        if (value == group.address and
            (effect_index == group.first_effect or
                effect_index == group.first_effect + 1) and field_index == 1)
            return true;
        if (value == group.current_clock and
            effect_index == group.first_effect + 1 and field_index == 2)
            return true;
        if (value == group.gap and
            effect_index == group.first_effect + 2 and field_index == 0)
            return true;
    }
    if (effect_index == 0 or field_index > 1) return false;
    const effect = arena.effectsView()[effect_index];
    const consume = arena.effectsView()[effect_index - 1];
    if (effect.kind != .state_produce or consume.kind != .state_consume or
        effect.liveness != consume.liveness)
        return false;
    const before = consume.values.slice(arena.effectValuesView()) orelse
        return false;
    if (before.len != 2) return false;
    if (field_index == 0 and effect.liveness != null and
        range_refinement.hasAlignedControlTargetPremise(
            arena,
            value,
            effect.liveness.?,
        )) return true;
    if (field_index == 0 and effect.liveness != null) {
        if (range_refinement.programControlTargetPremise(
            arena,
            value,
            effect.liveness.?,
        )) |present| {
            return present.current_pc == before[0] and
                types.idIndex(present.program_effect) < effect_index - 1;
        }
    }
    if (field_index == 0 and effect.liveness != null) {
        if (range_refinement.committedProgramControlTargetPremise(
            arena,
            value,
            effect.liveness.?,
        )) |present| {
            return present.current_pc == before[0] and
                types.idIndex(present.program_effect) < effect_index - 1;
        }
    }
    const derived = get(arena, value) orelse return false;
    return switch (derived) {
        .instruction_next_pc => |next| field_index == 0 and next.current == before[0],
        .instruction_next_clock => |next| field_index == 1 and next.current == before[1],
        else => false,
    };
}

fn isControlTarget(arena: *const ir.Arena, value: types.ValueId) bool {
    return range_refinement.alignedControlTargetPremiseLiveness(arena, value) != null or
        range_refinement.programControlTargetPremiseLiveness(arena, value) != null or
        range_refinement.committedProgramControlTargetPremiseLiveness(arena, value) != null;
}

fn get(arena: *const ir.Arena, value: types.ValueId) ?expr.MachineDerived {
    const node = arena.node(value) orelse return null;
    return switch (node.key.op) {
        .machine_derived => |derived| derived,
        else => null,
    };
}

pub fn isDerived(arena: *const ir.Arena, value: types.ValueId) bool {
    return get(arena, value) != null;
}

fn rejectClosed(arena: *const ir.Arena, value: types.ValueId) Error!void {
    if (get(arena, value) != null or isControlTarget(arena, value) or
        range_refinement.committedControlExpressionRole(arena, value) != null)
        return error.UnexpectedMachineDerivedUse;
}

fn rejectClosedEdge(
    arena: *const ir.Arena,
    parent: types.ValueId,
    child: types.ValueId,
) Error!void {
    if (range_refinement.isCommittedControlExpressionEdge(arena, parent, child))
        return;
    try rejectClosed(arena, child);
}

fn committedTargetUseCount(
    arena: *const ir.Arena,
    groups: AccessGroups,
    target: types.ValueId,
) usize {
    var count: usize = 0;
    for (arena.effectsView(), 0..) |effect, effect_index| {
        const values = effect.values.slice(arena.effectValuesView()) orelse
            return 0;
        for (values, 0..) |value, field_index| {
            if (value == target and
                allowedEffectUse(arena, groups, effect_index, field_index, value))
            {
                count += 1;
            }
        }
    }
    return count;
}

comptime {
    if (@intFromEnum(types.AccessOrdinal.third) != 3)
        @compileError("machine-derived validation capacity must track access ordinals");
}
