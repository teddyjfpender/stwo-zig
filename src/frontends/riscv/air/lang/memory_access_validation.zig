//! Allocation-free validation and fixed permutation metadata for E-003.
//!
//! Relation-entry order and physical tracker order are deliberately separate:
//! load groups serialize as rs1/src/dst while resolving as rs1/dst/src.

const std = @import("std");
const access_schedule = @import("access_schedule.zig");
const expr = @import("expr.zig");
const ir = @import("ir.zig");
const machine_validation = @import("machine_derived_validation.zig");
const program = @import("program.zig");
const relation = @import("relation.zig");
const types = @import("types.zig");

pub const GROUP_COUNT: usize = 3;

pub const Error = relation.Error || error{
    AccessScheduleExhausted,
    BindingVersionMismatch,
    InvalidAccessGroup,
    InvalidAccessPlan,
    MissingAlignedRangeEvidence,
    MissingRelationBinding,
    MissingRelationLiveness,
    MultipleAccessSchedules,
    OrphanedMachineDerived,
    RelationArityTooLarge,
    UnexpectedMachineDerivedUse,
    UnknownEffect,
    UnknownValue,
};

pub const Group = struct {
    first_effect: types.EffectId,
    kind: program.EffectKind,
    ordinal: types.AccessOrdinal,
    phase: types.AccessPhase,
    address: types.ValueId,
    current_clock: types.ValueId,
    gap: types.ValueId,
};

/// Copy-safe metadata prepared once outside any row loop.
pub const PreparedPlan = struct {
    kind: access_schedule.AccessPlanKind,
    groups_by_ordinal: [GROUP_COUNT]Group,
    ordinal_index_by_phase: [GROUP_COUNT]u8,
    aligned_range: types.EffectId,
    word_index: types.ValueId,
    instruction_clock: types.ValueId,
    active: types.ValueId,

    pub fn groupAtPhase(
        self: *const PreparedPlan,
        phase: types.AccessPhase,
    ) *const Group {
        const phase_index = @intFromEnum(phase) - 1;
        return &self.groups_by_ordinal[self.ordinal_index_by_phase[phase_index]];
    }
};

const ValidatedGroup = struct {
    first_effect: usize,
    kind: program.EffectKind,
    ordinal: types.AccessOrdinal,
    phase: types.AccessPhase,
    address_space: types.ValueId,
    address: types.ValueId,
    previous_clock: types.ValueId,
    current_clock: types.ValueId,
    gap: types.ValueId,
    instruction_clock: types.ValueId,
    active: types.ValueId,
};

/// Re-establish the complete fixed plan using stack-bounded state only.
pub fn prepare(arena: *const ir.Arena) Error!PreparedPlan {
    var groups: [GROUP_COUNT]ValidatedGroup = undefined;
    var group_count: usize = 0;

    var index: usize = 0;
    while (index < arena.effectsView().len) {
        const effect = arena.effectsView()[index];
        if (isAccessKind(effect.kind)) {
            if (group_count == GROUP_COUNT) return error.AccessScheduleExhausted;
            groups[group_count] = try validateGroup(
                arena,
                index,
                @enumFromInt(@as(u8, @intCast(group_count + 1))),
            );
            group_count += 1;
            index += 3;
            continue;
        }
        index += 1;
    }
    if (group_count != GROUP_COUNT) return error.InvalidAccessPlan;

    const range_index = groups[0].first_effect + 3;
    if (range_index >= arena.effectsView().len)
        return error.MissingAlignedRangeEvidence;
    if (range_index + 1 != groups[1].first_effect or
        groups[1].first_effect + 3 != groups[2].first_effect)
    {
        return error.InvalidAccessPlan;
    }

    const kind: access_schedule.AccessPlanKind = if (groups[0].kind == .register_read and
        groups[1].kind == .memory_read and
        groups[2].kind == .register_write)
        .load
    else if (groups[0].kind == .register_read and
        groups[1].kind == .register_read and
        groups[2].kind == .memory_write)
        .store
    else
        return error.InvalidAccessPlan;

    const expected_phases: [GROUP_COUNT]types.AccessPhase = switch (kind) {
        .load => .{ .first, .third, .second },
        .store => .{ .first, .second, .third },
    };
    const first = groups[0];
    for (&groups, expected_phases) |*group, expected_phase| {
        if (group.phase != expected_phase) return error.InvalidAccessPlan;
        if (group.active != first.active or
            group.instruction_clock != first.instruction_clock)
        {
            return error.MultipleAccessSchedules;
        }
        try validateAddress(arena, group);
    }

    const memory_group = switch (kind) {
        .load => groups[1],
        .store => groups[2],
    };
    const aligned = switch (machineDerived(arena, memory_group.address) orelse
        return error.InvalidAccessPlan) {
        .aligned_word_address => |address| address,
        else => return error.InvalidAccessPlan,
    };
    try validateAlignedRange(
        arena,
        range_index,
        aligned.word_index,
        first.active,
    );
    var derived_groups = machine_validation.AccessGroups{ .len = GROUP_COUNT };
    for (groups, &derived_groups.items) |group, *derived| {
        derived.* = .{
            .first_effect = group.first_effect,
            .address = group.address,
            .current_clock = group.current_clock,
            .gap = group.gap,
            .instruction_clock = group.instruction_clock,
            .active = group.active,
        };
    }
    try machine_validation.validate(arena, derived_groups);

    var prepared_groups: [GROUP_COUNT]Group = undefined;
    for (groups, &prepared_groups) |group, *prepared| {
        prepared.* = .{
            .first_effect = types.idFromIndex(
                types.EffectId,
                group.first_effect,
            ) catch return error.UnknownEffect,
            .kind = group.kind,
            .ordinal = group.ordinal,
            .phase = group.phase,
            .address = group.address,
            .current_clock = group.current_clock,
            .gap = group.gap,
        };
    }
    return .{
        .kind = kind,
        .groups_by_ordinal = prepared_groups,
        .ordinal_index_by_phase = switch (kind) {
            .load => .{ 0, 2, 1 },
            .store => .{ 0, 1, 2 },
        },
        .aligned_range = types.idFromIndex(
            types.EffectId,
            range_index,
        ) catch return error.UnknownEffect,
        .word_index = aligned.word_index,
        .instruction_clock = first.instruction_clock,
        .active = first.active,
    };
}

fn validateGroup(
    arena: *const ir.Arena,
    first_index: usize,
    ordinal: types.AccessOrdinal,
) Error!ValidatedGroup {
    if (first_index + 3 > arena.effectsView().len)
        return error.InvalidAccessGroup;
    const effects = arena.effectsView()[first_index .. first_index + 3];
    const consume = effects[0];
    const emitted = effects[1];
    const gap_effect = effects[2];
    if (emitted.kind != consume.kind or gap_effect.kind != consume.kind or
        !isAccessKind(consume.kind))
    {
        return error.InvalidAccessGroup;
    }
    const active = consume.liveness orelse return error.MissingRelationLiveness;
    if (emitted.liveness != active or gap_effect.liveness != active or
        !std.meta.eql(consume.source_span, emitted.source_span) or
        !std.meta.eql(consume.source_span, gap_effect.source_span))
    {
        return error.InvalidAccessGroup;
    }
    const raw_ordinal: u8 = @intFromEnum(ordinal);
    if (consume.access_ordinal != raw_ordinal or
        emitted.access_ordinal != raw_ordinal or
        gap_effect.access_ordinal != raw_ordinal)
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
    const consume_values = try valuesAt(arena, first_index);
    const emit_values = try valuesAt(arena, first_index + 1);
    const gap_values = try valuesAt(arena, first_index + 2);
    try preflightRelation(arena, consume_binding, consume_values, active, raw_ordinal);
    try preflightRelation(arena, emit_binding, emit_values, active, raw_ordinal);
    try preflightRelation(arena, gap_binding, gap_values, active, raw_ordinal);
    if (consume_values.len != 7 or emit_values.len != 7 or gap_values.len != 1 or
        consume_values[0] != emit_values[0] or
        consume_values[1] != emit_values[1])
    {
        return error.InvalidAccessGroup;
    }
    if (consume.kind == .register_read or consume.kind == .memory_read) {
        for (consume_values[3..7], emit_values[3..7]) |previous, next|
            if (previous != next) return error.InvalidAccessGroup;
    }

    const current = switch (machineDerived(arena, emit_values[2]) orelse
        return error.InvalidAccessGroup) {
        .access_clock => |clock| clock,
        else => return error.InvalidAccessGroup,
    };
    const gap = switch (machineDerived(arena, gap_values[0]) orelse
        return error.InvalidAccessGroup) {
        .strict_clock_gap => |clock_gap| clock_gap,
        else => return error.InvalidAccessGroup,
    };
    if (gap.current_clock != emit_values[2] or
        gap.previous_clock != consume_values[2] or
        gap.active != active or gap.phase != current.phase)
    {
        return error.InvalidAccessGroup;
    }
    return .{
        .first_effect = first_index,
        .kind = consume.kind,
        .ordinal = ordinal,
        .phase = current.phase,
        .address_space = consume_values[0],
        .address = consume_values[1],
        .previous_clock = consume_values[2],
        .current_clock = emit_values[2],
        .gap = gap_values[0],
        .instruction_clock = current.instruction_clock,
        .active = active,
    };
}

fn validateAddress(arena: *const ir.Arena, group: *const ValidatedGroup) Error!void {
    const derived = machineDerived(arena, group.address) orelse
        return error.InvalidAccessPlan;
    if (group.kind == .register_read or group.kind == .register_write) {
        if (!isCanonicalFelt(arena, group.address_space, 0))
            return error.InvalidAccessPlan;
        switch (derived) {
            .register_address => {},
            else => return error.InvalidAccessPlan,
        }
    } else {
        if (!isCanonicalFelt(arena, group.address_space, 1))
            return error.InvalidAccessPlan;
        switch (derived) {
            .aligned_word_address => {},
            else => return error.InvalidAccessPlan,
        }
    }
}

fn validateAlignedRange(
    arena: *const ir.Arena,
    index: usize,
    word_index: types.ValueId,
    active: types.ValueId,
) Error!void {
    const effect = arena.effectsView()[index];
    if (effect.kind != .range_request or effect.liveness != active or
        effect.access_ordinal != null or
        !bindingEqual(effect.binding, binding(.range_check_20, .request)))
    {
        return error.MissingAlignedRangeEvidence;
    }
    const values = try valuesAt(arena, index);
    if (values.len != 1 or values[0] != word_index)
        return error.MissingAlignedRangeEvidence;
    try preflightRelation(
        arena,
        binding(.range_check_20, .request),
        values,
        active,
        null,
    );
}

fn preflightRelation(
    arena: *const ir.Arena,
    relation_binding: program.RelationBinding,
    values: []const types.ValueId,
    active: types.ValueId,
    ordinal: ?u8,
) Error!void {
    const active_node = arena.node(active) orelse return error.UnknownValue;
    if (!active_node.key.ty.isSelector()) return error.MissingRelationLiveness;
    const schema = relation.getById(relation_binding.schema) orelse
        return error.UnknownSchema;
    if (schema.version != relation_binding.schema_version)
        return error.BindingVersionMismatch;
    if (values.len > 32) return error.RelationArityTooLarge;
    var field_types: [32]types.Type = undefined;
    for (values, field_types[0..values.len]) |value, *field_type| {
        field_type.* = (arena.node(value) orelse return error.UnknownValue).key.ty;
    }
    try relation.validateEvent(
        relation_binding.schema,
        relation_binding.role,
        field_types[0..values.len],
        ordinal,
    );
}

fn valuesAt(arena: *const ir.Arena, index: usize) Error![]const types.ValueId {
    const id = types.idFromIndex(types.EffectId, index) catch
        return error.UnknownEffect;
    return arena.effectValues(id) orelse error.UnknownEffect;
}

fn binding(domain: relation.Domain, role: relation.Role) program.RelationBinding {
    const schema = relation.get(domain);
    return .{ .schema = schema.id, .schema_version = schema.version, .role = role };
}

fn bindingEqual(
    actual: ?program.RelationBinding,
    expected: program.RelationBinding,
) bool {
    const present = actual orelse return false;
    return std.meta.eql(present, expected);
}

fn machineDerived(arena: *const ir.Arena, value: types.ValueId) ?expr.MachineDerived {
    const node = arena.node(value) orelse return null;
    return switch (node.key.op) {
        .machine_derived => |derived| derived,
        else => null,
    };
}

fn isCanonicalFelt(arena: *const ir.Arena, value: types.ValueId, wanted: u32) bool {
    const node = arena.node(value) orelse return false;
    if (!std.meta.eql(node.key.ty, types.Type.felt)) return false;
    return switch (node.key.op) {
        .constant => |constant| switch (constant) {
            .field => |field| field == wanted,
            .unsigned => false,
        },
        else => false,
    };
}

pub fn isAccessKind(kind: program.EffectKind) bool {
    return switch (kind) {
        .register_read, .register_write, .memory_read, .memory_write => true,
        else => false,
    };
}

pub fn hasMemoryCapability(arena: *const ir.Arena) bool {
    for (arena.effectsView()) |effect| switch (effect.kind) {
        .memory_read, .memory_write => return true,
        else => {},
    };
    for (arena.nodesView()) |node| switch (node.key.op) {
        .machine_derived => |derived| switch (derived) {
            .aligned_word_address => return true,
            else => {},
        },
        else => {},
    };
    return false;
}
