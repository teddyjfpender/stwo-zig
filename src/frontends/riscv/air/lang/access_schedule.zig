//! Allocation-conscious construction of instruction-local access groups.
//!
//! The schedule is the sole owner of access ordinals. Each append is
//! transactional: all semantic checks and both backing-store reservations
//! complete before the three adjacent effects become visible.

const std = @import("std");
const ir = @import("ir.zig");
const program = @import("program.zig");
const relation = @import("relation.zig");
const source = @import("source.zig");
const types = @import("types.zig");

pub const MAX_ARITY: usize = 32;
pub const MAX_ACCESS_GROUPS: u8 = 3;

pub const Error = ir.Error || relation.Error || error{
    AccessScheduleExhausted,
    BindingVersionMismatch,
    RelationArityTooLarge,
    UnexpectedMachineDerivedUse,
};

pub const RegisterReadInput = struct {
    index: types.ValueId,
    previous_clock: types.ValueId,
    value: [4]types.ValueId,
};

pub const RegisterWriteInput = struct {
    index: types.ValueId,
    previous_clock: types.ValueId,
    previous: [4]types.ValueId,
    next: [4]types.ValueId,
};

pub const RegisterAccessGroup = struct {
    consume: types.EffectId,
    emit: types.EffectId,
    clock_gap: types.EffectId,
    ordinal: types.AccessOrdinal,
};

/// Instruction-wide owner of the three production access phases.
///
/// E-002 exposes register groups only. E-003 extends this same counter with
/// memory groups so loads and stores cannot accidentally reset ordinal order.
pub const AccessSchedule = struct {
    arena: *ir.Arena,
    instruction_clock: types.ValueId,
    active: types.ValueId,
    next_ordinal: u8 = @intFromEnum(types.AccessOrdinal.first),

    pub fn begin(
        arena: *ir.Arena,
        instruction_clock: types.ValueId,
        active: types.ValueId,
        span: source.SourceSpan,
    ) Error!AccessSchedule {
        try arena.validateSpan(span);
        try requirePlainType(arena, instruction_clock, .clock);
        const active_node = arena.node(active) orelse return error.UnknownValue;
        if (!active_node.key.ty.isSelector()) return error.InvalidEffectLiveness;
        return .{
            .arena = arena,
            .instruction_clock = instruction_clock,
            .active = active,
        };
    }

    pub fn registerRead(
        self: *AccessSchedule,
        input: RegisterReadInput,
        span: source.SourceSpan,
    ) Error!RegisterAccessGroup {
        return self.appendRegisterGroup(
            .register_read,
            input.index,
            input.previous_clock,
            input.value,
            input.value,
            span,
        );
    }

    pub fn registerWrite(
        self: *AccessSchedule,
        input: RegisterWriteInput,
        span: source.SourceSpan,
    ) Error!RegisterAccessGroup {
        return self.appendRegisterGroup(
            .register_write,
            input.index,
            input.previous_clock,
            input.previous,
            input.next,
            span,
        );
    }

    fn appendRegisterGroup(
        self: *AccessSchedule,
        kind: program.EffectKind,
        index: types.ValueId,
        previous_clock: types.ValueId,
        previous: [4]types.ValueId,
        next: [4]types.ValueId,
        span: source.SourceSpan,
    ) Error!RegisterAccessGroup {
        if (self.next_ordinal < @intFromEnum(types.AccessOrdinal.first) or
            self.next_ordinal > MAX_ACCESS_GROUPS)
        {
            return error.AccessScheduleExhausted;
        }
        try self.arena.validateSpan(span);
        try requirePlainType(self.arena, self.instruction_clock, .clock);
        const active_node = self.arena.node(self.active) orelse
            return error.UnknownValue;
        if (!active_node.key.ty.isSelector())
            return error.InvalidEffectLiveness;
        try requirePlainType(self.arena, index, .register_index);
        try requirePlainType(self.arena, previous_clock, .clock);
        for (previous) |value| try requirePlainType(self.arena, value, .byte);
        for (next) |value| try requirePlainType(self.arena, value, .byte);

        const ordinal: types.AccessOrdinal = @enumFromInt(self.next_ordinal);
        const node_checkpoint = self.arena.nodeCheckpoint();
        errdefer self.arena.rollbackToNodeCheckpoint(node_checkpoint);

        const zero = try self.arena.constantField(0, span);
        const address = try self.arena.registerAddress(index, span);
        const current_clock = try self.arena.accessClock(
            self.instruction_clock,
            ordinal,
            span,
        );
        const gap = try self.arena.strictClockGap(
            current_clock,
            previous_clock,
            self.active,
            ordinal,
            span,
        );
        const consume_values = [7]types.ValueId{
            zero,
            address,
            previous_clock,
            previous[0],
            previous[1],
            previous[2],
            previous[3],
        };
        const emit_values = [7]types.ValueId{
            zero,
            address,
            current_clock,
            next[0],
            next[1],
            next[2],
            next[3],
        };
        const gap_values = [1]types.ValueId{gap};
        const ordinal_value: u8 = @intFromEnum(ordinal);
        const consume_binding = binding(.memory_access, .consume);
        const emit_binding = binding(.memory_access, .emit);
        const gap_binding = binding(.range_check_20, .request);
        try preflightRelation(
            self.arena,
            consume_binding,
            &consume_values,
            self.active,
            ordinal_value,
            span,
        );
        try preflightRelation(
            self.arena,
            emit_binding,
            &emit_values,
            self.active,
            ordinal_value,
            span,
        );
        try preflightRelation(
            self.arena,
            gap_binding,
            &gap_values,
            self.active,
            ordinal_value,
            span,
        );

        const effect_checkpoint = self.arena.effectCheckpoint();
        errdefer self.arena.rollbackToEffectCheckpoint(effect_checkpoint);
        try self.arena.ensureUnusedEffectCapacity(3, 15);
        const group = RegisterAccessGroup{
            .consume = try self.arena.addBoundEffectUnchecked(
                kind,
                consume_binding,
                &consume_values,
                self.active,
                ordinal_value,
                span,
            ),
            .emit = try self.arena.addBoundEffectUnchecked(
                kind,
                emit_binding,
                &emit_values,
                self.active,
                ordinal_value,
                span,
            ),
            .clock_gap = try self.arena.addBoundEffectUnchecked(
                kind,
                gap_binding,
                &gap_values,
                self.active,
                ordinal_value,
                span,
            ),
            .ordinal = ordinal,
        };
        self.next_ordinal += 1;
        return group;
    }
};

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

fn requirePlainType(
    arena: *const ir.Arena,
    value: types.ValueId,
    expected: types.Type,
) Error!void {
    const node = arena.node(value) orelse return error.UnknownValue;
    if (!std.meta.eql(node.key.ty, expected)) return error.InvalidFieldType;
    switch (node.key.op) {
        .machine_derived => return error.UnexpectedMachineDerivedUse,
        else => {},
    }
}

comptime {
    var maximum: usize = 0;
    for (relation.schemas) |schema| maximum = @max(maximum, schema.fields.len);
    if (maximum != MAX_ARITY)
        @compileError("typed effect arity must track the relation registry");
}
