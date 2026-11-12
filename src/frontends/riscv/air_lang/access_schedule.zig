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
    AccessPlanRequiresFreshSchedule,
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

/// Compatibility form for a production trace that already commits distinct
/// pre/post read limbs. Whole-program validation accepts it only when every
/// pair is bound by the exact active-gated read-only constraint.
pub const RegisterReadTransitionInput = struct {
    index: types.ValueId,
    previous_clock: types.ValueId,
    previous: [4]types.ValueId,
    next: [4]types.ValueId,
};

pub const RegisterWriteInput = struct {
    index: types.ValueId,
    previous_clock: types.ValueId,
    previous: [4]types.ValueId,
    next: [4]types.ValueId,
};

pub const MemoryReadInput = struct {
    word_index: types.ValueId,
    previous_clock: types.ValueId,
    value: [4]types.ValueId,
};

pub const MemoryWriteInput = struct {
    word_index: types.ValueId,
    previous_clock: types.ValueId,
    previous: [4]types.ValueId,
    next: [4]types.ValueId,
};

pub const LoadAccessInput = struct {
    rs1: RegisterReadInput,
    src: MemoryReadInput,
    dst: RegisterWriteInput,
};

pub const StoreAccessInput = struct {
    rs1: RegisterReadInput,
    src: RegisterReadInput,
    dst: MemoryWriteInput,
};

pub const RegisterAccessGroup = struct {
    consume: types.EffectId,
    emit: types.EffectId,
    clock_gap: types.EffectId,
    ordinal: types.AccessOrdinal,
    phase: types.AccessPhase,
};

pub const AccessPlanKind = enum(u8) { load, store };

pub const LoadStoreAccessPlan = struct {
    kind: AccessPlanKind,
    groups: [MAX_ACCESS_GROUPS]RegisterAccessGroup,
    aligned_range: types.EffectId,
    word_index: types.ValueId,
    aligned_address: types.ValueId,
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

    pub fn registerReadTransition(
        self: *AccessSchedule,
        input: RegisterReadTransitionInput,
        span: source.SourceSpan,
    ) Error!RegisterAccessGroup {
        return self.appendRegisterGroup(
            .register_read,
            input.index,
            input.previous_clock,
            input.previous,
            input.next,
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

    /// Emit the compatibility-exact load stream atomically:
    /// rs1(ordinal 1, phase 1), aligned range evidence,
    /// memory source(ordinal 2, phase 3), rd(ordinal 3, phase 2).
    pub fn load(
        self: *AccessSchedule,
        input: LoadAccessInput,
        span: source.SourceSpan,
    ) Error!LoadStoreAccessPlan {
        return self.appendFixedPlan(.{ .load = input }, span);
    }

    /// Emit the compatibility-exact store stream atomically:
    /// rs1(1,1), aligned range evidence, rs2(2,2), memory dst(3,3).
    pub fn store(
        self: *AccessSchedule,
        input: StoreAccessInput,
        span: source.SourceSpan,
    ) Error!LoadStoreAccessPlan {
        return self.appendFixedPlan(.{ .store = input }, span);
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
        const phase = phaseForOrdinal(ordinal);
        const node_checkpoint = self.arena.nodeCheckpoint();
        errdefer self.arena.rollbackToNodeCheckpoint(node_checkpoint);

        const zero = try self.arena.constantField(0, span);
        const address = try self.arena.registerAddress(index, span);
        const current_clock = try self.arena.accessClock(
            self.instruction_clock,
            phase,
            span,
        );
        const gap = try self.arena.strictClockGap(
            current_clock,
            previous_clock,
            self.active,
            phase,
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
            .phase = phase,
        };
        self.next_ordinal += 1;
        return group;
    }

    fn appendFixedPlan(
        self: *AccessSchedule,
        input: FixedPlanInput,
        span: source.SourceSpan,
    ) Error!LoadStoreAccessPlan {
        if (self.next_ordinal != @intFromEnum(types.AccessOrdinal.first))
            return error.AccessPlanRequiresFreshSchedule;
        try self.preflightFixedPlan(input, span);
        try preflightAppendRanges(self.arena, 11, 10, 46);

        const node_checkpoint = self.arena.nodeCheckpoint();
        const effect_checkpoint = self.arena.effectCheckpoint();
        const ordinal_checkpoint = self.next_ordinal;
        errdefer {
            self.arena.rollbackToEffectCheckpoint(effect_checkpoint);
            self.arena.rollbackToNodeCheckpoint(node_checkpoint);
            self.next_ordinal = ordinal_checkpoint;
        }

        // All four backing stores grow before the first proof-visible append.
        // The commit below can therefore use the ordinary checked hooks with
        // allocation failure proven unreachable.
        try self.arena.ensureUnusedNodeCapacity(11);
        try self.arena.ensureUnusedEffectCapacity(10, 46);

        const zero = self.arena.constantField(0, span) catch unreachable;
        const one = self.arena.constantField(1, span) catch unreachable;
        const memory = switch (input) {
            .load => |load_input| load_input.src,
            .store => |store_input| MemoryReadInput{
                .word_index = store_input.dst.word_index,
                .previous_clock = store_input.dst.previous_clock,
                .value = store_input.dst.previous,
            },
        };
        const aligned_address = self.arena.alignedWordAddress(
            memory.word_index,
            span,
        ) catch unreachable;
        const bindings = PlanBindings.canonical();

        var groups: [MAX_ACCESS_GROUPS]RegisterAccessGroup = undefined;
        switch (input) {
            .load => |load_input| {
                const rs1_address = self.arena.registerAddress(
                    load_input.rs1.index,
                    span,
                ) catch unreachable;
                const dst_address = self.arena.registerAddress(
                    load_input.dst.index,
                    span,
                ) catch unreachable;
                groups[0] = self.appendPreparedGroup(.{
                    .kind = .register_read,
                    .ordinal = .first,
                    .phase = .first,
                    .address_space = zero,
                    .address = rs1_address,
                    .previous_clock = load_input.rs1.previous_clock,
                    .previous = load_input.rs1.value,
                    .next = load_input.rs1.value,
                }, bindings, span);
                const aligned_range = self.appendAlignedRange(
                    memory.word_index,
                    bindings,
                    span,
                );
                groups[1] = self.appendPreparedGroup(.{
                    .kind = .memory_read,
                    .ordinal = .second,
                    .phase = .third,
                    .address_space = one,
                    .address = aligned_address,
                    .previous_clock = load_input.src.previous_clock,
                    .previous = load_input.src.value,
                    .next = load_input.src.value,
                }, bindings, span);
                groups[2] = self.appendPreparedGroup(.{
                    .kind = .register_write,
                    .ordinal = .third,
                    .phase = .second,
                    .address_space = zero,
                    .address = dst_address,
                    .previous_clock = load_input.dst.previous_clock,
                    .previous = load_input.dst.previous,
                    .next = load_input.dst.next,
                }, bindings, span);
                self.next_ordinal = MAX_ACCESS_GROUPS + 1;
                return .{
                    .kind = .load,
                    .groups = groups,
                    .aligned_range = aligned_range,
                    .word_index = memory.word_index,
                    .aligned_address = aligned_address,
                };
            },
            .store => |store_input| {
                const rs1_address = self.arena.registerAddress(
                    store_input.rs1.index,
                    span,
                ) catch unreachable;
                const src_address = self.arena.registerAddress(
                    store_input.src.index,
                    span,
                ) catch unreachable;
                groups[0] = self.appendPreparedGroup(.{
                    .kind = .register_read,
                    .ordinal = .first,
                    .phase = .first,
                    .address_space = zero,
                    .address = rs1_address,
                    .previous_clock = store_input.rs1.previous_clock,
                    .previous = store_input.rs1.value,
                    .next = store_input.rs1.value,
                }, bindings, span);
                const aligned_range = self.appendAlignedRange(
                    memory.word_index,
                    bindings,
                    span,
                );
                groups[1] = self.appendPreparedGroup(.{
                    .kind = .register_read,
                    .ordinal = .second,
                    .phase = .second,
                    .address_space = zero,
                    .address = src_address,
                    .previous_clock = store_input.src.previous_clock,
                    .previous = store_input.src.value,
                    .next = store_input.src.value,
                }, bindings, span);
                groups[2] = self.appendPreparedGroup(.{
                    .kind = .memory_write,
                    .ordinal = .third,
                    .phase = .third,
                    .address_space = one,
                    .address = aligned_address,
                    .previous_clock = store_input.dst.previous_clock,
                    .previous = store_input.dst.previous,
                    .next = store_input.dst.next,
                }, bindings, span);
                self.next_ordinal = MAX_ACCESS_GROUPS + 1;
                return .{
                    .kind = .store,
                    .groups = groups,
                    .aligned_range = aligned_range,
                    .word_index = memory.word_index,
                    .aligned_address = aligned_address,
                };
            },
        }
    }

    fn preflightFixedPlan(
        self: *const AccessSchedule,
        input: FixedPlanInput,
        span: source.SourceSpan,
    ) Error!void {
        try self.arena.validateSpan(span);
        try requirePlainType(self.arena, self.instruction_clock, .clock);
        const active_node = self.arena.node(self.active) orelse
            return error.UnknownValue;
        if (!active_node.key.ty.isSelector()) return error.InvalidEffectLiveness;
        switch (input) {
            .load => |plan| {
                try preflightRegisterRead(self.arena, plan.rs1);
                try preflightMemoryRead(self.arena, plan.src);
                try preflightRegisterWrite(self.arena, plan.dst);
            },
            .store => |plan| {
                try preflightRegisterRead(self.arena, plan.rs1);
                try preflightRegisterRead(self.arena, plan.src);
                try preflightMemoryWrite(self.arena, plan.dst);
            },
        }
        const bindings = PlanBindings.canonical();
        const access_types = [_]types.Type{
            .felt, .address, .clock, .byte, .byte, .byte, .byte,
        };
        const gap_types = [_]types.Type{.uint20};
        inline for (1..4) |ordinal| {
            try preflightRelationTypes(
                bindings.consume,
                &access_types,
                ordinal,
            );
            try preflightRelationTypes(
                bindings.emit,
                &access_types,
                ordinal,
            );
            try preflightRelationTypes(bindings.gap, &gap_types, ordinal);
        }
        try preflightRelationTypes(bindings.aligned_range, &gap_types, null);
    }

    fn appendPreparedGroup(
        self: *AccessSchedule,
        spec: PreparedGroup,
        bindings: PlanBindings,
        span: source.SourceSpan,
    ) RegisterAccessGroup {
        const current_clock = self.arena.accessClock(
            self.instruction_clock,
            spec.phase,
            span,
        ) catch unreachable;
        const gap = self.arena.strictClockGap(
            current_clock,
            spec.previous_clock,
            self.active,
            spec.phase,
            span,
        ) catch unreachable;
        const consume_values = [7]types.ValueId{
            spec.address_space,
            spec.address,
            spec.previous_clock,
            spec.previous[0],
            spec.previous[1],
            spec.previous[2],
            spec.previous[3],
        };
        const emit_values = [7]types.ValueId{
            spec.address_space,
            spec.address,
            current_clock,
            spec.next[0],
            spec.next[1],
            spec.next[2],
            spec.next[3],
        };
        const gap_values = [1]types.ValueId{gap};
        const ordinal: u8 = @intFromEnum(spec.ordinal);
        return .{
            .consume = self.arena.addBoundEffectUnchecked(
                spec.kind,
                bindings.consume,
                &consume_values,
                self.active,
                ordinal,
                span,
            ) catch unreachable,
            .emit = self.arena.addBoundEffectUnchecked(
                spec.kind,
                bindings.emit,
                &emit_values,
                self.active,
                ordinal,
                span,
            ) catch unreachable,
            .clock_gap = self.arena.addBoundEffectUnchecked(
                spec.kind,
                bindings.gap,
                &gap_values,
                self.active,
                ordinal,
                span,
            ) catch unreachable,
            .ordinal = spec.ordinal,
            .phase = spec.phase,
        };
    }

    fn appendAlignedRange(
        self: *AccessSchedule,
        word_index: types.ValueId,
        bindings: PlanBindings,
        span: source.SourceSpan,
    ) types.EffectId {
        const values = [1]types.ValueId{word_index};
        return self.arena.addBoundEffectUnchecked(
            .range_request,
            bindings.aligned_range,
            &values,
            self.active,
            null,
            span,
        ) catch unreachable;
    }
};

const FixedPlanInput = union(enum) {
    load: LoadAccessInput,
    store: StoreAccessInput,
};

const PreparedGroup = struct {
    kind: program.EffectKind,
    ordinal: types.AccessOrdinal,
    phase: types.AccessPhase,
    address_space: types.ValueId,
    address: types.ValueId,
    previous_clock: types.ValueId,
    previous: [4]types.ValueId,
    next: [4]types.ValueId,
};

const PlanBindings = struct {
    consume: program.RelationBinding,
    emit: program.RelationBinding,
    gap: program.RelationBinding,
    aligned_range: program.RelationBinding,

    fn canonical() PlanBindings {
        return .{
            .consume = binding(.memory_access, .consume),
            .emit = binding(.memory_access, .emit),
            .gap = binding(.range_check_20, .request),
            .aligned_range = binding(.range_check_20, .request),
        };
    }
};

fn preflightRegisterRead(
    arena: *const ir.Arena,
    input: RegisterReadInput,
) Error!void {
    try requirePlainType(arena, input.index, .register_index);
    try requirePlainType(arena, input.previous_clock, .clock);
    for (input.value) |value| try requirePlainType(arena, value, .byte);
}

fn preflightRegisterWrite(
    arena: *const ir.Arena,
    input: RegisterWriteInput,
) Error!void {
    try requirePlainType(arena, input.index, .register_index);
    try requirePlainType(arena, input.previous_clock, .clock);
    for (input.previous) |value| try requirePlainType(arena, value, .byte);
    for (input.next) |value| try requirePlainType(arena, value, .byte);
}

fn preflightMemoryRead(
    arena: *const ir.Arena,
    input: MemoryReadInput,
) Error!void {
    try requirePlainType(arena, input.word_index, .uint20);
    try requirePlainType(arena, input.previous_clock, .clock);
    for (input.value) |value| try requirePlainType(arena, value, .byte);
}

fn preflightMemoryWrite(
    arena: *const ir.Arena,
    input: MemoryWriteInput,
) Error!void {
    try requirePlainType(arena, input.word_index, .uint20);
    try requirePlainType(arena, input.previous_clock, .clock);
    for (input.previous) |value| try requirePlainType(arena, value, .byte);
    for (input.next) |value| try requirePlainType(arena, value, .byte);
}

fn preflightRelationTypes(
    relation_binding: program.RelationBinding,
    field_types: []const types.Type,
    access_ordinal: ?u8,
) Error!void {
    const schema = relation.getById(relation_binding.schema) orelse
        return error.UnknownSchema;
    if (schema.version != relation_binding.schema_version)
        return error.BindingVersionMismatch;
    try relation.validateEvent(
        relation_binding.schema,
        relation_binding.role,
        field_types,
        access_ordinal,
    );
}

fn preflightAppendRanges(
    arena: *const ir.Arena,
    node_count: usize,
    effect_count: usize,
    value_count: usize,
) Error!void {
    if (node_count != 0) {
        const last = std.math.add(usize, arena.nodeCount(), node_count - 1) catch
            return error.IdOverflow;
        _ = try types.idFromIndex(types.ValueId, last);
    }
    if (effect_count != 0) {
        const last = std.math.add(
            usize,
            arena.effectsView().len,
            effect_count - 1,
        ) catch return error.IdOverflow;
        _ = try types.idFromIndex(types.EffectId, last);
    }
    if (value_count != 0) {
        const last = std.math.add(
            usize,
            arena.effectValuesView().len,
            value_count - 1,
        ) catch return error.ReferenceRangeOverflow;
        _ = std.math.cast(u32, last) orelse
            return error.ReferenceRangeOverflow;
    }
}

fn phaseForOrdinal(ordinal: types.AccessOrdinal) types.AccessPhase {
    return switch (ordinal) {
        .first => .first,
        .second => .second,
        .third => .third,
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
