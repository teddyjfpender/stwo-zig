//! Native direct and effect authorship for RV32 load/store.
//!
//! Production AIR, witness selection, commitment geometry, and transcripts are
//! unchanged. All 48 physical columns, 63 direct roots, and 16 ordered relation
//! events are independently authored. A closed conditional-access proof binds
//! the committed address selectors and dynamic clock/gap aliases without
//! changing any tuple polynomial or allocating another trace column.

const std = @import("std");
const conditional_access = @import("conditional_access_plan.zig");
const constraints_mod = @import("typed_load_store_constraints.zig");
const digest = @import("digest.zig");
const effects = @import("effects.zig");
const instruction_effects = @import("instruction_effects.zig");
const ir = @import("ir.zig");
const program = @import("program.zig");
const range_refinement = @import("range_refinement.zig");
const relation = @import("relation.zig");
const source = @import("source.zig");
const types = @import("types.zig");
const validate_mod = @import("validate.zig");

pub const MAIN_COLUMN_COUNT: usize = 48;
pub const SEMANTIC_CONSTRAINT_COUNT = constraints_mod.SEMANTIC_CONSTRAINT_COUNT;
pub const DIRECT_CONSTRAINT_COUNT = constraints_mod.DIRECT_CONSTRAINT_COUNT;
pub const LOOKUP_COUNT: usize = 16;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const MAX_LOOKUP_ARITY: usize = 7;
pub const OPCODE_IDS = [8]u32{ 19, 20, 22, 23, 21, 24, 25, 26 };
pub const SEMANTIC_DIGEST_HEX =
    "ec8aefea7299e84a480524c3848c1ccc73241caea4e89f983f7c2605e6b04e90";
pub const SEMANTIC_DIGEST: digest.Digest = hexDigest(
    SEMANTIC_DIGEST_HEX,
    "invalid typed load/store semantic digest",
);
const ENFORCE_SEMANTIC_DIGEST = true;

pub const AuthoringBoundary = enum(u8) {
    native_direct_shadow_lookup = 1,
    native_direct_native_effects = 2,
};

pub const AUTHORING_BOUNDARY: AuthoringBoundary = .native_direct_native_effects;

pub const Location = union(enum) {
    generated,
    file: struct {
        path: []const u8,
        start: source.Position,
        end: source.Position,
    },

    fn install(self: Location, arena: *ir.Arena) !source.SourceSpan {
        return switch (self) {
            .generated => source.SourceSpan.generated(),
            .file => |file| source.SourceSpan.init(
                try arena.addSource(file.path),
                file.start,
                file.end,
            ),
        };
    }
};

pub const AccessColumns = struct {
    addr: types.ValueId,
    previous: [4]types.ValueId,
    previous_clock: types.ValueId,
    next: [4]types.ValueId,
};

pub const ReadColumns = struct {
    addr: types.ValueId,
    value: [4]types.ValueId,
    previous_clock: types.ValueId,
};

pub const Columns = struct {
    clock: types.ValueId,
    pc: types.ValueId,
    dst: AccessColumns,
    rs1: ReadColumns,
    src: ReadColumns,
    r2_idx: types.ValueId,
    imm_felt: types.ValueId,
    src_msb: types.ValueId,
    shift_amount: types.ValueId,
    src_addr_selector: types.ValueId,
    dst_addr_selector: types.ValueId,
    markers: [4]types.ValueId,
    is_lb: types.ValueId,
    is_lh: types.ValueId,
    is_lbu: types.ValueId,
    is_lhu: types.ValueId,
    is_lw: types.ValueId,
    is_sb: types.ValueId,
    is_sh: types.ValueId,
    is_sw: types.ValueId,
    result: [4]types.ValueId,
    destination_nonzero: types.ValueId,
    destination_inverse: types.ValueId,

    pub fn physical(self: Columns) [MAIN_COLUMN_COUNT]types.ValueId {
        return .{
            self.clock,
            self.pc,
            self.dst.addr,
            self.dst.previous[0],
            self.dst.previous[1],
            self.dst.previous[2],
            self.dst.previous[3],
            self.dst.previous_clock,
            self.dst.next[0],
            self.dst.next[1],
            self.dst.next[2],
            self.dst.next[3],
            self.rs1.addr,
            self.rs1.value[0],
            self.rs1.value[1],
            self.rs1.value[2],
            self.rs1.value[3],
            self.rs1.previous_clock,
            self.src.addr,
            self.src.value[0],
            self.src.value[1],
            self.src.value[2],
            self.src.value[3],
            self.src.previous_clock,
            self.r2_idx,
            self.imm_felt,
            self.src_msb,
            self.shift_amount,
            self.src_addr_selector,
            self.dst_addr_selector,
            self.markers[0],
            self.markers[1],
            self.markers[2],
            self.markers[3],
            self.is_lb,
            self.is_lh,
            self.is_lbu,
            self.is_lhu,
            self.is_lw,
            self.is_sb,
            self.is_sh,
            self.is_sw,
            self.result[0],
            self.result[1],
            self.result[2],
            self.result[3],
            self.destination_nonzero,
            self.destination_inverse,
        };
    }
};

pub const AccessEvents = struct {
    consume: types.EffectId,
    emit: types.EffectId,
    gap: types.EffectId,
};

pub const Events = struct {
    program_fetch: types.EffectId,
    retirement: effects.Retirement,
    rs1: AccessEvents,
    aligned_address_range: types.EffectId,
    base_address_range: types.EffectId,
    source: AccessEvents,
    destination: AccessEvents,
    lb_sign_range: types.EffectId,
    lh_sign_range: types.EffectId,
};

pub const ValidationError = validate_mod.Error || relation.Error || error{
    InvalidLoadStoreDefinition,
};

pub const Definition = struct {
    arena: ir.Arena,
    columns: Columns,
    is_active: types.ValueId,
    model: constraints_mod.Result,
    events: Events,

    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const Definition) ValidationError!void {
        const semantic_identity = try digest.computeIdentity(&self.arena);
        if (semantic_identity.format_version != digest.conditional_access_format_version or
            (ENFORCE_SEMANTIC_DIGEST and
                !std.mem.eql(u8, &semantic_identity.bytes, &SEMANTIC_DIGEST)))
        {
            return error.InvalidLoadStoreDefinition;
        }
        if (self.arena.effectsView().len != LOOKUP_COUNT or
            self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or
            self.arena.conditional_access_plans.items.len != 1 or
            self.arena.range_refinements.items.len != 5 or
            self.arena.fixed_table_requests.items.len != 4)
        {
            return error.InvalidLoadStoreDefinition;
        }
        const physical = self.columns.physical();
        for (physical, 0..) |value, index|
            if (types.idIndex(value) != index) return error.InvalidLoadStoreDefinition;
        if (types.idIndex(self.is_active) != MAIN_COLUMN_COUNT) {
            return error.InvalidLoadStoreDefinition;
        }
        var input_count: usize = 0;
        for (self.arena.nodesView(), 0..) |node, index| switch (node.key.op) {
            .input => {
                const value = types.idFromIndex(types.ValueId, index) catch
                    return error.InvalidLoadStoreDefinition;
                if (range_refinement.sourceForTarget(&self.arena, value) == null and
                    conditional_access.sourceForTarget(&self.arena, value) == null)
                {
                    input_count += 1;
                }
            },
            else => {},
        };
        if (input_count != MAIN_COLUMN_COUNT + 1)
            return error.InvalidLoadStoreDefinition;
        for (self.model.constraints, self.model.roots, 0..) |id, root, index| {
            if (types.idIndex(id) != index) return error.InvalidLoadStoreDefinition;
            const constraint = self.arena.constraint(id) orelse
                return error.InvalidLoadStoreDefinition;
            if (constraint.root != root or constraint.gate != null or
                constraint.category != .semantic)
            {
                return error.InvalidLoadStoreDefinition;
            }
            var name_buffer: [72]u8 = undefined;
            const expected = std.fmt.bufPrint(
                &name_buffer,
                "compat.riscv.load_store.direct.{d}",
                .{index},
            ) catch return error.InvalidLoadStoreDefinition;
            const actual = self.arena.name(constraint.name) orelse
                return error.InvalidLoadStoreDefinition;
            if (!std.mem.eql(u8, expected, actual))
                return error.InvalidLoadStoreDefinition;
        }
        try validateEventOrder(self);
    }
};

fn validateEventOrder(definition: *const Definition) ValidationError!void {
    const event_ids = [_]types.EffectId{
        definition.events.program_fetch,
        definition.events.retirement.consume,
        definition.events.retirement.produce,
        definition.events.rs1.consume,
        definition.events.rs1.emit,
        definition.events.rs1.gap,
        definition.events.aligned_address_range,
        definition.events.base_address_range,
        definition.events.source.consume,
        definition.events.source.emit,
        definition.events.source.gap,
        definition.events.destination.consume,
        definition.events.destination.emit,
        definition.events.destination.gap,
        definition.events.lb_sign_range,
        definition.events.lh_sign_range,
    };
    for (event_ids, 0..) |event, index| if (types.idIndex(event) != index)
        return error.InvalidLoadStoreDefinition;
}

pub fn build(allocator: std.mem.Allocator, location: Location) !Definition {
    var arena = ir.Arena.init(allocator);
    errdefer arena.deinit();
    const span = try location.install(&arena);
    const columns = Columns{
        .clock = try arena.input("clock", .clock, span),
        .pc = try arena.input("pc", .pc, span),
        .dst = try accessInputs(&arena, "dst", .felt, span),
        .rs1 = try readInputs(&arena, "rs1", .register_index, span),
        .src = try readInputs(&arena, "src", .felt, span),
        .r2_idx = try arena.input("r2_idx", .register_index, span),
        .imm_felt = try arena.input("imm_felt", .felt, span),
        .src_msb = try arena.input("src_msb", .bit, span),
        .shift_amount = try arena.input("shift_amount", .felt, span),
        .src_addr_selector = try arena.input("src_addr_selector", .felt, span),
        .dst_addr_selector = try arena.input("dst_addr_selector", .felt, span),
        .markers = try bitInputs(&arena, "marker", span),
        .is_lb = try arena.input("opcode_lb_flag", .bit, span),
        .is_lh = try arena.input("opcode_lh_flag", .bit, span),
        .is_lbu = try arena.input("opcode_lbu_flag", .bit, span),
        .is_lhu = try arena.input("opcode_lhu_flag", .bit, span),
        .is_lw = try arena.input("opcode_lw_flag", .bit, span),
        .is_sb = try arena.input("opcode_sb_flag", .bit, span),
        .is_sh = try arena.input("opcode_sh_flag", .bit, span),
        .is_sw = try arena.input("opcode_sw_flag", .bit, span),
        .result = try byteInputs(&arena, "result", span),
        .destination_nonzero = try arena.input("rd_nonzero", .bit, span),
        .destination_inverse = try arena.input("rd_inv", .felt, span),
    };
    const is_active = try arena.input("is_active", .selector, span);
    const model = try constraints_mod.author(&arena, columns, is_active, span);
    const events = try authorEffects(&arena, columns, model, span);
    var definition = Definition{
        .arena = arena,
        .columns = columns,
        .is_active = is_active,
        .model = model,
        .events = events,
    };
    try definition.validate();
    return definition;
}

fn authorEffects(
    arena: *ir.Arena,
    c: Columns,
    model: constraints_mod.Result,
    span: source.SourceSpan,
) !Events {
    const one = try arena.constantField(1, span);
    const c128 = try arena.constantField(128, span);
    const active = try range_refinement.booleanFromConstraint(
        arena,
        model.active,
        model.constraints[0],
        span,
    );
    const store_selector = try arena.oneHotSelector(
        &.{ c.is_sb, c.is_sh, c.is_sw },
        span,
    );
    const program_fetch = try effects.programFetch(arena, .{
        .pc = c.pc,
        .opcode_id = model.opcode_id,
        .rd = c.rs1.addr,
        .rs1 = c.r2_idx,
        .operand = c.imm_felt,
    }, active, span);
    const retirement = (try instruction_effects.retireSequential(arena, .{
        .pc = c.pc,
        .clock = c.clock,
    }, active, span)).events;
    var schedule = try effects.AccessSchedule.begin(arena, c.clock, active, span);
    const rs1_group = try schedule.registerRead(.{
        .index = c.rs1.addr,
        .previous_clock = c.rs1.previous_clock,
        .value = c.rs1.value,
    }, span);
    const rs1 = AccessEvents{
        .consume = rs1_group.consume,
        .emit = rs1_group.emit,
        .gap = rs1_group.clock_gap,
    };
    const aligned = try range_refinement.rangeCheck20(
        arena,
        model.aligned_addr_quarter,
        active,
        span,
    );
    const base = try range_refinement.rangeCheckM31(
        arena,
        c.rs1.value[0],
        c.rs1.value[3],
        active,
        span,
    );
    const second_clock = try accessClock(arena, c.clock, 2, span);
    const source_address = try conditional_access.internAlias(
        arena,
        c.src_addr_selector,
        .address,
        span,
    );
    const source_clock_source = try arena.add(second_clock, model.is_load, span);
    const source_clock = try conditional_access.internAlias(
        arena,
        source_clock_source,
        .clock,
        span,
    );
    const source_gap_source = try arena.sub(
        try arena.sub(source_clock_source, c.src.previous_clock, span),
        one,
        span,
    );
    const source_gap = try conditional_access.internAlias(
        arena,
        source_gap_source,
        .uint20,
        span,
    );
    const source_events = try appendConditionalAccess(
        arena,
        .memory_read,
        model.is_load,
        source_address.target,
        c.src.previous_clock,
        c.src.value,
        source_clock.target,
        c.src.value,
        source_gap.target,
        active,
        2,
        span,
    );
    const destination_address = try conditional_access.internAlias(
        arena,
        c.dst_addr_selector,
        .address,
        span,
    );
    const destination_clock_source = try arena.add(second_clock, model.is_store, span);
    const destination_clock = try conditional_access.internAlias(
        arena,
        destination_clock_source,
        .clock,
        span,
    );
    const destination_gap_source = try arena.sub(
        try arena.sub(destination_clock_source, c.dst.previous_clock, span),
        one,
        span,
    );
    const destination_gap = try conditional_access.internAlias(
        arena,
        destination_gap_source,
        .uint20,
        span,
    );
    const destination_events = try appendConditionalAccess(
        arena,
        .memory_write,
        model.is_store,
        destination_address.target,
        c.dst.previous_clock,
        c.dst.previous,
        destination_clock.target,
        c.dst.next,
        destination_gap.target,
        active,
        3,
        span,
    );
    try arena.conditional_access_plans.ensureUnusedCapacity(arena.allocator, 1);
    arena.conditional_access_plans.appendAssumeCapacity(.{
        .first_effect = rs1.consume,
        .aligned_range = aligned.effect,
        .base_range = base.effect,
        .active_source = model.active,
        .active = active,
        .store_source = model.is_store,
        .store_selector = store_selector,
        .is_load = model.is_load,
        .instruction_clock = c.clock,
        .second_clock = second_clock,
        .memory_address = model.mem_addr,
        .shift_amount = c.shift_amount,
        .register_index = c.r2_idx,
        .word_source = model.aligned_addr_quarter,
        .word_index = aligned.values[0],
        .base_low = base.values[0],
        .base_high = base.values[1],
        .source_address_constraint = model.constraints[constraints_mod.SOURCE_ADDRESS_CONSTRAINT_INDEX],
        .destination_address_constraint = model.constraints[constraints_mod.DESTINATION_ADDRESS_CONSTRAINT_INDEX],
        .source_address = source_address,
        .source_clock = source_clock,
        .source_gap = source_gap,
        .destination_address = destination_address,
        .destination_clock = destination_clock,
        .destination_gap = destination_gap,
        .source_span = span,
    });
    const zero_byte = try arena.constantUnsigned(.byte, 0, span);
    const lb_sign = try range_refinement.rangeCheckM31(
        arena,
        zero_byte,
        try arena.sub(c.result[0], try arena.mul(c.src_msb, c128, span), span),
        c.is_lb,
        span,
    );
    const lh_sign = try range_refinement.rangeCheckM31(
        arena,
        zero_byte,
        try arena.sub(c.result[1], try arena.mul(c.src_msb, c128, span), span),
        c.is_lh,
        span,
    );
    return .{
        .program_fetch = program_fetch,
        .retirement = retirement,
        .rs1 = rs1,
        .aligned_address_range = aligned.effect,
        .base_address_range = base.effect,
        .source = source_events,
        .destination = destination_events,
        .lb_sign_range = lb_sign.effect,
        .lh_sign_range = lh_sign.effect,
    };
}

fn appendConditionalAccess(
    arena: *ir.Arena,
    kind: program.EffectKind,
    address_space: types.ValueId,
    address: types.ValueId,
    previous_clock: types.ValueId,
    previous: [4]types.ValueId,
    current_clock: types.ValueId,
    next: [4]types.ValueId,
    gap: types.ValueId,
    active: types.ValueId,
    ordinal: u8,
    span: source.SourceSpan,
) !AccessEvents {
    const consume_values = [_]types.ValueId{
        address_space, address,     previous_clock,
        previous[0],   previous[1], previous[2],
        previous[3],
    };
    const emit_values = [_]types.ValueId{
        address_space, address, current_clock,
        next[0],       next[1], next[2],
        next[3],
    };
    const consume = relationBinding(.memory_access, .consume);
    const emit = relationBinding(.memory_access, .emit);
    const gap_binding = relationBinding(.range_check_20, .request);
    return .{
        .consume = try arena.addBoundEffectUnchecked(
            kind,
            consume,
            &consume_values,
            active,
            ordinal,
            span,
        ),
        .emit = try arena.addBoundEffectUnchecked(
            kind,
            emit,
            &emit_values,
            active,
            ordinal,
            span,
        ),
        .gap = try arena.addBoundEffectUnchecked(
            kind,
            gap_binding,
            &.{gap},
            active,
            ordinal,
            span,
        ),
    };
}

fn relationBinding(domain: relation.Domain, role: relation.Role) program.RelationBinding {
    const schema = relation.get(domain);
    return .{ .schema = schema.id, .schema_version = schema.version, .role = role };
}

fn accessClock(
    arena: *ir.Arena,
    instruction_clock: types.ValueId,
    phase: u32,
    span: source.SourceSpan,
) !types.ValueId {
    const one = try arena.constantField(1, span);
    const four = try arena.constantField(4, span);
    const phase_value = try arena.constantField(phase, span);
    return arena.add(
        try arena.mul(try arena.sub(instruction_clock, one, span), four, span),
        phase_value,
        span,
    );
}

fn accessInputs(
    arena: *ir.Arena,
    comptime prefix: []const u8,
    addr_type: types.Type,
    span: source.SourceSpan,
) !AccessColumns {
    return .{
        .addr = try arena.input(prefix ++ "_addr", addr_type, span),
        .previous = try byteInputs(arena, prefix ++ "_prev", span),
        .previous_clock = try arena.input(prefix ++ "_clock_prev", .clock, span),
        .next = try byteInputs(arena, prefix ++ "_next", span),
    };
}

fn readInputs(
    arena: *ir.Arena,
    comptime prefix: []const u8,
    addr_type: types.Type,
    span: source.SourceSpan,
) !ReadColumns {
    return .{
        .addr = try arena.input(prefix ++ "_addr", addr_type, span),
        .value = try byteInputs(arena, prefix ++ "_prev", span),
        .previous_clock = try arena.input(prefix ++ "_clock_prev", .clock, span),
    };
}

fn byteInputs(
    arena: *ir.Arena,
    comptime prefix: []const u8,
    span: source.SourceSpan,
) ![4]types.ValueId {
    var result: [4]types.ValueId = undefined;
    inline for (&result, 0..) |*value, index| value.* = try arena.input(
        std.fmt.comptimePrint("{s}_{d}", .{ prefix, index }),
        .byte,
        span,
    );
    return result;
}

fn bitInputs(
    arena: *ir.Arena,
    comptime prefix: []const u8,
    span: source.SourceSpan,
) ![4]types.ValueId {
    var result: [4]types.ValueId = undefined;
    inline for (&result, 0..) |*value, index| value.* = try arena.input(
        std.fmt.comptimePrint("{s}_{d}", .{ prefix, index }),
        .bit,
        span,
    );
    return result;
}

fn zeroValue(arena: *const ir.Arena) ?types.ValueId {
    for (arena.nodesView(), 0..) |node, index| switch (node.key.op) {
        .constant => |constant| switch (constant) {
            .field => |value| if (value == 0)
                return types.idFromIndex(types.ValueId, index) catch null,
            .unsigned => {},
        },
        else => {},
    };
    return null;
}

fn hashInt(hash: *std.crypto.hash.sha2.Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

fn hexDigest(comptime text: []const u8, comptime message: []const u8) digest.Digest {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, text) catch @compileError(message);
    return result;
}
