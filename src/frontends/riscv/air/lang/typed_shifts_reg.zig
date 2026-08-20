//! Native typed AIR authorship for SLL, SRL, and SRA.

const std = @import("std");
const common = @import("typed_shift_common.zig");
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

pub const MAIN_COLUMN_COUNT: usize = 60;
pub const SEMANTIC_CONSTRAINT_COUNT: usize = common.CONSTRAINT_COUNT + 4;
pub const DIRECT_CONSTRAINT_COUNT: usize = SEMANTIC_CONSTRAINT_COUNT + 1;
pub const RELATION_EVENT_COUNT: usize = 20;
pub const RELATION_BATCH_SIZE: usize = 2;
pub const SLL_OPCODE_ID: u32 = 2;
pub const SRL_OPCODE_ID: u32 = 6;
pub const SRA_OPCODE_ID: u32 = 7;
pub const INV_32: u32 = 67_108_864;

pub const SEMANTIC_DIGEST_HEX =
    "c40d1f981405a9108fe64ca3a4ec0037aa6c006733e9edd0ceb4787a4687ae09";
pub const SEMANTIC_DIGEST: digest.Digest = blk: {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, SEMANTIC_DIGEST_HEX) catch
        @compileError("invalid typed SHIFTS_REG semantic digest");
    break :blk result;
};

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

pub const Columns = struct {
    clock: types.ValueId,
    pc: types.ValueId,
    semantic: common.Columns,
    rs2: common.AccessColumns,

    pub fn physical(self: Columns) [MAIN_COLUMN_COUNT]types.ValueId {
        const s = self.semantic;
        return .{
            self.clock,
            self.pc,
            s.rd.addr,
            s.rd.previous[0],
            s.rd.previous[1],
            s.rd.previous[2],
            s.rd.previous[3],
            s.rd.previous_clock,
            s.rd.next[0],
            s.rd.next[1],
            s.rd.next[2],
            s.rd.next[3],
            s.rs1.addr,
            s.rs1.previous[0],
            s.rs1.previous[1],
            s.rs1.previous[2],
            s.rs1.previous[3],
            s.rs1.previous_clock,
            s.rs1.next[0],
            s.rs1.next[1],
            s.rs1.next[2],
            s.rs1.next[3],
            self.rs2.addr,
            self.rs2.previous[0],
            self.rs2.previous[1],
            self.rs2.previous[2],
            self.rs2.previous[3],
            self.rs2.previous_clock,
            self.rs2.next[0],
            self.rs2.next[1],
            self.rs2.next[2],
            self.rs2.next[3],
            s.rs1_sign,
            s.is_sll,
            s.is_srl,
            s.is_sra,
            s.bit_multiplier_left,
            s.bit_multiplier_right,
            s.bit_markers[0],
            s.bit_markers[1],
            s.bit_markers[2],
            s.bit_markers[3],
            s.bit_markers[4],
            s.bit_markers[5],
            s.bit_markers[6],
            s.bit_markers[7],
            s.limb_markers[0],
            s.limb_markers[1],
            s.limb_markers[2],
            s.limb_markers[3],
            s.carries[0],
            s.carries[1],
            s.carries[2],
            s.carries[3],
            s.result[0],
            s.result[1],
            s.result[2],
            s.result[3],
            s.destination_nonzero,
            s.destination_inverse,
        };
    }
};

pub const EventSpec = struct {
    kind: program.EffectKind,
    domain: relation.Domain,
    role: relation.Role,
    arity: u8,
    access_ordinal: ?u8 = null,
};

pub const EVENT_SPECS = [RELATION_EVENT_COUNT]EventSpec{
    .{ .kind = .program_fetch, .domain = .program_access, .role = .request, .arity = 5 },
    .{ .kind = .state_consume, .domain = .registers_state, .role = .consume, .arity = 2 },
    .{ .kind = .state_produce, .domain = .registers_state, .role = .emit, .arity = 2 },
    .{ .kind = .register_read, .domain = .memory_access, .role = .consume, .arity = 7, .access_ordinal = 1 },
    .{ .kind = .register_read, .domain = .memory_access, .role = .emit, .arity = 7, .access_ordinal = 1 },
    .{ .kind = .register_read, .domain = .range_check_20, .role = .request, .arity = 1, .access_ordinal = 1 },
    .{ .kind = .register_read, .domain = .memory_access, .role = .consume, .arity = 7, .access_ordinal = 2 },
    .{ .kind = .register_read, .domain = .memory_access, .role = .emit, .arity = 7, .access_ordinal = 2 },
    .{ .kind = .register_read, .domain = .range_check_20, .role = .request, .arity = 1, .access_ordinal = 2 },
    .{ .kind = .range_request, .domain = .range_check_20, .role = .request, .arity = 1 },
    .{ .kind = .range_request, .domain = .range_check_8_8, .role = .request, .arity = 2 },
    .{ .kind = .range_request, .domain = .range_check_8_8, .role = .request, .arity = 2 },
    .{ .kind = .range_request, .domain = .range_check_8_8, .role = .request, .arity = 2 },
    .{ .kind = .range_request, .domain = .range_check_8_8, .role = .request, .arity = 2 },
    .{ .kind = .range_request, .domain = .range_check_8_8, .role = .request, .arity = 2 },
    .{ .kind = .range_request, .domain = .range_check_8_8, .role = .request, .arity = 2 },
    .{ .kind = .register_write, .domain = .memory_access, .role = .consume, .arity = 7, .access_ordinal = 3 },
    .{ .kind = .register_write, .domain = .memory_access, .role = .emit, .arity = 7, .access_ordinal = 3 },
    .{ .kind = .register_write, .domain = .range_check_20, .role = .request, .arity = 1, .access_ordinal = 3 },
    .{ .kind = .range_request, .domain = .range_check_m31, .role = .request, .arity = 2 },
};

pub const Events = struct {
    program_fetch: types.EffectId,
    retirement: instruction_effects.SequentialRetirement,
    source_1: effects.RegisterAccessGroup,
    source_2: effects.RegisterAccessGroup,
    shift_amount_range: types.EffectId,
    carry_ranges: [4]types.EffectId,
    result_ranges: [2]types.EffectId,
    destination: effects.RegisterAccessGroup,
    sign_range: types.EffectId,
};

pub const ValidationError = validate_mod.Error || error{InvalidShiftsRegDefinition};

pub const Definition = struct {
    arena: ir.Arena,
    columns: Columns,
    is_active: types.ValueId,
    active: types.ValueId,
    constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId,
    constraint_roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId,
    events: Events,
    opcode: types.ValueId,
    shift_amount: types.ValueId,
    shift_amount_range_value: types.ValueId,

    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const Definition) ValidationError!void {
        try validate_mod.validate(&self.arena);
        const actual_digest = digest.computeV7(&self.arena) catch
            return error.InvalidShiftsRegDefinition;
        if (!std.mem.eql(u8, &actual_digest, &SEMANTIC_DIGEST))
            return error.InvalidShiftsRegDefinition;
        if (self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or
            self.arena.effectsView().len != RELATION_EVENT_COUNT)
        {
            return error.InvalidShiftsRegDefinition;
        }
        for (self.constraints, self.constraint_roots, 0..) |id, root, index| {
            if (types.idIndex(id) != index)
                return error.InvalidShiftsRegDefinition;
            const constraint = self.arena.constraint(id) orelse
                return error.InvalidShiftsRegDefinition;
            if (constraint.root != root or constraint.gate != null or
                constraint.category != .semantic)
            {
                return error.InvalidShiftsRegDefinition;
            }
        }
        for (self.columns.physical(), 0..) |value, index| if (types.idIndex(value) != index)
            return error.InvalidShiftsRegDefinition;
        if (types.idIndex(self.is_active) != MAIN_COLUMN_COUNT or
            self.events.source_1.ordinal != .first or
            self.events.source_1.phase != .first or
            self.events.source_2.ordinal != .second or
            self.events.source_2.phase != .second or
            self.events.destination.ordinal != .third or
            self.events.destination.phase != .third)
        {
            return error.InvalidShiftsRegDefinition;
        }
        for (EVENT_SPECS, 0..) |spec, index| {
            const id = types.idFromIndex(types.EffectId, index) catch
                return error.InvalidShiftsRegDefinition;
            const effect = self.arena.effect(id) orelse
                return error.InvalidShiftsRegDefinition;
            const binding = effect.binding orelse
                return error.InvalidShiftsRegDefinition;
            const schema = relation.get(spec.domain);
            const values = self.arena.effectValues(id) orelse
                return error.InvalidShiftsRegDefinition;
            if (effect.kind != spec.kind or binding.schema != schema.id or
                binding.schema_version != schema.version or
                binding.role != spec.role or values.len != spec.arity or
                effect.access_ordinal != spec.access_ordinal)
            {
                return error.InvalidShiftsRegDefinition;
            }
        }
    }
};

pub fn build(allocator: std.mem.Allocator, location: Location) !Definition {
    var arena = ir.Arena.init(allocator);
    errdefer arena.deinit();
    const span = try location.install(&arena);
    const columns = try buildColumns(&arena, span);
    const is_active = try arena.input("is_active", .selector, span);
    const derived = try common.derive(&arena, columns.semantic, span);
    const core_roots = try common.constraintRoots(
        &arena,
        columns.semantic,
        derived,
        span,
    );
    var roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId = undefined;
    @memcpy(roots[0..common.CONSTRAINT_COUNT], &core_roots);
    inline for (0..4) |limb| roots[common.CONSTRAINT_COUNT + limb] = try arena.mul(
        derived.active,
        try arena.sub(columns.rs2.next[limb], columns.rs2.previous[limb], span),
        span,
    );
    roots[SEMANTIC_CONSTRAINT_COUNT] = try arena.sub(
        derived.active,
        is_active,
        span,
    );
    var constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId = undefined;
    for (&constraints, roots, 0..) |*constraint, root, index|
        constraint.* = try assertDirect(&arena, index, root, span);

    var opcode = try arena.add(
        try arena.mul(
            columns.semantic.is_sll,
            try arena.constantField(SLL_OPCODE_ID, span),
            span,
        ),
        try arena.mul(
            columns.semantic.is_srl,
            try arena.constantField(SRL_OPCODE_ID, span),
            span,
        ),
        span,
    );
    opcode = try arena.add(
        opcode,
        try arena.mul(
            columns.semantic.is_sra,
            try arena.constantField(SRA_OPCODE_ID, span),
            span,
        ),
        span,
    );
    const fetch = try effects.programFetch(&arena, .{
        .pc = columns.pc,
        .opcode_id = opcode,
        .rd = columns.semantic.rd.addr,
        .rs1 = columns.semantic.rs1.addr,
        .operand = columns.rs2.addr,
    }, derived.active, span);
    const retirement = try instruction_effects.retireSequential(
        &arena,
        .{ .pc = columns.pc, .clock = columns.clock },
        derived.active,
        span,
    );
    var schedule = try effects.AccessSchedule.begin(
        &arena,
        columns.clock,
        derived.active,
        span,
    );
    const source_1 = try schedule.registerReadTransition(.{
        .index = columns.semantic.rs1.addr,
        .previous_clock = columns.semantic.rs1.previous_clock,
        .previous = columns.semantic.rs1.previous,
        .next = columns.semantic.rs1.next,
    }, span);
    const source_2 = try schedule.registerReadTransition(.{
        .index = columns.rs2.addr,
        .previous_clock = columns.rs2.previous_clock,
        .previous = columns.rs2.previous,
        .next = columns.rs2.next,
    }, span);
    const shift_amount_range_value = try arena.sub(
        try arena.constantField(7, span),
        try arena.mul(
            try arena.sub(columns.rs2.next[0], derived.shift_amount, span),
            try arena.constantField(INV_32, span),
            span,
        ),
        span,
    );
    const shift_amount_range = try range_refinement.rangeCheck20(
        &arena,
        shift_amount_range_value,
        derived.active,
        span,
    );
    const carry_upper = try common.carryUpper(&arena, derived, span);
    var carry_ranges: [4]types.EffectId = undefined;
    inline for (&carry_ranges, columns.semantic.carries) |*effect, carry| {
        const request = try range_refinement.rangeCheck88Refined(
            &arena,
            carry,
            try arena.sub(carry_upper, carry, span),
            derived.active,
            span,
        );
        effect.* = request.effect;
    }
    const result_ranges = try instruction_effects.rangeCheck88Pairs(&arena, .{
        .{
            .first_byte = columns.semantic.result[0],
            .second_byte = columns.semantic.result[1],
        },
        .{
            .first_byte = columns.semantic.result[2],
            .second_byte = columns.semantic.result[3],
        },
    }, derived.active, span);
    const destination = try schedule.registerWrite(.{
        .index = columns.semantic.rd.addr,
        .previous_clock = columns.semantic.rd.previous_clock,
        .previous = columns.semantic.rd.previous,
        .next = columns.semantic.rd.next,
    }, span);
    const zero_byte = try arena.constantUnsigned(.byte, 0, span);
    const sign_range = try range_refinement.rangeCheckM31(
        &arena,
        zero_byte,
        try common.signHigh(&arena, columns.semantic, span),
        columns.semantic.is_sra,
        span,
    );

    var definition = Definition{
        .arena = arena,
        .columns = columns,
        .is_active = is_active,
        .active = derived.active,
        .constraints = constraints,
        .constraint_roots = roots,
        .events = .{
            .program_fetch = fetch,
            .retirement = retirement,
            .source_1 = source_1,
            .source_2 = source_2,
            .shift_amount_range = shift_amount_range.effect,
            .carry_ranges = carry_ranges,
            .result_ranges = result_ranges,
            .destination = destination,
            .sign_range = sign_range.effect,
        },
        .opcode = opcode,
        .shift_amount = derived.shift_amount,
        .shift_amount_range_value = shift_amount_range.values[0],
    };
    try definition.validate();
    return definition;
}

fn buildColumns(arena: *ir.Arena, span: source.SourceSpan) !Columns {
    const clock = try arena.input("clock", .clock, span);
    const pc = try arena.input("pc", .pc, span);
    const rd = try accessInputs(arena, "rd", span);
    const rs1 = try accessInputs(arena, "rs1", span);
    const rs2 = try accessInputs(arena, "rs2", span);
    const rs1_sign = try arena.input("rs1_sign", .bit, span);
    const is_sll = try arena.input("opcode_sll_flag", .bit, span);
    const is_srl = try arena.input("opcode_srl_flag", .bit, span);
    const is_sra = try arena.input("opcode_sra_flag", .bit, span);
    const bit_multiplier_left = try arena.input("bit_multiplier_left", .felt, span);
    const bit_multiplier_right = try arena.input("bit_multiplier_right", .felt, span);
    const bit_markers = try bitInputs(arena, "bit_shift_marker", 8, span);
    const limb_markers = try bitInputs(arena, "limb_shift_marker", 4, span);
    const carries = try feltInputs(arena, "bit_shift_carry", 4, span);
    const result = try byteInputs(arena, "result", span);
    const destination_nonzero = try arena.input("rd_nonzero", .bit, span);
    const destination_inverse = try arena.input("rd_inv", .felt, span);
    return .{
        .clock = clock,
        .pc = pc,
        .semantic = .{
            .rd = rd,
            .rs1 = rs1,
            .rs1_sign = rs1_sign,
            .is_sll = is_sll,
            .is_srl = is_srl,
            .is_sra = is_sra,
            .bit_multiplier_left = bit_multiplier_left,
            .bit_multiplier_right = bit_multiplier_right,
            .bit_markers = bit_markers,
            .limb_markers = limb_markers,
            .carries = carries,
            .result = result,
            .destination_nonzero = destination_nonzero,
            .destination_inverse = destination_inverse,
        },
        .rs2 = rs2,
    };
}

fn accessInputs(
    arena: *ir.Arena,
    comptime prefix: []const u8,
    span: source.SourceSpan,
) !common.AccessColumns {
    return .{
        .addr = try arena.input(prefix ++ "_addr", .register_index, span),
        .previous = try byteInputs(arena, prefix ++ "_prev", span),
        .previous_clock = try arena.input(prefix ++ "_clock_prev", .clock, span),
        .next = try byteInputs(arena, prefix ++ "_next", span),
    };
}

fn byteInputs(
    arena: *ir.Arena,
    comptime prefix: []const u8,
    span: source.SourceSpan,
) ![4]types.ValueId {
    return feltOrBitInputs(arena, prefix, 4, .byte, span);
}

fn feltInputs(
    arena: *ir.Arena,
    comptime prefix: []const u8,
    comptime count: usize,
    span: source.SourceSpan,
) ![count]types.ValueId {
    return feltOrBitInputs(arena, prefix, count, .felt, span);
}

fn bitInputs(
    arena: *ir.Arena,
    comptime prefix: []const u8,
    comptime count: usize,
    span: source.SourceSpan,
) ![count]types.ValueId {
    return feltOrBitInputs(arena, prefix, count, .bit, span);
}

fn feltOrBitInputs(
    arena: *ir.Arena,
    comptime prefix: []const u8,
    comptime count: usize,
    comptime ty: types.Type,
    span: source.SourceSpan,
) ![count]types.ValueId {
    var values: [count]types.ValueId = undefined;
    inline for (&values, 0..) |*value, index| value.* = try arena.input(
        std.fmt.comptimePrint("{s}_{d}", .{ prefix, index }),
        ty,
        span,
    );
    return values;
}

fn assertDirect(
    arena: *ir.Arena,
    index: usize,
    root: types.ValueId,
    span: source.SourceSpan,
) !types.ConstraintId {
    var name_buffer: [64]u8 = undefined;
    const name = try std.fmt.bufPrint(
        &name_buffer,
        "compat.riscv.shifts_reg.direct.{d}",
        .{index},
    );
    return arena.assertZero(name, root, null, .semantic, span);
}
