//! Native typed AIR authorship for the compatibility-shared RV32 ALU-immediate
//! family.
//!
//! This definition authors the production 35-column, 22-root, 16-relation
//! program for ADDI, XORI, ORI, and ANDI. The fixed executable binding lives in
//! `typed_base_alu_imm_authority.zig`; the arena retained here is construction
//! and validation state, never hot runner state.

const std = @import("std");
const digest = @import("digest.zig");
const effects = @import("effects.zig");
const instruction_effects = @import("instruction_effects.zig");
const ir = @import("ir.zig");
const program = @import("program.zig");
const relation = @import("relation.zig");
const source = @import("source.zig");
const types = @import("types.zig");
const validate_mod = @import("validate.zig");

pub const MAIN_COLUMN_COUNT: usize = 35;
pub const SEMANTIC_CONSTRAINT_COUNT: usize = 21;
pub const DIRECT_CONSTRAINT_COUNT: usize = SEMANTIC_CONSTRAINT_COUNT + 1;
pub const RELATION_EVENT_COUNT: usize = 16;
pub const RELATION_BATCH_SIZE: usize = 2;
pub const ADDI_OPCODE_ID: u32 = 10;
pub const XORI_OPCODE_ID: u32 = 13;
pub const ORI_OPCODE_ID: u32 = 14;
pub const ANDI_OPCODE_ID: u32 = 15;

pub const SEMANTIC_DIGEST_HEX =
    "77cac74f85ee61abc8aa1ab97ee37c3f1fddb61eda7c9c982f166c75122908a6";

pub const SEMANTIC_DIGEST: digest.Digest = blk: {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, SEMANTIC_DIGEST_HEX) catch
        @compileError("invalid typed ADDI semantic digest");
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

pub const AccessColumns = struct {
    addr: types.ValueId,
    previous: [4]types.ValueId,
    previous_clock: types.ValueId,
    next: [4]types.ValueId,
};

pub const Columns = struct {
    clock: types.ValueId,
    pc: types.ValueId,
    rd: AccessColumns,
    rs1: AccessColumns,
    immediate_low: types.ValueId,
    immediate_high: types.ValueId,
    immediate_sign: types.ValueId,
    is_addi: types.ValueId,
    is_xori: types.ValueId,
    is_ori: types.ValueId,
    is_andi: types.ValueId,
    result: [4]types.ValueId,
    destination_nonzero: types.ValueId,
    destination_inverse: types.ValueId,

    pub fn physical(self: Columns) [MAIN_COLUMN_COUNT]types.ValueId {
        return .{
            self.clock,
            self.pc,
            self.rd.addr,
            self.rd.previous[0],
            self.rd.previous[1],
            self.rd.previous[2],
            self.rd.previous[3],
            self.rd.previous_clock,
            self.rd.next[0],
            self.rd.next[1],
            self.rd.next[2],
            self.rd.next[3],
            self.rs1.addr,
            self.rs1.previous[0],
            self.rs1.previous[1],
            self.rs1.previous[2],
            self.rs1.previous[3],
            self.rs1.previous_clock,
            self.rs1.next[0],
            self.rs1.next[1],
            self.rs1.next[2],
            self.rs1.next[3],
            self.immediate_low,
            self.immediate_high,
            self.immediate_sign,
            self.is_addi,
            self.is_xori,
            self.is_ori,
            self.is_andi,
            self.result[0],
            self.result[1],
            self.result[2],
            self.result[3],
            self.destination_nonzero,
            self.destination_inverse,
        };
    }
};

pub const Events = struct {
    program_fetch: types.EffectId,
    immediate_range: types.EffectId,
    retirement: instruction_effects.SequentialRetirement,
    source: effects.RegisterAccessGroup,
    bitwise: [4]types.EffectId,
    result_range: [2]types.EffectId,
    destination: effects.RegisterAccessGroup,
};

pub const ValidationError = validate_mod.Error || error{InvalidAddiDefinition};

pub const Definition = struct {
    arena: ir.Arena,
    columns: Columns,
    is_active: types.ValueId,
    active: types.ValueId,
    bitwise_active: types.ValueId,
    constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId,
    constraint_roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId,
    events: Events,
    immediate_limbs: [4]types.ValueId,
    unsigned_immediate: types.ValueId,
    opcode: types.ValueId,
    zero: types.ValueId,

    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const Definition) ValidationError!void {
        try validate_mod.validate(&self.arena);
        const semantic_digest = digest.computeV6(&self.arena) catch
            return error.InvalidAddiDefinition;
        if (!std.mem.eql(u8, &semantic_digest, &SEMANTIC_DIGEST))
            return error.InvalidAddiDefinition;
        if (self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or
            self.arena.effectsView().len != RELATION_EVENT_COUNT)
        {
            return error.InvalidAddiDefinition;
        }
        for (self.constraints, self.constraint_roots, 0..) |id, root, index| {
            if (types.idIndex(id) != index)
                return error.InvalidAddiDefinition;
            const constraint = self.arena.constraint(id) orelse
                return error.InvalidAddiDefinition;
            if (constraint.root != root or constraint.gate != null or
                constraint.category != .semantic)
            {
                return error.InvalidAddiDefinition;
            }
            const name = self.arena.name(constraint.name) orelse
                return error.InvalidAddiDefinition;
            var expected_name_buffer: [64]u8 = undefined;
            const expected_name = std.fmt.bufPrint(
                &expected_name_buffer,
                "compat.riscv.base_alu_imm.direct.{d}",
                .{index},
            ) catch return error.InvalidAddiDefinition;
            if (!std.mem.eql(u8, name, expected_name))
                return error.InvalidAddiDefinition;
        }

        const expected_effects = [_]types.EffectId{
            self.events.program_fetch,
            self.events.immediate_range,
            self.events.retirement.events.consume,
            self.events.retirement.events.produce,
            self.events.source.consume,
            self.events.source.emit,
            self.events.source.clock_gap,
            self.events.bitwise[0],
            self.events.bitwise[1],
            self.events.bitwise[2],
            self.events.bitwise[3],
            self.events.result_range[0],
            self.events.result_range[1],
            self.events.destination.consume,
            self.events.destination.emit,
            self.events.destination.clock_gap,
        };
        for (expected_effects, 0..) |id, index| if (types.idIndex(id) != index)
            return error.InvalidAddiDefinition;

        const physical = self.columns.physical();
        for (physical, 0..) |value, index| if (types.idIndex(value) != index)
            return error.InvalidAddiDefinition;
        var input_count: usize = 0;
        for (self.arena.nodesView()) |node| switch (node.key.op) {
            .input => input_count += 1,
            else => {},
        };
        if (types.idIndex(self.is_active) != MAIN_COLUMN_COUNT or
            input_count != MAIN_COLUMN_COUNT + 1 or
            self.events.source.ordinal != .first or
            self.events.source.phase != .first or
            self.events.destination.ordinal != .second or
            self.events.destination.phase != .second)
        {
            return error.InvalidAddiDefinition;
        }

        const c = self.columns;
        if (!effectMatches(
            &self.arena,
            self.events.program_fetch,
            .program_fetch,
            .program_access,
            .request,
            &.{ c.pc, self.opcode, c.rd.addr, c.rs1.addr, self.unsigned_immediate },
            self.active,
            null,
        ) or !effectMatches(
            &self.arena,
            self.events.immediate_range,
            .range_request,
            .range_check_8_11,
            .request,
            null,
            self.active,
            null,
        ) or !effectMatches(
            &self.arena,
            self.events.retirement.events.consume,
            .state_consume,
            .registers_state,
            .consume,
            &.{ c.pc, c.clock },
            self.active,
            null,
        ) or !effectMatches(
            &self.arena,
            self.events.retirement.events.produce,
            .state_produce,
            .registers_state,
            .emit,
            &.{ self.events.retirement.after.pc, self.events.retirement.after.clock },
            self.active,
            null,
        )) return error.InvalidAddiDefinition;

        const immediate_range = self.arena.effectValues(
            self.events.immediate_range,
        ) orelse return error.InvalidAddiDefinition;
        if (immediate_range.len != 2 or immediate_range[0] != c.immediate_low)
            return error.InvalidAddiDefinition;
        for (self.events.bitwise, 0..) |id, lane| {
            if (!effectMatches(
                &self.arena,
                id,
                .bitwise_request,
                .bitwise,
                .request,
                null,
                self.bitwise_active,
                null,
            )) return error.InvalidAddiDefinition;
            const values = self.arena.effectValues(id) orelse
                return error.InvalidAddiDefinition;
            if (values.len != 4 or values[0] != c.rs1.next[lane] or
                values[1] != self.immediate_limbs[lane] or
                values[2] != c.result[lane])
            {
                return error.InvalidAddiDefinition;
            }
        }
        for (self.events.result_range, 0..) |id, pair| {
            if (!effectMatches(
                &self.arena,
                id,
                .range_request,
                .range_check_8_8,
                .request,
                &.{ c.result[pair * 2], c.result[pair * 2 + 1] },
                self.active,
                null,
            )) return error.InvalidAddiDefinition;
        }
        if (!accessMatches(
            &self.arena,
            self.events.source,
            .register_read,
            c.rs1,
            self.active,
            .first,
        ) or !accessMatches(
            &self.arena,
            self.events.destination,
            .register_write,
            c.rd,
            self.active,
            .second,
        )) return error.InvalidAddiDefinition;
    }
};

pub fn build(allocator: std.mem.Allocator, location: Location) !Definition {
    var arena = ir.Arena.init(allocator);
    errdefer arena.deinit();
    const span = try location.install(&arena);
    const uint2 = try types.Type.boundedField(2);
    const uint3 = try types.Type.boundedField(3);
    const uint9 = try types.Type.boundedField(9);

    const columns = Columns{
        .clock = try arena.input("clock", .clock, span),
        .pc = try arena.input("pc", .pc, span),
        .rd = try accessInputs(&arena, "rd", span),
        .rs1 = try accessInputs(&arena, "rs1", span),
        .immediate_low = try arena.input("imm_0", .byte, span),
        .immediate_high = try arena.input("imm_1", uint3, span),
        .immediate_sign = try arena.input("imm_msb", .bit, span),
        .is_addi = try arena.input("opcode_add_flag", .bit, span),
        .is_xori = try arena.input("opcode_xor_flag", .bit, span),
        .is_ori = try arena.input("opcode_or_flag", .bit, span),
        .is_andi = try arena.input("opcode_and_flag", .bit, span),
        .result = try byteInputs(&arena, "result", span),
        .destination_nonzero = try arena.input("rd_nonzero", .bit, span),
        .destination_inverse = try arena.input("rd_inv", .felt, span),
    };
    const is_active = try arena.input("is_active", .selector, span);
    const zero = try arena.constantField(0, span);
    const one = try arena.constantField(1, span);
    const active = try arena.oneHotSelector(&.{
        columns.is_addi,
        columns.is_xori,
        columns.is_ori,
        columns.is_andi,
    }, span);
    const bitwise_active = try arena.oneHotSelector(&.{
        columns.is_xori,
        columns.is_ori,
        columns.is_andi,
    }, span);

    const c248 = try arena.constantField(248, span);
    const c255 = try arena.constantField(255, span);
    const c256 = try arena.constantField(256, span);
    const c2048 = try arena.constantField(1 << 11, span);
    const inv256 = try arena.constantField(1 << 23, span);
    const immediate_high = try arena.add(
        columns.immediate_high,
        try arena.mul(columns.immediate_sign, c248, span),
        span,
    );
    const immediate_fill = try arena.mul(columns.immediate_sign, c255, span);
    const direct_immediate_limbs = [4]types.ValueId{
        columns.immediate_low,
        immediate_high,
        immediate_fill,
        immediate_fill,
    };

    var constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId = undefined;
    var roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId = undefined;
    var constraint_index: usize = 0;
    roots[constraint_index] = try bitPolynomial(&arena, active, one, span);
    constraints[constraint_index] = try assertDirect(
        &arena,
        constraint_index,
        roots[constraint_index],
        span,
    );
    constraint_index += 1;
    inline for (.{
        columns.is_addi,
        columns.is_xori,
        columns.is_ori,
        columns.is_andi,
        columns.immediate_sign,
    }) |flag| {
        roots[constraint_index] = try bitPolynomial(&arena, flag, one, span);
        constraints[constraint_index] = try assertDirect(
            &arena,
            constraint_index,
            roots[constraint_index],
            span,
        );
        constraint_index += 1;
    }
    var carry = zero;
    inline for (0..4) |limb| {
        const numerator = try arena.sub(
            try arena.add(
                try arena.add(columns.rs1.next[limb], direct_immediate_limbs[limb], span),
                carry,
                span,
            ),
            columns.result[limb],
            span,
        );
        carry = try arena.mul(numerator, inv256, span);
        roots[constraint_index] = try arena.mul(
            columns.is_addi,
            try bitPolynomial(&arena, carry, one, span),
            span,
        );
        constraints[constraint_index] = try assertDirect(
            &arena,
            constraint_index,
            roots[constraint_index],
            span,
        );
        constraint_index += 1;
    }
    roots[constraint_index] = try bitPolynomial(
        &arena,
        columns.destination_nonzero,
        one,
        span,
    );
    constraints[constraint_index] = try assertDirect(
        &arena,
        constraint_index,
        roots[constraint_index],
        span,
    );
    constraint_index += 1;
    roots[constraint_index] = try arena.mul(
        columns.rd.addr,
        try arena.sub(one, columns.destination_nonzero, span),
        span,
    );
    constraints[constraint_index] = try assertDirect(
        &arena,
        constraint_index,
        roots[constraint_index],
        span,
    );
    constraint_index += 1;
    roots[constraint_index] = try arena.sub(
        try arena.mul(columns.rd.addr, columns.destination_inverse, span),
        columns.destination_nonzero,
        span,
    );
    constraints[constraint_index] = try assertDirect(
        &arena,
        constraint_index,
        roots[constraint_index],
        span,
    );
    constraint_index += 1;
    inline for (0..4) |limb| {
        roots[constraint_index] = try arena.sub(
            columns.rd.next[limb],
            try arena.mul(
                columns.destination_nonzero,
                columns.result[limb],
                span,
            ),
            span,
        );
        constraints[constraint_index] = try assertDirect(
            &arena,
            constraint_index,
            roots[constraint_index],
            span,
        );
        constraint_index += 1;
    }
    inline for (0..4) |limb| {
        roots[constraint_index] = try arena.mul(
            active,
            try arena.sub(
                columns.rs1.next[limb],
                columns.rs1.previous[limb],
                span,
            ),
            span,
        );
        constraints[constraint_index] = try assertDirect(
            &arena,
            constraint_index,
            roots[constraint_index],
            span,
        );
        constraint_index += 1;
    }
    roots[constraint_index] = try arena.sub(active, is_active, span);
    constraints[constraint_index] = try assertDirect(
        &arena,
        constraint_index,
        roots[constraint_index],
        span,
    );
    constraint_index += 1;
    std.debug.assert(constraint_index == DIRECT_CONSTRAINT_COUNT);

    var opcode = try arena.add(
        try arena.mul(columns.is_addi, try arena.constantField(ADDI_OPCODE_ID, span), span),
        try arena.mul(columns.is_xori, try arena.constantField(XORI_OPCODE_ID, span), span),
        span,
    );
    opcode = try arena.add(
        opcode,
        try arena.mul(columns.is_ori, try arena.constantField(ORI_OPCODE_ID, span), span),
        span,
    );
    opcode = try arena.add(
        opcode,
        try arena.mul(columns.is_andi, try arena.constantField(ANDI_OPCODE_ID, span), span),
        span,
    );
    const unsigned_immediate = try arena.add(
        try arena.add(
            columns.immediate_low,
            try arena.mul(columns.immediate_high, c256, span),
            span,
        ),
        try arena.mul(columns.immediate_sign, c2048, span),
        span,
    );

    const typed_248 = try arena.constantUnsigned(.byte, 248, span);
    const typed_255 = try arena.constantUnsigned(.byte, 255, span);
    const typed_256 = try arena.constantUnsigned(uint9, 256, span);
    const typed_2 = try arena.constantUnsigned(uint2, 2, span);
    const typed_high = try arena.boundedAdd(
        columns.immediate_high,
        try arena.boundedMul(columns.immediate_sign, typed_248, span),
        span,
    );
    const typed_fill = try arena.boundedMul(
        columns.immediate_sign,
        typed_255,
        span,
    );
    const immediate_limbs = [4]types.ValueId{
        columns.immediate_low,
        typed_high,
        typed_fill,
        typed_fill,
    };
    const shifted_high = try arena.boundedMul(
        columns.immediate_high,
        typed_256,
        span,
    );
    const operation_id = try arena.boundedAdd(
        try arena.boundedMul(columns.is_xori, typed_2, span),
        columns.is_ori,
        span,
    );

    const fetch = try effects.programFetch(
        &arena,
        .{
            .pc = columns.pc,
            .opcode_id = opcode,
            .rd = columns.rd.addr,
            .rs1 = columns.rs1.addr,
            .operand = unsigned_immediate,
        },
        active,
        span,
    );
    const immediate_range = try instruction_effects.rangeCheck811(
        &arena,
        .{ .low_byte = columns.immediate_low, .high_shifted = shifted_high },
        active,
        span,
    );
    const retirement = try instruction_effects.retireSequential(
        &arena,
        .{ .pc = columns.pc, .clock = columns.clock },
        active,
        span,
    );
    var schedule = try effects.AccessSchedule.begin(
        &arena,
        columns.clock,
        active,
        span,
    );
    const source_access = try schedule.registerReadTransition(.{
        .index = columns.rs1.addr,
        .previous_clock = columns.rs1.previous_clock,
        .previous = columns.rs1.previous,
        .next = columns.rs1.next,
    }, span);
    var bitwise_inputs: [4]instruction_effects.BitwiseInput = undefined;
    inline for (&bitwise_inputs, 0..) |*input, limb| input.* = .{
        .lhs = columns.rs1.next[limb],
        .rhs = immediate_limbs[limb],
        .result = columns.result[limb],
        .operation_id = operation_id,
    };
    const bitwise = try instruction_effects.bitwiseWord(
        &arena,
        bitwise_inputs,
        bitwise_active,
        span,
    );
    const result_range = try instruction_effects.rangeCheck88Pairs(
        &arena,
        .{
            .{ .first_byte = columns.result[0], .second_byte = columns.result[1] },
            .{ .first_byte = columns.result[2], .second_byte = columns.result[3] },
        },
        active,
        span,
    );
    const destination = try schedule.registerWrite(.{
        .index = columns.rd.addr,
        .previous_clock = columns.rd.previous_clock,
        .previous = columns.rd.previous,
        .next = columns.rd.next,
    }, span);

    var definition = Definition{
        .arena = arena,
        .columns = columns,
        .is_active = is_active,
        .active = active,
        .bitwise_active = bitwise_active,
        .constraints = constraints,
        .constraint_roots = roots,
        .events = .{
            .program_fetch = fetch,
            .immediate_range = immediate_range,
            .retirement = retirement,
            .source = source_access,
            .bitwise = bitwise,
            .result_range = result_range,
            .destination = destination,
        },
        .immediate_limbs = immediate_limbs,
        .unsigned_immediate = unsigned_immediate,
        .opcode = opcode,
        .zero = zero,
    };
    try definition.validate();
    return definition;
}

fn accessInputs(
    arena: *ir.Arena,
    comptime prefix: []const u8,
    span: source.SourceSpan,
) !AccessColumns {
    return .{
        .addr = try arena.input(
            std.fmt.comptimePrint("{s}_addr", .{prefix}),
            .register_index,
            span,
        ),
        .previous = try byteInputs(arena, prefix ++ "_prev", span),
        .previous_clock = try arena.input(
            std.fmt.comptimePrint("{s}_clock_prev", .{prefix}),
            .clock,
            span,
        ),
        .next = try byteInputs(arena, prefix ++ "_next", span),
    };
}

fn byteInputs(
    arena: *ir.Arena,
    comptime prefix: []const u8,
    span: source.SourceSpan,
) ![4]types.ValueId {
    var values: [4]types.ValueId = undefined;
    inline for (&values, 0..) |*value, index| value.* = try arena.input(
        std.fmt.comptimePrint("{s}_{d}", .{ prefix, index }),
        .byte,
        span,
    );
    return values;
}

fn bitPolynomial(
    arena: *ir.Arena,
    value: types.ValueId,
    one: types.ValueId,
    span: source.SourceSpan,
) !types.ValueId {
    return arena.mul(value, try arena.sub(value, one, span), span);
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
        "compat.riscv.base_alu_imm.direct.{d}",
        .{index},
    );
    return arena.assertZero(name, root, null, .semantic, span);
}

fn effectMatches(
    arena: *const ir.Arena,
    id: types.EffectId,
    kind: program.EffectKind,
    domain: relation.Domain,
    role: relation.Role,
    expected_values: ?[]const types.ValueId,
    active: types.ValueId,
    ordinal: ?u8,
) bool {
    const effect = arena.effect(id) orelse return false;
    const binding = effect.binding orelse return false;
    const schema = relation.get(domain);
    const values = arena.effectValues(id) orelse return false;
    return effect.kind == kind and binding.schema == schema.id and
        binding.schema_version == schema.version and binding.role == role and
        effect.liveness == active and effect.access_ordinal == ordinal and
        (expected_values == null or
            std.mem.eql(types.ValueId, values, expected_values.?));
}

fn accessMatches(
    arena: *const ir.Arena,
    group: effects.RegisterAccessGroup,
    kind: program.EffectKind,
    columns: AccessColumns,
    active: types.ValueId,
    ordinal: types.AccessOrdinal,
) bool {
    const ordinal_value: u8 = @intFromEnum(ordinal);
    if (!effectMatches(
        arena,
        group.consume,
        kind,
        .memory_access,
        .consume,
        null,
        active,
        ordinal_value,
    ) or !effectMatches(
        arena,
        group.emit,
        kind,
        .memory_access,
        .emit,
        null,
        active,
        ordinal_value,
    ) or !effectMatches(
        arena,
        group.clock_gap,
        kind,
        .range_check_20,
        .request,
        null,
        active,
        ordinal_value,
    )) return false;
    const consumed = arena.effectValues(group.consume) orelse return false;
    const emitted = arena.effectValues(group.emit) orelse return false;
    if (consumed.len != 7 or emitted.len != 7 or
        consumed[0] != arena.effectValues(group.emit).?[0] or
        consumed[2] != columns.previous_clock or
        !std.mem.eql(types.ValueId, consumed[3..7], &columns.previous) or
        !std.mem.eql(types.ValueId, emitted[3..7], &columns.next))
    {
        return false;
    }
    return true;
}
