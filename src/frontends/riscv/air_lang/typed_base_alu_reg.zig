//! Native typed AIR authorship for the complete RV32 BASE_ALU_REG family.
//!
//! This compatibility-exact definition owns ADD, SUB, XOR, OR, and AND in
//! the pinned 35-column layout. Arithmetic carry chains remain derived AIR
//! values; only final result bytes are committed. Compact register reads use
//! one physical value for both sides of each authenticated access transition.

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
pub const RELATION_EVENT_COUNT: usize = 18;
pub const RELATION_BATCH_SIZE: usize = 2;
pub const ADD_OPCODE_ID: u32 = 0;
pub const SUB_OPCODE_ID: u32 = 1;
pub const XOR_OPCODE_ID: u32 = 5;
pub const OR_OPCODE_ID: u32 = 8;
pub const AND_OPCODE_ID: u32 = 9;

pub const SEMANTIC_DIGEST_HEX =
    "f8cf9c0b60b41fc948ec7c5efd61caf5abf96ec30f242c6a375845ab905e61c5";

pub const SEMANTIC_DIGEST: digest.Digest = blk: {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, SEMANTIC_DIGEST_HEX) catch
        @compileError("invalid typed BASE_ALU_REG semantic digest");
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

pub const ReadColumns = struct {
    addr: types.ValueId,
    value: [4]types.ValueId,
    previous_clock: types.ValueId,
};

pub const Columns = struct {
    clock: types.ValueId,
    pc: types.ValueId,
    rd: AccessColumns,
    rs1: ReadColumns,
    rs2: ReadColumns,
    is_add: types.ValueId,
    is_sub: types.ValueId,
    is_xor: types.ValueId,
    is_or: types.ValueId,
    is_and: types.ValueId,
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
            self.rs1.value[0],
            self.rs1.value[1],
            self.rs1.value[2],
            self.rs1.value[3],
            self.rs1.previous_clock,
            self.rs2.addr,
            self.rs2.value[0],
            self.rs2.value[1],
            self.rs2.value[2],
            self.rs2.value[3],
            self.rs2.previous_clock,
            self.is_add,
            self.is_sub,
            self.is_xor,
            self.is_or,
            self.is_and,
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
    retirement: instruction_effects.SequentialRetirement,
    source_1: effects.RegisterAccessGroup,
    source_2: effects.RegisterAccessGroup,
    bitwise: [4]types.EffectId,
    result_range: [2]types.EffectId,
    destination: effects.RegisterAccessGroup,
};

pub const ValidationError = validate_mod.Error ||
    error{InvalidBaseAluRegDefinition};

pub const Definition = struct {
    arena: ir.Arena,
    columns: Columns,
    is_active: types.ValueId,
    active: types.ValueId,
    bitwise_active: types.ValueId,
    constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId,
    constraint_roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId,
    events: Events,
    opcode: types.ValueId,
    operation_id: types.ValueId,
    zero: types.ValueId,

    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const Definition) ValidationError!void {
        try validate_mod.validate(&self.arena);
        const semantic_digest = digest.computeV6(&self.arena) catch
            return error.InvalidBaseAluRegDefinition;
        if (!std.mem.eql(u8, &semantic_digest, &SEMANTIC_DIGEST))
            return error.InvalidBaseAluRegDefinition;
        if (self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or
            self.arena.effectsView().len != RELATION_EVENT_COUNT)
        {
            return error.InvalidBaseAluRegDefinition;
        }
        for (self.constraints, self.constraint_roots, 0..) |id, root, index| {
            if (types.idIndex(id) != index)
                return error.InvalidBaseAluRegDefinition;
            const constraint = self.arena.constraint(id) orelse
                return error.InvalidBaseAluRegDefinition;
            if (constraint.root != root or constraint.gate != null or
                constraint.category != .semantic)
            {
                return error.InvalidBaseAluRegDefinition;
            }
            const name = self.arena.name(constraint.name) orelse
                return error.InvalidBaseAluRegDefinition;
            var expected_name_buffer: [64]u8 = undefined;
            const expected_name = std.fmt.bufPrint(
                &expected_name_buffer,
                "compat.riscv.base_alu_reg.direct.{d}",
                .{index},
            ) catch return error.InvalidBaseAluRegDefinition;
            if (!std.mem.eql(u8, name, expected_name))
                return error.InvalidBaseAluRegDefinition;
        }

        const expected_effects = [_]types.EffectId{
            self.events.program_fetch,
            self.events.retirement.events.consume,
            self.events.retirement.events.produce,
            self.events.source_1.consume,
            self.events.source_1.emit,
            self.events.source_1.clock_gap,
            self.events.source_2.consume,
            self.events.source_2.emit,
            self.events.source_2.clock_gap,
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
            return error.InvalidBaseAluRegDefinition;

        const physical = self.columns.physical();
        for (physical, 0..) |value, index| if (types.idIndex(value) != index)
            return error.InvalidBaseAluRegDefinition;
        var input_count: usize = 0;
        for (self.arena.nodesView()) |node| switch (node.key.op) {
            .input => input_count += 1,
            else => {},
        };
        if (types.idIndex(self.is_active) != MAIN_COLUMN_COUNT or
            input_count != MAIN_COLUMN_COUNT + 1 or
            self.events.source_1.ordinal != .first or
            self.events.source_1.phase != .first or
            self.events.source_2.ordinal != .second or
            self.events.source_2.phase != .second or
            self.events.destination.ordinal != .third or
            self.events.destination.phase != .third)
        {
            return error.InvalidBaseAluRegDefinition;
        }

        const c = self.columns;
        if (!effectMatches(
            &self.arena,
            self.events.program_fetch,
            .program_fetch,
            .program_access,
            .request,
            &.{ c.pc, self.opcode, c.rd.addr, c.rs1.addr, c.rs2.addr },
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
        )) return error.InvalidBaseAluRegDefinition;

        for (self.events.bitwise, 0..) |id, lane| {
            if (!effectMatches(
                &self.arena,
                id,
                .bitwise_request,
                .bitwise,
                .request,
                &.{
                    c.rs1.value[lane],
                    c.rs2.value[lane],
                    c.result[lane],
                    self.operation_id,
                },
                self.bitwise_active,
                null,
            )) return error.InvalidBaseAluRegDefinition;
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
            )) return error.InvalidBaseAluRegDefinition;
        }
        if (!readAccessMatches(
            &self.arena,
            self.events.source_1,
            c.rs1,
            self.active,
            .first,
        ) or !readAccessMatches(
            &self.arena,
            self.events.source_2,
            c.rs2,
            self.active,
            .second,
        ) or !writeAccessMatches(
            &self.arena,
            self.events.destination,
            c.rd,
            self.active,
            .third,
        )) return error.InvalidBaseAluRegDefinition;
    }
};

pub fn build(allocator: std.mem.Allocator, location: Location) !Definition {
    var arena = ir.Arena.init(allocator);
    errdefer arena.deinit();
    const span = try location.install(&arena);
    const uint2 = try types.Type.boundedField(2);

    const columns = Columns{
        .clock = try arena.input("clock", .clock, span),
        .pc = try arena.input("pc", .pc, span),
        .rd = try accessInputs(&arena, "rd", span),
        .rs1 = try readInputs(&arena, "rs1", span),
        .rs2 = try readInputs(&arena, "rs2", span),
        .is_add = try arena.input("opcode_add_flag", .bit, span),
        .is_sub = try arena.input("opcode_sub_flag", .bit, span),
        .is_xor = try arena.input("opcode_xor_flag", .bit, span),
        .is_or = try arena.input("opcode_or_flag", .bit, span),
        .is_and = try arena.input("opcode_and_flag", .bit, span),
        .result = try byteInputs(&arena, "result", span),
        .destination_nonzero = try arena.input("rd_nonzero", .bit, span),
        .destination_inverse = try arena.input("rd_inv", .felt, span),
    };
    const is_active = try arena.input("is_active", .selector, span);
    const zero = try arena.constantField(0, span);
    const one = try arena.constantField(1, span);
    const active = try arena.oneHotSelector(&.{
        columns.is_add,
        columns.is_sub,
        columns.is_xor,
        columns.is_or,
        columns.is_and,
    }, span);
    const bitwise_active = try arena.oneHotSelector(&.{
        columns.is_xor,
        columns.is_or,
        columns.is_and,
    }, span);
    const inv256 = try arena.constantField(1 << 23, span);

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
        columns.is_add,
        columns.is_sub,
        columns.is_xor,
        columns.is_or,
        columns.is_and,
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
                try arena.add(columns.rs1.value[limb], columns.rs2.value[limb], span),
                carry,
                span,
            ),
            columns.result[limb],
            span,
        );
        carry = try arena.mul(numerator, inv256, span);
        roots[constraint_index] = try arena.mul(
            columns.is_add,
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
    carry = zero;
    inline for (0..4) |limb| {
        const numerator = try arena.sub(
            try arena.add(
                try arena.add(columns.result[limb], columns.rs2.value[limb], span),
                carry,
                span,
            ),
            columns.rs1.value[limb],
            span,
        );
        carry = try arena.mul(numerator, inv256, span);
        roots[constraint_index] = try arena.mul(
            columns.is_sub,
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
        try arena.mul(columns.is_add, zero, span),
        try arena.mul(columns.is_sub, try arena.constantField(SUB_OPCODE_ID, span), span),
        span,
    );
    opcode = try arena.add(
        opcode,
        try arena.mul(columns.is_xor, try arena.constantField(XOR_OPCODE_ID, span), span),
        span,
    );
    opcode = try arena.add(
        opcode,
        try arena.mul(columns.is_or, try arena.constantField(OR_OPCODE_ID, span), span),
        span,
    );
    opcode = try arena.add(
        opcode,
        try arena.mul(columns.is_and, try arena.constantField(AND_OPCODE_ID, span), span),
        span,
    );
    const typed_2 = try arena.constantUnsigned(uint2, 2, span);
    const operation_id = try arena.boundedAdd(
        try arena.boundedMul(columns.is_xor, typed_2, span),
        columns.is_or,
        span,
    );

    const fetch = try effects.programFetch(
        &arena,
        .{
            .pc = columns.pc,
            .opcode_id = opcode,
            .rd = columns.rd.addr,
            .rs1 = columns.rs1.addr,
            .operand = columns.rs2.addr,
        },
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
    const source_1 = try schedule.registerRead(.{
        .index = columns.rs1.addr,
        .previous_clock = columns.rs1.previous_clock,
        .value = columns.rs1.value,
    }, span);
    const source_2 = try schedule.registerRead(.{
        .index = columns.rs2.addr,
        .previous_clock = columns.rs2.previous_clock,
        .value = columns.rs2.value,
    }, span);
    var bitwise_inputs: [4]instruction_effects.BitwiseInput = undefined;
    inline for (&bitwise_inputs, 0..) |*input, limb| input.* = .{
        .lhs = columns.rs1.value[limb],
        .rhs = columns.rs2.value[limb],
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
            .retirement = retirement,
            .source_1 = source_1,
            .source_2 = source_2,
            .bitwise = bitwise,
            .result_range = result_range,
            .destination = destination,
        },
        .opcode = opcode,
        .operation_id = operation_id,
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
        .addr = try arena.input(prefix ++ "_addr", .register_index, span),
        .previous = try byteInputs(arena, prefix ++ "_prev", span),
        .previous_clock = try arena.input(prefix ++ "_clock_prev", .clock, span),
        .next = try byteInputs(arena, prefix ++ "_next", span),
    };
}

fn readInputs(
    arena: *ir.Arena,
    comptime prefix: []const u8,
    span: source.SourceSpan,
) !ReadColumns {
    return .{
        .addr = try arena.input(prefix ++ "_addr", .register_index, span),
        .value = try byteInputs(arena, prefix ++ "_prev", span),
        .previous_clock = try arena.input(prefix ++ "_clock_prev", .clock, span),
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
        "compat.riscv.base_alu_reg.direct.{d}",
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

fn readAccessMatches(
    arena: *const ir.Arena,
    group: effects.RegisterAccessGroup,
    columns: ReadColumns,
    active: types.ValueId,
    ordinal: types.AccessOrdinal,
) bool {
    const ordinal_value: u8 = @intFromEnum(ordinal);
    if (!accessEffectKindsMatch(arena, group, .register_read, active, ordinal_value))
        return false;
    const consumed = arena.effectValues(group.consume) orelse return false;
    const emitted = arena.effectValues(group.emit) orelse return false;
    return consumed.len == 7 and emitted.len == 7 and
        consumed[2] == columns.previous_clock and
        std.mem.eql(types.ValueId, consumed[3..7], &columns.value) and
        std.mem.eql(types.ValueId, emitted[3..7], &columns.value);
}

fn writeAccessMatches(
    arena: *const ir.Arena,
    group: effects.RegisterAccessGroup,
    columns: AccessColumns,
    active: types.ValueId,
    ordinal: types.AccessOrdinal,
) bool {
    const ordinal_value: u8 = @intFromEnum(ordinal);
    if (!accessEffectKindsMatch(arena, group, .register_write, active, ordinal_value))
        return false;
    const consumed = arena.effectValues(group.consume) orelse return false;
    const emitted = arena.effectValues(group.emit) orelse return false;
    return consumed.len == 7 and emitted.len == 7 and
        consumed[2] == columns.previous_clock and
        std.mem.eql(types.ValueId, consumed[3..7], &columns.previous) and
        std.mem.eql(types.ValueId, emitted[3..7], &columns.next);
}

fn accessEffectKindsMatch(
    arena: *const ir.Arena,
    group: effects.RegisterAccessGroup,
    kind: program.EffectKind,
    active: types.ValueId,
    ordinal: u8,
) bool {
    return effectMatches(
        arena,
        group.consume,
        kind,
        .memory_access,
        .consume,
        null,
        active,
        ordinal,
    ) and effectMatches(
        arena,
        group.emit,
        kind,
        .memory_access,
        .emit,
        null,
        active,
        ordinal,
    ) and effectMatches(
        arena,
        group.clock_gap,
        kind,
        .range_check_20,
        .request,
        null,
        active,
        ordinal,
    );
}
