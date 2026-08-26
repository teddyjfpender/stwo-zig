//! Native typed AIR authorship for RV32 `DIV`, `DIVU`, `REM`, and `REMU`.
//!
//! Production AIR, witness selection, commitment geometry, and transcripts are
//! unchanged. Direct roots and all 25 ordered relations are independently
//! authored over the exact 67-column layout. Derived range fields carry closed
//! proof records naming the constraint or fixed-table request that establishes
//! their semantic type; no unchecked cast or additional trace column exists.

const std = @import("std");
const constraints_mod = @import("typed_div_constraints.zig");
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

pub const MAIN_COLUMN_COUNT: usize = 67;
pub const SEMANTIC_CONSTRAINT_COUNT = constraints_mod.SEMANTIC_CONSTRAINT_COUNT;
pub const DIRECT_CONSTRAINT_COUNT = constraints_mod.DIRECT_CONSTRAINT_COUNT;
pub const LOOKUP_COUNT: usize = 25;
pub const LOOKUP_BATCH_SIZE: u8 = 1;
pub const MAX_LOOKUP_ARITY: usize = 7;
pub const RANGE_REFINEMENT_COUNT: usize = 14;
pub const FIXED_TABLE_REQUEST_COUNT: usize = 11;
pub const OPCODE_IDS = [4]u32{ 41, 42, 43, 44 };
pub const SEMANTIC_DIGEST_HEX =
    "a33fd73890a391f954566eac75c54111c3ab5da54f20554ce095f7083b9e3ec2";
pub const SEMANTIC_DIGEST: digest.Digest = hexDigest(
    SEMANTIC_DIGEST_HEX,
    "invalid typed DIV semantic digest",
);

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
    rs2: AccessColumns,
    zero_divisor: types.ValueId,
    r_zero: types.ValueId,
    q: [4]types.ValueId,
    r: [4]types.ValueId,
    b_sign: types.ValueId,
    c_sign: types.ValueId,
    q_sign: types.ValueId,
    sign_xor: types.ValueId,
    c_sum_inv: types.ValueId,
    r_sum_inv: types.ValueId,
    r_abs: [4]types.ValueId,
    r_inv: [4]types.ValueId,
    lt_markers: [4]types.ValueId,
    lt_diff: types.ValueId,
    is_div: types.ValueId,
    is_divu: types.ValueId,
    is_rem: types.ValueId,
    is_remu: types.ValueId,
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
            self.zero_divisor,
            self.r_zero,
            self.q[0],
            self.q[1],
            self.q[2],
            self.q[3],
            self.r[0],
            self.r[1],
            self.r[2],
            self.r[3],
            self.b_sign,
            self.c_sign,
            self.q_sign,
            self.sign_xor,
            self.c_sum_inv,
            self.r_sum_inv,
            self.r_abs[0],
            self.r_abs[1],
            self.r_abs[2],
            self.r_abs[3],
            self.r_inv[0],
            self.r_inv[1],
            self.r_inv[2],
            self.r_inv[3],
            self.lt_markers[0],
            self.lt_markers[1],
            self.lt_markers[2],
            self.lt_markers[3],
            self.lt_diff,
            self.is_div,
            self.is_divu,
            self.is_rem,
            self.is_remu,
            self.destination_nonzero,
            self.destination_inverse,
        };
    }
};

pub const ValidationError = validate_mod.Error || relation.Error || error{
    InvalidDivDefinition,
};

pub const Definition = struct {
    arena: ir.Arena,
    columns: Columns,
    is_active: types.ValueId,
    model: constraints_mod.Result,

    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const Definition) ValidationError!void {
        try validate_mod.validate(&self.arena);
        const semantic_identity = try digest.computeIdentity(&self.arena);
        if (semantic_identity.format_version != digest.range_refinement_format_version) {
            return error.InvalidDivDefinition;
        }
        if (self.arena.effectsView().len != LOOKUP_COUNT or
            self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or
            self.arena.range_refinements.items.len != RANGE_REFINEMENT_COUNT or
            self.arena.fixed_table_requests.items.len != FIXED_TABLE_REQUEST_COUNT)
        {
            return error.InvalidDivDefinition;
        }
        const physical = self.columns.physical();
        for (physical, 0..) |value, index| {
            if (types.idIndex(value) != index) return error.InvalidDivDefinition;
        }
        if (types.idIndex(self.is_active) != MAIN_COLUMN_COUNT)
            return error.InvalidDivDefinition;
        for (self.model.constraints, self.model.roots, 0..) |id, root, index| {
            if (types.idIndex(id) != index) return error.InvalidDivDefinition;
            const constraint = self.arena.constraint(id) orelse
                return error.InvalidDivDefinition;
            if (constraint.root != root or constraint.gate != null or
                constraint.category != .semantic)
            {
                return error.InvalidDivDefinition;
            }
            var name_buffer: [64]u8 = undefined;
            const expected = std.fmt.bufPrint(
                &name_buffer,
                "compat.riscv.div.direct.{d}",
                .{index},
            ) catch return error.InvalidDivDefinition;
            const actual = self.arena.name(constraint.name) orelse
                return error.InvalidDivDefinition;
            if (!std.mem.eql(u8, expected, actual))
                return error.InvalidDivDefinition;
        }
        for (self.arena.effectsView(), expectedLookupShapes, 0..) |effect, shape, index| {
            const binding = effect.binding orelse return error.InvalidDivDefinition;
            const id = types.idFromIndex(types.EffectId, index) catch
                return error.InvalidDivDefinition;
            const values = self.arena.effectValues(id) orelse
                return error.InvalidDivDefinition;
            if (effect.kind != shape.kind or
                binding.schema != relation.id(shape.domain) or
                binding.role != shape.role or values.len != shape.arity or
                effect.access_ordinal != shape.ordinal or effect.liveness == null)
            {
                return error.InvalidDivDefinition;
            }
            _ = try relation.validateEventShape(
                binding.schema,
                binding.role,
                values.len,
                effect.access_ordinal,
            );
            for (values) |value| if (self.arena.node(value) == null)
                return error.InvalidDivDefinition;
        }
        if (!std.mem.eql(u8, &semantic_identity.bytes, &SEMANTIC_DIGEST))
            return error.InvalidDivDefinition;
    }
};

const LookupShape = struct {
    kind: program.EffectKind,
    domain: relation.Domain,
    role: relation.Role,
    arity: u8,
    ordinal: ?u8 = null,
};

const expectedLookupShapes = [LOOKUP_COUNT]LookupShape{
    .{ .kind = .program_fetch, .domain = .program_access, .role = .request, .arity = 5 },
    .{ .kind = .state_consume, .domain = .registers_state, .role = .consume, .arity = 2 },
    .{ .kind = .state_produce, .domain = .registers_state, .role = .emit, .arity = 2 },
    .{ .kind = .register_read, .domain = .memory_access, .role = .consume, .arity = 7, .ordinal = 1 },
    .{ .kind = .register_read, .domain = .memory_access, .role = .emit, .arity = 7, .ordinal = 1 },
    .{ .kind = .register_read, .domain = .range_check_20, .role = .request, .arity = 1, .ordinal = 1 },
    .{ .kind = .register_read, .domain = .memory_access, .role = .consume, .arity = 7, .ordinal = 2 },
    .{ .kind = .register_read, .domain = .memory_access, .role = .emit, .arity = 7, .ordinal = 2 },
    .{ .kind = .register_read, .domain = .range_check_20, .role = .request, .arity = 1, .ordinal = 2 },
    .{ .kind = .range_request, .domain = .range_check_8_8, .role = .request, .arity = 2 },
    .{ .kind = .range_request, .domain = .range_check_8_8, .role = .request, .arity = 2 },
    .{ .kind = .range_request, .domain = .range_check_8_11, .role = .request, .arity = 2 },
    .{ .kind = .range_request, .domain = .range_check_8_11, .role = .request, .arity = 2 },
    .{ .kind = .range_request, .domain = .range_check_8_11, .role = .request, .arity = 2 },
    .{ .kind = .range_request, .domain = .range_check_8_11, .role = .request, .arity = 2 },
    .{ .kind = .range_request, .domain = .range_check_8_11, .role = .request, .arity = 2 },
    .{ .kind = .range_request, .domain = .range_check_8_11, .role = .request, .arity = 2 },
    .{ .kind = .range_request, .domain = .range_check_8_11, .role = .request, .arity = 2 },
    .{ .kind = .range_request, .domain = .range_check_8_11, .role = .request, .arity = 2 },
    .{ .kind = .range_request, .domain = .range_check_m31, .role = .request, .arity = 2 },
    .{ .kind = .range_request, .domain = .range_check_8_8, .role = .request, .arity = 2 },
    .{ .kind = .range_request, .domain = .range_check_20, .role = .request, .arity = 1 },
    .{ .kind = .register_write, .domain = .memory_access, .role = .consume, .arity = 7, .ordinal = 3 },
    .{ .kind = .register_write, .domain = .memory_access, .role = .emit, .arity = 7, .ordinal = 3 },
    .{ .kind = .register_write, .domain = .range_check_20, .role = .request, .arity = 1, .ordinal = 3 },
};

pub fn build(allocator: std.mem.Allocator, location: Location) !Definition {
    var arena = ir.Arena.init(allocator);
    errdefer arena.deinit();
    const span = try location.install(&arena);
    const columns = Columns{
        .clock = try arena.input("clock", .clock, span),
        .pc = try arena.input("pc", .pc, span),
        .rd = try accessInputs(&arena, "rd", span),
        .rs1 = try accessInputs(&arena, "rs1", span),
        .rs2 = try accessInputs(&arena, "rs2", span),
        .zero_divisor = try arena.input("zero_divisor", .bit, span),
        .r_zero = try arena.input("r_zero", .bit, span),
        .q = try byteInputs(&arena, "q", span),
        .r = try byteInputs(&arena, "r", span),
        .b_sign = try arena.input("b_sign", .bit, span),
        .c_sign = try arena.input("c_sign", .bit, span),
        .q_sign = try arena.input("q_sign", .bit, span),
        .sign_xor = try arena.input("sign_xor", .bit, span),
        .c_sum_inv = try arena.input("c_sum_inv", .felt, span),
        .r_sum_inv = try arena.input("r_sum_inv", .felt, span),
        .r_abs = try byteInputs(&arena, "r_abs", span),
        .r_inv = try feltInputs(&arena, "r_inv", span),
        .lt_markers = try bitInputs(&arena, "lt_marker", span),
        .lt_diff = try arena.input("lt_diff", .byte, span),
        .is_div = try arena.input("opcode_div_flag", .bit, span),
        .is_divu = try arena.input("opcode_divu_flag", .bit, span),
        .is_rem = try arena.input("opcode_rem_flag", .bit, span),
        .is_remu = try arena.input("opcode_remu_flag", .bit, span),
        .destination_nonzero = try arena.input("rd_nonzero", .bit, span),
        .destination_inverse = try arena.input("rd_inv", .felt, span),
    };
    const is_active = try arena.input("is_active", .selector, span);
    const model = try constraints_mod.author(&arena, columns, is_active, span);
    const is_signed = try arena.oneHotSelector(
        &.{ columns.is_div, columns.is_rem },
        span,
    );
    const valid_not_zero = try range_refinement.booleanFromConstraint(
        &arena,
        model.valid_not_zero_divisor,
        model.constraints[16],
        span,
    );
    const valid_not_special = try range_refinement.booleanFromConstraint(
        &arena,
        model.valid_not_special,
        model.constraints[17],
        span,
    );
    try authorEffects(
        &arena,
        columns,
        model,
        is_signed,
        valid_not_zero,
        valid_not_special,
        span,
    );
    var definition = Definition{
        .arena = arena,
        .columns = columns,
        .is_active = is_active,
        .model = model,
    };
    try definition.validate();
    return definition;
}

fn authorEffects(
    arena: *ir.Arena,
    c: Columns,
    model: constraints_mod.Result,
    is_signed: types.ValueId,
    valid_not_zero: types.ValueId,
    valid_not_special: types.ValueId,
    span: source.SourceSpan,
) !void {
    const one = try arena.constantField(1, span);
    const c128 = try arena.constantField(128, span);
    const zero_byte = try arena.constantUnsigned(.byte, 0, span);
    _ = try effects.programFetch(arena, .{
        .pc = c.pc,
        .opcode_id = model.opcode,
        .rd = c.rd.addr,
        .rs1 = c.rs1.addr,
        .operand = c.rs2.addr,
    }, model.active, span);
    _ = try instruction_effects.retireSequential(
        arena,
        .{ .pc = c.pc, .clock = c.clock },
        model.active,
        span,
    );
    var schedule = try effects.AccessSchedule.begin(arena, c.clock, model.active, span);
    _ = try schedule.registerReadTransition(.{
        .index = c.rs1.addr,
        .previous_clock = c.rs1.previous_clock,
        .previous = c.rs1.previous,
        .next = c.rs1.next,
    }, span);
    _ = try schedule.registerReadTransition(.{
        .index = c.rs2.addr,
        .previous_clock = c.rs2.previous_clock,
        .previous = c.rs2.previous,
        .next = c.rs2.next,
    }, span);
    _ = try instruction_effects.rangeCheck88Pairs(arena, .{
        .{ .first_byte = c.rs2.next[0], .second_byte = c.rs2.next[1] },
        .{ .first_byte = c.rs2.next[2], .second_byte = c.rs2.next[3] },
    }, model.active, span);
    inline for (0..8) |limb| {
        const value = if (limb < 4) c.q[limb] else c.r[limb - 4];
        _ = try range_refinement.rangeCheck811(
            arena,
            value,
            model.product_carries[limb],
            model.active,
            span,
        );
    }
    const quotient_sign_live = try arena.sub(
        try arena.boundedMul(is_signed, valid_not_zero, span),
        try arena.boundedMul(c.b_sign, c.c_sign, span),
        span,
    );
    _ = try range_refinement.rangeCheckM31(
        arena,
        zero_byte,
        try arena.sub(c.q[3], try arena.mul(c.q_sign, c128, span), span),
        quotient_sign_live,
        span,
    );
    _ = try range_refinement.rangeCheck88Refined(
        arena,
        model.sign_checks[0],
        model.sign_checks[1],
        model.active,
        span,
    );
    _ = try range_refinement.rangeCheck20(
        arena,
        try arena.sub(c.lt_diff, one, span),
        valid_not_special,
        span,
    );
    _ = try schedule.registerWrite(.{
        .index = c.rd.addr,
        .previous_clock = c.rd.previous_clock,
        .previous = c.rd.previous,
        .next = c.rd.next,
    }, span);
    if (arena.effectsView().len != LOOKUP_COUNT) return error.InvalidDivDefinition;
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

fn feltInputs(
    arena: *ir.Arena,
    comptime prefix: []const u8,
    span: source.SourceSpan,
) ![4]types.ValueId {
    var result: [4]types.ValueId = undefined;
    inline for (&result, 0..) |*value, index| value.* = try arena.input(
        std.fmt.comptimePrint("{s}_{d}", .{ prefix, index }),
        .felt,
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

fn hexDigest(comptime text: []const u8, comptime message: []const u8) digest.Digest {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, text) catch @compileError(message);
    return result;
}
