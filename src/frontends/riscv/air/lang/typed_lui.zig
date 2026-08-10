//! Native typed AIR authorship for the compatibility-exact RV32 LUI family.
//!
//! This module is shadow-only: it does not change production selection,
//! witness authority, commitment geometry, or the proof transcript.

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

pub const MAIN_COLUMN_COUNT: usize = 18;
pub const DIRECT_CONSTRAINT_COUNT: usize = 9;
pub const RELATION_EVENT_COUNT: usize = 7;
pub const OPCODE_ID: u32 = 35;
pub const SEMANTIC_DIGEST_HEX =
    "3f69a47662e9216f86c03bba257b52fb280542af610972a4c98cf7630252fd68";

pub const SEMANTIC_DIGEST: digest.Digest = blk: {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, SEMANTIC_DIGEST_HEX) catch
        @compileError("invalid typed LUI semantic digest");
    break :blk result;
};

const direct_constraint_names = [_][]const u8{
    "compat.riscv.lui.direct.0",
    "compat.riscv.lui.direct.1",
    "compat.riscv.lui.direct.2",
    "compat.riscv.lui.direct.3",
    "compat.riscv.lui.direct.4",
    "compat.riscv.lui.direct.5",
    "compat.riscv.lui.direct.6",
    "compat.riscv.lui.direct.7",
    "compat.riscv.lui.direct.8",
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
    enabler: types.ValueId,
    clock: types.ValueId,
    pc: types.ValueId,
    rd_addr: types.ValueId,
    rd_previous: [4]types.ValueId,
    rd_previous_clock: types.ValueId,
    rd_next: [4]types.ValueId,
    immediate_low_nibble: types.ValueId,
    immediate_middle_byte: types.ValueId,
    immediate_high_byte: types.ValueId,
    rd_nonzero: types.ValueId,
    rd_inverse: types.ValueId,

    pub fn physical(self: Columns) [MAIN_COLUMN_COUNT]types.ValueId {
        return .{
            self.enabler,
            self.clock,
            self.pc,
            self.rd_addr,
            self.rd_previous[0],
            self.rd_previous[1],
            self.rd_previous[2],
            self.rd_previous[3],
            self.rd_previous_clock,
            self.rd_next[0],
            self.rd_next[1],
            self.rd_next[2],
            self.rd_next[3],
            self.immediate_low_nibble,
            self.immediate_middle_byte,
            self.immediate_high_byte,
            self.rd_nonzero,
            self.rd_inverse,
        };
    }
};

pub const Events = struct {
    program_fetch: types.EffectId,
    retirement: instruction_effects.SequentialRetirement,
    immediate_range: types.EffectId,
    destination: effects.RegisterAccessGroup,
};

pub const ValidationError = validate_mod.Error || error{InvalidLuiDefinition};

pub const Definition = struct {
    arena: ir.Arena,
    columns: Columns,
    is_active: types.ValueId,
    constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId,
    constraint_roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId,
    events: Events,
    immediate: types.ValueId,
    result: [4]types.ValueId,
    zero: types.ValueId,
    opcode: types.ValueId,

    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const Definition) ValidationError!void {
        try validate_mod.validate(&self.arena);
        const semantic_digest = try digest.computeV5(&self.arena);
        if (!std.mem.eql(u8, &semantic_digest, &SEMANTIC_DIGEST))
            return error.InvalidLuiDefinition;
        if (self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or
            self.arena.effectsView().len != RELATION_EVENT_COUNT)
            return error.InvalidLuiDefinition;
        for (self.constraints, 0..) |id, index| {
            if (types.idIndex(id) != index)
                return error.InvalidLuiDefinition;
            const constraint = self.arena.constraint(id) orelse
                return error.InvalidLuiDefinition;
            if (constraint.root != self.constraint_roots[index] or
                constraint.gate != null or constraint.category != .semantic)
                return error.InvalidLuiDefinition;
            const name = self.arena.name(constraint.name) orelse
                return error.InvalidLuiDefinition;
            if (!std.mem.eql(u8, name, direct_constraint_names[index]))
                return error.InvalidLuiDefinition;
        }
        const expected_effects = [_]types.EffectId{
            self.events.program_fetch,
            self.events.retirement.events.consume,
            self.events.retirement.events.produce,
            self.events.immediate_range,
            self.events.destination.consume,
            self.events.destination.emit,
            self.events.destination.clock_gap,
        };
        for (expected_effects, 0..) |id, index| {
            if (types.idIndex(id) != index)
                return error.InvalidLuiDefinition;
        }
        const physical = self.columns.physical();
        for (physical, 0..) |value, index| {
            if (types.idIndex(value) != index)
                return error.InvalidLuiDefinition;
        }
        var input_count: usize = 0;
        for (self.arena.nodesView()) |node| switch (node.key.op) {
            .input => input_count += 1,
            else => {},
        };
        if (types.idIndex(self.is_active) != MAIN_COLUMN_COUNT or
            input_count != MAIN_COLUMN_COUNT + 1 or
            self.events.destination.ordinal != .first or
            self.events.destination.phase != .first)
            return error.InvalidLuiDefinition;
        const c = self.columns;
        if (self.result[0] != self.zero or
            self.result[2] != c.immediate_middle_byte or
            self.result[3] != c.immediate_high_byte or
            !isCanonicalProduct(
                &self.arena,
                self.result[1],
                c.immediate_low_nibble,
                1 << 4,
            ))
        {
            return error.InvalidLuiDefinition;
        }
        if (!effectMatches(
            &self.arena,
            self.events.program_fetch,
            .program_fetch,
            .program_access,
            .request,
            &.{ c.pc, self.opcode, c.rd_addr, self.immediate, self.zero },
            c.enabler,
            null,
        ) or !effectMatches(
            &self.arena,
            self.events.retirement.events.consume,
            .state_consume,
            .registers_state,
            .consume,
            &.{ c.pc, c.clock },
            c.enabler,
            null,
        ) or !effectMatches(
            &self.arena,
            self.events.retirement.events.produce,
            .state_produce,
            .registers_state,
            .emit,
            &.{ self.events.retirement.after.pc, self.events.retirement.after.clock },
            c.enabler,
            null,
        ) or !effectMatches(
            &self.arena,
            self.events.immediate_range,
            .range_request,
            .range_check_8_8_4,
            .request,
            &.{ c.immediate_middle_byte, c.immediate_high_byte, c.immediate_low_nibble },
            c.enabler,
            null,
        )) return error.InvalidLuiDefinition;
        const consume = self.arena.effectValues(self.events.destination.consume) orelse
            return error.InvalidLuiDefinition;
        const emitted = self.arena.effectValues(self.events.destination.emit) orelse
            return error.InvalidLuiDefinition;
        if (consume.len != 7 or emitted.len != 7 or
            consume[0] != self.zero or emitted[0] != self.zero or
            consume[2] != c.rd_previous_clock or
            !std.mem.eql(types.ValueId, consume[3..7], &c.rd_previous) or
            !std.mem.eql(types.ValueId, emitted[3..7], &c.rd_next))
            return error.InvalidLuiDefinition;
        const address = switch ((self.arena.node(consume[1]) orelse
            return error.InvalidLuiDefinition).key.op) {
            .machine_derived => |derived| switch (derived) {
                .register_address => |item| item,
                else => return error.InvalidLuiDefinition,
            },
            else => return error.InvalidLuiDefinition,
        };
        const current = switch ((self.arena.node(emitted[2]) orelse
            return error.InvalidLuiDefinition).key.op) {
            .machine_derived => |derived| switch (derived) {
                .access_clock => |item| item,
                else => return error.InvalidLuiDefinition,
            },
            else => return error.InvalidLuiDefinition,
        };
        if (address.index != c.rd_addr or current.instruction_clock != c.clock or
            current.phase != .first)
            return error.InvalidLuiDefinition;
    }
};

fn isCanonicalProduct(
    arena: *const ir.Arena,
    product: types.ValueId,
    value: types.ValueId,
    canonical: u32,
) bool {
    const node = arena.node(product) orelse return false;
    const operands = switch (node.key.op) {
        .mul => |binary| binary,
        else => return false,
    };
    if (operands.lhs == value)
        return isCanonicalFelt(arena, operands.rhs, canonical);
    if (operands.rhs == value)
        return isCanonicalFelt(arena, operands.lhs, canonical);
    return false;
}

fn isCanonicalFelt(
    arena: *const ir.Arena,
    value: types.ValueId,
    canonical: u32,
) bool {
    const node = arena.node(value) orelse return false;
    if (!std.meta.eql(node.key.ty, types.Type.felt)) return false;
    return switch (node.key.op) {
        .constant => |constant| switch (constant) {
            .field => |actual| actual == canonical,
            .unsigned => false,
        },
        else => false,
    };
}

pub fn build(
    allocator: std.mem.Allocator,
    location: Location,
) !Definition {
    var arena = ir.Arena.init(allocator);
    errdefer arena.deinit();
    const span = try location.install(&arena);
    const uint4 = try types.Type.boundedField(4);
    const columns = Columns{
        .enabler = try arena.input("enabler", .bit, span),
        .clock = try arena.input("clock", .clock, span),
        .pc = try arena.input("pc", .pc, span),
        .rd_addr = try arena.input("rd_addr", .register_index, span),
        .rd_previous = try byteInputs(&arena, "rd_prev", span),
        .rd_previous_clock = try arena.input("rd_clock_prev", .clock, span),
        .rd_next = try byteInputs(&arena, "rd_next", span),
        .immediate_low_nibble = try arena.input("imm_0", uint4, span),
        .immediate_middle_byte = try arena.input("imm_1", .byte, span),
        .immediate_high_byte = try arena.input("imm_2", .byte, span),
        .rd_nonzero = try arena.input("rd_nonzero", .bit, span),
        .rd_inverse = try arena.input("rd_inv", .felt, span),
    };
    const is_active = try arena.input("is_active", .selector, span);
    const zero = try arena.constantField(0, span);
    const one = try arena.constantField(1, span);
    const sixteen = try arena.constantField(1 << 4, span);
    const four_thousand_ninety_six = try arena.constantField(1 << 12, span);
    const opcode = try arena.constantField(OPCODE_ID, span);

    const low_shifted = try arena.mul(columns.immediate_low_nibble, sixteen, span);
    const middle_shifted = try arena.mul(
        columns.immediate_middle_byte,
        sixteen,
        span,
    );
    const high_shifted = try arena.mul(
        columns.immediate_high_byte,
        four_thousand_ninety_six,
        span,
    );
    const immediate = try arena.add(
        try arena.add(columns.immediate_low_nibble, middle_shifted, span),
        high_shifted,
        span,
    );
    const result = [4]types.ValueId{
        zero,
        low_shifted,
        columns.immediate_middle_byte,
        columns.immediate_high_byte,
    };

    var constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId = undefined;
    var constraint_roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId = undefined;
    constraint_roots[0] = try bitPolynomial(&arena, columns.enabler, one, span);
    constraints[0] = try assertDirect(
        &arena,
        0,
        constraint_roots[0],
        span,
    );
    constraint_roots[1] = try bitPolynomial(&arena, columns.rd_nonzero, one, span);
    constraints[1] = try assertDirect(
        &arena,
        1,
        constraint_roots[1],
        span,
    );
    constraint_roots[2] = try arena.mul(
        columns.rd_addr,
        try arena.sub(one, columns.rd_nonzero, span),
        span,
    );
    constraints[2] = try assertDirect(&arena, 2, constraint_roots[2], span);
    constraint_roots[3] = try arena.sub(
        try arena.mul(columns.rd_addr, columns.rd_inverse, span),
        columns.rd_nonzero,
        span,
    );
    constraints[3] = try assertDirect(&arena, 3, constraint_roots[3], span);
    inline for (columns.rd_next, result, 0..) |next, expected, index| {
        constraint_roots[index + 4] = try arena.sub(
            next,
            try arena.mul(columns.rd_nonzero, expected, span),
            span,
        );
        constraints[index + 4] = try assertDirect(
            &arena,
            index + 4,
            constraint_roots[index + 4],
            span,
        );
    }
    constraint_roots[8] = try arena.sub(columns.enabler, is_active, span);
    constraints[8] = try assertDirect(
        &arena,
        8,
        constraint_roots[8],
        span,
    );

    const fetch = try effects.programFetch(
        &arena,
        .{
            .pc = columns.pc,
            .opcode_id = opcode,
            .rd = columns.rd_addr,
            .rs1 = immediate,
            .operand = zero,
        },
        columns.enabler,
        span,
    );
    const retirement = try instruction_effects.retireSequential(
        &arena,
        .{ .pc = columns.pc, .clock = columns.clock },
        columns.enabler,
        span,
    );
    const immediate_range = try instruction_effects.rangeCheck884(
        &arena,
        .{
            .first_byte = columns.immediate_middle_byte,
            .second_byte = columns.immediate_high_byte,
            .low_nibble = columns.immediate_low_nibble,
        },
        columns.enabler,
        span,
    );
    var schedule = try effects.AccessSchedule.begin(
        &arena,
        columns.clock,
        columns.enabler,
        span,
    );
    const destination = try schedule.registerWrite(.{
        .index = columns.rd_addr,
        .previous_clock = columns.rd_previous_clock,
        .previous = columns.rd_previous,
        .next = columns.rd_next,
    }, span);

    var result_definition = Definition{
        .arena = arena,
        .columns = columns,
        .is_active = is_active,
        .constraints = constraints,
        .constraint_roots = constraint_roots,
        .events = .{
            .program_fetch = fetch,
            .retirement = retirement,
            .immediate_range = immediate_range,
            .destination = destination,
        },
        .immediate = immediate,
        .result = result,
        .zero = zero,
        .opcode = opcode,
    };
    try result_definition.validate();
    return result_definition;
}

fn effectMatches(
    arena: *const ir.Arena,
    id: types.EffectId,
    kind: program.EffectKind,
    domain: relation.Domain,
    role: relation.Role,
    expected_values: []const types.ValueId,
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
        std.mem.eql(types.ValueId, values, expected_values);
}

fn byteInputs(
    arena: *ir.Arena,
    comptime prefix: []const u8,
    span: source.SourceSpan,
) ![4]types.ValueId {
    var values: [4]types.ValueId = undefined;
    inline for (&values, 0..) |*value, index| {
        value.* = try arena.input(
            std.fmt.comptimePrint("{s}_{d}", .{ prefix, index }),
            .byte,
            span,
        );
    }
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
    comptime index: usize,
    root: types.ValueId,
    span: source.SourceSpan,
) !types.ConstraintId {
    return arena.assertZero(
        std.fmt.comptimePrint("compat.riscv.lui.direct.{d}", .{index}),
        root,
        null,
        program.ConstraintCategory.semantic,
        span,
    );
}
