//! Native typed AIR authorship for RV32 `JALR`.
//!
//! Production AIR, witness selection, commitment geometry, and transcripts are
//! unchanged. This shadow definition independently authors all 41 physical
//! columns, 23 direct roots, and 18 ordered lookup events. The control target
//! is refined to `.pc` only from named fixed-table evidence for the exact
//! `low20/high8` split; the immediate nibble is likewise proof-carrying.

const std = @import("std");
const constraints_mod = @import("typed_jalr_constraints.zig");
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

pub const MAIN_COLUMN_COUNT: usize = 41;
pub const SEMANTIC_CONSTRAINT_COUNT = constraints_mod.SEMANTIC_CONSTRAINT_COUNT;
pub const DIRECT_CONSTRAINT_COUNT = constraints_mod.DIRECT_CONSTRAINT_COUNT;
pub const LOOKUP_COUNT: usize = 18;
pub const LOOKUP_BATCH_SIZE: u8 = 2;
pub const MAX_LOOKUP_ARITY: usize = 7;
pub const RANGE_REFINEMENT_COUNT: usize = 2;
pub const FIXED_TABLE_REQUEST_COUNT: usize = 7;
pub const OPCODE_ID: u32 = 34;

pub const SEMANTIC_DIGEST_HEX =
    "9e374e33bcc65926240d5181eac52bad8b57b699097a211425715ba372a86f28";
pub const SEMANTIC_DIGEST: digest.Digest = hexDigest(
    SEMANTIC_DIGEST_HEX,
    "invalid typed JALR semantic digest",
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
    enabler: types.ValueId,
    clock: types.ValueId,
    pc: types.ValueId,
    rd: AccessColumns,
    rs1: AccessColumns,
    to_pc_over_two: types.ValueId,
    to_pc_lsb: types.ValueId,
    imm_felt: types.ValueId,
    result: [4]types.ValueId,
    destination_nonzero: types.ValueId,
    destination_inverse: types.ValueId,
    target_word_low_20: types.ValueId,
    target_word_high_8: types.ValueId,
    target_limbs: [4]types.ValueId,
    imm_byte_0: types.ValueId,
    imm_nibble: types.ValueId,
    imm_sign: types.ValueId,

    pub fn physical(self: Columns) [MAIN_COLUMN_COUNT]types.ValueId {
        return .{
            self.enabler,
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
            self.to_pc_over_two,
            self.to_pc_lsb,
            self.imm_felt,
            self.result[0],
            self.result[1],
            self.result[2],
            self.result[3],
            self.destination_nonzero,
            self.destination_inverse,
            self.target_word_low_20,
            self.target_word_high_8,
            self.target_limbs[0],
            self.target_limbs[1],
            self.target_limbs[2],
            self.target_limbs[3],
            self.imm_byte_0,
            self.imm_nibble,
            self.imm_sign,
        };
    }
};

pub const Events = struct {
    program_fetch: types.EffectId,
    source: effects.RegisterAccessGroup,
    source_ranges: [2]types.EffectId,
    target_word_low: types.EffectId,
    target_word_high: types.EffectId,
    target_middle: types.EffectId,
    target_m31: types.EffectId,
    immediate_range: types.EffectId,
    retirement: effects.Retirement,
    result_middle: types.EffectId,
    result_m31: types.EffectId,
    destination: effects.RegisterAccessGroup,
};

pub const ValidationError = validate_mod.Error || relation.Error || error{
    InvalidJalrDefinition,
};

pub const Definition = struct {
    arena: ir.Arena,
    columns: Columns,
    is_active: types.ValueId,
    /// Exact scalar view of physical PC column two for direct-root parity.
    pc_polynomial: types.ValueId,
    model: constraints_mod.Result,
    target_pc: types.ValueId,
    immediate_low_nibble: types.ValueId,
    events: Events,

    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const Definition) ValidationError!void {
        try validate_mod.validate(&self.arena);
        const identity = try digest.computeIdentity(&self.arena);
        if (identity.format_version != digest.range_refinement_format_version or
            !std.mem.eql(u8, &identity.bytes, &SEMANTIC_DIGEST) or
            self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or
            self.arena.effectsView().len != LOOKUP_COUNT or
            self.arena.range_refinements.items.len != RANGE_REFINEMENT_COUNT or
            self.arena.fixed_table_requests.items.len != FIXED_TABLE_REQUEST_COUNT)
        {
            return error.InvalidJalrDefinition;
        }

        for (self.columns.physical(), 0..) |value, index| {
            if (types.idIndex(value) != index) return error.InvalidJalrDefinition;
        }
        if (types.idIndex(self.is_active) != MAIN_COLUMN_COUNT or
            types.idIndex(self.pc_polynomial) != MAIN_COLUMN_COUNT + 1)
        {
            return error.InvalidJalrDefinition;
        }
        var input_count: usize = 0;
        for (self.arena.nodesView()) |node| switch (node.key.op) {
            .input => input_count += 1,
            else => {},
        };
        if (input_count != MAIN_COLUMN_COUNT + 2)
            return error.InvalidJalrDefinition;

        for (self.model.constraints, self.model.roots, 0..) |id, root, index| {
            if (types.idIndex(id) != index) return error.InvalidJalrDefinition;
            const constraint = self.arena.constraint(id) orelse
                return error.InvalidJalrDefinition;
            if (constraint.root != root or constraint.gate != null or
                constraint.category != .semantic)
            {
                return error.InvalidJalrDefinition;
            }
            var name_buffer: [64]u8 = undefined;
            const expected = std.fmt.bufPrint(
                &name_buffer,
                "compat.riscv.jalr.direct.{d}",
                .{index},
            ) catch return error.InvalidJalrDefinition;
            const actual = self.arena.name(constraint.name) orelse
                return error.InvalidJalrDefinition;
            if (!std.mem.eql(u8, expected, actual))
                return error.InvalidJalrDefinition;
        }

        const expected_ids = self.orderedEventIds();
        for (self.arena.effectsView(), expectedLookupShapes, expected_ids, 0..) |
            effect,
            shape,
            id,
            index,
        | {
            if (types.idIndex(id) != index) return error.InvalidJalrDefinition;
            const binding = effect.binding orelse return error.InvalidJalrDefinition;
            const values = self.arena.effectValues(id) orelse
                return error.InvalidJalrDefinition;
            if (effect.kind != shape.kind or binding.schema != relation.id(shape.domain) or
                binding.role != shape.role or values.len != shape.arity or
                effect.access_ordinal != shape.ordinal or
                effect.liveness != self.columns.enabler)
            {
                return error.InvalidJalrDefinition;
            }
            _ = try relation.validateEventShape(
                binding.schema,
                binding.role,
                values.len,
                effect.access_ordinal,
            );
        }
        if (self.events.source.ordinal != .first or
            self.events.source.phase != .first or
            self.events.destination.ordinal != .second or
            self.events.destination.phase != .second)
        {
            return error.InvalidJalrDefinition;
        }
    }

    pub fn orderedEventIds(self: *const Definition) [LOOKUP_COUNT]types.EffectId {
        return .{
            self.events.program_fetch,
            self.events.source.consume,
            self.events.source.emit,
            self.events.source.clock_gap,
            self.events.source_ranges[0],
            self.events.source_ranges[1],
            self.events.target_word_low,
            self.events.target_word_high,
            self.events.target_middle,
            self.events.target_m31,
            self.events.immediate_range,
            self.events.retirement.consume,
            self.events.retirement.produce,
            self.events.result_middle,
            self.events.result_m31,
            self.events.destination.consume,
            self.events.destination.emit,
            self.events.destination.clock_gap,
        };
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
    .{ .kind = .register_read, .domain = .memory_access, .role = .consume, .arity = 7, .ordinal = 1 },
    .{ .kind = .register_read, .domain = .memory_access, .role = .emit, .arity = 7, .ordinal = 1 },
    .{ .kind = .register_read, .domain = .range_check_20, .role = .request, .arity = 1, .ordinal = 1 },
    .{ .kind = .range_request, .domain = .range_check_8_8, .role = .request, .arity = 2 },
    .{ .kind = .range_request, .domain = .range_check_8_8, .role = .request, .arity = 2 },
    .{ .kind = .range_request, .domain = .range_check_20, .role = .request, .arity = 1 },
    .{ .kind = .range_request, .domain = .range_check_8_8, .role = .request, .arity = 2 },
    .{ .kind = .range_request, .domain = .range_check_8_8, .role = .request, .arity = 2 },
    .{ .kind = .range_request, .domain = .range_check_m31, .role = .request, .arity = 2 },
    .{ .kind = .range_request, .domain = .range_check_8_8_4, .role = .request, .arity = 3 },
    .{ .kind = .state_consume, .domain = .registers_state, .role = .consume, .arity = 2 },
    .{ .kind = .state_produce, .domain = .registers_state, .role = .emit, .arity = 2 },
    .{ .kind = .range_request, .domain = .range_check_8_8, .role = .request, .arity = 2 },
    .{ .kind = .range_request, .domain = .range_check_m31, .role = .request, .arity = 2 },
    .{ .kind = .register_write, .domain = .memory_access, .role = .consume, .arity = 7, .ordinal = 2 },
    .{ .kind = .register_write, .domain = .memory_access, .role = .emit, .arity = 7, .ordinal = 2 },
    .{ .kind = .register_write, .domain = .range_check_20, .role = .request, .arity = 1, .ordinal = 2 },
};

pub fn build(allocator: std.mem.Allocator, location: Location) !Definition {
    var definition = try buildDefinition(allocator, location);
    errdefer definition.deinit();
    try definition.validate();
    return definition;
}

fn buildDefinition(allocator: std.mem.Allocator, location: Location) !Definition {
    var arena = ir.Arena.init(allocator);
    errdefer arena.deinit();
    const span = try location.install(&arena);
    const uint7 = try types.Type.boundedField(7);
    const columns = Columns{
        .enabler = try arena.input("enabler", .bit, span),
        .clock = try arena.input("clock", .clock, span),
        .pc = try arena.input("pc", .pc, span),
        .rd = try accessInputs(&arena, "rd", span),
        .rs1 = try accessInputs(&arena, "rs1", span),
        .to_pc_over_two = try arena.input("to_pc_over_two", .felt, span),
        .to_pc_lsb = try arena.input("to_pc_lsb", .bit, span),
        .imm_felt = try arena.input("imm_felt", .felt, span),
        .result = .{
            try arena.input("result_0", .byte, span),
            try arena.input("result_1", .byte, span),
            try arena.input("result_2", .byte, span),
            try arena.input("result_3", uint7, span),
        },
        .destination_nonzero = try arena.input("rd_nonzero", .bit, span),
        .destination_inverse = try arena.input("rd_inv", .felt, span),
        .target_word_low_20 = try arena.input("target_word_low_20", .uint20, span),
        .target_word_high_8 = try arena.input("target_word_high_8", .byte, span),
        .target_limbs = .{
            try arena.input("target_0", .byte, span),
            try arena.input("target_1", .byte, span),
            try arena.input("target_2", .byte, span),
            try arena.input("target_3", uint7, span),
        },
        .imm_byte_0 = try arena.input("imm_byte_0", .byte, span),
        .imm_nibble = try arena.input("imm_nibble", .felt, span),
        .imm_sign = try arena.input("imm_sign", .bit, span),
    };
    const is_active = try arena.input("is_active", .selector, span);
    const pc_polynomial = try arena.input("pc_polynomial", .felt, span);
    const model = try constraints_mod.author(
        &arena,
        columns,
        pc_polynomial,
        is_active,
        span,
    );
    const authored = try authorEffects(&arena, columns, model, span);
    return .{
        .arena = arena,
        .columns = columns,
        .is_active = is_active,
        .pc_polynomial = pc_polynomial,
        .model = model,
        .target_pc = authored.target_pc,
        .immediate_low_nibble = authored.immediate_low_nibble,
        .events = authored.events,
    };
}

const AuthoredEffects = struct {
    target_pc: types.ValueId,
    immediate_low_nibble: types.ValueId,
    events: Events,
};

fn authorEffects(
    arena: *ir.Arena,
    c: Columns,
    model: constraints_mod.Result,
    span: source.SourceSpan,
) !AuthoredEffects {
    const zero_byte = try arena.constantUnsigned(.byte, 0, span);
    const c2 = try arena.constantField(2, span);
    const c8 = try arena.constantField(8, span);
    const program_fetch = try effects.programFetch(arena, .{
        .pc = c.pc,
        .opcode_id = model.opcode,
        .rd = c.rd.addr,
        .rs1 = c.rs1.addr,
        .operand = c.imm_felt,
    }, c.enabler, span);

    var schedule = try effects.AccessSchedule.begin(arena, c.clock, c.enabler, span);
    const source_access = try schedule.registerReadTransition(.{
        .index = c.rs1.addr,
        .previous_clock = c.rs1.previous_clock,
        .previous = c.rs1.previous,
        .next = c.rs1.next,
    }, span);
    const source_ranges = try instruction_effects.rangeCheck88Pairs(arena, .{
        .{ .first_byte = c.rs1.next[1], .second_byte = c.rs1.next[2] },
        .{ .first_byte = c.rs1.next[0], .second_byte = c.rs1.next[3] },
    }, c.enabler, span);

    const target_word_low = try range_refinement.rangeCheck20Typed(
        arena,
        c.target_word_low_20,
        c.enabler,
        span,
    );
    const target_word_high = try range_refinement.rangeCheck88Typed(
        arena,
        c.target_word_high_8,
        zero_byte,
        c.enabler,
        span,
    );
    const target_middle = try range_refinement.rangeCheck88Typed(
        arena,
        c.target_limbs[1],
        c.target_limbs[2],
        c.enabler,
        span,
    );
    const target_m31 = try range_refinement.rangeCheckM31Typed(
        arena,
        c.target_limbs[0],
        c.target_limbs[3],
        c.enabler,
        span,
    );
    const immediate_low_nibble_polynomial = try arena.mul(
        try arena.sub(c.imm_nibble, try arena.mul(c.imm_sign, c8, span), span),
        c2,
        span,
    );
    const immediate_range = try range_refinement.rangeCheck884Refined(
        arena,
        c.imm_byte_0,
        zero_byte,
        immediate_low_nibble_polynomial,
        c.enabler,
        span,
    );
    const target_pc = try range_refinement.alignedControlTarget(
        arena,
        c.target_word_low_20,
        c.target_word_high_8,
        target_word_low.effect,
        target_word_high.effect,
        c.enabler,
        span,
    );
    const next_clock = try arena.instructionNextClock(c.clock, span);
    const retirement = try effects.retire(
        arena,
        .{ .pc = c.pc, .clock = c.clock },
        .{ .pc = target_pc, .clock = next_clock },
        c.enabler,
        span,
    );
    const result_middle = try range_refinement.rangeCheck88Typed(
        arena,
        c.result[1],
        c.result[2],
        c.enabler,
        span,
    );
    const result_m31 = try range_refinement.rangeCheckM31Typed(
        arena,
        c.result[0],
        c.result[3],
        c.enabler,
        span,
    );
    const destination = try schedule.registerWrite(.{
        .index = c.rd.addr,
        .previous_clock = c.rd.previous_clock,
        .previous = c.rd.previous,
        .next = c.rd.next,
    }, span);
    if (arena.effectsView().len != LOOKUP_COUNT)
        return error.InvalidJalrDefinition;
    return .{
        .target_pc = target_pc,
        .immediate_low_nibble = immediate_range.values[2],
        .events = .{
            .program_fetch = program_fetch,
            .source = source_access,
            .source_ranges = source_ranges,
            .target_word_low = target_word_low.effect,
            .target_word_high = target_word_high.effect,
            .target_middle = target_middle.effect,
            .target_m31 = target_m31.effect,
            .immediate_range = immediate_range.effect,
            .retirement = retirement,
            .result_middle = result_middle.effect,
            .result_m31 = result_m31.effect,
            .destination = destination,
        },
    };
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

fn hexDigest(comptime value: []const u8, comptime message: []const u8) digest.Digest {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}
