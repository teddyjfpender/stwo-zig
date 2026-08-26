//! Native typed AIR authorship for compatibility-exact RV32 SLT/SLTU.

const std = @import("std");
const constraints_mod = @import("typed_lt_reg_constraints.zig");
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

pub const MAIN_COLUMN_COUNT: usize = 44;
pub const DIRECT_CONSTRAINT_COUNT = constraints_mod.DIRECT_CONSTRAINT_COUNT;
pub const LOOKUP_COUNT: usize = 14;
pub const RANGE_REFINEMENT_COUNT: usize = 5;
pub const FIXED_TABLE_REQUEST_COUNT: usize = 2;
pub const SLT_OPCODE_ID: u32 = 3;
pub const SLTU_OPCODE_ID: u32 = 4;

pub const SEMANTIC_DIGEST_HEX =
    "e28ede4abf49917335d8ecec6e4f5c6bfdea3e4e8f967501313a95dad4d703b0";
pub const SEMANTIC_DIGEST: digest.Digest = hexDigest(
    SEMANTIC_DIGEST_HEX,
    "invalid typed LT_REG semantic digest",
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
    cmp_result: types.ValueId,
    rs1_msl_felt: types.ValueId,
    rs2_msl_felt: types.ValueId,
    is_slt: types.ValueId,
    is_sltu: types.ValueId,
    diff_markers: [4]types.ValueId,
    diff_val: types.ValueId,
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
            self.cmp_result,
            self.rs1_msl_felt,
            self.rs2_msl_felt,
            self.is_slt,
            self.is_sltu,
            self.diff_markers[0],
            self.diff_markers[1],
            self.diff_markers[2],
            self.diff_markers[3],
            self.diff_val,
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
    msl_range: types.EffectId,
    positive_difference: types.EffectId,
    destination: effects.RegisterAccessGroup,
};

pub const ValidationError = validate_mod.Error || relation.Error || error{
    InvalidLtRegDefinition,
};

pub const Definition = struct {
    arena: ir.Arena,
    columns: Columns,
    is_active: types.ValueId,
    model: constraints_mod.Result,
    active: types.ValueId,
    positive: types.ValueId,
    msl_range_values: [2]types.ValueId,
    positive_difference: types.ValueId,
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
            return error.InvalidLtRegDefinition;
        }
        for (self.columns.physical(), 0..) |value, index| {
            if (types.idIndex(value) != index) return error.InvalidLtRegDefinition;
        }
        if (types.idIndex(self.is_active) != MAIN_COLUMN_COUNT)
            return error.InvalidLtRegDefinition;
        var input_count: usize = 0;
        for (self.arena.nodesView()) |node| switch (node.key.op) {
            .input => input_count += 1,
            else => {},
        };
        if (input_count != MAIN_COLUMN_COUNT + 1)
            return error.InvalidLtRegDefinition;

        for (self.model.constraints, self.model.roots, 0..) |id, root, index| {
            if (types.idIndex(id) != index) return error.InvalidLtRegDefinition;
            const constraint = self.arena.constraint(id) orelse
                return error.InvalidLtRegDefinition;
            if (constraint.root != root or constraint.gate != null or
                constraint.category != .semantic)
            {
                return error.InvalidLtRegDefinition;
            }
            var name_buffer: [64]u8 = undefined;
            const expected = std.fmt.bufPrint(
                &name_buffer,
                "compat.riscv.lt_reg.direct.{d}",
                .{index},
            ) catch return error.InvalidLtRegDefinition;
            const actual = self.arena.name(constraint.name) orelse
                return error.InvalidLtRegDefinition;
            if (!std.mem.eql(u8, expected, actual))
                return error.InvalidLtRegDefinition;
        }

        const expected_ids = self.orderedEventIds();
        for (self.arena.effectsView(), expected_lookup_shapes, expected_ids, 0..) |
            effect,
            shape,
            id,
            index,
        | {
            if (types.idIndex(id) != index) return error.InvalidLtRegDefinition;
            const binding = effect.binding orelse return error.InvalidLtRegDefinition;
            const values = self.arena.effectValues(id) orelse
                return error.InvalidLtRegDefinition;
            const expected_liveness = if (index == 10) self.positive else self.active;
            if (effect.kind != shape.kind or
                binding.schema != relation.id(shape.domain) or
                binding.role != shape.role or
                values.len != shape.arity or
                effect.access_ordinal != shape.ordinal or
                effect.liveness != expected_liveness)
            {
                return error.InvalidLtRegDefinition;
            }
            _ = try relation.validateEventShape(
                binding.schema,
                binding.role,
                values.len,
                effect.access_ordinal,
            );
        }
        if (self.events.source_1.ordinal != .first or
            self.events.source_1.phase != .first or
            self.events.source_2.ordinal != .second or
            self.events.source_2.phase != .second or
            self.events.destination.ordinal != .third or
            self.events.destination.phase != .third)
        {
            return error.InvalidLtRegDefinition;
        }
    }

    pub fn orderedEventIds(self: *const Definition) [LOOKUP_COUNT]types.EffectId {
        return .{
            self.events.program_fetch,
            self.events.retirement.events.consume,
            self.events.retirement.events.produce,
            self.events.source_1.consume,
            self.events.source_1.emit,
            self.events.source_1.clock_gap,
            self.events.source_2.consume,
            self.events.source_2.emit,
            self.events.source_2.clock_gap,
            self.events.msl_range,
            self.events.positive_difference,
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

const expected_lookup_shapes = [LOOKUP_COUNT]LookupShape{
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
    .{ .kind = .range_request, .domain = .range_check_20, .role = .request, .arity = 1 },
    .{ .kind = .register_write, .domain = .memory_access, .role = .consume, .arity = 7, .ordinal = 3 },
    .{ .kind = .register_write, .domain = .memory_access, .role = .emit, .arity = 7, .ordinal = 3 },
    .{ .kind = .register_write, .domain = .range_check_20, .role = .request, .arity = 1, .ordinal = 3 },
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
    const columns = Columns{
        .clock = try arena.input("clock", .clock, span),
        .pc = try arena.input("pc", .pc, span),
        .rd = try accessInputs(&arena, "rd", span),
        .rs1 = try accessInputs(&arena, "rs1", span),
        .rs2 = try accessInputs(&arena, "rs2", span),
        .cmp_result = try arena.input("cmp_result", .bit, span),
        .rs1_msl_felt = try arena.input("rs1_msl_felt", .felt, span),
        .rs2_msl_felt = try arena.input("rs2_msl_felt", .felt, span),
        .is_slt = try arena.input("opcode_slt_flag", .bit, span),
        .is_sltu = try arena.input("opcode_sltu_flag", .bit, span),
        .diff_markers = .{
            try arena.input("diff_marker_0", .bit, span),
            try arena.input("diff_marker_1", .bit, span),
            try arena.input("diff_marker_2", .bit, span),
            try arena.input("diff_marker_3", .bit, span),
        },
        .diff_val = try arena.input("diff_val", .felt, span),
        .destination_nonzero = try arena.input("rd_nonzero", .bit, span),
        .destination_inverse = try arena.input("rd_inv", .felt, span),
    };
    const is_active = try arena.input("is_active", .selector, span);
    const model = try constraints_mod.author(&arena, columns, is_active, span);
    const positive = try range_refinement.booleanFromConstraint(
        &arena,
        model.prefix_sum,
        model.constraints[18],
        span,
    );
    const authored = try authorEffects(
        &arena,
        columns,
        model,
        model.active_selector,
        positive,
        span,
    );
    return .{
        .arena = arena,
        .columns = columns,
        .is_active = is_active,
        .model = model,
        .active = model.active_selector,
        .positive = positive,
        .msl_range_values = authored.msl_range_values,
        .positive_difference = authored.positive_difference,
        .events = authored.events,
    };
}

const AuthoredEffects = struct {
    msl_range_values: [2]types.ValueId,
    positive_difference: types.ValueId,
    events: Events,
};

fn authorEffects(
    arena: *ir.Arena,
    c: Columns,
    model: constraints_mod.Result,
    active: types.ValueId,
    positive: types.ValueId,
    span: source.SourceSpan,
) !AuthoredEffects {
    const program_fetch = try effects.programFetch(arena, .{
        .pc = c.pc,
        .opcode_id = model.opcode,
        .rd = c.rd.addr,
        .rs1 = c.rs1.addr,
        .operand = c.rs2.addr,
    }, active, span);
    const retirement = try instruction_effects.retireSequential(
        arena,
        .{ .pc = c.pc, .clock = c.clock },
        active,
        span,
    );
    var schedule = try effects.AccessSchedule.begin(arena, c.clock, active, span);
    const source_1 = try schedule.registerReadTransition(.{
        .index = c.rs1.addr,
        .previous_clock = c.rs1.previous_clock,
        .previous = c.rs1.previous,
        .next = c.rs1.next,
    }, span);
    const source_2 = try schedule.registerReadTransition(.{
        .index = c.rs2.addr,
        .previous_clock = c.rs2.previous_clock,
        .previous = c.rs2.previous,
        .next = c.rs2.next,
    }, span);
    const msl_range = try range_refinement.rangeCheck88Refined(
        arena,
        model.rs1_msl_shifted,
        model.rs2_msl_shifted,
        active,
        span,
    );
    const positive_difference = try range_refinement.rangeCheck20(
        arena,
        model.positive_difference,
        positive,
        span,
    );
    const destination = try schedule.registerWrite(.{
        .index = c.rd.addr,
        .previous_clock = c.rd.previous_clock,
        .previous = c.rd.previous,
        .next = c.rd.next,
    }, span);
    return .{
        .msl_range_values = msl_range.values[0..2].*,
        .positive_difference = positive_difference.values[0],
        .events = .{
            .program_fetch = program_fetch,
            .retirement = retirement,
            .source_1 = source_1,
            .source_2 = source_2,
            .msl_range = msl_range.effect,
            .positive_difference = positive_difference.effect,
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
    return .{
        try arena.input(prefix ++ "_0", .byte, span),
        try arena.input(prefix ++ "_1", .byte, span),
        try arena.input(prefix ++ "_2", .byte, span),
        try arena.input(prefix ++ "_3", .byte, span),
    };
}

fn hexDigest(comptime value: []const u8, comptime message: []const u8) digest.Digest {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}
