//! Native typed AIR authorship for compatibility-exact RV32 AUIPC.
//!
//! This definition independently owns all physical columns, direct roots, and
//! ordered relation effects. Its authenticated witness recipe may become the
//! production row authority without routing the hot path through the legacy
//! handwritten writer.

const std = @import("std");
const constraints_mod = @import("typed_auipc_constraints.zig");
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

pub const MAIN_COLUMN_COUNT: usize = 29;
pub const DIRECT_CONSTRAINT_COUNT = constraints_mod.DIRECT_CONSTRAINT_COUNT;
pub const LOOKUP_COUNT: usize = 12;
pub const RANGE_REFINEMENT_COUNT: usize = 1;
pub const FIXED_TABLE_REQUEST_COUNT: usize = 4;
pub const OPCODE_ID: u32 = 36;

pub const SEMANTIC_DIGEST_HEX =
    "b65eb0279c680db06f9fe36f4bbf3db1f1c99d913afb5e0a0e00e3a1b0f9abfe";
pub const SEMANTIC_DIGEST: digest.Digest = hexDigest(
    SEMANTIC_DIGEST_HEX,
    "invalid typed AUIPC semantic digest",
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
    imm_felt: types.ValueId,
    result: [4]types.ValueId,
    destination_nonzero: types.ValueId,
    destination_inverse: types.ValueId,
    pc_limbs: [4]types.ValueId,
    imm_limbs: [4]types.ValueId,
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
            self.imm_felt,
            self.result[0],
            self.result[1],
            self.result[2],
            self.result[3],
            self.destination_nonzero,
            self.destination_inverse,
            self.pc_limbs[0],
            self.pc_limbs[1],
            self.pc_limbs[2],
            self.pc_limbs[3],
            self.imm_limbs[0],
            self.imm_limbs[1],
            self.imm_limbs[2],
            self.imm_limbs[3],
            self.imm_sign,
        };
    }
};

pub const Events = struct {
    program_fetch: types.EffectId,
    retirement: instruction_effects.SequentialRetirement,
    result_ranges: [2]types.EffectId,
    pc_middle: types.EffectId,
    pc_outer: types.EffectId,
    immediate_middle: types.EffectId,
    immediate_outer: types.EffectId,
    destination: effects.RegisterAccessGroup,
};

pub const ValidationError = validate_mod.Error || relation.Error || error{
    InvalidAuipcDefinition,
};

pub const Definition = struct {
    arena: ir.Arena,
    columns: Columns,
    is_active: types.ValueId,
    pc_polynomial: types.ValueId,
    model: constraints_mod.Result,
    immediate_outer_high: types.ValueId,
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
            return error.InvalidAuipcDefinition;
        }

        for (self.columns.physical(), 0..) |value, index| {
            if (types.idIndex(value) != index) return error.InvalidAuipcDefinition;
        }
        if (types.idIndex(self.is_active) != MAIN_COLUMN_COUNT or
            types.idIndex(self.pc_polynomial) != MAIN_COLUMN_COUNT + 1)
        {
            return error.InvalidAuipcDefinition;
        }
        var input_count: usize = 0;
        for (self.arena.nodesView()) |node| switch (node.key.op) {
            .input => input_count += 1,
            else => {},
        };
        if (input_count != MAIN_COLUMN_COUNT + 2)
            return error.InvalidAuipcDefinition;

        for (self.model.constraints, self.model.roots, 0..) |id, root, index| {
            if (types.idIndex(id) != index) return error.InvalidAuipcDefinition;
            const constraint = self.arena.constraint(id) orelse
                return error.InvalidAuipcDefinition;
            if (constraint.root != root or constraint.gate != null or
                constraint.category != .semantic)
            {
                return error.InvalidAuipcDefinition;
            }
            var name_buffer: [64]u8 = undefined;
            const expected = std.fmt.bufPrint(
                &name_buffer,
                "compat.riscv.auipc.direct.{d}",
                .{index},
            ) catch return error.InvalidAuipcDefinition;
            const actual = self.arena.name(constraint.name) orelse
                return error.InvalidAuipcDefinition;
            if (!std.mem.eql(u8, expected, actual))
                return error.InvalidAuipcDefinition;
        }

        const expected_ids = self.orderedEventIds();
        for (self.arena.effectsView(), expected_lookup_shapes, expected_ids, 0..) |
            effect,
            shape,
            id,
            index,
        | {
            if (types.idIndex(id) != index) return error.InvalidAuipcDefinition;
            const binding = effect.binding orelse return error.InvalidAuipcDefinition;
            const values = self.arena.effectValues(id) orelse
                return error.InvalidAuipcDefinition;
            if (effect.kind != shape.kind or
                binding.schema != relation.id(shape.domain) or
                binding.role != shape.role or
                values.len != shape.arity or
                effect.access_ordinal != shape.ordinal or
                effect.liveness != self.columns.enabler)
            {
                return error.InvalidAuipcDefinition;
            }
            _ = try relation.validateEventShape(
                binding.schema,
                binding.role,
                values.len,
                effect.access_ordinal,
            );
        }
        if (self.events.destination.ordinal != .first or
            self.events.destination.phase != .first)
        {
            return error.InvalidAuipcDefinition;
        }
    }

    pub fn orderedEventIds(self: *const Definition) [LOOKUP_COUNT]types.EffectId {
        return .{
            self.events.program_fetch,
            self.events.retirement.events.consume,
            self.events.retirement.events.produce,
            self.events.result_ranges[0],
            self.events.result_ranges[1],
            self.events.pc_middle,
            self.events.pc_outer,
            self.events.immediate_middle,
            self.events.immediate_outer,
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
    .{ .kind = .range_request, .domain = .range_check_8_8, .role = .request, .arity = 2 },
    .{ .kind = .range_request, .domain = .range_check_8_8, .role = .request, .arity = 2 },
    .{ .kind = .range_request, .domain = .range_check_8_8, .role = .request, .arity = 2 },
    .{ .kind = .range_request, .domain = .range_check_m31, .role = .request, .arity = 2 },
    .{ .kind = .range_request, .domain = .range_check_8_8, .role = .request, .arity = 2 },
    .{ .kind = .range_request, .domain = .range_check_m31, .role = .request, .arity = 2 },
    .{ .kind = .register_write, .domain = .memory_access, .role = .consume, .arity = 7, .ordinal = 1 },
    .{ .kind = .register_write, .domain = .memory_access, .role = .emit, .arity = 7, .ordinal = 1 },
    .{ .kind = .register_write, .domain = .range_check_20, .role = .request, .arity = 1, .ordinal = 1 },
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
        .imm_felt = try arena.input("imm_felt", .felt, span),
        .result = try byteInputs(&arena, "result", span),
        .destination_nonzero = try arena.input("rd_nonzero", .bit, span),
        .destination_inverse = try arena.input("rd_inv", .felt, span),
        .pc_limbs = .{
            try arena.input("pc_limb_0", .byte, span),
            try arena.input("pc_limb_1", .byte, span),
            try arena.input("pc_limb_2", .byte, span),
            try arena.input("pc_limb_3", uint7, span),
        },
        .imm_limbs = try byteInputs(&arena, "imm_limb", span),
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
        .immediate_outer_high = authored.immediate_outer_high,
        .events = authored.events,
    };
}

const AuthoredEffects = struct {
    immediate_outer_high: types.ValueId,
    events: Events,
};

fn authorEffects(
    arena: *ir.Arena,
    c: Columns,
    model: constraints_mod.Result,
    span: source.SourceSpan,
) !AuthoredEffects {
    const c128 = try arena.constantField(128, span);
    const program_fetch = try effects.programFetch(arena, .{
        .pc = c.pc,
        .opcode_id = model.opcode,
        .rd = c.rd.addr,
        .rs1 = c.imm_felt,
        .operand = try arena.constantField(0, span),
    }, c.enabler, span);
    const retirement = try instruction_effects.retireSequential(
        arena,
        .{ .pc = c.pc, .clock = c.clock },
        c.enabler,
        span,
    );
    const result_ranges = try instruction_effects.rangeCheck88Pairs(arena, .{
        .{ .first_byte = c.result[0], .second_byte = c.result[1] },
        .{ .first_byte = c.result[2], .second_byte = c.result[3] },
    }, c.enabler, span);
    const pc_middle = try range_refinement.rangeCheck88Typed(
        arena,
        c.pc_limbs[1],
        c.pc_limbs[2],
        c.enabler,
        span,
    );
    const pc_outer = try range_refinement.rangeCheckM31Typed(
        arena,
        c.pc_limbs[0],
        c.pc_limbs[3],
        c.enabler,
        span,
    );
    const immediate_middle = try range_refinement.rangeCheck88Typed(
        arena,
        c.imm_limbs[1],
        c.imm_limbs[2],
        c.enabler,
        span,
    );
    const immediate_outer_high = try arena.sub(
        c.imm_limbs[3],
        try arena.mul(c.imm_sign, c128, span),
        span,
    );
    const immediate_outer = try range_refinement.rangeCheckM31(
        arena,
        c.imm_limbs[0],
        immediate_outer_high,
        c.enabler,
        span,
    );
    var schedule = try effects.AccessSchedule.begin(arena, c.clock, c.enabler, span);
    const destination = try schedule.registerWrite(.{
        .index = c.rd.addr,
        .previous_clock = c.rd.previous_clock,
        .previous = c.rd.previous,
        .next = c.rd.next,
    }, span);
    return .{
        .immediate_outer_high = immediate_outer.values[1],
        .events = .{
            .program_fetch = program_fetch,
            .retirement = retirement,
            .result_ranges = result_ranges,
            .pc_middle = pc_middle.effect,
            .pc_outer = pc_outer.effect,
            .immediate_middle = immediate_middle.effect,
            .immediate_outer = immediate_outer.effect,
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
