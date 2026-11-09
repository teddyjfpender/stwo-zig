//! Native typed AIR authorship for compatibility-exact RV32 high-word multiply.
//!
//! `MULH`, `MULHSU`, and `MULHU` share one 47-column component. The typed
//! definition preserves all twenty-four direct roots and twenty-two ordered
//! effects from production. Eight schoolbook carries and both sign witnesses
//! are closed by proof-owned fixed-table refinements without adding trace
//! columns or hot-path work.

const std = @import("std");
const constraints_mod = @import("typed_mulh_constraints.zig");
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

pub const MAIN_COLUMN_COUNT: usize = 47;
pub const DIRECT_CONSTRAINT_COUNT: usize = constraints_mod.DIRECT_CONSTRAINT_COUNT;
pub const LOOKUP_COUNT: usize = 22;
pub const LOOKUP_BATCH_SIZE: u8 = 1;
pub const RANGE_REFINEMENT_COUNT: usize = 10;
pub const FIXED_TABLE_REQUEST_COUNT: usize = 10;
pub const MULH_OPCODE_ID: u32 = 38;
pub const MULHSU_OPCODE_ID: u32 = 39;
pub const MULHU_OPCODE_ID: u32 = 40;

pub const SEMANTIC_DIGEST_HEX =
    "00d717cfbaa5ba3f82604ce9fdedd1e3f4de1ede56d3fe09ddd835d3118c0e7b";
pub const SEMANTIC_DIGEST: digest.Digest = hexDigest(
    SEMANTIC_DIGEST_HEX,
    "invalid typed MULH semantic digest",
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
    low_product: [4]types.ValueId,
    rs1_sign: types.ValueId,
    rs2_sign: types.ValueId,
    is_mulh: types.ValueId,
    is_mulhsu: types.ValueId,
    is_mulhu: types.ValueId,
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
            self.low_product[0],
            self.low_product[1],
            self.low_product[2],
            self.low_product[3],
            self.rs1_sign,
            self.rs2_sign,
            self.is_mulh,
            self.is_mulhsu,
            self.is_mulhu,
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
    product_ranges: [8]types.EffectId,
    sign_ranges: [2]types.EffectId,
    destination: effects.RegisterAccessGroup,
};

pub const EventSpec = struct {
    kind: program.EffectKind,
    domain: relation.Domain,
    role: relation.Role,
    arity: u8,
    ordinal: ?u8 = null,
};

pub const EVENT_SPECS = [LOOKUP_COUNT]EventSpec{
    .{ .kind = .program_fetch, .domain = .program_access, .role = .request, .arity = 5 },
    .{ .kind = .state_consume, .domain = .registers_state, .role = .consume, .arity = 2 },
    .{ .kind = .state_produce, .domain = .registers_state, .role = .emit, .arity = 2 },
    .{ .kind = .register_read, .domain = .memory_access, .role = .consume, .arity = 7, .ordinal = 1 },
    .{ .kind = .register_read, .domain = .memory_access, .role = .emit, .arity = 7, .ordinal = 1 },
    .{ .kind = .register_read, .domain = .range_check_20, .role = .request, .arity = 1, .ordinal = 1 },
    .{ .kind = .register_read, .domain = .memory_access, .role = .consume, .arity = 7, .ordinal = 2 },
    .{ .kind = .register_read, .domain = .memory_access, .role = .emit, .arity = 7, .ordinal = 2 },
    .{ .kind = .register_read, .domain = .range_check_20, .role = .request, .arity = 1, .ordinal = 2 },
    .{ .kind = .range_request, .domain = .range_check_8_11, .role = .request, .arity = 2 },
    .{ .kind = .range_request, .domain = .range_check_8_11, .role = .request, .arity = 2 },
    .{ .kind = .range_request, .domain = .range_check_8_11, .role = .request, .arity = 2 },
    .{ .kind = .range_request, .domain = .range_check_8_11, .role = .request, .arity = 2 },
    .{ .kind = .range_request, .domain = .range_check_8_11, .role = .request, .arity = 2 },
    .{ .kind = .range_request, .domain = .range_check_8_11, .role = .request, .arity = 2 },
    .{ .kind = .range_request, .domain = .range_check_8_11, .role = .request, .arity = 2 },
    .{ .kind = .range_request, .domain = .range_check_8_11, .role = .request, .arity = 2 },
    .{ .kind = .range_request, .domain = .range_check_m31, .role = .request, .arity = 2 },
    .{ .kind = .range_request, .domain = .range_check_m31, .role = .request, .arity = 2 },
    .{ .kind = .register_write, .domain = .memory_access, .role = .consume, .arity = 7, .ordinal = 3 },
    .{ .kind = .register_write, .domain = .memory_access, .role = .emit, .arity = 7, .ordinal = 3 },
    .{ .kind = .register_write, .domain = .range_check_20, .role = .request, .arity = 1, .ordinal = 3 },
};

pub const ValidationError = validate_mod.Error || relation.Error || error{
    InvalidMulhDefinition,
};

pub const Definition = struct {
    arena: ir.Arena,
    columns: Columns,
    is_active: types.ValueId,
    active: types.ValueId,
    signed_rs1: types.ValueId,
    model: constraints_mod.Result,
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
            return error.InvalidMulhDefinition;
        }
        for (self.columns.physical(), 0..) |value, index| {
            if (types.idIndex(value) != index) return error.InvalidMulhDefinition;
        }
        if (types.idIndex(self.is_active) != MAIN_COLUMN_COUNT)
            return error.InvalidMulhDefinition;
        if (self.active != self.model.active or
            self.signed_rs1 != self.model.signed_rs1)
        {
            return error.InvalidMulhDefinition;
        }
        var input_count: usize = 0;
        for (self.arena.nodesView()) |node| switch (node.key.op) {
            .input => input_count += 1,
            else => {},
        };
        if (input_count != MAIN_COLUMN_COUNT + 1)
            return error.InvalidMulhDefinition;

        for (self.model.constraints, self.model.roots, 0..) |id, root, index| {
            if (types.idIndex(id) != index) return error.InvalidMulhDefinition;
            const constraint = self.arena.constraint(id) orelse
                return error.InvalidMulhDefinition;
            if (constraint.root != root or constraint.gate != null or
                constraint.category != .semantic)
            {
                return error.InvalidMulhDefinition;
            }
            var name_buffer: [64]u8 = undefined;
            const expected = std.fmt.bufPrint(
                &name_buffer,
                "compat.riscv.mulh.direct.{d}",
                .{index},
            ) catch return error.InvalidMulhDefinition;
            const actual = self.arena.name(constraint.name) orelse
                return error.InvalidMulhDefinition;
            if (!std.mem.eql(u8, expected, actual))
                return error.InvalidMulhDefinition;
        }

        const ordered = self.orderedEventIds();
        for (EVENT_SPECS, ordered, 0..) |spec, id, index| {
            if (types.idIndex(id) != index) return error.InvalidMulhDefinition;
            const effect = self.arena.effect(id) orelse
                return error.InvalidMulhDefinition;
            const binding = effect.binding orelse
                return error.InvalidMulhDefinition;
            const values = self.arena.effectValues(id) orelse
                return error.InvalidMulhDefinition;
            const schema = relation.get(spec.domain);
            const expected_liveness = switch (index) {
                17 => self.signed_rs1,
                18 => self.columns.is_mulh,
                else => self.active,
            };
            if (effect.kind != spec.kind or binding.schema != schema.id or
                binding.schema_version != schema.version or
                binding.role != spec.role or values.len != spec.arity or
                effect.access_ordinal != spec.ordinal or
                effect.liveness != expected_liveness)
            {
                return error.InvalidMulhDefinition;
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
            return error.InvalidMulhDefinition;
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
            self.events.product_ranges[0],
            self.events.product_ranges[1],
            self.events.product_ranges[2],
            self.events.product_ranges[3],
            self.events.product_ranges[4],
            self.events.product_ranges[5],
            self.events.product_ranges[6],
            self.events.product_ranges[7],
            self.events.sign_ranges[0],
            self.events.sign_ranges[1],
            self.events.destination.consume,
            self.events.destination.emit,
            self.events.destination.clock_gap,
        };
    }
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
        .low_product = try byteInputs(&arena, "rd_high", span),
        .rs1_sign = try arena.input("rs1_sign", .bit, span),
        .rs2_sign = try arena.input("rs2_sign", .bit, span),
        .is_mulh = try arena.input("opcode_mulh_flag", .bit, span),
        .is_mulhsu = try arena.input("opcode_mulhsu_flag", .bit, span),
        .is_mulhu = try arena.input("opcode_mulhu_flag", .bit, span),
        .result = try byteInputs(&arena, "result", span),
        .destination_nonzero = try arena.input("rd_nonzero", .bit, span),
        .destination_inverse = try arena.input("rd_inv", .felt, span),
    };
    const is_active = try arena.input("is_active", .selector, span);
    const model = try constraints_mod.author(&arena, columns, is_active, span);
    const active = model.active;
    const signed_rs1 = model.signed_rs1;

    const program_fetch = try effects.programFetch(&arena, .{
        .pc = columns.pc,
        .opcode_id = model.opcode,
        .rd = columns.rd.addr,
        .rs1 = columns.rs1.addr,
        .operand = columns.rs2.addr,
    }, active, span);
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
    const source_1 = try schedule.registerReadTransition(.{
        .index = columns.rs1.addr,
        .previous_clock = columns.rs1.previous_clock,
        .previous = columns.rs1.previous,
        .next = columns.rs1.next,
    }, span);
    const source_2 = try schedule.registerReadTransition(.{
        .index = columns.rs2.addr,
        .previous_clock = columns.rs2.previous_clock,
        .previous = columns.rs2.previous,
        .next = columns.rs2.next,
    }, span);

    var product_ranges: [8]types.EffectId = undefined;
    inline for (&product_ranges, 0..) |*effect, limb| {
        const product_byte = if (limb < 4)
            columns.low_product[limb]
        else
            columns.result[limb - 4];
        effect.* = (try range_refinement.rangeCheck811(
            &arena,
            product_byte,
            model.carries[limb],
            active,
            span,
        )).effect;
    }

    const zero_byte = try arena.constantUnsigned(.byte, 0, span);
    const c128 = try arena.constantField(128, span);
    const rs1_high = try arena.sub(
        columns.rs1.next[3],
        try arena.mul(columns.rs1_sign, c128, span),
        span,
    );
    const rs2_high = try arena.sub(
        columns.rs2.next[3],
        try arena.mul(columns.rs2_sign, c128, span),
        span,
    );
    const sign_ranges = [2]types.EffectId{
        (try range_refinement.rangeCheckM31(
            &arena,
            zero_byte,
            rs1_high,
            signed_rs1,
            span,
        )).effect,
        (try range_refinement.rangeCheckM31(
            &arena,
            zero_byte,
            rs2_high,
            columns.is_mulh,
            span,
        )).effect,
    };
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
        .signed_rs1 = signed_rs1,
        .model = model,
        .events = .{
            .program_fetch = program_fetch,
            .retirement = retirement,
            .source_1 = source_1,
            .source_2 = source_2,
            .product_ranges = product_ranges,
            .sign_ranges = sign_ranges,
            .destination = destination,
        },
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
