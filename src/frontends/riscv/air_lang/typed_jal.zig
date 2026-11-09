//! Native typed AIR authorship for compatibility-exact RV32 JAL.
//!
//! This definition independently owns all twenty physical columns, ten direct
//! roots, and eight ordered relation effects. Its jump target is a zero-AIR,
//! program-authenticated control refinement: no committed target column,
//! additional constraint, or witness operation is introduced.

const std = @import("std");
const constraints_mod = @import("typed_jal_constraints.zig");
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

pub const MAIN_COLUMN_COUNT: usize = 20;
pub const DIRECT_CONSTRAINT_COUNT = constraints_mod.DIRECT_CONSTRAINT_COUNT;
pub const LOOKUP_COUNT: usize = 8;
pub const LOOKUP_BATCH_SIZE: usize = 2;
pub const RANGE_REFINEMENT_COUNT: usize = 1;
pub const FIXED_TABLE_REQUEST_COUNT: usize = 2;
pub const OPCODE_ID: u32 = 33;

pub const SEMANTIC_DIGEST_HEX =
    "0677d8ecf741d37f938ae0f77e647e782952fbec11a8f07702e62d6980735dc5";
pub const SEMANTIC_DIGEST: digest.Digest = hexDigest(
    SEMANTIC_DIGEST_HEX,
    "invalid typed JAL semantic digest",
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
        };
    }
};

pub const Events = struct {
    program_fetch: types.EffectId,
    retirement: instruction_effects.SequentialRetirement,
    result_middle: types.EffectId,
    result_outer: types.EffectId,
    destination: effects.RegisterAccessGroup,
};

pub const ValidationError = validate_mod.Error || relation.Error || error{
    InvalidJalDefinition,
};

pub const Definition = struct {
    arena: ir.Arena,
    columns: Columns,
    is_active: types.ValueId,
    pc_polynomial: types.ValueId,
    model: constraints_mod.Result,
    target_pc: types.ValueId,
    events: Events,

    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const Definition) ValidationError!void {
        try validate_mod.validate(&self.arena);
        const identity = try digest.computeIdentity(&self.arena);
        if (identity.format_version != digest.program_control_target_format_version or
            !std.mem.eql(u8, &identity.bytes, &SEMANTIC_DIGEST) or
            self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or
            self.arena.effectsView().len != LOOKUP_COUNT or
            self.arena.range_refinements.items.len != RANGE_REFINEMENT_COUNT or
            self.arena.fixed_table_requests.items.len != FIXED_TABLE_REQUEST_COUNT)
        {
            return error.InvalidJalDefinition;
        }

        for (self.columns.physical(), 0..) |value, index| {
            if (types.idIndex(value) != index) return error.InvalidJalDefinition;
        }
        if (types.idIndex(self.is_active) != MAIN_COLUMN_COUNT or
            types.idIndex(self.pc_polynomial) != MAIN_COLUMN_COUNT + 1)
        {
            return error.InvalidJalDefinition;
        }
        var input_count: usize = 0;
        for (self.arena.nodesView()) |node| switch (node.key.op) {
            .input => input_count += 1,
            else => {},
        };
        if (input_count != MAIN_COLUMN_COUNT + 2)
            return error.InvalidJalDefinition;

        for (self.model.constraints, self.model.roots, 0..) |id, root, index| {
            if (types.idIndex(id) != index) return error.InvalidJalDefinition;
            const constraint = self.arena.constraint(id) orelse
                return error.InvalidJalDefinition;
            if (constraint.root != root or constraint.gate != null or
                constraint.category != .semantic)
            {
                return error.InvalidJalDefinition;
            }
            var name_buffer: [64]u8 = undefined;
            const expected = std.fmt.bufPrint(
                &name_buffer,
                "compat.riscv.jal.direct.{d}",
                .{index},
            ) catch return error.InvalidJalDefinition;
            const actual = self.arena.name(constraint.name) orelse
                return error.InvalidJalDefinition;
            if (!std.mem.eql(u8, expected, actual))
                return error.InvalidJalDefinition;
        }

        const expected_ids = self.orderedEventIds();
        for (self.arena.effectsView(), expected_shapes, expected_ids, 0..) |
            effect,
            shape,
            id,
            index,
        | {
            if (types.idIndex(id) != index) return error.InvalidJalDefinition;
            const binding = effect.binding orelse return error.InvalidJalDefinition;
            const values = self.arena.effectValues(id) orelse
                return error.InvalidJalDefinition;
            if (effect.kind != shape.kind or
                binding.schema != relation.id(shape.domain) or
                binding.role != shape.role or values.len != shape.arity or
                effect.access_ordinal != shape.ordinal or
                effect.liveness != self.columns.enabler)
            {
                return error.InvalidJalDefinition;
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
            return error.InvalidJalDefinition;
        }
        const program_values = self.arena.effectValues(self.events.program_fetch) orelse
            return error.InvalidJalDefinition;
        const zero = program_values[4];
        if (!std.mem.eql(types.ValueId, program_values, &.{
            self.columns.pc,
            self.model.opcode,
            self.columns.rd.addr,
            self.columns.imm_felt,
            zero,
        }) or !isConstant(&self.arena, zero, 0)) return error.InvalidJalDefinition;
        const proof = self.arena.range_refinements.items[0];
        if (proof.target != self.target_pc) return error.InvalidJalDefinition;
        switch (proof.premise) {
            .program_control_target => |control| {
                if (control.program_effect != self.events.program_fetch or
                    control.current_pc != self.columns.pc or
                    control.offset != self.columns.imm_felt or
                    control.liveness != self.columns.enabler)
                {
                    return error.InvalidJalDefinition;
                }
                switch (control.kind) {
                    .jump => {},
                    else => return error.InvalidJalDefinition,
                }
            },
            else => return error.InvalidJalDefinition,
        }
        if (self.events.retirement.after.pc != self.target_pc)
            return error.InvalidJalDefinition;
    }

    pub fn orderedEventIds(self: *const Definition) [LOOKUP_COUNT]types.EffectId {
        return .{
            self.events.program_fetch,
            self.events.retirement.events.consume,
            self.events.retirement.events.produce,
            self.events.result_middle,
            self.events.result_outer,
            self.events.destination.consume,
            self.events.destination.emit,
            self.events.destination.clock_gap,
        };
    }
};

const Shape = struct {
    kind: program.EffectKind,
    domain: relation.Domain,
    role: relation.Role,
    arity: u8,
    ordinal: ?u8 = null,
};

const expected_shapes = [LOOKUP_COUNT]Shape{
    .{ .kind = .program_fetch, .domain = .program_access, .role = .request, .arity = 5 },
    .{ .kind = .state_consume, .domain = .registers_state, .role = .consume, .arity = 2 },
    .{ .kind = .state_produce, .domain = .registers_state, .role = .emit, .arity = 2 },
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
    const columns = Columns{
        .enabler = try arena.input("enabler", .bit, span),
        .clock = try arena.input("clock", .clock, span),
        .pc = try arena.input("pc", .pc, span),
        .rd = try accessInputs(&arena, "rd", span),
        .imm_felt = try arena.input("imm_felt", .felt, span),
        .result = .{
            try arena.input("result_0", .byte, span),
            try arena.input("result_1", .byte, span),
            try arena.input("result_2", .byte, span),
            try arena.input("result_3", try types.Type.boundedField(7), span),
        },
        .destination_nonzero = try arena.input("rd_nonzero", .bit, span),
        .destination_inverse = try arena.input("rd_inv", .felt, span),
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
    const program_fetch = try effects.programFetch(&arena, .{
        .pc = columns.pc,
        .opcode_id = model.opcode,
        .rd = columns.rd.addr,
        .rs1 = columns.imm_felt,
        .operand = try arena.constantField(0, span),
    }, columns.enabler, span);
    const target_pc = try range_refinement.programControlTarget(
        &arena,
        program_fetch,
        columns.pc,
        columns.imm_felt,
        .jump,
        columns.enabler,
        span,
    );
    const after = effects.MachineState{
        .pc = target_pc,
        .clock = try arena.instructionNextClock(columns.clock, span),
    };
    const retirement = instruction_effects.SequentialRetirement{
        .events = try effects.retire(
            &arena,
            .{ .pc = columns.pc, .clock = columns.clock },
            after,
            columns.enabler,
            span,
        ),
        .after = after,
    };
    const result_middle = try range_refinement.rangeCheck88Typed(
        &arena,
        columns.result[1],
        columns.result[2],
        columns.enabler,
        span,
    );
    const result_outer = try range_refinement.rangeCheckM31Typed(
        &arena,
        columns.result[0],
        columns.result[3],
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
        .index = columns.rd.addr,
        .previous_clock = columns.rd.previous_clock,
        .previous = columns.rd.previous,
        .next = columns.rd.next,
    }, span);
    return .{
        .arena = arena,
        .columns = columns,
        .is_active = is_active,
        .pc_polynomial = pc_polynomial,
        .model = model,
        .target_pc = target_pc,
        .events = .{
            .program_fetch = program_fetch,
            .retirement = retirement,
            .result_middle = result_middle.effect,
            .result_outer = result_outer.effect,
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

fn isConstant(arena: *const ir.Arena, value: types.ValueId, expected: u32) bool {
    return switch ((arena.node(value) orelse return false).key.op) {
        .constant => |constant| switch (constant) {
            .field, .unsigned => |number| number == expected,
        },
        else => false,
    };
}

fn hexDigest(comptime value: []const u8, comptime message: []const u8) digest.Digest {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}
