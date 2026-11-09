//! Native typed AIR authorship for RV32 BLT/BLTU/BGE/BGEU.
//!
//! The committed branch target remains a physical trace column. A closed,
//! program-authenticated control proof binds that column to the exact selected
//! target without adding AIR roots, witness columns, or relation events.

const std = @import("std");
const constraints_mod = @import("typed_branch_lt_constraints.zig");
const digest = @import("digest.zig");
const effects = @import("effects.zig");
const ir = @import("ir.zig");
const program = @import("program.zig");
const range_refinement = @import("range_refinement.zig");
const relation = @import("relation.zig");
const source = @import("source.zig");
const types = @import("types.zig");
const validate_mod = @import("validate.zig");

pub const MAIN_COLUMN_COUNT: usize = 37;
pub const SEMANTIC_CONSTRAINT_COUNT = constraints_mod.SEMANTIC_CONSTRAINT_COUNT;
pub const DIRECT_CONSTRAINT_COUNT = constraints_mod.DIRECT_CONSTRAINT_COUNT;
pub const LOOKUP_COUNT: usize = 11;
pub const LOOKUP_BATCH_SIZE: usize = 2;
pub const RANGE_REFINEMENT_COUNT: usize = 5;
pub const FIXED_TABLE_REQUEST_COUNT: usize = 2;
pub const COMMITTED_PROGRAM_CONTROL_TARGET_COUNT: usize = 1;
pub const BLT_OPCODE_ID: u32 = 29;
pub const BGE_OPCODE_ID: u32 = 30;
pub const BLTU_OPCODE_ID: u32 = 31;
pub const BGEU_OPCODE_ID: u32 = 32;

pub const SEMANTIC_DIGEST_HEX =
    "262eae1d57530034e41143c0c5961e3c7826d0e5c3af69a0b656ede2d0eeeded";
pub const SEMANTIC_DIGEST: digest.Digest = hexDigest(
    SEMANTIC_DIGEST_HEX,
    "invalid typed BRANCH_LT semantic digest",
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
    rs1: AccessColumns,
    rs2: AccessColumns,
    rs1_msl_felt: types.ValueId,
    rs2_msl_felt: types.ValueId,
    imm_felt: types.ValueId,
    cmp_result: types.ValueId,
    cmp_lt: types.ValueId,
    diff_markers: [4]types.ValueId,
    diff_val: types.ValueId,
    branch_target: types.ValueId,
    is_blt: types.ValueId,
    is_bltu: types.ValueId,
    is_bge: types.ValueId,
    is_bgeu: types.ValueId,

    pub fn physical(self: Columns) [MAIN_COLUMN_COUNT]types.ValueId {
        return .{
            self.clock,
            self.pc,
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
            self.rs1_msl_felt,
            self.rs2_msl_felt,
            self.imm_felt,
            self.cmp_result,
            self.cmp_lt,
            self.diff_markers[0],
            self.diff_markers[1],
            self.diff_markers[2],
            self.diff_markers[3],
            self.diff_val,
            self.branch_target,
            self.is_blt,
            self.is_bltu,
            self.is_bge,
            self.is_bgeu,
        };
    }
};

pub const Events = struct {
    program_fetch: types.EffectId,
    retirement: effects.Retirement,
    source_1: effects.RegisterAccessGroup,
    source_2: effects.RegisterAccessGroup,
    msl_range: types.EffectId,
    positive_difference: types.EffectId,
};

pub const ValidationError = validate_mod.Error || relation.Error || error{
    InvalidBranchLtDefinition,
};

pub const Definition = struct {
    arena: ir.Arena,
    columns: Columns,
    is_active: types.ValueId,
    pc_polynomial: types.ValueId,
    branch_target_polynomial: types.ValueId,
    model: constraints_mod.Result,
    target_pc: types.ValueId,
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
        if (identity.format_version !=
            digest.committed_program_control_target_format_version or
            !std.mem.eql(u8, &identity.bytes, &SEMANTIC_DIGEST) or
            self.arena.constraintsView().len != DIRECT_CONSTRAINT_COUNT or
            self.arena.effectsView().len != LOOKUP_COUNT or
            self.arena.range_refinements.items.len != RANGE_REFINEMENT_COUNT or
            self.arena.fixed_table_requests.items.len != FIXED_TABLE_REQUEST_COUNT or
            self.arena.committed_program_control_targets.items.len !=
                COMMITTED_PROGRAM_CONTROL_TARGET_COUNT)
        {
            return error.InvalidBranchLtDefinition;
        }
        for (self.columns.physical(), 0..) |value, index| {
            if (types.idIndex(value) != index)
                return error.InvalidBranchLtDefinition;
        }
        if (types.idIndex(self.is_active) != MAIN_COLUMN_COUNT or
            types.idIndex(self.pc_polynomial) != MAIN_COLUMN_COUNT + 1 or
            types.idIndex(self.branch_target_polynomial) != MAIN_COLUMN_COUNT + 2)
        {
            return error.InvalidBranchLtDefinition;
        }
        var input_count: usize = 0;
        for (self.arena.nodesView()) |node| switch (node.key.op) {
            .input => input_count += 1,
            else => {},
        };
        if (input_count != MAIN_COLUMN_COUNT + 3)
            return error.InvalidBranchLtDefinition;

        const target_proof = self.arena.committed_program_control_targets.items[0];
        if (target_proof.program_effect != self.events.program_fetch or
            target_proof.current_pc != self.columns.pc or
            target_proof.current_pc_polynomial != self.pc_polynomial or
            target_proof.offset != self.columns.imm_felt or
            target_proof.condition != self.columns.cmp_result or
            target_proof.condition_constraint != self.model.constraints[5] or
            target_proof.committed_target != self.columns.branch_target or
            target_proof.committed_target_polynomial !=
                self.branch_target_polynomial or
            target_proof.target_constraint != self.model.constraints[10] or
            target_proof.liveness != self.model.active_selector)
        {
            return error.InvalidBranchLtDefinition;
        }

        for (self.model.constraints, self.model.roots, 0..) |id, root, index| {
            if (types.idIndex(id) != index)
                return error.InvalidBranchLtDefinition;
            const constraint = self.arena.constraint(id) orelse
                return error.InvalidBranchLtDefinition;
            if (constraint.root != root or constraint.gate != null or
                constraint.category != .semantic)
            {
                return error.InvalidBranchLtDefinition;
            }
            var name_buffer: [64]u8 = undefined;
            const expected = std.fmt.bufPrint(
                &name_buffer,
                "compat.riscv.branch_lt.direct.{d}",
                .{index},
            ) catch return error.InvalidBranchLtDefinition;
            const actual = self.arena.name(constraint.name) orelse
                return error.InvalidBranchLtDefinition;
            if (!std.mem.eql(u8, expected, actual))
                return error.InvalidBranchLtDefinition;
        }

        const expected_ids = self.orderedEventIds();
        for (self.arena.effectsView(), expected_shapes, expected_ids, 0..) |
            effect,
            shape,
            id,
            index,
        | {
            if (types.idIndex(id) != index)
                return error.InvalidBranchLtDefinition;
            const binding = effect.binding orelse
                return error.InvalidBranchLtDefinition;
            const values = self.arena.effectValues(id) orelse
                return error.InvalidBranchLtDefinition;
            const expected_liveness = if (index == 10)
                self.positive
            else
                self.model.active_selector;
            if (effect.kind != shape.kind or
                binding.schema != relation.id(shape.domain) or
                binding.role != shape.role or values.len != shape.arity or
                effect.access_ordinal != shape.ordinal or
                effect.liveness != expected_liveness)
            {
                return error.InvalidBranchLtDefinition;
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
            self.target_pc != self.columns.branch_target)
        {
            return error.InvalidBranchLtDefinition;
        }
        const program_values = self.arena.effectValues(self.events.program_fetch) orelse
            return error.InvalidBranchLtDefinition;
        if (!std.mem.eql(types.ValueId, program_values, &.{
            self.columns.pc,
            self.model.opcode,
            self.columns.rs1.addr,
            self.columns.rs2.addr,
            self.columns.imm_felt,
        })) return error.InvalidBranchLtDefinition;
        const state_after = self.arena.effectValues(self.events.retirement.produce) orelse
            return error.InvalidBranchLtDefinition;
        if (state_after[0] != self.columns.branch_target)
            return error.InvalidBranchLtDefinition;
    }

    pub fn orderedEventIds(self: *const Definition) [LOOKUP_COUNT]types.EffectId {
        return .{
            self.events.program_fetch,
            self.events.retirement.consume,
            self.events.retirement.produce,
            self.events.source_1.consume,
            self.events.source_1.emit,
            self.events.source_1.clock_gap,
            self.events.source_2.consume,
            self.events.source_2.emit,
            self.events.source_2.clock_gap,
            self.events.msl_range,
            self.events.positive_difference,
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
    .{ .kind = .register_read, .domain = .memory_access, .role = .consume, .arity = 7, .ordinal = 1 },
    .{ .kind = .register_read, .domain = .memory_access, .role = .emit, .arity = 7, .ordinal = 1 },
    .{ .kind = .register_read, .domain = .range_check_20, .role = .request, .arity = 1, .ordinal = 1 },
    .{ .kind = .register_read, .domain = .memory_access, .role = .consume, .arity = 7, .ordinal = 2 },
    .{ .kind = .register_read, .domain = .memory_access, .role = .emit, .arity = 7, .ordinal = 2 },
    .{ .kind = .register_read, .domain = .range_check_20, .role = .request, .arity = 1, .ordinal = 2 },
    .{ .kind = .range_request, .domain = .range_check_8_8, .role = .request, .arity = 2 },
    .{ .kind = .range_request, .domain = .range_check_20, .role = .request, .arity = 1 },
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
        .rs1 = try accessInputs(&arena, "rs1", span),
        .rs2 = try accessInputs(&arena, "rs2", span),
        .rs1_msl_felt = try arena.input("rs1_msl_felt", .felt, span),
        .rs2_msl_felt = try arena.input("rs2_msl_felt", .felt, span),
        .imm_felt = try arena.input("imm_felt", .felt, span),
        .cmp_result = try arena.input("cmp_result", .bit, span),
        .cmp_lt = try arena.input("cmp_lt", .bit, span),
        .diff_markers = .{
            try arena.input("diff_marker_0", .bit, span),
            try arena.input("diff_marker_1", .bit, span),
            try arena.input("diff_marker_2", .bit, span),
            try arena.input("diff_marker_3", .bit, span),
        },
        .diff_val = try arena.input("diff_val", .felt, span),
        .branch_target = try arena.input("branch_target", .pc, span),
        .is_blt = try arena.input("opcode_blt_flag", .bit, span),
        .is_bltu = try arena.input("opcode_bltu_flag", .bit, span),
        .is_bge = try arena.input("opcode_bge_flag", .bit, span),
        .is_bgeu = try arena.input("opcode_bgeu_flag", .bit, span),
    };
    const is_active = try arena.input("is_active", .selector, span);
    const pc_polynomial = try arena.input("pc_polynomial", .felt, span);
    const branch_target_polynomial = try arena.input(
        "branch_target_polynomial",
        .felt,
        span,
    );
    const model = try constraints_mod.author(
        &arena,
        columns,
        pc_polynomial,
        branch_target_polynomial,
        is_active,
        span,
    );
    const positive = try range_refinement.booleanFromConstraint(
        &arena,
        model.prefix_sum,
        model.constraints[21],
        span,
    );
    const program_fetch = try effects.programFetch(&arena, .{
        .pc = columns.pc,
        .opcode_id = model.opcode,
        .rd = columns.rs1.addr,
        .rs1 = columns.rs2.addr,
        .operand = columns.imm_felt,
    }, model.active_selector, span);
    const target_pc = try range_refinement.committedProgramControlTarget(
        &arena,
        program_fetch,
        columns.pc,
        pc_polynomial,
        columns.imm_felt,
        columns.cmp_result,
        model.constraints[5],
        columns.branch_target,
        branch_target_polynomial,
        model.constraints[10],
        model.active_selector,
        span,
    );
    const retirement = try effects.retire(
        &arena,
        .{ .pc = columns.pc, .clock = columns.clock },
        .{
            .pc = target_pc,
            .clock = try arena.instructionNextClock(columns.clock, span),
        },
        model.active_selector,
        span,
    );
    var schedule = try effects.AccessSchedule.begin(
        &arena,
        columns.clock,
        model.active_selector,
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
    const c128 = try arena.constantField(128, span);
    const rs1_msl_shifted = try arena.add(
        columns.rs1_msl_felt,
        try arena.mul(model.signed, c128, span),
        span,
    );
    const rs2_msl_shifted = try arena.add(
        columns.rs2_msl_felt,
        try arena.mul(model.signed, c128, span),
        span,
    );
    const msl_range = try range_refinement.rangeCheck88Refined(
        &arena,
        rs1_msl_shifted,
        rs2_msl_shifted,
        model.active_selector,
        span,
    );
    const positive_difference = try range_refinement.rangeCheck20(
        &arena,
        model.positive_difference,
        positive,
        span,
    );
    return .{
        .arena = arena,
        .columns = columns,
        .is_active = is_active,
        .pc_polynomial = pc_polynomial,
        .branch_target_polynomial = branch_target_polynomial,
        .model = model,
        .target_pc = target_pc,
        .positive = positive,
        .msl_range_values = .{
            msl_range.values[0],
            msl_range.values[1],
        },
        .positive_difference = positive_difference.values[0],
        .events = .{
            .program_fetch = program_fetch,
            .retirement = retirement,
            .source_1 = source_1,
            .source_2 = source_2,
            .msl_range = msl_range.effect,
            .positive_difference = positive_difference.effect,
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
