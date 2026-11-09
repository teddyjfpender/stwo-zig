//! Native typed AIR authorship for compatibility-exact RV32 BEQ/BNE.
//!
//! The selected next PC is a zero-AIR, program-authenticated control
//! refinement. No target column, extra direct root, or witness operation is
//! introduced beyond the shipped thirty-column layout.

const std = @import("std");
const constraints_mod = @import("typed_branch_eq_constraints.zig");
const digest = @import("digest.zig");
const effects = @import("effects.zig");
const ir = @import("ir.zig");
const program = @import("program.zig");
const range_refinement = @import("range_refinement.zig");
const relation = @import("relation.zig");
const source = @import("source.zig");
const types = @import("types.zig");
const validate_mod = @import("validate.zig");

pub const MAIN_COLUMN_COUNT: usize = 30;
pub const SEMANTIC_CONSTRAINT_COUNT = constraints_mod.SEMANTIC_CONSTRAINT_COUNT;
pub const DIRECT_CONSTRAINT_COUNT = constraints_mod.DIRECT_CONSTRAINT_COUNT;
pub const LOOKUP_COUNT: usize = 9;
pub const LOOKUP_BATCH_SIZE: usize = 2;
pub const RANGE_REFINEMENT_COUNT: usize = 2;
pub const FIXED_TABLE_REQUEST_COUNT: usize = 0;
pub const BEQ_OPCODE_ID: u32 = 27;
pub const BNE_OPCODE_ID: u32 = 28;

pub const SEMANTIC_DIGEST_HEX =
    "4b7ac248bf672d93a01cbd659e59a7a98f1ec81ab5b50dd29090ca8816e49b09";
pub const SEMANTIC_DIGEST: digest.Digest = hexDigest(
    SEMANTIC_DIGEST_HEX,
    "invalid typed BRANCH_EQ semantic digest",
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
    imm_felt: types.ValueId,
    cmp_result: types.ValueId,
    diff_inverse_markers: [4]types.ValueId,
    is_beq: types.ValueId,
    is_bne: types.ValueId,

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
            self.imm_felt,
            self.cmp_result,
            self.diff_inverse_markers[0],
            self.diff_inverse_markers[1],
            self.diff_inverse_markers[2],
            self.diff_inverse_markers[3],
            self.is_beq,
            self.is_bne,
        };
    }
};

pub const Events = struct {
    program_fetch: types.EffectId,
    retirement: effects.Retirement,
    source_1: effects.RegisterAccessGroup,
    source_2: effects.RegisterAccessGroup,
};

pub const ValidationError = validate_mod.Error || relation.Error || error{
    InvalidBranchEqDefinition,
};

pub const Definition = struct {
    arena: ir.Arena,
    columns: Columns,
    is_active: types.ValueId,
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
            self.arena.fixed_table_requests.items.len != FIXED_TABLE_REQUEST_COUNT or
            self.arena.committed_program_control_targets.items.len != 0)
        {
            return error.InvalidBranchEqDefinition;
        }
        for (self.columns.physical(), 0..) |value, index| {
            if (types.idIndex(value) != index)
                return error.InvalidBranchEqDefinition;
        }
        if (types.idIndex(self.is_active) != MAIN_COLUMN_COUNT)
            return error.InvalidBranchEqDefinition;
        var input_count: usize = 0;
        for (self.arena.nodesView()) |node| switch (node.key.op) {
            .input => input_count += 1,
            else => {},
        };
        if (input_count != MAIN_COLUMN_COUNT + 1)
            return error.InvalidBranchEqDefinition;

        for (self.model.constraints, self.model.roots, 0..) |id, root, index| {
            if (types.idIndex(id) != index)
                return error.InvalidBranchEqDefinition;
            const constraint = self.arena.constraint(id) orelse
                return error.InvalidBranchEqDefinition;
            if (constraint.root != root or constraint.gate != null or
                constraint.category != .semantic)
            {
                return error.InvalidBranchEqDefinition;
            }
            var name_buffer: [64]u8 = undefined;
            const expected = std.fmt.bufPrint(
                &name_buffer,
                "compat.riscv.branch_eq.direct.{d}",
                .{index},
            ) catch return error.InvalidBranchEqDefinition;
            const actual = self.arena.name(constraint.name) orelse
                return error.InvalidBranchEqDefinition;
            if (!std.mem.eql(u8, expected, actual))
                return error.InvalidBranchEqDefinition;
        }

        const expected_ids = self.orderedEventIds();
        for (self.arena.effectsView(), expected_shapes, expected_ids, 0..) |
            effect,
            shape,
            id,
            index,
        | {
            if (types.idIndex(id) != index)
                return error.InvalidBranchEqDefinition;
            const binding = effect.binding orelse
                return error.InvalidBranchEqDefinition;
            const values = self.arena.effectValues(id) orelse
                return error.InvalidBranchEqDefinition;
            if (effect.kind != shape.kind or
                binding.schema != relation.id(shape.domain) or
                binding.role != shape.role or values.len != shape.arity or
                effect.access_ordinal != shape.ordinal or
                effect.liveness != self.model.active_selector)
            {
                return error.InvalidBranchEqDefinition;
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
            self.events.source_2.phase != .second)
        {
            return error.InvalidBranchEqDefinition;
        }
        const program_values = self.arena.effectValues(self.events.program_fetch) orelse
            return error.InvalidBranchEqDefinition;
        if (!std.mem.eql(types.ValueId, program_values, &.{
            self.columns.pc,
            self.model.opcode,
            self.columns.rs1.addr,
            self.columns.rs2.addr,
            self.columns.imm_felt,
        })) return error.InvalidBranchEqDefinition;
        const control_refinement = self.arena.range_refinements.items[1];
        if (control_refinement.target != self.target_pc)
            return error.InvalidBranchEqDefinition;
        switch (control_refinement.premise) {
            .program_control_target => |control| {
                if (control.program_effect != self.events.program_fetch or
                    control.current_pc != self.columns.pc or
                    control.offset != self.columns.imm_felt or
                    control.liveness != self.model.active_selector)
                {
                    return error.InvalidBranchEqDefinition;
                }
                switch (control.kind) {
                    .branch => |branch| if (branch.condition != self.columns.cmp_result or
                        branch.condition_constraint != self.model.constraints[3])
                    {
                        return error.InvalidBranchEqDefinition;
                    },
                    else => return error.InvalidBranchEqDefinition,
                }
            },
            else => return error.InvalidBranchEqDefinition,
        }
        const state_after = self.arena.effectValues(self.events.retirement.produce) orelse
            return error.InvalidBranchEqDefinition;
        if (state_after[0] != self.target_pc)
            return error.InvalidBranchEqDefinition;
    }

    pub fn orderedEventIds(self: *const Definition) [LOOKUP_COUNT]types.EffectId {
        return .{
            self.events.program_fetch,
            self.events.source_1.consume,
            self.events.source_1.emit,
            self.events.source_1.clock_gap,
            self.events.source_2.consume,
            self.events.source_2.emit,
            self.events.source_2.clock_gap,
            self.events.retirement.consume,
            self.events.retirement.produce,
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
    .{ .kind = .register_read, .domain = .memory_access, .role = .consume, .arity = 7, .ordinal = 1 },
    .{ .kind = .register_read, .domain = .memory_access, .role = .emit, .arity = 7, .ordinal = 1 },
    .{ .kind = .register_read, .domain = .range_check_20, .role = .request, .arity = 1, .ordinal = 1 },
    .{ .kind = .register_read, .domain = .memory_access, .role = .consume, .arity = 7, .ordinal = 2 },
    .{ .kind = .register_read, .domain = .memory_access, .role = .emit, .arity = 7, .ordinal = 2 },
    .{ .kind = .register_read, .domain = .range_check_20, .role = .request, .arity = 1, .ordinal = 2 },
    .{ .kind = .state_consume, .domain = .registers_state, .role = .consume, .arity = 2 },
    .{ .kind = .state_produce, .domain = .registers_state, .role = .emit, .arity = 2 },
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
        .imm_felt = try arena.input("imm_felt", .felt, span),
        .cmp_result = try arena.input("cmp_result", .bit, span),
        .diff_inverse_markers = .{
            try arena.input("diff_inv_marker_0", .felt, span),
            try arena.input("diff_inv_marker_1", .felt, span),
            try arena.input("diff_inv_marker_2", .felt, span),
            try arena.input("diff_inv_marker_3", .felt, span),
        },
        .is_beq = try arena.input("opcode_beq_flag", .bit, span),
        .is_bne = try arena.input("opcode_bne_flag", .bit, span),
    };
    const is_active = try arena.input("is_active", .selector, span);
    const model = try constraints_mod.author(&arena, columns, is_active, span);
    const program_fetch = try effects.programFetch(&arena, .{
        .pc = columns.pc,
        .opcode_id = model.opcode,
        .rd = columns.rs1.addr,
        .rs1 = columns.rs2.addr,
        .operand = columns.imm_felt,
    }, model.active_selector, span);
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
    const target_pc = try range_refinement.programControlTarget(
        &arena,
        program_fetch,
        columns.pc,
        columns.imm_felt,
        .{ .branch = .{
            .condition = columns.cmp_result,
            .condition_constraint = model.constraints[3],
        } },
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
    return .{
        .arena = arena,
        .columns = columns,
        .is_active = is_active,
        .model = model,
        .target_pc = target_pc,
        .events = .{
            .program_fetch = program_fetch,
            .retirement = retirement,
            .source_1 = source_1,
            .source_2 = source_2,
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
