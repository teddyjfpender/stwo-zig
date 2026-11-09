//! Authenticated, allocation-free witness authority for RV32 compare branches.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const direct_witness_executor = @import("direct_witness_executor.zig");
const digest = @import("digest.zig");
const program = @import("program.zig");
const relation = @import("relation.zig");
const production_columns = @import("../trace_columns/compare.zig");
const trace_row = @import("../../runner/trace_row.zig");
const typed = @import("typed_branch_lt.zig");
const types = @import("types.zig");

pub const MAIN_COLUMN_COUNT: usize = typed.MAIN_COLUMN_COUNT;
pub const EVENT_COUNT: usize = typed.LOOKUP_COUNT;
pub const MAX_EVENT_ARITY: usize = 7;
pub const TraceRow = trace_row.TraceRow;

pub const WITNESS_BINDING_FORMAT_VERSION: u16 = 1;
pub const WITNESS_BINDING_DOMAIN_SEPARATOR =
    "stwo-zig/typed-air/branch-lt-witness-binding/v1";
pub const WITNESS_BINDING_DIGEST_HEX =
    "ececbcd217b91a87f7988f1741d1e7c3f390886ec4d47bfe9bc98d8fe3bbde4b";
pub const WITNESS_BINDING_DIGEST: digest.Digest = hexDigest(
    WITNESS_BINDING_DIGEST_HEX,
    "invalid typed BRANCH_LT witness-binding digest",
);

pub const RowSource = enum(u8) {
    trace_clock = 0,
    trace_pc = 1,
    trace_rs1_address = 2,
    trace_rs1_value_previous_byte_0 = 3,
    trace_rs1_value_previous_byte_1 = 4,
    trace_rs1_value_previous_byte_2 = 5,
    trace_rs1_value_previous_byte_3 = 6,
    trace_rs1_previous_clock = 7,
    trace_rs1_value_next_byte_0 = 8,
    trace_rs1_value_next_byte_1 = 9,
    trace_rs1_value_next_byte_2 = 10,
    trace_rs1_value_next_byte_3 = 11,
    trace_rs2_address = 12,
    trace_rs2_value_previous_byte_0 = 13,
    trace_rs2_value_previous_byte_1 = 14,
    trace_rs2_value_previous_byte_2 = 15,
    trace_rs2_value_previous_byte_3 = 16,
    trace_rs2_previous_clock = 17,
    trace_rs2_value_next_byte_0 = 18,
    trace_rs2_value_next_byte_1 = 19,
    trace_rs2_value_next_byte_2 = 20,
    trace_rs2_value_next_byte_3 = 21,
    derived_rs1_most_significant_limb = 22,
    derived_rs2_most_significant_limb = 23,
    trace_signed_immediate = 24,
    derived_branch_decision = 25,
    derived_comparison_less = 26,
    hint_first_difference_marker_0 = 27,
    hint_first_difference_marker_1 = 28,
    hint_first_difference_marker_2 = 29,
    hint_first_difference_marker_3 = 30,
    hint_positive_difference = 31,
    trace_branch_target = 32,
    derived_blt_flag = 33,
    derived_bltu_flag = 34,
    derived_bge_flag = 35,
    derived_bgeu_flag = 36,
};

pub const CANONICAL_RECIPE = [MAIN_COLUMN_COUNT]RowSource{
    .trace_clock,
    .trace_pc,
    .trace_rs1_address,
    .trace_rs1_value_previous_byte_0,
    .trace_rs1_value_previous_byte_1,
    .trace_rs1_value_previous_byte_2,
    .trace_rs1_value_previous_byte_3,
    .trace_rs1_previous_clock,
    .trace_rs1_value_next_byte_0,
    .trace_rs1_value_next_byte_1,
    .trace_rs1_value_next_byte_2,
    .trace_rs1_value_next_byte_3,
    .trace_rs2_address,
    .trace_rs2_value_previous_byte_0,
    .trace_rs2_value_previous_byte_1,
    .trace_rs2_value_previous_byte_2,
    .trace_rs2_value_previous_byte_3,
    .trace_rs2_previous_clock,
    .trace_rs2_value_next_byte_0,
    .trace_rs2_value_next_byte_1,
    .trace_rs2_value_next_byte_2,
    .trace_rs2_value_next_byte_3,
    .derived_rs1_most_significant_limb,
    .derived_rs2_most_significant_limb,
    .trace_signed_immediate,
    .derived_branch_decision,
    .derived_comparison_less,
    .hint_first_difference_marker_0,
    .hint_first_difference_marker_1,
    .hint_first_difference_marker_2,
    .hint_first_difference_marker_3,
    .hint_positive_difference,
    .trace_branch_target,
    .derived_blt_flag,
    .derived_bltu_flag,
    .derived_bge_flag,
    .derived_bgeu_flag,
};

pub const SlotBinding = struct {
    column: u8,
    value: types.ValueId,
    source: RowSource,
};

pub const ComparisonAlgorithm = enum(u8) {
    signed_i32 = 0,
    unsigned_u32 = 1,
};

pub const BranchDecision = enum(u8) {
    less = 0,
    greater_or_equal = 1,
};

pub const OperationBinding = struct {
    opcode_id: u32,
    flag_column: u8,
    comparison: ComparisonAlgorithm,
    decision: BranchDecision,
};

pub const CANONICAL_OPERATIONS = [4]OperationBinding{
    .{
        .opcode_id = typed.BLT_OPCODE_ID,
        .flag_column = 33,
        .comparison = .signed_i32,
        .decision = .less,
    },
    .{
        .opcode_id = typed.BLTU_OPCODE_ID,
        .flag_column = 34,
        .comparison = .unsigned_u32,
        .decision = .less,
    },
    .{
        .opcode_id = typed.BGE_OPCODE_ID,
        .flag_column = 35,
        .comparison = .signed_i32,
        .decision = .greater_or_equal,
    },
    .{
        .opcode_id = typed.BGEU_OPCODE_ID,
        .flag_column = 36,
        .comparison = .unsigned_u32,
        .decision = .greater_or_equal,
    },
};

pub const EventSpec = struct {
    kind: program.EffectKind,
    domain: relation.Domain,
    role: relation.Role,
    arity: u8,
    access_ordinal: ?u8 = null,
};

pub const EVENT_SPECS = [EVENT_COUNT]EventSpec{
    .{ .kind = .program_fetch, .domain = .program_access, .role = .request, .arity = 5 },
    .{ .kind = .state_consume, .domain = .registers_state, .role = .consume, .arity = 2 },
    .{ .kind = .state_produce, .domain = .registers_state, .role = .emit, .arity = 2 },
    .{ .kind = .register_read, .domain = .memory_access, .role = .consume, .arity = 7, .access_ordinal = 1 },
    .{ .kind = .register_read, .domain = .memory_access, .role = .emit, .arity = 7, .access_ordinal = 1 },
    .{ .kind = .register_read, .domain = .range_check_20, .role = .request, .arity = 1, .access_ordinal = 1 },
    .{ .kind = .register_read, .domain = .memory_access, .role = .consume, .arity = 7, .access_ordinal = 2 },
    .{ .kind = .register_read, .domain = .memory_access, .role = .emit, .arity = 7, .access_ordinal = 2 },
    .{ .kind = .register_read, .domain = .range_check_20, .role = .request, .arity = 1, .access_ordinal = 2 },
    .{ .kind = .range_request, .domain = .range_check_8_8, .role = .request, .arity = 2 },
    .{ .kind = .range_request, .domain = .range_check_20, .role = .request, .arity = 1 },
};

pub const WitnessBinding = struct {
    format_version: u16,
    semantic_format_version: u16,
    semantic_digest: digest.Digest,
    slots: [MAIN_COLUMN_COUNT]SlotBinding,
    operations: [CANONICAL_OPERATIONS.len]OperationBinding,

    pub fn canonical(definition: *const typed.Definition) ConstructionError!WitnessBinding {
        try definition.validate();
        try validatePhysicalDefinition(definition);
        return canonicalUnchecked(definition);
    }

    pub fn identityDigest(self: *const WitnessBinding) digest.Digest {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(WITNESS_BINDING_DOMAIN_SEPARATOR);
        hashInt(&hash, u16, self.format_version);
        hashInt(&hash, u16, self.semantic_format_version);
        hash.update(&self.semantic_digest);
        hashInt(&hash, u16, MAIN_COLUMN_COUNT);
        for (self.slots) |slot| {
            hashInt(&hash, u8, slot.column);
            hashInt(&hash, u32, @intFromEnum(slot.value));
            hashInt(&hash, u8, @intFromEnum(slot.source));
        }
        hashInt(&hash, u8, CANONICAL_OPERATIONS.len);
        for (self.operations) |operation| {
            hashInt(&hash, u32, operation.opcode_id);
            hashInt(&hash, u8, operation.flag_column);
            hashInt(&hash, u8, @intFromEnum(operation.comparison));
            hashInt(&hash, u8, @intFromEnum(operation.decision));
        }
        return hash.finalResult();
    }
};

pub const ConstructionError = typed.ValidationError || error{InvalidWitnessBinding};
pub const ExecutionError = direct_witness_executor.Error;

pub const RelationEvent = struct {
    kind: program.EffectKind,
    domain: relation.Domain,
    role: relation.Role,
    liveness: M31,
    arity: u8,
    values: [MAX_EVENT_ARITY]M31,
    access_ordinal: ?u8,

    pub fn signedNumerator(self: RelationEvent) M31 {
        return switch (self.role) {
            .emit => self.liveness,
            .request, .consume => self.liveness.neg(),
        };
    }
};

pub const RelationRow = struct { events: [EVENT_COUNT]RelationEvent };

pub const Executor = struct {
    binding: WitnessBinding,
    binding_digest: digest.Digest,

    pub fn init(
        definition: *const typed.Definition,
        supplied: *const WitnessBinding,
    ) ConstructionError!Executor {
        try definition.validate();
        try validatePhysicalDefinition(definition);
        const expected = canonicalUnchecked(definition);
        if (!std.meta.eql(expected, supplied.*))
            return error.InvalidWitnessBinding;
        const binding_digest = supplied.identityDigest();
        if (!std.mem.eql(u8, &binding_digest, &WITNESS_BINDING_DIGEST))
            return error.InvalidWitnessBinding;
        return .{ .binding = supplied.*, .binding_digest = binding_digest };
    }

    pub fn identitySnapshot(self: *const Executor) WitnessBinding {
        return self.binding;
    }

    pub fn identityDigest(self: *const Executor) digest.Digest {
        return self.binding_digest;
    }

    pub fn generateMainInto(
        self: *const Executor,
        columns: *[MAIN_COLUMN_COUNT][]M31,
        rows: []const TraceRow,
        log_size: u32,
    ) ExecutionError!void {
        return direct_witness_executor.generateMainInto(
            M31,
            TraceRow,
            MAIN_COLUMN_COUNT,
            columns,
            rows,
            log_size,
            M31.zero(),
            self,
            validateRow,
            writeActiveRow,
        );
    }

    pub fn generateRelationRow(_: *const Executor, row: TraceRow) ExecutionError!RelationRow {
        try validateRow(row);
        return buildRelationRow(row);
    }
};

fn canonicalUnchecked(definition: *const typed.Definition) WitnessBinding {
    const physical = definition.columns.physical();
    var slots: [MAIN_COLUMN_COUNT]SlotBinding = undefined;
    for (&slots, physical, CANONICAL_RECIPE, 0..) |*slot, value, row_source, column| {
        slot.* = .{
            .column = @intCast(column),
            .value = value,
            .source = row_source,
        };
    }
    return .{
        .format_version = WITNESS_BINDING_FORMAT_VERSION,
        .semantic_format_version = digest.committed_program_control_target_format_version,
        .semantic_digest = typed.SEMANTIC_DIGEST,
        .slots = slots,
        .operations = CANONICAL_OPERATIONS,
    };
}

const PhysicalSpec = struct {
    name: []const u8,
    ty: types.Type,
    source: RowSource,
};

const physical_specs = [MAIN_COLUMN_COUNT]PhysicalSpec{
    .{ .name = "clock", .ty = .clock, .source = .trace_clock },
    .{ .name = "pc", .ty = .pc, .source = .trace_pc },
    .{ .name = "rs1_addr", .ty = .register_index, .source = .trace_rs1_address },
    .{ .name = "rs1_prev_0", .ty = .byte, .source = .trace_rs1_value_previous_byte_0 },
    .{ .name = "rs1_prev_1", .ty = .byte, .source = .trace_rs1_value_previous_byte_1 },
    .{ .name = "rs1_prev_2", .ty = .byte, .source = .trace_rs1_value_previous_byte_2 },
    .{ .name = "rs1_prev_3", .ty = .byte, .source = .trace_rs1_value_previous_byte_3 },
    .{ .name = "rs1_clock_prev", .ty = .clock, .source = .trace_rs1_previous_clock },
    .{ .name = "rs1_next_0", .ty = .byte, .source = .trace_rs1_value_next_byte_0 },
    .{ .name = "rs1_next_1", .ty = .byte, .source = .trace_rs1_value_next_byte_1 },
    .{ .name = "rs1_next_2", .ty = .byte, .source = .trace_rs1_value_next_byte_2 },
    .{ .name = "rs1_next_3", .ty = .byte, .source = .trace_rs1_value_next_byte_3 },
    .{ .name = "rs2_addr", .ty = .register_index, .source = .trace_rs2_address },
    .{ .name = "rs2_prev_0", .ty = .byte, .source = .trace_rs2_value_previous_byte_0 },
    .{ .name = "rs2_prev_1", .ty = .byte, .source = .trace_rs2_value_previous_byte_1 },
    .{ .name = "rs2_prev_2", .ty = .byte, .source = .trace_rs2_value_previous_byte_2 },
    .{ .name = "rs2_prev_3", .ty = .byte, .source = .trace_rs2_value_previous_byte_3 },
    .{ .name = "rs2_clock_prev", .ty = .clock, .source = .trace_rs2_previous_clock },
    .{ .name = "rs2_next_0", .ty = .byte, .source = .trace_rs2_value_next_byte_0 },
    .{ .name = "rs2_next_1", .ty = .byte, .source = .trace_rs2_value_next_byte_1 },
    .{ .name = "rs2_next_2", .ty = .byte, .source = .trace_rs2_value_next_byte_2 },
    .{ .name = "rs2_next_3", .ty = .byte, .source = .trace_rs2_value_next_byte_3 },
    .{ .name = "rs1_msl_felt", .ty = .felt, .source = .derived_rs1_most_significant_limb },
    .{ .name = "rs2_msl_felt", .ty = .felt, .source = .derived_rs2_most_significant_limb },
    .{ .name = "imm_felt", .ty = .felt, .source = .trace_signed_immediate },
    .{ .name = "cmp_result", .ty = .bit, .source = .derived_branch_decision },
    .{ .name = "cmp_lt", .ty = .bit, .source = .derived_comparison_less },
    .{ .name = "diff_marker_0", .ty = .bit, .source = .hint_first_difference_marker_0 },
    .{ .name = "diff_marker_1", .ty = .bit, .source = .hint_first_difference_marker_1 },
    .{ .name = "diff_marker_2", .ty = .bit, .source = .hint_first_difference_marker_2 },
    .{ .name = "diff_marker_3", .ty = .bit, .source = .hint_first_difference_marker_3 },
    .{ .name = "diff_val", .ty = .felt, .source = .hint_positive_difference },
    .{ .name = "branch_target", .ty = .pc, .source = .trace_branch_target },
    .{ .name = "opcode_blt_flag", .ty = .bit, .source = .derived_blt_flag },
    .{ .name = "opcode_bltu_flag", .ty = .bit, .source = .derived_bltu_flag },
    .{ .name = "opcode_bge_flag", .ty = .bit, .source = .derived_bge_flag },
    .{ .name = "opcode_bgeu_flag", .ty = .bit, .source = .derived_bgeu_flag },
};

fn validatePhysicalDefinition(
    definition: *const typed.Definition,
) error{InvalidWitnessBinding}!void {
    const physical = definition.columns.physical();
    inline for (physical_specs, physical, CANONICAL_RECIPE, 0..) |
        spec,
        value,
        row_source,
        column,
    | {
        if (types.idIndex(value) != column or spec.source != row_source)
            return error.InvalidWitnessBinding;
        const node = definition.arena.node(value) orelse
            return error.InvalidWitnessBinding;
        if (!std.meta.eql(node.key.ty, spec.ty))
            return error.InvalidWitnessBinding;
        const name_id = switch (node.key.op) {
            .input => |name| name,
            else => return error.InvalidWitnessBinding,
        };
        const name = definition.arena.name(name_id) orelse
            return error.InvalidWitnessBinding;
        if (!std.mem.eql(u8, name, spec.name))
            return error.InvalidWitnessBinding;
    }
}

const Comparison = struct {
    lhs_most_significant: M31,
    rhs_most_significant: M31,
    less: bool,
    markers: [4]M31,
    difference: M31,

    inline fn unequal(self: Comparison) bool {
        return !self.difference.isZero();
    }
};

const DecodedRow = struct {
    clock: M31,
    pc: M31,
    rs1: M31,
    rs1_value: [4]M31,
    rs1_previous_clock: M31,
    rs2: M31,
    rs2_value: [4]M31,
    rs2_previous_clock: M31,
    immediate: M31,
    comparison: Comparison,
    taken: bool,
    target: M31,
    opcode_id: M31,
    flags: [4]M31,
};

inline fn decodeRow(row: TraceRow) DecodedRow {
    const comparison = compare(row.rs1_val, row.rs2_val, isSignedOpcode(row));
    return .{
        .clock = fromUnsigned(row.clk),
        .pc = fromUnsigned(row.pc),
        .rs1 = fromUnsigned(row.rs1),
        .rs1_value = limbs(row.rs1_val),
        .rs1_previous_clock = fromUnsigned(row.rs1_prev_clk),
        .rs2 = fromUnsigned(row.rs2),
        .rs2_value = limbs(row.rs2_val),
        .rs2_previous_clock = fromUnsigned(row.rs2_prev_clk),
        .immediate = fromSigned(row.imm),
        .comparison = comparison,
        .taken = if (isLessOpcode(row)) comparison.less else !comparison.less,
        .target = fromUnsigned(row.next_pc),
        .opcode_id = fromUnsigned(opcodeId(row)),
        .flags = .{
            flag(row.opcode == .BLT),
            flag(row.opcode == .BLTU),
            flag(row.opcode == .BGE),
            flag(row.opcode == .BGEU),
        },
    };
}

pub inline fn writeActiveRow(columns: anytype, row_index: usize, row: TraceRow) void {
    @setEvalBranchQuota(10_000);
    const d = decodeRow(row);
    inline for (CANONICAL_RECIPE, 0..) |row_source, column| {
        columns[column][row_index] = switch (row_source) {
            .trace_clock => d.clock,
            .trace_pc => d.pc,
            .trace_rs1_address => d.rs1,
            .trace_rs1_value_previous_byte_0 => d.rs1_value[0],
            .trace_rs1_value_previous_byte_1 => d.rs1_value[1],
            .trace_rs1_value_previous_byte_2 => d.rs1_value[2],
            .trace_rs1_value_previous_byte_3 => d.rs1_value[3],
            .trace_rs1_previous_clock => d.rs1_previous_clock,
            .trace_rs1_value_next_byte_0 => d.rs1_value[0],
            .trace_rs1_value_next_byte_1 => d.rs1_value[1],
            .trace_rs1_value_next_byte_2 => d.rs1_value[2],
            .trace_rs1_value_next_byte_3 => d.rs1_value[3],
            .trace_rs2_address => d.rs2,
            .trace_rs2_value_previous_byte_0 => d.rs2_value[0],
            .trace_rs2_value_previous_byte_1 => d.rs2_value[1],
            .trace_rs2_value_previous_byte_2 => d.rs2_value[2],
            .trace_rs2_value_previous_byte_3 => d.rs2_value[3],
            .trace_rs2_previous_clock => d.rs2_previous_clock,
            .trace_rs2_value_next_byte_0 => d.rs2_value[0],
            .trace_rs2_value_next_byte_1 => d.rs2_value[1],
            .trace_rs2_value_next_byte_2 => d.rs2_value[2],
            .trace_rs2_value_next_byte_3 => d.rs2_value[3],
            .derived_rs1_most_significant_limb => d.comparison.lhs_most_significant,
            .derived_rs2_most_significant_limb => d.comparison.rhs_most_significant,
            .trace_signed_immediate => d.immediate,
            .derived_branch_decision => flag(d.taken),
            .derived_comparison_less => flag(d.comparison.less),
            .hint_first_difference_marker_0 => d.comparison.markers[0],
            .hint_first_difference_marker_1 => d.comparison.markers[1],
            .hint_first_difference_marker_2 => d.comparison.markers[2],
            .hint_first_difference_marker_3 => d.comparison.markers[3],
            .hint_positive_difference => d.comparison.difference,
            .trace_branch_target => d.target,
            .derived_blt_flag => d.flags[0],
            .derived_bltu_flag => d.flags[1],
            .derived_bge_flag => d.flags[2],
            .derived_bgeu_flag => d.flags[3],
        };
    }
}

fn validateRow(row: TraceRow) ExecutionError!void {
    if (!isFamilyOpcode(row) or row.imm < -4096 or row.imm > 4094 or
        (@as(u32, @bitCast(row.imm)) & 1) != 0 or row.clk == 0 or
        row.pc & 3 != 0 or row.pc >= (@as(u32, 1) << 30) or
        row.is_load or row.is_store or
        row.mem_addr != 0 or row.mem_val != 0 or row.mem_prev_word != 0 or
        row.mem_next_word != 0 or row.mem_prev_clk != 0)
    {
        return error.InvalidTraceRow;
    }
    const source_1_clock = accessClock(row.clk, 1) orelse
        return error.InvalidTraceRow;
    const source_2_clock = accessClock(row.clk, 2) orelse
        return error.InvalidTraceRow;
    if (!validGap(row.rs1_prev_clk, source_1_clock) or
        !validGap(row.rs2_prev_clk, source_2_clock) or
        (row.rs1 == 0 and row.rs1_val != 0) or
        (row.rs2 == 0 and row.rs2_val != 0) or
        (row.rs1 == row.rs2 and
            (row.rs1_val != row.rs2_val or row.rs2_prev_clk != source_1_clock)))
    {
        return error.InvalidTraceRow;
    }
    const less = lessFor(row);
    const taken = if (isLessOpcode(row)) less else !less;
    const target = if (taken)
        row.pc +% @as(u32, @bitCast(row.imm))
    else
        row.pc +% 4;
    if (target & 3 != 0 or target >= (@as(u32, 1) << 30) or
        row.next_pc != target or row.branch_taken != (target != row.pc +% 4))
    {
        return error.InvalidTraceRow;
    }
}

fn buildRelationRow(row: TraceRow) RelationRow {
    const d = decodeRow(row);
    const one = M31.one();
    const zero = M31.zero();
    const four = fromUnsigned(4);
    const source_1_clock = d.clock.sub(one).mul(four).add(one);
    const source_2_clock = d.clock.sub(one).mul(four).add(fromUnsigned(2));
    const signed_shift = if (isSignedOpcode(row)) fromUnsigned(128) else zero;

    var result: RelationRow = undefined;
    result.events[0] = makeEvent(0, one, .{
        d.pc, d.opcode_id, d.rs1, d.rs2, d.immediate,
    });
    result.events[1] = makeEvent(1, one, .{ d.pc, d.clock });
    result.events[2] = makeEvent(2, one, .{ d.target, d.clock.add(one) });
    result.events[3] = makeEvent(3, one, .{
        zero,           d.rs1,          d.rs1_previous_clock,
        d.rs1_value[0], d.rs1_value[1], d.rs1_value[2],
        d.rs1_value[3],
    });
    result.events[4] = makeEvent(4, one, .{
        zero,           d.rs1,          source_1_clock,
        d.rs1_value[0], d.rs1_value[1], d.rs1_value[2],
        d.rs1_value[3],
    });
    result.events[5] = makeEvent(
        5,
        one,
        .{source_1_clock.sub(d.rs1_previous_clock).sub(one)},
    );
    result.events[6] = makeEvent(6, one, .{
        zero,           d.rs2,          d.rs2_previous_clock,
        d.rs2_value[0], d.rs2_value[1], d.rs2_value[2],
        d.rs2_value[3],
    });
    result.events[7] = makeEvent(7, one, .{
        zero,           d.rs2,          source_2_clock,
        d.rs2_value[0], d.rs2_value[1], d.rs2_value[2],
        d.rs2_value[3],
    });
    result.events[8] = makeEvent(
        8,
        one,
        .{source_2_clock.sub(d.rs2_previous_clock).sub(one)},
    );
    result.events[9] = makeEvent(9, one, .{
        d.comparison.lhs_most_significant.add(signed_shift),
        d.comparison.rhs_most_significant.add(signed_shift),
    });
    result.events[10] = makeEvent(
        10,
        flag(d.comparison.unequal()),
        .{d.comparison.difference.sub(one)},
    );
    return result;
}

fn makeEvent(comptime index: usize, liveness: M31, values: anytype) RelationEvent {
    const spec = EVENT_SPECS[index];
    comptime if (values.len != spec.arity)
        @compileError("typed BRANCH_LT relation row arity drift");
    var owned = [_]M31{M31.zero()} ** MAX_EVENT_ARITY;
    inline for (values, 0..) |value, field| owned[field] = value;
    return .{
        .kind = spec.kind,
        .domain = spec.domain,
        .role = spec.role,
        .liveness = liveness,
        .arity = spec.arity,
        .values = owned,
        .access_ordinal = spec.access_ordinal,
    };
}

inline fn compare(lhs: u32, rhs: u32, signed_comparison: bool) Comparison {
    const lhs_bytes = limbs(lhs);
    const rhs_bytes = limbs(rhs);
    const less = if (signed_comparison)
        @as(i32, @bitCast(lhs)) < @as(i32, @bitCast(rhs))
    else
        lhs < rhs;
    const lhs_msl = if (signed_comparison)
        signedByte(@truncate(lhs >> 24))
    else
        lhs_bytes[3];
    const rhs_msl = if (signed_comparison)
        signedByte(@truncate(rhs >> 24))
    else
        rhs_bytes[3];
    var result = Comparison{
        .lhs_most_significant = lhs_msl,
        .rhs_most_significant = rhs_msl,
        .less = less,
        .markers = .{M31.zero()} ** 4,
        .difference = M31.zero(),
    };
    var limb: usize = 4;
    while (limb > 0) {
        limb -= 1;
        const a = if (limb == 3) lhs_msl else lhs_bytes[limb];
        const b = if (limb == 3) rhs_msl else rhs_bytes[limb];
        if (!a.eql(b)) {
            result.markers[limb] = M31.one();
            result.difference = if (less) b.sub(a) else a.sub(b);
            break;
        }
    }
    return result;
}

inline fn isFamilyOpcode(row: TraceRow) bool {
    return switch (row.opcode) {
        .BLT, .BLTU, .BGE, .BGEU => true,
        else => false,
    };
}

inline fn isSignedOpcode(row: TraceRow) bool {
    return row.opcode == .BLT or row.opcode == .BGE;
}

inline fn isLessOpcode(row: TraceRow) bool {
    return row.opcode == .BLT or row.opcode == .BLTU;
}

inline fn lessFor(row: TraceRow) bool {
    return if (isSignedOpcode(row))
        @as(i32, @bitCast(row.rs1_val)) < @as(i32, @bitCast(row.rs2_val))
    else
        row.rs1_val < row.rs2_val;
}

inline fn opcodeId(row: TraceRow) u32 {
    return switch (row.opcode) {
        .BLT => typed.BLT_OPCODE_ID,
        .BLTU => typed.BLTU_OPCODE_ID,
        .BGE => typed.BGE_OPCODE_ID,
        .BGEU => typed.BGEU_OPCODE_ID,
        else => unreachable,
    };
}

fn accessClock(clock: u32, phase: u32) ?u32 {
    if (clock == 0 or phase == 0 or phase > 2) return null;
    return std.math.cast(u32, (@as(u64, clock) - 1) * 4 + phase);
}

fn validGap(previous: u32, current: u32) bool {
    if (previous >= current) return false;
    return current - previous - 1 < (@as(u32, 1) << 20);
}

inline fn flag(value: bool) M31 {
    return if (value) M31.one() else M31.zero();
}

inline fn fromUnsigned(value: anytype) M31 {
    return M31.fromU64(@intCast(value));
}

inline fn fromSigned(value: i32) M31 {
    if (value >= 0) return fromUnsigned(value);
    return M31.zero().sub(M31.fromU64(@intCast(-@as(i64, value))));
}

inline fn signedByte(value: u8) M31 {
    return fromSigned(@as(i8, @bitCast(value)));
}

inline fn limbs(value: u32) [4]M31 {
    return .{
        fromUnsigned(value & 0xff),
        fromUnsigned((value >> 8) & 0xff),
        fromUnsigned((value >> 16) & 0xff),
        fromUnsigned(value >> 24),
    };
}

fn hashInt(hash: anytype, comptime T: type, value: T) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hash.update(&encoded);
}

fn hexDigest(comptime value: []const u8, comptime message: []const u8) digest.Digest {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}

comptime {
    if (MAIN_COLUMN_COUNT != production_columns.BranchLtColumns.N_COLUMNS)
        @compileError("typed BRANCH_LT witness width drifted from production");
    if (EVENT_COUNT != 11 or MAX_EVENT_ARITY != relation.get(.memory_access).fields.len)
        @compileError("typed BRANCH_LT relation geometry drifted");
    const fields = @typeInfo(production_columns.BranchLtColumns).@"struct".fields;
    for (physical_specs, fields, CANONICAL_RECIPE, 0..) |
        spec,
        field,
        row_source,
        column,
    | {
        if (!std.mem.eql(u8, spec.name, field.name))
            @compileError("typed BRANCH_LT witness name drifted from production");
        if (spec.source != row_source or @intFromEnum(row_source) != column)
            @compileError("typed BRANCH_LT numeric witness recipe is not canonical");
    }
}
