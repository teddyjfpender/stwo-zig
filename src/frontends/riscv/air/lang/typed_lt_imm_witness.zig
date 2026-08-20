//! Authenticated, allocation-free witness authority for RV32 SLTI/SLTIU.
//!
//! Cold construction authenticates the native typed definition, every
//! physical source slot, and both signedness policies. The hot row kernel
//! writes final column-major storage directly and emits the exact ordered
//! relation row without allocator, scratch storage, or legacy delegation.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const direct_witness_executor = @import("direct_witness_executor.zig");
const digest = @import("digest.zig");
const program = @import("program.zig");
const relation = @import("relation.zig");
const production_columns = @import("../trace_columns/compare.zig");
const trace_row = @import("../../runner/trace_row.zig");
const typed = @import("typed_lt_imm.zig");
const types = @import("types.zig");

pub const MAIN_COLUMN_COUNT: usize = typed.MAIN_COLUMN_COUNT;
pub const EVENT_COUNT: usize = typed.LOOKUP_COUNT;
pub const MAX_EVENT_ARITY: usize = 7;
pub const TraceRow = trace_row.TraceRow;

pub const WITNESS_BINDING_FORMAT_VERSION: u16 = 1;
pub const WITNESS_BINDING_DOMAIN_SEPARATOR =
    "stwo-zig/typed-air/lt-imm-witness-binding/v1";
pub const WITNESS_BINDING_DIGEST_HEX =
    "5811fe79e3ea7166dc67af42044b97171cd4284efc93783b7d28fb42b0c667ff";
pub const WITNESS_BINDING_DIGEST: digest.Digest = hexDigest(
    WITNESS_BINDING_DIGEST_HEX,
    "invalid typed LT_IMM witness-binding digest",
);

/// Stable numeric identities for every physical column source.
pub const RowSource = enum(u8) {
    trace_clock = 0,
    trace_pc = 1,
    trace_rd_address = 2,
    trace_rd_previous_byte_0 = 3,
    trace_rd_previous_byte_1 = 4,
    trace_rd_previous_byte_2 = 5,
    trace_rd_previous_byte_3 = 6,
    trace_rd_previous_clock = 7,
    trace_rd_next_byte_0 = 8,
    trace_rd_next_byte_1 = 9,
    trace_rd_next_byte_2 = 10,
    trace_rd_next_byte_3 = 11,
    trace_rs1_address = 12,
    trace_rs1_value_previous_byte_0 = 13,
    trace_rs1_value_previous_byte_1 = 14,
    trace_rs1_value_previous_byte_2 = 15,
    trace_rs1_value_previous_byte_3 = 16,
    trace_rs1_previous_clock = 17,
    trace_rs1_value_next_byte_0 = 18,
    trace_rs1_value_next_byte_1 = 19,
    trace_rs1_value_next_byte_2 = 20,
    trace_rs1_value_next_byte_3 = 21,
    derived_comparison_result = 22,
    derived_rs1_most_significant_limb = 23,
    trace_signed_immediate_low_byte = 24,
    trace_signed_immediate_high_three_bits = 25,
    trace_signed_immediate_sign = 26,
    derived_slti_flag = 27,
    derived_sltiu_flag = 28,
    hint_first_difference_marker_0 = 29,
    hint_first_difference_marker_1 = 30,
    hint_first_difference_marker_2 = 31,
    hint_first_difference_marker_3 = 32,
    hint_positive_difference = 33,
    hint_rd_nonzero = 34,
    hint_rd_inverse_or_zero = 35,
    derived_immediate_most_significant_limb = 36,
};

pub const CANONICAL_RECIPE = [MAIN_COLUMN_COUNT]RowSource{
    .trace_clock,
    .trace_pc,
    .trace_rd_address,
    .trace_rd_previous_byte_0,
    .trace_rd_previous_byte_1,
    .trace_rd_previous_byte_2,
    .trace_rd_previous_byte_3,
    .trace_rd_previous_clock,
    .trace_rd_next_byte_0,
    .trace_rd_next_byte_1,
    .trace_rd_next_byte_2,
    .trace_rd_next_byte_3,
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
    .derived_comparison_result,
    .derived_rs1_most_significant_limb,
    .trace_signed_immediate_low_byte,
    .trace_signed_immediate_high_three_bits,
    .trace_signed_immediate_sign,
    .derived_slti_flag,
    .derived_sltiu_flag,
    .hint_first_difference_marker_0,
    .hint_first_difference_marker_1,
    .hint_first_difference_marker_2,
    .hint_first_difference_marker_3,
    .hint_positive_difference,
    .hint_rd_nonzero,
    .hint_rd_inverse_or_zero,
    .derived_immediate_most_significant_limb,
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

pub const OperationBinding = struct {
    opcode_id: u32,
    flag_column: u8,
    comparison: ComparisonAlgorithm,
};

pub const CANONICAL_OPERATIONS = [2]OperationBinding{
    .{
        .opcode_id = typed.SLTI_OPCODE_ID,
        .flag_column = 27,
        .comparison = .signed_i32,
    },
    .{
        .opcode_id = typed.SLTIU_OPCODE_ID,
        .flag_column = 28,
        .comparison = .unsigned_u32,
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
    .{ .kind = .range_request, .domain = .range_check_8_8_4, .role = .request, .arity = 3 },
    .{ .kind = .state_consume, .domain = .registers_state, .role = .consume, .arity = 2 },
    .{ .kind = .state_produce, .domain = .registers_state, .role = .emit, .arity = 2 },
    .{ .kind = .register_read, .domain = .memory_access, .role = .consume, .arity = 7, .access_ordinal = 1 },
    .{ .kind = .register_read, .domain = .memory_access, .role = .emit, .arity = 7, .access_ordinal = 1 },
    .{ .kind = .register_read, .domain = .range_check_20, .role = .request, .arity = 1, .access_ordinal = 1 },
    .{ .kind = .range_request, .domain = .range_check_20, .role = .request, .arity = 1 },
    .{ .kind = .register_write, .domain = .memory_access, .role = .consume, .arity = 7, .access_ordinal = 2 },
    .{ .kind = .register_write, .domain = .memory_access, .role = .emit, .arity = 7, .access_ordinal = 2 },
    .{ .kind = .register_write, .domain = .range_check_20, .role = .request, .arity = 1, .access_ordinal = 2 },
};

/// Pointer-free family recipe retained after the typed arena is destroyed.
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

    pub fn generateRelationRow(
        _: *const Executor,
        row: TraceRow,
    ) ExecutionError!RelationRow {
        try validateRow(row);
        return buildRelationRow(row);
    }
};

fn canonicalUnchecked(definition: *const typed.Definition) WitnessBinding {
    const physical = definition.columns.physical();
    var slots: [MAIN_COLUMN_COUNT]SlotBinding = undefined;
    for (&slots, physical, CANONICAL_RECIPE, 0..) |*slot, value, source, column| {
        slot.* = .{ .column = @intCast(column), .value = value, .source = source };
    }
    return .{
        .format_version = WITNESS_BINDING_FORMAT_VERSION,
        .semantic_format_version = digest.range_refinement_format_version,
        .semantic_digest = typed.SEMANTIC_DIGEST,
        .slots = slots,
        .operations = CANONICAL_OPERATIONS,
    };
}

const uint3 = types.Type{ .bounded_uint = .{
    .bits = 3,
    .representation = .canonical_field,
} };

const PhysicalSpec = struct {
    name: []const u8,
    ty: types.Type,
    source: RowSource,
};

const physical_specs = [MAIN_COLUMN_COUNT]PhysicalSpec{
    .{ .name = "clock", .ty = .clock, .source = .trace_clock },
    .{ .name = "pc", .ty = .pc, .source = .trace_pc },
    .{ .name = "rd_addr", .ty = .register_index, .source = .trace_rd_address },
    .{ .name = "rd_prev_0", .ty = .byte, .source = .trace_rd_previous_byte_0 },
    .{ .name = "rd_prev_1", .ty = .byte, .source = .trace_rd_previous_byte_1 },
    .{ .name = "rd_prev_2", .ty = .byte, .source = .trace_rd_previous_byte_2 },
    .{ .name = "rd_prev_3", .ty = .byte, .source = .trace_rd_previous_byte_3 },
    .{ .name = "rd_clock_prev", .ty = .clock, .source = .trace_rd_previous_clock },
    .{ .name = "rd_next_0", .ty = .byte, .source = .trace_rd_next_byte_0 },
    .{ .name = "rd_next_1", .ty = .byte, .source = .trace_rd_next_byte_1 },
    .{ .name = "rd_next_2", .ty = .byte, .source = .trace_rd_next_byte_2 },
    .{ .name = "rd_next_3", .ty = .byte, .source = .trace_rd_next_byte_3 },
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
    .{ .name = "cmp_result", .ty = .bit, .source = .derived_comparison_result },
    .{ .name = "rs1_msl_felt", .ty = .felt, .source = .derived_rs1_most_significant_limb },
    .{ .name = "imm_0", .ty = .byte, .source = .trace_signed_immediate_low_byte },
    .{ .name = "imm_1", .ty = uint3, .source = .trace_signed_immediate_high_three_bits },
    .{ .name = "imm_msb", .ty = .bit, .source = .trace_signed_immediate_sign },
    .{ .name = "opcode_slti_flag", .ty = .bit, .source = .derived_slti_flag },
    .{ .name = "opcode_sltiu_flag", .ty = .bit, .source = .derived_sltiu_flag },
    .{ .name = "diff_marker_0", .ty = .bit, .source = .hint_first_difference_marker_0 },
    .{ .name = "diff_marker_1", .ty = .bit, .source = .hint_first_difference_marker_1 },
    .{ .name = "diff_marker_2", .ty = .bit, .source = .hint_first_difference_marker_2 },
    .{ .name = "diff_marker_3", .ty = .bit, .source = .hint_first_difference_marker_3 },
    .{ .name = "diff_val", .ty = .felt, .source = .hint_positive_difference },
    .{ .name = "rd_nonzero", .ty = .bit, .source = .hint_rd_nonzero },
    .{ .name = "rd_inv", .ty = .felt, .source = .hint_rd_inverse_or_zero },
    .{ .name = "imm_msl_felt", .ty = .felt, .source = .derived_immediate_most_significant_limb },
};

fn validatePhysicalDefinition(
    definition: *const typed.Definition,
) error{InvalidWitnessBinding}!void {
    const physical = definition.columns.physical();
    inline for (physical_specs, physical, CANONICAL_RECIPE, 0..) |
        spec,
        value,
        source,
        index,
    | {
        if (types.idIndex(value) != index or spec.source != source)
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
    rd: M31,
    rd_previous: [4]M31,
    rd_previous_clock: M31,
    rd_next: [4]M31,
    rs1: M31,
    rs1_value: [4]M31,
    rs1_previous_clock: M31,
    immediate_bits: u32,
    immediate_low: M31,
    immediate_high_three: M31,
    immediate_sign: M31,
    comparison: Comparison,
    opcode_id: M31,
    flags: [2]M31,
    destination_nonzero: M31,
    destination_inverse: M31,
};

inline fn decodeRow(row: TraceRow) DecodedRow {
    const immediate_bits: u32 = @bitCast(row.imm);
    const comparison = compare(
        row.rs1_val,
        immediate_bits,
        row.opcode == .SLTI,
    );
    const rd = fromUnsigned(row.rd);
    return .{
        .clock = fromUnsigned(row.clk),
        .pc = fromUnsigned(row.pc),
        .rd = rd,
        .rd_previous = limbs(row.rd_prev_val),
        .rd_previous_clock = fromUnsigned(row.rd_prev_clk),
        .rd_next = limbs(row.rd_val),
        .rs1 = fromUnsigned(row.rs1),
        .rs1_value = limbs(row.rs1_val),
        .rs1_previous_clock = fromUnsigned(row.rs1_prev_clk),
        .immediate_bits = immediate_bits & 0xfff,
        .immediate_low = fromUnsigned(immediate_bits & 0xff),
        .immediate_high_three = fromUnsigned((immediate_bits >> 8) & 0x7),
        .immediate_sign = flag(row.imm < 0),
        .comparison = comparison,
        .opcode_id = fromUnsigned(opcodeId(row)),
        .flags = .{ flag(row.opcode == .SLTI), flag(row.opcode == .SLTIU) },
        .destination_nonzero = flag(row.rd != 0),
        .destination_inverse = if (row.rd == 0)
            M31.zero()
        else
            rd.invUncheckedNonZero(),
    };
}

pub inline fn writeActiveRow(
    columns: anytype,
    row_index: usize,
    row: TraceRow,
) void {
    const d = decodeRow(row);
    inline for (CANONICAL_RECIPE, 0..) |row_source, column| {
        columns[column][row_index] = switch (row_source) {
            .trace_clock => d.clock,
            .trace_pc => d.pc,
            .trace_rd_address => d.rd,
            .trace_rd_previous_byte_0 => d.rd_previous[0],
            .trace_rd_previous_byte_1 => d.rd_previous[1],
            .trace_rd_previous_byte_2 => d.rd_previous[2],
            .trace_rd_previous_byte_3 => d.rd_previous[3],
            .trace_rd_previous_clock => d.rd_previous_clock,
            .trace_rd_next_byte_0 => d.rd_next[0],
            .trace_rd_next_byte_1 => d.rd_next[1],
            .trace_rd_next_byte_2 => d.rd_next[2],
            .trace_rd_next_byte_3 => d.rd_next[3],
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
            .derived_comparison_result => flag(d.comparison.less),
            .derived_rs1_most_significant_limb => d.comparison.lhs_most_significant,
            .trace_signed_immediate_low_byte => d.immediate_low,
            .trace_signed_immediate_high_three_bits => d.immediate_high_three,
            .trace_signed_immediate_sign => d.immediate_sign,
            .derived_slti_flag => d.flags[0],
            .derived_sltiu_flag => d.flags[1],
            .hint_first_difference_marker_0 => d.comparison.markers[0],
            .hint_first_difference_marker_1 => d.comparison.markers[1],
            .hint_first_difference_marker_2 => d.comparison.markers[2],
            .hint_first_difference_marker_3 => d.comparison.markers[3],
            .hint_positive_difference => d.comparison.difference,
            .hint_rd_nonzero => d.destination_nonzero,
            .hint_rd_inverse_or_zero => d.destination_inverse,
            .derived_immediate_most_significant_limb => d.comparison.rhs_most_significant,
        };
    }
}

fn validateRow(row: TraceRow) ExecutionError!void {
    if (!isFamilyOpcode(row) or row.imm < -2048 or row.imm > 2047 or
        row.clk == 0 or row.next_pc != row.pc +% 4 or row.is_load or
        row.is_store or row.branch_taken)
    {
        return error.InvalidTraceRow;
    }
    const source_clock = accessClock(row.clk, 1) orelse
        return error.InvalidTraceRow;
    const destination_clock = accessClock(row.clk, 2) orelse
        return error.InvalidTraceRow;
    if (!validGap(row.rs1_prev_clk, source_clock) or
        !validGap(row.rd_prev_clk, destination_clock))
    {
        return error.InvalidTraceRow;
    }
    const expected = resultFor(row);
    if (row.rd_val != (if (row.rd == 0) 0 else expected) or
        (row.rs1 == 0 and row.rs1_val != 0) or
        (row.rd == 0 and row.rd_prev_val != 0))
    {
        return error.InvalidTraceRow;
    }
    if (row.rd == row.rs1 and
        (row.rd_prev_val != row.rs1_val or row.rd_prev_clk != source_clock))
    {
        return error.InvalidTraceRow;
    }
}

fn buildRelationRow(row: TraceRow) RelationRow {
    const d = decodeRow(row);
    const one = M31.one();
    const zero = M31.zero();
    const four = fromUnsigned(4);
    const source_clock = d.clock.sub(one).mul(four).add(one);
    const destination_clock = d.clock.sub(one).mul(four).add(fromUnsigned(2));
    const source_gap = source_clock.sub(d.rs1_previous_clock).sub(one);
    const destination_gap = destination_clock.sub(d.rd_previous_clock).sub(one);
    const rs1_shifted = d.comparison.lhs_most_significant.add(
        if (row.opcode == .SLTI) fromUnsigned(128) else zero,
    );

    var result: RelationRow = undefined;
    result.events[0] = makeEvent(0, one, .{
        d.pc, d.opcode_id, d.rd, d.rs1, fromUnsigned(d.immediate_bits),
    });
    result.events[1] = makeEvent(1, one, .{
        rs1_shifted,
        d.immediate_low,
        d.immediate_high_three.add(d.immediate_high_three),
    });
    result.events[2] = makeEvent(2, one, .{ d.pc, d.clock });
    result.events[3] = makeEvent(3, one, .{ d.pc.add(four), d.clock.add(one) });
    result.events[4] = makeEvent(4, one, .{
        zero,           d.rs1,          d.rs1_previous_clock,
        d.rs1_value[0], d.rs1_value[1], d.rs1_value[2],
        d.rs1_value[3],
    });
    result.events[5] = makeEvent(5, one, .{
        zero,           d.rs1,          source_clock,
        d.rs1_value[0], d.rs1_value[1], d.rs1_value[2],
        d.rs1_value[3],
    });
    result.events[6] = makeEvent(6, one, .{source_gap});
    result.events[7] = makeEvent(
        7,
        flag(d.comparison.unequal()),
        .{d.comparison.difference.sub(one)},
    );
    result.events[8] = makeEvent(8, one, .{
        zero,             d.rd,             d.rd_previous_clock,
        d.rd_previous[0], d.rd_previous[1], d.rd_previous[2],
        d.rd_previous[3],
    });
    result.events[9] = makeEvent(9, one, .{
        zero,         d.rd,         destination_clock,
        d.rd_next[0], d.rd_next[1], d.rd_next[2],
        d.rd_next[3],
    });
    result.events[10] = makeEvent(10, one, .{destination_gap});
    return result;
}

fn makeEvent(
    comptime index: usize,
    liveness: M31,
    values: anytype,
) RelationEvent {
    const spec = EVENT_SPECS[index];
    comptime if (values.len != spec.arity)
        @compileError("typed LT_IMM relation row arity drift");
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

inline fn compare(lhs: u32, rhs: u32, signed: bool) Comparison {
    const lhs_bytes = limbs(lhs);
    const rhs_bytes = limbs(rhs);
    const less = if (signed)
        @as(i32, @bitCast(lhs)) < @as(i32, @bitCast(rhs))
    else
        lhs < rhs;
    const lhs_most_significant = if (signed)
        signedByte(@truncate(lhs >> 24))
    else
        lhs_bytes[3];
    const rhs_most_significant = if (signed)
        signedByte(@truncate(rhs >> 24))
    else
        rhs_bytes[3];
    var result = Comparison{
        .lhs_most_significant = lhs_most_significant,
        .rhs_most_significant = rhs_most_significant,
        .less = less,
        .markers = .{M31.zero()} ** 4,
        .difference = M31.zero(),
    };
    var limb: usize = 4;
    while (limb > 0) {
        limb -= 1;
        const a = if (limb == 3) lhs_most_significant else lhs_bytes[limb];
        const b = if (limb == 3) rhs_most_significant else rhs_bytes[limb];
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
        .SLTI, .SLTIU => true,
        else => false,
    };
}

inline fn resultFor(row: TraceRow) u32 {
    const immediate: u32 = @bitCast(row.imm);
    const less = switch (row.opcode) {
        .SLTI => @as(i32, @bitCast(row.rs1_val)) < row.imm,
        .SLTIU => row.rs1_val < immediate,
        else => unreachable,
    };
    return @intFromBool(less);
}

inline fn opcodeId(row: TraceRow) u32 {
    return switch (row.opcode) {
        .SLTI => typed.SLTI_OPCODE_ID,
        .SLTIU => typed.SLTIU_OPCODE_ID,
        else => unreachable,
    };
}

fn accessClock(clock: u32, phase: u32) ?u32 {
    if (clock == 0 or phase == 0 or phase > 3) return null;
    const encoded = (@as(u64, clock) - 1) * 4 + phase;
    return std.math.cast(u32, encoded);
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
    if (MAIN_COLUMN_COUNT != production_columns.LtImmColumns.N_COLUMNS)
        @compileError("typed LT_IMM witness width drifted from production");
    if (EVENT_COUNT != 11 or MAX_EVENT_ARITY != relation.get(.memory_access).fields.len)
        @compileError("typed LT_IMM relation geometry drifted");
    const fields = @typeInfo(production_columns.LtImmColumns).@"struct".fields;
    for (physical_specs, fields, CANONICAL_RECIPE, 0..) |
        spec,
        field,
        row_source,
        column,
    | {
        if (!std.mem.eql(u8, spec.name, field.name))
            @compileError("typed LT_IMM witness name drifted from production");
        if (spec.source != row_source or @intFromEnum(row_source) != column)
            @compileError("typed LT_IMM numeric witness recipe is not canonical");
    }
    if (CANONICAL_OPERATIONS[0].opcode_id != 11 or
        CANONICAL_OPERATIONS[1].opcode_id != 12)
    {
        @compileError("typed LT_IMM opcode identity drifted");
    }
}
