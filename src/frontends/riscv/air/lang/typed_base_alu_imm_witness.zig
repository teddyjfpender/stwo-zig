//! Authenticated, allocation-free witness authority for the complete RV32
//! BASE_ALU_IMM family: ADDI, XORI, ORI, and ANDI.
//!
//! `typed_addi.zig` already authors the complete compatibility AIR. Its first
//! witness executor intentionally selected only ADDI. This layer retains that
//! definition/effect authentication as an anchor, then authenticates the full
//! family row recipe and opcode-result policy. The hot path writes final SoA
//! storage directly and never calls a handwritten writer.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const direct_witness_executor = @import("direct_witness_executor.zig");
const digest = @import("digest.zig");
const program = @import("program.zig");
const relation = @import("relation.zig");
const production_columns = @import("../trace_columns/base.zig");
const typed_addi = @import("typed_addi.zig");
const addi_witness = @import("typed_addi_witness.zig");
const types = @import("types.zig");

pub const MAIN_COLUMN_COUNT: usize = typed_addi.MAIN_COLUMN_COUNT;
pub const EVENT_COUNT: usize = typed_addi.RELATION_EVENT_COUNT;
pub const MAX_EVENT_ARITY: usize = addi_witness.MAX_EVENT_ARITY;
pub const TraceRow = addi_witness.TraceRow;
pub const EventSpec = addi_witness.EventSpec;
pub const EVENT_SPECS = addi_witness.EVENT_SPECS;
pub const RelationEvent = addi_witness.RelationEvent;
pub const RelationRow = addi_witness.RelationRow;

pub const WITNESS_BINDING_FORMAT_VERSION: u16 = 1;
pub const WITNESS_BINDING_DOMAIN_SEPARATOR =
    "stwo-zig/typed-air/base-alu-imm-witness-binding/v1";
pub const WITNESS_BINDING_DIGEST_HEX =
    "9142e37c74b78adfe14d7b86970f712264b5b5ee70ae50023a81bc6c769a8db5";

pub const WITNESS_BINDING_DIGEST: digest.Digest = blk: {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, WITNESS_BINDING_DIGEST_HEX) catch
        @compileError("invalid typed BASE_ALU_IMM witness-binding digest");
    break :blk result;
};

/// Stable numeric identities for all 35 physical column sources.
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
    trace_signed_immediate_low_byte = 22,
    trace_signed_immediate_high_three_bits = 23,
    trace_signed_immediate_sign = 24,
    derived_addi_flag = 25,
    derived_xori_flag = 26,
    derived_ori_flag = 27,
    derived_andi_flag = 28,
    derived_result_byte_0 = 29,
    derived_result_byte_1 = 30,
    derived_result_byte_2 = 31,
    derived_result_byte_3 = 32,
    hint_rd_nonzero = 33,
    hint_rd_inverse_or_zero = 34,
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
    .trace_signed_immediate_low_byte,
    .trace_signed_immediate_high_three_bits,
    .trace_signed_immediate_sign,
    .derived_addi_flag,
    .derived_xori_flag,
    .derived_ori_flag,
    .derived_andi_flag,
    .derived_result_byte_0,
    .derived_result_byte_1,
    .derived_result_byte_2,
    .derived_result_byte_3,
    .hint_rd_nonzero,
    .hint_rd_inverse_or_zero,
};

pub const SlotBinding = struct {
    column: u8,
    value: types.ValueId,
    source: RowSource,
};

pub const ResultAlgorithm = enum(u8) {
    rv32_wrapping_add_signed_imm12 = 0,
    rv32_bitwise_xor_signed_imm12 = 1,
    rv32_bitwise_or_signed_imm12 = 2,
    rv32_bitwise_and_signed_imm12 = 3,
};

pub const OperationBinding = struct {
    opcode_id: u32,
    flag_column: u8,
    result: ResultAlgorithm,
    bitwise_active: bool,
    bitwise_operation_id: u8,
};

pub const CANONICAL_OPERATIONS = [4]OperationBinding{
    .{
        .opcode_id = typed_addi.ADDI_OPCODE_ID,
        .flag_column = 25,
        .result = .rv32_wrapping_add_signed_imm12,
        .bitwise_active = false,
        .bitwise_operation_id = 0,
    },
    .{
        .opcode_id = typed_addi.XORI_OPCODE_ID,
        .flag_column = 26,
        .result = .rv32_bitwise_xor_signed_imm12,
        .bitwise_active = true,
        .bitwise_operation_id = 2,
    },
    .{
        .opcode_id = typed_addi.ORI_OPCODE_ID,
        .flag_column = 27,
        .result = .rv32_bitwise_or_signed_imm12,
        .bitwise_active = true,
        .bitwise_operation_id = 1,
    },
    .{
        .opcode_id = typed_addi.ANDI_OPCODE_ID,
        .flag_column = 28,
        .result = .rv32_bitwise_and_signed_imm12,
        .bitwise_active = true,
        .bitwise_operation_id = 0,
    },
};

/// Pointer-free family recipe retained after the typed arena is destroyed.
pub const WitnessBinding = struct {
    format_version: u16,
    semantic_format_version: u16,
    semantic_digest: digest.Digest,
    typed_definition_binding_digest: digest.Digest,
    slots: [MAIN_COLUMN_COUNT]SlotBinding,
    operations: [CANONICAL_OPERATIONS.len]OperationBinding,

    pub fn canonical(
        definition: *const typed_addi.Definition,
    ) ConstructionError!WitnessBinding {
        const anchor = try authenticatedDefinitionBinding(definition);
        return canonicalUnchecked(definition, &anchor);
    }

    pub fn identityDigest(self: *const WitnessBinding) digest.Digest {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(WITNESS_BINDING_DOMAIN_SEPARATOR);
        hashInt(&hash, u16, self.format_version);
        hashInt(&hash, u16, self.semantic_format_version);
        hash.update(&self.semantic_digest);
        hash.update(&self.typed_definition_binding_digest);
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
            hashInt(&hash, u8, @intFromEnum(operation.result));
            hashInt(&hash, u8, @intFromBool(operation.bitwise_active));
            hashInt(&hash, u8, operation.bitwise_operation_id);
        }
        return hash.finalResult();
    }
};

pub const ConstructionError = addi_witness.ConstructionError;
pub const ExecutionError = direct_witness_executor.Error;

/// Immutable executor with no allocator, scratch state, or hot dispatch table.
pub const Executor = struct {
    binding: WitnessBinding,
    binding_digest: digest.Digest,

    pub fn init(
        definition: *const typed_addi.Definition,
        supplied: *const WitnessBinding,
    ) ConstructionError!Executor {
        const anchor = try authenticatedDefinitionBinding(definition);
        const expected = canonicalUnchecked(definition, &anchor);
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

fn authenticatedDefinitionBinding(
    definition: *const typed_addi.Definition,
) ConstructionError!addi_witness.WitnessBinding {
    const anchor = try addi_witness.WitnessBinding.canonical(definition);
    _ = try addi_witness.Executor.init(definition, &anchor);
    return anchor;
}

fn canonicalUnchecked(
    definition: *const typed_addi.Definition,
    anchor: *const addi_witness.WitnessBinding,
) WitnessBinding {
    const physical = definition.columns.physical();
    var slots: [MAIN_COLUMN_COUNT]SlotBinding = undefined;
    for (&slots, physical, CANONICAL_RECIPE, 0..) |*slot, value, source, column| {
        slot.* = .{ .column = @intCast(column), .value = value, .source = source };
    }
    return .{
        .format_version = WITNESS_BINDING_FORMAT_VERSION,
        .semantic_format_version = anchor.semantic_format_version,
        .semantic_digest = typed_addi.SEMANTIC_DIGEST,
        .typed_definition_binding_digest = anchor.identityDigest(),
        .slots = slots,
        .operations = CANONICAL_OPERATIONS,
    };
}

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
    immediate: [4]M31,
    opcode_id: M31,
    operation_id: M31,
    bitwise_active: M31,
    flags: [4]M31,
    result: [4]M31,
    destination_nonzero: M31,
    destination_inverse: M31,
};

inline fn decodeRow(row: TraceRow) DecodedRow {
    const immediate_word: u32 = @bitCast(row.imm);
    const immediate_bits = immediate_word & 0xfff;
    const sign = (immediate_bits >> 11) & 1;
    const rd = fromUnsigned(row.rd);
    const nonzero = row.rd != 0;
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
        .immediate_bits = immediate_bits,
        .immediate = .{
            fromUnsigned(immediate_bits & 0xff),
            fromUnsigned(((immediate_bits >> 8) & 0x7) + sign * 248),
            fromUnsigned(sign * 255),
            fromUnsigned(sign * 255),
        },
        .opcode_id = fromUnsigned(opcodeId(row)),
        .operation_id = fromUnsigned(bitwiseOperationId(row)),
        .bitwise_active = if (row.opcode == .ADDI) M31.zero() else M31.one(),
        .flags = .{
            flag(row.opcode == .ADDI),
            flag(row.opcode == .XORI),
            flag(row.opcode == .ORI),
            flag(row.opcode == .ANDI),
        },
        .result = limbs(resultFor(row)),
        .destination_nonzero = flag(nonzero),
        .destination_inverse = if (nonzero)
            rd.invUncheckedNonZero()
        else
            M31.zero(),
    };
}

/// Direct final-storage writer selected after family classification.
pub inline fn writeActiveRow(
    columns: anytype,
    row_index: usize,
    row: TraceRow,
) void {
    const d = decodeRow(row);
    inline for (CANONICAL_RECIPE, 0..) |source, column| {
        columns[column][row_index] = switch (source) {
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
            .trace_signed_immediate_low_byte => d.immediate[0],
            .trace_signed_immediate_high_three_bits => fromUnsigned((d.immediate_bits >> 8) & 0x7),
            .trace_signed_immediate_sign => fromUnsigned(d.immediate_bits >> 11),
            .derived_addi_flag => d.flags[0],
            .derived_xori_flag => d.flags[1],
            .derived_ori_flag => d.flags[2],
            .derived_andi_flag => d.flags[3],
            .derived_result_byte_0 => d.result[0],
            .derived_result_byte_1 => d.result[1],
            .derived_result_byte_2 => d.result[2],
            .derived_result_byte_3 => d.result[3],
            .hint_rd_nonzero => d.destination_nonzero,
            .hint_rd_inverse_or_zero => d.destination_inverse,
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
    const high_shifted = fromUnsigned(((d.immediate_bits >> 8) & 0x7) << 8);

    var result: RelationRow = undefined;
    result.events[0] = makeEvent(0, one, .{
        d.pc, d.opcode_id, d.rd, d.rs1, fromUnsigned(d.immediate_bits),
    });
    result.events[1] = makeEvent(1, one, .{ d.immediate[0], high_shifted });
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
    inline for (0..4) |limb| result.events[7 + limb] = makeEvent(
        7 + limb,
        d.bitwise_active,
        .{ d.rs1_value[limb], d.immediate[limb], d.result[limb], d.operation_id },
    );
    result.events[11] = makeEvent(11, one, .{ d.result[0], d.result[1] });
    result.events[12] = makeEvent(12, one, .{ d.result[2], d.result[3] });
    result.events[13] = makeEvent(13, one, .{
        zero,             d.rd,             d.rd_previous_clock,
        d.rd_previous[0], d.rd_previous[1], d.rd_previous[2],
        d.rd_previous[3],
    });
    result.events[14] = makeEvent(14, one, .{
        zero,         d.rd,         destination_clock,
        d.rd_next[0], d.rd_next[1], d.rd_next[2],
        d.rd_next[3],
    });
    result.events[15] = makeEvent(15, one, .{destination_gap});
    return result;
}

fn makeEvent(
    comptime index: usize,
    liveness: M31,
    values: anytype,
) RelationEvent {
    const spec = EVENT_SPECS[index];
    comptime if (values.len != spec.arity)
        @compileError("typed BASE_ALU_IMM relation row arity drift");
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

inline fn isFamilyOpcode(row: TraceRow) bool {
    return switch (row.opcode) {
        .ADDI, .XORI, .ORI, .ANDI => true,
        else => false,
    };
}

inline fn resultFor(row: TraceRow) u32 {
    const immediate: u32 = @bitCast(row.imm);
    return switch (row.opcode) {
        .ADDI => row.rs1_val +% immediate,
        .XORI => row.rs1_val ^ immediate,
        .ORI => row.rs1_val | immediate,
        .ANDI => row.rs1_val & immediate,
        else => unreachable,
    };
}

inline fn opcodeId(row: TraceRow) u32 {
    return switch (row.opcode) {
        .ADDI => typed_addi.ADDI_OPCODE_ID,
        .XORI => typed_addi.XORI_OPCODE_ID,
        .ORI => typed_addi.ORI_OPCODE_ID,
        .ANDI => typed_addi.ANDI_OPCODE_ID,
        else => unreachable,
    };
}

inline fn bitwiseOperationId(row: TraceRow) u32 {
    return switch (row.opcode) {
        .XORI => 2,
        .ORI => 1,
        .ADDI, .ANDI => 0,
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

comptime {
    if (MAIN_COLUMN_COUNT != production_columns.BaseAluImmColumns.N_COLUMNS)
        @compileError("typed BASE_ALU_IMM witness width drifted from production");
    if (CANONICAL_OPERATIONS[0].opcode_id != 10 or
        CANONICAL_OPERATIONS[1].opcode_id != 13 or
        CANONICAL_OPERATIONS[2].opcode_id != 14 or
        CANONICAL_OPERATIONS[3].opcode_id != 15)
    {
        @compileError("typed BASE_ALU_IMM opcode identity drifted");
    }
    for (CANONICAL_RECIPE, 0..) |source, column| {
        if (@intFromEnum(source) != column)
            @compileError("typed BASE_ALU_IMM numeric recipe is not canonical");
    }
}
