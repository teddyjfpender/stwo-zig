//! Authenticated, allocation-free witness authority for RV32 SHIFTS_IMM.
//!
//! Cold construction authenticates the native typed definition, every
//! physical source slot, and all three shift policies. The hot path writes
//! final column-major storage directly and emits the exact 16 ordered relation
//! events without allocator, scratch trace, or handwritten delegation.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const direct_witness_executor = @import("direct_witness_executor.zig");
const digest = @import("digest.zig");
const program = @import("program.zig");
const relation = @import("relation.zig");
const production_columns = @import("../trace_columns/base.zig");
const trace_row = @import("../../runner/trace_row.zig");
const typed = @import("typed_shifts_imm.zig");
const types = @import("types.zig");

pub const MAIN_COLUMN_COUNT: usize = typed.MAIN_COLUMN_COUNT;
pub const EVENT_COUNT: usize = typed.RELATION_EVENT_COUNT;
pub const MAX_EVENT_ARITY: usize = 7;
pub const TraceRow = trace_row.TraceRow;

pub const WITNESS_BINDING_FORMAT_VERSION: u16 = 1;
pub const WITNESS_BINDING_DOMAIN_SEPARATOR =
    "stwo-zig/typed-air/shifts-imm-witness-binding/v1";
pub const WITNESS_BINDING_DIGEST_HEX =
    "456da6514e3b104bf3ae8426423de0a2cdaa03428dd7d59c3df69c110e172925";

pub const WITNESS_BINDING_DIGEST: digest.Digest = blk: {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, WITNESS_BINDING_DIGEST_HEX) catch
        @compileError("invalid typed SHIFTS_IMM witness-binding digest");
    break :blk result;
};

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
    derived_rs1_sign = 22,
    trace_shift_amount = 23,
    derived_slli_flag = 24,
    derived_srli_flag = 25,
    derived_srai_flag = 26,
    derived_bit_multiplier_left = 27,
    derived_bit_multiplier_right = 28,
    derived_bit_marker_0 = 29,
    derived_bit_marker_1 = 30,
    derived_bit_marker_2 = 31,
    derived_bit_marker_3 = 32,
    derived_bit_marker_4 = 33,
    derived_bit_marker_5 = 34,
    derived_bit_marker_6 = 35,
    derived_bit_marker_7 = 36,
    derived_limb_marker_0 = 37,
    derived_limb_marker_1 = 38,
    derived_limb_marker_2 = 39,
    derived_limb_marker_3 = 40,
    derived_carry_0 = 41,
    derived_carry_1 = 42,
    derived_carry_2 = 43,
    derived_carry_3 = 44,
    derived_result_byte_0 = 45,
    derived_result_byte_1 = 46,
    derived_result_byte_2 = 47,
    derived_result_byte_3 = 48,
    hint_rd_nonzero = 49,
    hint_rd_inverse_or_zero = 50,
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
    .derived_rs1_sign,
    .trace_shift_amount,
    .derived_slli_flag,
    .derived_srli_flag,
    .derived_srai_flag,
    .derived_bit_multiplier_left,
    .derived_bit_multiplier_right,
    .derived_bit_marker_0,
    .derived_bit_marker_1,
    .derived_bit_marker_2,
    .derived_bit_marker_3,
    .derived_bit_marker_4,
    .derived_bit_marker_5,
    .derived_bit_marker_6,
    .derived_bit_marker_7,
    .derived_limb_marker_0,
    .derived_limb_marker_1,
    .derived_limb_marker_2,
    .derived_limb_marker_3,
    .derived_carry_0,
    .derived_carry_1,
    .derived_carry_2,
    .derived_carry_3,
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

pub const ShiftAlgorithm = enum(u8) {
    rv32_logical_left = 0,
    rv32_logical_right = 1,
    rv32_arithmetic_right = 2,
};

pub const OperationBinding = struct {
    opcode_id: u32,
    flag_column: u8,
    algorithm: ShiftAlgorithm,
};

pub const CANONICAL_OPERATIONS = [3]OperationBinding{
    .{
        .opcode_id = typed.SLLI_OPCODE_ID,
        .flag_column = 24,
        .algorithm = .rv32_logical_left,
    },
    .{
        .opcode_id = typed.SRLI_OPCODE_ID,
        .flag_column = 25,
        .algorithm = .rv32_logical_right,
    },
    .{
        .opcode_id = typed.SRAI_OPCODE_ID,
        .flag_column = 26,
        .algorithm = .rv32_arithmetic_right,
    },
};

pub const EVENT_SPECS = typed.EVENT_SPECS;

pub const WitnessBinding = struct {
    format_version: u16,
    semantic_format_version: u16,
    semantic_digest: digest.Digest,
    slots: [MAIN_COLUMN_COUNT]SlotBinding,
    operations: [CANONICAL_OPERATIONS.len]OperationBinding,

    pub fn canonical(definition: *const typed.Definition) ConstructionError!WitnessBinding {
        try definition.validate();
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
            hashInt(&hash, u8, @intFromEnum(operation.algorithm));
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
            .request, .consume => M31.zero().sub(self.liveness),
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
        .semantic_format_version = digest.typed_lookup_request_format_version,
        .semantic_digest = typed.SEMANTIC_DIGEST,
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
    rs1_sign: M31,
    amount: u5,
    amount_felt: M31,
    opcode_id: M31,
    flags: [3]M31,
    bit_multiplier: M31,
    bit_multiplier_left: M31,
    bit_multiplier_right: M31,
    bit_markers: [8]M31,
    limb_markers: [4]M31,
    carries: [4]M31,
    result: [4]M31,
    destination_nonzero: M31,
    destination_inverse: M31,
};

inline fn decodeRow(row: TraceRow) DecodedRow {
    const amount: u5 = @intCast(row.imm);
    const bit_shift: u3 = @truncate(amount);
    const limb_shift: u2 = @truncate(amount >> 3);
    const left = row.opcode == .SLLI;
    const arithmetic = row.opcode == .SRAI;
    const multiplier = @as(u32, 1) << bit_shift;
    const rd = fromUnsigned(row.rd);
    var bit_markers = [_]M31{M31.zero()} ** 8;
    var limb_markers = [_]M31{M31.zero()} ** 4;
    var carries = [_]M31{M31.zero()} ** 4;
    bit_markers[bit_shift] = M31.one();
    limb_markers[limb_shift] = M31.one();
    inline for (0..4) |index| {
        const byte: u8 = @truncate(row.rs1_val >> @intCast(8 * index));
        const carry = if (bit_shift == 0)
            0
        else if (left)
            @as(u32, byte) >> @intCast(8 - @as(u4, bit_shift))
        else
            @as(u32, byte) & ((@as(u32, 1) << bit_shift) - 1);
        carries[index] = fromUnsigned(carry);
    }
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
        .rs1_sign = flag(arithmetic and (row.rs1_val >> 31) != 0),
        .amount = amount,
        .amount_felt = fromUnsigned(amount),
        .opcode_id = fromUnsigned(opcodeId(row)),
        .flags = .{ flag(left), flag(!left and !arithmetic), flag(arithmetic) },
        .bit_multiplier = fromUnsigned(multiplier),
        .bit_multiplier_left = fromUnsigned(if (left) multiplier else 0),
        .bit_multiplier_right = fromUnsigned(if (left) 0 else multiplier),
        .bit_markers = bit_markers,
        .limb_markers = limb_markers,
        .carries = carries,
        .result = limbs(resultFor(row)),
        .destination_nonzero = flag(row.rd != 0),
        .destination_inverse = if (row.rd == 0)
            M31.zero()
        else
            rd.invUncheckedNonZero(),
    };
}

/// Direct final-storage writer selected after family classification.
pub inline fn writeActiveRow(
    columns: anytype,
    row_index: usize,
    row: TraceRow,
) void {
    const d = decodeRow(row);
    inline for (CANONICAL_RECIPE, 0..) |source_value, column| {
        columns[column][row_index] = switch (source_value) {
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
            .derived_rs1_sign => d.rs1_sign,
            .trace_shift_amount => d.amount_felt,
            .derived_slli_flag => d.flags[0],
            .derived_srli_flag => d.flags[1],
            .derived_srai_flag => d.flags[2],
            .derived_bit_multiplier_left => d.bit_multiplier_left,
            .derived_bit_multiplier_right => d.bit_multiplier_right,
            .derived_bit_marker_0 => d.bit_markers[0],
            .derived_bit_marker_1 => d.bit_markers[1],
            .derived_bit_marker_2 => d.bit_markers[2],
            .derived_bit_marker_3 => d.bit_markers[3],
            .derived_bit_marker_4 => d.bit_markers[4],
            .derived_bit_marker_5 => d.bit_markers[5],
            .derived_bit_marker_6 => d.bit_markers[6],
            .derived_bit_marker_7 => d.bit_markers[7],
            .derived_limb_marker_0 => d.limb_markers[0],
            .derived_limb_marker_1 => d.limb_markers[1],
            .derived_limb_marker_2 => d.limb_markers[2],
            .derived_limb_marker_3 => d.limb_markers[3],
            .derived_carry_0 => d.carries[0],
            .derived_carry_1 => d.carries[1],
            .derived_carry_2 => d.carries[2],
            .derived_carry_3 => d.carries[3],
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
    if (!isFamilyOpcode(row) or row.imm < 0 or row.imm > 31 or row.clk == 0 or
        row.next_pc != row.pc +% 4 or row.is_load or row.is_store or
        row.branch_taken)
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
    if ((row.rs1 == 0 and row.rs1_val != 0) or
        (row.rd == 0 and row.rd_prev_val != 0) or
        row.rd_val != (if (row.rd == 0) 0 else resultFor(row)))
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
    const carry_upper = d.bit_multiplier.sub(one);

    var result: RelationRow = undefined;
    result.events[0] = makeEvent(0, one, .{
        d.pc, d.opcode_id, d.rd, d.rs1, d.amount_felt,
    });
    result.events[1] = makeEvent(1, one, .{ d.pc, d.clock });
    result.events[2] = makeEvent(2, one, .{ d.pc.add(four), d.clock.add(one) });
    result.events[3] = makeEvent(3, one, .{
        zero,           d.rs1,          d.rs1_previous_clock,
        d.rs1_value[0], d.rs1_value[1], d.rs1_value[2],
        d.rs1_value[3],
    });
    result.events[4] = makeEvent(4, one, .{
        zero,           d.rs1,          source_clock,
        d.rs1_value[0], d.rs1_value[1], d.rs1_value[2],
        d.rs1_value[3],
    });
    result.events[5] = makeEvent(5, one, .{source_gap});
    inline for (0..4) |limb| result.events[6 + limb] = makeEvent(
        6 + limb,
        one,
        .{ d.carries[limb], carry_upper.sub(d.carries[limb]) },
    );
    result.events[10] = makeEvent(10, one, .{ d.result[0], d.result[1] });
    result.events[11] = makeEvent(11, one, .{ d.result[2], d.result[3] });
    result.events[12] = makeEvent(12, one, .{
        zero,             d.rd,             d.rd_previous_clock,
        d.rd_previous[0], d.rd_previous[1], d.rd_previous[2],
        d.rd_previous[3],
    });
    result.events[13] = makeEvent(13, one, .{
        zero,         d.rd,         destination_clock,
        d.rd_next[0], d.rd_next[1], d.rd_next[2],
        d.rd_next[3],
    });
    result.events[14] = makeEvent(14, one, .{destination_gap});
    result.events[15] = makeEvent(15, d.flags[2], .{
        zero,
        d.rs1_value[3].sub(d.rs1_sign.mul(fromUnsigned(128))),
    });
    return result;
}

fn makeEvent(
    comptime index: usize,
    liveness: M31,
    values: anytype,
) RelationEvent {
    const spec = EVENT_SPECS[index];
    comptime if (values.len != spec.arity)
        @compileError("typed SHIFTS_IMM relation row arity drift");
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
        .SLLI, .SRLI, .SRAI => true,
        else => false,
    };
}

inline fn resultFor(row: TraceRow) u32 {
    const amount: u5 = @intCast(row.imm);
    return switch (row.opcode) {
        .SLLI => row.rs1_val << amount,
        .SRLI => row.rs1_val >> amount,
        .SRAI => @bitCast(@as(i32, @bitCast(row.rs1_val)) >> amount),
        else => unreachable,
    };
}

inline fn opcodeId(row: TraceRow) u32 {
    return switch (row.opcode) {
        .SLLI => typed.SLLI_OPCODE_ID,
        .SRLI => typed.SRLI_OPCODE_ID,
        .SRAI => typed.SRAI_OPCODE_ID,
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
    if (MAIN_COLUMN_COUNT != production_columns.ShiftsImmColumns.N_COLUMNS)
        @compileError("typed SHIFTS_IMM witness width drifted from production");
    if (EVENT_COUNT != 16 or MAX_EVENT_ARITY != relation.get(.memory_access).fields.len)
        @compileError("typed SHIFTS_IMM relation geometry drifted");
    if (CANONICAL_OPERATIONS[0].opcode_id != 16 or
        CANONICAL_OPERATIONS[1].opcode_id != 17 or
        CANONICAL_OPERATIONS[2].opcode_id != 18)
    {
        @compileError("typed SHIFTS_IMM opcode identity drifted");
    }
    for (CANONICAL_RECIPE, 0..) |source_value, column| {
        if (@intFromEnum(source_value) != column)
            @compileError("typed SHIFTS_IMM numeric recipe is not canonical");
    }
}
