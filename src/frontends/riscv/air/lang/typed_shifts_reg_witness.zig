//! Authenticated, allocation-free witness authority for RV32 SHIFTS_REG.
//!
//! Cold construction authenticates the native typed definition, every
//! physical source slot, and all three shift policies. The hot path writes
//! final column-major storage directly and emits the exact 20 ordered relation
//! events without allocator, scratch trace, or handwritten delegation.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const direct_witness_executor = @import("direct_witness_executor.zig");
const digest = @import("digest.zig");
const program = @import("program.zig");
const relation = @import("relation.zig");
const production_columns = @import("../trace_columns/base.zig");
const trace_row = @import("../../runner/trace_row.zig");
const typed = @import("typed_shifts_reg.zig");
const types = @import("types.zig");

pub const MAIN_COLUMN_COUNT: usize = typed.MAIN_COLUMN_COUNT;
pub const EVENT_COUNT: usize = typed.RELATION_EVENT_COUNT;
pub const MAX_EVENT_ARITY: usize = 7;
pub const TraceRow = trace_row.TraceRow;

pub const WITNESS_BINDING_FORMAT_VERSION: u16 = 1;
pub const WITNESS_BINDING_DOMAIN_SEPARATOR =
    "stwo-zig/typed-air/shifts-reg-witness-binding/v1";
pub const WITNESS_BINDING_DIGEST_HEX =
    "df63c869e2d34e44b9d1bef63edf53dc4395bc4945316724f06ea92e485a6d20";

pub const WITNESS_BINDING_DIGEST: digest.Digest = blk: {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, WITNESS_BINDING_DIGEST_HEX) catch
        @compileError("invalid typed SHIFTS_REG witness-binding digest");
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
    trace_rs2_address = 22,
    trace_rs2_value_previous_byte_0 = 23,
    trace_rs2_value_previous_byte_1 = 24,
    trace_rs2_value_previous_byte_2 = 25,
    trace_rs2_value_previous_byte_3 = 26,
    trace_rs2_previous_clock = 27,
    trace_rs2_value_next_byte_0 = 28,
    trace_rs2_value_next_byte_1 = 29,
    trace_rs2_value_next_byte_2 = 30,
    trace_rs2_value_next_byte_3 = 31,
    derived_rs1_sign = 32,
    derived_sll_flag = 33,
    derived_srl_flag = 34,
    derived_sra_flag = 35,
    derived_bit_multiplier_left = 36,
    derived_bit_multiplier_right = 37,
    derived_bit_marker_0 = 38,
    derived_bit_marker_1 = 39,
    derived_bit_marker_2 = 40,
    derived_bit_marker_3 = 41,
    derived_bit_marker_4 = 42,
    derived_bit_marker_5 = 43,
    derived_bit_marker_6 = 44,
    derived_bit_marker_7 = 45,
    derived_limb_marker_0 = 46,
    derived_limb_marker_1 = 47,
    derived_limb_marker_2 = 48,
    derived_limb_marker_3 = 49,
    derived_carry_0 = 50,
    derived_carry_1 = 51,
    derived_carry_2 = 52,
    derived_carry_3 = 53,
    derived_result_byte_0 = 54,
    derived_result_byte_1 = 55,
    derived_result_byte_2 = 56,
    derived_result_byte_3 = 57,
    hint_rd_nonzero = 58,
    hint_rd_inverse_or_zero = 59,
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
    .derived_rs1_sign,
    .derived_sll_flag,
    .derived_srl_flag,
    .derived_sra_flag,
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
    rv32_logical_left_low_five = 0,
    rv32_logical_right_low_five = 1,
    rv32_arithmetic_right_low_five = 2,
};

pub const OperationBinding = struct {
    opcode_id: u32,
    flag_column: u8,
    algorithm: ShiftAlgorithm,
};

pub const CANONICAL_OPERATIONS = [3]OperationBinding{
    .{
        .opcode_id = typed.SLL_OPCODE_ID,
        .flag_column = 33,
        .algorithm = .rv32_logical_left_low_five,
    },
    .{
        .opcode_id = typed.SRL_OPCODE_ID,
        .flag_column = 34,
        .algorithm = .rv32_logical_right_low_five,
    },
    .{
        .opcode_id = typed.SRA_OPCODE_ID,
        .flag_column = 35,
        .algorithm = .rv32_arithmetic_right_low_five,
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
    for (&slots, physical, CANONICAL_RECIPE, 0..) |*slot, value, source_value, column| {
        slot.* = .{ .column = @intCast(column), .value = value, .source = source_value };
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
    rs2: M31,
    rs2_value: [4]M31,
    rs2_previous_clock: M31,
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
    const amount: u5 = @truncate(row.rs2_val);
    const bit_shift: u3 = @truncate(amount);
    const limb_shift: u2 = @truncate(amount >> 3);
    const left = row.opcode == .SLL;
    const arithmetic = row.opcode == .SRA;
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
        .rs2 = fromUnsigned(row.rs2),
        .rs2_value = limbs(row.rs2_val),
        .rs2_previous_clock = fromUnsigned(row.rs2_prev_clk),
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

pub inline fn writeActiveRow(
    columns: anytype,
    row_index: usize,
    row: TraceRow,
) void {
    const amount: u5 = @truncate(row.rs2_val);
    const left = row.opcode == .SLL;
    const arithmetic = row.opcode == .SRA;
    const shift = computeShift(row.rs1_val, amount, left, arithmetic);
    const multiplier = @as(u32, 1) << @as(u3, @truncate(amount));

    set(columns, row_index, 0, fromUnsigned(row.clk));
    set(columns, row_index, 1, fromUnsigned(row.pc));
    writeAccess(columns, row_index, 2, row.rd, row.rd_prev_val, row.rd_prev_clk, row.rd_val);
    writeAccess(columns, row_index, 12, row.rs1, row.rs1_val, row.rs1_prev_clk, row.rs1_val);
    writeAccess(columns, row_index, 22, row.rs2, row.rs2_val, row.rs2_prev_clk, row.rs2_val);
    set(columns, row_index, 32, fromUnsigned(shift.sign));
    set(columns, row_index, 33, flag(left));
    set(columns, row_index, 34, flag(!left and !arithmetic));
    set(columns, row_index, 35, flag(arithmetic));
    set(columns, row_index, 36, fromUnsigned(if (left) multiplier else 0));
    set(columns, row_index, 37, fromUnsigned(if (left) 0 else multiplier));
    for (shift.bit_markers, 0..) |marker, marker_index|
        set(columns, row_index, 38 + marker_index, fromUnsigned(marker));
    for (shift.limb_markers, 0..) |marker, marker_index|
        set(columns, row_index, 46 + marker_index, fromUnsigned(marker));
    for (shift.carries, 0..) |carry, carry_index|
        set(columns, row_index, 50 + carry_index, fromUnsigned(carry));
    writeWord(columns, row_index, 54, shiftedValue(row.rs1_val, amount, left, arithmetic));
    writeDestination(columns, row_index, 58, row.rd);
}

const ShiftWitness = struct {
    sign: u32,
    bit_markers: [8]u32,
    limb_markers: [4]u32,
    carries: [4]u32,
};

fn computeShift(value: u32, amount: u5, left: bool, arithmetic: bool) ShiftWitness {
    const bit_shift: u3 = @truncate(amount);
    const limb_shift: u2 = @truncate(amount >> 3);
    var result = ShiftWitness{
        .sign = if (arithmetic) value >> 31 else 0,
        .bit_markers = .{0} ** 8,
        .limb_markers = .{0} ** 4,
        .carries = .{0} ** 4,
    };
    result.bit_markers[bit_shift] = 1;
    result.limb_markers[limb_shift] = 1;
    for (0..4) |index| {
        const byte: u8 = @truncate(value >> @intCast(8 * index));
        result.carries[index] = if (bit_shift == 0)
            0
        else if (left)
            @as(u32, byte) >> @intCast(8 - @as(u4, bit_shift))
        else
            @as(u32, byte) & ((@as(u32, 1) << bit_shift) - 1);
    }
    return result;
}

fn shiftedValue(value: u32, amount: u5, left: bool, arithmetic: bool) u32 {
    if (left) return value << amount;
    if (!arithmetic) return value >> amount;
    const signed: i32 = @bitCast(value);
    return @bitCast(signed >> amount);
}

inline fn set(columns: anytype, row_index: usize, column: usize, value: M31) void {
    columns[column][row_index] = value;
}

fn writeAccess(
    columns: anytype,
    row_index: usize,
    start: usize,
    address: u32,
    previous: u32,
    previous_clock: u32,
    next: u32,
) void {
    set(columns, row_index, start, fromUnsigned(address));
    writeWord(columns, row_index, start + 1, previous);
    set(columns, row_index, start + 5, fromUnsigned(previous_clock));
    writeWord(columns, row_index, start + 6, next);
}

fn writeWord(
    columns: anytype,
    row_index: usize,
    start: usize,
    value: u32,
) void {
    for (limbs(value), 0..) |limb, index|
        set(columns, row_index, start + index, limb);
}

fn writeDestination(
    columns: anytype,
    row_index: usize,
    start: usize,
    address: u5,
) void {
    const address_felt = fromUnsigned(address);
    const nonzero = address != 0;
    set(columns, row_index, start, flag(nonzero));
    set(
        columns,
        row_index,
        start + 1,
        if (nonzero) address_felt.invUncheckedNonZero() else M31.zero(),
    );
}

fn validateRow(row: TraceRow) ExecutionError!void {
    if (!isFamilyOpcode(row) or row.imm != 0 or row.clk == 0 or
        row.next_pc != row.pc +% 4 or row.is_load or row.is_store or
        row.branch_taken)
    {
        return error.InvalidTraceRow;
    }
    const source_1_clock = accessClock(row.clk, 1) orelse
        return error.InvalidTraceRow;
    const source_2_clock = accessClock(row.clk, 2) orelse
        return error.InvalidTraceRow;
    const destination_clock = accessClock(row.clk, 3) orelse
        return error.InvalidTraceRow;
    if (!validGap(row.rs1_prev_clk, source_1_clock) or
        !validGap(row.rs2_prev_clk, source_2_clock) or
        !validGap(row.rd_prev_clk, destination_clock))
    {
        return error.InvalidTraceRow;
    }
    if ((row.rs1 == 0 and row.rs1_val != 0) or
        (row.rs2 == 0 and row.rs2_val != 0) or
        (row.rd == 0 and row.rd_prev_val != 0) or
        (row.rs1 == row.rs2 and
            (row.rs1_val != row.rs2_val or row.rs2_prev_clk != source_1_clock)))
    {
        return error.InvalidTraceRow;
    }
    const expected_previous_clock = if (row.rd == row.rs2)
        source_2_clock
    else if (row.rd == row.rs1)
        source_1_clock
    else
        row.rd_prev_clk;
    const expected_previous_value = if (row.rd == row.rs2)
        row.rs2_val
    else if (row.rd == row.rs1)
        row.rs1_val
    else
        row.rd_prev_val;
    if ((row.rd == row.rs1 or row.rd == row.rs2) and
        (row.rd_prev_clk != expected_previous_clock or
            row.rd_prev_val != expected_previous_value))
    {
        return error.InvalidTraceRow;
    }
    if (row.rd_val != (if (row.rd == 0) 0 else resultFor(row)))
        return error.InvalidTraceRow;
}

fn buildRelationRow(row: TraceRow) RelationRow {
    const d = decodeRow(row);
    const one = M31.one();
    const zero = M31.zero();
    const four = fromUnsigned(4);
    const source_1_clock = d.clock.sub(one).mul(four).add(one);
    const source_2_clock = d.clock.sub(one).mul(four).add(fromUnsigned(2));
    const destination_clock = d.clock.sub(one).mul(four).add(fromUnsigned(3));
    const source_1_gap = source_1_clock.sub(d.rs1_previous_clock).sub(one);
    const source_2_gap = source_2_clock.sub(d.rs2_previous_clock).sub(one);
    const destination_gap = destination_clock.sub(d.rd_previous_clock).sub(one);
    const carry_upper = d.bit_multiplier.sub(one);
    const shift_range_value = fromUnsigned(7 - ((row.rs2_val & 0xff) >> 5));

    var result: RelationRow = undefined;
    result.events[0] = makeEvent(0, one, .{
        d.pc, d.opcode_id, d.rd, d.rs1, d.rs2,
    });
    result.events[1] = makeEvent(1, one, .{ d.pc, d.clock });
    result.events[2] = makeEvent(2, one, .{ d.pc.add(four), d.clock.add(one) });
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
    result.events[5] = makeEvent(5, one, .{source_1_gap});
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
    result.events[8] = makeEvent(8, one, .{source_2_gap});
    result.events[9] = makeEvent(9, one, .{shift_range_value});
    inline for (0..4) |limb| result.events[10 + limb] = makeEvent(
        10 + limb,
        one,
        .{ d.carries[limb], carry_upper.sub(d.carries[limb]) },
    );
    result.events[14] = makeEvent(14, one, .{ d.result[0], d.result[1] });
    result.events[15] = makeEvent(15, one, .{ d.result[2], d.result[3] });
    result.events[16] = makeEvent(16, one, .{
        zero,             d.rd,             d.rd_previous_clock,
        d.rd_previous[0], d.rd_previous[1], d.rd_previous[2],
        d.rd_previous[3],
    });
    result.events[17] = makeEvent(17, one, .{
        zero,         d.rd,         destination_clock,
        d.rd_next[0], d.rd_next[1], d.rd_next[2],
        d.rd_next[3],
    });
    result.events[18] = makeEvent(18, one, .{destination_gap});
    result.events[19] = makeEvent(19, d.flags[2], .{
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
        @compileError("typed SHIFTS_REG relation row arity drift");
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
        .SLL, .SRL, .SRA => true,
        else => false,
    };
}

inline fn resultFor(row: TraceRow) u32 {
    const amount: u5 = @truncate(row.rs2_val);
    return switch (row.opcode) {
        .SLL => row.rs1_val << amount,
        .SRL => row.rs1_val >> amount,
        .SRA => @bitCast(@as(i32, @bitCast(row.rs1_val)) >> amount),
        else => unreachable,
    };
}

inline fn opcodeId(row: TraceRow) u32 {
    return switch (row.opcode) {
        .SLL => typed.SLL_OPCODE_ID,
        .SRL => typed.SRL_OPCODE_ID,
        .SRA => typed.SRA_OPCODE_ID,
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
    if (MAIN_COLUMN_COUNT != production_columns.ShiftsRegColumns.N_COLUMNS)
        @compileError("typed SHIFTS_REG witness width drifted from production");
    if (EVENT_COUNT != 20 or MAX_EVENT_ARITY != relation.get(.memory_access).fields.len)
        @compileError("typed SHIFTS_REG relation geometry drifted");
    if (CANONICAL_OPERATIONS[0].opcode_id != 2 or
        CANONICAL_OPERATIONS[1].opcode_id != 6 or
        CANONICAL_OPERATIONS[2].opcode_id != 7)
    {
        @compileError("typed SHIFTS_REG opcode identity drifted");
    }
    for (CANONICAL_RECIPE, 0..) |source_value, column| {
        if (@intFromEnum(source_value) != column)
            @compileError("typed SHIFTS_REG numeric recipe is not canonical");
    }
}
