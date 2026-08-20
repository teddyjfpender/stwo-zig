//! Authenticated, allocation-free witness authority for RV32 BASE_ALU_REG.
//!
//! Cold construction authenticates the native typed definition, every
//! physical source slot, and all five opcode/result policies. The hot path
//! writes final column-major storage directly and emits the exact 18 ordered
//! relation events without allocator, scratch, or handwritten delegation.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const direct_witness_executor = @import("direct_witness_executor.zig");
const digest = @import("digest.zig");
const program = @import("program.zig");
const relation = @import("relation.zig");
const production_columns = @import("../trace_columns/base.zig");
const trace_row = @import("../../runner/trace_row.zig");
const typed = @import("typed_base_alu_reg.zig");
const types = @import("types.zig");

pub const MAIN_COLUMN_COUNT: usize = typed.MAIN_COLUMN_COUNT;
pub const EVENT_COUNT: usize = typed.RELATION_EVENT_COUNT;
pub const MAX_EVENT_ARITY: usize = 7;
pub const TraceRow = trace_row.TraceRow;

pub const WITNESS_BINDING_FORMAT_VERSION: u16 = 1;
pub const WITNESS_BINDING_DOMAIN_SEPARATOR =
    "stwo-zig/typed-air/base-alu-reg-witness-binding/v1";
pub const WITNESS_BINDING_DIGEST_HEX =
    "303393f35211581e572e99f4ef5edc70949cf5e44744f7c7a8f031bf8f662c55";

pub const WITNESS_BINDING_DIGEST: digest.Digest = blk: {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, WITNESS_BINDING_DIGEST_HEX) catch
        @compileError("invalid typed BASE_ALU_REG witness-binding digest");
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
    trace_rs1_value_byte_0 = 13,
    trace_rs1_value_byte_1 = 14,
    trace_rs1_value_byte_2 = 15,
    trace_rs1_value_byte_3 = 16,
    trace_rs1_previous_clock = 17,
    trace_rs2_address = 18,
    trace_rs2_value_byte_0 = 19,
    trace_rs2_value_byte_1 = 20,
    trace_rs2_value_byte_2 = 21,
    trace_rs2_value_byte_3 = 22,
    trace_rs2_previous_clock = 23,
    derived_add_flag = 24,
    derived_sub_flag = 25,
    derived_xor_flag = 26,
    derived_or_flag = 27,
    derived_and_flag = 28,
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
    .trace_rs1_value_byte_0,
    .trace_rs1_value_byte_1,
    .trace_rs1_value_byte_2,
    .trace_rs1_value_byte_3,
    .trace_rs1_previous_clock,
    .trace_rs2_address,
    .trace_rs2_value_byte_0,
    .trace_rs2_value_byte_1,
    .trace_rs2_value_byte_2,
    .trace_rs2_value_byte_3,
    .trace_rs2_previous_clock,
    .derived_add_flag,
    .derived_sub_flag,
    .derived_xor_flag,
    .derived_or_flag,
    .derived_and_flag,
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
    rv32_wrapping_add = 0,
    rv32_wrapping_sub = 1,
    rv32_bitwise_xor = 2,
    rv32_bitwise_or = 3,
    rv32_bitwise_and = 4,
};

pub const OperationBinding = struct {
    opcode_id: u32,
    flag_column: u8,
    result: ResultAlgorithm,
    bitwise_active: bool,
    bitwise_operation_id: u8,
};

pub const CANONICAL_OPERATIONS = [5]OperationBinding{
    .{
        .opcode_id = typed.ADD_OPCODE_ID,
        .flag_column = 24,
        .result = .rv32_wrapping_add,
        .bitwise_active = false,
        .bitwise_operation_id = 0,
    },
    .{
        .opcode_id = typed.SUB_OPCODE_ID,
        .flag_column = 25,
        .result = .rv32_wrapping_sub,
        .bitwise_active = false,
        .bitwise_operation_id = 0,
    },
    .{
        .opcode_id = typed.XOR_OPCODE_ID,
        .flag_column = 26,
        .result = .rv32_bitwise_xor,
        .bitwise_active = true,
        .bitwise_operation_id = 2,
    },
    .{
        .opcode_id = typed.OR_OPCODE_ID,
        .flag_column = 27,
        .result = .rv32_bitwise_or,
        .bitwise_active = true,
        .bitwise_operation_id = 1,
    },
    .{
        .opcode_id = typed.AND_OPCODE_ID,
        .flag_column = 28,
        .result = .rv32_bitwise_and,
        .bitwise_active = true,
        .bitwise_operation_id = 0,
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
    .{ .kind = .bitwise_request, .domain = .bitwise, .role = .request, .arity = 4 },
    .{ .kind = .bitwise_request, .domain = .bitwise, .role = .request, .arity = 4 },
    .{ .kind = .bitwise_request, .domain = .bitwise, .role = .request, .arity = 4 },
    .{ .kind = .bitwise_request, .domain = .bitwise, .role = .request, .arity = 4 },
    .{ .kind = .range_request, .domain = .range_check_8_8, .role = .request, .arity = 2 },
    .{ .kind = .range_request, .domain = .range_check_8_8, .role = .request, .arity = 2 },
    .{ .kind = .register_write, .domain = .memory_access, .role = .consume, .arity = 7, .access_ordinal = 3 },
    .{ .kind = .register_write, .domain = .memory_access, .role = .emit, .arity = 7, .access_ordinal = 3 },
    .{ .kind = .register_write, .domain = .range_check_20, .role = .request, .arity = 1, .access_ordinal = 3 },
};

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
            hashInt(&hash, u8, @intFromEnum(operation.result));
            hashInt(&hash, u8, @intFromBool(operation.bitwise_active));
            hashInt(&hash, u8, operation.bitwise_operation_id);
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
    rs2: M31,
    rs2_value: [4]M31,
    rs2_previous_clock: M31,
    opcode_id: M31,
    operation_id: M31,
    bitwise_active: M31,
    flags: [5]M31,
    result: [4]M31,
    destination_nonzero: M31,
    destination_inverse: M31,
};

inline fn decodeRow(row: TraceRow) DecodedRow {
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
        .rs2 = fromUnsigned(row.rs2),
        .rs2_value = limbs(row.rs2_val),
        .rs2_previous_clock = fromUnsigned(row.rs2_prev_clk),
        .opcode_id = fromUnsigned(opcodeId(row)),
        .operation_id = fromUnsigned(bitwiseOperationId(row)),
        .bitwise_active = flag(isBitwise(row)),
        .flags = .{
            flag(row.opcode == .ADD),
            flag(row.opcode == .SUB),
            flag(row.opcode == .XOR),
            flag(row.opcode == .OR),
            flag(row.opcode == .AND),
        },
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
            .trace_rs1_value_byte_0 => d.rs1_value[0],
            .trace_rs1_value_byte_1 => d.rs1_value[1],
            .trace_rs1_value_byte_2 => d.rs1_value[2],
            .trace_rs1_value_byte_3 => d.rs1_value[3],
            .trace_rs1_previous_clock => d.rs1_previous_clock,
            .trace_rs2_address => d.rs2,
            .trace_rs2_value_byte_0 => d.rs2_value[0],
            .trace_rs2_value_byte_1 => d.rs2_value[1],
            .trace_rs2_value_byte_2 => d.rs2_value[2],
            .trace_rs2_value_byte_3 => d.rs2_value[3],
            .trace_rs2_previous_clock => d.rs2_previous_clock,
            .derived_add_flag => d.flags[0],
            .derived_sub_flag => d.flags[1],
            .derived_xor_flag => d.flags[2],
            .derived_or_flag => d.flags[3],
            .derived_and_flag => d.flags[4],
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
    const expected = resultFor(row);
    if (row.rd_val != (if (row.rd == 0) 0 else expected))
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
    inline for (0..4) |limb| result.events[9 + limb] = makeEvent(
        9 + limb,
        d.bitwise_active,
        .{ d.rs1_value[limb], d.rs2_value[limb], d.result[limb], d.operation_id },
    );
    result.events[13] = makeEvent(13, one, .{ d.result[0], d.result[1] });
    result.events[14] = makeEvent(14, one, .{ d.result[2], d.result[3] });
    result.events[15] = makeEvent(15, one, .{
        zero,             d.rd,             d.rd_previous_clock,
        d.rd_previous[0], d.rd_previous[1], d.rd_previous[2],
        d.rd_previous[3],
    });
    result.events[16] = makeEvent(16, one, .{
        zero,         d.rd,         destination_clock,
        d.rd_next[0], d.rd_next[1], d.rd_next[2],
        d.rd_next[3],
    });
    result.events[17] = makeEvent(17, one, .{destination_gap});
    return result;
}

fn makeEvent(
    comptime index: usize,
    liveness: M31,
    values: anytype,
) RelationEvent {
    const spec = EVENT_SPECS[index];
    comptime if (values.len != spec.arity)
        @compileError("typed BASE_ALU_REG relation row arity drift");
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
        .ADD, .SUB, .XOR, .OR, .AND => true,
        else => false,
    };
}

inline fn resultFor(row: TraceRow) u32 {
    return switch (row.opcode) {
        .ADD => row.rs1_val +% row.rs2_val,
        .SUB => row.rs1_val -% row.rs2_val,
        .XOR => row.rs1_val ^ row.rs2_val,
        .OR => row.rs1_val | row.rs2_val,
        .AND => row.rs1_val & row.rs2_val,
        else => unreachable,
    };
}

inline fn opcodeId(row: TraceRow) u32 {
    return switch (row.opcode) {
        .ADD => typed.ADD_OPCODE_ID,
        .SUB => typed.SUB_OPCODE_ID,
        .XOR => typed.XOR_OPCODE_ID,
        .OR => typed.OR_OPCODE_ID,
        .AND => typed.AND_OPCODE_ID,
        else => unreachable,
    };
}

inline fn isBitwise(row: TraceRow) bool {
    return switch (row.opcode) {
        .XOR, .OR, .AND => true,
        .ADD, .SUB => false,
        else => unreachable,
    };
}

inline fn bitwiseOperationId(row: TraceRow) u32 {
    return switch (row.opcode) {
        .XOR => 2,
        .OR => 1,
        .ADD, .SUB, .AND => 0,
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
    if (MAIN_COLUMN_COUNT != production_columns.BaseAluRegColumns.N_COLUMNS)
        @compileError("typed BASE_ALU_REG witness width drifted from production");
    if (EVENT_COUNT != 18 or MAX_EVENT_ARITY != relation.get(.memory_access).fields.len)
        @compileError("typed BASE_ALU_REG relation geometry drifted");
    for (CANONICAL_RECIPE, 0..) |source, column| {
        if (@intFromEnum(source) != column)
            @compileError("typed BASE_ALU_REG numeric recipe is not canonical");
    }
}
