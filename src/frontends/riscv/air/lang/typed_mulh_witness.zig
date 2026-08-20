//! Authenticated, allocation-free witness authority for RV32 high-word multiply.
//!
//! Cold construction authenticates the native typed definition, the exact
//! 47-column physical recipe, and the signedness policy of `MULH`, `MULHSU`,
//! and `MULHU`. The hot loop remains a direct scalar writer. Derived carry
//! work is confined to relation generation and therefore does not inflate the
//! committed main-trace path.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const direct_witness_executor = @import("direct_witness_executor.zig");
const digest = @import("digest.zig");
const program = @import("program.zig");
const production_columns = @import("../trace_columns/m_extension.zig");
const relation = @import("relation.zig");
const trace_row = @import("../../runner/trace_row.zig");
const typed = @import("typed_mulh.zig");
const types = @import("types.zig");

pub const MAIN_COLUMN_COUNT: usize = typed.MAIN_COLUMN_COUNT;
pub const EVENT_COUNT: usize = typed.LOOKUP_COUNT;
pub const MAX_EVENT_ARITY: usize = 7;
pub const TraceRow = trace_row.TraceRow;

pub const WITNESS_BINDING_FORMAT_VERSION: u16 = 1;
pub const WITNESS_BINDING_DOMAIN_SEPARATOR =
    "stwo-zig/typed-air/mulh-witness-binding/v1";
pub const WITNESS_BINDING_DIGEST_HEX =
    "af742d11e7259a13e1e16a7a6f607d5fe641e62e6b1d1551fe005854cf3f2ea2";
pub const WITNESS_BINDING_DIGEST: digest.Digest = hexDigest(
    WITNESS_BINDING_DIGEST_HEX,
    "invalid typed MULH witness-binding digest",
);

/// Numeric values and names are the committed physical column contract.
pub const RowSource = enum(u8) {
    clock = 0,
    pc = 1,
    rd_addr = 2,
    rd_prev_0 = 3,
    rd_prev_1 = 4,
    rd_prev_2 = 5,
    rd_prev_3 = 6,
    rd_clock_prev = 7,
    rd_next_0 = 8,
    rd_next_1 = 9,
    rd_next_2 = 10,
    rd_next_3 = 11,
    rs1_addr = 12,
    rs1_prev_0 = 13,
    rs1_prev_1 = 14,
    rs1_prev_2 = 15,
    rs1_prev_3 = 16,
    rs1_clock_prev = 17,
    rs1_next_0 = 18,
    rs1_next_1 = 19,
    rs1_next_2 = 20,
    rs1_next_3 = 21,
    rs2_addr = 22,
    rs2_prev_0 = 23,
    rs2_prev_1 = 24,
    rs2_prev_2 = 25,
    rs2_prev_3 = 26,
    rs2_clock_prev = 27,
    rs2_next_0 = 28,
    rs2_next_1 = 29,
    rs2_next_2 = 30,
    rs2_next_3 = 31,
    rd_high_0 = 32,
    rd_high_1 = 33,
    rd_high_2 = 34,
    rd_high_3 = 35,
    rs1_sign = 36,
    rs2_sign = 37,
    opcode_mulh_flag = 38,
    opcode_mulhsu_flag = 39,
    opcode_mulhu_flag = 40,
    result_0 = 41,
    result_1 = 42,
    result_2 = 43,
    result_3 = 44,
    rd_nonzero = 45,
    rd_inv = 46,
};

pub const CANONICAL_RECIPE = std.enums.values(RowSource);

pub const SlotBinding = struct {
    column: u8,
    value: types.ValueId,
    source: RowSource,
};

pub const ProductAlgorithm = enum(u8) {
    rv32_signed_signed_high = 0,
    rv32_signed_unsigned_high = 1,
    rv32_unsigned_unsigned_high = 2,
};

pub const OperationBinding = struct {
    opcode_id: u32,
    flag_column: u8,
    algorithm: ProductAlgorithm,
};

pub const CANONICAL_OPERATIONS = [3]OperationBinding{
    .{
        .opcode_id = typed.MULH_OPCODE_ID,
        .flag_column = 38,
        .algorithm = .rv32_signed_signed_high,
    },
    .{
        .opcode_id = typed.MULHSU_OPCODE_ID,
        .flag_column = 39,
        .algorithm = .rv32_signed_unsigned_high,
    },
    .{
        .opcode_id = typed.MULHU_OPCODE_ID,
        .flag_column = 40,
        .algorithm = .rv32_unsigned_unsigned_high,
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
        try validateSlotContract(definition);
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
        try validateSlotContract(definition);
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
        slot.* = .{
            .column = @intCast(column),
            .value = value,
            .source = source_value,
        };
    }
    return .{
        .format_version = WITNESS_BINDING_FORMAT_VERSION,
        .semantic_format_version = digest.range_refinement_format_version,
        .semantic_digest = typed.SEMANTIC_DIGEST,
        .slots = slots,
        .operations = CANONICAL_OPERATIONS,
    };
}

const physical_types = [MAIN_COLUMN_COUNT]types.Type{
    .clock,          .pc,             .register_index,
    .byte,           .byte,           .byte,
    .byte,           .clock,          .byte,
    .byte,           .byte,           .byte,
    .register_index, .byte,           .byte,
    .byte,           .byte,           .clock,
    .byte,           .byte,           .byte,
    .byte,           .register_index, .byte,
    .byte,           .byte,           .byte,
    .clock,          .byte,           .byte,
    .byte,           .byte,           .byte,
    .byte,           .byte,           .byte,
    .bit,            .bit,            .bit,
    .bit,            .bit,            .byte,
    .byte,           .byte,           .byte,
    .bit,            .felt,
};

fn validateSlotContract(
    definition: *const typed.Definition,
) error{InvalidWitnessBinding}!void {
    const physical = definition.columns.physical();
    inline for (physical, physical_types, CANONICAL_RECIPE, 0..) |
        value,
        expected_type,
        source_value,
        index,
    | {
        if (types.idIndex(value) != index)
            return error.InvalidWitnessBinding;
        const node = definition.arena.node(value) orelse
            return error.InvalidWitnessBinding;
        if (!std.meta.eql(node.key.ty, expected_type))
            return error.InvalidWitnessBinding;
        const name_id = switch (node.key.op) {
            .input => |name| name,
            else => return error.InvalidWitnessBinding,
        };
        const name = definition.arena.name(name_id) orelse
            return error.InvalidWitnessBinding;
        if (!std.mem.eql(u8, name, @tagName(source_value)))
            return error.InvalidWitnessBinding;
    }
}

/// Direct hot writer. Keep this scalar and structurally parallel to the retired
/// oracle: carry derivation belongs to interaction generation, not this loop.
pub inline fn writeActiveRow(
    columns: anytype,
    row_index: usize,
    row: TraceRow,
) void {
    const product = productFor(row);
    set(columns, row_index, 0, fromUnsigned(row.clk));
    set(columns, row_index, 1, fromUnsigned(row.pc));
    writeAccess(columns, row_index, 2, row.rd, row.rd_prev_val, row.rd_prev_clk, row.rd_val);
    writeAccess(columns, row_index, 12, row.rs1, row.rs1_val, row.rs1_prev_clk, row.rs1_val);
    writeAccess(columns, row_index, 22, row.rs2, row.rs2_val, row.rs2_prev_clk, row.rs2_val);
    writeWord(columns, row_index, 32, @truncate(product));
    set(columns, row_index, 36, flag(rs1Signed(row) and (row.rs1_val >> 31) == 1));
    set(columns, row_index, 37, flag(rs2Signed(row) and (row.rs2_val >> 31) == 1));
    set(columns, row_index, 38, flag(row.opcode == .MULH));
    set(columns, row_index, 39, flag(row.opcode == .MULHSU));
    set(columns, row_index, 40, flag(row.opcode == .MULHU));
    writeWord(columns, row_index, 41, @truncate(product >> 32));
    writeDestination(columns, row_index, 45, row.rd);
}

inline fn set(columns: anytype, row_index: usize, column: usize, value: M31) void {
    columns[column][row_index] = value;
}

inline fn writeAccess(
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

inline fn writeWord(
    columns: anytype,
    row_index: usize,
    start: usize,
    value: u32,
) void {
    inline for (0..4) |limb| set(
        columns,
        row_index,
        start + limb,
        fromUnsigned((value >> @intCast(8 * limb)) & 0xff),
    );
}

inline fn writeDestination(
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
    if (row.rd_val != (if (row.rd == 0) 0 else highProduct(row)))
        return error.InvalidTraceRow;
}

fn buildRelationRow(row: TraceRow) RelationRow {
    const one = M31.one();
    const zero = M31.zero();
    const four = fromUnsigned(4);
    const clock = fromUnsigned(row.clk);
    const pc = fromUnsigned(row.pc);
    const rd = fromUnsigned(row.rd);
    const rs1 = fromUnsigned(row.rs1);
    const rs2 = fromUnsigned(row.rs2);
    const rd_previous = limbs(row.rd_prev_val);
    const rd_next = limbs(row.rd_val);
    const rs1_value = limbs(row.rs1_val);
    const rs2_value = limbs(row.rs2_val);
    const rd_previous_clock = fromUnsigned(row.rd_prev_clk);
    const rs1_previous_clock = fromUnsigned(row.rs1_prev_clk);
    const rs2_previous_clock = fromUnsigned(row.rs2_prev_clk);
    const source_1_clock = clock.sub(one).mul(four).add(one);
    const source_2_clock = clock.sub(one).mul(four).add(fromUnsigned(2));
    const destination_clock = clock.sub(one).mul(four).add(fromUnsigned(3));
    const source_1_gap = source_1_clock.sub(rs1_previous_clock).sub(one);
    const source_2_gap = source_2_clock.sub(rs2_previous_clock).sub(one);
    const destination_gap = destination_clock.sub(rd_previous_clock).sub(one);
    const product = productFor(row);
    const product_bytes = limbs64(product);
    const carry = productCarries(row, product);
    const rs1_sign = flag(rs1Signed(row) and (row.rs1_val >> 31) == 1);
    const rs2_sign = flag(rs2Signed(row) and (row.rs2_val >> 31) == 1);
    const signed_rs1 = flag(rs1Signed(row));
    const signed_rs2 = flag(rs2Signed(row));

    var result: RelationRow = undefined;
    result.events[0] = makeEvent(0, one, .{
        pc, fromUnsigned(opcodeId(row)), rd, rs1, rs2,
    });
    result.events[1] = makeEvent(1, one, .{ pc, clock });
    result.events[2] = makeEvent(2, one, .{ pc.add(four), clock.add(one) });
    result.events[3] = makeEvent(3, one, .{
        zero,         rs1,          rs1_previous_clock,
        rs1_value[0], rs1_value[1], rs1_value[2],
        rs1_value[3],
    });
    result.events[4] = makeEvent(4, one, .{
        zero,         rs1,          source_1_clock,
        rs1_value[0], rs1_value[1], rs1_value[2],
        rs1_value[3],
    });
    result.events[5] = makeEvent(5, one, .{source_1_gap});
    result.events[6] = makeEvent(6, one, .{
        zero,         rs2,          rs2_previous_clock,
        rs2_value[0], rs2_value[1], rs2_value[2],
        rs2_value[3],
    });
    result.events[7] = makeEvent(7, one, .{
        zero,         rs2,          source_2_clock,
        rs2_value[0], rs2_value[1], rs2_value[2],
        rs2_value[3],
    });
    result.events[8] = makeEvent(8, one, .{source_2_gap});
    inline for (0..8) |limb| result.events[9 + limb] = makeEvent(
        9 + limb,
        one,
        .{ product_bytes[limb], fromUnsigned(carry[limb]) },
    );
    result.events[17] = makeEvent(17, signed_rs1, .{
        zero,
        rs1_value[3].sub(rs1_sign.mul(fromUnsigned(128))),
    });
    result.events[18] = makeEvent(18, signed_rs2, .{
        zero,
        rs2_value[3].sub(rs2_sign.mul(fromUnsigned(128))),
    });
    result.events[19] = makeEvent(19, one, .{
        zero,           rd,             rd_previous_clock,
        rd_previous[0], rd_previous[1], rd_previous[2],
        rd_previous[3],
    });
    result.events[20] = makeEvent(20, one, .{
        zero,       rd,         destination_clock,
        rd_next[0], rd_next[1], rd_next[2],
        rd_next[3],
    });
    result.events[21] = makeEvent(21, one, .{destination_gap});
    return result;
}

fn makeEvent(
    comptime index: usize,
    liveness: M31,
    values: anytype,
) RelationEvent {
    const spec = EVENT_SPECS[index];
    comptime if (values.len != spec.arity)
        @compileError("typed MULH relation row arity drift");
    var owned = [_]M31{M31.zero()} ** MAX_EVENT_ARITY;
    inline for (values, 0..) |value, field| owned[field] = value;
    return .{
        .kind = spec.kind,
        .domain = spec.domain,
        .role = spec.role,
        .liveness = liveness,
        .arity = spec.arity,
        .values = owned,
        .access_ordinal = spec.ordinal,
    };
}

fn productCarries(row: TraceRow, product: u64) [8]u32 {
    const lhs_fill: u32 = if (rs1Signed(row) and (row.rs1_val >> 31) == 1) 255 else 0;
    const rhs_fill: u32 = if (rs2Signed(row) and (row.rs2_val >> 31) == 1) 255 else 0;
    var lhs: [8]u32 = undefined;
    var rhs: [8]u32 = undefined;
    inline for (0..4) |limb| {
        lhs[limb] = (row.rs1_val >> @intCast(8 * limb)) & 0xff;
        rhs[limb] = (row.rs2_val >> @intCast(8 * limb)) & 0xff;
    }
    inline for (4..8) |limb| {
        lhs[limb] = lhs_fill;
        rhs[limb] = rhs_fill;
    }
    var carries: [8]u32 = undefined;
    var previous: u32 = 0;
    inline for (0..8) |output_limb| {
        var numerator = previous;
        inline for (0..output_limb + 1) |lhs_limb|
            numerator += lhs[lhs_limb] * rhs[output_limb - lhs_limb];
        const product_byte: u32 = @truncate(
            (product >> @intCast(8 * output_limb)) & 0xff,
        );
        std.debug.assert(numerator >= product_byte);
        std.debug.assert((numerator - product_byte) & 0xff == 0);
        carries[output_limb] = (numerator - product_byte) >> 8;
        previous = carries[output_limb];
    }
    return carries;
}

inline fn isFamilyOpcode(row: TraceRow) bool {
    return switch (row.opcode) {
        .MULH, .MULHSU, .MULHU => true,
        else => false,
    };
}

pub inline fn productFor(row: TraceRow) u64 {
    return switch (row.opcode) {
        .MULH => @bitCast(
            @as(i64, @as(i32, @bitCast(row.rs1_val))) *%
                @as(i64, @as(i32, @bitCast(row.rs2_val))),
        ),
        .MULHSU => @bitCast(
            @as(i64, @as(i32, @bitCast(row.rs1_val))) * @as(i64, row.rs2_val),
        ),
        .MULHU => @as(u64, row.rs1_val) * @as(u64, row.rs2_val),
        else => unreachable,
    };
}

pub inline fn highProduct(row: TraceRow) u32 {
    return @truncate(productFor(row) >> 32);
}

inline fn rs1Signed(row: TraceRow) bool {
    return row.opcode == .MULH or row.opcode == .MULHSU;
}

inline fn rs2Signed(row: TraceRow) bool {
    return row.opcode == .MULH;
}

inline fn opcodeId(row: TraceRow) u32 {
    return switch (row.opcode) {
        .MULH => typed.MULH_OPCODE_ID,
        .MULHSU => typed.MULHSU_OPCODE_ID,
        .MULHU => typed.MULHU_OPCODE_ID,
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

inline fn limbs64(value: u64) [8]M31 {
    var result: [8]M31 = undefined;
    inline for (&result, 0..) |*limb, index|
        limb.* = fromUnsigned((value >> @intCast(8 * index)) & 0xff);
    return result;
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
    if (MAIN_COLUMN_COUNT != production_columns.MulhColumns.N_COLUMNS)
        @compileError("typed MULH witness width drifted from production");
    if (EVENT_COUNT != 22 or MAX_EVENT_ARITY != relation.get(.memory_access).fields.len)
        @compileError("typed MULH relation geometry drifted");
    if (CANONICAL_OPERATIONS[0].opcode_id != 38 or
        CANONICAL_OPERATIONS[1].opcode_id != 39 or
        CANONICAL_OPERATIONS[2].opcode_id != 40)
    {
        @compileError("typed MULH opcode identity drifted");
    }
    const fields = @typeInfo(production_columns.MulhColumns).@"struct".fields;
    if (CANONICAL_RECIPE.len != fields.len or physical_types.len != fields.len)
        @compileError("typed MULH witness recipe width drifted");
    for (fields, CANONICAL_RECIPE, 0..) |field, source_value, index| {
        if (@intFromEnum(source_value) != index)
            @compileError("typed MULH numeric witness recipe is not canonical");
        if (!std.mem.eql(u8, field.name, @tagName(source_value)))
            @compileError("typed MULH witness name drifted from production");
    }
}
