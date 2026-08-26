//! Authenticated allocation-free witness authority for RV32 `MUL`.
//!
//! Cold construction binds the semantic identity, exact 39-column recipe,
//! opcode, and low-word multiplication policy. The hot loop writes final
//! column-major storage directly without allocation, recipe dispatch, or an
//! intermediate row buffer.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const direct_witness_executor = @import("direct_witness_executor.zig");
const digest = @import("digest.zig");
const production_columns = @import("../trace_columns/m_extension.zig");
const trace_row = @import("../../runner/trace_row.zig");
const typed_mul = @import("typed_mul.zig");
const types = @import("types.zig");

pub const MAIN_COLUMN_COUNT: usize = typed_mul.MAIN_COLUMN_COUNT;
pub const TraceRow = trace_row.TraceRow;

pub const WITNESS_BINDING_FORMAT_VERSION: u16 = 1;
pub const WITNESS_BINDING_DOMAIN_SEPARATOR =
    "stwo-zig/typed-air/mul-witness-binding/v1";
pub const WITNESS_BINDING_DIGEST_HEX =
    "acde25f5ffabccde3bc4d8ee503fc37b98b7ba410e3c5b6bcff2c950d94ea532";
pub const WITNESS_BINDING_DIGEST: digest.Digest = hexDigest(
    WITNESS_BINDING_DIGEST_HEX,
    "invalid typed MUL witness-binding digest",
);

/// Numeric values and names are the committed physical column contract.
pub const RowSource = enum(u8) {
    enabler = 0,
    clock = 1,
    pc = 2,
    rd_addr = 3,
    rd_prev_0 = 4,
    rd_prev_1 = 5,
    rd_prev_2 = 6,
    rd_prev_3 = 7,
    rd_clock_prev = 8,
    rd_next_0 = 9,
    rd_next_1 = 10,
    rd_next_2 = 11,
    rd_next_3 = 12,
    rs1_addr = 13,
    rs1_prev_0 = 14,
    rs1_prev_1 = 15,
    rs1_prev_2 = 16,
    rs1_prev_3 = 17,
    rs1_clock_prev = 18,
    rs1_next_0 = 19,
    rs1_next_1 = 20,
    rs1_next_2 = 21,
    rs1_next_3 = 22,
    rs2_addr = 23,
    rs2_prev_0 = 24,
    rs2_prev_1 = 25,
    rs2_prev_2 = 26,
    rs2_prev_3 = 27,
    rs2_clock_prev = 28,
    rs2_next_0 = 29,
    rs2_next_1 = 30,
    rs2_next_2 = 31,
    rs2_next_3 = 32,
    result_0 = 33,
    result_1 = 34,
    result_2 = 35,
    result_3 = 36,
    rd_nonzero = 37,
    rd_inv = 38,
};

pub const CANONICAL_RECIPE = std.enums.values(RowSource);

pub const SlotBinding = struct {
    column: u8,
    value: types.ValueId,
    source: RowSource,
};

pub const ResultAlgorithm = enum(u8) {
    rv32_low_word_product = 0,
    reserved = 255,
};

pub const WitnessBinding = struct {
    format_version: u16,
    semantic_format_version: u16,
    opcode_id: u32,
    semantic_digest: digest.Digest,
    result_algorithm: ResultAlgorithm,
    slots: [MAIN_COLUMN_COUNT]SlotBinding,

    pub fn canonical(definition: *const typed_mul.Definition) WitnessBinding {
        const physical = definition.columns.physical();
        var slots: [MAIN_COLUMN_COUNT]SlotBinding = undefined;
        for (&slots, physical, CANONICAL_RECIPE, 0..) |*slot, value, source, column| {
            slot.* = .{
                .column = @intCast(column),
                .value = value,
                .source = source,
            };
        }
        return .{
            .format_version = WITNESS_BINDING_FORMAT_VERSION,
            .semantic_format_version = digest.range_refinement_format_version,
            .opcode_id = typed_mul.OPCODE_ID,
            .semantic_digest = typed_mul.SEMANTIC_DIGEST,
            .result_algorithm = .rv32_low_word_product,
            .slots = slots,
        };
    }

    pub fn identityDigest(self: *const WitnessBinding) digest.Digest {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(WITNESS_BINDING_DOMAIN_SEPARATOR);
        hashInt(&hash, u16, self.format_version);
        hashInt(&hash, u16, self.semantic_format_version);
        hashInt(&hash, u32, self.opcode_id);
        hash.update(&self.semantic_digest);
        hashInt(&hash, u8, @intFromEnum(self.result_algorithm));
        hashInt(&hash, u16, MAIN_COLUMN_COUNT);
        for (self.slots) |slot| {
            hashInt(&hash, u8, slot.column);
            hashInt(&hash, u32, @intFromEnum(slot.value));
            hashInt(&hash, u8, @intFromEnum(slot.source));
        }
        return hash.finalResult();
    }
};

pub const ConstructionError = typed_mul.ValidationError || error{
    InvalidWitnessBinding,
};
pub const ExecutionError = direct_witness_executor.Error;

pub const Executor = struct {
    binding: WitnessBinding,
    binding_digest: digest.Digest,

    pub fn init(
        definition: *const typed_mul.Definition,
        supplied: *const WitnessBinding,
    ) ConstructionError!Executor {
        try definition.validate();
        try validateBinding(definition, supplied);
        const binding_digest = supplied.identityDigest();
        if (!std.mem.eql(u8, &binding_digest, &WITNESS_BINDING_DIGEST)) {
            return error.InvalidWitnessBinding;
        }
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
};

const physical_types = [MAIN_COLUMN_COUNT]types.Type{
    .bit,            .clock,          .pc,
    .register_index, .byte,           .byte,
    .byte,           .byte,           .clock,
    .byte,           .byte,           .byte,
    .byte,           .register_index, .byte,
    .byte,           .byte,           .byte,
    .clock,          .byte,           .byte,
    .byte,           .byte,           .register_index,
    .byte,           .byte,           .byte,
    .byte,           .clock,          .byte,
    .byte,           .byte,           .byte,
    .byte,           .byte,           .byte,
    .byte,           .bit,            .felt,
};

fn validateBinding(
    definition: *const typed_mul.Definition,
    supplied: *const WitnessBinding,
) error{InvalidWitnessBinding}!void {
    if (supplied.format_version != WITNESS_BINDING_FORMAT_VERSION or
        supplied.semantic_format_version != digest.range_refinement_format_version or
        supplied.opcode_id != typed_mul.OPCODE_ID or
        !std.mem.eql(u8, &supplied.semantic_digest, &typed_mul.SEMANTIC_DIGEST) or
        supplied.result_algorithm != .rv32_low_word_product)
    {
        return error.InvalidWitnessBinding;
    }
    const physical = definition.columns.physical();
    inline for (physical, physical_types, CANONICAL_RECIPE, 0..) |
        value,
        expected_type,
        source,
        index,
    | {
        const slot = supplied.slots[index];
        if (types.idIndex(value) != index or slot.column != index or
            slot.value != value or slot.source != source)
        {
            return error.InvalidWitnessBinding;
        }
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
        if (!std.mem.eql(u8, name, @tagName(source)))
            return error.InvalidWitnessBinding;
    }
}

pub inline fn writeActiveRow(columns: anytype, row_index: usize, row: TraceRow) void {
    const rd_previous = limbs(row.rd_prev_val);
    const rd_next = limbs(row.rd_val);
    const rs1_value = limbs(row.rs1_val);
    const rs2_value = limbs(row.rs2_val);
    const result = limbs(@truncate(@as(u64, row.rs1_val) *% @as(u64, row.rs2_val)));
    const rd = fromUnsigned(row.rd);
    const rs1 = fromUnsigned(row.rs1);
    const rs2 = fromUnsigned(row.rs2);
    const rd_nonzero = row.rd != 0;

    inline for (CANONICAL_RECIPE, 0..) |source, column| {
        columns[column][row_index] = switch (source) {
            .enabler => M31.one(),
            .clock => fromUnsigned(row.clk),
            .pc => fromUnsigned(row.pc),
            .rd_addr => rd,
            .rd_prev_0 => rd_previous[0],
            .rd_prev_1 => rd_previous[1],
            .rd_prev_2 => rd_previous[2],
            .rd_prev_3 => rd_previous[3],
            .rd_clock_prev => fromUnsigned(row.rd_prev_clk),
            .rd_next_0 => rd_next[0],
            .rd_next_1 => rd_next[1],
            .rd_next_2 => rd_next[2],
            .rd_next_3 => rd_next[3],
            .rs1_addr => rs1,
            .rs1_prev_0, .rs1_next_0 => rs1_value[0],
            .rs1_prev_1, .rs1_next_1 => rs1_value[1],
            .rs1_prev_2, .rs1_next_2 => rs1_value[2],
            .rs1_prev_3, .rs1_next_3 => rs1_value[3],
            .rs1_clock_prev => fromUnsigned(row.rs1_prev_clk),
            .rs2_addr => rs2,
            .rs2_prev_0, .rs2_next_0 => rs2_value[0],
            .rs2_prev_1, .rs2_next_1 => rs2_value[1],
            .rs2_prev_2, .rs2_next_2 => rs2_value[2],
            .rs2_prev_3, .rs2_next_3 => rs2_value[3],
            .rs2_clock_prev => fromUnsigned(row.rs2_prev_clk),
            .result_0 => result[0],
            .result_1 => result[1],
            .result_2 => result[2],
            .result_3 => result[3],
            .rd_nonzero => bit(rd_nonzero),
            .rd_inv => if (rd_nonzero) rd.invUncheckedNonZero() else M31.zero(),
        };
    }
}

fn validateRow(row: TraceRow) ExecutionError!void {
    if (row.opcode != .MUL) return error.InvalidTraceRow;
}

inline fn fromUnsigned(value: anytype) M31 {
    return M31.fromU64(@intCast(value));
}

inline fn bit(value: bool) M31 {
    return if (value) M31.one() else M31.zero();
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
    if (MAIN_COLUMN_COUNT != production_columns.MulColumns.N_COLUMNS)
        @compileError("typed MUL witness width drifted from production");
    const fields = @typeInfo(production_columns.MulColumns).@"struct".fields;
    if (CANONICAL_RECIPE.len != fields.len or physical_types.len != fields.len)
        @compileError("typed MUL witness recipe width drifted");
    for (fields, CANONICAL_RECIPE, 0..) |field, source, index| {
        if (@intFromEnum(source) != index)
            @compileError("typed MUL numeric witness recipe is not canonical");
        if (!std.mem.eql(u8, field.name, @tagName(source)))
            @compileError("typed MUL witness name drifted from production");
    }
}
