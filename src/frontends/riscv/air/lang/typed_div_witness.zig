//! Allocation-free production witness generation for typed RV32 DIV/REM.
//!
//! The immutable binding authenticates the exact 67-column physical layout,
//! the four-opcode semantic identity, and the closed `rv32_divrem@1` hint.
//! Active rows are written directly into final column-major storage; no
//! allocator, runtime recipe dispatch, string lookup, or scratch copy appears
//! in the row loop.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const M31 = m31.M31;
const direct_witness_executor = @import("direct_witness_executor.zig");
const digest = @import("digest.zig");
const hint_recipe = @import("hint_recipe.zig");
const trace_row = @import("../../runner/trace_row.zig");
const production_columns = @import("../trace_columns/m_extension.zig");
const typed_div = @import("typed_div.zig");
const types = @import("types.zig");

pub const MAIN_COLUMN_COUNT: usize = typed_div.MAIN_COLUMN_COUNT;
pub const TraceRow = trace_row.TraceRow;

pub const WITNESS_BINDING_FORMAT_VERSION: u16 = 1;
pub const WITNESS_BINDING_DOMAIN_SEPARATOR =
    "stwo-zig/typed-air/div-witness-binding/v1";

pub const WITNESS_BINDING_DIGEST_HEX =
    "1310f45968fb0e8336e1cfed92ee27eea614d7dbfd9e48f6441ffe5d87919040";
pub const WITNESS_BINDING_DIGEST: digest.Digest = hexDigest(
    WITNESS_BINDING_DIGEST_HEX,
    "invalid typed DIV witness-binding digest",
);

/// Stable numeric row-source codes. Values are artifact identity and therefore
/// explicit even though the canonical order currently matches physical order.
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
    zero_divisor = 32,
    r_zero = 33,
    q_0 = 34,
    q_1 = 35,
    q_2 = 36,
    q_3 = 37,
    r_0 = 38,
    r_1 = 39,
    r_2 = 40,
    r_3 = 41,
    b_sign = 42,
    c_sign = 43,
    q_sign = 44,
    sign_xor = 45,
    c_sum_inv = 46,
    r_sum_inv = 47,
    r_abs_0 = 48,
    r_abs_1 = 49,
    r_abs_2 = 50,
    r_abs_3 = 51,
    r_inv_0 = 52,
    r_inv_1 = 53,
    r_inv_2 = 54,
    r_inv_3 = 55,
    lt_marker_0 = 56,
    lt_marker_1 = 57,
    lt_marker_2 = 58,
    lt_marker_3 = 59,
    lt_diff = 60,
    opcode_div_flag = 61,
    opcode_divu_flag = 62,
    opcode_rem_flag = 63,
    opcode_remu_flag = 64,
    rd_nonzero = 65,
    rd_inv = 66,
};

pub const CANONICAL_RECIPE = std.enums.values(RowSource);

pub const SlotBinding = struct {
    column: u8,
    value: types.ValueId,
    source: RowSource,
};

/// Pointer-free identity that remains valid after the authored arena dies.
pub const WitnessBinding = struct {
    format_version: u16,
    semantic_format_version: u16,
    opcode_ids: [4]u32,
    semantic_digest: digest.Digest,
    hint_recipe_id: types.HintRecipeId,
    hint_recipe_version: u16,
    slots: [MAIN_COLUMN_COUNT]SlotBinding,

    pub fn canonical(definition: *const typed_div.Definition) WitnessBinding {
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
            .opcode_ids = typed_div.OPCODE_IDS,
            .semantic_digest = typed_div.SEMANTIC_DIGEST,
            .hint_recipe_id = hint_recipe.id(.rv32_divrem),
            .hint_recipe_version = hint_recipe.get(.rv32_divrem).version,
            .slots = slots,
        };
    }

    pub fn identityDigest(self: *const WitnessBinding) digest.Digest {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(WITNESS_BINDING_DOMAIN_SEPARATOR);
        hashInt(&hash, u16, self.format_version);
        hashInt(&hash, u16, self.semantic_format_version);
        for (self.opcode_ids) |opcode_id| hashInt(&hash, u32, opcode_id);
        hash.update(&self.semantic_digest);
        hashInt(&hash, u32, @intFromEnum(self.hint_recipe_id));
        hashInt(&hash, u16, self.hint_recipe_version);
        hashInt(&hash, u16, MAIN_COLUMN_COUNT);
        for (self.slots) |slot| {
            hashInt(&hash, u8, slot.column);
            hashInt(&hash, u32, @intFromEnum(slot.value));
            hashInt(&hash, u8, @intFromEnum(slot.source));
        }
        return hash.finalResult();
    }
};

pub const ConstructionError = typed_div.ValidationError || error{
    InvalidWitnessBinding,
};
pub const ExecutionError = direct_witness_executor.Error;

/// Immutable and reentrant prepared DIV/REM witness executor.
pub const Executor = struct {
    binding: WitnessBinding,
    binding_digest: digest.Digest,

    pub fn init(
        definition: *const typed_div.Definition,
        supplied: *const WitnessBinding,
    ) ConstructionError!Executor {
        try definition.validate();
        try validateBinding(definition, supplied);
        const owned = supplied.*;
        const binding_digest = owned.identityDigest();
        if (!std.mem.eql(u8, &binding_digest, &WITNESS_BINDING_DIGEST))
            return error.InvalidWitnessBinding;
        return .{ .binding = owned, .binding_digest = binding_digest };
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

const uint_types = struct {
    const bit = types.Type.bit;
    const byte = types.Type.byte;
    const felt = types.Type.felt;
    const clock = types.Type.clock;
    const pc = types.Type.pc;
    const register = types.Type.register_index;
};

const physical_types = [MAIN_COLUMN_COUNT]types.Type{
    uint_types.clock,    uint_types.pc,
    uint_types.register, uint_types.byte,
    uint_types.byte,     uint_types.byte,
    uint_types.byte,     uint_types.clock,
    uint_types.byte,     uint_types.byte,
    uint_types.byte,     uint_types.byte,
    uint_types.register, uint_types.byte,
    uint_types.byte,     uint_types.byte,
    uint_types.byte,     uint_types.clock,
    uint_types.byte,     uint_types.byte,
    uint_types.byte,     uint_types.byte,
    uint_types.register, uint_types.byte,
    uint_types.byte,     uint_types.byte,
    uint_types.byte,     uint_types.clock,
    uint_types.byte,     uint_types.byte,
    uint_types.byte,     uint_types.byte,
    uint_types.bit,      uint_types.bit,
    uint_types.byte,     uint_types.byte,
    uint_types.byte,     uint_types.byte,
    uint_types.byte,     uint_types.byte,
    uint_types.byte,     uint_types.byte,
    uint_types.bit,      uint_types.bit,
    uint_types.bit,      uint_types.bit,
    uint_types.felt,     uint_types.felt,
    uint_types.byte,     uint_types.byte,
    uint_types.byte,     uint_types.byte,
    uint_types.felt,     uint_types.felt,
    uint_types.felt,     uint_types.felt,
    uint_types.bit,      uint_types.bit,
    uint_types.bit,      uint_types.bit,
    uint_types.byte,     uint_types.bit,
    uint_types.bit,      uint_types.bit,
    uint_types.bit,      uint_types.bit,
    uint_types.felt,
};

fn validateBinding(
    definition: *const typed_div.Definition,
    supplied: *const WitnessBinding,
) error{InvalidWitnessBinding}!void {
    const recipe = hint_recipe.getById(supplied.hint_recipe_id) orelse
        return error.InvalidWitnessBinding;
    if (supplied.format_version != WITNESS_BINDING_FORMAT_VERSION or
        supplied.semantic_format_version != digest.range_refinement_format_version or
        !std.mem.eql(u32, &supplied.opcode_ids, &typed_div.OPCODE_IDS) or
        !std.mem.eql(u8, &supplied.semantic_digest, &typed_div.SEMANTIC_DIGEST) or
        recipe.kind != .rv32_divrem or
        recipe.version != supplied.hint_recipe_version)
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
        if (types.idIndex(value) != index or
            slot.column != index or slot.value != value or slot.source != source)
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

const Derived = struct {
    quotient: [4]M31,
    remainder: [4]M31,
    zero_divisor: bool,
    r_zero: bool,
    b_sign: bool,
    c_sign: bool,
    q_sign: bool,
    sign_xor: bool,
    c_sum_inv: M31,
    r_sum_inv: M31,
    r_abs: [4]M31,
    r_inv: [4]M31,
    lt_markers: [4]M31,
    lt_diff: M31,
};

/// Directly write one already-classified active family row.
pub inline fn writeActiveRow(columns: anytype, row_index: usize, row: TraceRow) void {
    const rd_previous = limbs(row.rd_prev_val);
    const rd_next = limbs(row.rd_val);
    const rs1_value = limbs(row.rs1_val);
    const rs2_value = limbs(row.rs2_val);
    const derived = derive(row);
    const rd = fromUnsigned(row.rd);
    const rs1 = fromUnsigned(row.rs1);
    const rs2 = fromUnsigned(row.rs2);
    const rd_nonzero = row.rd != 0;

    inline for (CANONICAL_RECIPE, 0..) |source, column| {
        columns[column][row_index] = switch (source) {
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
            .zero_divisor => bit(derived.zero_divisor),
            .r_zero => bit(derived.r_zero),
            .q_0 => derived.quotient[0],
            .q_1 => derived.quotient[1],
            .q_2 => derived.quotient[2],
            .q_3 => derived.quotient[3],
            .r_0 => derived.remainder[0],
            .r_1 => derived.remainder[1],
            .r_2 => derived.remainder[2],
            .r_3 => derived.remainder[3],
            .b_sign => bit(derived.b_sign),
            .c_sign => bit(derived.c_sign),
            .q_sign => bit(derived.q_sign),
            .sign_xor => bit(derived.sign_xor),
            .c_sum_inv => derived.c_sum_inv,
            .r_sum_inv => derived.r_sum_inv,
            .r_abs_0 => derived.r_abs[0],
            .r_abs_1 => derived.r_abs[1],
            .r_abs_2 => derived.r_abs[2],
            .r_abs_3 => derived.r_abs[3],
            .r_inv_0 => derived.r_inv[0],
            .r_inv_1 => derived.r_inv[1],
            .r_inv_2 => derived.r_inv[2],
            .r_inv_3 => derived.r_inv[3],
            .lt_marker_0 => derived.lt_markers[0],
            .lt_marker_1 => derived.lt_markers[1],
            .lt_marker_2 => derived.lt_markers[2],
            .lt_marker_3 => derived.lt_markers[3],
            .lt_diff => derived.lt_diff,
            .opcode_div_flag => bit(row.opcode == .DIV),
            .opcode_divu_flag => bit(row.opcode == .DIVU),
            .opcode_rem_flag => bit(row.opcode == .REM),
            .opcode_remu_flag => bit(row.opcode == .REMU),
            .rd_nonzero => bit(rd_nonzero),
            .rd_inv => if (rd_nonzero) rd.invUncheckedNonZero() else M31.zero(),
        };
    }
}

fn derive(row: TraceRow) Derived {
    const signed = row.opcode == .DIV or row.opcode == .REM;
    const output = hint_recipe.evaluateRv32DivRemV1(
        row.rs1_val,
        row.rs2_val,
        signed,
    );
    const lhs = rawLimbs(row.rs1_val);
    const rhs = rawLimbs(row.rs2_val);
    const remainder = rawLimbs(output.remainder);
    const b_sign = signed and lhs[3] & 0x80 != 0;
    const c_sign = signed and rhs[3] & 0x80 != 0;
    const sign_xor = b_sign != c_sign;
    const r_zero = output.remainder == 0 and !output.zeroDivisor();
    const r_abs_raw = if (sign_xor) negateLimbs(remainder) else remainder;

    var r_inverse: [4]M31 = undefined;
    for (&r_inverse, r_abs_raw) |*inverse, limb| {
        inverse.* = M31.fromCanonical(m31.Modulus - 256 + limb)
            .invUncheckedNonZero();
    }

    var markers = [_]M31{M31.zero()} ** 4;
    var difference: u32 = 0;
    if (!output.zeroDivisor() and !r_zero and !output.signedOverflow()) {
        var index: usize = 4;
        while (index > 0) {
            index -= 1;
            if (rhs[index] == r_abs_raw[index]) continue;
            markers[index] = M31.one();
            difference = if (c_sign)
                r_abs_raw[index] -% rhs[index]
            else
                rhs[index] -% r_abs_raw[index];
            break;
        }
    }

    var rhs_sum: u32 = 0;
    var remainder_sum: u32 = 0;
    for (rhs) |limb| rhs_sum += limb;
    for (remainder) |limb| remainder_sum += limb;

    return .{
        .quotient = limbs(output.quotient),
        .remainder = limbs(output.remainder),
        .zero_divisor = output.zeroDivisor(),
        .r_zero = r_zero,
        .b_sign = b_sign,
        .c_sign = c_sign,
        .q_sign = if (output.zeroDivisor()) signed else signed and !output.signedOverflow() and output.quotient >> 31 == 1,
        .sign_xor = sign_xor,
        .c_sum_inv = inverseOrZero(rhs_sum),
        .r_sum_inv = inverseOrZero(remainder_sum),
        .r_abs = feltLimbs(r_abs_raw),
        .r_inv = r_inverse,
        .lt_markers = markers,
        .lt_diff = fromUnsigned(difference),
    };
}

fn validateRow(row: TraceRow) ExecutionError!void {
    switch (row.opcode) {
        .DIV, .DIVU, .REM, .REMU => {},
        else => return error.InvalidTraceRow,
    }
}

inline fn fromUnsigned(value: anytype) M31 {
    return M31.fromU64(@intCast(value));
}

inline fn bit(value: bool) M31 {
    return if (value) M31.one() else M31.zero();
}

inline fn rawLimbs(value: u32) [4]u32 {
    return .{ value & 0xff, (value >> 8) & 0xff, (value >> 16) & 0xff, value >> 24 };
}

inline fn feltLimbs(values: [4]u32) [4]M31 {
    return .{
        fromUnsigned(values[0]), fromUnsigned(values[1]),
        fromUnsigned(values[2]), fromUnsigned(values[3]),
    };
}

inline fn limbs(value: u32) [4]M31 {
    return feltLimbs(rawLimbs(value));
}

fn negateLimbs(values: [4]u32) [4]u32 {
    var carry: u32 = 1;
    var result: [4]u32 = undefined;
    for (values, 0..) |limb, index| {
        const value = 256 + carry - 1 - limb;
        carry = value >> 8;
        result[index] = value & 0xff;
    }
    return result;
}

inline fn inverseOrZero(value: u32) M31 {
    if (value == 0) return M31.zero();
    return M31.fromCanonical(value).invUncheckedNonZero();
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
    if (MAIN_COLUMN_COUNT != production_columns.DivColumns.N_COLUMNS)
        @compileError("typed DIV witness width drifted from production");
    const fields = @typeInfo(production_columns.DivColumns).@"struct".fields;
    if (CANONICAL_RECIPE.len != fields.len or physical_types.len != fields.len)
        @compileError("typed DIV witness recipe width drifted");
    for (fields, CANONICAL_RECIPE, 0..) |field, source, index| {
        if (@intFromEnum(source) != index)
            @compileError("typed DIV numeric witness recipe is not canonical");
        if (!std.mem.eql(u8, field.name, @tagName(source)))
            @compileError("typed DIV witness name drifted from production");
    }
}
