//! Allocation-free production witness generation for native typed RV32 AUIPC.
//!
//! Cold construction authenticates the semantic definition, exact 29-slot
//! row-source recipe, wrapping-add policy, and inverse-or-zero hint. Accepted
//! hot rows then write directly into caller-owned final SoA storage with no
//! allocator, scratch copy, string dispatch, or runtime recipe loop.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const direct_witness_executor = @import("direct_witness_executor.zig");
const digest = @import("digest.zig");
const hint_recipe = @import("hint_recipe.zig");
const trace_row = @import("../../runner/trace_row.zig");
const production_columns = @import("../trace_columns/control.zig");
const typed_auipc = @import("typed_auipc.zig");
const types = @import("types.zig");

pub const MAIN_COLUMN_COUNT: usize = typed_auipc.MAIN_COLUMN_COUNT;
pub const TraceRow = trace_row.TraceRow;

pub const WITNESS_BINDING_FORMAT_VERSION: u16 = 1;
pub const WITNESS_BINDING_DOMAIN_SEPARATOR =
    "stwo-zig/typed-air/auipc-witness-binding/v1";
pub const WITNESS_BINDING_DIGEST_HEX =
    "ae149874f8f99896f45faf4756aad4b322dd29b204455d979c8e59d3e43d2b81";
pub const WITNESS_BINDING_DIGEST: digest.Digest = hexDigest(
    WITNESS_BINDING_DIGEST_HEX,
    "invalid typed AUIPC witness-binding digest",
);

pub const RowSource = enum(u8) {
    constant_one = 0,
    trace_clock = 1,
    trace_pc = 2,
    trace_rd_address = 3,
    trace_rd_previous_byte_0 = 4,
    trace_rd_previous_byte_1 = 5,
    trace_rd_previous_byte_2 = 6,
    trace_rd_previous_byte_3 = 7,
    trace_rd_previous_clock = 8,
    trace_rd_next_byte_0 = 9,
    trace_rd_next_byte_1 = 10,
    trace_rd_next_byte_2 = 11,
    trace_rd_next_byte_3 = 12,
    trace_signed_immediate = 13,
    derived_wrapping_result_byte_0 = 14,
    derived_wrapping_result_byte_1 = 15,
    derived_wrapping_result_byte_2 = 16,
    derived_wrapping_result_byte_3 = 17,
    hint_rd_nonzero = 18,
    hint_rd_inverse_or_zero = 19,
    trace_pc_byte_0 = 20,
    trace_pc_byte_1 = 21,
    trace_pc_byte_2 = 22,
    trace_pc_byte_3 = 23,
    trace_immediate_byte_0 = 24,
    trace_immediate_byte_1 = 25,
    trace_immediate_byte_2 = 26,
    trace_immediate_byte_3 = 27,
    trace_immediate_sign = 28,
};

pub const CANONICAL_RECIPE = [MAIN_COLUMN_COUNT]RowSource{
    .constant_one,
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
    .trace_signed_immediate,
    .derived_wrapping_result_byte_0,
    .derived_wrapping_result_byte_1,
    .derived_wrapping_result_byte_2,
    .derived_wrapping_result_byte_3,
    .hint_rd_nonzero,
    .hint_rd_inverse_or_zero,
    .trace_pc_byte_0,
    .trace_pc_byte_1,
    .trace_pc_byte_2,
    .trace_pc_byte_3,
    .trace_immediate_byte_0,
    .trace_immediate_byte_1,
    .trace_immediate_byte_2,
    .trace_immediate_byte_3,
    .trace_immediate_sign,
};

pub const ArithmeticAlgorithm = enum(u8) {
    rv32_wrapping_pc_plus_signed_u_immediate = 0,
};

pub const ArithmeticBinding = struct {
    algorithm: ArithmeticAlgorithm,
    pc_column: u8,
    immediate_column: u8,
    first_result_column: u8,
    result_limb_count: u8,
};

pub const CANONICAL_ARITHMETIC = ArithmeticBinding{
    .algorithm = .rv32_wrapping_pc_plus_signed_u_immediate,
    .pc_column = 2,
    .immediate_column = 13,
    .first_result_column = 14,
    .result_limb_count = 4,
};

pub const DestinationHintBinding = struct {
    recipe: types.HintRecipeId,
    recipe_version: u16,
    algorithm: hint_recipe.Algorithm,
    exceptional_cases: hint_recipe.ExceptionalCasePolicy,
    input_column: u8,
    inverse_output_column: u8,
    nonzero_output_column: u8,
};

const destination_recipe = hint_recipe.get(.field_inverse_or_zero);

pub const CANONICAL_DESTINATION_HINT = DestinationHintBinding{
    .recipe = hint_recipe.id(.field_inverse_or_zero),
    .recipe_version = destination_recipe.version,
    .algorithm = destination_recipe.algorithm,
    .exceptional_cases = destination_recipe.exceptional_cases,
    .input_column = 3,
    .inverse_output_column = 19,
    .nonzero_output_column = 18,
};

pub const SlotBinding = struct {
    column: u8,
    value: types.ValueId,
    source: RowSource,
};

pub const WitnessBinding = struct {
    format_version: u16,
    semantic_format_version: u16,
    opcode_id: u32,
    semantic_digest: digest.Digest,
    slots: [MAIN_COLUMN_COUNT]SlotBinding,
    arithmetic: ArithmeticBinding,
    destination_hint: DestinationHintBinding,

    pub fn canonical(
        definition: *const typed_auipc.Definition,
    ) ConstructionError!WitnessBinding {
        try definition.validate();
        try validatePhysicalDefinition(definition);
        const physical = definition.columns.physical();
        var slots: [MAIN_COLUMN_COUNT]SlotBinding = undefined;
        for (&slots, physical, CANONICAL_RECIPE, 0..) |
            *slot,
            value,
            source,
            column,
        | slot.* = .{
            .column = @intCast(column),
            .value = value,
            .source = source,
        };
        return .{
            .format_version = WITNESS_BINDING_FORMAT_VERSION,
            .semantic_format_version = digest.range_refinement_format_version,
            .opcode_id = typed_auipc.OPCODE_ID,
            .semantic_digest = typed_auipc.SEMANTIC_DIGEST,
            .slots = slots,
            .arithmetic = CANONICAL_ARITHMETIC,
            .destination_hint = CANONICAL_DESTINATION_HINT,
        };
    }

    pub fn identityDigest(self: *const WitnessBinding) digest.Digest {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(WITNESS_BINDING_DOMAIN_SEPARATOR);
        hashInt(&hash, u16, self.format_version);
        hashInt(&hash, u16, self.semantic_format_version);
        hashInt(&hash, u32, self.opcode_id);
        hash.update(&self.semantic_digest);
        hashInt(&hash, u16, MAIN_COLUMN_COUNT);
        for (self.slots) |slot| {
            hashInt(&hash, u8, slot.column);
            hashInt(&hash, u32, @intFromEnum(slot.value));
            hashInt(&hash, u8, @intFromEnum(slot.source));
        }
        hashInt(&hash, u8, @intFromEnum(self.arithmetic.algorithm));
        hashInt(&hash, u8, self.arithmetic.pc_column);
        hashInt(&hash, u8, self.arithmetic.immediate_column);
        hashInt(&hash, u8, self.arithmetic.first_result_column);
        hashInt(&hash, u8, self.arithmetic.result_limb_count);
        hashInt(&hash, u16, @intFromEnum(self.destination_hint.recipe));
        hashInt(&hash, u16, self.destination_hint.recipe_version);
        hashInt(&hash, u16, @intFromEnum(self.destination_hint.algorithm));
        hashInt(
            &hash,
            u8,
            @intFromEnum(self.destination_hint.exceptional_cases),
        );
        hashInt(&hash, u8, self.destination_hint.input_column);
        hashInt(&hash, u8, self.destination_hint.inverse_output_column);
        hashInt(&hash, u8, self.destination_hint.nonzero_output_column);
        return hash.finalResult();
    }
};

pub const ConstructionError = typed_auipc.ValidationError || error{
    InvalidWitnessBinding,
};
pub const ExecutionError = direct_witness_executor.Error;

pub const Executor = struct {
    binding: WitnessBinding,
    binding_digest: digest.Digest,

    pub fn init(
        definition: *const typed_auipc.Definition,
        supplied: *const WitnessBinding,
    ) ConstructionError!Executor {
        const expected = try WitnessBinding.canonical(definition);
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
};

const PhysicalSpec = struct {
    name: []const u8,
    ty: types.Type,
    source: RowSource,
};

const uint7 = types.Type{ .bounded_uint = .{
    .bits = 7,
    .representation = .canonical_field,
} };

const physical_specs = [MAIN_COLUMN_COUNT]PhysicalSpec{
    .{ .name = "enabler", .ty = .bit, .source = .constant_one },
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
    .{ .name = "imm_felt", .ty = .felt, .source = .trace_signed_immediate },
    .{ .name = "result_0", .ty = .byte, .source = .derived_wrapping_result_byte_0 },
    .{ .name = "result_1", .ty = .byte, .source = .derived_wrapping_result_byte_1 },
    .{ .name = "result_2", .ty = .byte, .source = .derived_wrapping_result_byte_2 },
    .{ .name = "result_3", .ty = .byte, .source = .derived_wrapping_result_byte_3 },
    .{ .name = "rd_nonzero", .ty = .bit, .source = .hint_rd_nonzero },
    .{ .name = "rd_inv", .ty = .felt, .source = .hint_rd_inverse_or_zero },
    .{ .name = "pc_limb_0", .ty = .byte, .source = .trace_pc_byte_0 },
    .{ .name = "pc_limb_1", .ty = .byte, .source = .trace_pc_byte_1 },
    .{ .name = "pc_limb_2", .ty = .byte, .source = .trace_pc_byte_2 },
    .{ .name = "pc_limb_3", .ty = uint7, .source = .trace_pc_byte_3 },
    .{ .name = "imm_limb_0", .ty = .byte, .source = .trace_immediate_byte_0 },
    .{ .name = "imm_limb_1", .ty = .byte, .source = .trace_immediate_byte_1 },
    .{ .name = "imm_limb_2", .ty = .byte, .source = .trace_immediate_byte_2 },
    .{ .name = "imm_limb_3", .ty = .byte, .source = .trace_immediate_byte_3 },
    .{ .name = "imm_sign", .ty = .bit, .source = .trace_immediate_sign },
};

fn validatePhysicalDefinition(
    definition: *const typed_auipc.Definition,
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

pub inline fn writeActiveRow(
    columns: anytype,
    row_index: usize,
    row: TraceRow,
) void {
    const previous = limbs(row.rd_prev_val);
    const next = limbs(row.rd_val);
    const pc = limbs(row.pc);
    const immediate_bits: u32 = @bitCast(row.imm);
    const immediate = limbs(immediate_bits);
    const result = limbs(row.pc +% immediate_bits);
    const rd = fromUnsigned(row.rd);
    const nonzero = row.rd != 0;

    inline for (CANONICAL_RECIPE, 0..) |source, column| {
        columns[column][row_index] = switch (source) {
            .constant_one => M31.one(),
            .trace_clock => fromUnsigned(row.clk),
            .trace_pc => fromUnsigned(row.pc),
            .trace_rd_address => rd,
            .trace_rd_previous_byte_0 => previous[0],
            .trace_rd_previous_byte_1 => previous[1],
            .trace_rd_previous_byte_2 => previous[2],
            .trace_rd_previous_byte_3 => previous[3],
            .trace_rd_previous_clock => fromUnsigned(row.rd_prev_clk),
            .trace_rd_next_byte_0 => next[0],
            .trace_rd_next_byte_1 => next[1],
            .trace_rd_next_byte_2 => next[2],
            .trace_rd_next_byte_3 => next[3],
            .trace_signed_immediate => signed(row.imm),
            .derived_wrapping_result_byte_0 => result[0],
            .derived_wrapping_result_byte_1 => result[1],
            .derived_wrapping_result_byte_2 => result[2],
            .derived_wrapping_result_byte_3 => result[3],
            .hint_rd_nonzero => if (nonzero) M31.one() else M31.zero(),
            .hint_rd_inverse_or_zero => if (nonzero)
                rd.invUncheckedNonZero()
            else
                M31.zero(),
            .trace_pc_byte_0 => pc[0],
            .trace_pc_byte_1 => pc[1],
            .trace_pc_byte_2 => pc[2],
            .trace_pc_byte_3 => pc[3],
            .trace_immediate_byte_0 => immediate[0],
            .trace_immediate_byte_1 => immediate[1],
            .trace_immediate_byte_2 => immediate[2],
            .trace_immediate_byte_3 => immediate[3],
            .trace_immediate_sign => if (row.imm < 0) M31.one() else M31.zero(),
        };
    }
}

fn validateRow(row: TraceRow) ExecutionError!void {
    const immediate: u32 = @bitCast(row.imm);
    const result = row.pc +% immediate;
    if (row.opcode != .AUIPC or
        immediate & 0xfff != 0 or
        row.pc >= (@as(u32, 1) << 30) or
        row.next_pc != row.pc +% 4 or
        row.rd_val != (if (row.rd == 0) 0 else result) or
        (row.rd == 0 and (row.rd_prev_val != 0 or row.rd_prev_clk != 0)))
    {
        return error.InvalidTraceRow;
    }
}

inline fn fromUnsigned(value: anytype) M31 {
    return M31.fromU64(@intCast(value));
}

inline fn signed(value: i32) M31 {
    if (value >= 0) return fromUnsigned(value);
    return M31.zero().sub(M31.fromU64(@intCast(-@as(i64, value))));
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
    if (MAIN_COLUMN_COUNT != production_columns.AuipcColumns.N_COLUMNS)
        @compileError("typed AUIPC witness width drifted from production");
    const fields = @typeInfo(production_columns.AuipcColumns).@"struct".fields;
    for (physical_specs, fields, CANONICAL_RECIPE, 0..) |
        spec,
        field,
        source,
        index,
    | {
        if (!std.mem.eql(u8, spec.name, field.name))
            @compileError("typed AUIPC witness name drifted from production");
        if (spec.source != source or @intFromEnum(source) != index)
            @compileError("typed AUIPC numeric witness recipe is not canonical");
    }
}
