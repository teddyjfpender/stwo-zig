//! Allocation-free production witness generation for native typed RV32 JALR.
//!
//! `WitnessBinding` is the pointer-free, versioned identity of every physical
//! JALR column and its exact row source. Cold construction authenticates that
//! recipe against the validated typed semantic definition. The hot writer then
//! emits 41 direct stores into caller-owned final SoA storage without an
//! allocator, scratch buffer, indirect dispatch, or intermediate row object.
//!
//! Once wired by the runner, this module is the sole production authority for
//! active JALR rows. The former handwritten implementation is retained only as
//! an independent test oracle.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const direct_witness_executor = @import("direct_witness_executor.zig");
const digest = @import("digest.zig");
const trace_row = @import("../../runner/trace_row.zig");
const production_columns = @import("../trace_columns/control.zig");
const typed_jalr = @import("typed_jalr.zig");
const types = @import("types.zig");

pub const MAIN_COLUMN_COUNT: usize = typed_jalr.MAIN_COLUMN_COUNT;
pub const TraceRow = trace_row.TraceRow;

pub const WITNESS_BINDING_FORMAT_VERSION: u16 = 1;
pub const WITNESS_BINDING_DOMAIN_SEPARATOR =
    "stwo-zig/typed-air/jalr-witness-binding/v1";
pub const WITNESS_BINDING_DIGEST_HEX =
    "bd1f1fed416f562a83d8939e9e686d81ebf1a0b7f6753369c29db866568183fd";

pub const WITNESS_BINDING_DIGEST: digest.Digest = blk: {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, WITNESS_BINDING_DIGEST_HEX) catch
        @compileError("invalid typed JALR witness-binding digest");
    break :blk result;
};

/// Stable numeric source codes. Their explicit values are persisted witness
/// identity, not ordinals inferred from field names or declaration layout.
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
    trace_rs1_address = 13,
    trace_rs1_previous_byte_0 = 14,
    trace_rs1_previous_byte_1 = 15,
    trace_rs1_previous_byte_2 = 16,
    trace_rs1_previous_byte_3 = 17,
    trace_rs1_previous_clock = 18,
    trace_rs1_next_byte_0 = 19,
    trace_rs1_next_byte_1 = 20,
    trace_rs1_next_byte_2 = 21,
    trace_rs1_next_byte_3 = 22,
    derived_target_over_two = 23,
    derived_unaligned_lsb = 24,
    trace_signed_immediate = 25,
    derived_link_byte_0 = 26,
    derived_link_byte_1 = 27,
    derived_link_byte_2 = 28,
    derived_link_byte_3 = 29,
    hint_rd_nonzero = 30,
    hint_rd_inverse_or_zero = 31,
    derived_target_word_low_20 = 32,
    derived_target_word_high_8 = 33,
    derived_target_byte_0 = 34,
    derived_target_byte_1 = 35,
    derived_target_byte_2 = 36,
    derived_target_byte_3 = 37,
    derived_immediate_low_byte = 38,
    derived_immediate_high_nibble = 39,
    derived_immediate_sign = 40,
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
    .trace_rs1_address,
    .trace_rs1_previous_byte_0,
    .trace_rs1_previous_byte_1,
    .trace_rs1_previous_byte_2,
    .trace_rs1_previous_byte_3,
    .trace_rs1_previous_clock,
    .trace_rs1_next_byte_0,
    .trace_rs1_next_byte_1,
    .trace_rs1_next_byte_2,
    .trace_rs1_next_byte_3,
    .derived_target_over_two,
    .derived_unaligned_lsb,
    .trace_signed_immediate,
    .derived_link_byte_0,
    .derived_link_byte_1,
    .derived_link_byte_2,
    .derived_link_byte_3,
    .hint_rd_nonzero,
    .hint_rd_inverse_or_zero,
    .derived_target_word_low_20,
    .derived_target_word_high_8,
    .derived_target_byte_0,
    .derived_target_byte_1,
    .derived_target_byte_2,
    .derived_target_byte_3,
    .derived_immediate_low_byte,
    .derived_immediate_high_nibble,
    .derived_immediate_sign,
};

pub const SlotBinding = struct {
    column: u8,
    value: types.ValueId,
    source: RowSource,
};

/// Self-contained executable identity retained after the authored arena dies.
pub const WitnessBinding = struct {
    format_version: u16,
    semantic_format_version: u16,
    opcode_id: u32,
    semantic_digest: digest.Digest,
    slots: [MAIN_COLUMN_COUNT]SlotBinding,

    pub fn canonical(definition: *const typed_jalr.Definition) WitnessBinding {
        const physical = definition.columns.physical();
        var slots: [MAIN_COLUMN_COUNT]SlotBinding = undefined;
        for (&slots, physical, CANONICAL_RECIPE, 0..) |
            *slot,
            value,
            source,
            column,
        | {
            slot.* = .{
                .column = @intCast(column),
                .value = value,
                .source = source,
            };
        }
        return .{
            .format_version = WITNESS_BINDING_FORMAT_VERSION,
            .semantic_format_version = digest.range_refinement_format_version,
            .opcode_id = typed_jalr.OPCODE_ID,
            .semantic_digest = typed_jalr.SEMANTIC_DIGEST,
            .slots = slots,
        };
    }

    /// Canonical digest of the complete witness binding, computed only at the
    /// cold construction boundary.
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
        return hash.finalResult();
    }
};

pub const ConstructionError = typed_jalr.ValidationError || error{
    InvalidWitnessBinding,
};

pub const ExecutionError = direct_witness_executor.Error;

/// Immutable JALR witness executor, allocation-free and reentrant after init.
pub const Executor = struct {
    binding: WitnessBinding,
    binding_digest: digest.Digest,

    pub fn init(
        definition: *const typed_jalr.Definition,
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

    /// Fill final column-major storage in logical row order and zero padding.
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
    .{ .name = "rs1_addr", .ty = .register_index, .source = .trace_rs1_address },
    .{ .name = "rs1_prev_0", .ty = .byte, .source = .trace_rs1_previous_byte_0 },
    .{ .name = "rs1_prev_1", .ty = .byte, .source = .trace_rs1_previous_byte_1 },
    .{ .name = "rs1_prev_2", .ty = .byte, .source = .trace_rs1_previous_byte_2 },
    .{ .name = "rs1_prev_3", .ty = .byte, .source = .trace_rs1_previous_byte_3 },
    .{ .name = "rs1_clock_prev", .ty = .clock, .source = .trace_rs1_previous_clock },
    .{ .name = "rs1_next_0", .ty = .byte, .source = .trace_rs1_next_byte_0 },
    .{ .name = "rs1_next_1", .ty = .byte, .source = .trace_rs1_next_byte_1 },
    .{ .name = "rs1_next_2", .ty = .byte, .source = .trace_rs1_next_byte_2 },
    .{ .name = "rs1_next_3", .ty = .byte, .source = .trace_rs1_next_byte_3 },
    .{ .name = "to_pc_over_two", .ty = .felt, .source = .derived_target_over_two },
    .{ .name = "to_pc_lsb", .ty = .bit, .source = .derived_unaligned_lsb },
    .{ .name = "imm_felt", .ty = .felt, .source = .trace_signed_immediate },
    .{ .name = "result_0", .ty = .byte, .source = .derived_link_byte_0 },
    .{ .name = "result_1", .ty = .byte, .source = .derived_link_byte_1 },
    .{ .name = "result_2", .ty = .byte, .source = .derived_link_byte_2 },
    .{ .name = "result_3", .ty = uint7, .source = .derived_link_byte_3 },
    .{ .name = "rd_nonzero", .ty = .bit, .source = .hint_rd_nonzero },
    .{ .name = "rd_inv", .ty = .felt, .source = .hint_rd_inverse_or_zero },
    .{ .name = "target_word_low_20", .ty = .uint20, .source = .derived_target_word_low_20 },
    .{ .name = "target_word_high_8", .ty = .byte, .source = .derived_target_word_high_8 },
    .{ .name = "target_0", .ty = .byte, .source = .derived_target_byte_0 },
    .{ .name = "target_1", .ty = .byte, .source = .derived_target_byte_1 },
    .{ .name = "target_2", .ty = .byte, .source = .derived_target_byte_2 },
    .{ .name = "target_3", .ty = uint7, .source = .derived_target_byte_3 },
    .{ .name = "imm_byte_0", .ty = .byte, .source = .derived_immediate_low_byte },
    .{ .name = "imm_nibble", .ty = .felt, .source = .derived_immediate_high_nibble },
    .{ .name = "imm_sign", .ty = .bit, .source = .derived_immediate_sign },
};

fn validateBinding(
    definition: *const typed_jalr.Definition,
    supplied: *const WitnessBinding,
) error{InvalidWitnessBinding}!void {
    if (supplied.format_version != WITNESS_BINDING_FORMAT_VERSION or
        supplied.semantic_format_version != digest.range_refinement_format_version or
        supplied.opcode_id != typed_jalr.OPCODE_ID or
        !std.mem.eql(u8, &supplied.semantic_digest, &typed_jalr.SEMANTIC_DIGEST))
    {
        return error.InvalidWitnessBinding;
    }

    const physical = definition.columns.physical();
    inline for (physical_specs, 0..) |spec, index| {
        const value = physical[index];
        const slot = supplied.slots[index];
        if (types.idIndex(value) != index or
            slot.column != index or
            slot.value != value or
            slot.source != spec.source or
            slot.source != CANONICAL_RECIPE[index])
        {
            return error.InvalidWitnessBinding;
        }
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

/// Write one already-admitted row directly into final column-major storage.
pub inline fn writeActiveRow(
    columns: anytype,
    row_index: usize,
    row: TraceRow,
) void {
    @setEvalBranchQuota(10_000);
    const rd_previous = limbs(row.rd_prev_val);
    const rd_next = limbs(row.rd_val);
    const rs1 = limbs(row.rs1_val);
    const unaligned = row.rs1_val +% @as(u32, @bitCast(row.imm));
    const target = unaligned & ~@as(u32, 1);
    const target_word = target >> 2;
    const immediate_bits: u32 = @bitCast(row.imm);
    const immediate_12 = immediate_bits & 0xfff;
    const link = limbs(row.pc +% 4);
    const target_bytes = limbs(target);
    const rd = fromUnsigned(row.rd);
    const nonzero = row.rd != 0;

    // Every source and destination is compile-time known after inlining. The
    // recipe remains the single ordering authority without runtime tag work.
    inline for (CANONICAL_RECIPE, 0..) |source, column| {
        columns[column][row_index] = switch (source) {
            .constant_one => M31.one(),
            .trace_clock => fromUnsigned(row.clk),
            .trace_pc => fromUnsigned(row.pc),
            .trace_rd_address => rd,
            .trace_rd_previous_byte_0 => rd_previous[0],
            .trace_rd_previous_byte_1 => rd_previous[1],
            .trace_rd_previous_byte_2 => rd_previous[2],
            .trace_rd_previous_byte_3 => rd_previous[3],
            .trace_rd_previous_clock => fromUnsigned(row.rd_prev_clk),
            .trace_rd_next_byte_0 => rd_next[0],
            .trace_rd_next_byte_1 => rd_next[1],
            .trace_rd_next_byte_2 => rd_next[2],
            .trace_rd_next_byte_3 => rd_next[3],
            .trace_rs1_address => fromUnsigned(row.rs1),
            .trace_rs1_previous_byte_0 => rs1[0],
            .trace_rs1_previous_byte_1 => rs1[1],
            .trace_rs1_previous_byte_2 => rs1[2],
            .trace_rs1_previous_byte_3 => rs1[3],
            .trace_rs1_previous_clock => fromUnsigned(row.rs1_prev_clk),
            .trace_rs1_next_byte_0 => rs1[0],
            .trace_rs1_next_byte_1 => rs1[1],
            .trace_rs1_next_byte_2 => rs1[2],
            .trace_rs1_next_byte_3 => rs1[3],
            .derived_target_over_two => fromUnsigned(target / 2),
            .derived_unaligned_lsb => fromUnsigned(unaligned & 1),
            .trace_signed_immediate => fromSigned(row.imm),
            .derived_link_byte_0 => link[0],
            .derived_link_byte_1 => link[1],
            .derived_link_byte_2 => link[2],
            .derived_link_byte_3 => link[3],
            .hint_rd_nonzero => if (nonzero) M31.one() else M31.zero(),
            .hint_rd_inverse_or_zero => if (nonzero)
                rd.invUncheckedNonZero()
            else
                M31.zero(),
            .derived_target_word_low_20 => fromUnsigned(target_word & 0xfffff),
            .derived_target_word_high_8 => fromUnsigned(target_word >> 20),
            .derived_target_byte_0 => target_bytes[0],
            .derived_target_byte_1 => target_bytes[1],
            .derived_target_byte_2 => target_bytes[2],
            .derived_target_byte_3 => target_bytes[3],
            .derived_immediate_low_byte => fromUnsigned(immediate_12 & 0xff),
            .derived_immediate_high_nibble => fromUnsigned(immediate_12 >> 8),
            .derived_immediate_sign => if (row.imm < 0) M31.one() else M31.zero(),
        };
    }
}

fn validateRow(row: TraceRow) ExecutionError!void {
    if (row.opcode != .JALR) return error.InvalidTraceRow;
}

inline fn fromUnsigned(value: anytype) M31 {
    return M31.fromU64(@intCast(value));
}

inline fn fromSigned(value: i32) M31 {
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

comptime {
    if (MAIN_COLUMN_COUNT != production_columns.JalrColumns.N_COLUMNS)
        @compileError("typed JALR witness width drifted from production");
    const production_fields = @typeInfo(production_columns.JalrColumns).@"struct".fields;
    for (physical_specs, production_fields, CANONICAL_RECIPE, 0..) |
        spec,
        field,
        source,
        index,
    | {
        if (!std.mem.eql(u8, spec.name, field.name))
            @compileError("typed JALR witness name drifted from production");
        if (spec.source != source or @intFromEnum(source) != index)
            @compileError("typed JALR numeric witness recipe is not canonical");
    }
}
