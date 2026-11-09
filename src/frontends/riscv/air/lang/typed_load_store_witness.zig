//! Allocation-free production witness generation for typed RV32 loads/stores.
//!
//! The prepared binding authenticates the native 50-column definition and its
//! complete opcode family. The row loop writes final SoA storage directly and
//! preserves the production role split between register and memory accesses.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const direct_witness_executor = @import("direct_witness_executor.zig");
const digest = @import("digest.zig");
const trace_row = @import("../../runner/trace_row.zig");
const production_columns = @import("../trace_columns/memory.zig");
const typed_load_store = @import("typed_load_store.zig");
const types = @import("types.zig");

pub const MAIN_COLUMN_COUNT: usize = typed_load_store.MAIN_COLUMN_COUNT;
pub const TraceRow = trace_row.TraceRow;

pub const WITNESS_BINDING_FORMAT_VERSION: u16 = 1;
pub const WITNESS_BINDING_DOMAIN_SEPARATOR =
    "stwo-zig/typed-air/load-store-witness-binding/v1";
pub const WITNESS_BINDING_DIGEST_HEX =
    "64e774c27535518b4abd2d3b44adb3c27141a774a244912965b02df92cdf61a3";
pub const WITNESS_BINDING_DIGEST: digest.Digest = hexDigest(
    WITNESS_BINDING_DIGEST_HEX,
    "invalid typed load/store witness-binding digest",
);
const ENFORCE_WITNESS_BINDING_DIGEST = true;

pub const RowSource = enum(u8) {
    clock = 0,
    pc = 1,
    dst_addr = 2,
    dst_prev_0 = 3,
    dst_prev_1 = 4,
    dst_prev_2 = 5,
    dst_prev_3 = 6,
    dst_clock_prev = 7,
    dst_next_0 = 8,
    dst_next_1 = 9,
    dst_next_2 = 10,
    dst_next_3 = 11,
    rs1_addr = 12,
    rs1_prev_0 = 13,
    rs1_prev_1 = 14,
    rs1_prev_2 = 15,
    rs1_prev_3 = 16,
    rs1_clock_prev = 17,
    src_addr = 18,
    src_prev_0 = 19,
    src_prev_1 = 20,
    src_prev_2 = 21,
    src_prev_3 = 22,
    src_clock_prev = 23,
    r2_idx = 24,
    imm_felt = 25,
    src_msb = 26,
    shift_amount = 27,
    src_addr_selector = 28,
    dst_addr_selector = 29,
    marker_0 = 30,
    marker_1 = 31,
    marker_2 = 32,
    marker_3 = 33,
    opcode_lb_flag = 34,
    opcode_lh_flag = 35,
    opcode_lbu_flag = 36,
    opcode_lhu_flag = 37,
    opcode_lw_flag = 38,
    opcode_sb_flag = 39,
    opcode_sh_flag = 40,
    opcode_sw_flag = 41,
    result_0 = 42,
    result_1 = 43,
    result_2 = 44,
    result_3 = 45,
    rd_nonzero = 46,
    rd_inv = 47,
    aligned_addr_quarter = 48,
    aligned_addr_low20 = 49,
};

pub const CANONICAL_RECIPE = std.enums.values(RowSource);

pub const SlotBinding = struct {
    column: u8,
    value: types.ValueId,
    source: RowSource,
};

pub const WitnessBinding = struct {
    format_version: u16,
    semantic_format_version: u16,
    opcode_ids: [8]u32,
    semantic_digest: digest.Digest,
    slots: [MAIN_COLUMN_COUNT]SlotBinding,

    pub fn canonical(
        definition: *const typed_load_store.Definition,
    ) WitnessBinding {
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
            .semantic_format_version = digest.conditional_access_format_version,
            .opcode_ids = typed_load_store.OPCODE_IDS,
            .semantic_digest = typed_load_store.SEMANTIC_DIGEST,
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
        hashInt(&hash, u16, MAIN_COLUMN_COUNT);
        for (self.slots) |slot| {
            hashInt(&hash, u8, slot.column);
            hashInt(&hash, u32, @intFromEnum(slot.value));
            hashInt(&hash, u8, @intFromEnum(slot.source));
        }
        return hash.finalResult();
    }
};

pub const ConstructionError = typed_load_store.ValidationError || error{
    InvalidWitnessBinding,
};
pub const ExecutionError = direct_witness_executor.Error;

pub const Executor = struct {
    binding: WitnessBinding,
    binding_digest: digest.Digest,

    pub fn init(
        definition: *const typed_load_store.Definition,
        supplied: *const WitnessBinding,
    ) ConstructionError!Executor {
        try definition.validate();
        try validateBinding(definition, supplied);
        const owned = supplied.*;
        const binding_digest = owned.identityDigest();
        if (ENFORCE_WITNESS_BINDING_DIGEST and
            !std.mem.eql(u8, &binding_digest, &WITNESS_BINDING_DIGEST))
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
            validateTraceRow,
            writeActiveRow,
        );
    }
};

const physical_types = [MAIN_COLUMN_COUNT]types.Type{
    .clock,                                                                   .pc,
    .felt,                                                                    .byte,
    .byte,                                                                    .byte,
    .byte,                                                                    .clock,
    .byte,                                                                    .byte,
    .byte,                                                                    .byte,
    .register_index,                                                          .byte,
    .byte,                                                                    .byte,
    .byte,                                                                    .clock,
    .felt,                                                                    .byte,
    .byte,                                                                    .byte,
    .byte,                                                                    .clock,
    .register_index,                                                          .felt,
    .bit,                                                                     .felt,
    .felt,                                                                    .felt,
    .bit,                                                                     .bit,
    .bit,                                                                     .bit,
    .bit,                                                                     .bit,
    .bit,                                                                     .bit,
    .bit,                                                                     .bit,
    .bit,                                                                     .bit,
    .byte,                                                                    .byte,
    .byte,                                                                    .byte,
    .bit,                                                                     .felt,
    .{ .bounded_uint = .{ .bits = 28, .representation = .canonical_field } }, .uint20,
};

fn validateBinding(
    definition: *const typed_load_store.Definition,
    supplied: *const WitnessBinding,
) error{InvalidWitnessBinding}!void {
    if (supplied.format_version != WITNESS_BINDING_FORMAT_VERSION or
        supplied.semantic_format_version != digest.conditional_access_format_version or
        !std.mem.eql(u32, &supplied.opcode_ids, &typed_load_store.OPCODE_IDS) or
        !std.mem.eql(u8, &supplied.semantic_digest, &typed_load_store.SEMANTIC_DIGEST))
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

const RowValues = struct {
    dst_addr: M31,
    dst_previous: [4]M31,
    dst_previous_clock: M31,
    dst_next: [4]M31,
    rs1_value: [4]M31,
    src_addr: M31,
    src_value: [4]M31,
    src_previous_clock: M31,
    r2: u5,
    src_msb: M31,
    shift: u32,
    src_selector: M31,
    dst_selector: M31,
    markers: [4]M31,
    result: [4]M31,
};

pub inline fn writeActiveRow(columns: anytype, row_index: usize, row: TraceRow) void {
    const values = derive(row);
    const rd_nonzero = values.r2 != 0;
    const rd = fromUnsigned(values.r2);

    inline for (CANONICAL_RECIPE, 0..) |source, column| {
        columns[column][row_index] = switch (source) {
            .clock => fromUnsigned(row.clk),
            .pc => fromUnsigned(row.pc),
            .dst_addr => values.dst_addr,
            .dst_prev_0 => values.dst_previous[0],
            .dst_prev_1 => values.dst_previous[1],
            .dst_prev_2 => values.dst_previous[2],
            .dst_prev_3 => values.dst_previous[3],
            .dst_clock_prev => values.dst_previous_clock,
            .dst_next_0 => values.dst_next[0],
            .dst_next_1 => values.dst_next[1],
            .dst_next_2 => values.dst_next[2],
            .dst_next_3 => values.dst_next[3],
            .rs1_addr => fromUnsigned(row.rs1),
            .rs1_prev_0 => values.rs1_value[0],
            .rs1_prev_1 => values.rs1_value[1],
            .rs1_prev_2 => values.rs1_value[2],
            .rs1_prev_3 => values.rs1_value[3],
            .rs1_clock_prev => fromUnsigned(row.rs1_prev_clk),
            .src_addr => values.src_addr,
            .src_prev_0 => values.src_value[0],
            .src_prev_1 => values.src_value[1],
            .src_prev_2 => values.src_value[2],
            .src_prev_3 => values.src_value[3],
            .src_clock_prev => values.src_previous_clock,
            .r2_idx => rd,
            .imm_felt => fromSigned(row.imm),
            .src_msb => values.src_msb,
            .shift_amount => fromUnsigned(values.shift),
            .src_addr_selector => values.src_selector,
            .dst_addr_selector => values.dst_selector,
            .marker_0 => values.markers[0],
            .marker_1 => values.markers[1],
            .marker_2 => values.markers[2],
            .marker_3 => values.markers[3],
            .opcode_lb_flag => bit(row.opcode == .LB),
            .opcode_lh_flag => bit(row.opcode == .LH),
            .opcode_lbu_flag => bit(row.opcode == .LBU),
            .opcode_lhu_flag => bit(row.opcode == .LHU),
            .opcode_lw_flag => bit(row.opcode == .LW),
            .opcode_sb_flag => bit(row.opcode == .SB),
            .opcode_sh_flag => bit(row.opcode == .SH),
            .opcode_sw_flag => bit(row.opcode == .SW),
            .result_0 => values.result[0],
            .result_1 => values.result[1],
            .result_2 => values.result[2],
            .result_3 => values.result[3],
            .rd_nonzero => bit(rd_nonzero),
            .rd_inv => if (rd_nonzero) rd.invUncheckedNonZero() else M31.zero(),
            .aligned_addr_quarter => fromUnsigned((row.mem_addr & ~@as(u32, 3)) >> 2),
            .aligned_addr_low20 => fromUnsigned(
                ((row.mem_addr & ~@as(u32, 3)) >> 2) & ((1 << 20) - 1),
            ),
        };
    }
}

fn derive(row: TraceRow) RowValues {
    const byte_op = row.opcode == .LB or row.opcode == .LBU or row.opcode == .SB;
    const half_op = row.opcode == .LH or row.opcode == .LHU or row.opcode == .SH;
    const offset = row.mem_addr & 3;
    const shift = if (byte_op) offset else if (half_op) offset & 2 else 0;
    const r2: u5 = if (row.is_load) row.rd else row.rs2;
    const aligned = row.mem_addr -% shift;
    const result_word = loadResult(row);

    var markers = [_]M31{M31.zero()} ** 4;
    for (&markers, 0..) |*marker, limb| {
        const marked = if (byte_op)
            limb == offset
        else if (half_op)
            (offset < 2 and limb < 2) or (offset >= 2 and limb >= 2)
        else
            false;
        marker.* = bit(marked);
    }

    return .{
        .dst_addr = fromUnsigned(if (row.is_store) row.mem_addr & ~@as(u32, 3) else row.rd),
        .dst_previous = limbs(if (row.is_store) row.mem_prev_word else row.rd_prev_val),
        .dst_previous_clock = fromUnsigned(if (row.is_store) row.mem_prev_clk else row.rd_prev_clk),
        .dst_next = limbs(if (row.is_store) row.mem_next_word else row.rd_val),
        .rs1_value = limbs(row.rs1_val),
        .src_addr = fromUnsigned(if (row.is_load) row.mem_addr & ~@as(u32, 3) else row.rs2),
        .src_value = limbs(if (row.is_load) row.mem_prev_word else row.rs2_val),
        .src_previous_clock = fromUnsigned(if (row.is_load) row.mem_prev_clk else row.rs2_prev_clk),
        .r2 = r2,
        .src_msb = if (row.opcode == .LB or row.opcode == .LH)
            fromUnsigned((result_word >> 31) & 1)
        else
            M31.zero(),
        .shift = shift,
        .src_selector = fromUnsigned(if (row.is_load) aligned else r2),
        .dst_selector = fromUnsigned(if (row.is_load) r2 else aligned),
        .markers = markers,
        .result = limbs(result_word),
    };
}

inline fn loadResult(row: TraceRow) u32 {
    return switch (row.opcode) {
        .LB => @bitCast(@as(i32, @as(i8, @bitCast(@as(u8, @truncate(row.mem_val)))))),
        .LH => @bitCast(@as(i32, @as(i16, @bitCast(@as(u16, @truncate(row.mem_val)))))),
        .LBU, .LHU, .LW => row.mem_val,
        else => 0,
    };
}

pub fn validateTraceRow(row: TraceRow) ExecutionError!void {
    const expected_load = switch (row.opcode) {
        .LB, .LH, .LBU, .LHU, .LW => true,
        .SB, .SH, .SW => false,
        else => return error.InvalidTraceRow,
    };
    if (row.is_load != expected_load or row.is_store == expected_load)
        return error.InvalidTraceRow;
}

inline fn fromUnsigned(value: anytype) M31 {
    return M31.fromU64(@intCast(value));
}

inline fn fromSigned(value: i32) M31 {
    if (value >= 0) return fromUnsigned(value);
    return M31.zero().sub(M31.fromU64(@intCast(-@as(i64, value))));
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
    if (MAIN_COLUMN_COUNT != production_columns.LoadStoreColumns.N_COLUMNS)
        @compileError("typed load/store witness width drifted from production");
    const fields = @typeInfo(production_columns.LoadStoreColumns).@"struct".fields;
    for (fields, CANONICAL_RECIPE, 0..) |field, source, index| {
        if (@intFromEnum(source) != index)
            @compileError("typed load/store numeric witness recipe is not canonical");
        if (!std.mem.eql(u8, field.name, @tagName(source)))
            @compileError("typed load/store witness name drifted from production");
    }
}
