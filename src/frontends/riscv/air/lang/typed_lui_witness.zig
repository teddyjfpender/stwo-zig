//! Allocation-free production witness generation for native typed RV32 LUI.
//!
//! The current typed expression IR deliberately treats every physical LUI
//! column as an input. It therefore cannot infer whether a cell comes directly
//! from a runner row, from a byte decomposition, or from an inverse hint. This
//! module closes that gap explicitly: `WitnessBinding` is the versioned numeric
//! identity of the exact 18-slot row-source recipe. Construction authenticates
//! that recipe against the validated typed definition and production-compatible
//! physical names and types before returning a self-contained executor.
//!
//! This module is the sole production authority for active LUI family rows.
//! It writes the final preallocated column storage directly; the runner owns
//! padding zeroing and physical row placement. The former handwritten writer
//! is retained only as an independent test oracle.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const direct_witness_executor = @import("direct_witness_executor.zig");
const digest = @import("digest.zig");
const trace_row = @import("../../runner/trace_row.zig");
const production_columns = @import("../trace_columns/control.zig");
const typed_lui = @import("typed_lui.zig");
const types = @import("types.zig");

pub const MAIN_COLUMN_COUNT: usize = typed_lui.MAIN_COLUMN_COUNT;
pub const TraceRow = trace_row.TraceRow;

pub const WITNESS_BINDING_FORMAT_VERSION: u16 = 1;
pub const WITNESS_BINDING_DOMAIN_SEPARATOR =
    "stwo-zig/typed-air/lui-witness-binding/v1";
pub const WITNESS_BINDING_DIGEST_HEX =
    "4c17aa282c61916a03bdba82739b50b913c595505fec8de7b6a4b30dc51df1fc";

pub const WITNESS_BINDING_DIGEST: digest.Digest = blk: {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, WITNESS_BINDING_DIGEST_HEX) catch
        @compileError("invalid typed LUI witness-binding digest");
    break :blk result;
};

/// Stable numeric row-source codes. The explicit values are artifact identity,
/// not implementation ordinals inferred from field names.
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
    trace_u_immediate_low_nibble = 13,
    trace_u_immediate_middle_byte = 14,
    trace_u_immediate_high_byte = 15,
    rd_nonzero = 16,
    rd_inverse_or_zero = 17,
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
    .trace_u_immediate_low_nibble,
    .trace_u_immediate_middle_byte,
    .trace_u_immediate_high_byte,
    .rd_nonzero,
    .rd_inverse_or_zero,
};

pub const SlotBinding = struct {
    column: u8,
    value: types.ValueId,
    source: RowSource,
};

/// Transportable, pointer-free witness identity. A canonical value can be
/// retained after the authored arena is destroyed.
pub const WitnessBinding = struct {
    format_version: u16,
    semantic_format_version: u16,
    opcode_id: u32,
    semantic_digest: digest.Digest,
    slots: [MAIN_COLUMN_COUNT]SlotBinding,

    pub fn canonical(definition: *const typed_lui.Definition) WitnessBinding {
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
            .semantic_format_version = digest.sequential_retirement_format_version,
            .opcode_id = typed_lui.OPCODE_ID,
            .semantic_digest = typed_lui.SEMANTIC_DIGEST,
            .slots = slots,
        };
    }

    /// Canonical digest of the complete executable binding. This is computed at
    /// the cold construction boundary and never in witness generation.
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

pub const ConstructionError = typed_lui.ValidationError || error{
    InvalidWitnessBinding,
};

pub const ExecutionError = direct_witness_executor.Error;

/// Immutable, self-contained LUI witness executor.
///
/// It owns no allocation or scratch state and is safe to share between worker
/// threads. `generateMainInto` is allocation-free and reentrant.
pub const Executor = struct {
    binding: WitnessBinding,
    binding_digest: digest.Digest,

    pub fn init(
        definition: *const typed_lui.Definition,
        supplied: *const WitnessBinding,
    ) ConstructionError!Executor {
        // Establish semantic authority before trusting any supplied binding
        // field, then authenticate the witness-only source recipe explicitly.
        try definition.validate();
        try validateBinding(definition, supplied);
        const owned = supplied.*;
        const binding_digest = owned.identityDigest();
        if (!std.mem.eql(u8, &binding_digest, &WITNESS_BINDING_DIGEST))
            return error.InvalidWitnessBinding;
        return .{
            .binding = owned,
            .binding_digest = binding_digest,
        };
    }

    pub fn identitySnapshot(self: *const Executor) WitnessBinding {
        return self.binding;
    }

    pub fn identityDigest(self: *const Executor) digest.Digest {
        return self.binding_digest;
    }

    /// Fill final column-major main storage in the same logical row order as
    /// `Trace.columnsForFamily(.lui)`. Unused domain rows are exactly zero.
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

const uint4 = types.Type{ .bounded_uint = .{
    .bits = 4,
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
    .{ .name = "imm_0", .ty = uint4, .source = .trace_u_immediate_low_nibble },
    .{ .name = "imm_1", .ty = .byte, .source = .trace_u_immediate_middle_byte },
    .{ .name = "imm_2", .ty = .byte, .source = .trace_u_immediate_high_byte },
    .{ .name = "rd_nonzero", .ty = .bit, .source = .rd_nonzero },
    .{ .name = "rd_inv", .ty = .felt, .source = .rd_inverse_or_zero },
};

fn validateBinding(
    definition: *const typed_lui.Definition,
    supplied: *const WitnessBinding,
) error{InvalidWitnessBinding}!void {
    if (supplied.format_version != WITNESS_BINDING_FORMAT_VERSION or
        supplied.semantic_format_version != digest.sequential_retirement_format_version or
        supplied.opcode_id != typed_lui.OPCODE_ID or
        !std.mem.eql(u8, &supplied.semantic_digest, &typed_lui.SEMANTIC_DIGEST))
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

/// Write one already-admitted active row into final column-major storage.
///
/// This is the production hot path called after opcode classification and
/// shard placement. It is allocation-free, branch-bounded, and contains no
/// string or recipe dispatch. The checked batch executor above uses the same
/// function after validating shapes, aliasing, and every row opcode.
pub inline fn writeActiveRow(
    columns: anytype,
    row_index: usize,
    row: TraceRow,
) void {
    const previous = limbs(row.rd_prev_val);
    const next = limbs(row.rd_val);
    const immediate = @as(u32, @bitCast(row.imm)) >> 12;
    const rd = fromUnsigned(row.rd);
    const nonzero = row.rd != 0;

    // `inline` makes every source and destination a compile-time constant: the
    // recipe is the single column-order authority, while emitted code remains
    // 18 direct stores with no loop or tag dispatch.
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
            .trace_u_immediate_low_nibble => fromUnsigned(immediate & 0xf),
            .trace_u_immediate_middle_byte => fromUnsigned((immediate >> 4) & 0xff),
            .trace_u_immediate_high_byte => fromUnsigned(immediate >> 12),
            .rd_nonzero => if (nonzero) M31.one() else M31.zero(),
            .rd_inverse_or_zero => if (nonzero)
                rd.invUncheckedNonZero()
            else
                M31.zero(),
        };
    }
}

fn validateRow(row: TraceRow) ExecutionError!void {
    if (row.opcode != .LUI) return error.InvalidTraceRow;
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
    if (MAIN_COLUMN_COUNT != production_columns.LuiColumns.N_COLUMNS)
        @compileError("typed LUI witness width drifted from production");
    const production_fields = @typeInfo(production_columns.LuiColumns).@"struct".fields;
    for (physical_specs, production_fields, CANONICAL_RECIPE, 0..) |
        spec,
        field,
        source,
        index,
    | {
        if (!std.mem.eql(u8, spec.name, field.name))
            @compileError("typed LUI witness name drifted from production");
        if (spec.source != source or @intFromEnum(source) != index)
            @compileError("typed LUI numeric witness recipe is not canonical");
    }
}
