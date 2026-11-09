//! Allocation-free production witness generation for native typed RV32 FENCE.
//!
//! Cold construction authenticates the semantic program and exact six-slot
//! source recipe. Accepted hot rows write directly into caller-owned final SoA
//! storage with no allocator, scratch copy, dynamic dispatch, or recipe loop.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const direct_witness_executor = @import("direct_witness_executor.zig");
const digest = @import("digest.zig");
const trace_row = @import("../../runner/trace_row.zig");
const production_columns = @import("../trace_columns/control.zig");
const typed_fence = @import("typed_fence.zig");
const types = @import("types.zig");

pub const MAIN_COLUMN_COUNT: usize = typed_fence.MAIN_COLUMN_COUNT;
pub const TraceRow = trace_row.TraceRow;

pub const WITNESS_BINDING_FORMAT_VERSION: u16 = 1;
pub const WITNESS_BINDING_DOMAIN_SEPARATOR =
    "stwo-zig/typed-air/fence-witness-binding/v1";
pub const WITNESS_BINDING_DIGEST_HEX =
    "58ce202e83000452d1b53f29173680b60d46c8a1703911cf44a7b891405eda07";
pub const WITNESS_BINDING_DIGEST: digest.Digest = hexDigest(
    WITNESS_BINDING_DIGEST_HEX,
    "invalid typed FENCE witness-binding digest",
);

pub const RowSource = enum(u8) {
    constant_one = 0,
    trace_clock = 1,
    trace_pc = 2,
    trace_encoding_rd = 3,
    trace_encoding_rs1 = 4,
    trace_immediate_low_12_bits = 5,
};

pub const CANONICAL_RECIPE = [MAIN_COLUMN_COUNT]RowSource{
    .constant_one,
    .trace_clock,
    .trace_pc,
    .trace_encoding_rd,
    .trace_encoding_rs1,
    .trace_immediate_low_12_bits,
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

    pub fn canonical(definition: *const typed_fence.Definition) ConstructionError!WitnessBinding {
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
            .semantic_format_version = digest.sequential_retirement_format_version,
            .opcode_id = typed_fence.OPCODE_ID,
            .semantic_digest = typed_fence.SEMANTIC_DIGEST,
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
        hashInt(&hash, u16, MAIN_COLUMN_COUNT);
        for (self.slots) |slot| {
            hashInt(&hash, u8, slot.column);
            hashInt(&hash, u32, @intFromEnum(slot.value));
            hashInt(&hash, u8, @intFromEnum(slot.source));
        }
        return hash.finalResult();
    }
};

pub const ConstructionError = typed_fence.ValidationError || error{
    InvalidWitnessBinding,
};
pub const ExecutionError = direct_witness_executor.Error;

pub const Executor = struct {
    binding: WitnessBinding,
    binding_digest: digest.Digest,

    pub fn init(
        definition: *const typed_fence.Definition,
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

const uint12 = types.Type{ .bounded_uint = .{
    .bits = 12,
    .representation = .canonical_field,
} };

const PhysicalSpec = struct {
    name: []const u8,
    ty: types.Type,
    source: RowSource,
};

const physical_specs = [MAIN_COLUMN_COUNT]PhysicalSpec{
    .{ .name = "enabler", .ty = .bit, .source = .constant_one },
    .{ .name = "clock", .ty = .clock, .source = .trace_clock },
    .{ .name = "pc", .ty = .pc, .source = .trace_pc },
    .{ .name = "rd", .ty = .register_index, .source = .trace_encoding_rd },
    .{ .name = "rs1", .ty = .register_index, .source = .trace_encoding_rs1 },
    .{ .name = "immediate", .ty = uint12, .source = .trace_immediate_low_12_bits },
};

fn validatePhysicalDefinition(
    definition: *const typed_fence.Definition,
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
    const immediate: u32 = @bitCast(row.imm);
    inline for (CANONICAL_RECIPE, 0..) |source, column| {
        columns[column][row_index] = switch (source) {
            .constant_one => M31.one(),
            .trace_clock => fromUnsigned(row.clk),
            .trace_pc => fromUnsigned(row.pc),
            .trace_encoding_rd => fromUnsigned(row.rd),
            .trace_encoding_rs1 => fromUnsigned(row.rs1),
            .trace_immediate_low_12_bits => fromUnsigned(immediate & 0xfff),
        };
    }
}

fn validateRow(row: TraceRow) ExecutionError!void {
    if (row.opcode != .FENCE or
        row.imm < -2048 or row.imm > 2047 or
        row.next_pc != row.pc +% 4 or
        row.branch_taken or row.is_load or row.is_store or
        row.rd_val != row.rd_prev_val or
        row.rs1_prev_clk != 0 or row.rs2_prev_clk != 0 or row.rd_prev_clk != 0 or
        row.mem_addr != 0 or row.mem_val != 0 or row.mem_prev_word != 0 or
        row.mem_next_word != 0 or row.mem_prev_clk != 0)
    {
        return error.InvalidTraceRow;
    }
}

inline fn fromUnsigned(value: anytype) M31 {
    return M31.fromU64(@intCast(value));
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
    if (MAIN_COLUMN_COUNT != production_columns.FenceColumns.N_COLUMNS)
        @compileError("typed FENCE witness width drifted from production");
    const fields = @typeInfo(production_columns.FenceColumns).@"struct".fields;
    for (physical_specs, fields, CANONICAL_RECIPE, 0..) |
        spec,
        field,
        source,
        index,
    | {
        if (!std.mem.eql(u8, spec.name, field.name))
            @compileError("typed FENCE witness name drifted from production");
        if (spec.source != source or @intFromEnum(source) != index)
            @compileError("typed FENCE numeric witness recipe is not canonical");
    }
}
