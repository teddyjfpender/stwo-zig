//! Allocation-free direct witness generation for typed recursion QM31 products.
//!
//! The hot row writer uses the canonical optimized `QM31.mul` implementation,
//! writes final SoA storage directly, and is authenticated against the exact
//! typed program and twelve-slot physical recipe during cold construction.

const std = @import("std");
const stwo_core = @import("stwo_core");
const direct_witness_executor = @import("../../air/lang/direct_witness_executor.zig");
const digest = @import("../../air/lang/digest.zig");
const types = @import("../../air/lang/types.zig");
const qm31_mul = @import("qm31_mul.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;

pub const PHYSICAL_COLUMN_COUNT = qm31_mul.PHYSICAL_COLUMN_COUNT;
pub const WITNESS_BINDING_FORMAT_VERSION: u16 = 1;
pub const WITNESS_BINDING_DOMAIN =
    "stwo-zig/typed-air/recursion-qm31-mul-witness-binding/v1\x00";
pub const WITNESS_BINDING_DIGEST_HEX =
    "f4092277db963c4d69d90f6b928776af54eb84b15c01f8ba5fc7ecececce10cc";
pub const WITNESS_BINDING_DIGEST: digest.Digest = hexDigest(
    WITNESS_BINDING_DIGEST_HEX,
    "invalid recursion QM31 multiplication witness-binding digest",
);

pub const Invocation = struct {
    a: QM31,
    b: QM31,
};

pub const RowSource = enum(u8) {
    a_0 = 0,
    a_1 = 1,
    a_2 = 2,
    a_3 = 3,
    b_0 = 4,
    b_1 = 5,
    b_2 = 6,
    b_3 = 7,
    c_0 = 8,
    c_1 = 9,
    c_2 = 10,
    c_3 = 11,
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
    semantic_digest: digest.Digest,
    slots: [PHYSICAL_COLUMN_COUNT]SlotBinding,

    pub fn canonical(definition: *const qm31_mul.Definition) ConstructionError!WitnessBinding {
        try definition.validate();
        var slots: [PHYSICAL_COLUMN_COUNT]SlotBinding = undefined;
        for (&slots, definition.columns.physical(), CANONICAL_RECIPE, 0..) |
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
            .semantic_format_version = digest.format_version,
            .semantic_digest = qm31_mul.SEMANTIC_DIGEST,
            .slots = slots,
        };
    }

    pub fn identityDigest(self: *const WitnessBinding) digest.Digest {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(WITNESS_BINDING_DOMAIN);
        hashInt(&hash, u16, self.format_version);
        hashInt(&hash, u16, self.semantic_format_version);
        hash.update(&self.semantic_digest);
        hashInt(&hash, u16, PHYSICAL_COLUMN_COUNT);
        for (self.slots) |slot| {
            hashInt(&hash, u8, slot.column);
            hashInt(&hash, u32, @intFromEnum(slot.value));
            hashInt(&hash, u8, @intFromEnum(slot.source));
        }
        return hash.finalResult();
    }
};

pub const ConstructionError = qm31_mul.ValidationError || error{
    InvalidWitnessBinding,
};
pub const ExecutionError = direct_witness_executor.Error;

pub const Executor = struct {
    binding: WitnessBinding,
    binding_digest: digest.Digest,

    pub fn init(
        definition: *const qm31_mul.Definition,
        supplied: *const WitnessBinding,
    ) ConstructionError!Executor {
        const expected = try WitnessBinding.canonical(definition);
        if (!std.meta.eql(expected, supplied.*))
            return error.InvalidWitnessBinding;
        const binding_digest = supplied.identityDigest();
        if (!std.mem.eql(u8, &binding_digest, &WITNESS_BINDING_DIGEST)) {
            return error.InvalidWitnessBinding;
        }
        return .{ .binding = supplied.*, .binding_digest = binding_digest };
    }

    pub fn generateMainInto(
        self: *const Executor,
        columns: *[PHYSICAL_COLUMN_COUNT][]M31,
        invocations: []const Invocation,
        log_size: u32,
    ) ExecutionError!void {
        return direct_witness_executor.generateMainInto(
            M31,
            Invocation,
            PHYSICAL_COLUMN_COUNT,
            columns,
            invocations,
            log_size,
            M31.zero(),
            self,
            validateInvocation,
            writeActiveRow,
        );
    }
};

pub inline fn writeActiveRow(
    columns: anytype,
    row_index: usize,
    invocation: Invocation,
) void {
    const a = invocation.a.toM31Array();
    const b = invocation.b.toM31Array();
    const c = invocation.a.mul(invocation.b).toM31Array();
    inline for (CANONICAL_RECIPE, 0..) |source, column| {
        columns[column][row_index] = switch (source) {
            .a_0 => a[0],
            .a_1 => a[1],
            .a_2 => a[2],
            .a_3 => a[3],
            .b_0 => b[0],
            .b_1 => b[1],
            .b_2 => b[2],
            .b_3 => b[3],
            .c_0 => c[0],
            .c_1 => c[1],
            .c_2 => c[2],
            .c_3 => c[3],
        };
    }
}

fn validateInvocation(_: Invocation) ExecutionError!void {}

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
