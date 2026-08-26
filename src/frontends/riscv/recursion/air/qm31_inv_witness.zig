//! Direct main and preprocessing writers for recursion QM31 inversion.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const direct = @import("../../air/lang/direct_witness_executor.zig");
const digest = @import("../../air/lang/digest.zig");
const types = @import("../../air/lang/types.zig");
const full = @import("qm31_inv.zig");
const proof_kind_mod = @import("proof_kind.zig");

pub const MAIN_COLUMN_COUNT = full.PHYSICAL_MAIN_COLUMN_COUNT;
pub const PREPROCESSED_COLUMN_COUNT = full.PREPROCESSED_COLUMN_COUNT;
pub const BINDING_FORMAT_VERSION: u16 = 1;
pub const BINDING_DOMAIN =
    "stwo-zig/typed-air/recursion-qm31-inv-witness/v1\x00";
pub const BINDING_DIGEST_HEX =
    "3d425a1e4452957fd3dafb96117f1b2bd5e84aa7f5680583394364dec985fc97";
pub const BINDING_DIGEST: digest.Digest = hexDigest(
    BINDING_DIGEST_HEX,
    "invalid recursion QM31 inversion witness-binding digest",
);
pub const ProofKind = proof_kind_mod.ProofKind;

pub const CircuitMetadata = struct {
    circuit_id: M31,
    node_id: M31,
    lhs_id: M31,
    uses: M31,
};

pub const Invocation = struct {
    a: QM31,
    circuit: ?CircuitMetadata = null,
};

pub const PreprocessedRow = struct {
    segment: ?CircuitMetadata = null,
    binary: ?CircuitMetadata = null,
    empty: ?CircuitMetadata = null,
};

pub const MainSource = enum(u8) {
    enabler = 0,
    a_0 = 1,
    a_1 = 2,
    a_2 = 3,
    a_3 = 4,
    inv_0 = 5,
    inv_1 = 6,
    inv_2 = 7,
    inv_3 = 8,
    circuit_id = 9,
    node_id = 10,
    lhs_id = 11,
    uses = 12,
    in_circuit = 13,
};

pub const PreprocessedSource = enum(u8) {
    segment_mask = 0,
    segment_circuit_id = 1,
    segment_node_id = 2,
    segment_lhs_id = 3,
    segment_uses = 4,
    binary_mask = 5,
    binary_circuit_id = 6,
    binary_node_id = 7,
    binary_lhs_id = 8,
    binary_uses = 9,
    empty_mask = 10,
    empty_circuit_id = 11,
    empty_node_id = 12,
    empty_lhs_id = 13,
    empty_uses = 14,
};

pub const MAIN_RECIPE = std.enums.values(MainSource);
pub const PREPROCESSED_RECIPE = std.enums.values(PreprocessedSource);

pub fn Slot(comptime Source: type) type {
    return struct { column: u8, value: types.ValueId, source: Source };
}

pub const Binding = struct {
    format_version: u16,
    semantic_format_version: u16,
    semantic_digest: digest.Digest,
    main: [MAIN_COLUMN_COUNT]Slot(MainSource),
    preprocessed: [PREPROCESSED_COLUMN_COUNT]Slot(PreprocessedSource),
    parameters: [3]types.ValueId,

    pub fn canonical(definition: *const full.Definition) ConstructionError!Binding {
        try definition.validate();
        var main: [MAIN_COLUMN_COUNT]Slot(MainSource) = undefined;
        for (&main, definition.main.physical(), MAIN_RECIPE, 0..) |
            *slot,
            value,
            source_value,
            column,
        | slot.* = .{ .column = @intCast(column), .value = value, .source = source_value };
        var preprocessed: [PREPROCESSED_COLUMN_COUNT]Slot(PreprocessedSource) = undefined;
        for (&preprocessed, definition.preprocessed.physical(), PREPROCESSED_RECIPE, 0..) |
            *slot,
            value,
            source_value,
            column,
        | slot.* = .{ .column = @intCast(column), .value = value, .source = source_value };
        return .{
            .format_version = BINDING_FORMAT_VERSION,
            .semantic_format_version = digest.typed_effect_format_version,
            .semantic_digest = full.SEMANTIC_DIGEST,
            .main = main,
            .preprocessed = preprocessed,
            .parameters = definition.parameters.physical(),
        };
    }

    pub fn identityDigest(self: *const Binding) digest.Digest {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(BINDING_DOMAIN);
        hashInt(&hash, u16, self.format_version);
        hashInt(&hash, u16, self.semantic_format_version);
        hash.update(&self.semantic_digest);
        hashInt(&hash, u16, MAIN_COLUMN_COUNT);
        for (self.main) |slot| hashSlot(&hash, slot);
        hashInt(&hash, u16, PREPROCESSED_COLUMN_COUNT);
        for (self.preprocessed) |slot| hashSlot(&hash, slot);
        hashInt(&hash, u16, self.parameters.len);
        for (self.parameters) |value| hashInt(&hash, u32, @intFromEnum(value));
        return hash.finalResult();
    }
};

pub const ConstructionError = full.ValidationError || error{InvalidWitnessBinding};
pub const ExecutionError = direct.Error;

pub const Executor = struct {
    binding: Binding,
    binding_digest: digest.Digest,

    pub fn init(
        definition: *const full.Definition,
        supplied: *const Binding,
    ) ConstructionError!Executor {
        const expected = try Binding.canonical(definition);
        if (!std.meta.eql(expected, supplied.*)) return error.InvalidWitnessBinding;
        const binding_digest = supplied.identityDigest();
        if (!std.mem.eql(u8, &binding_digest, &BINDING_DIGEST))
            return error.InvalidWitnessBinding;
        return .{ .binding = supplied.*, .binding_digest = binding_digest };
    }

    pub fn generateMainInto(
        self: *const Executor,
        columns: *[MAIN_COLUMN_COUNT][]M31,
        invocations: []const Invocation,
        log_size: u32,
    ) ExecutionError!void {
        return direct.generateMainInto(
            M31,
            Invocation,
            MAIN_COLUMN_COUNT,
            columns,
            invocations,
            log_size,
            M31.zero(),
            self,
            validateInvocation,
            writeMainRow,
        );
    }

    pub fn generatePreprocessedInto(
        self: *const Executor,
        columns: *[PREPROCESSED_COLUMN_COUNT][]M31,
        rows: []const PreprocessedRow,
        log_size: u32,
    ) ExecutionError!void {
        return direct.generateMainInto(
            M31,
            PreprocessedRow,
            PREPROCESSED_COLUMN_COUNT,
            columns,
            rows,
            log_size,
            M31.zero(),
            self,
            validatePreprocessedRow,
            writePreprocessedRow,
        );
    }
};

pub fn mainRow(invocation: Invocation) ExecutionError![MAIN_COLUMN_COUNT]M31 {
    try validateInvocation(invocation);
    var result: [MAIN_COLUMN_COUNT]M31 = undefined;
    var columns: [MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&columns, 0..) |*column, index| column.* = result[index .. index + 1];
    writeMainRow(&columns, 0, invocation);
    return result;
}

pub fn preprocessedRow(row: PreprocessedRow) [PREPROCESSED_COLUMN_COUNT]M31 {
    var result: [PREPROCESSED_COLUMN_COUNT]M31 = undefined;
    var columns: [PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
    for (&columns, 0..) |*column, index| column.* = result[index .. index + 1];
    writePreprocessedRow(&columns, 0, row);
    return result;
}

pub fn logicalInputs(
    main: [MAIN_COLUMN_COUNT]M31,
    preprocessed: [PREPROCESSED_COLUMN_COUNT]M31,
    selected_kind: ProofKind,
) [full.LOGICAL_INPUT_COUNT]M31 {
    var result: [full.LOGICAL_INPUT_COUNT]M31 = undefined;
    @memcpy(result[0..MAIN_COLUMN_COUNT], &main);
    @memcpy(
        result[MAIN_COLUMN_COUNT .. MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT],
        &preprocessed,
    );
    const selectors = selected_kind.selectors();
    @memcpy(result[MAIN_COLUMN_COUNT + PREPROCESSED_COLUMN_COUNT ..], &selectors);
    return result;
}

pub inline fn writeMainRow(columns: anytype, row_index: usize, invocation: Invocation) void {
    const a = invocation.a.toM31Array();
    const inverse = (invocation.a.inv() catch unreachable).toM31Array();
    const metadata = invocation.circuit orelse CircuitMetadata{
        .circuit_id = M31.zero(),
        .node_id = M31.zero(),
        .lhs_id = M31.zero(),
        .uses = M31.zero(),
    };
    inline for (MAIN_RECIPE, 0..) |source_value, column| {
        columns[column][row_index] = switch (source_value) {
            .enabler => M31.one(),
            .a_0 => a[0],
            .a_1 => a[1],
            .a_2 => a[2],
            .a_3 => a[3],
            .inv_0 => inverse[0],
            .inv_1 => inverse[1],
            .inv_2 => inverse[2],
            .inv_3 => inverse[3],
            .circuit_id => metadata.circuit_id,
            .node_id => metadata.node_id,
            .lhs_id => metadata.lhs_id,
            .uses => metadata.uses,
            .in_circuit => if (invocation.circuit == null) M31.zero() else M31.one(),
        };
    }
}

pub inline fn writePreprocessedRow(
    columns: anytype,
    row_index: usize,
    row: PreprocessedRow,
) void {
    inline for (PREPROCESSED_RECIPE, 0..) |source_value, column| {
        const metadata = switch (source_value) {
            .segment_mask,
            .segment_circuit_id,
            .segment_node_id,
            .segment_lhs_id,
            .segment_uses,
            => row.segment,
            .binary_mask,
            .binary_circuit_id,
            .binary_node_id,
            .binary_lhs_id,
            .binary_uses,
            => row.binary,
            .empty_mask,
            .empty_circuit_id,
            .empty_node_id,
            .empty_lhs_id,
            .empty_uses,
            => row.empty,
        };
        columns[column][row_index] = if (metadata) |present| switch (source_value) {
            .segment_mask, .binary_mask, .empty_mask => M31.one(),
            .segment_circuit_id, .binary_circuit_id, .empty_circuit_id => present.circuit_id,
            .segment_node_id, .binary_node_id, .empty_node_id => present.node_id,
            .segment_lhs_id, .binary_lhs_id, .empty_lhs_id => present.lhs_id,
            .segment_uses, .binary_uses, .empty_uses => present.uses,
        } else M31.zero();
    }
}

fn validateInvocation(invocation: Invocation) ExecutionError!void {
    if (invocation.a.isZero()) return error.InvalidTraceRow;
}

fn validatePreprocessedRow(_: PreprocessedRow) ExecutionError!void {}

fn hashSlot(hash: anytype, slot: anytype) void {
    hashInt(hash, u8, slot.column);
    hashInt(hash, u32, @intFromEnum(slot.value));
    hashInt(hash, u8, @intFromEnum(slot.source));
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

fn hexDigest(comptime value: []const u8, comptime message: []const u8) digest.Digest {
    var result: digest.Digest = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch @compileError(message);
    return result;
}
