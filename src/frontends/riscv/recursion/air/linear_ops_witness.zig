//! Direct main and preprocessing writers for recursion QM31 linear operations.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const direct = @import("../../air/lang/direct_witness_executor.zig");
const digest = @import("../../air/lang/digest.zig");
const types = @import("../../air/lang/types.zig");
const full = @import("linear_ops.zig");
const proof_kind_mod = @import("proof_kind.zig");

pub const MAIN_COLUMN_COUNT = full.PHYSICAL_MAIN_COLUMN_COUNT;
pub const PREPROCESSED_COLUMN_COUNT = full.PREPROCESSED_COLUMN_COUNT;
pub const BINDING_FORMAT_VERSION: u16 = 1;
pub const BINDING_DOMAIN =
    "stwo-zig/typed-air/recursion-linear-ops-witness/v1\x00";
pub const BINDING_DIGEST_HEX =
    "d890047c4bf2ca586bec3122acb9738a29ff9f9ea220e31160bca83294750e5d";
pub const BINDING_DIGEST: digest.Digest = hexDigest(
    BINDING_DIGEST_HEX,
    "invalid recursion linear-ops witness-binding digest",
);
pub const ProofKind = proof_kind_mod.ProofKind;

pub const Operation = enum(u8) {
    add = 0,
    sub = 1,
    neg = 2,

    pub fn flags(self: Operation) [3]M31 {
        var result = [_]M31{M31.zero()} ** 3;
        result[@intFromEnum(self)] = M31.one();
        return result;
    }

    pub fn apply(self: Operation, lhs: QM31, rhs: QM31) QM31 {
        return switch (self) {
            .add => lhs.add(rhs),
            .sub => lhs.sub(rhs),
            .neg => lhs.neg(),
        };
    }
};

pub const CircuitMetadata = struct {
    circuit_id: M31,
    node_id: M31,
    lhs_id: M31,
    rhs_id: M31,
    uses: M31,
};

pub const Invocation = struct {
    operation: Operation,
    lhs: QM31,
    rhs: QM31 = QM31.zero(),
    circuit: CircuitMetadata,
};

pub const ScheduleRow = struct {
    operation: Operation,
    circuit: CircuitMetadata,
};

pub const PreprocessedRow = struct {
    segment: ?ScheduleRow = null,
    binary: ?ScheduleRow = null,
    empty: ?ScheduleRow = null,
};

pub const MainSource = enum(u8) {
    enabler = 0,
    circuit_id = 1,
    node_id = 2,
    is_add = 3,
    is_sub = 4,
    is_neg = 5,
    lhs_id = 6,
    rhs_id = 7,
    lhs_0 = 8,
    lhs_1 = 9,
    lhs_2 = 10,
    lhs_3 = 11,
    rhs_0 = 12,
    rhs_1 = 13,
    rhs_2 = 14,
    rhs_3 = 15,
    out_0 = 16,
    out_1 = 17,
    out_2 = 18,
    out_3 = 19,
    uses = 20,
};

pub const PreprocessedSource = enum(u8) {
    segment_mask = 0,
    segment_circuit_id = 1,
    segment_node_id = 2,
    segment_is_add = 3,
    segment_is_sub = 4,
    segment_is_neg = 5,
    segment_lhs_id = 6,
    segment_rhs_id = 7,
    segment_uses = 8,
    binary_mask = 9,
    binary_circuit_id = 10,
    binary_node_id = 11,
    binary_is_add = 12,
    binary_is_sub = 13,
    binary_is_neg = 14,
    binary_lhs_id = 15,
    binary_rhs_id = 16,
    binary_uses = 17,
    empty_mask = 18,
    empty_circuit_id = 19,
    empty_node_id = 20,
    empty_is_add = 21,
    empty_is_sub = 22,
    empty_is_neg = 23,
    empty_lhs_id = 24,
    empty_rhs_id = 25,
    empty_uses = 26,
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
    const flags = invocation.operation.flags();
    const lhs = invocation.lhs.toM31Array();
    const rhs_value = if (invocation.operation == .neg) QM31.zero() else invocation.rhs;
    const rhs = rhs_value.toM31Array();
    const out = invocation.operation.apply(invocation.lhs, rhs_value).toM31Array();
    inline for (MAIN_RECIPE, 0..) |source_value, column| {
        columns[column][row_index] = switch (source_value) {
            .enabler => M31.one(),
            .circuit_id => invocation.circuit.circuit_id,
            .node_id => invocation.circuit.node_id,
            .is_add => flags[0],
            .is_sub => flags[1],
            .is_neg => flags[2],
            .lhs_id => invocation.circuit.lhs_id,
            .rhs_id => invocation.circuit.rhs_id,
            .lhs_0 => lhs[0],
            .lhs_1 => lhs[1],
            .lhs_2 => lhs[2],
            .lhs_3 => lhs[3],
            .rhs_0 => rhs[0],
            .rhs_1 => rhs[1],
            .rhs_2 => rhs[2],
            .rhs_3 => rhs[3],
            .out_0 => out[0],
            .out_1 => out[1],
            .out_2 => out[2],
            .out_3 => out[3],
            .uses => invocation.circuit.uses,
        };
    }
}

pub inline fn writePreprocessedRow(
    columns: anytype,
    row_index: usize,
    row: PreprocessedRow,
) void {
    inline for (PREPROCESSED_RECIPE, 0..) |source_value, column| {
        const scheduled = switch (source_value) {
            .segment_mask,
            .segment_circuit_id,
            .segment_node_id,
            .segment_is_add,
            .segment_is_sub,
            .segment_is_neg,
            .segment_lhs_id,
            .segment_rhs_id,
            .segment_uses,
            => row.segment,
            .binary_mask,
            .binary_circuit_id,
            .binary_node_id,
            .binary_is_add,
            .binary_is_sub,
            .binary_is_neg,
            .binary_lhs_id,
            .binary_rhs_id,
            .binary_uses,
            => row.binary,
            .empty_mask,
            .empty_circuit_id,
            .empty_node_id,
            .empty_is_add,
            .empty_is_sub,
            .empty_is_neg,
            .empty_lhs_id,
            .empty_rhs_id,
            .empty_uses,
            => row.empty,
        };
        columns[column][row_index] = if (scheduled) |present| blk: {
            const flags = present.operation.flags();
            break :blk switch (source_value) {
                .segment_mask, .binary_mask, .empty_mask => M31.one(),
                .segment_circuit_id, .binary_circuit_id, .empty_circuit_id => present.circuit.circuit_id,
                .segment_node_id, .binary_node_id, .empty_node_id => present.circuit.node_id,
                .segment_is_add, .binary_is_add, .empty_is_add => flags[0],
                .segment_is_sub, .binary_is_sub, .empty_is_sub => flags[1],
                .segment_is_neg, .binary_is_neg, .empty_is_neg => flags[2],
                .segment_lhs_id, .binary_lhs_id, .empty_lhs_id => present.circuit.lhs_id,
                .segment_rhs_id, .binary_rhs_id, .empty_rhs_id => present.circuit.rhs_id,
                .segment_uses, .binary_uses, .empty_uses => present.circuit.uses,
            };
        } else M31.zero();
    }
}

fn validateInvocation(invocation: Invocation) ExecutionError!void {
    if (invocation.operation == .neg and
        (!invocation.rhs.isZero() or !invocation.circuit.rhs_id.isZero()))
    {
        return error.InvalidTraceRow;
    }
}

fn validatePreprocessedRow(row: PreprocessedRow) ExecutionError!void {
    inline for (.{ row.segment, row.binary, row.empty }) |scheduled| {
        if (scheduled) |present| {
            if (present.operation == .neg and !present.circuit.rhs_id.isZero())
                return error.InvalidTraceRow;
        }
    }
}

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
