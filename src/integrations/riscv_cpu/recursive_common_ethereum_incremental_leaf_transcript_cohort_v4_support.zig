//! Internal physical-writer helpers for the role-0 transcript cohort.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const manifest_mod =
    @import("recursive_common_ethereum_incremental_leaf_universal_manifest_v4.zig");

const M31 = stwo_core.fields.m31.M31;
const air = frontend.recursion.air;
const framework = air.framework_interaction;
const direct_program = air.direct_constraint_program;
const relation_interaction = air.relation_interaction;

pub const Error = error{
    ArithmeticOverflow,
    ConstraintViolation,
    DestinationAlias,
    DestinationColumnCountMismatch,
    DestinationLogSizeMismatch,
    EthereumIncrementalTranscriptCohortMismatchV4,
    InvalidTreeIndex,
};

pub fn validateDirect(
    comptime Air: type,
    program: *const direct_program.Program,
    rows: []const [Air.LOGICAL_INPUT_COUNT]M31,
) !void {
    var scratch: [direct_program.MAX_NODES]M31 = undefined;
    var roots: [Air.DIRECT_CONSTRAINT_COUNT]M31 = undefined;
    for (rows) |row| {
        try program.evaluateBaseInto(&row, &scratch, &roots);
        for (roots) |root| if (!root.isZero())
            return error.ConstraintViolation;
    }
}

pub fn appendTuples(
    plan: anytype,
    ledger: *relation_interaction.TupleLedger,
    component: manifest_mod.ComponentKey,
    rows: anytype,
) !void {
    try plan.appendPreparedTupleContributions(
        ledger,
        manifest_mod.keyIndex(component),
        rows,
        relation_interaction.allDomainMask(),
    );
}

pub fn writePhysical(
    comptime Air: type,
    rows: []const [Air.LOGICAL_INPUT_COUNT]M31,
    placement: manifest_mod.Placement,
    tree: usize,
    destination: []const []M31,
) void {
    const local_count = switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => Air.PREPROCESSED_COLUMN_COUNT,
        manifest_mod.MAIN_TREE_INDEX => Air.PHYSICAL_MAIN_COLUMN_COUNT,
        else => unreachable,
    };
    const input_start = if (tree == manifest_mod.PREPROCESSED_TREE_INDEX)
        Air.PHYSICAL_MAIN_COLUMN_COUNT
    else
        0;
    const output_start: usize = switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => @intCast(placement.preprocessed_offset),
        manifest_mod.MAIN_TREE_INDEX => @intCast(placement.main_offset),
        else => unreachable,
    };
    for (destination[output_start..][0..local_count]) |column|
        @memset(column, M31.zero());
    for (rows, 0..) |row, logical_row| {
        const committed_row = framework.committedRow(
            logical_row,
            placement.geometry.log_size,
        );
        for (0..local_count) |column| {
            destination[output_start + column][committed_row] =
                row[input_start + column];
        }
    }
}

pub fn preflightTree(
    manifest: *const manifest_mod.Manifest,
    tree: usize,
    destination: []const []M31,
    protected: []const AddressRange,
) !void {
    try manifest.validate();
    if (tree >= manifest_mod.TREE_COUNT) return error.InvalidTreeIndex;
    if (destination.len != manifestTreeColumnCount(manifest, tree))
        return error.DestinationColumnCountMismatch;
    for (destination, 0..) |column, index| {
        const log_size = try columnLogSize(manifest, tree, index);
        if (column.len != try traceSize(log_size))
            return error.DestinationLogSizeMismatch;
        const range = try sliceRange(column);
        for (protected) |other| if (range.overlaps(other))
            return error.DestinationAlias;
        for (destination[0..index]) |other| if (range.overlaps(try sliceRange(other))) return error.DestinationAlias;
    }
}

pub const AddressRange = struct {
    start: usize,
    end: usize,

    pub fn overlaps(self: AddressRange, other: AddressRange) bool {
        return self.start < other.end and other.start < self.end;
    }
};

pub fn sliceRange(values: anytype) !AddressRange {
    if (values.len == 0) return .{ .start = 0, .end = 0 };
    const byte_len = try checkedMul(
        values.len,
        @sizeOf(std.meta.Elem(@TypeOf(values))),
    );
    const start = @intFromPtr(values.ptr);
    return .{ .start = start, .end = try checkedAdd(start, byte_len) };
}

pub fn traceSize(log_size: u32) !usize {
    if (log_size >= @bitSizeOf(usize) or log_size >= 31)
        return error.DestinationLogSizeMismatch;
    return @as(usize, 1) << @intCast(log_size);
}

pub fn checkedAdd(left: usize, right: usize) !usize {
    return std.math.add(usize, left, right) catch error.ArithmeticOverflow;
}

pub fn checkedMul(left: usize, right: usize) !usize {
    return std.math.mul(usize, left, right) catch error.ArithmeticOverflow;
}

pub fn interactionStorageCount(
    manifest: *const manifest_mod.Manifest,
    first: usize,
    count: usize,
) !usize {
    var result: usize = 0;
    for (first..first + count) |ordinal| {
        const placement = try manifest.placement(@enumFromInt(ordinal));
        result = try checkedAdd(
            result,
            try checkedMul(
                @intCast(placement.geometry.interaction_columns),
                try traceSize(placement.geometry.log_size),
            ),
        );
    }
    return result;
}

pub fn stagedColumns(
    comptime Framework: type,
    stage: []M31,
    offset: usize,
    log_size: u32,
) ![Framework.INTERACTION_COLUMN_COUNT][]M31 {
    const size = try traceSize(log_size);
    const count = try checkedMul(Framework.INTERACTION_COLUMN_COUNT, size);
    if (offset > stage.len or count > stage.len - offset)
        return error.EthereumIncrementalTranscriptCohortMismatchV4;
    var result: [Framework.INTERACTION_COLUMN_COUNT][]M31 = undefined;
    for (&result, 0..) |*column, index| {
        const first = offset + index * size;
        column.* = stage[first..][0..size];
    }
    return result;
}

pub fn copyInteraction(
    comptime Framework: type,
    columns: *const [Framework.INTERACTION_COLUMN_COUNT][]M31,
    placement: manifest_mod.Placement,
    destination: []const []M31,
) void {
    const first: usize = @intCast(placement.interaction_offset);
    for (columns, 0..) |source, index| {
        @memcpy(
            destination[first + index],
            source,
        );
    }
}

pub fn hashRows(hash: anytype, rows: anytype) void {
    hashInt(hash, u64, rows.len);
    for (rows) |row| for (row) |value|
        hashInt(hash, u32, value.toU32());
}

pub fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

fn manifestTreeColumnCount(
    manifest: *const manifest_mod.Manifest,
    tree: usize,
) usize {
    return switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => @intCast(manifest.total_preprocessed_columns),
        manifest_mod.MAIN_TREE_INDEX => @intCast(manifest.total_main_columns),
        manifest_mod.INTERACTION_TREE_INDEX => @intCast(manifest.total_interaction_columns),
        else => unreachable,
    };
}

fn columnLogSize(
    manifest: *const manifest_mod.Manifest,
    tree: usize,
    column_index: usize,
) !u32 {
    for (manifest_mod.COMPONENT_KEYS) |key| {
        const placement = try manifest.placement(key);
        const first: usize = switch (tree) {
            manifest_mod.PREPROCESSED_TREE_INDEX => @intCast(placement.preprocessed_offset),
            manifest_mod.MAIN_TREE_INDEX => @intCast(placement.main_offset),
            manifest_mod.INTERACTION_TREE_INDEX => @intCast(placement.interaction_offset),
            else => return error.InvalidTreeIndex,
        };
        const count: usize = switch (tree) {
            manifest_mod.PREPROCESSED_TREE_INDEX => @intCast(placement.geometry.preprocessed_columns),
            manifest_mod.MAIN_TREE_INDEX => @intCast(placement.geometry.main_columns),
            manifest_mod.INTERACTION_TREE_INDEX => @intCast(placement.geometry.interaction_columns),
            else => return error.InvalidTreeIndex,
        };
        if (column_index >= first and column_index - first < count)
            return placement.geometry.log_size;
    }
    return error.DestinationColumnCountMismatch;
}
