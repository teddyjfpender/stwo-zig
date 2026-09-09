//! Canonical Tree-0 authority for the combined Ethereum profile.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const prover_pcs = @import("stwo_prover_engine").pcs;
const keccak_component = @import("../../air/guest_precompile/keccakf_component.zig");
const keccak_table_component = @import("../../air/guest_precompile/keccakf_table_component.zig");
const keccak_tables = @import("../../air/guest_precompile/keccakf_tables.zig");
const keccak_trace = @import("../../air/guest_precompile/keccakf_trace.zig");
const keccak_witness = @import("../../air/guest_precompile/keccakf_witness.zig");
const secp_trace = @import("../../air/guest_precompile/secp256k1_component_trace.zig");
const base_statement = @import("../../air/statement.zig");
const statement_mod = @import("../../air/guest_precompile/ethereum_statement.zig");
const base_preprocessed = @import("../preprocessed.zig");
const statement_v2 = @import("../../air/statement_v2.zig");
const native_provider_omit = @import("../memory_provider_shards/native_provider_omit_v1.zig");
const external_tree = @import("external_profile_tree.zig");

pub const extension_column_count: usize =
    keccak_component.preprocessed_column_count +
    2 * keccak_table_component.preprocessed_column_count +
    11 * secp_trace.preprocessed_column_count;

pub fn generate(
    allocator: std.mem.Allocator,
    core: *const base_statement.RiscVStatement,
    extension: *const statement_mod.Statement,
) ![]prover_pcs.ColumnEvaluation {
    try extension.validateStructure(core);
    const base = try base_preprocessed.generate(allocator, core.*);
    var base_owned = true;
    errdefer if (base_owned) freeColumns(allocator, base);
    const result = try allocator.alloc(
        prover_pcs.ColumnEvaluation,
        base.len + extension_column_count,
    );
    var initialized: usize = 0;
    errdefer {
        for (result[0..initialized]) |column|
            allocator.free(@constCast(column.values));
        allocator.free(result);
    }
    @memcpy(result[0..base.len], base);
    initialized = base.len;
    allocator.free(base);
    base_owned = false;

    try appendKeccak(allocator, result, &initialized, extension);
    try appendTable(allocator, result, &initialized, .chi);
    try appendTable(allocator, result, &initialized, .xor5);
    for (extension.components[3..], 0..) |descriptor, index| {
        const active_prefix = if (index == 10)
            extension.counts.signer_calls
        else
            0;
        try appendSecpSelectors(
            allocator,
            result,
            &initialized,
            descriptor.log_size,
            active_prefix,
        );
    }
    if (initialized != result.len) return error.InvalidTraceShape;
    return result;
}

/// Additive joined-profile Tree-0 sibling. The ordinary base and all fourteen
/// Ethereum blocks remain the exact prefix; caller-owned fixed columns append
/// strictly afterward in statement order.
pub fn generateWithExternalBlocks(
    allocator: std.mem.Allocator,
    core: *const base_statement.RiscVStatement,
    extension: *const statement_mod.Statement,
    blocks: []const external_tree.BorrowedBlock,
) ![]prover_pcs.ColumnEvaluation {
    const ordinary = try generate(allocator, core, extension);
    var ordinary_owned = true;
    errdefer if (ordinary_owned) freeColumns(allocator, ordinary);
    var total = ordinary.len;
    for (blocks) |block_value| total = std.math.add(
        usize,
        total,
        block_value.columns.len,
    ) catch return error.InvalidTraceShape;
    const result = try allocator.alloc(prover_pcs.ColumnEvaluation, total);
    var initialized: usize = ordinary.len;
    errdefer {
        for (result[ordinary.len..initialized]) |column|
            allocator.free(@constCast(column.values));
        allocator.free(result);
    }
    @memcpy(result[0..ordinary.len], ordinary);
    allocator.free(ordinary);
    ordinary_owned = false;
    for (blocks) |block_value| for (block_value.columns) |values| {
        if (values.len != try domainSize(block_value.log_size))
            return error.InvalidTraceShape;
        result[initialized] = .{
            .log_size = block_value.log_size,
            .values = try allocator.dupe(M31, values),
        };
        initialized += 1;
    };
    if (initialized != result.len) return error.InvalidTraceShape;
    return result;
}

/// Canonical joined Tree-0 for the provider-externalized core. Extension
/// admission is checked against the full native statement; only the base fixed
/// columns are generated from the sealed projected geometry.
pub fn generateWithoutNativePoseidonV2(
    allocator: std.mem.Allocator,
    projection: *const native_provider_omit.ProjectionV1,
    full_native: *const statement_v2.RiscVStatementV2,
    extension: *const statement_mod.Statement,
) ![]prover_pcs.ColumnEvaluation {
    try projection.validateSealAndFull(full_native, extension);
    const base = try base_preprocessed.generate(
        allocator,
        projection.projected_native.core,
    );
    var base_owned = true;
    errdefer if (base_owned) freeColumns(allocator, base);
    const result = try allocator.alloc(
        prover_pcs.ColumnEvaluation,
        base.len + extension_column_count,
    );
    var initialized: usize = 0;
    errdefer {
        for (result[0..initialized]) |column|
            allocator.free(@constCast(column.values));
        allocator.free(result);
    }
    @memcpy(result[0..base.len], base);
    initialized = base.len;
    allocator.free(base);
    base_owned = false;

    try appendKeccak(allocator, result, &initialized, extension);
    try appendTable(allocator, result, &initialized, .chi);
    try appendTable(allocator, result, &initialized, .xor5);
    for (extension.components[3..], 0..) |descriptor, index| {
        const active_prefix = if (index == 10)
            extension.counts.signer_calls
        else
            0;
        try appendSecpSelectors(
            allocator,
            result,
            &initialized,
            descriptor.log_size,
            active_prefix,
        );
    }
    if (initialized != result.len) return error.InvalidTraceShape;
    return result;
}

/// Candidate-only Tree-0 sibling. The sealed projected core and fourteen
/// Ethereum fixed blocks are generated by the canonical path above; external
/// blocks are copied strictly afterward in caller-supplied statement order.
pub fn generateWithoutNativePoseidonV2WithExternalBlocks(
    allocator: std.mem.Allocator,
    projection: *const native_provider_omit.ProjectionV1,
    full_native: *const statement_v2.RiscVStatementV2,
    extension: *const statement_mod.Statement,
    blocks: []const external_tree.BorrowedBlock,
) ![]prover_pcs.ColumnEvaluation {
    const ordinary = try generateWithoutNativePoseidonV2(
        allocator,
        projection,
        full_native,
        extension,
    );
    var ordinary_owned = true;
    errdefer if (ordinary_owned) freeColumns(allocator, ordinary);
    var total = ordinary.len;
    for (blocks) |block_value| total = std.math.add(
        usize,
        total,
        block_value.columns.len,
    ) catch return error.InvalidTraceShape;
    const result = try allocator.alloc(prover_pcs.ColumnEvaluation, total);
    var initialized: usize = ordinary.len;
    errdefer {
        for (result[ordinary.len..initialized]) |column|
            allocator.free(@constCast(column.values));
        allocator.free(result);
    }
    @memcpy(result[0..ordinary.len], ordinary);
    allocator.free(ordinary);
    ordinary_owned = false;
    for (blocks) |block_value| for (block_value.columns) |values| {
        if (values.len != try domainSize(block_value.log_size))
            return error.InvalidTraceShape;
        result[initialized] = .{
            .log_size = block_value.log_size,
            .values = try allocator.dupe(M31, values),
        };
        initialized += 1;
    };
    if (initialized != result.len) return error.InvalidTraceShape;
    return result;
}

pub fn logSizes(
    allocator: std.mem.Allocator,
    core: *const base_statement.RiscVStatement,
    extension: *const statement_mod.Statement,
) ![]u32 {
    try extension.validateStructure(core);
    const base = try base_preprocessed.logSizes(allocator, core.*);
    defer allocator.free(base);
    const result = try allocator.alloc(u32, base.len + extension_column_count);
    @memcpy(result[0..base.len], base);
    var cursor = base.len;
    for (extension.components) |descriptor| {
        @memset(
            result[cursor..][0..descriptor.preprocessed_columns],
            descriptor.log_size,
        );
        cursor += descriptor.preprocessed_columns;
    }
    if (cursor != result.len) return error.InvalidTraceShape;
    return result;
}

pub fn logSizesWithExternalBlocks(
    allocator: std.mem.Allocator,
    core: *const base_statement.RiscVStatement,
    extension: *const statement_mod.Statement,
    blocks: []const external_tree.BorrowedBlock,
) ![]u32 {
    const ordinary = try logSizes(allocator, core, extension);
    defer allocator.free(ordinary);
    return external_tree.appendLogSizes(allocator, ordinary, blocks);
}

fn appendKeccak(
    allocator: std.mem.Allocator,
    result: []prover_pcs.ColumnEvaluation,
    initialized: *usize,
    extension: *const statement_mod.Statement,
) !void {
    const descriptor = extension.components[0];
    const domain_size = try domainSize(descriptor.log_size);
    const slots = std.math.divCeil(
        u32,
        extension.counts.keccak_calls,
        2,
    ) catch unreachable;
    var column = try zeroColumn(allocator, descriptor.log_size);
    @constCast(column.values)[keccak_trace.committedRow(0, descriptor.log_size)] =
        M31.one();
    try append(result, initialized, column);
    for (0..keccak_witness.row_count) |group| {
        column = try zeroColumn(allocator, descriptor.log_size);
        const values = @constCast(column.values);
        for (0..slots) |slot| {
            const logical = slot * keccak_witness.row_count + group;
            if (logical >= domain_size) return error.InvalidTraceShape;
            values[keccak_trace.committedRow(logical, descriptor.log_size)] =
                M31.one();
        }
        try append(result, initialized, column);
    }
    column = try zeroColumn(allocator, descriptor.log_size);
    const values = @constCast(column.values);
    const paired_slots = extension.counts.keccak_calls / 2;
    for (0..paired_slots) |slot| for (0..keccak_witness.row_count) |group| {
        const logical = slot * keccak_witness.row_count + group;
        values[keccak_trace.committedRow(logical, descriptor.log_size)] =
            M31.one();
    };
    try append(result, initialized, column);
}

fn appendTable(
    allocator: std.mem.Allocator,
    result: []prover_pcs.ColumnEvaluation,
    initialized: *usize,
    kind: keccak_tables.Kind,
) !void {
    const log_size = keccak_tables.logSize(kind);
    const first = try zeroColumn(allocator, log_size);
    @constCast(first.values)[secp_trace.committedRow(0, log_size)] = M31.one();
    try append(result, initialized, first);
    var tuples = try keccak_tables.generatePreprocessed(allocator, kind);
    var transferred: usize = 0;
    defer {
        for (tuples.columns[transferred..]) |column| allocator.free(column);
    }
    for (&tuples.columns) |*values| {
        const column = prover_pcs.ColumnEvaluation{
            .log_size = log_size,
            .values = values.*,
        };
        values.* = &.{};
        transferred += 1;
        try append(result, initialized, column);
    }
}

fn appendSecpSelectors(
    allocator: std.mem.Allocator,
    result: []prover_pcs.ColumnEvaluation,
    initialized: *usize,
    log_size: u32,
    active_prefix: u32,
) !void {
    const first = try zeroColumn(allocator, log_size);
    @constCast(first.values)[secp_trace.committedRow(0, log_size)] = M31.one();
    try append(result, initialized, first);
    const group_first = try zeroColumn(allocator, log_size);
    const group_first_values = @constCast(group_first.values);
    for (0..active_prefix) |logical| group_first_values[
        secp_trace.committedRow(logical, log_size)
    ] = M31.one();
    try append(result, initialized, group_first);
    try append(result, initialized, try zeroColumn(allocator, log_size));
}

fn zeroColumn(
    allocator: std.mem.Allocator,
    log_size: u32,
) !prover_pcs.ColumnEvaluation {
    const values = try allocator.alloc(M31, try domainSize(log_size));
    @memset(values, M31.zero());
    return .{ .log_size = log_size, .values = values };
}

fn append(
    result: []prover_pcs.ColumnEvaluation,
    initialized: *usize,
    column: prover_pcs.ColumnEvaluation,
) !void {
    if (initialized.* >= result.len) return error.InvalidTraceShape;
    result[initialized.*] = column;
    initialized.* += 1;
}

fn domainSize(log_size: u32) !usize {
    if (log_size >= @bitSizeOf(usize)) return error.InvalidLogSize;
    return @as(usize, 1) << @intCast(log_size);
}

fn freeColumns(
    allocator: std.mem.Allocator,
    columns: []prover_pcs.ColumnEvaluation,
) void {
    for (columns) |column| allocator.free(@constCast(column.values));
    allocator.free(columns);
}

comptime {
    if (extension_column_count != 78)
        @compileError("Ethereum Tree-0 column authority drifted");
}
