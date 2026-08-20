//! Verifier-visible commitment geometry for the Poseidon2 guest profile.
//!
//! The base tree order is reproduced exactly and the two profile components
//! are appended in authenticated statement order: caller, then provider.  Each
//! builder performs profile admission before allocation and returns one owned
//! log-size vector plus constant-size boundary metadata; there is no parallel
//! per-column ownership or provenance array.

const std = @import("std");
const pcs_core = @import("stwo_core").pcs;
const guest_interaction = @import("../../air/guest_precompile/interaction.zig");
const guest_main_trace = @import("../../air/guest_precompile/main_trace.zig");
const guest_statement = @import("../../air/guest_precompile/statement.zig");
const opcode_interaction = @import("../../air/lookups/opcode_interaction.zig");
const base_statement = @import("../../air/statement.zig");
const preprocessed = @import("../preprocessed.zig");
const types = @import("../types.zig");

pub const GeometryError = error{
    InvalidTraceGeometry,
    TraceGeometryOverflow,
};

/// Half-open boundaries in the one returned column vector.
///
/// `base_end == caller_start`, `caller_end == provider_start`, and
/// `provider_end == values.len`.  Keeping both names makes protocol-visible
/// hand-off points explicit at call sites without allocating per-column tags.
pub const Boundaries = struct {
    base_end: usize,
    caller_start: usize,
    caller_end: usize,
    provider_start: usize,
    provider_end: usize,

    pub fn checked(
        base_count: usize,
        caller_count: usize,
        provider_count: usize,
    ) GeometryError!Boundaries {
        const caller_end = std.math.add(usize, base_count, caller_count) catch
            return error.TraceGeometryOverflow;
        const provider_end = std.math.add(usize, caller_end, provider_count) catch
            return error.TraceGeometryOverflow;
        return .{
            .base_end = base_count,
            .caller_start = base_count,
            .caller_end = caller_end,
            .provider_start = caller_end,
            .provider_end = provider_end,
        };
    }
};

pub const OwnedLogSizes = struct {
    values: []u32,
    boundaries: Boundaries,

    pub fn deinit(self: *OwnedLogSizes, allocator: std.mem.Allocator) void {
        allocator.free(self.values);
        self.* = undefined;
    }
};

/// Tree 0: unchanged base selectors/table columns, caller selectors, provider
/// selectors.  Both profile blocks are exactly `(is_first, is_active)`.
pub fn tree0LogSizes(
    allocator: std.mem.Allocator,
    core: *const base_statement.RiscVStatement,
    extension: *const guest_statement.ExtensionStatement,
) (guest_statement.Error || std.mem.Allocator.Error || GeometryError)!OwnedLogSizes {
    try extension.validate(core);

    var base_count: usize = 0;
    for (core.component_descs[0..core.n_components]) |_| {
        base_count = try checkedAdd(base_count, 2);
    }
    for (core.infra_descs[0..core.n_infra]) |descriptor| {
        base_count = try checkedAdd(
            base_count,
            @intCast(base_statement.nPreprocessedColumnsForInfra(descriptor.kind)),
        );
    }
    const boundaries = try Boundaries.checked(base_count, 2, 2);
    var result = try allocate(allocator, boundaries);
    errdefer result.deinit(allocator);

    var cursor: usize = 0;
    for (core.component_descs[0..core.n_components]) |descriptor| {
        try appendRun(result.values, &cursor, 2, descriptor.log_size);
    }
    for (core.infra_descs[0..core.n_infra]) |descriptor| {
        try appendRun(
            result.values,
            &cursor,
            @intCast(base_statement.nPreprocessedColumnsForInfra(descriptor.kind)),
            descriptor.log_size,
        );
    }
    try requireBoundary(cursor, boundaries.caller_start);
    try appendRun(result.values, &cursor, 2, extension.components[0].log_size);
    try requireBoundary(cursor, boundaries.provider_start);
    try appendRun(result.values, &cursor, 2, extension.components[1].log_size);
    try requireBoundary(cursor, boundaries.provider_end);
    return result;
}

/// Tree 1: unchanged base main columns followed by the fixed 286-column caller
/// block and 445-column provider block.
pub fn tree1LogSizes(
    allocator: std.mem.Allocator,
    core: *const base_statement.RiscVStatement,
    extension: *const guest_statement.ExtensionStatement,
) (guest_statement.Error || std.mem.Allocator.Error || GeometryError)!OwnedLogSizes {
    try extension.validate(core);

    var base_count: usize = 0;
    for (core.component_descs[0..core.n_components]) |descriptor| {
        base_count = try checkedAdd(base_count, @intCast(descriptor.n_columns));
    }
    for (core.infra_descs[0..core.n_infra]) |descriptor| {
        base_count = try checkedAdd(base_count, @intCast(descriptor.n_columns));
    }
    const boundaries = try Boundaries.checked(
        base_count,
        guest_main_trace.caller_main_column_count,
        guest_main_trace.provider_main_column_count,
    );
    var result = try allocate(allocator, boundaries);
    errdefer result.deinit(allocator);

    var cursor: usize = 0;
    for (core.component_descs[0..core.n_components]) |descriptor| {
        try appendRun(result.values, &cursor, @intCast(descriptor.n_columns), descriptor.log_size);
    }
    for (core.infra_descs[0..core.n_infra]) |descriptor| {
        try appendRun(result.values, &cursor, @intCast(descriptor.n_columns), descriptor.log_size);
    }
    try requireBoundary(cursor, boundaries.caller_start);
    try appendRun(
        result.values,
        &cursor,
        guest_main_trace.caller_main_column_count,
        extension.components[0].log_size,
    );
    try requireBoundary(cursor, boundaries.provider_start);
    try appendRun(
        result.values,
        &cursor,
        guest_main_trace.provider_main_column_count,
        extension.components[1].log_size,
    );
    try requireBoundary(cursor, boundaries.provider_end);
    return result;
}

/// Tree 2: unchanged base interaction columns followed by the fixed 308-column
/// caller block and 8-column provider block.
pub fn tree2LogSizes(
    allocator: std.mem.Allocator,
    core: *const base_statement.RiscVStatement,
    extension: *const guest_statement.ExtensionStatement,
) (guest_statement.Error || std.mem.Allocator.Error || GeometryError)!OwnedLogSizes {
    try extension.validate(core);

    var base_count: usize = 0;
    for (core.component_descs[0..core.n_components]) |descriptor| {
        base_count = try checkedAdd(
            base_count,
            opcode_interaction.nColumns(descriptor.family),
        );
    }
    for (core.infra_descs[0..core.n_infra]) |descriptor| {
        base_count = try checkedAdd(
            base_count,
            @intCast(base_statement.nInteractionColsForInfra(descriptor.kind)),
        );
    }
    const boundaries = try Boundaries.checked(
        base_count,
        guest_interaction.caller_column_count,
        guest_interaction.provider_column_count,
    );
    var result = try allocate(allocator, boundaries);
    errdefer result.deinit(allocator);

    var cursor: usize = 0;
    for (core.component_descs[0..core.n_components]) |descriptor| {
        try appendRun(
            result.values,
            &cursor,
            opcode_interaction.nColumns(descriptor.family),
            descriptor.log_size,
        );
    }
    for (core.infra_descs[0..core.n_infra]) |descriptor| {
        try appendRun(
            result.values,
            &cursor,
            @intCast(base_statement.nInteractionColsForInfra(descriptor.kind)),
            descriptor.log_size,
        );
    }
    try requireBoundary(cursor, boundaries.caller_start);
    try appendRun(
        result.values,
        &cursor,
        guest_interaction.caller_column_count,
        extension.components[0].log_size,
    );
    try requireBoundary(cursor, boundaries.provider_start);
    try appendRun(
        result.values,
        &cursor,
        guest_interaction.provider_column_count,
        extension.components[1].log_size,
    );
    try requireBoundary(cursor, boundaries.provider_end);
    return result;
}

/// Recompute Tree 0 from the authenticated profile statement on a fresh
/// commitment scheme and channel, and accept exactly one matching root.
pub fn verifyPreprocessedRoot(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    core: *const base_statement.RiscVStatement,
    extension: *const guest_statement.ExtensionStatement,
    actual: types.Hasher.Hash,
) !void {
    // Keep profile rejection before generator allocation and engine setup even
    // though the canonical generator independently repeats this admission.
    try extension.validate(core);
    const columns = try preprocessed.generatePoseidon2(allocator, core, extension);
    var columns_moved = false;
    errdefer if (!columns_moved) freeColumns(allocator, columns);

    var scheme = try Engine.init(allocator, pcs_config);
    defer Engine.deinit(&scheme, allocator);
    var channel = Engine.Channel{};
    // `Engine.commit` consumes the generated columns on both success and
    // failure. Relinquish rollback ownership at the final handoff boundary.
    columns_moved = true;
    try Engine.commit(&scheme, allocator, columns, null, &channel);

    var roots = try scheme.roots(allocator);
    defer roots.deinit(allocator);
    if (roots.items.len != 1 or !std.meta.eql(roots.items[0], actual))
        return types.ProverError.InvalidPreprocessedCommitment;
}

fn allocate(
    allocator: std.mem.Allocator,
    boundaries: Boundaries,
) std.mem.Allocator.Error!OwnedLogSizes {
    return .{
        .values = try allocator.alloc(u32, boundaries.provider_end),
        .boundaries = boundaries,
    };
}

fn checkedAdd(a: usize, b: usize) GeometryError!usize {
    return std.math.add(usize, a, b) catch error.TraceGeometryOverflow;
}

fn appendRun(
    values: []u32,
    cursor: *usize,
    count: usize,
    log_size: u32,
) GeometryError!void {
    if (cursor.* > values.len or count > values.len - cursor.*)
        return error.InvalidTraceGeometry;
    const end = cursor.* + count;
    @memset(values[cursor.*..end], log_size);
    cursor.* = end;
}

fn requireBoundary(actual: usize, expected: usize) GeometryError!void {
    if (actual != expected) return error.InvalidTraceGeometry;
}

fn freeColumns(
    allocator: std.mem.Allocator,
    columns: []@import("stwo_prover_engine").pcs.ColumnEvaluation,
) void {
    for (columns) |column| allocator.free(@constCast(column.values));
    allocator.free(columns);
}

comptime {
    if (guest_main_trace.preprocessed_column_count != 4 or
        guest_main_trace.caller_main_column_count != 286 or
        guest_main_trace.provider_main_column_count != 445 or
        guest_interaction.caller_column_count != 308 or
        guest_interaction.provider_column_count != 8)
    {
        @compileError("Poseidon2 profile commitment geometry drifted");
    }
}
