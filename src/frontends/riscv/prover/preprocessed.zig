//! Tree 0: canonical preprocessed columns for RISC-V components, and their
//! commitment.
//!
//! Every column here is a function of the statement geometry alone -- no
//! execution value reaches it -- which is why Tree 0 is committed first, before
//! any witness-derived column exists. `logSizes` states the same geometry for
//! the verifier, and the two must be read as one declaration: a column added to
//! `generate` without a matching entry in `logSizes` is a prover and a verifier
//! that disagree about the shape of the same tree.

const std = @import("std");
const prover_pcs = @import("stwo_prover_engine").pcs;
const stage_profile = @import("stwo_prover_api").stage_profile;
const table_schema = @import("../air/lookups/tables/schema.zig");
const statement_mod = @import("../air/statement.zig");
const guest_statement = @import("../air/guest_precompile/statement.zig");
const guest_main_trace = @import("../air/guest_precompile/main_trace.zig");
const opcode_trace = @import("opcode_trace.zig");
const proof_phase_meter = @import("proof_phase_meter.zig");
const relation_diagnostic = @import("relation_diagnostic.zig");
const test_witness_hook = @import("test_witness_hook.zig");
const types = @import("types.zig");

/// Generates the preprocessed columns and commits them as Tree 0.
///
/// The diagnostic snapshot is taken *before* any test mutation, unlike Tree 1's:
/// a preprocessed mutation is a claim that the verifier's own recomputation
/// rejects it, so the diagnostic must retain the canonical columns to compare
/// against. The column array is **transferred** to the scheme at the commit
/// point and released here on every path that does not reach it.
pub fn generateAndCommit(
    comptime Engine: type,
    comptime mode: types.RunMode,
    allocator: std.mem.Allocator,
    statement: *const statement_mod.RiscVStatement,
    scheme: *Engine.Scheme,
    channel: *Engine.Channel,
    recorder: ?*stage_profile.Recorder,
    test_mutation: ?test_witness_hook.Mutation,
    retained_tree: *?relation_diagnostic.RetainedTree,
    phase_meter: ?*proof_phase_meter.Meter,
) !void {
    var stage = try stage_profile.StageScope.begin(recorder, "riscv_preprocessed_commit", "RISC-V preprocessed trace commit");
    defer stage.end();

    var materialization_region: ?proof_phase_meter.WitnessRegion =
        if (phase_meter) |meter| try meter.begin() else null;
    errdefer if (materialization_region) |*region| region.abort();

    const columns = try generate(allocator, statement.*);
    var moved = false;
    errdefer if (!moved) {
        for (columns) |column| allocator.free(@constCast(column.values));
        allocator.free(columns);
    };

    if (comptime mode == .relation_diagnostic) {
        retained_tree.* = try relation_diagnostic.RetainedTree.capture(allocator, columns);
    }
    if (test_mutation) |mutation|
        try test_witness_hook.applyPreprocessed(allocator, statement.*, columns, mutation);

    if (materialization_region) |*region| try region.finish();

    moved = true;
    try Engine.commit(scheme, allocator, columns, recorder, channel);
}

/// Tree 0 for the Poseidon2 profile: the unchanged base columns followed by
/// caller and provider `(is_first, is_active)` pairs. Base column buffers move
/// into the extended descriptor array without copying.
pub fn generateAndCommitPoseidon2(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    statement: *const statement_mod.RiscVStatement,
    extension: *const guest_statement.ExtensionStatement,
    scheme: *Engine.Scheme,
    channel: *Engine.Channel,
    recorder: ?*stage_profile.Recorder,
) !void {
    return generateAndCommitPoseidon2WithPhaseMeter(
        Engine,
        allocator,
        statement,
        extension,
        scheme,
        channel,
        recorder,
        null,
    );
}

/// Profile Tree 0 with the same materialization boundary used by the base
/// prover. Commitment work is deliberately outside the witness region.
pub fn generateAndCommitPoseidon2WithPhaseMeter(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    statement: *const statement_mod.RiscVStatement,
    extension: *const guest_statement.ExtensionStatement,
    scheme: *Engine.Scheme,
    channel: *Engine.Channel,
    recorder: ?*stage_profile.Recorder,
    phase_meter: ?*proof_phase_meter.Meter,
) !void {
    var stage = try stage_profile.StageScope.begin(
        recorder,
        "riscv_guest_preprocessed_commit",
        "RISC-V guest preprocessed trace commit",
    );
    defer stage.end();

    var materialization_region: ?proof_phase_meter.WitnessRegion =
        if (phase_meter) |meter| try meter.begin() else null;
    errdefer if (materialization_region) |*region| region.abort();
    const columns = try generatePoseidon2(allocator, statement, extension);
    var moved = false;
    errdefer if (!moved) freeColumns(allocator, columns);
    if (materialization_region) |*region| try region.finish();
    moved = true;
    try Engine.commit(scheme, allocator, columns, recorder, channel);
}

pub fn generate(
    allocator: std.mem.Allocator,
    statement: statement_mod.RiscVStatement,
) ![]prover_pcs.ColumnEvaluation {
    const columns = try allocator.alloc(
        prover_pcs.ColumnEvaluation,
        statement.nPreprocessedColumns(),
    );
    var initialized: usize = 0;
    errdefer {
        for (columns[0..initialized]) |column| allocator.free(@constCast(column.values));
        allocator.free(columns);
    }
    for (0..statement.n_components) |index| {
        const desc = statement.component_descs[index];
        try appendSelectors(allocator, columns, &initialized, desc.log_size, desc.n_rows);
    }
    for (0..statement.n_infra) |index| {
        const desc = statement.infra_descs[index];
        if (statement_mod.tableKind(desc.kind)) |kind| {
            columns[initialized] = .{
                .log_size = desc.log_size,
                .values = try opcode_trace.generateIsFirst(allocator, desc.log_size),
            };
            initialized += 1;
            var tuples = try table_schema.generatePreprocessed(allocator, kind);
            for (tuples.columns[0..tuples.n_columns]) |values| {
                columns[initialized] = .{ .log_size = desc.log_size, .values = values };
                initialized += 1;
            }
            tuples.n_columns = 0;
        } else {
            try appendSelectors(allocator, columns, &initialized, desc.log_size, desc.n_rows);
        }
    }
    std.debug.assert(initialized == columns.len);
    return columns;
}

pub fn generatePoseidon2(
    allocator: std.mem.Allocator,
    statement: *const statement_mod.RiscVStatement,
    extension: *const guest_statement.ExtensionStatement,
) ![]prover_pcs.ColumnEvaluation {
    try extension.validate(statement);
    const base = try generate(allocator, statement.*);
    var base_owned = true;
    errdefer if (base_owned) freeColumns(allocator, base);

    const total_count = std.math.add(
        usize,
        base.len,
        guest_main_trace.preprocessed_column_count,
    ) catch return error.InvalidTraceShape;
    const result = try allocator.alloc(prover_pcs.ColumnEvaluation, total_count);
    var initialized: usize = 0;
    errdefer {
        for (result[0..initialized]) |column| allocator.free(@constCast(column.values));
        allocator.free(result);
    }
    @memcpy(result[0..base.len], base);
    initialized = base.len;
    allocator.free(base);
    base_owned = false;

    for (extension.components) |descriptor| {
        try appendSelectors(
            allocator,
            result,
            &initialized,
            descriptor.log_size,
            descriptor.n_rows,
        );
    }
    std.debug.assert(initialized == result.len);
    return result;
}

pub fn logSizes(
    allocator: std.mem.Allocator,
    statement: statement_mod.RiscVStatement,
) ![]u32 {
    const result = try allocator.alloc(u32, statement.nPreprocessedColumns());
    var offset: usize = 0;
    for (0..statement.n_components) |index| {
        const desc = statement.component_descs[index];
        @memset(result[offset .. offset + 2], desc.log_size);
        offset += 2;
    }
    for (0..statement.n_infra) |index| {
        const desc = statement.infra_descs[index];
        const count = statement_mod.nPreprocessedColumnsForInfra(desc.kind);
        @memset(result[offset .. offset + count], desc.log_size);
        offset += count;
    }
    std.debug.assert(offset == result.len);
    return result;
}

pub fn logSizesPoseidon2(
    allocator: std.mem.Allocator,
    statement: *const statement_mod.RiscVStatement,
    extension: *const guest_statement.ExtensionStatement,
) ![]u32 {
    try extension.validate(statement);
    const base = try logSizes(allocator, statement.*);
    defer allocator.free(base);
    const result = try allocator.alloc(
        u32,
        base.len + guest_main_trace.preprocessed_column_count,
    );
    @memcpy(result[0..base.len], base);
    var offset = base.len;
    for (extension.components) |descriptor| {
        @memset(result[offset .. offset + 2], descriptor.log_size);
        offset += 2;
    }
    std.debug.assert(offset == result.len);
    return result;
}

fn freeColumns(
    allocator: std.mem.Allocator,
    columns: []prover_pcs.ColumnEvaluation,
) void {
    for (columns) |column| allocator.free(@constCast(column.values));
    allocator.free(columns);
}

fn appendSelectors(
    allocator: std.mem.Allocator,
    columns: []prover_pcs.ColumnEvaluation,
    offset: *usize,
    log_size: u32,
    n_rows: u32,
) !void {
    columns[offset.*] = .{
        .log_size = log_size,
        .values = try opcode_trace.generateIsFirst(allocator, log_size),
    };
    offset.* += 1;
    columns[offset.*] = .{
        .log_size = log_size,
        .values = try opcode_trace.generateIsActive(allocator, log_size, n_rows),
    };
    offset.* += 1;
}

test "preprocessed trace pins exact six-table geometry" {
    const allocator = std.testing.allocator;
    var statement: statement_mod.RiscVStatement = undefined;
    statement.n_components = 0;
    statement.n_infra = table_schema.KIND_COUNT;
    for (0..table_schema.KIND_COUNT) |index| {
        const kind: table_schema.Kind = @enumFromInt(index);
        statement.infra_descs[index] = .{
            .kind = statement_mod.infraKindForTable(kind),
            .log_size = table_schema.logSize(kind),
            .n_rows = @intCast(table_schema.size(kind)),
            .n_columns = 1,
        };
    }

    const expected_offsets = [_]usize{ 0, 5, 7, 10, 14, 17, 20 };
    for (expected_offsets, 0..) |expected, index| {
        try std.testing.expectEqual(expected, statement.preprocessedOffsetForInfra(index));
    }
    try std.testing.expectEqual(@as(u32, 20), statement.nPreprocessedColumns());
    try std.testing.expectEqual(@as(u64, 9_469_952), statement.nPreprocessedCells());

    const log_sizes = try logSizes(allocator, statement);
    defer allocator.free(log_sizes);
    const columns = try generate(allocator, statement);
    defer {
        for (columns) |column| allocator.free(@constCast(column.values));
        allocator.free(columns);
    }
    try std.testing.expectEqual(statement.nPreprocessedColumns(), log_sizes.len);
    try std.testing.expectEqual(log_sizes.len, columns.len);
    for (columns, log_sizes) |column, log_size| {
        try std.testing.expectEqual(log_size, column.log_size);
    }
}

test "guest preprocessed trace appends exact caller provider selector pairs" {
    const support = @import("../air/guest_precompile/main_trace_test_support.zig");
    const allocator = std.testing.allocator;
    var statement = support.coreFixture(17);
    const extension = try guest_statement.ExtensionStatement.canonical(&statement, 17);
    const base = try generate(allocator, statement);
    defer freeColumns(allocator, base);
    const extended = try generatePoseidon2(allocator, &statement, &extension);
    defer freeColumns(allocator, extended);
    const logs = try logSizesPoseidon2(allocator, &statement, &extension);
    defer allocator.free(logs);

    try std.testing.expectEqual(
        base.len + guest_main_trace.preprocessed_column_count,
        extended.len,
    );
    try std.testing.expectEqual(extended.len, logs.len);
    for (base, extended[0..base.len]) |expected, actual| {
        try std.testing.expectEqual(expected.log_size, actual.log_size);
        try std.testing.expectEqualSlices(
            @import("stwo_core").fields.m31.M31,
            expected.values,
            actual.values,
        );
    }
    for (0..guest_main_trace.component_count) |component| {
        const offset = base.len + 2 * component;
        try std.testing.expectEqual(@as(u32, 5), logs[offset]);
        try std.testing.expectEqual(@as(u32, 5), logs[offset + 1]);
        for (0..32) |logical_row| {
            const row = guest_main_trace.committedRow(logical_row, 5);
            try std.testing.expectEqual(
                @as(u32, @intFromBool(logical_row == 0)),
                extended[offset].values[row].toU32(),
            );
            try std.testing.expectEqual(
                @as(u32, @intFromBool(logical_row < 17)),
                extended[offset + 1].values[row].toU32(),
            );
        }
    }
}
