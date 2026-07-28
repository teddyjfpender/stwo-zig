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
const prover_pcs = @import("stwo_prover_impl").pcs;
const stage_profile = @import("stwo_prover_impl").stage_profile;
const table_schema = @import("../air/lookups/tables/schema.zig");
const statement_mod = @import("../air/statement.zig");
const opcode_trace = @import("opcode_trace.zig");
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
) !void {
    var stage = try stage_profile.StageScope.begin(recorder, "riscv_preprocessed_commit", "RISC-V preprocessed trace commit");
    defer stage.end();

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
