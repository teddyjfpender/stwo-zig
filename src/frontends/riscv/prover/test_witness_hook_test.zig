//! Adversarial tests for the witness-mutation core.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const prover_pcs = @import("stwo_prover_engine").pcs;
const statement_mod = @import("../air/statement.zig");
const infra = @import("../infra_trace.zig");
const trace = @import("../runner/trace.zig");
const legacy_lui = @import("../runner/witness/lui_legacy_test_oracle.zig");
const opcode_interaction = @import("../air/lookups/opcode_interaction.zig");
const owner = @import("test_witness_hook_core.zig");

const Target = owner.Target;
const Cell = owner.Cell;
const ColumnValue = owner.ColumnValue;
const RowOverride = owner.RowOverride;
const Mutation = owner.Mutation;
const Error = owner.Error;
const applyPreprocessed = owner.applyPreprocessed;
const applyMain = owner.applyMain;
const applyInteraction = owner.applyInteraction;
const applyOpcodeWitness = owner.applyOpcodeWitness;
const applyLegacyLuiAuthority = owner.applyLegacyLuiAuthority;

const TEST_LOG_SIZE: u32 = 2;
const TEST_DOMAIN: usize = @as(usize, 1) << TEST_LOG_SIZE;
const TEST_N_ROWS: u32 = 3;
const TEST_N_COLUMNS: u32 = 3;
const TEST_N_INTERACTION_COLUMNS: usize = opcode_interaction.nColumns(.div);
const TEST_TARGET: Target = .{ .opcode = .{ .family = .div } };

fn testStatement() statement_mod.RiscVStatement {
    var statement: statement_mod.RiscVStatement = undefined;
    statement.n_components = 1;
    statement.component_descs[0] = .{
        .family = .div,
        .log_size = TEST_LOG_SIZE,
        .n_rows = TEST_N_ROWS,
        .n_columns = TEST_N_COLUMNS,
    };
    statement.n_infra = 0;
    return statement;
}

/// Distinct sentinels per cell so an unintended write is visible.
fn fillTestStorage(storage: *[TEST_N_COLUMNS][TEST_DOMAIN]M31) void {
    for (storage, 0..) |*cells, column| {
        for (cells, 0..) |*cell, row| {
            cell.* = M31.fromU64(1000 * (column + 1) + row);
        }
    }
}

fn bindTestColumns(
    storage: *[TEST_N_COLUMNS][TEST_DOMAIN]M31,
    columns: *[TEST_N_COLUMNS]prover_pcs.ColumnEvaluation,
) void {
    for (columns, storage) |*column, *cells| {
        column.* = .{ .log_size = TEST_LOG_SIZE, .values = cells };
    }
}

fn fillInteractionStorage(
    storage: *[TEST_N_INTERACTION_COLUMNS][TEST_DOMAIN]M31,
) void {
    for (storage, 0..) |*cells, column| {
        for (cells, 0..) |*cell, row| {
            cell.* = M31.fromU64(10_000 + 100 * column + row);
        }
    }
}

fn bindInteractionColumns(
    storage: *[TEST_N_INTERACTION_COLUMNS][TEST_DOMAIN]M31,
    columns: *[TEST_N_INTERACTION_COLUMNS]prover_pcs.ColumnEvaluation,
) void {
    for (columns, storage) |*column, *cells| {
        column.* = .{ .log_size = TEST_LOG_SIZE, .values = cells };
    }
}

/// The workspace view of the same storage: one component of `TEST_N_COLUMNS` buffers.
fn bindTestComponents(
    storage: *[TEST_N_COLUMNS][TEST_DOMAIN]M31,
    components: *[1]trace.TraceColumns,
) void {
    components[0].n_columns = TEST_N_COLUMNS;
    components[0].n_real_rows = TEST_N_ROWS;
    for (components[0].columns[0..TEST_N_COLUMNS], storage) |*column, *cells| {
        column.* = cells;
    }
}

fn luiTestRow(index: usize) trace.TraceRow {
    const rd: u5 = @intCast(index % 32);
    const immediate = @as(u32, @intCast(index * 0x34567)) & 0xfffff;
    const result = immediate << 12;
    return .{
        .clk = @intCast(index + 1),
        .pc = @intCast(0x1000 + index * 4),
        .opcode = .LUI,
        .rd = rd,
        .rs1 = 0,
        .rs2 = 0,
        .imm = @bitCast(result),
        .rs1_val = 0,
        .rs2_val = 0,
        .rd_prev_val = if (rd == 0) 0 else @intCast(index * 17),
        .rd_prev_clk = if (rd == 0) 0 else @intCast(index),
        .rd_val = if (rd == 0) 0 else result,
        .mem_addr = 0,
        .mem_val = 0,
        .is_load = false,
        .is_store = false,
        .branch_taken = false,
        .next_pc = @intCast(0x1004 + index * 4),
    };
}

test "applyOpcodeWitness assigns every requested column of one logical row" {
    const allocator = std.testing.allocator;
    var storage: [TEST_N_COLUMNS][TEST_DOMAIN]M31 = undefined;
    fillTestStorage(&storage);
    const honest = storage;
    var components: [1]trace.TraceColumns = undefined;
    bindTestComponents(&storage, &components);

    const values = [_]ColumnValue{
        .{ .column = 0, .value = 7 },
        .{ .column = 2, .value = 256 },
    };
    try std.testing.expect(try applyOpcodeWitness(allocator, testStatement(), &components, .{ .main_row = .{
        .target = TEST_TARGET,
        .logical_row = 1,
        .values = &values,
    } }));

    const placement = try infra.BitReversalTable.init(allocator, TEST_LOG_SIZE);
    defer placement.deinit(allocator);
    const physical = placement.map(1);

    // Assigned, not added: the honest sentinel is replaced.
    try std.testing.expectEqual(@as(u32, 7), storage[0][physical].v);
    try std.testing.expectEqual(@as(u32, 256), storage[2][physical].v);
    for (storage, honest, 0..) |cells, honest_cells, column| {
        for (cells, honest_cells, 0..) |cell, honest_cell, row| {
            const overridden = row == physical and (column == 0 or column == 2);
            if (!overridden) try std.testing.expectEqual(honest_cell.v, cell.v);
        }
    }
}

test "legacy LUI authority rewrites complete bit-reversed shards atomically" {
    const allocator = std.testing.allocator;
    const n_columns = trace.nColumnsForFamily(.lui);
    const log_size: u32 = 2;
    const domain = @as(usize, 1) << log_size;
    const shard_rows = [_]u32{ 3, 2 };

    var statement: statement_mod.RiscVStatement = undefined;
    statement.n_components = shard_rows.len;
    statement.n_infra = 0;
    for (shard_rows, 0..) |n_rows, index| {
        statement.component_descs[index] = .{
            .family = .lui,
            .log_size = log_size,
            .n_rows = n_rows,
            .n_columns = @intCast(n_columns),
        };
    }

    const sentinel = M31.fromU64(0x5151);
    var storage: [2][18][domain]M31 = .{.{.{sentinel} ** domain} ** 18} ** 2;
    var expected: [2][18][domain]M31 = .{.{.{M31.zero()} ** domain} ** 18} ** 2;
    var components: [2]trace.TraceColumns = undefined;
    var expected_views: [2][trace.MAX_FAMILY_COLUMNS][]M31 = undefined;
    for (&components, &expected_views, &storage, &expected, shard_rows) |
        *component,
        *expected_component,
        *component_storage,
        *expected_storage,
        n_rows,
    | {
        component.n_columns = n_columns;
        component.n_real_rows = n_rows;
        for (
            component.columns[0..n_columns],
            expected_component[0..n_columns],
            component_storage,
            expected_storage,
        ) |*column, *expected_column, *cells, *expected_cells| {
            column.* = cells;
            expected_column.* = expected_cells;
        }
    }

    var execution = trace.Trace.init(allocator);
    defer execution.deinit();
    for (0..5) |index| try execution.append(luiTestRow(index));

    var family_row: usize = 0;
    for (shard_rows, 0..) |n_rows, shard| {
        const placement = try infra.BitReversalTable.init(allocator, log_size);
        defer placement.deinit(allocator);
        for (0..n_rows) |logical_row| {
            legacy_lui.writeRow(
                &expected_views[shard],
                placement.map(logical_row),
                execution.rows.items[family_row],
            );
            family_row += 1;
        }
    }

    try std.testing.expect(try applyLegacyLuiAuthority(
        allocator,
        statement,
        &components,
        &execution,
        .legacy_lui_authority,
    ));
    for (storage, expected) |actual_component, expected_component| {
        for (actual_component, expected_component) |actual, wanted| {
            try std.testing.expectEqualSlices(M31, &wanted, &actual);
        }
    }

    // A rejected preflight cannot clear even one cell.
    @memset(&storage[0][0], sentinel);
    const original = storage[0][0];
    components[0].columns[0] = storage[0][0][0 .. domain - 1];
    try std.testing.expectError(
        Error.InvalidTraceShape,
        applyLegacyLuiAuthority(
            allocator,
            statement,
            &components,
            &execution,
            .legacy_lui_authority,
        ),
    );
    try std.testing.expectEqualSlices(M31, &original, &storage[0][0]);
}

test "applyOpcodeWitness rejects malformed overrides without touching the witness" {
    const allocator = std.testing.allocator;
    var storage: [TEST_N_COLUMNS][TEST_DOMAIN]M31 = undefined;
    fillTestStorage(&storage);
    const honest = storage;
    var components: [1]trace.TraceColumns = undefined;
    bindTestComponents(&storage, &components);

    const empty = [_]ColumnValue{};
    const out_of_range_column = [_]ColumnValue{.{ .column = TEST_N_COLUMNS, .value = 1 }};
    const duplicate = [_]ColumnValue{
        .{ .column = 1, .value = 4 },
        .{ .column = 0, .value = 5 },
        .{ .column = 1, .value = 6 },
    };
    const single = [_]ColumnValue{.{ .column = 0, .value = 9 }};

    const cases = [_]struct { expected: anyerror, override: RowOverride }{
        .{ .expected = Error.EmptyMutationRowOverride, .override = .{
            .target = TEST_TARGET,
            .logical_row = 0,
            .values = &empty,
        } },
        .{ .expected = Error.InvalidMutationColumn, .override = .{
            .target = TEST_TARGET,
            .logical_row = 0,
            .values = &out_of_range_column,
        } },
        // Row TEST_N_ROWS exists in the padded domain but not in the component.
        .{ .expected = Error.InvalidMutationRow, .override = .{
            .target = TEST_TARGET,
            .logical_row = TEST_N_ROWS,
            .values = &single,
        } },
        .{ .expected = Error.DuplicateMutationColumn, .override = .{
            .target = TEST_TARGET,
            .logical_row = 0,
            .values = &duplicate,
        } },
        .{ .expected = Error.InvalidMutationTarget, .override = .{
            .target = .{ .opcode = .{ .family = .div, .shard = 1 } },
            .logical_row = 0,
            .values = &single,
        } },
        // An infrastructure row override has no coherent application point here.
        .{ .expected = Error.InvalidMutationTarget, .override = .{
            .target = .{ .infrastructure = .{ .kind = .program } },
            .logical_row = 0,
            .values = &single,
        } },
    };

    for (cases) |case| {
        try std.testing.expectError(
            case.expected,
            applyOpcodeWitness(allocator, testStatement(), &components, .{ .main_row = case.override }),
        );
    }

    for (storage, honest) |cells, honest_cells| {
        for (cells, honest_cells) |cell, honest_cell| {
            try std.testing.expectEqual(honest_cell.v, cell.v);
        }
    }
}

test "applyOpcodeWitness rejects a wrong witness shape" {
    const allocator = std.testing.allocator;
    var storage: [TEST_N_COLUMNS][TEST_DOMAIN]M31 = undefined;
    fillTestStorage(&storage);
    var components: [1]trace.TraceColumns = undefined;
    bindTestComponents(&storage, &components);

    const single = [_]ColumnValue{.{ .column = 0, .value = 9 }};
    const override: Mutation = .{ .main_row = .{
        .target = TEST_TARGET,
        .logical_row = 0,
        .values = &single,
    } };

    // Fewer generated columns than the statement claims.
    components[0].n_columns = TEST_N_COLUMNS - 1;
    try std.testing.expectError(
        Error.InvalidTraceShape,
        applyOpcodeWitness(allocator, testStatement(), &components, override),
    );

    // Right column count, wrong domain for the targeted column.
    components[0].n_columns = TEST_N_COLUMNS;
    components[0].columns[0] = storage[0][0 .. TEST_DOMAIN - 1];
    try std.testing.expectError(
        Error.InvalidTraceShape,
        applyOpcodeWitness(allocator, testStatement(), &components, override),
    );
}

test "the committed-trace appliers ignore a main row override" {
    const allocator = std.testing.allocator;
    var storage: [TEST_N_COLUMNS][TEST_DOMAIN]M31 = undefined;
    fillTestStorage(&storage);
    const honest = storage;
    var columns: [TEST_N_COLUMNS]prover_pcs.ColumnEvaluation = undefined;
    bindTestColumns(&storage, &columns);

    const single = [_]ColumnValue{.{ .column = 0, .value = 9 }};
    const override: Mutation = .{ .main_row = .{
        .target = TEST_TARGET,
        .logical_row = 0,
        .values = &single,
    } };
    // Both must be no-ops: `applyOpcodeWitness` already applied the row, and a second
    // application would silently double a forgery that is meant to be applied once.
    try applyPreprocessed(allocator, testStatement(), &columns, override);
    try applyMain(allocator, testStatement(), &columns, override);
    // And a cell mutation reports no forged row, so ingestion keeps rejecting an
    // unrepresentable request as the prover bug it would be.
    var components: [1]trace.TraceColumns = undefined;
    bindTestComponents(&storage, &components);
    try std.testing.expect(!try applyOpcodeWitness(allocator, testStatement(), &components, .{
        .main = .{ .target = TEST_TARGET, .column = 0, .logical_row = 0 },
    }));

    for (storage, honest) |cells, honest_cells| {
        for (cells, honest_cells) |cell, honest_cell| {
            try std.testing.expectEqual(honest_cell.v, cell.v);
        }
    }
}

fn exerciseInteractionMutation(allocator: std.mem.Allocator) !void {
    var storage: [TEST_N_INTERACTION_COLUMNS][TEST_DOMAIN]M31 = undefined;
    fillInteractionStorage(&storage);
    const honest = storage;
    var columns: [TEST_N_INTERACTION_COLUMNS]prover_pcs.ColumnEvaluation = undefined;
    bindInteractionColumns(&storage, &columns);

    const mutation: Mutation = .{ .interaction = .{
        .target = TEST_TARGET,
        .column = @intCast(TEST_N_INTERACTION_COLUMNS - 1),
        .logical_row = 1,
        .delta = 7,
    } };
    applyInteraction(allocator, testStatement(), &columns, mutation) catch |err| {
        try std.testing.expectEqualDeep(honest, storage);
        return err;
    };

    const placement = try infra.BitReversalTable.init(std.testing.allocator, TEST_LOG_SIZE);
    defer placement.deinit(std.testing.allocator);
    const physical = placement.map(1);
    for (storage, honest, 0..) |cells, honest_cells, column| {
        for (cells, honest_cells, 0..) |cell, honest_cell, row| {
            const selected = column == TEST_N_INTERACTION_COLUMNS - 1 and row == physical;
            const expected = if (selected)
                honest_cell.add(M31.fromU64(7))
            else
                honest_cell;
            try std.testing.expectEqual(expected.v, cell.v);
        }
    }
}

test "interaction mutation is exact, failure-atomic, and allocation-failure clean" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        exerciseInteractionMutation,
        .{},
    );
}

test "interaction mutation validates tree shape, target, column, row, and delta" {
    var storage: [TEST_N_INTERACTION_COLUMNS][TEST_DOMAIN]M31 = undefined;
    fillInteractionStorage(&storage);
    const honest = storage;
    var columns: [TEST_N_INTERACTION_COLUMNS]prover_pcs.ColumnEvaluation = undefined;
    bindInteractionColumns(&storage, &columns);
    const statement = testStatement();

    const cases = [_]struct { expected: anyerror, cell: Cell }{
        .{ .expected = Error.InvalidMutationTarget, .cell = .{
            .target = .{ .opcode = .{ .family = .lui } },
            .column = 0,
            .logical_row = 0,
        } },
        .{ .expected = Error.InvalidMutationColumn, .cell = .{
            .target = TEST_TARGET,
            .column = TEST_N_INTERACTION_COLUMNS,
            .logical_row = 0,
        } },
        .{ .expected = Error.InvalidMutationRow, .cell = .{
            .target = TEST_TARGET,
            .column = 0,
            .logical_row = TEST_N_ROWS,
        } },
        .{ .expected = Error.InvalidMutationDelta, .cell = .{
            .target = TEST_TARGET,
            .column = 0,
            .logical_row = 0,
            .delta = 0,
        } },
    };
    for (cases) |case| {
        try std.testing.expectError(
            case.expected,
            applyInteraction(
                std.testing.allocator,
                statement,
                &columns,
                .{ .interaction = case.cell },
            ),
        );
        try std.testing.expectEqualDeep(honest, storage);
    }

    columns[0].values = storage[0][0 .. TEST_DOMAIN - 1];
    try std.testing.expectError(
        Error.InvalidTraceShape,
        applyInteraction(
            std.testing.allocator,
            statement,
            &columns,
            .{ .interaction = .{ .target = TEST_TARGET, .column = 0, .logical_row = 0 } },
        ),
    );
    try std.testing.expectEqualDeep(honest, storage);
}
