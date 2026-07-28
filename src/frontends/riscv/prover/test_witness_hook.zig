//! Test-only mutation of committed witness values before commitment.
//!
//! Three mutation shapes exist because they answer three different questions, and the
//! stage each one is applied at is what makes the difference — not the shape of the edit.
//!
//! `.preprocessed` / `.main` add a delta to one cell of an otherwise honest row, applied
//! to the *duplicated* committed columns after every derived artefact already exists.
//! The adversary they model is incoherent on purpose: the question is only "does the
//! commitment bind this cell at all", and the answer is yes for any cell that any tree
//! reads. An additive delta cannot express a forgery whose soundness argument depends on
//! several columns agreeing — perturbing one limb also breaks the sibling relations the
//! forged row must still satisfy, so the row is rejected for an unrelated reason and the
//! test would still pass with the range check under scrutiny deleted. That is
//! coverage-shaped, not coverage.
//!
//! `.main_row` therefore assigns absolute values to several columns of one row in a
//! single pass, so a forged row can be self-consistent rather than a perturbation of the
//! honest one. The DIVU divisor forgery is the motivating case: limbs `[0, 0, 0, 256]`
//! compose to 2^32, which is 2 mod p, so the divisor's field value is 2 while its limbs
//! are non-bytes; `q = 0, r = 100` then satisfies the recurrence and only a byte range
//! check on the divisor limbs rejects the row. Building that row means setting the
//! divisor limbs, quotient, remainder and product carries coherently at once.
//!
//! ## Why `.main_row` is applied through `applyOpcodeWitness`, not `applyMain`
//!
//! A real malicious prover picks its witness and then derives *everything* from that
//! witness: the committed main trace, the lookup multiplicities, and the interaction
//! columns. Applying a row override to the committed duplicate alone simulates a prover
//! who forges tree 1 and then honestly derives tree 2 from the true witness. The two
//! trees then disagree, so the prover's own composition check refuses the row whatever
//! the AIR would have said, and no `.main_row` forgery can be attributed to the
//! constraint it names. `applyOpcodeWitness` therefore writes into the workspace opcode
//! buffers *before* `lookup_sources.ingest`, which is the single point all three
//! consumers read. `applyMain` keeps `.main` at its post-generation position and ignores
//! `.main_row`; applying a row override at both sites would apply it twice.
//!
//! Ownership: a `RowOverride`'s `values` slice is borrowed for the duration of the apply
//! call and is never retained.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const prover_pcs = @import("stwo_prover_engine").pcs;
const statement_mod = @import("../air/statement.zig");
const infra = @import("../infra_trace.zig");
const trace = @import("../runner/trace.zig");

pub const Target = union(enum) {
    opcode: struct {
        family: trace.OpcodeFamily,
        shard: u32 = 0,
    },
    infrastructure: struct {
        kind: statement_mod.InfraKind,
        occurrence: u32 = 0,
    },
};

pub const Cell = struct {
    target: Target,
    column: u32,
    logical_row: u32,
    delta: u32 = 1,
};

/// One absolute committed value. `value` is reduced into F_p rather than rejected, so a
/// caller may name a field element by any of its representatives.
pub const ColumnValue = struct {
    column: u32,
    value: u32,
};

/// Absolute values for several columns of one logical row of one component.
/// `values` is borrowed by the apply call.
pub const RowOverride = struct {
    target: Target,
    logical_row: u32,
    values: []const ColumnValue,
};

pub const Mutation = union(enum) {
    preprocessed: Cell,
    main: Cell,
    main_row: RowOverride,
};

pub const Error = error{
    InvalidMutationTarget,
    InvalidMutationColumn,
    InvalidMutationRow,
    InvalidMutationDelta,
    InvalidTraceShape,
    EmptyMutationRowOverride,
    DuplicateMutationColumn,
};

const Location = struct {
    column_offset: usize,
    log_size: u32,
    n_rows: u32,
    n_columns: u32,
};

pub fn applyPreprocessed(
    allocator: std.mem.Allocator,
    statement: statement_mod.RiscVStatement,
    columns: []prover_pcs.ColumnEvaluation,
    mutation: Mutation,
) !void {
    const cell = switch (mutation) {
        .preprocessed => |value| value,
        .main, .main_row => return,
    };
    if (columns.len != statement.nPreprocessedColumns()) return Error.InvalidTraceShape;
    try mutate(allocator, columns, try locatePreprocessed(statement, cell.target), cell);
}

/// Single-cell tamper of the committed main columns, after every derived artefact
/// exists. `.main_row` is deliberately not handled here; see the module comment.
pub fn applyMain(
    allocator: std.mem.Allocator,
    statement: statement_mod.RiscVStatement,
    columns: []prover_pcs.ColumnEvaluation,
    mutation: Mutation,
) !void {
    const cell = switch (mutation) {
        .preprocessed, .main_row => return,
        .main => |value| value,
    };
    if (columns.len != statement.nMainColumns()) return Error.InvalidTraceShape;
    try mutate(allocator, columns, try locateMain(statement, cell.target), cell);
}

/// Applies a `.main_row` override to the generated opcode witness itself, so the
/// multiplicity counters, the interaction columns and the committed main trace are all
/// derived from the forged row rather than from two different witnesses.
///
/// `components` is the workspace array `main_trace.copyOpcodeColumns` later duplicates
/// into the committed prefix, indexed by statement component order.
///
/// Returns whether a row was forged. The caller needs that to decide the ingestion
/// policy for unrepresentable lookup requests: a forged row may ask a table for a tuple
/// the table does not contain, which the honest pipeline treats as a prover bug.
pub fn applyOpcodeWitness(
    allocator: std.mem.Allocator,
    statement: statement_mod.RiscVStatement,
    components: []trace.TraceColumns,
    mutation: Mutation,
) !bool {
    const override = switch (mutation) {
        .preprocessed, .main => return false,
        .main_row => |value| value,
    };
    // Infrastructure columns have no workspace buffer that every consumer reads, so an
    // infrastructure row override cannot be made coherent at this stage. Refusing beats
    // committing a forgery whose two trees disagree for a reason the test never names.
    const wanted = switch (override.target) {
        .opcode => |value| value,
        .infrastructure => return Error.InvalidMutationTarget,
    };
    const index = try opcodeComponentIndex(statement, wanted.family, wanted.shard);
    const desc = statement.component_descs[index];
    const component = &components[index];
    if (component.n_columns != desc.n_columns) return Error.InvalidTraceShape;
    try validateRowOverride(desc.n_rows, desc.n_columns, override);
    const domain = @as(usize, 1) << @intCast(desc.log_size);
    for (override.values) |value| {
        if (component.columns[value.column].len != domain) return Error.InvalidTraceShape;
    }

    const placement = try infra.BitReversalTable.init(allocator, desc.log_size);
    defer placement.deinit(allocator);
    const row = placement.map(override.logical_row);
    for (override.values) |value| {
        component.columns[value.column][row] = M31.fromU64(value.value);
    }
    return true;
}

fn mutate(
    allocator: std.mem.Allocator,
    columns: []prover_pcs.ColumnEvaluation,
    location: Location,
    cell: Cell,
) !void {
    if (cell.delta == 0) return Error.InvalidMutationDelta;
    if (cell.column >= location.n_columns) return Error.InvalidMutationColumn;
    if (cell.logical_row >= location.n_rows) return Error.InvalidMutationRow;
    const column = &columns[location.column_offset + cell.column];
    if (column.log_size != location.log_size) return Error.InvalidTraceShape;
    const placement = try infra.BitReversalTable.init(allocator, location.log_size);
    defer placement.deinit(allocator);
    const row = placement.map(cell.logical_row);
    const values = @constCast(column.values);
    values[row] = values[row].add(M31.fromU64(cell.delta));
}

/// Assign every requested cell of one logical row, or assign none of them.
///
/// The whole point of the primitive is that the resulting row is coherent, so a partially
/// applied override would produce a row whose rejection reason says nothing about the
/// constraint under test. Validation therefore completes before the first write.
fn validateRowOverride(n_rows: u32, n_columns: u32, override: RowOverride) Error!void {
    if (override.values.len == 0) return Error.EmptyMutationRowOverride;
    if (override.logical_row >= n_rows) return Error.InvalidMutationRow;
    for (override.values, 0..) |entry, index| {
        if (entry.column >= n_columns) return Error.InvalidMutationColumn;
        // Two entries for one cell mean the caller holds two intentions for it. Silently
        // letting the last one win would hide a broken forgery recipe, so reject instead.
        // The scan is quadratic in a list bounded by the component's column count.
        for (override.values[index + 1 ..]) |later| {
            if (later.column == entry.column) return Error.DuplicateMutationColumn;
        }
    }
}

fn locateMain(statement: statement_mod.RiscVStatement, target: Target) Error!Location {
    return switch (target) {
        .opcode => |wanted| locateOpcodeMain(statement, wanted.family, wanted.shard),
        .infrastructure => |wanted| locateInfraMain(statement, wanted.kind, wanted.occurrence),
    };
}

/// Statement position of one shard of one family, which is also its position in the
/// workspace opcode-column array.
fn opcodeComponentIndex(
    statement: statement_mod.RiscVStatement,
    family: trace.OpcodeFamily,
    wanted_shard: u32,
) Error!usize {
    var shard: u32 = 0;
    for (0..statement.n_components) |index| {
        if (statement.component_descs[index].family != family) continue;
        if (shard == wanted_shard) return index;
        shard += 1;
    }
    return Error.InvalidMutationTarget;
}

fn locateOpcodeMain(
    statement: statement_mod.RiscVStatement,
    family: trace.OpcodeFamily,
    wanted_shard: u32,
) Error!Location {
    const wanted = try opcodeComponentIndex(statement, family, wanted_shard);
    var offset: usize = 0;
    for (0..wanted) |index| offset += statement.component_descs[index].n_columns;
    const desc = statement.component_descs[wanted];
    return .{
        .column_offset = offset,
        .log_size = desc.log_size,
        .n_rows = desc.n_rows,
        .n_columns = desc.n_columns,
    };
}

fn locateInfraMain(
    statement: statement_mod.RiscVStatement,
    kind: statement_mod.InfraKind,
    wanted_occurrence: u32,
) Error!Location {
    var offset: usize = statement.nOpcodeMainColumns();
    var occurrence: u32 = 0;
    for (0..statement.n_infra) |index| {
        const desc = statement.infra_descs[index];
        if (desc.kind == kind) {
            if (occurrence == wanted_occurrence) return .{
                .column_offset = offset,
                .log_size = desc.log_size,
                .n_rows = desc.n_rows,
                .n_columns = desc.n_columns,
            };
            occurrence += 1;
        }
        offset += desc.n_columns;
    }
    return Error.InvalidMutationTarget;
}

fn locatePreprocessed(statement: statement_mod.RiscVStatement, target: Target) Error!Location {
    const wanted = switch (target) {
        .opcode => return Error.InvalidMutationTarget,
        .infrastructure => |value| value,
    };
    var occurrence: u32 = 0;
    for (0..statement.n_infra) |index| {
        const desc = statement.infra_descs[index];
        if (desc.kind == wanted.kind) {
            if (occurrence == wanted.occurrence) return .{
                .column_offset = statement.preprocessedOffsetForInfra(index),
                .log_size = desc.log_size,
                .n_rows = @intCast(@as(usize, 1) << @intCast(desc.log_size)),
                .n_columns = statement_mod.nPreprocessedColumnsForInfra(desc.kind),
            };
            occurrence += 1;
        }
    }
    return Error.InvalidMutationTarget;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const TEST_LOG_SIZE: u32 = 2;
const TEST_DOMAIN: usize = @as(usize, 1) << TEST_LOG_SIZE;
const TEST_N_ROWS: u32 = 3;
const TEST_N_COLUMNS: u32 = 3;

const TEST_TARGET: Target = .{ .opcode = .{ .family = .div } };

/// One `div` component, three columns, four-row domain of which three rows are used.
/// `public_data` stays `undefined` because no mutation path reads it.
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
