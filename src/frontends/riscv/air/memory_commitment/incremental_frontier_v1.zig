//! Shared untouched-subtree rows for an incremental sparse-memory transition.
//!
//! Every row consumes the same `(index, depth, value)` claim under both the
//! entry and exit roots.  Existing Merkle-node rows must emit those claims.
//! Consequently an omitted subtree is authenticated by the entry root and is
//! reused byte-for-byte by the exit-root computation.  No transport digest is
//! trusted as field authority.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const infra = @import("../../infra_trace.zig");
const lookup_entry = @import("../lookups/entry.zig");
const logup = @import("../logup.zig");
const relations_mod = @import("../relation_challenges.zig");

pub const N_MAIN_COLUMNS: usize = 3;
pub const N_SUMS: usize = 1;
pub const N_INTERACTION_COLUMNS: usize = 4;
pub const N_CONSTRAINTS: usize = 1;

pub const Row = struct {
    index: u32,
    depth: u32,
    value: u32,
};

pub const Columns = struct {
    values: [N_MAIN_COLUMNS][]M31,

    pub fn deinit(self: *Columns, allocator: std.mem.Allocator) void {
        freeColumns(allocator, &self.values);
        self.* = undefined;
    }
};

pub const Claims = struct {
    sum: QM31,
};

pub const Interaction = struct {
    columns: [N_INTERACTION_COLUMNS][]M31,
    claims: Claims,

    pub fn deinit(self: *Interaction, allocator: std.mem.Allocator) void {
        freeColumns(allocator, &self.columns);
        self.* = undefined;
    }
};

pub fn generateMain(
    allocator: std.mem.Allocator,
    rows: []const Row,
    log_size: u32,
) !Columns {
    const size = @as(usize, 1) << @intCast(log_size);
    if (rows.len > size) return error.InvalidTraceShape;
    var columns = try allocateColumns(allocator, N_MAIN_COLUMNS, size);
    errdefer freeColumns(allocator, &columns);
    for (&columns) |column| @memset(column, M31.zero());
    const table = try infra.BitReversalTable.init(allocator, log_size);
    defer table.deinit(allocator);
    for (rows, 0..) |row, logical_row| {
        const destination = table.map(logical_row);
        columns[0][destination] = M31.fromU64(row.index);
        columns[1][destination] = M31.fromU64(row.depth);
        columns[2][destination] = M31.fromU64(row.value);
    }
    return .{ .values = columns };
}

pub fn generateInteraction(
    allocator: std.mem.Allocator,
    rows: []const Row,
    log_size: u32,
    entry_root: u32,
    exit_root: u32,
    relations: *const relations_mod.Relations,
) !Interaction {
    const size = @as(usize, 1) << @intCast(log_size);
    if (rows.len > size) return error.InvalidTraceShape;
    const pairs = try allocator.alloc(logup.RowPair, size);
    defer allocator.free(pairs);
    for (0..size) |index| {
        pairs[index] = if (index < rows.len)
            rowPair(rows[index], entry_root, exit_root, relations)
        else
            paddingPair();
    }
    var cumulative = try logup.cumulativeColumn(allocator, pairs);
    defer cumulative.deinit(allocator);
    var columns = try allocateColumns(allocator, N_INTERACTION_COLUMNS, size);
    errdefer freeColumns(allocator, &columns);
    const table = try infra.BitReversalTable.init(allocator, log_size);
    defer table.deinit(allocator);
    for (cumulative.sums, 0..) |sum, logical_row| {
        const destination = table.map(logical_row);
        const coordinates = sum.toM31Array();
        for (coordinates, 0..) |coordinate, column| {
            columns[column][destination] = coordinate;
        }
    }
    return .{
        .columns = columns,
        .claims = .{ .sum = cumulative.claimed },
    };
}

pub fn evaluate(
    main: [N_MAIN_COLUMNS]QM31,
    is_active: QM31,
    is_first: QM31,
    sum: QM31,
    previous: QM31,
    claim: QM31,
    entry_root: QM31,
    exit_root: QM31,
    relations: *const relations_mod.Relations,
) [N_CONSTRAINTS]QM31 {
    return evaluateGeneric(
        QM31,
        main,
        is_active,
        is_first,
        sum,
        previous,
        claim,
        entry_root,
        exit_root,
        relations,
    );
}

pub fn evaluateGeneric(
    comptime S: type,
    main: [N_MAIN_COLUMNS]S,
    is_active: S,
    is_first: S,
    sum: S,
    previous: S,
    claim: S,
    entry_root: S,
    exit_root: S,
    relations: anytype,
) [N_CONSTRAINTS]S {
    const pair = rowPairGeneric(
        S,
        main,
        is_active,
        entry_root,
        exit_root,
        relations,
    );
    return .{logup.pairConstraintGeneric(
        S,
        sum,
        previous,
        is_first,
        claim,
        pair,
    )};
}

pub fn diagnosticClaim(
    rows: []const Row,
    entry_root: u32,
    exit_root: u32,
    relations: *const relations_mod.Relations,
) !QM31 {
    var result = QM31.zero();
    for (rows) |row| {
        const pair = rowPair(row, entry_root, exit_root, relations);
        result = result.add(pair.n1.mul(try pair.d1.inv()));
        result = result.add(pair.n2.mul(try pair.d2.inv()));
    }
    return result;
}

fn rowPair(
    row: Row,
    entry_root: u32,
    exit_root: u32,
    relations: *const relations_mod.Relations,
) logup.RowPair {
    const main = [N_MAIN_COLUMNS]QM31{
        base(row.index),
        base(row.depth),
        base(row.value),
    };
    return rowPairGeneric(
        QM31,
        main,
        QM31.one(),
        base(entry_root),
        base(exit_root),
        relations,
    );
}

fn rowPairGeneric(
    comptime S: type,
    main: [N_MAIN_COLUMNS]S,
    enabler: S,
    entry_root: S,
    exit_root: S,
    relations: anytype,
) logup.RowPairFor(S) {
    const EntryBuilder = lookup_entry.Builder(S);
    var list = EntryBuilder.List{};
    appendGeneric(S, &list, enabler.neg(), main, entry_root);
    appendGeneric(S, &list, enabler.neg(), main, exit_root);
    return list.pairWith(0, relations) catch unreachable;
}

fn appendGeneric(
    comptime S: type,
    list: *lookup_entry.Builder(S).List,
    numerator: S,
    main: [N_MAIN_COLUMNS]S,
    root: S,
) void {
    var item = lookup_entry.Builder(S).Entry{
        .domain = .merkle,
        .numerator = numerator,
        .arity = 4,
    };
    item.values[0] = main[0];
    item.values[1] = main[1];
    item.values[2] = main[2];
    item.values[3] = root;
    list.append(item);
}

fn paddingPair() logup.RowPair {
    return .{
        .n1 = QM31.zero(),
        .d1 = QM31.one(),
        .n2 = QM31.zero(),
        .d2 = QM31.one(),
    };
}

fn allocateColumns(
    allocator: std.mem.Allocator,
    comptime count: usize,
    len: usize,
) ![count][]M31 {
    var columns: [count][]M31 = undefined;
    var initialized: usize = 0;
    errdefer for (columns[0..initialized]) |column| allocator.free(column);
    for (&columns) |*column| {
        column.* = try allocator.alloc(M31, len);
        initialized += 1;
    }
    return columns;
}

fn freeColumns(allocator: std.mem.Allocator, columns: []const []M31) void {
    for (columns) |column| allocator.free(column);
}

fn base(value: u32) QM31 {
    return QM31.fromBase(M31.fromU64(value));
}

test "shared frontier row consumes one identical subtree under both roots" {
    const relations = relations_mod.Relations.dummy();
    const row = Row{ .index = 9, .depth = 7, .value = 123 };
    const pair = rowPair(row, 456, 789, &relations);
    try std.testing.expect(pair.n1.eql(QM31.one().neg()));
    try std.testing.expect(pair.n2.eql(QM31.one().neg()));
    try std.testing.expect(!pair.d1.eql(pair.d2));

    const claimed = pair.n1.mul(try pair.d1.inv()).add(
        pair.n2.mul(try pair.d2.inv()),
    );
    const constraints = evaluate(
        .{ base(row.index), base(row.depth), base(row.value) },
        QM31.one(),
        QM31.one(),
        claimed,
        claimed,
        claimed,
        base(456),
        base(789),
        &relations,
    );
    try std.testing.expect(constraints[0].isZero());
}
