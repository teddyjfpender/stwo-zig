//! Field-native custody rows for changed-only sparse-memory updates.
//!
//! A row moves one exact Merkle tuple between the authenticated entry and
//! exit root scopes, or supplies an external multiproof node to one/both
//! scopes.  The four one-hot modes deliberately keep the algebra simple:
//! this table is tiny compared with the Poseidon provider work it removes.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const infra = @import("../../infra_trace.zig");
const lookup_entry = @import("../lookups/entry.zig");
const logup = @import("../logup.zig");
const relations_mod = @import("../relation_challenges.zig");

pub const N_MODES: usize = 4;
pub const N_MAIN_COLUMNS: usize = 3 + N_MODES;
pub const N_INTERACTION_COLUMNS: usize = 4;
pub const N_CONSTRAINTS: usize = 1 + N_MODES + 1;

pub const Mode = enum(u2) {
    /// External frontier tuple is used only by the entry computation.
    external_entry,
    /// External frontier tuple is used by both root computations.
    external_both,
    /// An unchanged final leaf is proved equal to its entry leaf.
    unchanged_leaf,
    /// An entry-authenticated internal subtree is reused by the exit update.
    reused_subtree,
};

pub const Row = struct {
    index: u32,
    depth: u32,
    value: u32,
    mode: Mode,
};

pub const Columns = struct {
    values: [N_MAIN_COLUMNS][]M31,

    pub fn deinit(self: *Columns, allocator: std.mem.Allocator) void {
        freeColumns(allocator, &self.values);
        self.* = undefined;
    }
};

pub const Interaction = struct {
    columns: [N_INTERACTION_COLUMNS][]M31,
    claim: QM31,

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
        const mode_index: usize = @intFromEnum(row.mode);
        columns[3 + mode_index][destination] = M31.one();
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
    for (0..size) |index| pairs[index] = if (index < rows.len)
        rowPair(rows[index], entry_root, exit_root, relations)
    else
        paddingPair();
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
    return .{ .columns = columns, .claim = cumulative.claimed };
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
    var result: [N_CONSTRAINTS]S = undefined;
    result[0] = logup.pairConstraintGeneric(
        S,
        sum,
        previous,
        is_first,
        claim,
        pair,
    );
    var selector_sum = S.zero();
    for (main[3..]) |selector| {
        selector_sum = selector_sum.add(selector);
    }
    inline for (0..N_MODES) |index| {
        const selector = main[3 + index];
        result[1 + index] = selector.mul(selector.sub(S.one()));
    }
    result[1 + N_MODES] = selector_sum.sub(is_active);
    return result;
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
    var main = [_]QM31{QM31.zero()} ** N_MAIN_COLUMNS;
    main[0] = base(row.index);
    main[1] = base(row.depth);
    main[2] = base(row.value);
    const mode_index: usize = @intFromEnum(row.mode);
    main[3 + mode_index] = QM31.one();
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
    const external_entry = main[3];
    const external_both = main[4];
    const unchanged_leaf = main[5];
    const reused_subtree = main[6];
    const entry_numerator = external_entry.add(external_both)
        .add(unchanged_leaf).neg().add(reused_subtree).mul(enabler);
    const exit_numerator = external_both.neg().add(unchanged_leaf)
        .sub(reused_subtree).mul(enabler);
    const EntryBuilder = lookup_entry.Builder(S);
    var list = EntryBuilder.List{};
    appendGeneric(S, &list, entry_numerator, main[0..3].*, entry_root);
    appendGeneric(S, &list, exit_numerator, main[0..3].*, exit_root);
    return list.pairWith(0, relations) catch unreachable;
}

fn appendGeneric(
    comptime S: type,
    list: *lookup_entry.Builder(S).List,
    numerator: S,
    main: [3]S,
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

fn base(value: u32) QM31 {
    return QM31.fromBase(M31.fromU64(value));
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

test "changed-only bridge mode numerators are exact" {
    const relations = relations_mod.Relations.dummy();
    const rows = [_]Row{
        .{ .index = 4, .depth = 30, .value = 7, .mode = .external_entry },
        .{ .index = 5, .depth = 30, .value = 8, .mode = .external_both },
        .{ .index = 6, .depth = 30, .value = 9, .mode = .unchanged_leaf },
        .{ .index = 3, .depth = 29, .value = 10, .mode = .reused_subtree },
    };
    var main = try generateMain(std.testing.allocator, &rows, 4);
    defer main.deinit(std.testing.allocator);
    var interaction = try generateInteraction(
        std.testing.allocator,
        &rows,
        4,
        11,
        12,
        &relations,
    );
    defer interaction.deinit(std.testing.allocator);
    try std.testing.expect(!interaction.claim.isZero());
}
