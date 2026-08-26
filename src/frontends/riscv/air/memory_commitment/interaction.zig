//! LogUp columns for Stark-V's ordinary RW-memory boundary table.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const infra = @import("../../infra_trace.zig");
const lookup_entry = @import("../lookups/entry.zig");
const logup = @import("../logup.zig");
const relations_mod = @import("../relation_challenges.zig");
const boundary = @import("boundary.zig");

pub const N_SUMS: usize = 4;
pub const N_COLUMNS: usize = N_SUMS * 4;

pub const Claims = struct {
    sums: [N_SUMS]QM31,

    pub fn total(self: Claims) QM31 {
        var result = QM31.zero();
        for (self.sums) |sum| result = result.add(sum);
        return result;
    }
};

pub const Result = struct {
    columns: [N_COLUMNS][]M31,
    claims: Claims,

    pub fn deinit(self: *Result, allocator: std.mem.Allocator) void {
        freeColumns(allocator, &self.columns);
        self.* = undefined;
    }
};

pub fn generate(
    allocator: std.mem.Allocator,
    rows: []const boundary.Row,
    log_size: u32,
    relations: *const relations_mod.Relations,
) !Result {
    const size = @as(usize, 1) << @intCast(log_size);
    if (rows.len > size) return error.InvalidTraceShape;
    const pairs = try allocator.alloc([N_SUMS]logup.RowPair, size);
    defer allocator.free(pairs);
    for (0..size) |index| pairs[index] = if (index < rows.len)
        rowPairs(rows[index], relations)
    else
        paddingPairs(relations);

    var cumulative: [N_SUMS]logup.CumulativeColumn = undefined;
    var initialized: usize = 0;
    defer for (cumulative[0..initialized]) |*column| column.deinit(allocator);
    for (&cumulative, 0..) |*column, sum_index| {
        const row_pairs = try allocator.alloc(logup.RowPair, size);
        defer allocator.free(row_pairs);
        for (pairs, row_pairs) |row, *pair| pair.* = row[sum_index];
        column.* = try logup.cumulativeColumn(allocator, row_pairs);
        initialized += 1;
    }

    var columns = try allocateColumns(allocator, N_COLUMNS, size);
    errdefer freeColumns(allocator, &columns);
    const table = try infra.BitReversalTable.init(allocator, log_size);
    defer table.deinit(allocator);
    for (0..size) |row| {
        const dst = table.map(row);
        for (0..N_SUMS) |sum_index| {
            const current = cumulative[sum_index].sums[row].toM31Array();
            for (0..4) |coordinate| {
                columns[sum_index * 4 + coordinate][dst] = current[coordinate];
            }
        }
    }
    return .{
        .columns = columns,
        .claims = .{ .sums = .{
            cumulative[0].claimed,
            cumulative[1].claimed,
            cumulative[2].claimed,
            cumulative[3].claimed,
        } },
    };
}

pub fn rowPairs(row: boundary.Row, relations: *const relations_mod.Relations) [N_SUMS]logup.RowPair {
    const list = entriesFromRow(row);
    return .{
        list.pair(0, relations) catch unreachable,
        list.pair(1, relations) catch unreachable,
        list.pair(2, relations) catch unreachable,
        list.pair(3, relations) catch unreachable,
    };
}

pub fn entriesFromRow(row: boundary.Row) lookup_entry.List {
    const addr = base(row.addr);
    const root = base(row.root);
    const values = [4]QM31{
        base(row.value[0]),
        base(row.value[1]),
        base(row.value[2]),
        base(row.value[3]),
    };
    return entries(.{
        addr,
        base(row.clock),
        values[0],
        values[1],
        values[2],
        values[3],
        QM31.fromBase(row.multiplicity),
        root,
    }, QM31.one());
}

pub fn paddingPairs(relations: *const relations_mod.Relations) [N_SUMS]logup.RowPair {
    const zero = QM31.zero();
    const one = QM31.one();
    _ = relations;
    return .{
        .{ .n1 = zero, .d1 = one, .n2 = zero, .d2 = one },
        .{ .n1 = zero, .d1 = one, .n2 = zero, .d2 = one },
        .{ .n1 = zero, .d1 = one, .n2 = zero, .d2 = one },
        .{ .n1 = zero, .d1 = one, .n2 = zero, .d2 = one },
    };
}

pub const N_CONSTRAINTS: usize = N_SUMS + 2;

pub fn evaluate(
    main: [8]QM31,
    is_active: QM31,
    is_first: QM31,
    sums: [N_SUMS]QM31,
    previous: [N_SUMS]QM31,
    claims: [N_SUMS]QM31,
    relations: *const relations_mod.Relations,
) [N_CONSTRAINTS]QM31 {
    return evaluateGeneric(QM31, main, is_active, is_first, sums, previous, claims, relations);
}

pub fn evaluateGeneric(
    comptime S: type,
    main: [8]S,
    is_active: S,
    is_first: S,
    sums: [N_SUMS]S,
    previous: [N_SUMS]S,
    claims: [N_SUMS]S,
    relations: anytype,
) [N_CONSTRAINTS]S {
    const addr = main[0];
    const clock = main[1];
    const values = main[2..6];
    const multiplicity = main[6];
    const root = main[7];
    const list = entriesGeneric(S, .{ addr, clock, values[0], values[1], values[2], values[3], multiplicity, root }, is_active);
    const pairs = [N_SUMS]logup.RowPairFor(S){
        list.pairWith(0, relations) catch unreachable,
        list.pairWith(1, relations) catch unreachable,
        list.pairWith(2, relations) catch unreachable,
        list.pairWith(3, relations) catch unreachable,
    };
    var result: [N_CONSTRAINTS]S = undefined;
    for (0..N_SUMS) |index| {
        result[index] = logup.pairConstraintGeneric(
            S,
            sums[index],
            previous[index],
            is_first,
            claims[index],
            pairs[index],
        );
    }
    const multiplicity_squared = multiplicity.square();
    result[N_SUMS] = multiplicity.mul(multiplicity_squared.sub(S.one()));
    result[N_SUMS + 1] = multiplicity_squared.sub(is_active);
    return result;
}

pub fn entries(main: [8]QM31, enabler: QM31) lookup_entry.List {
    return entriesGeneric(QM31, main, enabler);
}

pub fn entriesGeneric(comptime S: type, main: [8]S, enabler: S) lookup_entry.Builder(S).List {
    const EntryBuilder = lookup_entry.Builder(S);
    const addr = main[0];
    const clock = main[1];
    const values = main[2..6];
    const multiplicity = main[6];
    const root = main[7];
    const depth = baseGeneric(S, 30);
    var list = EntryBuilder.List{};
    appendGeneric(S, &list, .range_check_8_8, enabler.neg(), .{ values[0], values[1] });
    appendGeneric(S, &list, .range_check_8_8, enabler.neg(), .{ values[2], values[3] });
    appendGeneric(S, &list, .memory_access, multiplicity, .{
        S.one(), addr, clock, values[0], values[1], values[2], values[3],
    });
    appendGeneric(S, &list, .merkle, enabler.neg(), .{ addr, depth, values[0], root });
    appendGeneric(S, &list, .merkle, enabler.neg(), .{ addr.add(baseGeneric(S, 1)), depth, values[1], root });
    appendGeneric(S, &list, .merkle, enabler.neg(), .{ addr.add(baseGeneric(S, 2)), depth, values[2], root });
    appendGeneric(S, &list, .merkle, enabler.neg(), .{ addr.add(baseGeneric(S, 3)), depth, values[3], root });
    return list;
}

pub fn diagnosticSum(
    rows: []const boundary.Row,
    domain: lookup_entry.Domain,
    relations: *const relations_mod.Relations,
) !QM31 {
    var result = QM31.zero();
    for (rows) |row| {
        const list = entriesFromRow(row);
        for (list.entries[0..list.len]) |item| {
            if (item.domain != domain or item.numerator.isZero()) continue;
            const denominator = try item.denominator(relations);
            result = result.add(item.numerator.mul(try denominator.inv()));
        }
    }
    return result;
}

fn append(list: *lookup_entry.List, domain: lookup_entry.Domain, numerator: QM31, values: anytype) void {
    return appendGeneric(QM31, list, domain, numerator, values);
}

fn appendGeneric(comptime S: type, list: *lookup_entry.Builder(S).List, domain: lookup_entry.Domain, numerator: S, values: anytype) void {
    var item = lookup_entry.Builder(S).Entry{ .domain = domain, .numerator = numerator, .arity = values.len };
    inline for (values, 0..) |value, index| item.values[index] = value;
    list.append(item);
}

fn allocateColumns(allocator: std.mem.Allocator, comptime n: usize, len: usize) ![n][]M31 {
    var columns: [n][]M31 = undefined;
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

fn base(value: anytype) QM31 {
    return QM31.fromBase(M31.fromU64(@as(u64, value)));
}

fn baseGeneric(comptime S: type, value: anytype) S {
    return S.fromBase(M31.fromU64(@as(u64, value)));
}

test "memory boundary interaction is padding invariant" {
    const relations = relations_mod.Relations.dummy();
    const row = boundary.Row{
        .addr = 0x1000,
        .clock = 7,
        .value = .{ 1, 2, 3, 4 },
        .multiplicity = M31.one().neg(),
        .root = 99,
    };
    var compact = try generate(std.testing.allocator, &.{row}, 0, &relations);
    defer compact.deinit(std.testing.allocator);
    var padded = try generate(std.testing.allocator, &.{row}, 3, &relations);
    defer padded.deinit(std.testing.allocator);
    for (compact.claims.sums, padded.claims.sums) |actual, expected| {
        try std.testing.expect(actual.eql(expected));
    }
}
