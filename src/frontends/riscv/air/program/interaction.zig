//! Exact declaration-order LogUp columns for the program commitment table.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const infra = @import("../../infra_trace.zig");
const lookup_entry = @import("../lookups/entry.zig");
const logup = @import("../logup.zig");
const relations_mod = @import("../relation_challenges.zig");
const commitment = @import("commitment.zig");

pub const N_SUMS: usize = 4;
pub const N_COLUMNS: usize = N_SUMS * 4;
pub const N_CONSTRAINTS: usize = N_SUMS + 3;
pub const Previous = [N_SUMS][4][]M31;

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
    previous: Previous,
    claims: Claims,

    pub fn deinit(self: *Result, allocator: std.mem.Allocator) void {
        freeColumns(allocator, &self.columns);
        for (&self.previous) |*set| freeColumns(allocator, set);
        self.* = undefined;
    }
};

pub fn generate(
    allocator: std.mem.Allocator,
    rows: []const commitment.Row,
    log_size: u32,
    relations: *const relations_mod.Relations,
) !Result {
    const size = @as(usize, 1) << @intCast(log_size);
    if (rows.len > size) return error.InvalidTraceShape;
    const pairs = try allocator.alloc([N_SUMS]logup.RowPair, size);
    defer allocator.free(pairs);
    for (0..size) |index| pairs[index] = if (index < rows.len)
        rowPairsFromRow(rows[index], relations)
    else
        paddingPairs();
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
    var previous = try allocatePrevious(allocator, size);
    errdefer for (&previous) |*set| freeColumns(allocator, set);
    const placement = try infra.BitReversalTable.init(allocator, log_size);
    defer placement.deinit(allocator);
    for (0..size) |row| {
        const dst = placement.map(row);
        for (0..N_SUMS) |sum_index| {
            const current = cumulative[sum_index].sums[row].toM31Array();
            const prev = cumulative[sum_index].sums[(row + size - 1) % size].toM31Array();
            for (0..4) |coordinate| {
                columns[4 * sum_index + coordinate][dst] = current[coordinate];
                previous[sum_index][coordinate][dst] = prev[coordinate];
            }
        }
    }
    return .{
        .columns = columns,
        .previous = previous,
        .claims = .{ .sums = .{
            cumulative[0].claimed,
            cumulative[1].claimed,
            cumulative[2].claimed,
            cumulative[3].claimed,
        } },
    };
}

pub fn evaluate(
    main: [commitment.N_MAIN_COLUMNS]QM31,
    is_active: QM31,
    is_first: QM31,
    sums: [N_SUMS]QM31,
    previous: [N_SUMS]QM31,
    claims: [N_SUMS]QM31,
    relations: *const relations_mod.Relations,
) [N_CONSTRAINTS]QM31 {
    const pairs = rowPairs(main, relations);
    var result: [N_CONSTRAINTS]QM31 = undefined;
    for (0..N_SUMS) |index| {
        result[index] = logup.pairConstraint(
            sums[index],
            previous[index],
            is_first,
            claims[index],
            pairs[index],
        );
    }
    result[N_SUMS] = main[0].sub(is_active);
    result[N_SUMS + 1] = main[6].mul(QM31.one().sub(is_active));
    const word_address = main[8].add(main[9].mul(base(@as(u32, 1) << 20)));
    result[N_SUMS + 2] = main[0].mul(
        main[1].sub(word_address.mul(base(4))),
    );
    return result;
}

pub fn rowPairsFromRow(row: commitment.Row, relations: *const relations_mod.Relations) [N_SUMS]logup.RowPair {
    const main = [commitment.N_MAIN_COLUMNS]QM31{
        QM31.one(),
        base(row.addr),
        base(row.values[0]),
        base(row.values[1]),
        base(row.values[2]),
        base(row.values[3]),
        base(row.multiplicity),
        base(row.root),
        base((row.addr >> 2) & ((@as(u32, 1) << 20) - 1)),
        base(row.addr >> 22),
    };
    return rowPairs(main, relations);
}

pub fn rowPairs(main: [commitment.N_MAIN_COLUMNS]QM31, relations: *const relations_mod.Relations) [N_SUMS]logup.RowPair {
    const list = entries(main);
    return .{
        list.pair(0, relations) catch unreachable,
        list.pair(1, relations) catch unreachable,
        list.pair(2, relations) catch unreachable,
        list.pair(3, relations) catch unreachable,
    };
}

pub fn entries(main: [commitment.N_MAIN_COLUMNS]QM31) lookup_entry.List {
    const enabler = main[0];
    const addr = main[1];
    const values = main[2..6];
    const root = main[7];
    const depth = base(30);
    var list = lookup_entry.List{};
    append(&list, .program_access, main[6], .{ addr, values[0], values[1], values[2], values[3] });
    append(&list, .merkle, enabler.neg(), .{ addr, depth, values[0], root });
    append(&list, .merkle, enabler.neg(), .{ addr.add(base(1)), depth, values[1], root });
    append(&list, .merkle, enabler.neg(), .{ addr.add(base(2)), depth, values[2], root });
    append(&list, .merkle, enabler.neg(), .{ addr.add(base(3)), depth, values[3], root });
    append(&list, .range_check_20, enabler.neg(), .{main[8]});
    append(&list, .range_check_8_8, enabler.neg(), .{ main[9], QM31.zero() });
    return list;
}

pub fn diagnosticSum(
    rows: []const commitment.Row,
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

pub fn entriesFromRow(row: commitment.Row) lookup_entry.List {
    return entries(.{
        QM31.one(),
        base(row.addr),
        base(row.values[0]),
        base(row.values[1]),
        base(row.values[2]),
        base(row.values[3]),
        base(row.multiplicity),
        base(row.root),
        base((row.addr >> 2) & ((@as(u32, 1) << 20) - 1)),
        base(row.addr >> 22),
    });
}

pub fn paddingPairs() [N_SUMS]logup.RowPair {
    const zero = QM31.zero();
    const one = QM31.one();
    return .{
        .{ .n1 = zero, .d1 = one, .n2 = zero, .d2 = one },
        .{ .n1 = zero, .d1 = one, .n2 = zero, .d2 = one },
        .{ .n1 = zero, .d1 = one, .n2 = zero, .d2 = one },
        .{ .n1 = zero, .d1 = one, .n2 = zero, .d2 = one },
    };
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

fn allocatePrevious(allocator: std.mem.Allocator, len: usize) !Previous {
    var previous: Previous = undefined;
    var initialized: usize = 0;
    errdefer for (previous[0..initialized]) |*set| freeColumns(allocator, set);
    for (&previous) |*set| {
        set.* = try allocateColumns(allocator, 4, len);
        initialized += 1;
    }
    return previous;
}

fn freeColumns(allocator: std.mem.Allocator, columns: []const []M31) void {
    for (columns) |column| allocator.free(column);
}

fn base(value: u32) QM31 {
    return QM31.fromBase(M31.fromU64(value));
}

fn append(list: *lookup_entry.List, domain: lookup_entry.Domain, numerator: QM31, values: anytype) void {
    var item = lookup_entry.Entry{ .domain = domain, .numerator = numerator, .arity = values.len };
    inline for (values, 0..) |value, index| item.values[index] = value;
    list.append(item);
}

test "program interaction: exact declaration order uses four pair columns" {
    const relations = relations_mod.Relations.dummy();
    const row = commitment.Row{
        .addr = 0x1000,
        .values = .{ 10, 1, 0, 1 },
        .multiplicity = 3,
        .root = 99,
    };
    const pairs = rowPairsFromRow(row, &relations);
    try std.testing.expect(!pairs[0].n1.isZero());
    try std.testing.expect(!pairs[0].n2.isZero());
    try std.testing.expect(!pairs[2].n2.isZero());
    try std.testing.expect(pairs[3].n2.isZero());
}

test "program interaction: inactive rows cannot inject program multiplicity" {
    const zero = QM31.zero();
    const relations = relations_mod.Relations.dummy();
    var main = [_]QM31{zero} ** commitment.N_MAIN_COLUMNS;
    main[6] = QM31.one();
    const forged = evaluate(
        main,
        zero,
        zero,
        .{zero} ** N_SUMS,
        .{zero} ** N_SUMS,
        .{zero} ** N_SUMS,
        &relations,
    );
    try std.testing.expect(!forged[N_SUMS + 1].isZero());

    main[6] = zero;
    const padding = evaluate(
        main,
        zero,
        zero,
        .{zero} ** N_SUMS,
        .{zero} ** N_SUMS,
        .{zero} ** N_SUMS,
        &relations,
    );
    try std.testing.expect(padding[N_SUMS + 1].isZero());
}

test "program interaction: address limbs bind aligned words over the full Merkle domain" {
    const zero = QM31.zero();
    const one = QM31.one();
    const relations = relations_mod.Relations.dummy();
    var main = [_]QM31{zero} ** commitment.N_MAIN_COLUMNS;
    main[0] = one;
    main[1] = base(0x3fff_fffc);
    main[8] = base(0x000f_ffff);
    main[9] = base(0xff);
    const valid = evaluate(
        main,
        one,
        zero,
        .{zero} ** N_SUMS,
        .{zero} ** N_SUMS,
        .{zero} ** N_SUMS,
        &relations,
    );
    try std.testing.expect(valid[N_SUMS + 2].isZero());

    main[8] = main[8].add(one);
    const forged_limb = evaluate(
        main,
        one,
        zero,
        .{zero} ** N_SUMS,
        .{zero} ** N_SUMS,
        .{zero} ** N_SUMS,
        &relations,
    );
    try std.testing.expect(!forged_limb[N_SUMS + 2].isZero());

    main[1] = base(0x1002);
    main[8] = base(0x400);
    main[9] = zero;
    const unaligned = evaluate(
        main,
        one,
        zero,
        .{zero} ** N_SUMS,
        .{zero} ** N_SUMS,
        .{zero} ** N_SUMS,
        &relations,
    );
    try std.testing.expect(!unaligned[N_SUMS + 2].isZero());
}

test "program interaction: address limbs are range-table consumers" {
    const list = entriesFromRow(.{
        .addr = 0x3fff_fffc,
        .values = .{ 10, 1, 0, 1 },
        .multiplicity = 1,
        .root = 99,
    });
    try std.testing.expectEqual(@as(usize, 7), list.len);
    try std.testing.expectEqual(lookup_entry.Domain.range_check_20, list.entries[5].domain);
    try std.testing.expectEqual(lookup_entry.Domain.range_check_8_8, list.entries[6].domain);
    try std.testing.expect(list.entries[5].numerator.eql(QM31.one().neg()));
    try std.testing.expect(list.entries[6].numerator.eql(QM31.one().neg()));
}
