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

/// Four LogUp pair constraints, the ternary multiplicity range, the
/// multiplicity/activity binding, and the initial-row clock binding
/// (`m * (m + 1) * clock = 0`): a `+1` row opens an access chain at clock 0,
/// matching the prover's row builder (`boundary.zig`, initial rows carry
/// `.clock = 0`).  Without it the opening clock of every chain is a free
/// prover choice.  Degree 3, within the `log_size + 1` quotient bound.
/// Plus two public-root bindings: `m·(m+1)·(k_i·root + b_i) = 0` and
/// `m·(m−1)·(k_f·root + b_f) = 0`, where `(k, b)` is `(1, −R)` for a present
/// statement root `R` and `(0, 1)` for an absent one.  A `+1` (initial) row
/// must therefore carry `initial_rw_root` and a `−1` (final) row
/// `final_rw_root`, matching the builder (`boundary.zig`: initial rows use
/// `initial_tree.root`, final rows `final_tree.root`); an absent root forbids
/// that side entirely, matching a builder that emits no such rows.  Without
/// the binding a prover may open a word's chain against the final tree and
/// close it against the initial one, starting execution from `.data` contents
/// the verified initial root never committed.  Degree 3 in trace columns.
pub const N_CONSTRAINTS: usize = N_SUMS + 5;
pub const N_CONSTRAINTS_WITHOUT_ROOTS: usize = N_SUMS + 3;
pub const N_ROOT_PARAMETERS: usize = 4;

/// Verifier-owned constants binding row sign to the statement's public roots.
pub fn RootParameters(comptime S: type) type {
    return struct {
        initial_scale: S,
        initial_offset: S,
        final_scale: S,
        final_offset: S,

        pub fn fromPublic(initial: ?u32, final: ?u32) @This() {
            const initial_side = sideParameters(S, initial);
            const final_side = sideParameters(S, final);
            return .{
                .initial_scale = initial_side[0],
                .initial_offset = initial_side[1],
                .final_scale = final_side[0],
                .final_offset = final_side[1],
            };
        }

        pub fn fromArray(values: [N_ROOT_PARAMETERS]S) @This() {
            return .{
                .initial_scale = values[0],
                .initial_offset = values[1],
                .final_scale = values[2],
                .final_offset = values[3],
            };
        }

        pub fn toArray(self: @This()) [N_ROOT_PARAMETERS]S {
            return .{ self.initial_scale, self.initial_offset, self.final_scale, self.final_offset };
        }

        /// `k_i·root + b_i`: zero exactly when `root` is the initial root.
        pub fn initialTerm(self: @This(), root: S) S {
            return self.initial_scale.mul(root).add(self.initial_offset);
        }

        /// `k_f·root + b_f`: zero exactly when `root` is the final root.
        pub fn finalTerm(self: @This(), root: S) S {
            return self.final_scale.mul(root).add(self.final_offset);
        }
    };
}

fn sideParameters(comptime S: type, root: ?u32) [2]S {
    if (root) |value| return .{ S.one(), S.fromBase(M31.fromU64(value).neg()) };
    return .{ S.zero(), S.one() };
}

pub fn evaluate(
    main: [8]QM31,
    is_active: QM31,
    is_first: QM31,
    sums: [N_SUMS]QM31,
    previous: [N_SUMS]QM31,
    claims: [N_SUMS]QM31,
    relations: *const relations_mod.Relations,
    roots: RootParameters(QM31),
) [N_CONSTRAINTS]QM31 {
    return evaluateGeneric(QM31, main, is_active, is_first, sums, previous, claims, relations, roots);
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
    roots: RootParameters(S),
) [N_CONSTRAINTS]S {
    const base_constraints = evaluateWithoutRootsGeneric(S, main, is_active, is_first, sums, previous, claims, relations);
    var result: [N_CONSTRAINTS]S = undefined;
    @memcpy(result[0..N_CONSTRAINTS_WITHOUT_ROOTS], &base_constraints);
    const multiplicity = main[6];
    const root = main[7];
    result[N_SUMS + 3] = initialRootBindingGeneric(S, multiplicity, roots.initialTerm(root));
    result[N_SUMS + 4] = finalRootBindingGeneric(S, multiplicity, roots.finalTerm(root));
    return result;
}

/// `m·(m + 1)·term`: vanishes for `m` in {-1, 0}; a `+1` row forces `term = 0`.
pub fn initialRootBindingGeneric(comptime S: type, multiplicity: S, term: S) S {
    return multiplicity.mul(multiplicity.add(S.one())).mul(term);
}

/// `m·(m − 1)·term`: vanishes for `m` in {0, +1}; a `−1` row forces `term = 0`.
pub fn finalRootBindingGeneric(comptime S: type, multiplicity: S, term: S) S {
    return multiplicity.mul(multiplicity.sub(S.one())).mul(term);
}

/// Retired constraint shape without the public-root bindings; see
/// `N_CONSTRAINTS_WITHOUT_ROOTS`.
fn evaluateWithoutRootsGeneric(
    comptime S: type,
    main: [8]S,
    is_active: S,
    is_first: S,
    sums: [N_SUMS]S,
    previous: [N_SUMS]S,
    claims: [N_SUMS]S,
    relations: anytype,
) [N_CONSTRAINTS_WITHOUT_ROOTS]S {
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
    var result: [N_CONSTRAINTS_WITHOUT_ROOTS]S = undefined;
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
    result[N_SUMS + 2] = initialRowClockConstraintGeneric(S, multiplicity, clock);
    return result;
}

/// `m * (m + 1) * clock`: zero for `m` in {-1, 0}, and forces `clock = 0` on a
/// `+1` (initial) row.
pub fn initialRowClockConstraintGeneric(comptime S: type, multiplicity: S, clock: S) S {
    return multiplicity.mul(multiplicity.add(S.one())).mul(clock);
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

test "memory boundary AIR: initial rows must open their access chain at clock zero" {
    const relations = relations_mod.Relations.dummy();
    const zero = QM31.zero();
    const one = QM31.one();
    const Case = struct { multiplicity: QM31, clock: QM31, ok: bool };
    const cases = [_]Case{
        .{ .multiplicity = one, .clock = QM31.fromBase(M31.fromU64(7)), .ok = false },
        .{ .multiplicity = one, .clock = one, .ok = false },
        .{ .multiplicity = one, .clock = zero, .ok = true },
        .{ .multiplicity = one.neg(), .clock = QM31.fromBase(M31.fromU64(7)), .ok = true },
        .{ .multiplicity = one.neg(), .clock = zero, .ok = true },
        .{ .multiplicity = zero, .clock = QM31.fromBase(M31.fromU64(7)), .ok = true },
    };
    for (cases) |case| {
        var main = [_]QM31{zero} ** 8;
        main[0] = QM31.fromBase(M31.fromU64(0x1000));
        main[1] = case.clock;
        main[6] = case.multiplicity;
        const is_active = if (case.multiplicity.isZero()) zero else one;
        const constraints = evaluate(
            main,
            is_active,
            zero,
            .{zero} ** N_SUMS,
            .{zero} ** N_SUMS,
            .{zero} ** N_SUMS,
            &relations,
            RootParameters(QM31).fromPublic(0, 0),
        );
        try std.testing.expectEqual(case.ok, constraints[N_SUMS + 2].isZero());
        // The pre-existing multiplicity constraints are untouched by the clock.
        try std.testing.expect(constraints[N_SUMS].isZero());
        try std.testing.expect(constraints[N_SUMS + 1].isZero());
    }

    // Honest builder rows satisfy the binding on both sides of the boundary.
    var claims = try boundary.build(std.testing.allocator, &.{
        .{ .addr = 0x1000, .initial_word = 3, .final_word = 4, .final_clock = 9 },
    });
    defer claims.deinit(std.testing.allocator);
    for (claims.rows) |row| {
        const constraint = initialRowClockConstraintGeneric(
            QM31,
            QM31.fromBase(row.multiplicity),
            base(row.clock),
        );
        try std.testing.expect(constraint.isZero());
    }
}

test "memory boundary AIR: row sign is bound to the statement's public roots" {
    const relations = relations_mod.Relations.dummy();
    const zero = QM31.zero();
    var claims = try boundary.build(std.testing.allocator, &.{
        .{ .addr = 0x1000, .initial_word = 3, .final_word = 4, .final_clock = 9 },
        .{ .addr = 0x2000, .initial_word = 7, .final_word = 7, .final_clock = 0 },
    });
    defer claims.deinit(std.testing.allocator);
    const initial_root = claims.initial_tree.?.root;
    const final_root = claims.final_tree.?.root;
    try std.testing.expect(initial_root != final_root);
    const roots = RootParameters(QM31).fromPublic(initial_root, final_root);

    const Check = struct {
        fn direct(row: boundary.Row, parameters: RootParameters(QM31), challenges: *const relations_mod.Relations) [N_CONSTRAINTS - N_SUMS]QM31 {
            var main: [8]QM31 = undefined;
            main[0] = base(row.addr);
            main[1] = base(row.clock);
            for (0..4) |limb| main[2 + limb] = base(row.value[limb]);
            main[6] = QM31.fromBase(row.multiplicity);
            main[7] = base(row.root);
            const constraints = evaluate(main, QM31.one(), QM31.zero(), .{QM31.zero()} ** N_SUMS, .{QM31.zero()} ** N_SUMS, .{QM31.zero()} ** N_SUMS, challenges, parameters);
            return constraints[N_SUMS..].*;
        }
    };

    // The honest builder puts the initial root on `+1` rows and the final
    // root on `-1` rows; every direct constraint vanishes.
    var initial_rows: usize = 0;
    var final_rows: usize = 0;
    for (claims.rows) |row| {
        if (row.multiplicity.eql(M31.one())) {
            try std.testing.expectEqual(initial_root, row.root);
            initial_rows += 1;
        } else {
            try std.testing.expectEqual(final_root, row.root);
            final_rows += 1;
        }
        for (Check.direct(row, roots, &relations)) |constraint| try std.testing.expect(constraint.isZero());
    }
    try std.testing.expectEqual(@as(usize, 2), initial_rows);
    try std.testing.expectEqual(@as(usize, 2), final_rows);

    // Swapped roots: a `+1` row carrying the final root opens a chain from
    // state the initial root never committed; a `-1` row carrying the
    // initial root closes it there.  Each violates exactly its own binding.
    var swapped_initial = claims.rows[0];
    swapped_initial.root = final_root;
    const initial_violation = Check.direct(swapped_initial, roots, &relations);
    try std.testing.expect(!initial_violation[3].isZero());
    try std.testing.expect(initial_violation[4].isZero());
    var swapped_final = claims.rows[1];
    swapped_final.root = initial_root;
    const final_violation = Check.direct(swapped_final, roots, &relations);
    try std.testing.expect(final_violation[3].isZero());
    try std.testing.expect(!final_violation[4].isZero());

    // An arbitrary third root fails on whichever side the row claims.
    var foreign = claims.rows[0];
    foreign.root = initial_root ^ 0x5555;
    try std.testing.expect(!Check.direct(foreign, roots, &relations)[3].isZero());

    // An absent public root forbids that side entirely, as the builder emits
    // no such rows; the other side is unaffected.
    const no_initial = RootParameters(QM31).fromPublic(null, final_root);
    try std.testing.expect(!Check.direct(claims.rows[0], no_initial, &relations)[3].isZero());
    try std.testing.expect(Check.direct(claims.rows[1], no_initial, &relations)[4].isZero());
    const no_final = RootParameters(QM31).fromPublic(initial_root, null);
    try std.testing.expect(Check.direct(claims.rows[0], no_final, &relations)[3].isZero());
    try std.testing.expect(!Check.direct(claims.rows[1], no_final, &relations)[4].isZero());

    // Padding and multiplicity-zero rows never trip either binding.
    var main = [_]QM31{zero} ** 8;
    main[7] = base(initial_root ^ 1);
    const padding = evaluate(main, zero, zero, .{zero} ** N_SUMS, .{zero} ** N_SUMS, .{zero} ** N_SUMS, &relations, roots);
    try std.testing.expect(padding[N_SUMS + 3].isZero());
    try std.testing.expect(padding[N_SUMS + 4].isZero());
}
