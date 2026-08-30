//! Singleton LogUp interaction columns for lookup multiplicity tables.

const std = @import("std");
const fields = @import("stwo_core").fields;
const core_utils = @import("stwo_core").utils;
const work_pool = @import("stwo_prover_engine").work_pool;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const infra = @import("../../../infra_trace.zig");
const entry = @import("../entry.zig");
const logup = @import("../../logup.zig");
const relations_mod = @import("../../relation_challenges.zig");
const counter_mod = @import("counter.zig");
const schema = @import("schema.zig");

pub const N_COLUMNS: usize = 4;
pub const CHUNK_ROWS: usize = 4096;

pub const Result = struct {
    columns: [N_COLUMNS][]M31,
    claim: QM31,

    /// Moves the current cumulative columns out for commitment. The claim
    /// remains available after the transfer.
    pub fn takeColumns(self: *Result) [N_COLUMNS][]M31 {
        const result = self.columns;
        self.columns = .{&.{}} ** N_COLUMNS;
        return result;
    }

    pub fn deinit(self: *Result, allocator: std.mem.Allocator) void {
        freeColumns(allocator, &self.columns);
        self.* = undefined;
    }
};

pub fn tableEntry(
    kind: schema.Kind,
    tuple: schema.Tuple,
    signed_multiplicity: M31,
) entry.Entry {
    var result = entry.Entry{
        .domain = schema.domain(kind),
        .numerator = QM31.fromBase(signed_multiplicity).neg(),
        .arity = @intCast(tuple.len),
    };
    for (tuple.slice(), result.values[0..tuple.len]) |value, *dst| dst.* = QM31.fromBase(value);
    return result;
}

pub fn rowPair(
    kind: schema.Kind,
    tuple: schema.Tuple,
    signed_multiplicity: M31,
    relations: *const relations_mod.Relations,
) !logup.RowPair {
    const relation_entry = tableEntry(kind, tuple, signed_multiplicity);
    return logup.RowPair.single(relation_entry.numerator, try relation_entry.denominator(relations));
}

/// Combines a generated table tuple without promoting its base-field values to
/// secure-field elements. The schema owns the fixed arity, so production table
/// generation pays one `QM31.mulM31` per coordinate instead of a general
/// `QM31.mul` while retaining the public `Entry` path as an independent oracle.
fn denominatorBase(
    kind: schema.Kind,
    tuple: schema.Tuple,
    relations: *const relations_mod.Relations,
) !QM31 {
    return denominatorBaseValues(kind, tuple.slice(), relations);
}

fn denominatorBaseValues(
    kind: schema.Kind,
    values: []const M31,
    relations: *const relations_mod.Relations,
) !QM31 {
    if (values.len != schema.arity(kind)) return error.InvalidArity;
    return switch (kind) {
        .bitwise => relations.bitwise.combineBase(values[0..4].*),
        .range_check_20 => relations.range_check_20.combineBase(values[0..1].*),
        .range_check_8_11 => relations.range_check_8_11.combineBase(values[0..2].*),
        .range_check_8_8_4 => relations.range_check_8_8_4.combineBase(values[0..3].*),
        .range_check_8_8 => relations.range_check_8_8.combineBase(values[0..2].*),
        .range_check_m31 => relations.range_check_m31.combineBase(values[0..2].*),
    };
}

/// Generate one secure singleton cumulative column as four committed M31
/// columns. Denominators are batch-inverted because tables reach 2^20 rows.
pub fn generate(
    allocator: std.mem.Allocator,
    counter: *const counter_mod.Counter,
    relations: *const relations_mod.Relations,
) !Result {
    const size = schema.size(counter.kind);
    if (counter.values.len != size) return error.InvalidTraceShape;
    var columns = try allocateColumns(allocator, size);
    errdefer freeColumns(allocator, &columns);
    const chunk_capacity = @min(size, CHUNK_ROWS);
    const denominators = try allocator.alloc(QM31, chunk_capacity);
    defer allocator.free(denominators);
    const inverses = try allocator.alloc(QM31, chunk_capacity);
    defer allocator.free(inverses);
    const claim = try generateInto(
        counter,
        relations,
        &columns,
        denominators,
        inverses,
    );
    return .{ .columns = columns, .claim = claim };
}

/// Allocation-free singleton interaction writer. All geometry, alias, and
/// denominator checks complete before the first destination store, so a
/// rejected challenge or malformed workspace leaves Tree 2 untouched.
/// Exactly two `CHUNK_ROWS` QM31 scratch spans are reused for the full table.
pub fn generateInto(
    counter: *const counter_mod.Counter,
    relations: *const relations_mod.Relations,
    columns: *[N_COLUMNS][]M31,
    denominators: []QM31,
    inverses: []QM31,
) !QM31 {
    const size = schema.size(counter.kind);
    const scratch_len = @min(size, CHUNK_ROWS);
    if (counter.values.len != size or
        denominators.len < scratch_len or inverses.len < scratch_len)
    {
        return error.InvalidTraceShape;
    }
    try preflightIntoAliases(
        counter,
        relations,
        columns,
        denominators[0..scratch_len],
        inverses[0..scratch_len],
        size,
    );

    // A full read-only pass is intentional: batch inversion is the only
    // data-dependent failure after structural validation. Proving every
    // denominator non-zero here makes all following chunk writes infallible.
    for (0..size) |row| {
        const tuple = try schema.tupleAt(counter.kind, row);
        if ((try denominatorBase(counter.kind, tuple, relations)).isZero())
            return error.DivisionByZero;
    }

    const log_size = schema.logSize(counter.kind);
    var accumulator = QM31.zero();
    var row_start: usize = 0;
    while (row_start < size) {
        const chunk_len = @min(CHUNK_ROWS, size - row_start);
        for (denominators[0..chunk_len], 0..) |*denominator, local_row| {
            const row = row_start + local_row;
            const tuple = schema.tupleAt(counter.kind, row) catch unreachable;
            denominator.* = denominatorBase(counter.kind, tuple, relations) catch unreachable;
        }
        fields.batchInverseInPlace(
            QM31,
            denominators[0..chunk_len],
            inverses[0..chunk_len],
        ) catch unreachable;
        for (
            inverses[0..chunk_len],
            counter.values[row_start .. row_start + chunk_len],
            0..,
        ) |denominator_inverse, multiplicity, local_row| {
            const row = row_start + local_row;
            accumulator = accumulator.add(
                denominator_inverse.mulM31(multiplicity.neg()),
            );
            const current = accumulator.toM31Array();
            const dst = core_utils.bitReverseIndex(
                core_utils.cosetIndexToCircleDomainIndex(row, log_size),
                log_size,
            );
            for (0..N_COLUMNS) |coordinate|
                columns[coordinate][dst] = current[coordinate];
        }
        row_start += chunk_len;
    }
    return accumulator;
}

const AddressRange = struct {
    start: usize,
    end: usize,

    fn overlaps(self: AddressRange, other: AddressRange) bool {
        return self.start < other.end and other.start < self.end;
    }
};

fn byteRange(comptime T: type, values: []const T) !AddressRange {
    const start = @intFromPtr(values.ptr);
    const bytes = std.math.mul(usize, values.len, @sizeOf(T)) catch
        return error.InvalidTraceShape;
    const end = std.math.add(usize, start, bytes) catch
        return error.InvalidTraceShape;
    return .{ .start = start, .end = end };
}

fn objectRange(value: anytype) !AddressRange {
    return byteRange(u8, std.mem.asBytes(value));
}

fn preflightIntoAliases(
    counter: *const counter_mod.Counter,
    relations: *const relations_mod.Relations,
    columns: *const [N_COLUMNS][]M31,
    denominators: []QM31,
    inverses: []QM31,
    size: usize,
) !void {
    const counter_header = try objectRange(counter);
    const relation_header = try objectRange(relations);
    const counter_values = try byteRange(M31, counter.values);
    const denominator_range = try byteRange(QM31, denominators);
    const inverse_range = try byteRange(QM31, inverses);
    if (denominator_range.overlaps(inverse_range) or
        denominator_range.overlaps(counter_header) or
        denominator_range.overlaps(counter_values) or
        denominator_range.overlaps(relation_header) or
        inverse_range.overlaps(counter_header) or
        inverse_range.overlaps(counter_values) or
        inverse_range.overlaps(relation_header))
    {
        return error.AliasedInput;
    }
    var ranges: [N_COLUMNS]AddressRange = undefined;
    for (columns, 0..) |column, index| {
        if (column.len != size) return error.InvalidTraceShape;
        ranges[index] = try byteRange(M31, column);
        if (ranges[index].overlaps(counter_header) or
            ranges[index].overlaps(counter_values) or
            ranges[index].overlaps(relation_header) or
            ranges[index].overlaps(denominator_range) or
            ranges[index].overlaps(inverse_range))
        {
            return error.AliasedInput;
        }
        for (ranges[0..index]) |previous|
            if (ranges[index].overlaps(previous))
                return error.AliasedDestination;
    }
}

/// Work-efficient two-level inclusive scan. Chunks derive and invert their
/// row terms independently, publish a local prefix and total, then a tiny
/// serial scan assigns chunk offsets for a disjoint parallel fix-up pass.
pub fn generateParallel(
    allocator: std.mem.Allocator,
    counter: *const counter_mod.Counter,
    relations: *const relations_mod.Relations,
    pool: *work_pool.WorkPool,
) !Result {
    const size = schema.size(counter.kind);
    if (counter.values.len != size) return error.InvalidTraceShape;
    var columns = try allocateColumns(allocator, size);
    errdefer freeColumns(allocator, &columns);
    const table = try infra.BitReversalTable.init(allocator, schema.logSize(counter.kind));
    defer table.deinit(allocator);

    const chunk_count = std.math.divCeil(usize, size, CHUNK_ROWS) catch unreachable;
    const chunks = try allocator.alloc(TableChunk, chunk_count);
    defer allocator.free(chunks);
    for (chunks, 0..) |*chunk, index| {
        const row_start = index * CHUNK_ROWS;
        chunk.* = .{
            .allocator = allocator,
            .counter = counter,
            .relations = relations,
            .table = table,
            .columns = &columns,
            .row_start = row_start,
            .row_end = @min(size, row_start + CHUNK_ROWS),
        };
    }

    var wait_group = std.Thread.WaitGroup{};
    for (chunks[1..]) |*chunk| pool.spawnWg(&wait_group, TableChunk.generate, .{chunk});
    TableChunk.generate(&chunks[0]);
    wait_group.wait();
    for (chunks) |chunk| if (chunk.err) |err| return err;

    var claim = QM31.zero();
    for (chunks) |*chunk| {
        chunk.offset = claim;
        claim = claim.add(chunk.total);
    }

    wait_group = .{};
    for (chunks[1..]) |*chunk| pool.spawnWg(&wait_group, TableChunk.addOffset, .{chunk});
    TableChunk.addOffset(&chunks[0]);
    wait_group.wait();
    return .{ .columns = columns, .claim = claim };
}

const TableChunk = struct {
    allocator: std.mem.Allocator,
    counter: *const counter_mod.Counter,
    relations: *const relations_mod.Relations,
    table: infra.BitReversalTable,
    columns: *[N_COLUMNS][]M31,
    row_start: usize,
    row_end: usize,
    total: QM31 = QM31.zero(),
    offset: QM31 = QM31.zero(),
    err: ?anyerror = null,

    fn generate(self: *@This()) void {
        self.generateFallible() catch |err| {
            self.err = err;
        };
    }

    fn generateFallible(self: *@This()) !void {
        const chunk_len = self.row_end - self.row_start;
        const denominators = try self.allocator.alloc(QM31, chunk_len);
        defer self.allocator.free(denominators);
        const inverses = try self.allocator.alloc(QM31, chunk_len);
        defer self.allocator.free(inverses);
        for (denominators, 0..) |*denominator, local_row| {
            const row = self.row_start + local_row;
            const tuple = try schema.tupleAt(self.counter.kind, row);
            denominator.* = try denominatorBase(self.counter.kind, tuple, self.relations);
        }
        try fields.batchInverseInPlace(QM31, denominators, inverses);

        var accumulator = QM31.zero();
        for (inverses, self.counter.values[self.row_start..self.row_end], 0..) |denominator_inverse, multiplicity, local_row| {
            accumulator = accumulator.add(
                denominator_inverse.mulM31(multiplicity.neg()),
            );
            const current = accumulator.toM31Array();
            const dst = self.table.map(self.row_start + local_row);
            for (0..N_COLUMNS) |coordinate| self.columns[coordinate][dst] = current[coordinate];
        }
        self.total = accumulator;
    }

    fn addOffset(self: *@This()) void {
        if (self.offset.isZero()) return;
        for (self.row_start..self.row_end) |row| {
            const dst = self.table.map(row);
            const local = QM31.fromM31(
                self.columns[0][dst],
                self.columns[1][dst],
                self.columns[2][dst],
                self.columns[3][dst],
            ).add(self.offset).toM31Array();
            for (0..N_COLUMNS) |coordinate| self.columns[coordinate][dst] = local[coordinate];
        }
    }
};

/// Shared on-domain/OODS table AIR identity.
pub fn evaluate(
    kind: schema.Kind,
    tuple: []const QM31,
    signed_multiplicity: QM31,
    current: QM31,
    previous: QM31,
    is_first: QM31,
    claim: QM31,
    relations: *const relations_mod.Relations,
) !QM31 {
    return evaluateGeneric(
        QM31,
        kind,
        tuple,
        signed_multiplicity,
        current,
        previous,
        is_first,
        claim,
        relations,
    );
}

/// Prepared-domain evaluator for table tuples that remain in the base field.
/// The LogUp transition is exactly `evaluate`; only relation combination uses
/// QM31-by-M31 products instead of first promoting every tuple coordinate.
pub fn evaluateBaseTuple(
    kind: schema.Kind,
    tuple: []const M31,
    signed_multiplicity: M31,
    current: QM31,
    previous: QM31,
    is_first: M31,
    claim: QM31,
    relations: *const relations_mod.Relations,
) !QM31 {
    return logup.pairConstraint(
        current,
        previous,
        QM31.fromBase(is_first),
        claim,
        logup.RowPair.single(
            QM31.fromBase(signed_multiplicity).neg(),
            try denominatorBaseValues(kind, tuple, relations),
        ),
    );
}

pub fn evaluateGeneric(
    comptime S: type,
    kind: schema.Kind,
    tuple: []const S,
    signed_multiplicity: S,
    current: S,
    previous: S,
    is_first: S,
    claim: S,
    relations: anytype,
) !S {
    if (tuple.len != schema.arity(kind)) return error.InvalidTraceShape;
    var relation_entry = entry.Builder(S).Entry{
        .domain = schema.domain(kind),
        .numerator = signed_multiplicity.neg(),
        .arity = @intCast(tuple.len),
    };
    @memcpy(relation_entry.values[0..tuple.len], tuple);
    return logup.pairConstraintGeneric(
        S,
        current,
        previous,
        is_first,
        claim,
        logup.RowPairFor(S).single(
            relation_entry.numerator,
            try relation_entry.denominatorWith(relations),
        ),
    );
}

fn allocateColumns(allocator: std.mem.Allocator, len: usize) ![N_COLUMNS][]M31 {
    var result: [N_COLUMNS][]M31 = undefined;
    var initialized: usize = 0;
    errdefer for (result[0..initialized]) |column| allocator.free(column);
    for (&result) |*column| {
        column.* = try allocator.alloc(M31, len);
        initialized += 1;
    }
    return result;
}

fn freeColumns(allocator: std.mem.Allocator, columns: []const []M31) void {
    for (columns) |column| {
        if (column.len != 0) allocator.free(column);
    }
}

fn generateFullDomainReference(
    allocator: std.mem.Allocator,
    counter: *const counter_mod.Counter,
    relations: *const relations_mod.Relations,
) !Result {
    const size = schema.size(counter.kind);
    if (counter.values.len != size) return error.InvalidTraceShape;
    const denominators = try allocator.alloc(QM31, size);
    defer allocator.free(denominators);
    for (denominators, 0..) |*denominator, row| {
        const tuple = try schema.tupleAt(counter.kind, row);
        const relation_entry = tableEntry(counter.kind, tuple, counter.values[row]);
        denominator.* = try relation_entry.denominator(relations);
    }
    const inverses = try fields.batchInverse(QM31, allocator, denominators);
    defer allocator.free(inverses);
    const sums = try allocator.alloc(QM31, size);
    defer allocator.free(sums);
    var accumulator = QM31.zero();
    for (sums, inverses, counter.values) |*sum, denominator_inverse, multiplicity| {
        accumulator = accumulator.add(denominator_inverse.mulM31(multiplicity.neg()));
        sum.* = accumulator;
    }

    var columns = try allocateColumns(allocator, size);
    errdefer freeColumns(allocator, &columns);
    const table = try infra.BitReversalTable.init(allocator, schema.logSize(counter.kind));
    defer table.deinit(allocator);
    for (0..size) |row| {
        const dst = table.map(row);
        const current = sums[row].toM31Array();
        for (0..N_COLUMNS) |coordinate| {
            columns[coordinate][dst] = current[coordinate];
        }
    }
    return .{ .columns = columns, .claim = accumulator };
}

fn expectEqualResults(expected: *const Result, actual: *const Result) !void {
    try std.testing.expect(expected.claim.eql(actual.claim));
    for (0..N_COLUMNS) |coordinate| {
        try std.testing.expectEqual(expected.columns[coordinate].len, actual.columns[coordinate].len);
        try std.testing.expect(std.mem.eql(
            u8,
            std.mem.sliceAsBytes(expected.columns[coordinate]),
            std.mem.sliceAsBytes(actual.columns[coordinate]),
        ));
    }
}

fn sourceTerm(
    kind: schema.Kind,
    values: []const QM31,
    numerator: QM31,
    relations: *const relations_mod.Relations,
) !QM31 {
    var relation_entry = entry.Entry{
        .domain = schema.domain(kind),
        .numerator = numerator,
        .arity = @intCast(values.len),
    };
    @memcpy(relation_entry.values[0..values.len], values);
    return numerator.mul(try (try relation_entry.denominator(relations)).inv());
}

test "base table denominator matches canonical entry for every schema" {
    const relations = relations_mod.Relations.dummy();
    for (0..schema.KIND_COUNT) |index| {
        const kind: schema.Kind = @enumFromInt(index);
        for ([_]usize{ 0, 17, schema.size(kind) - 1 }) |row| {
            const tuple = try schema.tupleAt(kind, row);
            const canonical = tableEntry(kind, tuple, M31.one());
            try std.testing.expect(
                (try denominatorBase(kind, tuple, &relations)).eql(
                    try canonical.denominator(&relations),
                ),
            );
        }
        var malformed = try schema.tupleAt(kind, 0);
        malformed.len -= 1;
        try std.testing.expectError(
            error.InvalidArity,
            denominatorBase(kind, malformed, &relations),
        );

        const signed_multiplicity = M31.fromU64(19);
        const current = QM31.fromU32Unchecked(5, 7, 11, 13);
        const previous = QM31.fromU32Unchecked(17, 23, 29, 31);
        const is_first = M31.fromU64(37);
        const claim = QM31.fromU32Unchecked(41, 43, 47, 53);
        var secure: [schema.MAX_ARITY]QM31 = undefined;
        const tuple = try schema.tupleAt(kind, 17);
        for (tuple.slice(), secure[0..tuple.len]) |value, *dst| {
            dst.* = QM31.fromBase(value);
        }
        try std.testing.expect((try evaluateBaseTuple(
            kind,
            tuple.slice(),
            signed_multiplicity,
            current,
            previous,
            is_first,
            claim,
            &relations,
        )).eql(try evaluate(
            kind,
            secure[0..tuple.len],
            QM31.fromBase(signed_multiplicity),
            current,
            previous,
            QM31.fromBase(is_first),
            claim,
            &relations,
        )));
    }
}

test "table singleton balances signed source multiplicity for all six domains" {
    const relations = relations_mod.Relations.dummy();
    for (0..schema.KIND_COUNT) |index| {
        const kind: schema.Kind = @enumFromInt(index);
        const tuple = try schema.tupleAt(kind, 17);
        var secure: [schema.MAX_ARITY]QM31 = undefined;
        for (tuple.slice(), secure[0..tuple.len]) |value, *dst| dst.* = QM31.fromBase(value);
        const source = try sourceTerm(kind, secure[0..tuple.len], QM31.one().neg(), &relations);
        const table = try rowPair(kind, tuple, M31.one().neg(), &relations);
        const table_term = table.n1.mul(try table.d1.inv());
        try std.testing.expect(source.add(table_term).isZero());

        const wrong = try rowPair(kind, tuple, M31.fromU64(2).neg(), &relations);
        const wrong_term = wrong.n1.mul(try wrong.d1.inv());
        try std.testing.expect(!source.add(wrong_term).isZero());
        try std.testing.expect(!source.isZero()); // omitted table row
    }
}

test "table AIR identity rejects multiplicity, tuple, and claim mutations" {
    const relations = relations_mod.Relations.dummy();
    const kind: schema.Kind = .range_check_8_8;
    const tuple = [_]QM31{ QM31.fromBase(M31.fromU64(1)), QM31.fromBase(M31.fromU64(2)) };
    const pair = logup.RowPair.single(
        QM31.one(),
        relations.range_check_8_8.combineSecure(tuple),
    );
    const claim = pair.n1.mul(try pair.d1.inv());
    const honest = try evaluate(kind, &tuple, QM31.one().neg(), claim, claim, QM31.one(), claim, &relations);
    try std.testing.expect(honest.isZero());
    const bad_mult = try evaluate(kind, &tuple, M31QM31(2).neg(), claim, claim, QM31.one(), claim, &relations);
    try std.testing.expect(!bad_mult.isZero());
    var swapped = tuple;
    std.mem.swap(QM31, &swapped[0], &swapped[1]);
    const bad_tuple = try evaluate(kind, &swapped, QM31.one().neg(), claim, claim, QM31.one(), claim, &relations);
    try std.testing.expect(!bad_tuple.isZero());
    const bad_claim = try evaluate(kind, &tuple, QM31.one().neg(), claim, claim, QM31.one(), claim.add(QM31.one()), &relations);
    try std.testing.expect(!bad_claim.isZero());
}

test "generated singleton column closes one signed range M31 request" {
    const allocator = std.testing.allocator;
    const relations = relations_mod.Relations.dummy();
    var counter = try counter_mod.Counter.init(allocator, .range_check_m31);
    defer counter.deinit(allocator);
    const tuple = [_]QM31{ M31QM31(1), M31QM31(2) };
    try counter.registerRaw(QM31.one().neg(), &tuple);
    var generated = try generate(allocator, &counter, &relations);
    defer generated.deinit(allocator);

    const source = try sourceTerm(.range_check_m31, &tuple, QM31.one().neg(), &relations);
    try std.testing.expect(source.add(generated.claim).isZero());
    const table = try infra.BitReversalTable.init(allocator, schema.logSize(.range_check_m31));
    defer table.deinit(allocator);
    const last = table.map(schema.size(.range_check_m31) - 1);
    const claim_from_column = QM31.fromM31(
        generated.columns[0][last],
        generated.columns[1][last],
        generated.columns[2][last],
        generated.columns[3][last],
    );
    try std.testing.expect(claim_from_column.eql(generated.claim));

    const owned_columns = generated.takeColumns();
    defer freeColumns(allocator, &owned_columns);
    for (generated.columns) |column| try std.testing.expectEqual(@as(usize, 0), column.len);
    for (owned_columns) |column| {
        try std.testing.expectEqual(schema.size(.range_check_m31), column.len);
    }
    try std.testing.expect(generated.claim.eql(claim_from_column));
}

test "chunked table interaction is byte-identical across inversion boundaries" {
    const allocator = std.testing.allocator;
    const relations = relations_mod.Relations.dummy();
    var counter = try counter_mod.Counter.init(allocator, .range_check_m31);
    defer counter.deinit(allocator);
    const size = schema.size(counter.kind);
    try std.testing.expect(size > 2 * CHUNK_ROWS);
    counter.values[0] = M31.one();
    counter.values[CHUNK_ROWS - 1] = M31.fromU64(2).neg();
    counter.values[CHUNK_ROWS] = M31.fromU64(3);
    counter.values[CHUNK_ROWS + 1] = M31.fromU64(4).neg();
    counter.values[2 * CHUNK_ROWS - 1] = M31.fromU64(5);
    counter.values[2 * CHUNK_ROWS] = M31.fromU64(6).neg();
    counter.values[size - 1] = M31.fromU64(7);

    var expected = try generateFullDomainReference(allocator, &counter, &relations);
    defer expected.deinit(allocator);
    var actual = try generate(allocator, &counter, &relations);
    defer actual.deinit(allocator);
    try expectEqualResults(&expected, &actual);
}

fn generateForAllocationTest(
    allocator: std.mem.Allocator,
    counter: *const counter_mod.Counter,
    relations: *const relations_mod.Relations,
) !void {
    var generated = try generate(allocator, counter, relations);
    defer generated.deinit(allocator);
}

test "chunked table interaction rolls back every allocation failure" {
    const allocator = std.testing.allocator;
    const relations = relations_mod.Relations.dummy();
    var counter = try counter_mod.Counter.init(allocator, .range_check_m31);
    defer counter.deinit(allocator);
    counter.values[CHUNK_ROWS - 1] = M31.one();
    counter.values[CHUNK_ROWS] = M31.one().neg();
    try std.testing.checkAllAllocationFailures(
        allocator,
        generateForAllocationTest,
        .{ &counter, &relations },
    );
}

fn M31QM31(value: u32) QM31 {
    return QM31.fromBase(M31.fromU64(value));
}
