//! Backend-neutral reference construction for Cairo lookup interaction traces.
//!
//! Relation descriptors and layout-specific source columns are borrowed from the caller. The
//! evaluator owns only O(relation columns) scratch and can therefore stream
//! rows into checkpoint digests without materializing the complete trace.

const std = @import("std");
const fields = @import("stwo_core").fields;
const m31_mod = @import("stwo_core").fields.m31;
const M31 = m31_mod.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const interaction_source = @import("interaction_source.zig");

pub const LookupColumns = interaction_source.LookupColumns;
pub const SparseColumns = interaction_source.SparseColumns;
pub const SourceView = interaction_source.SourceView;

pub const descriptor_words = 16;
pub const use_words = 7;

/// Rows evaluated per combine iteration.
///
/// Every relation term folds into a serial `acc = acc + alpha * word`
/// dependency chain whose latency, not throughput, bounds the scalar loop.
/// Four rows give four independent chains while still fitting the accumulator
/// set, the term alphas, and one cache line per source column in registers and
/// L1. Wider unrolls were measured and rejected — see the campaign note.
const combine_rows = 4;

/// Rows per output tile in the fraction-consumption pass.
///
/// The pass is column-major so a whole tile's running cumulative column stays
/// resident while every relation column is folded into it. 1,024 rows is
/// 16 KiB of QM31 accumulators.
const consume_rows = 1024;

/// One relation word of one use, with its layout dispatch already resolved.
const Term = struct {
    alpha: QM31,
    access: interaction_source.WordAccess,
};

/// One relation use, with its constant fold, term span, and multiplicity
/// reader resolved once instead of once per row.
const UsePlan = struct {
    /// `-z + alpha^0 * use[3]`, the part of the combine that never varies.
    constant: QM31,
    first_term: u32,
    term_count: u32,
    /// Every term reads a contiguous borrowed column, so the row loop needs no
    /// per-element union dispatch.
    dense_terms: bool,
    multiplicity: interaction_source.MultiplicityAccess,
    negate: bool,
};

/// One interaction column: the span of uses whose fractions it sums.
const ColumnPlan = struct {
    first_use: u32,
    use_count: u32,
};

/// Writes finished cumulative fractions of one interaction column.
///
/// The evaluator produces each column as contiguous row runs, which lets the
/// prover lower straight into committed base-field coordinate planes while
/// conformance keeps the secure column-major form.
pub const SecureSink = struct {
    destination: []QM31,
    source_rows: usize,

    pub fn emit(
        self: SecureSink,
        column: usize,
        first_row: usize,
        values: []const QM31,
    ) void {
        @memcpy(
            self.destination[column * self.source_rows + first_row ..][0..values.len],
            values,
        );
    }
};

/// Emits three of the four secure coordinates of every column directly into
/// its committed base-field plane.
///
/// The last interaction column is held in secure form because
/// `scanLastColumnInPlace` rewrites it once the claimed sum is known; it is
/// lowered afterwards by `lowerLastColumn`.
pub const CoordinateSink = struct {
    /// Four planes per interaction column, ordered `column * 4 + coordinate`.
    planes: []const []M31,
    last_column: []QM31,
    last_index: usize,

    pub fn emit(
        self: CoordinateSink,
        column: usize,
        first_row: usize,
        values: []const QM31,
    ) void {
        if (column == self.last_index) {
            @memcpy(self.last_column[first_row..][0..values.len], values);
            return;
        }
        const group = column * 4;
        const plane0 = self.planes[group][first_row..][0..values.len];
        const plane1 = self.planes[group + 1][first_row..][0..values.len];
        const plane2 = self.planes[group + 2][first_row..][0..values.len];
        const plane3 = self.planes[group + 3][first_row..][0..values.len];
        for (values, 0..) |value, index| {
            plane0[index] = value.c0.a;
            plane1[index] = value.c0.b;
            plane2[index] = value.c1.a;
            plane3[index] = value.c1.b;
        }
    }
};

/// Lowers one already-scanned secure column into its four coordinate planes.
pub fn lowerLastColumn(planes: []const []M31, values: []const QM31) void {
    for (values, 0..) |value, index| {
        planes[0][index] = value.c0.a;
        planes[1][index] = value.c0.b;
        planes[2][index] = value.c1.a;
        planes[3][index] = value.c1.b;
    }
}

pub const Error = interaction_source.Error || error{
    DivisionByZero,
    InvalidRowCount,
    InvalidTraceShape,
    OutOfMemory,
};

/// Streaming scalar reference for the relation fractions of one interaction trace.
///
/// `descriptors`, `source`, and `alpha_powers` remain caller-owned and must
/// outlive the evaluator. Each descriptor occupies 16 words and represents
/// either one fraction or the sum of two fractions.
pub const Reference = struct {
    allocator: std.mem.Allocator,
    descriptors: []const u32,
    source: SourceView,
    z: QM31,
    alpha_powers: []const QM31,
    numerators: []QM31,
    denominators: []QM31,
    denominator_prefixes: []QM31,
    terms: []Term,
    uses: []UsePlan,
    column_plans: []ColumnPlan,

    pub fn init(
        allocator: std.mem.Allocator,
        descriptors: []const u32,
        source: SourceView,
        z: QM31,
        alpha_powers: []const QM31,
    ) Error!Reference {
        try validateDescriptors(descriptors, source, alpha_powers.len);
        const columns = descriptors.len / descriptor_words;
        const numerators = try allocator.alloc(QM31, columns);
        errdefer allocator.free(numerators);
        const denominators = try allocator.alloc(QM31, columns);
        errdefer allocator.free(denominators);
        const denominator_prefixes = try allocator.alloc(QM31, columns);
        errdefer allocator.free(denominator_prefixes);
        const column_plans = try allocator.alloc(ColumnPlan, columns);
        errdefer allocator.free(column_plans);

        var use_total: usize = 0;
        var term_total: usize = 0;
        var descriptor_index: usize = 0;
        while (descriptor_index < descriptors.len) : (descriptor_index += descriptor_words) {
            const descriptor = descriptors[descriptor_index..][0..descriptor_words];
            use_total += descriptor[0];
            for (0..descriptor[0]) |use_index|
                term_total += descriptors[descriptor_index + 1 + use_index * use_words + 2] - 1;
        }
        const uses = try allocator.alloc(UsePlan, use_total);
        errdefer allocator.free(uses);
        const terms = try allocator.alloc(Term, term_total);
        errdefer allocator.free(terms);

        var use_cursor: usize = 0;
        var term_cursor: usize = 0;
        descriptor_index = 0;
        while (descriptor_index < descriptors.len) : (descriptor_index += descriptor_words) {
            const descriptor = descriptors[descriptor_index..][0..descriptor_words];
            column_plans[descriptor_index / descriptor_words] = .{
                .first_use = @intCast(use_cursor),
                .use_count = descriptor[0],
            };
            for (0..descriptor[0]) |use_index| {
                const use = descriptor[1 + use_index * use_words ..][0..use_words];
                const first_term = term_cursor;
                var dense_terms = true;
                for (1..use[2]) |word| {
                    const access = try source.resolveWord(use[0], use[1], word);
                    if (access != .dense) dense_terms = false;
                    terms[term_cursor] = .{
                        .alpha = alpha_powers[word],
                        .access = access,
                    };
                    term_cursor += 1;
                }
                uses[use_cursor] = .{
                    .constant = z.neg().add(
                        alpha_powers[0].mulM31(M31.fromCanonical(use[3])),
                    ),
                    .first_term = @intCast(first_term),
                    .term_count = @intCast(term_cursor - first_term),
                    .dense_terms = dense_terms,
                    .multiplicity = try source.resolveMultiplicity(use[4], use[5]),
                    .negate = use[6] != 0,
                };
                use_cursor += 1;
            }
        }

        return .{
            .allocator = allocator,
            .descriptors = descriptors,
            .source = source,
            .z = z,
            .alpha_powers = alpha_powers,
            .numerators = numerators,
            .denominators = denominators,
            .denominator_prefixes = denominator_prefixes,
            .terms = terms,
            .uses = uses,
            .column_plans = column_plans,
        };
    }

    pub fn deinit(self: *Reference) void {
        self.allocator.free(self.numerators);
        self.allocator.free(self.denominators);
        self.allocator.free(self.denominator_prefixes);
        self.allocator.free(self.terms);
        self.allocator.free(self.uses);
        self.allocator.free(self.column_plans);
        self.* = undefined;
    }

    pub fn columnCount(self: Reference) usize {
        return self.descriptors.len / descriptor_words;
    }

    /// Evaluates one row using one batch inversion across all relation columns.
    /// `cumulative_sums[i]` receives the sum of fractions through column `i`.
    pub fn evaluateRow(
        self: *Reference,
        row: usize,
        cumulative_sums: []QM31,
    ) Error!QM31 {
        if (row >= self.source.rows()) return Error.InvalidRow;
        if (cumulative_sums.len != self.columnCount()) return Error.InvalidTraceShape;

        var denominator_product = QM31.one();
        var descriptor_index: usize = 0;
        while (descriptor_index < self.descriptors.len) : (descriptor_index += descriptor_words) {
            const descriptor = self.descriptors[descriptor_index..][0..descriptor_words];
            const column = descriptor_index / descriptor_words;
            const a = descriptor[1..][0..use_words];
            const denominator_a = try self.combine(row, a);
            const multiplicity_a = try self.multiplicity(row, a);
            if (descriptor[0] == 2) {
                const b = descriptor[8..][0..use_words];
                const denominator_b = try self.combine(row, b);
                const multiplicity_b = try self.multiplicity(row, b);
                self.numerators[column] = denominator_a.mulM31(multiplicity_b)
                    .add(denominator_b.mulM31(multiplicity_a));
                self.denominators[column] = denominator_a.mul(denominator_b);
            } else {
                self.numerators[column] = QM31.fromBase(multiplicity_a);
                self.denominators[column] = denominator_a;
            }
            self.denominator_prefixes[column] = denominator_product;
            denominator_product = denominator_product.mul(self.denominators[column]);
        }

        var running_inverse = denominator_product.inv() catch return Error.DivisionByZero;
        var column = self.columnCount();
        while (column != 0) {
            column -= 1;
            self.numerators[column] = self.numerators[column]
                .mul(running_inverse.mul(self.denominator_prefixes[column]));
            running_inverse = running_inverse.mul(self.denominators[column]);
        }

        var total = QM31.zero();
        for (self.numerators, cumulative_sums) |fraction, *sum| {
            total = total.add(fraction);
            sum.* = total;
        }
        return total;
    }

    /// Evaluates a contiguous row range into the complete column-major secure
    /// trace allocation. Retained for conformance and the fixture oracles.
    pub fn evaluateRange(
        self: *Reference,
        first_row: usize,
        row_count: usize,
        destination: []QM31,
    ) Error!QM31 {
        const output_count = std.math.mul(usize, self.columnCount(), self.source.rows()) catch
            return Error.InvalidTraceShape;
        if (destination.len != output_count) return Error.InvalidTraceShape;
        return self.evaluateRangeInto(first_row, row_count, SecureSink{
            .destination = destination,
            .source_rows = self.source.rows(),
        });
    }

    /// Evaluates a contiguous row range with one batch inversion across every
    /// relation fraction in that range.
    ///
    /// The pipeline is use-major: each relation use resolves its layout
    /// dispatch once (`Reference.init`) and then combines whole row runs, so
    /// the inner loop is a plain contiguous load plus the already-vectorized
    /// `QM31.mulM31`/`QM31.add` pair. Consumption is column-major so finished
    /// fractions leave as contiguous runs the sink can lower in place.
    pub fn evaluateRangeInto(
        self: *Reference,
        first_row: usize,
        row_count: usize,
        sink: anytype,
    ) Error!QM31 {
        const source_rows = self.source.rows();
        const range_end = std.math.add(usize, first_row, row_count) catch
            return Error.InvalidRowCount;
        if (row_count == 0 or range_end > source_rows)
            return Error.InvalidTraceShape;

        const uses_per_row = self.uses.len;
        const fraction_count = std.math.mul(usize, uses_per_row, row_count) catch
            return Error.InvalidTraceShape;
        const denominators = try self.allocator.alloc(QM31, fraction_count);
        defer self.allocator.free(denominators);
        const inverses = try self.allocator.alloc(QM31, fraction_count);
        defer self.allocator.free(inverses);
        const multiplicities = try self.allocator.alloc(M31, fraction_count);
        defer self.allocator.free(multiplicities);

        for (self.uses, 0..) |use, use_index| {
            const span = use_index * row_count;
            try self.combineUse(
                use,
                first_row,
                denominators[span..][0..row_count],
                multiplicities[span..][0..row_count],
            );
        }
        fields.batchInverseInPlace(QM31, denominators, inverses) catch
            return Error.DivisionByZero;

        const cumulative = try self.allocator.alloc(QM31, @min(consume_rows, row_count));
        defer self.allocator.free(cumulative);

        var claimed_sum = QM31.zero();
        var tile_start: usize = 0;
        while (tile_start < row_count) : (tile_start += consume_rows) {
            const tile = @min(consume_rows, row_count - tile_start);
            const totals = cumulative[0..tile];
            @memset(totals, QM31.zero());
            for (self.column_plans, 0..) |plan, column| {
                const first = @as(usize, plan.first_use) * row_count + tile_start;
                if (plan.use_count == 2) {
                    const second = first + row_count;
                    for (totals, 0..) |*total, index| {
                        total.* = total.*
                            .add(inverses[first + index].mulM31(multiplicities[first + index]))
                            .add(inverses[second + index].mulM31(multiplicities[second + index]));
                    }
                } else {
                    for (totals, 0..) |*total, index| {
                        total.* = total.*
                            .add(inverses[first + index].mulM31(multiplicities[first + index]));
                    }
                }
                sink.emit(column, first_row + tile_start, totals);
            }
            for (totals) |total| claimed_sum = claimed_sum.add(total);
        }
        return claimed_sum;
    }

    /// Combines one relation use across a whole row run.
    ///
    /// Four rows are folded per iteration so the four `acc = acc + alpha*word`
    /// chains proceed independently. Canonicality of dense words is checked
    /// with a running lane-wise maximum instead of a per-element branch; a
    /// violation still fails the range with `NonCanonicalM31`.
    fn combineUse(
        self: *Reference,
        use: UsePlan,
        first_row: usize,
        denominators: []QM31,
        multiplicities: []M31,
    ) Error!void {
        const terms = self.terms[use.first_term..][0..use.term_count];
        var bound: m31_mod.Vec4u32 = @splat(0);
        var row: usize = 0;
        if (use.dense_terms) {
            while (row + combine_rows <= denominators.len) : (row += combine_rows) {
                var acc = [_]QM31{use.constant} ** combine_rows;
                for (terms) |term| {
                    const words = term.access.dense;
                    const lane = m31_mod.loadVec4(@ptrCast(words + first_row + row));
                    bound = @max(bound, lane);
                    inline for (0..combine_rows) |offset|
                        acc[offset] = acc[offset].add(
                            term.alpha.mulM31(M31.fromU32Unchecked(lane[offset])),
                        );
                }
                inline for (0..combine_rows) |offset|
                    denominators[row + offset] = acc[offset];
            }
        }
        while (row < denominators.len) : (row += 1) {
            var acc = use.constant;
            for (terms) |term|
                acc = acc.add(term.alpha.mulM31(try term.access.value(first_row + row)));
            denominators[row] = acc;
        }
        if (@reduce(.Max, bound) >= m31_mod.Modulus)
            return interaction_source.Error.NonCanonicalM31;

        switch (use.multiplicity) {
            .one => @memset(
                multiplicities,
                if (use.negate) M31.one().neg() else M31.one(),
            ),
            .row_enabler => |real_rows| for (multiplicities, 0..) |*value, offset| {
                const active = M31.fromCanonical(
                    @intFromBool(first_row + offset < real_rows),
                );
                value.* = if (use.negate) active.neg() else active;
            },
            else => for (multiplicities, 0..) |*value, offset| {
                const raw = try use.multiplicity.value(first_row + offset);
                value.* = if (use.negate) raw.neg() else raw;
            },
        }
    }

    fn combine(self: Reference, row: usize, use: []const u32) Error!QM31 {
        var denominator = self.z.neg();
        for (0..use[2]) |word| {
            const value = if (word == 0)
                M31.fromCanonical(use[3])
            else
                try self.source.relationWord(use[0], use[1], word, row);
            denominator = denominator.add(self.alpha_powers[word].mulM31(value));
        }
        return denominator;
    }

    fn multiplicity(self: Reference, row: usize, use: []const u32) Error!M31 {
        const value = try self.source.multiplicity(use[4], use[5], row);
        return if (use[6] == 0) value else value.neg();
    }
};

/// Converts row totals into the final logup column in place.
///
/// The scan follows Stwo's circle-domain order and removes `claimed_sum / rows`
/// at every step. The returned final prefix is zero when `claimed_sum` equals
/// the sum of the original row totals.
pub fn scanLastColumnInPlace(values: []QM31, claimed_sum: QM31) Error!QM31 {
    try validateScanRows(values.len);
    const row_count = M31.fromCanonical(@intCast(values.len));
    const row_count_inverse = row_count.inv() catch return Error.InvalidRowCount;
    const shift = claimed_sum.mulM31(row_count_inverse);
    var prefix = QM31.zero();
    for (0..values.len) |scan_index| {
        const row = circleScanRowUnchecked(values.len, scan_index);
        prefix = prefix.add(values[row]).sub(shift);
        values[row] = prefix;
    }
    return prefix;
}

/// Maps a scan ordinal to the bit-reversed circle-domain row it visits.
pub fn circleScanRow(rows: usize, scan_index: usize) Error!usize {
    try validateScanRows(rows);
    if (scan_index >= rows) return Error.InvalidRow;
    return circleScanRowUnchecked(rows, scan_index);
}

fn validateDescriptors(
    descriptors: []const u32,
    source: SourceView,
    alpha_power_count: usize,
) Error!void {
    if (descriptors.len == 0 or descriptors.len % descriptor_words != 0)
        return Error.InvalidDescriptor;
    var descriptor_index: usize = 0;
    while (descriptor_index < descriptors.len) : (descriptor_index += descriptor_words) {
        const descriptor = descriptors[descriptor_index..][0..descriptor_words];
        if (descriptor[0] < 1 or descriptor[0] > 2) return Error.InvalidDescriptor;
        for (0..descriptor[0]) |use_index| {
            const use = descriptor[1 + use_index * use_words ..][0..use_words];
            try source.validateUse(use, alpha_power_count);
        }
    }
}

fn validateScanRows(rows: usize) Error!void {
    if (rows == 0 or !std.math.isPowerOfTwo(rows) or rows >= m31_mod.Modulus or
        rows > std.math.maxInt(u32))
        return Error.InvalidRowCount;
}

fn circleScanRowUnchecked(rows: usize, scan_index: usize) usize {
    const circle_index = if ((scan_index & 1) == 0)
        scan_index / 2
    else
        rows - 1 - scan_index / 2;
    const log_rows = std.math.log2_int(u32, @intCast(rows));
    return @bitReverse(@as(u32, @intCast(circle_index))) >>
        @intCast(@as(u32, 32) - @as(u32, log_rows));
}

fn base(value: u32) QM31 {
    return QM31.fromBase(M31.fromCanonical(value));
}

fn singleDescriptor(
    relation_id: u32,
    source_start: u32,
    relation_words: u32,
    multiplicity_column: ?u32,
    negate: bool,
) [descriptor_words]u32 {
    var descriptor = [_]u32{0} ** descriptor_words;
    descriptor[0] = 1;
    descriptor[1] = 0;
    descriptor[2] = source_start;
    descriptor[3] = relation_words;
    descriptor[4] = relation_id;
    descriptor[5] = if (multiplicity_column == null) 0 else 2;
    descriptor[6] = multiplicity_column orelse 0;
    descriptor[7] = @intFromBool(negate);
    return descriptor;
}

test "Cairo interaction reference evaluates a dynamic single relation" {
    const source_words = [_]u32{ 99, 98, 2, 3 };
    const source = try LookupColumns.init(&source_words, 2);
    const alpha_powers = [_]QM31{
        QM31.fromU32Unchecked(2, 3, 5, 7),
        QM31.fromU32Unchecked(11, 13, 17, 19),
    };
    const z = QM31.fromU32Unchecked(23, 29, 31, 37);
    const descriptor = singleDescriptor(9, 0, 2, 1, false);
    var reference = try Reference.init(
        std.testing.allocator,
        &descriptor,
        try SourceView.lookupWords(source, 2),
        z,
        &alpha_powers,
    );
    defer reference.deinit();

    var cumulative: [1]QM31 = undefined;
    const actual = try reference.evaluateRow(0, &cumulative);
    const denominator = z.neg()
        .add(alpha_powers[0].mulM31(M31.fromCanonical(9)))
        .add(alpha_powers[1].mulM31(M31.fromCanonical(2)));
    const expected = try base(2).div(denominator);
    try std.testing.expect(QM31.eql(expected, actual));
    try std.testing.expect(QM31.eql(expected, cumulative[0]));
}

test "Cairo interaction reference batches paired fractions and cumulative columns" {
    const source_words = [_]u32{ 90, 91, 4, 5, 6, 7 };
    const source = try LookupColumns.init(&source_words, 2);
    const alpha_powers = [_]QM31{ base(3), base(11) };
    const z = base(101);
    const first = singleDescriptor(13, 0, 1, null, false);
    var second = [_]u32{0} ** descriptor_words;
    second[0] = 2;
    second[1..8].* = .{ 0, 0, 2, 17, 2, 1, 0 };
    second[8..15].* = .{ 0, 1, 2, 19, 2, 2, 1 };
    var descriptors: [descriptor_words * 2]u32 = undefined;
    descriptors[0..descriptor_words].* = first;
    descriptors[descriptor_words..].* = second;
    var reference = try Reference.init(
        std.testing.allocator,
        &descriptors,
        try SourceView.lookupWords(source, 2),
        z,
        &alpha_powers,
    );
    defer reference.deinit();

    var cumulative: [2]QM31 = undefined;
    const actual = try reference.evaluateRow(0, &cumulative);
    const d0 = z.neg().add(alpha_powers[0].mulM31(M31.fromCanonical(13)));
    const d1 = z.neg().add(alpha_powers[0].mulM31(M31.fromCanonical(17)))
        .add(alpha_powers[1].mulM31(M31.fromCanonical(4)));
    const d2 = z.neg().add(alpha_powers[0].mulM31(M31.fromCanonical(19)))
        .add(alpha_powers[1].mulM31(M31.fromCanonical(6)));
    const fraction0 = try base(1).div(d0);
    const fraction1 = (try base(4).div(d1)).add(try base(6).neg().div(d2));
    try std.testing.expect(QM31.eql(fraction0, cumulative[0]));
    try std.testing.expect(QM31.eql(fraction0.add(fraction1), cumulative[1]));
    try std.testing.expect(QM31.eql(cumulative[1], actual));

    var range_values: [4]QM31 = undefined;
    const range_sum = try reference.evaluateRange(0, 2, &range_values);
    var second_row: [2]QM31 = undefined;
    const expected_second = try reference.evaluateRow(1, &second_row);
    try std.testing.expect(QM31.eql(actual.add(expected_second), range_sum));
    try std.testing.expect(QM31.eql(cumulative[0], range_values[0]));
    try std.testing.expect(QM31.eql(second_row[0], range_values[1]));
    try std.testing.expect(QM31.eql(cumulative[1], range_values[2]));
    try std.testing.expect(QM31.eql(second_row[1], range_values[3]));
}

test "Cairo interaction reference scans the final column in circle order" {
    const expected_rows = [_]usize{ 0, 7, 4, 3, 2, 5, 6, 1 };
    for (expected_rows, 0..) |expected, scan_index|
        try std.testing.expectEqual(expected, try circleScanRow(8, scan_index));

    var values = [_]QM31{ base(1), base(2), base(3), base(4), base(5), base(6), base(7), base(12) };
    const final_prefix = try scanLastColumnInPlace(&values, base(40));
    try std.testing.expect(QM31.eql(QM31.zero(), final_prefix));
    const expected = [_]u32{ m31_mod.Modulus - 4, 0, 0, 2, 3, 1, 3, 3 };
    for (values, expected) |actual, value|
        try std.testing.expect(QM31.eql(base(value), actual));
}

test "Cairo interaction reference rejects malformed geometry and words" {
    const source_words = [_]u32{1};
    const source = try LookupColumns.init(&source_words, 1);
    const alpha_powers = [_]QM31{base(2)};
    var descriptor = singleDescriptor(3, 0, 1, null, false);
    descriptor[1] = 1;
    try std.testing.expectError(
        Error.InvalidDescriptor,
        Reference.init(
            std.testing.allocator,
            &descriptor,
            try SourceView.lookupWords(source, 1),
            base(5),
            &alpha_powers,
        ),
    );
    try std.testing.expectError(Error.InvalidRowCount, circleScanRow(3, 0));

    descriptor = singleDescriptor(3, 0, 1, 0, false);
    const bad_source_words = [_]u32{m31_mod.Modulus};
    const bad_source = try LookupColumns.init(&bad_source_words, 1);
    var reference = try Reference.init(
        std.testing.allocator,
        &descriptor,
        try SourceView.lookupWords(bad_source, 1),
        base(5),
        &alpha_powers,
    );
    defer reference.deinit();
    var cumulative: [1]QM31 = undefined;
    try std.testing.expectError(Error.NonCanonicalM31, reference.evaluateRow(0, &cumulative));
}

test "Cairo interaction reference accepts every generated relation template" {
    const relation_bundle = @import("relation_bundle.zig");
    var bundle = try relation_bundle.Bundle.readFile(
        std.testing.allocator,
        "vectors/cairo/cairo_relation_templates.bin",
    );
    defer bundle.deinit();
    const alpha_powers = [_]QM31{base(1)} ** 128;
    const rows: usize = 2;
    var trace_count: usize = 0;
    var source_kinds = [_]bool{false} ** 7;
    var multiplicity_kinds = [_]bool{false} ** 7;
    for (bundle.components) |component| {
        for (component.traces) |trace| {
            const source_column_count: usize = switch (trace.layout) {
                .lookup_words => component.lookup_words orelse return error.MissingLookupGeometry,
                .memory_address => @as(usize, trace.layout_arg) * 2,
                .memory_big, .memory_small => @as(usize, trace.layout_arg) + 1,
                .bitwise_xor_12 => trace.layout_arg,
            };
            const source_words = try std.testing.allocator.alloc(u32, source_column_count * rows);
            defer std.testing.allocator.free(source_words);
            @memset(source_words, 0);
            const sparse = try std.testing.allocator.alloc([]const u32, source_column_count);
            defer std.testing.allocator.free(sparse);
            for (sparse, 0..) |*column, column_index|
                column.* = source_words[column_index * rows ..][0..rows];
            const source: SourceView = switch (trace.layout) {
                .lookup_words => try SourceView.lookupWords(
                    try LookupColumns.init(source_words, rows),
                    rows,
                ),
                .memory_address => try SourceView.memoryAddress(
                    try SparseColumns.init(sparse, rows),
                    trace.layout_arg,
                    rows,
                ),
                .memory_big => try SourceView.memoryBig(
                    try SparseColumns.init(sparse, rows),
                    trace.layout_arg,
                    rows,
                    0,
                ),
                .memory_small => try SourceView.memorySmall(
                    try SparseColumns.init(sparse, rows),
                    trace.layout_arg,
                    rows,
                    0,
                ),
                .bitwise_xor_12 => try SourceView.bitwiseXor12(
                    try SparseColumns.init(sparse, rows),
                    trace.layout_arg,
                    rows,
                ),
            };
            try source.validateDeclaration(trace.layout, trace.layout_arg);
            var descriptor_index: usize = 0;
            while (descriptor_index < trace.descriptors.len) : (descriptor_index += descriptor_words) {
                const descriptor = trace.descriptors[descriptor_index..][0..descriptor_words];
                for (0..descriptor[0]) |use_index| {
                    const use = descriptor[1 + use_index * use_words ..][0..use_words];
                    source_kinds[use[0]] = true;
                    multiplicity_kinds[use[4]] = true;
                }
            }
            var reference = try Reference.init(
                std.testing.allocator,
                trace.descriptors,
                source,
                base(2),
                &alpha_powers,
            );
            reference.deinit();
            trace_count += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 68), trace_count);
    for (source_kinds) |covered| try std.testing.expect(covered);
    for (multiplicity_kinds) |covered| try std.testing.expect(covered);
}
