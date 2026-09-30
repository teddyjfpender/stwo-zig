//! Secure-column builder for LogUp interaction traces, with the semantics of
//! Stwo's `LogupTraceGenerator` (`crates/constraint-framework/src/prover/logup.rs`):
//! every interaction column holds, per row, the running sum of its own and all
//! earlier columns' fractions; the last column is shifted by
//! `claimed_sum / 2^log_size` and prefix-summed in coset order
//! (`finalize_last`). The fraction values, not the way a frontend combines
//! paired numerators and denominators, fix the committed bytes.

const std = @import("std");
const fields = @import("stwo_core").fields;
const M31 = fields.m31.M31;
const QM31 = fields.qm31.QM31;
const utils = @import("stwo_core").utils;
const prover_pcs = @import("../pcs/mod.zig");
const row_spans = @import("row_spans.zig");
const MAX_WORKERS = @import("../work_pool.zig").MAX_WORKERS;

pub const Fraction = struct {
    numerator: QM31,
    denominator: QM31,
};

pub const Output = struct {
    columns: []prover_pcs.ColumnEvaluation,
    claimed_sum: QM31,
};

pub fn build(
    allocator: std.mem.Allocator,
    log_size: u32,
    secure_columns: usize,
    context: anytype,
    comptime fillRow: fn (
        @TypeOf(context),
        usize,
        []Fraction,
    ) anyerror!void,
) !Output {
    if (secure_columns == 0 or log_size >= @bitSizeOf(usize))
        return error.InvalidPreparedGeometry;
    const row_count = @as(usize, 1) << @intCast(log_size);
    const fraction_count = std.math.mul(usize, row_count, secure_columns) catch
        return error.ColumnCountOverflow;
    const fractions = try allocator.alloc(Fraction, fraction_count);
    defer allocator.free(fractions);

    for (0..row_count) |row| {
        const row_fractions = try rowSlice(fractions, row, secure_columns);
        try fillRow(context, row, row_fractions);
        for (row_fractions) |fraction| {
            if (fraction.denominator.isZero()) return error.DegenerateDenominator;
        }
    }
    try invertFractions(allocator, fractions);

    const columns = try allocator.alloc(
        prover_pcs.ColumnEvaluation,
        secure_columns * 4,
    );
    var initialized: usize = 0;
    errdefer {
        for (columns[0..initialized]) |column| allocator.free(column.values);
        allocator.free(columns);
    }
    for (columns) |*column| {
        column.* = .{
            .log_size = log_size,
            .values = try allocator.alloc(M31, row_count),
        };
        initialized += 1;
    }

    var claimed_sum = QM31.zero();
    for (0..row_count) |row| {
        var cumulative = QM31.zero();
        for (try rowSlice(fractions, row, secure_columns), 0..) |fraction, batch| {
            cumulative = cumulative.add(fraction.numerator);
            const coordinates = cumulative.toM31Array();
            for (coordinates, 0..) |coordinate, index| {
                @constCast(columns[4 * batch + index].values)[row] = coordinate;
            }
        }
        claimed_sum = claimed_sum.add(cumulative);
    }

    const shift = try claimed_sum.divM31(M31.fromU64(row_count));
    const shift_coordinates = shift.toM31Array();
    const last_base = 4 * (secure_columns - 1);
    for (0..4) |coordinate| {
        const values = @constCast(columns[last_base + coordinate].values);
        for (values) |*value| value.* = value.sub(shift_coordinates[coordinate]);
        try inclusivePrefixSum(allocator, values);
    }
    return .{ .columns = columns, .claimed_sum = claimed_sum };
}

/// `build` over row spans on the work pool, without the whole-trace
/// fraction buffer: each span fills, inverts and accumulates its rows in
/// blocks. `fillRow` must be safe to call concurrently for distinct rows.
///
/// Every value is the one `build` writes: an inverse is unique whatever
/// batch computes it, the per-span claimed sums are exact field sums, and the
/// last column's coset-order prefix sum is a block scan of exact additions.
pub fn buildParallel(
    allocator: std.mem.Allocator,
    log_size: u32,
    secure_columns: usize,
    context: anytype,
    comptime fillRow: fn (
        @TypeOf(context),
        usize,
        []Fraction,
    ) anyerror!void,
) !Output {
    if (secure_columns == 0 or log_size >= @bitSizeOf(usize))
        return error.InvalidPreparedGeometry;
    const row_count = @as(usize, 1) << @intCast(log_size);
    _ = std.math.mul(usize, row_count, secure_columns) catch
        return error.ColumnCountOverflow;

    const columns = try allocator.alloc(prover_pcs.ColumnEvaluation, secure_columns * 4);
    var initialized: usize = 0;
    errdefer {
        for (columns[0..initialized]) |column| allocator.free(column.values);
        allocator.free(columns);
    }
    for (columns) |*column| {
        column.* = .{ .log_size = log_size, .values = try allocator.alloc(M31, row_count) };
        initialized += 1;
    }

    const spans = row_spans.spanCount(row_count, 1 << 12);
    const block_len = parallel_block_rows * secure_columns;
    const fractions = try allocator.alloc(Fraction, spans * block_len);
    defer allocator.free(fractions);
    const denominators = try allocator.alloc(QM31, 2 * spans * block_len);
    defer allocator.free(denominators);
    var partial_sums: [MAX_WORKERS]QM31 = undefined;

    const Fill = struct {
        context: @TypeOf(context),
        secure_columns: usize,
        columns: []prover_pcs.ColumnEvaluation,
        fractions: []Fraction,
        denominators: []QM31,
        partial_sums: *[MAX_WORKERS]QM31,

        fn span(self: @This(), index: usize, rows: row_spans.Span) anyerror!void {
            const len = parallel_block_rows * self.secure_columns;
            const block_fractions = self.fractions[index * len ..][0..len];
            const block_denominators = self.denominators[2 * index * len ..][0..len];
            const block_inverses = self.denominators[(2 * index + 1) * len ..][0..len];
            var sum = QM31.zero();
            var start = rows.start;
            while (start < rows.end) {
                const end = @min(rows.end, start + parallel_block_rows);
                const n = (end - start) * self.secure_columns;
                for (start..end, 0..) |row, local| {
                    const out = block_fractions[local * self.secure_columns ..][0..self.secure_columns];
                    try fillRow(self.context, row, out);
                    for (out) |fraction| {
                        if (fraction.denominator.isZero()) return error.DegenerateDenominator;
                    }
                }
                for (block_fractions[0..n], block_denominators[0..n]) |fraction, *denominator| denominator.* = fraction.denominator;
                try fields.batchInverseInPlace(QM31, block_denominators[0..n], block_inverses[0..n]);
                for (start..end, 0..) |row, local| {
                    var cumulative = QM31.zero();
                    for (0..self.secure_columns) |batch| {
                        const at = local * self.secure_columns + batch;
                        cumulative = cumulative.add(block_fractions[at].numerator.mul(block_inverses[at]));
                        const coordinates = cumulative.toM31Array();
                        for (coordinates, 0..) |coordinate, coordinate_index| {
                            @constCast(self.columns[4 * batch + coordinate_index].values)[row] = coordinate;
                        }
                    }
                    sum = sum.add(cumulative);
                }
                start = end;
            }
            self.partial_sums[index] = sum;
        }
    };
    try row_spans.run(spans, row_count, Fill{
        .context = context,
        .secure_columns = secure_columns,
        .columns = columns,
        .fractions = fractions,
        .denominators = denominators,
        .partial_sums = &partial_sums,
    }, Fill.span);

    var claimed_sum = QM31.zero();
    for (partial_sums[0..spans]) |partial| claimed_sum = claimed_sum.add(partial);
    const shift = try claimed_sum.divM31(M31.fromU64(row_count));
    try shiftedCosetPrefixSums(columns[4 * (secure_columns - 1) ..][0..4], log_size, shift.toM31Array());
    return .{ .columns = columns, .claimed_sum = claimed_sum };
}

const parallel_block_rows: usize = 256;

/// Row `j` of the coset order: its index in the bit-reversed circle-domain
/// order the columns are stored in (`inclusivePrefixSum`'s permutation).
inline fn cosetRowPosition(j: usize, n: usize, log_size: u32) usize {
    const circle = if (j & 1 == 0) j >> 1 else n - 1 - (j >> 1);
    return utils.bitReverseIndex(circle, log_size);
}

/// `value - shift`, then `inclusivePrefixSum`, for four columns at once:
/// each span scans its coset-order rows, then adds the exact sum of the
/// spans before it.
fn shiftedCosetPrefixSums(columns: []prover_pcs.ColumnEvaluation, log_size: u32, shift: [4]M31) !void {
    const n = @as(usize, 1) << @intCast(log_size);
    const spans = row_spans.spanCount(n, 1 << 14);
    var totals: [4][MAX_WORKERS]M31 = undefined;
    const Scan = struct {
        columns: []prover_pcs.ColumnEvaluation,
        log_size: u32,
        shift: [4]M31,
        totals: *[4][MAX_WORKERS]M31,
        offsets: bool,

        fn span(self: @This(), index: usize, rows: row_spans.Span) anyerror!void {
            const len = @as(usize, 1) << @intCast(self.log_size);
            for (self.columns, 0..) |column, coordinate| {
                const values = @constCast(column.values);
                if (!self.offsets) {
                    var sum = M31.zero();
                    for (rows.start..rows.end) |j| {
                        const at = cosetRowPosition(j, len, self.log_size);
                        sum = sum.add(values[at].sub(self.shift[coordinate]));
                        values[at] = sum;
                    }
                    self.totals[coordinate][index] = sum;
                } else if (index > 0) {
                    const offset = self.totals[coordinate][index];
                    for (rows.start..rows.end) |j| {
                        const at = cosetRowPosition(j, len, self.log_size);
                        values[at] = values[at].add(offset);
                    }
                }
            }
        }
    };
    try row_spans.run(spans, n, Scan{ .columns = columns, .log_size = log_size, .shift = shift, .totals = &totals, .offsets = false }, Scan.span);
    if (spans == 1) return;
    // Exclusive prefix of the span totals, in place.
    for (&totals) |*per_span| {
        var running = M31.zero();
        for (per_span[0..spans]) |*total| {
            const next = running.add(total.*);
            total.* = running;
            running = next;
        }
    }
    try row_spans.run(spans, n, Scan{ .columns = columns, .log_size = log_size, .shift = shift, .totals = &totals, .offsets = true }, Scan.span);
}

fn rowSlice(
    fractions: []Fraction,
    row: usize,
    secure_columns: usize,
) ![]Fraction {
    const start = std.math.mul(usize, row, secure_columns) catch
        return error.ColumnCountOverflow;
    return fractions[start .. start + secure_columns];
}

fn invertFractions(
    allocator: std.mem.Allocator,
    fractions: []Fraction,
) !void {
    const max_chunk: usize = 1 << 16;
    var start: usize = 0;
    while (start < fractions.len) {
        const end = @min(start + max_chunk, fractions.len);
        const denominators = try allocator.alloc(QM31, end - start);
        defer allocator.free(denominators);
        for (fractions[start..end], denominators) |fraction, *denominator| {
            denominator.* = fraction.denominator;
        }
        const inverses = try fields.batchInverse(QM31, allocator, denominators);
        defer allocator.free(inverses);
        for (fractions[start..end], inverses) |*fraction, inverse| {
            fraction.numerator = fraction.numerator.mul(inverse);
        }
        start = end;
    }
}

fn inclusivePrefixSum(
    allocator: std.mem.Allocator,
    values: []M31,
) !void {
    utils.bitReverse(M31, values);
    const coset = try utils.circleDomainOrderToCosetOrder(M31, allocator, values);
    defer allocator.free(coset);

    var sum = M31.zero();
    for (coset) |*value| {
        sum = sum.add(value.*);
        value.* = sum;
    }

    const circle = try utils.cosetOrderToCircleDomainOrder(M31, allocator, coset);
    defer allocator.free(circle);
    utils.bitReverse(M31, circle);
    @memcpy(values, circle);
}

test "paired LogUp builder accumulates batches and shifts the final column" {
    const Context = struct {
        fn fill(_: @This(), row: usize, out: []Fraction) !void {
            const value = M31.fromU64(row + 1);
            out[0] = .{
                .numerator = QM31.fromBase(value),
                .denominator = QM31.one(),
            };
            out[1] = .{
                .numerator = QM31.fromBase(value),
                .denominator = QM31.one(),
            };
        }
    };
    const allocator = std.testing.allocator;
    const output = try build(allocator, 4, 2, Context{}, Context.fill);
    defer {
        for (output.columns) |column| allocator.free(column.values);
        allocator.free(output.columns);
    }
    try std.testing.expectEqual(@as(usize, 8), output.columns.len);
    try std.testing.expect(output.claimed_sum.eql(QM31.fromBase(M31.fromCanonical(272))));
}

test "parallel LogUp builder writes the serial builder's columns" {
    const Context = struct {
        fn fill(_: @This(), row: usize, out: []Fraction) !void {
            for (out, 0..) |*fraction, batch| {
                const a = M31.fromU64(row * 7 + batch + 1);
                const b = M31.fromU64(row * 13 + batch * 5 + 3);
                fraction.* = .{
                    .numerator = QM31.fromM31Array(.{ a, b, a.add(b), M31.fromU64(batch) }),
                    .denominator = QM31.fromM31Array(.{ b, a, M31.fromU64(row + 2), M31.one() }),
                };
            }
        }
    };
    const allocator = std.testing.allocator;
    const work_pool = @import("../work_pool.zig");
    var pool: work_pool.WorkPool = undefined;
    try pool.initInPlace();
    defer pool.deinit();
    var binding = try work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    for ([_]u32{ 4, 9, 13, 16 }) |log_size| for ([_]usize{ 1, 3 }) |secure_columns| {
        const serial = try build(allocator, log_size, secure_columns, Context{}, Context.fill);
        defer {
            for (serial.columns) |column| allocator.free(column.values);
            allocator.free(serial.columns);
        }
        const parallel = try buildParallel(allocator, log_size, secure_columns, Context{}, Context.fill);
        defer {
            for (parallel.columns) |column| allocator.free(column.values);
            allocator.free(parallel.columns);
        }
        try std.testing.expect(serial.claimed_sum.eql(parallel.claimed_sum));
        for (serial.columns, parallel.columns) |want, got|
            try std.testing.expectEqualSlices(M31, want.values, got.values);
    };
}
