//! Memory-bounded secure-column builder for paired LogUp relations.

const std = @import("std");
const fields = @import("stwo_core").fields;
const M31 = fields.m31.M31;
const QM31 = fields.qm31.QM31;
const utils = @import("stwo_core").utils;
const prover_pcs = @import("stwo_prover_impl").pcs;

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
                columns[4 * batch + index].values[row] = coordinate;
            }
        }
        claimed_sum = claimed_sum.add(cumulative);
    }

    const shift = try claimed_sum.divM31(M31.fromU64(row_count));
    const shift_coordinates = shift.toM31Array();
    const last_base = 4 * (secure_columns - 1);
    for (0..4) |coordinate| {
        const values = columns[last_base + coordinate].values;
        for (values) |*value| value.* = value.sub(shift_coordinates[coordinate]);
        try inclusivePrefixSum(allocator, values);
    }
    return .{ .columns = columns, .claimed_sum = claimed_sum };
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
