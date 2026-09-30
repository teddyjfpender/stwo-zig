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
const work_pool = @import("../work_pool.zig");

pub const Fraction = struct {
    numerator: QM31,
    denominator: QM31,
};

pub const Output = struct {
    columns: []prover_pcs.ColumnEvaluation,
    claimed_sum: QM31,
};

/// Rows are produced in fixed-size chunks on the global work pool (serially
/// without one). A chunk fills its fractions, batch-inverts them and writes
/// its running sums straight into the output columns, so the only full-size
/// allocations are the columns themselves: no `rows x secure_columns`
/// fraction table. Inversion and field addition are exact, so the chunking
/// and the order the per-chunk claimed sums are combined in cannot change a
/// value.
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
    return buildReusing(allocator, log_size, secure_columns, &.{}, context, fillRow);
}

/// `build` whose first `reuse.len` output columns are written into `reuse`'s
/// buffers (each `2^log_size` values from `allocator`) instead of fresh
/// ones; the output owns them on success and the caller keeps them on
/// error. A chunk reads all its rows (`fillRow`) before it writes any, and
/// chunks are disjoint row runs, so `reuse` may be the very columns
/// `fillRow` reads provided `fillRow(r)` reads only row `r` of them: the
/// values written are the same as `build`'s.
pub fn buildReusing(
    allocator: std.mem.Allocator,
    log_size: u32,
    secure_columns: usize,
    reuse: []const []M31,
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
    if (reuse.len > secure_columns * 4) return error.InvalidPreparedGeometry;
    for (reuse) |buffer| if (buffer.len != row_count) return error.InvalidPreparedGeometry;

    const columns = try allocator.alloc(
        prover_pcs.ColumnEvaluation,
        secure_columns * 4,
    );
    var initialized: usize = reuse.len;
    errdefer {
        for (columns[reuse.len..initialized]) |column| allocator.free(column.values);
        allocator.free(columns);
    }
    for (columns[0..reuse.len], reuse) |*column, buffer| column.* = .{ .log_size = log_size, .values = buffer };
    for (columns[reuse.len..]) |*column| {
        column.* = .{
            .log_size = log_size,
            .values = try allocator.alloc(M31, row_count),
        };
        initialized += 1;
    }

    const Context = @TypeOf(context);
    const Worker = struct {
        context: Context,
        columns: []prover_pcs.ColumnEvaluation,
        secure_columns: usize,
        chunk_rows: usize,
        row_count: usize,
        cursor: *std.atomic.Value(usize),
        fractions: []Fraction,
        denominators: []QM31,
        inverses: []QM31,
        sum: QM31 = QM31.zero(),
        failure: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runChunks() catch |err| {
                self.failure = err;
            };
        }

        fn runChunks(self: *@This()) !void {
            while (true) {
                const first = self.cursor.fetchAdd(self.chunk_rows, .monotonic);
                if (first >= self.row_count) return;
                try self.chunk(first, @min(first + self.chunk_rows, self.row_count));
            }
        }

        fn chunk(self: *@This(), first: usize, end: usize) !void {
            const n = (end - first) * self.secure_columns;
            const fractions = self.fractions[0..n];
            for (first..end) |row| {
                const row_fractions = fractions[(row - first) * self.secure_columns ..][0..self.secure_columns];
                try fillRow(self.context, row, row_fractions);
                for (row_fractions) |fraction| {
                    if (fraction.denominator.isZero()) return error.DegenerateDenominator;
                }
            }
            for (fractions, self.denominators[0..n]) |fraction, *denominator| denominator.* = fraction.denominator;
            try fields.batchInverseInPlace(QM31, self.denominators[0..n], self.inverses[0..n]);
            for (first..end) |row| {
                var cumulative = QM31.zero();
                const row_fractions = fractions[(row - first) * self.secure_columns ..][0..self.secure_columns];
                const row_inverses = self.inverses[(row - first) * self.secure_columns ..][0..self.secure_columns];
                for (row_fractions, row_inverses, 0..) |fraction, inverse, batch| {
                    cumulative = cumulative.add(fraction.numerator.mul(inverse));
                    const coordinates = cumulative.toM31Array();
                    for (coordinates, 0..) |coordinate, index| {
                        @constCast(self.columns[4 * batch + index].values)[row] = coordinate;
                    }
                }
                self.sum = self.sum.add(cumulative);
            }
        }
    };

    const chunk_rows: usize = @min(row_count, 1 << 12);
    const chunk_count = row_count / chunk_rows;
    const maybe_pool = work_pool.getGlobalPool();
    const worker_count: usize = if (maybe_pool) |pool| @max(1, @min(pool.workerCount(), chunk_count)) else 1;
    const scratch_len = chunk_rows * secure_columns;
    const fractions = try allocator.alloc(Fraction, scratch_len * worker_count);
    defer allocator.free(fractions);
    const scalars = try allocator.alloc(QM31, 2 * scratch_len * worker_count);
    defer allocator.free(scalars);
    const workers = try allocator.alloc(Worker, worker_count);
    defer allocator.free(workers);
    var cursor = std.atomic.Value(usize).init(0);
    for (workers, 0..) |*worker, index| worker.* = .{
        .context = context,
        .columns = columns,
        .secure_columns = secure_columns,
        .chunk_rows = chunk_rows,
        .row_count = row_count,
        .cursor = &cursor,
        .fractions = fractions[index * scratch_len ..][0..scratch_len],
        .denominators = scalars[2 * index * scratch_len ..][0..scratch_len],
        .inverses = scalars[(2 * index + 1) * scratch_len ..][0..scratch_len],
    };
    if (maybe_pool) |pool| {
        var group: std.Thread.WaitGroup = .{};
        for (workers[1..]) |*worker| pool.spawnWg(&group, Worker.run, .{worker});
        workers[0].run();
        group.wait();
    } else workers[0].run();
    var claimed_sum = QM31.zero();
    for (workers) |worker| {
        if (worker.failure) |err| return err;
        claimed_sum = claimed_sum.add(worker.sum);
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

test "LogUp builder writing into the columns it reads matches a fresh build" {
    // Rows span several chunks so reads and writes interleave across workers.
    const log_size: u32 = 14;
    const row_count = @as(usize, 1) << log_size;
    const Context = struct {
        inputs: []const []M31,

        fn fill(self: @This(), row: usize, out: []Fraction) !void {
            for (out, 0..) |*fraction, index| {
                const a = self.inputs[2 * index][row];
                const b = self.inputs[2 * index + 1][row];
                fraction.* = .{
                    .numerator = QM31.fromBase(a),
                    .denominator = QM31.fromU32Unchecked(b.v, a.v, 7, @intCast(row % 13)).add(QM31.one()),
                };
            }
        }
    };
    const allocator = std.testing.allocator;
    var inputs: [6][]M31 = undefined;
    for (&inputs, 0..) |*column, index| {
        column.* = try allocator.alloc(M31, row_count);
        for (column.*, 0..) |*value, row| value.* = M31.fromU64((row * 2654435761 + index * 40503) % 2147483647);
    }
    const expected = try build(allocator, log_size, 3, Context{ .inputs = &inputs }, Context.fill);
    defer {
        for (expected.columns) |column| allocator.free(column.values);
        allocator.free(expected.columns);
    }
    // The six input columns become the first six of twelve outputs.
    const actual = try buildReusing(allocator, log_size, 3, &inputs, Context{ .inputs = &inputs }, Context.fill);
    defer {
        for (actual.columns) |column| allocator.free(column.values);
        allocator.free(actual.columns);
    }
    try std.testing.expect(actual.claimed_sum.eql(expected.claimed_sum));
    for (actual.columns[0..inputs.len], inputs) |column, input| try std.testing.expectEqual(input.ptr, column.values.ptr);
    for (actual.columns, expected.columns) |a, e| try std.testing.expectEqualSlices(M31, e.values, a.values);
}
