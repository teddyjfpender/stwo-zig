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

const utils = @import("stwo_core").utils;
const prover_pcs = @import("../pcs/mod.zig");
const work_pool = @import("../work_pool.zig");

/// The numerical algorithm is shared by the two admitted secure fields. The
/// legacy aliases instantiate the identical degree-four operations/order.
pub fn ForField(comptime Secure: type) type {
    if (Secure != fields.qm31.QM31 and Secure != fields.om31.OM31) @compileError("unsupported LogUp field");
    const DEGREE: usize = if (Secure == fields.qm31.QM31) 4 else 8;
    return struct {
        pub const Fraction = struct {
            numerator: Secure,
            denominator: Secure,
        };

        pub const Output = struct {
            columns: []prover_pcs.ColumnEvaluation,
            claimed_sum: Secure,
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
            _ = std.math.mul(usize, row_count, secure_columns * DEGREE) catch
                return error.ColumnCountOverflow;

            const columns = try allocator.alloc(
                prover_pcs.ColumnEvaluation,
                secure_columns * DEGREE,
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

            // Rows are independent until the final column's prefix sum: every
            // chunk fills, inverts and accumulates its own rows, and the claimed
            // sum adds the chunks' partial sums. Field inverses and sums are
            // exact, so the chunking and the thread count never change a value.
            const chunk_rows = @min(row_count, rows_per_chunk);
            const n_chunks = row_count / chunk_rows;
            const partials = try allocator.alloc(Secure, n_chunks);
            defer allocator.free(partials);
            const pool = work_pool.getGlobalPool();
            const n_workers = if (pool) |active| @min(active.workerCount(), n_chunks) else 1;

            const Shared = RowShared(@TypeOf(context), fillRow);
            var shared = Shared{
                .context = context,
                .columns = columns,
                .secure_columns = secure_columns,
                .chunk_rows = chunk_rows,
                .n_chunks = n_chunks,
                .partials = partials,
            };
            const workers = try allocator.alloc(Shared.Worker, n_workers);
            defer allocator.free(workers);
            var scratch_ready: usize = 0;
            defer for (workers[0..scratch_ready]) |*worker| worker.deinit(allocator);
            for (workers) |*worker| {
                worker.* = try Shared.Worker.init(allocator, &shared);
                scratch_ready += 1;
            }
            if (pool != null and n_workers > 1) {
                var wait_group = std.Thread.WaitGroup{};
                for (workers[1..]) |*worker| pool.?.spawnWg(&wait_group, Shared.Worker.run, .{worker});
                Shared.Worker.run(&workers[0]);
                wait_group.wait();
            } else {
                Shared.Worker.run(&workers[0]);
            }
            for (workers) |worker| if (worker.err) |err| return err;

            var claimed_sum = Secure.zero();
            for (partials) |partial| claimed_sum = claimed_sum.add(partial);

            const shift = claimed_sum.mulM31(try M31.fromU64(row_count).inv());
            const shift_coordinates = shift.toM31Array();
            const last_base = DEGREE * (secure_columns - 1);
            for (0..DEGREE) |coordinate| {
                const values = @constCast(columns[last_base + coordinate].values);
                shiftedPrefix(values, shift_coordinates[coordinate], log_size);
            }
            return .{ .columns = columns, .claimed_sum = claimed_sum };
        }

        /// Rows one worker fills and inverts as a batch.
        const rows_per_chunk: usize = 1 << 12;

        fn RowShared(
            comptime Context: type,
            comptime fillRow: fn (Context, usize, []Fraction) anyerror!void,
        ) type {
            return struct {
                const Self = @This();

                context: Context,
                columns: []prover_pcs.ColumnEvaluation,
                secure_columns: usize,
                chunk_rows: usize,
                n_chunks: usize,
                partials: []Secure,
                cursor: std.atomic.Value(usize) = .init(0),

                const Worker = struct {
                    shared: *Self,
                    fractions: []Fraction,
                    denominators: []Secure,
                    inverses: []Secure,
                    err: ?anyerror = null,

                    fn init(allocator: std.mem.Allocator, shared: *Self) !Worker {
                        const len = shared.chunk_rows * shared.secure_columns;
                        const fractions = try allocator.alloc(Fraction, len);
                        errdefer allocator.free(fractions);
                        const denominators = try allocator.alloc(Secure, len);
                        errdefer allocator.free(denominators);
                        return .{
                            .shared = shared,
                            .fractions = fractions,
                            .denominators = denominators,
                            .inverses = try allocator.alloc(Secure, len),
                        };
                    }

                    fn deinit(self: *Worker, allocator: std.mem.Allocator) void {
                        allocator.free(self.fractions);
                        allocator.free(self.denominators);
                        allocator.free(self.inverses);
                    }

                    fn run(self: *Worker) void {
                        while (self.err == null) {
                            const next = self.shared.cursor.fetchAdd(1, .monotonic);
                            if (next >= self.shared.n_chunks) return;
                            self.fillChunk(next) catch |err| {
                                self.err = err;
                            };
                        }
                    }

                    fn reduceOcticFractions(self: *Worker) !void {
                        // Keep norm scratch bounded and hot across chunks. The same
                        // temporary denominator plane then holds each numerator.
                        const pack = fields.packed_om31;
                        const group = 256;
                        const ones = [_]M31{M31.one()} ** group;
                        var scratch: [2 * group]fields.qm31.QM31 = undefined;
                        var start: usize = 0;
                        while (start < self.inverses.len) {
                            const size: usize = @min(group, self.inverses.len - start);
                            const ds = self.denominators[start..][0..size];
                            const inv = self.inverses[start..][0..size];
                            try fields.om31.invertScaledPacked(ds, inv, scratch[0 .. 2 * size], ones[0..size]);
                            for (ds, self.fractions[start..][0..size]) |*num, fraction| num.* = fraction.numerator;
                            const lanes = fields.m31.PACK_WIDTH;
                            var offset: usize = 0;
                            while (offset + lanes <= size) : (offset += lanes) {
                                const value = pack.mul(pack.loadNative(ds[offset..]), pack.loadNative(inv[offset..]));
                                pack.storeNative(inv[offset..], value);
                            }
                            for (inv[offset..], ds[offset..]) |*dst, num| dst.* = dst.mul(num);
                            start += size;
                        }
                    }

                    fn fillChunk(self: *Worker, index: usize) !void {
                        const shared = self.shared;
                        const width = shared.secure_columns;
                        const first_row = index * shared.chunk_rows;
                        for (0..shared.chunk_rows) |offset| {
                            const row_fractions = self.fractions[offset * width ..][0..width];
                            try fillRow(shared.context, first_row + offset, row_fractions);
                            for (row_fractions) |fraction| {
                                if (fraction.denominator.isZero()) return error.DegenerateDenominator;
                            }
                        }
                        for (self.fractions, self.denominators) |fraction, *denominator| denominator.* = fraction.denominator;
                        if (Secure == fields.om31.OM31) {
                            try self.reduceOcticFractions();
                        } else try fields.batchInverseInPlace(Secure, self.denominators, self.inverses);

                        var partial = Secure.zero();
                        for (0..shared.chunk_rows) |offset| {
                            const row = first_row + offset;
                            var cumulative = Secure.zero();
                            for (0..width) |batch| {
                                const at = offset * width + batch;
                                const value = if (Secure == fields.om31.OM31) self.inverses[at] else self.fractions[at].numerator.mul(self.inverses[at]);
                                cumulative = cumulative.add(value);
                                const coordinates = cumulative.toM31Array();
                                for (coordinates, 0..) |coordinate, coordinate_index| {
                                    @constCast(shared.columns[DEGREE * batch + coordinate_index].values)[row] = coordinate;
                                }
                            }
                            partial = partial.add(cumulative);
                        }
                        shared.partials[index] = partial;
                    }
                };
            };
        }
    };
}

// A coset visits circle positions i and n-1-i consecutively. Their physical
// (bit-reversed) indices are complements. Scan 128 independent coset intervals
// together so that each visit consumes contiguous cache lines on both sides.
fn shiftedPrefix(values: []M31, shift: M31, log: u32) void {
    const lane_log = 7;
    const lanes = 1 << lane_log;
    const n = values.len;
    if (n < 2 * lanes) {
        if (n == 1) {
            values[0] = values[0].sub(shift);
            return;
        }
        var sum = M31.zero();
        for (0..n / 2) |i| {
            const even = utils.bitReverseIndex(i, log);
            sum = sum.add(values[even].sub(shift));
            values[even] = sum;
            const odd = n - 1 - even;
            sum = sum.add(values[odd].sub(shift));
            values[odd] = sum;
        }
        return;
    }
    var sums = [_]M31{M31.zero()} ** lanes;
    for (0..n / (2 * lanes)) |i| {
        const base = utils.bitReverseIndex(i, log);
        for (0..lanes) |lane| {
            const even = base + 2 * lane;
            const odd = n - 1 - even;
            sums[lane] = sums[lane].add(values[even].sub(shift));
            values[even] = sums[lane];
            sums[lane] = sums[lane].add(values[odd].sub(shift));
            values[odd] = sums[lane];
        }
    }
    // Turn interval totals into exclusive offsets in chronological order.
    var offset = M31.zero();
    for (0..lanes) |interval| {
        const lane = utils.bitReverseIndex(interval, lane_log);
        const total = sums[lane];
        sums[lane] = offset;
        offset = offset.add(total);
    }
    var base: usize = 0;
    while (base < n) : (base += 2 * lanes) {
        for (0..lanes) |lane| {
            const even = base + 2 * lane;
            values[even] = values[even].add(sums[lane]);
            values[even + 1] = values[even + 1].add(sums[lanes - 1 - lane]);
        }
    }
}

test "shifted LogUp prefix matches the circle permutation at every coordinate" {
    const a = std.testing.allocator;
    var rng = std.Random.DefaultPrng.init(427);
    for (0..15) |log| {
        const n = @as(usize, 1) << @intCast(log);
        const input = try a.alloc(M31, n);
        defer a.free(input);
        for (input) |*v| v.* = M31.fromU64(rng.next());
        const shift = M31.fromU64(rng.next());
        const expected = try a.dupe(M31, input);
        defer a.free(expected);
        // Independent reference uses the explicit physical -> circle -> coset maps.
        var sum = M31.zero();
        for (0..n) |i| {
            const physical = utils.bitReverseIndex(i, @intCast(log));
            const logical = if (n == 1) 0 else utils.circleDomainIndexToCosetIndex(physical, @intCast(log));
            expected[logical] = input[i].sub(shift);
        }
        for (expected) |*v| {
            sum = sum.add(v.*);
            v.* = sum;
        }
        shiftedPrefix(input, shift, @intCast(log));
        for (input, 0..) |v, i| {
            const circle = utils.bitReverseIndex(i, @intCast(log));
            const logical = if (n == 1) 0 else utils.circleDomainIndexToCosetIndex(circle, @intCast(log));
            try std.testing.expectEqual(expected[logical], v);
        }
    }
}

test "octic LogUp fractions preserve prefix columns and reject zero denominators" {
    const O = fields.om31.OM31;
    const L = ForField(O);
    const Context = struct {
        fault: bool,
        fn fill(self: @This(), row: usize, fractions: []L.Fraction) !void {
            for (fractions, 0..) |*fraction, j| {
                var coordinates: [8]M31 = undefined;
                for (&coordinates, 0..) |*value, k| value.* = M31.fromU64(1 + row + 7 * j + 53 * k);
                fraction.* = .{ .numerator = if ((row + j) % 3 == 0) O.zero() else O.fromM31Array(coordinates).neg(), .denominator = if (self.fault and row == 85 and j == 1) O.zero() else O.fromM31Array(coordinates).add(O.one()) };
            }
        }
    };
    const a = std.testing.allocator;
    const log = 7;
    const rows = 1 << log;
    const context = Context{ .fault = false };
    const result = try L.build(a, log, 3, context, Context.fill);
    defer {
        for (result.columns) |column| a.free(column.values);
        a.free(result.columns);
    }
    var sums: [rows]O = undefined;
    var claim = O.zero();
    for (&sums, 0..) |*sum, row| {
        var fractions: [3]L.Fraction = undefined;
        try context.fill(row, &fractions);
        var prefix = O.zero();
        for (fractions, 0..) |fraction, j| {
            prefix = prefix.add(try fraction.numerator.div(fraction.denominator));
            if (j < 2) for (prefix.toM31Array(), 0..) |coord, k| try std.testing.expectEqual(coord, result.columns[8 * j + k].values[row]);
        }
        sum.* = prefix;
        claim = claim.add(prefix);
    }
    try std.testing.expectEqual(claim, result.claimed_sum);
    const shift = claim.mulM31(try M31.fromU64(rows).inv());
    for (0..8) |k| {
        var expected: [rows]M31 = undefined;
        for (sums, &expected) |sum, *v| v.* = sum.toM31Array()[k];
        shiftedPrefix(&expected, shift.toM31Array()[k], log);
        try std.testing.expectEqualSlices(M31, &expected, result.columns[16 + k].values);
    }
    try std.testing.expectError(error.DegenerateDenominator, L.build(a, log, 3, Context{ .fault = true }, Context.fill));
}
