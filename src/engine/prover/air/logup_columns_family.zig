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
const Profile = @import("stwo_prover_api").stage_profile;

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
            return buildWithRecorder(allocator, log_size, secure_columns, context, fillRow, null);
        }

        /// Serial-owner timing only; worker callbacks never mutate the recorder.
        pub fn buildWithRecorder(
            allocator: std.mem.Allocator,
            log_size: u32,
            secure_columns: usize,
            context: anytype,
            comptime fillRow: fn (@TypeOf(context), usize, []Fraction) anyerror!void,
            recorder: ?*Profile.Recorder,
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

            var rows_scope = try Profile.StageScope.begin(recorder, "logup_rows", "LogUp fractions, inverses and scatter");
            defer rows_scope.end();
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
            rows_scope.end();

            var prefix_scope = try Profile.StageScope.begin(recorder, "logup_prefix", "LogUp shifted coset prefix");
            defer prefix_scope.end();
            const shift = claimed_sum.mulM31(try M31.fromU64(row_count).inv());
            const shift_coordinates = shift.toM31Array();
            const last_base = DEGREE * (secure_columns - 1);
            if (!try @import("logup_prefix.zig").tryParallel(allocator, columns[last_base..][0..DEGREE], &shift_coordinates)) for (0..DEGREE) |coordinate| {
                const values = @constCast(columns[last_base + coordinate].values);
                for (values) |*value| value.* = value.sub(shift_coordinates[coordinate]);
                try inclusivePrefixSum(allocator, values);
            };
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
                        try fields.batchInverseInPlace(Secure, self.denominators, self.inverses);

                        var partial = Secure.zero();
                        for (0..shared.chunk_rows) |offset| {
                            const row = first_row + offset;
                            var cumulative = Secure.zero();
                            for (0..width) |batch| {
                                const at = offset * width + batch;
                                cumulative = cumulative.add(self.fractions[at].numerator.mul(self.inverses[at]));
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
    };
}
