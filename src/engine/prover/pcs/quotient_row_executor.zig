//! Bounded CPU row execution for FRI quotient construction.

const std = @import("std");
const circle = @import("stwo_core").circle;
const cm31 = @import("stwo_core").fields.cm31;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const quotients = @import("stwo_core").pcs.quotients;
const canonic = @import("stwo_core").poly.circle.canonic;
const constraints = @import("stwo_core").constraints;
const core_utils = @import("stwo_core").utils;
const tile_sink = @import("quotient_tile_sink.zig");
const scalar_executor = @import("quotient_scalar_executor.zig");
const domain_walk = @import("quotient_domain_walk.zig");

const CircleDomain = @import("stwo_core").poly.circle.domain.CircleDomain;
const CirclePointM31 = circle.CirclePointM31;
const CM31 = cm31.CM31;
const M31 = m31.M31;
const QM31 = qm31.QM31;

pub const MAX_ROWS: usize = 1024;
pub const MAX_BYTES_PER_WORKER: usize = 8 * 1024 * 1024;
pub const MIN_BATCHED_DOMAIN_ROWS: usize = 8192;

pub const LiftingColumnView = struct {
    values: []const M31,
    shift_amt: std.math.Log2Int(usize),
    is_direct: bool,
};

pub const CombinedContributionView = struct {
    coordinates: [qm31.SECURE_EXTENSION_DEGREE][]M31,
    coordinate_backing: ?[]align(std.heap.page_size_max) M31 = null,

    batch_index: usize,
    shift_amt: std.math.Log2Int(usize),
    is_direct: bool,
    pub fn deinitCoordinates(self: @This(), a: std.mem.Allocator) void {
        if (self.coordinate_backing) |owner| a.free(owner) else for (self.coordinates) |coordinate| a.free(coordinate);
    }
};

pub const ColumnContribution = struct {
    batch_index: usize,
    value_coeff: QM31,
};

pub const ColumnContributionRange = struct {
    start: usize,
    len: usize,
};

pub inline fn shouldBatchDomain(total_rows: usize) bool {
    return total_rows >= MIN_BATCHED_DOMAIN_ROWS;
}

pub const Scratch = struct {
    domain_points: []CirclePointM31,
    denominators: []CM31,
    denominator_inverses: []CM31,
    batch_count: usize,
    prepared_rows: usize,
    inverse_layout: enum { row_major, batch_major },

    pub fn init(
        allocator: std.mem.Allocator,
        batch_count: usize,
        requested_rows: usize,
    ) !Scratch {
        const row_capacity = try rowCapacityForBatchCount(batch_count, requested_rows);
        const cell_count = std.math.mul(usize, row_capacity, batch_count) catch
            return error.ScratchSizeOverflow;

        const domain_points = try allocator.alloc(CirclePointM31, row_capacity);
        errdefer allocator.free(domain_points);
        const denominators = try allocator.alloc(CM31, cell_count);
        errdefer allocator.free(denominators);
        const denominator_inverses = try allocator.alloc(CM31, cell_count);
        errdefer allocator.free(denominator_inverses);

        return .{
            .domain_points = domain_points,
            .denominators = denominators,
            .denominator_inverses = denominator_inverses,
            .batch_count = batch_count,
            .prepared_rows = 0,
            .inverse_layout = .row_major,
        };
    }

    pub fn deinit(self: *Scratch, allocator: std.mem.Allocator) void {
        allocator.free(self.domain_points);
        allocator.free(self.denominators);
        allocator.free(self.denominator_inverses);
        self.* = undefined;
    }

    pub inline fn rowCapacity(self: Scratch) usize {
        return self.domain_points.len;
    }

    pub fn prepare(
        self: *Scratch,
        workspace: *const quotients.RowQuotientWorkspace,
        row_count: usize,
    ) !void {
        if (row_count == 0 or row_count > self.rowCapacity()) return error.InvalidChunkSize;
        if (workspace.batch_numerators.len != self.batch_count) return error.ShapeMismatch;
        self.prepared_rows = 0;
        const cell_count = std.math.mul(usize, row_count, self.batch_count) catch
            return error.ScratchSizeOverflow;
        try workspace.prepareDenominatorInversesForRows(
            self.domain_points[0..row_count],
            self.denominators[0..cell_count],
            self.denominator_inverses[0..cell_count],
        );
        self.prepared_rows = row_count;
        self.inverse_layout = .row_major;
    }

    pub fn prepareBatchMajor(
        self: *Scratch,
        workspace: *const quotients.RowQuotientWorkspace,
        row_count: usize,
    ) !void {
        if (row_count == 0 or row_count > self.rowCapacity()) return error.InvalidChunkSize;
        if (workspace.batch_numerators.len != self.batch_count) return error.ShapeMismatch;
        self.prepared_rows = 0;
        const cell_count = std.math.mul(usize, row_count, self.batch_count) catch
            return error.ScratchSizeOverflow;
        try workspace.prepareDenominatorInversesForRowsBatchMajor(
            self.domain_points[0..row_count],
            self.denominators[0..cell_count],
            self.denominator_inverses[0..cell_count],
        );
        self.prepared_rows = row_count;
        self.inverse_layout = .batch_major;
    }

    pub fn inversesForRow(self: Scratch, row: usize) ![]const CM31 {
        if (self.inverse_layout != .row_major or row >= self.prepared_rows) {
            return error.InvalidChunkSize;
        }
        const start = std.math.mul(usize, row, self.batch_count) catch
            return error.ScratchSizeOverflow;
        return self.denominator_inverses[start..][0..self.batch_count];
    }

    pub inline fn batchMajorInversePtr(self: *const Scratch, batch: usize, row: usize) [*]const CM31 {
        std.debug.assert(self.inverse_layout == .batch_major);
        std.debug.assert(batch < self.batch_count and row < self.prepared_rows);
        return self.denominator_inverses.ptr + batch * self.prepared_rows + row;
    }

    pub inline fn batchMajorInverse(self: *const Scratch, batch: usize, row: usize) CM31 {
        return self.batchMajorInversePtr(batch, row)[0];
    }

    pub fn retainedBytes(self: Scratch) usize {
        return self.domain_points.len * @sizeOf(CirclePointM31) +
            self.denominators.len * @sizeOf(CM31) +
            self.denominator_inverses.len * @sizeOf(CM31);
    }
};

pub fn rowCapacityForBatchCount(batch_count: usize, requested_rows: usize) !usize {
    if (requested_rows == 0) return error.InvalidChunkSize;
    const denominator_bytes = std.math.mul(usize, batch_count, 2 * @sizeOf(CM31)) catch
        return error.ScratchSizeOverflow;
    const bytes_per_row = std.math.add(
        usize,
        @sizeOf(CirclePointM31),
        denominator_bytes,
    ) catch return error.ScratchSizeOverflow;
    if (bytes_per_row > MAX_BYTES_PER_WORKER) return error.ScratchMemoryLimitExceeded;

    const bounded_request = @min(requested_rows, MAX_ROWS);
    return @min(bounded_request, MAX_BYTES_PER_WORKER / bytes_per_row);
}

pub fn initScratchOrScalarFallback(
    allocator: std.mem.Allocator,
    batch_count: usize,
    requested_rows: usize,
    total_rows: usize,
) !?Scratch {
    if (!shouldBatchDomain(total_rows)) return null;
    return Scratch.init(allocator, batch_count, requested_rows) catch |err| switch (err) {
        error.ScratchMemoryLimitExceeded => null,
        else => return err,
    };
}

pub fn initParallelScratch(
    allocator: std.mem.Allocator,
    batch_count: usize,
    requested_rows: usize,
    total_rows: usize,
) !Scratch {
    if (!shouldBatchDomain(total_rows)) return error.ParallelUnavailable;
    return Scratch.init(allocator, batch_count, requested_rows) catch |err| switch (err) {
        error.ScratchMemoryLimitExceeded => return error.ParallelUnavailable,
        else => return err,
    };
}

pub fn prepareParallelScratchPolicy(
    batch_count: usize,
    requested_rows: usize,
    total_rows: usize,
) !bool {
    if (!shouldBatchDomain(total_rows)) return false;
    _ = rowCapacityForBatchCount(batch_count, requested_rows) catch |err| switch (err) {
        error.ScratchMemoryLimitExceeded => return error.ParallelUnavailable,
        else => return err,
    };
    return true;
}

pub fn workerSpan(domain_size: usize, n_workers: usize) !usize {
    if (n_workers == 0) return error.ParallelUnavailable;
    const rounded = std.math.add(usize, domain_size, n_workers - 1) catch
        return error.ScratchSizeOverflow;
    return rounded / n_workers;
}

pub const WorkerRange = struct {
    start: usize,
    end: usize,
};

pub fn workerRange(domain_size: usize, worker_span: usize, worker: usize) !WorkerRange {
    const start = std.math.mul(usize, worker, worker_span) catch
        return error.ScratchSizeOverflow;
    const unbounded_end = std.math.mul(usize, worker + 1, worker_span) catch
        return error.ScratchSizeOverflow;
    return .{
        .start = @min(domain_size, start),
        .end = @min(domain_size, unbounded_end),
    };
}

pub const MaterializedWork = struct {
    out_columns: [qm31.SECURE_EXTENSION_DEGREE][]M31,
    start: usize,
    end: usize,
    workspace: *quotients.RowQuotientWorkspace,
    scratch: ?*Scratch,
    domain: CircleDomain,
    lifted_columns: []const []M31,
    contribution_plan_ranges: []const ColumnContributionRange,
    contributions: []const ColumnContribution,
    quotient_constants: *const quotients.QuotientConstants,
    lifting_log_size: u32,
    failure: ?anyerror = null,
};

pub fn executeMaterialized(item: *const MaterializedWork) !void {
    const scratch = item.scratch orelse return scalar_executor.executeMaterialized(item);
    const workspace = item.workspace;
    var chunk_start = item.start;
    var walk = domain_walk.BitReversedCosetWalk.init(
        item.domain,
        item.lifting_log_size,
        item.start,
    );
    while (chunk_start < item.end) {
        const row_count = @min(scratch.rowCapacity(), item.end - chunk_start);
        for (scratch.domain_points[0..row_count]) |*domain_point| {
            domain_point.* = walk.next();
        }
        try scratch.prepare(workspace, row_count);

        for (0..row_count) |row| {
            const position = chunk_start + row;
            const domain_point = scratch.domain_points[row];
            workspace.resetNumerators();
            for (item.lifted_columns, item.contribution_plan_ranges) |lifted_column, contribution_range| {
                const base_value = lifted_column[position];
                for (item.contributions[contribution_range.start..][0..contribution_range.len]) |contribution| {
                    workspace.batch_numerators[contribution.batch_index] =
                        workspace.batch_numerators[contribution.batch_index].add(
                            contribution.value_coeff.mulM31(base_value),
                        );
                }
            }
            try writeQuotientRow(
                item.out_columns,
                position,
                item.quotient_constants,
                domain_point.y,
                workspace.batch_numerators,
                try scratch.inversesForRow(row),
            );
        }
        chunk_start += row_count;
    }
}

pub fn materializedWorker(item: *MaterializedWork) void {
    executeMaterialized(item) catch |err| {
        item.failure = err;
    };
}

pub const StreamingWork = struct {
    out_columns: [qm31.SECURE_EXTENSION_DEGREE][]M31,
    start: usize,
    end: usize,
    output_start: usize = 0,
    workspace: *quotients.RowQuotientWorkspace,
    scratch: ?*Scratch,
    domain: CircleDomain,
    combined_views: []const CombinedContributionView,
    quotient_constants: *const quotients.QuotientConstants,
    lifting_log_size: u32,
    tile_writer: ?tile_sink.Writer = null,
    completed_tiles: usize = 0,
    failure: ?anyerror = null,
};

pub fn executeStreaming(item: *StreamingWork) !void {
    if (item.output_start > item.start) return error.ShapeMismatch;
    const output_end = item.end - item.output_start;
    for (item.out_columns) |column| {
        if (output_end > column.len) return error.ShapeMismatch;
    }

    const scratch = item.scratch orelse return scalar_executor.executeStreaming(item);
    const workspace = item.workspace;
    var chunk_start = item.start;
    var walk = domain_walk.BitReversedCosetWalk.init(
        item.domain,
        item.lifting_log_size,
        item.start,
    );
    while (chunk_start < item.end) {
        const row_count = @min(scratch.rowCapacity(), item.end - chunk_start);
        for (scratch.domain_points[0..row_count]) |*domain_point| {
            domain_point.* = walk.next();
        }
        try scratch.prepare(workspace, row_count);

        var tile_row_start: usize = 0;
        while (tile_row_start < row_count) {
            const tile_row_end = @min(
                row_count,
                tile_row_start + tile_sink.DEFAULT_TILE_ROWS,
            );
            for (tile_row_start..tile_row_end) |row| {
                const position = chunk_start + row;
                const domain_point = scratch.domain_points[row];
                workspace.resetNumerators();
                accumulateStreamingNumerators(workspace, item.combined_views, position);
                try writeQuotientRow(
                    item.out_columns,
                    position - item.output_start,
                    item.quotient_constants,
                    domain_point.y,
                    workspace.batch_numerators,
                    try scratch.inversesForRow(row),
                );
            }
            try emitCompletedTile(
                item,
                chunk_start + tile_row_start,
                chunk_start + tile_row_end,
            );
            tile_row_start = tile_row_end;
        }
        chunk_start += row_count;
    }
}

pub fn emitCompletedTile(item: *StreamingWork, start: usize, end: usize) !void {
    const writer = item.tile_writer orelse return;
    if (start < item.output_start or end <= start) return error.ShapeMismatch;
    const output_start = start - item.output_start;
    const output_end = end - item.output_start;
    var coordinates: [qm31.SECURE_EXTENSION_DEGREE][]const M31 = undefined;
    inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
        coordinates[coordinate] = item.out_columns[coordinate][output_start..output_end];
    }
    try writer.absorb(.{ .start = start, .coordinates = coordinates });
    item.completed_tiles += 1;
}

pub fn accumulateStreamingNumerators(
    workspace: *quotients.RowQuotientWorkspace,
    views: []const CombinedContributionView,
    position: usize,
) void {
    for (views) |view| {
        const idx = if (view.is_direct)
            position
        else
            ((position >> view.shift_amt) << 1) + (position & 1);
        const value = QM31.fromM31(
            view.coordinates[0][idx],
            view.coordinates[1][idx],
            view.coordinates[2][idx],
            view.coordinates[3][idx],
        );
        workspace.batch_numerators[view.batch_index] =
            workspace.batch_numerators[view.batch_index].add(value);
    }
}

pub fn streamingWorker(item: *StreamingWork) void {
    executeStreaming(item) catch |err| {
        item.failure = err;
    };
}

pub fn writeQuotientRow(
    out_columns: [qm31.SECURE_EXTENSION_DEGREE][]M31,
    output_position: usize,
    quotient_constants: *const quotients.QuotientConstants,
    domain_y: M31,
    batch_numerators: []const QM31,
    denominator_inverses: []const CM31,
) !void {
    const quotient_value = try quotients.finalizeRowQuotients(
        quotient_constants,
        domain_y,
        batch_numerators,
        denominator_inverses,
    );
    const coordinates = quotient_value.toM31Array();
    inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
        out_columns[coordinate][output_position] = coordinates[coordinate];
    }
}

test "quotient row scratch rejects invalid, overflowing, and over-budget shapes" {
    try std.testing.expectError(error.InvalidChunkSize, rowCapacityForBatchCount(1, 0));
    try std.testing.expectError(
        error.ScratchSizeOverflow,
        rowCapacityForBatchCount(std.math.maxInt(usize), 1),
    );
    try std.testing.expectError(
        error.ScratchMemoryLimitExceeded,
        rowCapacityForBatchCount(MAX_BYTES_PER_WORKER / @sizeOf(CM31), 1),
    );
}

test "quotient row inverses match scalar rows across batch counts and domains" {
    const allocator = std.testing.allocator;
    const batch_counts = [_]usize{ 1, 3, 8 };
    const log_sizes = [_]u32{ 3, 6, 10 };
    var entries: [batch_counts[batch_counts.len - 1]][1]quotients.NumeratorData = undefined;

    for (batch_counts) |batch_count| {
        var batches: [batch_counts[batch_counts.len - 1]]quotients.ColumnSampleBatch = undefined;
        for (batches[0..batch_count], 0..) |*batch, index| {
            entries[index][0] = .{
                .column_index = 0,
                .sample_value = QM31.fromU32Unchecked(@intCast(index + 3), 1, 2, 3),
                .random_coeff = QM31.fromU32Unchecked(@intCast(index + 5), 0, 1, 0),
            };
            batch.* = .{
                .point = circle.SECURE_FIELD_CIRCLE_GEN.mul(17 + index * 12),
                .cols_vals_randpows = entries[index][0..],
            };
        }

        var constants = try quotients.quotientConstants(allocator, batches[0..batch_count]);
        defer constants.deinit(allocator);
        var workspace = try quotients.RowQuotientWorkspace.init(allocator, batches[0..batch_count]);
        defer workspace.deinit(allocator);

        for (log_sizes) |log_size| {
            const domain = canonic.CanonicCoset.new(log_size).circleDomain();
            var scratch = try Scratch.init(allocator, batch_count, domain.size());
            defer scratch.deinit(allocator);

            for (scratch.domain_points, 0..) |*point, row| point.* = domain.at(row);
            try scratch.prepare(&workspace, scratch.rowCapacity());

            for (scratch.domain_points, 0..) |domain_point, row| {
                try workspace.beginRow(domain_point);
                const batched = try scratch.inversesForRow(row);
                for (workspace.denominator_inverses, batched) |scalar, chunked| {
                    try std.testing.expect(scalar.eql(chunked));
                }

                const queried_values = [_]M31{M31.fromCanonical(@intCast(row + 11))};
                const scalar_quotient = try quotients.accumulateRowQuotientsWithWorkspace(
                    batches[0..batch_count],
                    queried_values[0..],
                    &constants,
                    domain_point,
                    &workspace,
                );

                workspace.resetNumerators();
                for (constants.line_coeffs, 0..) |line_coeffs, batch_index| {
                    workspace.batch_numerators[batch_index] =
                        workspace.batch_numerators[batch_index].add(
                            line_coeffs[0].c.mulM31(queried_values[0]),
                        );
                }
                const chunked_quotient = try quotients.finalizeRowQuotients(
                    &constants,
                    domain_point.y,
                    workspace.batch_numerators,
                    batched,
                );
                try std.testing.expect(scalar_quotient.eql(chunked_quotient));
            }

            try scratch.prepareBatchMajor(&workspace, scratch.rowCapacity());
            try std.testing.expectError(error.InvalidChunkSize, scratch.inversesForRow(0));
            for (scratch.domain_points, 0..) |domain_point, row| {
                try workspace.beginRow(domain_point);
                for (workspace.denominator_inverses, 0..) |scalar, batch| {
                    try std.testing.expect(scalar.eql(scratch.batchMajorInverse(batch, row)));
                }
            }
        }

        // Exercise packed groups, scalar tails, and changing batch-major
        // strides in the same retained scratch allocation.
        const tail_domain = canonic.CanonicCoset.new(6).circleDomain();
        var tail_scratch = try Scratch.init(allocator, batch_count, 17);
        defer tail_scratch.deinit(allocator);
        for (tail_scratch.domain_points, 0..) |*point, row| {
            point.* = tail_domain.at(row);
        }
        for ([_]usize{ 1, 2, 3, 4, 7, 8, 17 }) |row_count| {
            try tail_scratch.prepareBatchMajor(&workspace, row_count);
            for (tail_scratch.domain_points[0..row_count], 0..) |domain_point, row| {
                try workspace.beginRow(domain_point);
                for (workspace.denominator_inverses, 0..) |scalar, batch| {
                    try std.testing.expect(scalar.eql(tail_scratch.batchMajorInverse(batch, row)));
                }
            }
        }
    }
}

test "quotient row scratch reports a zero denominator" {
    const allocator = std.testing.allocator;
    const domain_point = canonic.CanonicCoset.new(3).circleDomain().at(2);
    var empty_entries: [0]quotients.NumeratorData = .{};
    const batch = quotients.ColumnSampleBatch{
        .point = .{
            .x = qm31.QM31.fromBase(domain_point.x),
            .y = qm31.QM31.fromBase(domain_point.y),
        },
        .cols_vals_randpows = empty_entries[0..],
    };
    var workspace = try quotients.RowQuotientWorkspace.init(allocator, &.{batch});
    defer workspace.deinit(allocator);
    var scratch = try Scratch.init(allocator, 1, 1);
    defer scratch.deinit(allocator);
    scratch.domain_points[0] = domain_point;

    try std.testing.expectError(error.DivisionByZero, scratch.prepare(&workspace, 1));
    try std.testing.expectError(error.DivisionByZero, scratch.prepareBatchMajor(&workspace, 1));
}

test "quotient row scratch policy honors cost boundary and memory fallback" {
    const over_budget_batches = MAX_BYTES_PER_WORKER / @sizeOf(CM31);
    var below_boundary = try initScratchOrScalarFallback(
        std.testing.allocator,
        std.math.maxInt(usize),
        1,
        MIN_BATCHED_DOMAIN_ROWS - 1,
    );
    defer if (below_boundary) |*value| value.deinit(std.testing.allocator);
    try std.testing.expectEqual(null, below_boundary);
    try std.testing.expectEqual(
        false,
        try prepareParallelScratchPolicy(
            std.math.maxInt(usize),
            1,
            MIN_BATCHED_DOMAIN_ROWS - 1,
        ),
    );

    var at_boundary = try initScratchOrScalarFallback(
        std.testing.allocator,
        1,
        1,
        MIN_BATCHED_DOMAIN_ROWS,
    );
    defer if (at_boundary) |*value| value.deinit(std.testing.allocator);
    try std.testing.expect(at_boundary != null);

    var over_budget = try initScratchOrScalarFallback(
        std.testing.allocator,
        over_budget_batches,
        1,
        MIN_BATCHED_DOMAIN_ROWS,
    );
    defer if (over_budget) |*value| value.deinit(std.testing.allocator);
    try std.testing.expectEqual(null, over_budget);
    try std.testing.expectError(
        error.ParallelUnavailable,
        initParallelScratch(
            std.testing.allocator,
            over_budget_batches,
            1,
            MIN_BATCHED_DOMAIN_ROWS,
        ),
    );
    try std.testing.expectError(
        error.ScratchSizeOverflow,
        initScratchOrScalarFallback(
            std.testing.allocator,
            std.math.maxInt(usize),
            1,
            MIN_BATCHED_DOMAIN_ROWS,
        ),
    );
}

test "quotient row worker partitions cover each domain exactly once" {
    const cases = [_]struct { domain_size: usize, worker_count: usize }{
        .{ .domain_size = 512, .worker_count = 2 },
        .{ .domain_size = 1024, .worker_count = 3 },
        .{ .domain_size = 4096, .worker_count = 7 },
    };
    for (cases) |case| {
        const span = try workerSpan(case.domain_size, case.worker_count);
        var cursor: usize = 0;
        for (0..case.worker_count) |worker| {
            const range = try workerRange(case.domain_size, span, worker);
            try std.testing.expectEqual(cursor, range.start);
            try std.testing.expect(range.end > range.start);
            cursor = range.end;
        }
        try std.testing.expectEqual(case.domain_size, cursor);
    }
    try std.testing.expectError(error.ParallelUnavailable, workerSpan(1024, 0));
    try std.testing.expectError(
        error.ScratchSizeOverflow,
        workerRange(std.math.maxInt(usize), std.math.maxInt(usize), 1),
    );
}

test "quotient row workers propagate denominator failures" {
    const allocator = std.testing.allocator;
    const log_size: u32 = 3;
    const domain = canonic.CanonicCoset.new(log_size).circleDomain();
    const domain_point = domain.at(core_utils.bitReverseIndex(0, log_size));
    var empty_entries: [0]quotients.NumeratorData = .{};
    const batch = quotients.ColumnSampleBatch{
        .point = .{
            .x = QM31.fromBase(domain_point.x),
            .y = QM31.fromBase(domain_point.y),
        },
        .cols_vals_randpows = empty_entries[0..],
    };
    const batches = [_]quotients.ColumnSampleBatch{batch};
    var constants = try quotients.quotientConstants(allocator, batches[0..]);
    defer constants.deinit(allocator);
    var workspace = try quotients.RowQuotientWorkspace.init(allocator, batches[0..]);
    defer workspace.deinit(allocator);
    var scratch = try Scratch.init(allocator, batches.len, domain.size());
    defer scratch.deinit(allocator);

    var storage: [qm31.SECURE_EXTENSION_DEGREE][8]M31 = undefined;
    var out_columns: [qm31.SECURE_EXTENSION_DEGREE][]M31 = undefined;
    inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
        out_columns[coordinate] = storage[coordinate][0..];
    }

    var materialized = MaterializedWork{
        .out_columns = out_columns,
        .start = 0,
        .end = domain.size(),
        .workspace = &workspace,
        .scratch = &scratch,
        .domain = domain,
        .lifted_columns = &.{},
        .contribution_plan_ranges = &.{},
        .contributions = &.{},
        .quotient_constants = &constants,
        .lifting_log_size = log_size,
    };
    materializedWorker(&materialized);
    try std.testing.expectEqual(error.DivisionByZero, materialized.failure.?);

    var streaming = StreamingWork{
        .out_columns = out_columns,
        .start = 0,
        .end = domain.size(),
        .workspace = &workspace,
        .scratch = &scratch,
        .domain = domain,
        .combined_views = &.{},
        .quotient_constants = &constants,
        .lifting_log_size = log_size,
    };
    streamingWorker(&streaming);
    try std.testing.expectEqual(error.DivisionByZero, streaming.failure.?);
}
