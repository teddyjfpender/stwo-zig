//! Bounded CPU execution for direct contribution-to-quotient row tiles.

const std = @import("std");
const circle = @import("stwo_core").circle;
const cm31 = @import("stwo_core").fields.cm31;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const quotients = @import("stwo_core").pcs.quotients;
const row_executor = @import("quotient_row_executor.zig");
const tile_sink = @import("quotient_tile_sink.zig");
const compact_groups = @import("quotient_compact_groups.zig");
const direct_groups = @import("quotient_direct_groups.zig");
const direct_plan = @import("quotient_direct_plan.zig");
const constraints = @import("stwo_core").constraints;
const domain_walk = @import("quotient_domain_walk.zig");
const work_pool_mod = @import("../work_pool.zig");

const CircleDomain = @import("stwo_core").poly.circle.domain.CircleDomain;
const CirclePointM31 = circle.CirclePointM31;
const CM31 = cm31.CM31;
const M31 = m31.M31;
const QM31 = qm31.QM31;

pub const MAX_SCRATCH_BYTES_PER_WORKER: usize = 8 * 1024 * 1024;
const MIN_POSITIONS_PER_WORKER: usize = 256;

pub inline fn shouldUseBoundedInput(lifting_log_size: u32) bool {
    return lifting_log_size >= 13;
}

pub const DirectContributionPlan = direct_plan.Plan;
pub const buildDirectContributionPlan = direct_plan.build;

pub const Scratch = struct {
    row_scratch: row_executor.Scratch,
    numerators: []M31,
    batch_count: usize,
    row_capacity: usize,

    pub fn init(
        allocator: std.mem.Allocator,
        batch_count: usize,
        requested_rows: usize,
    ) !Scratch {
        const capacity = try rowCapacityForBatchCount(batch_count, requested_rows);
        var row_scratch = try row_executor.Scratch.init(allocator, batch_count, capacity);
        errdefer row_scratch.deinit(allocator);
        const plane_count = std.math.mul(
            usize,
            batch_count,
            qm31.SECURE_EXTENSION_DEGREE,
        ) catch return error.ScratchSizeOverflow;
        const numerator_count = std.math.mul(usize, plane_count, capacity) catch
            return error.ScratchSizeOverflow;
        const numerators = try allocator.alloc(M31, numerator_count);
        return .{
            .row_scratch = row_scratch,
            .numerators = numerators,
            .batch_count = batch_count,
            .row_capacity = capacity,
        };
    }

    pub fn deinit(self: *Scratch, allocator: std.mem.Allocator) void {
        self.row_scratch.deinit(allocator);
        allocator.free(self.numerators);
        self.* = undefined;
    }

    pub fn retainedBytes(self: Scratch) usize {
        return self.row_scratch.retainedBytes() + self.numerators.len * @sizeOf(M31);
    }

    pub fn numeratorBytes(self: Scratch) usize {
        return self.numerators.len * @sizeOf(M31);
    }

    fn clearNumerators(self: *Scratch, row_count: usize) !void {
        if (row_count == 0 or row_count > self.row_capacity) return error.InvalidChunkSize;
        if (row_count == self.row_capacity) {
            @memset(self.numerators, M31.zero());
            return;
        }
        for (0..self.batch_count * qm31.SECURE_EXTENSION_DEGREE) |plane| {
            const start = plane * self.row_capacity;
            @memset(self.numerators[start..][0..row_count], M31.zero());
        }
    }

    fn numerator(self: *Scratch, batch: usize, coordinate: usize, row: usize) *M31 {
        std.debug.assert(batch < self.batch_count);
        std.debug.assert(coordinate < qm31.SECURE_EXTENSION_DEGREE);
        std.debug.assert(row < self.row_capacity);
        const plane = batch * qm31.SECURE_EXTENSION_DEGREE + coordinate;
        return &self.numerators[plane * self.row_capacity + row];
    }
};

pub fn initScratchOrScalarFallback(
    allocator: std.mem.Allocator,
    batch_count: usize,
    requested_rows: usize,
    total_rows: usize,
) !?Scratch {
    if (!row_executor.shouldBatchDomain(total_rows)) return null;
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
    if (!row_executor.shouldBatchDomain(total_rows)) return error.ParallelUnavailable;
    return Scratch.init(allocator, batch_count, requested_rows) catch |err| switch (err) {
        error.ScratchMemoryLimitExceeded => return error.ParallelUnavailable,
        else => return err,
    };
}

pub fn rowCapacityForBatchCount(batch_count: usize, requested_rows: usize) !usize {
    if (batch_count == 0 or requested_rows == 0) return error.InvalidChunkSize;
    const denominator_bytes = std.math.mul(usize, batch_count, 2 * @sizeOf(CM31)) catch
        return error.ScratchSizeOverflow;
    const numerator_bytes = std.math.mul(
        usize,
        batch_count,
        qm31.SECURE_EXTENSION_DEGREE * @sizeOf(M31),
    ) catch return error.ScratchSizeOverflow;
    const bytes_per_row = std.math.add(
        usize,
        @sizeOf(CirclePointM31),
        std.math.add(usize, denominator_bytes, numerator_bytes) catch
            return error.ScratchSizeOverflow,
    ) catch return error.ScratchSizeOverflow;
    if (bytes_per_row > MAX_SCRATCH_BYTES_PER_WORKER) {
        return error.ScratchMemoryLimitExceeded;
    }
    return @min(
        @min(requested_rows, tile_sink.DEFAULT_TILE_ROWS),
        MAX_SCRATCH_BYTES_PER_WORKER / bytes_per_row,
    );
}

pub const Work = struct {
    out_columns: [qm31.SECURE_EXTENSION_DEGREE][]M31,
    start: usize,
    end: usize,
    output_start: usize = 0,
    workspace: *quotients.RowQuotientWorkspace,
    scratch: ?*Scratch,
    domain: CircleDomain,
    compact_groups: []const compact_groups.Group = &.{},
    column_views: []const row_executor.LiftingColumnView,
    contribution_ranges: []const row_executor.ColumnContributionRange,
    contributions: []const row_executor.ColumnContribution,
    quotient_constants: *const quotients.QuotientConstants,
    lifting_log_size: u32,
    tile_writer: ?tile_sink.Writer = null,
    completed_tiles: usize = 0,
    failure: ?anyerror = null,
};

pub fn execute(work: *Work) !void {
    if (work.column_views.len != work.contribution_ranges.len or
        work.output_start > work.start)
    {
        return error.ShapeMismatch;
    }
    const output_end = work.end - work.output_start;
    for (work.out_columns) |column| {
        if (output_end > column.len) return error.ShapeMismatch;
    }
    if (work.scratch) |scratch| return executeBatched(work, scratch);
    return executeScalar(work);
}

fn executeBatched(work: *Work, scratch: *Scratch) !void {
    var tile_start = work.start;
    var walk = domain_walk.BitReversedCosetWalk.init(
        work.domain,
        work.lifting_log_size,
        work.start,
    );
    while (tile_start < work.end) {
        const row_count = @min(scratch.row_capacity, work.end - tile_start);
        for (scratch.row_scratch.domain_points[0..row_count]) |*point| {
            point.* = walk.next();
        }
        try scratch.row_scratch.prepareBatchMajor(work.workspace, row_count);
        try scratch.clearNumerators(row_count);
        accumulateTile(work, scratch, tile_start, row_count);

        var row: usize = 0;
        while (row + m31.VEC_WIDTH <= row_count) : (row += m31.VEC_WIDTH) {
            var ys: [m31.VEC_WIDTH]M31 = undefined;
            inline for (0..m31.VEC_WIDTH) |lane| {
                ys[lane] = scratch.row_scratch.domain_points[row + lane].y;
            }
            const quotient = finalizeGroupVec4(
                work.quotient_constants,
                m31.loadVec4(&ys),
                scratch,
                row,
            );
            inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
                m31.storeVec4(
                    work.out_columns[coordinate][tile_start + row - work.output_start ..].ptr,
                    quotient[coordinate],
                );
            }
        }
        while (row < row_count) : (row += 1) {
            for (0..scratch.batch_count) |batch| {
                work.workspace.batch_numerators[batch] = QM31.fromM31(
                    scratch.numerator(batch, 0, row).*,
                    scratch.numerator(batch, 1, row).*,
                    scratch.numerator(batch, 2, row).*,
                    scratch.numerator(batch, 3, row).*,
                );
                work.workspace.denominator_inverses[batch] =
                    scratch.row_scratch.batchMajorInverse(batch, row);
            }
            try writeRow(
                work,
                tile_start + row,
                scratch.row_scratch.domain_points[row].y,
                work.workspace.denominator_inverses,
            );
        }
        try emitTile(work, tile_start, tile_start + row_count);
        tile_start += row_count;
    }
}

fn accumulateTile(work: *const Work, scratch: *Scratch, start: usize, row_count: usize) void {
    accumulateNumeratorInputs(
        work.compact_groups,
        work.column_views,
        work.contribution_ranges,
        work.contributions,
        scratch,
        start,
        row_count,
    );
}

/// Reconstructs only the pre-finalization numerator planes for a bounded row
/// tile. This is an additive diagnostic seam used by device backends to
/// compare an in-flight quotient accumulation before denominators and linear
/// terms can hide its first divergent source run.
///
/// The result remains owned by `scratch` and is laid out as
/// `[batch][coordinate][local_row]`. No transcript or proof path calls this
/// helper unless an explicit backend diagnostic is enabled.
pub fn accumulateDirectNumeratorTile(
    scratch: *Scratch,
    column_views: []const row_executor.LiftingColumnView,
    contribution_ranges: []const row_executor.ColumnContributionRange,
    contributions: []const row_executor.ColumnContribution,
    start: usize,
    row_count: usize,
) !void {
    if (column_views.len != contribution_ranges.len or row_count == 0 or
        row_count > scratch.row_capacity)
    {
        return error.ShapeMismatch;
    }
    const end = std.math.add(usize, start, row_count) catch
        return error.ShapeMismatch;
    for (column_views, contribution_ranges) |view, range| {
        if (range.start > contributions.len or
            range.len > contributions.len - range.start)
        {
            return error.ShapeMismatch;
        }
        const required_source = if (view.is_direct)
            end
        else blk: {
            if (view.shift_amt == 0) return error.ShapeMismatch;
            const last_position = end - 1;
            break :blk (((last_position >> view.shift_amt) << 1) |
                (last_position & 1)) + 1;
        };
        if (required_source > view.values.len) return error.ShapeMismatch;
        for (contributions[range.start..][0..range.len]) |contribution| {
            if (contribution.batch_index >= scratch.batch_count)
                return error.ShapeMismatch;
        }
    }
    try scratch.clearNumerators(row_count);
    accumulateNumeratorInputs(
        &.{},
        column_views,
        contribution_ranges,
        contributions,
        scratch,
        start,
        row_count,
    );
}

pub fn directNumeratorValue(
    scratch: *const Scratch,
    batch: usize,
    coordinate: usize,
    local_row: usize,
) !M31 {
    if (batch >= scratch.batch_count or
        coordinate >= qm31.SECURE_EXTENSION_DEGREE or
        local_row >= scratch.row_capacity)
    {
        return error.ShapeMismatch;
    }
    const plane = batch * qm31.SECURE_EXTENSION_DEGREE + coordinate;
    return scratch.numerators[plane * scratch.row_capacity + local_row];
}

fn accumulateNumeratorInputs(
    compact_inputs: []const compact_groups.Group,
    column_views: []const row_executor.LiftingColumnView,
    contribution_ranges: []const row_executor.ColumnContributionRange,
    contributions: []const row_executor.ColumnContribution,
    scratch: *Scratch,
    start: usize,
    row_count: usize,
) void {
    for (compact_inputs) |group| {
        compact_groups.accumulate(
            scratch.numerators,
            scratch.row_capacity,
            scratch.batch_count,
            group,
            start,
            row_count,
        );
    }
    var view_index: usize = 0;
    while (view_index < column_views.len) {
        if (direct_groups.canAccumulate(
            column_views,
            contribution_ranges,
            contributions,
            view_index,
        )) {
            var views: [4]row_executor.LiftingColumnView = undefined;
            var coefficients: [4][qm31.SECURE_EXTENSION_DEGREE]M31 = undefined;
            const first_range = contribution_ranges[view_index];
            const batch = contributions[first_range.start].batch_index;
            inline for (0..4) |term| {
                views[term] = column_views[view_index + term];
                const contribution_range = contribution_ranges[view_index + term];
                coefficients[term] =
                    contributions[contribution_range.start].value_coeff.toM31Array();
            }
            direct_groups.accumulate(
                scratch.numerators,
                scratch.row_capacity,
                views,
                start,
                row_count,
                batch,
                coefficients,
            );
            view_index += 4;
            continue;
        }

        const view = column_views[view_index];
        const contribution_range = contribution_ranges[view_index];
        const column_contributions = contributions[contribution_range.start..][0..contribution_range.len];
        for (column_contributions) |contribution| {
            const coefficients = contribution.value_coeff.toM31Array();
            if (view.is_direct and m31.PACK_WIDTH > 1) {
                accumulateDirectPacked(
                    scratch,
                    view.values[start..][0..row_count],
                    contribution.batch_index,
                    coefficients,
                );
                continue;
            }
            if (!view.is_direct) {
                accumulateLiftedRuns(
                    scratch,
                    view.values,
                    view.shift_amt,
                    start,
                    row_count,
                    contribution.batch_index,
                    coefficients,
                );
                continue;
            }
            for (0..row_count) |row| {
                const position = start + row;
                const source_index = ((position >> view.shift_amt) << 1) + (position & 1);
                const base = view.values[source_index];
                inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
                    const numerator = scratch.numerator(contribution.batch_index, coordinate, row);
                    numerator.* = numerator.add(base.mul(coefficients[coordinate]));
                }
            }
        }
        view_index += 1;
    }
}

/// Accumulates an implicitly lifted column without repeating its field
/// products for every output row. A non-direct view repeats one even/odd source
/// pair across each `2^shift_amt`-row run. Products are invariant within that
/// run, so compute the two parity values once and broadcast packed additions
/// into the output-stationary numerator planes.
fn accumulateLiftedRuns(
    scratch: *Scratch,
    values: []const M31,
    shift_amt: std.math.Log2Int(usize),
    start: usize,
    row_count: usize,
    batch: usize,
    coefficients: [qm31.SECURE_EXTENSION_DEGREE]M31,
) void {
    std.debug.assert(shift_amt >= 2);
    const end = start + row_count;
    var position = start;
    while (position < end) {
        const source_block = position >> shift_amt;
        const block_end = @min(end, (source_block + 1) << shift_amt);
        const source_index = source_block << 1;
        std.debug.assert(source_index + 1 < values.len);

        var products: [qm31.SECURE_EXTENSION_DEGREE][2]M31 = undefined;
        var even_first: [qm31.SECURE_EXTENSION_DEGREE]m31.PackedM31 = undefined;
        var odd_first: [qm31.SECURE_EXTENSION_DEGREE]m31.PackedM31 = undefined;
        inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
            products[coordinate] = .{
                values[source_index].mul(coefficients[coordinate]),
                values[source_index + 1].mul(coefficients[coordinate]),
            };
            var even_lanes: [m31.PACK_WIDTH]u32 = undefined;
            var odd_lanes: [m31.PACK_WIDTH]u32 = undefined;
            inline for (0..m31.PACK_WIDTH) |lane| {
                even_lanes[lane] = products[coordinate][lane & 1].v;
                odd_lanes[lane] = products[coordinate][1 - (lane & 1)].v;
            }
            even_first[coordinate] = @bitCast(even_lanes);
            odd_first[coordinate] = @bitCast(odd_lanes);
        }

        while (block_end - position >= m31.PACK_WIDTH) : (position += m31.PACK_WIDTH) {
            const local_row = position - start;
            inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
                const plane = batch * qm31.SECURE_EXTENSION_DEGREE + coordinate;
                const numerators = scratch.numerators.ptr + plane * scratch.row_capacity + local_row;
                const addend = if ((position & 1) == 0)
                    even_first[coordinate]
                else
                    odd_first[coordinate];
                m31.storePacked(numerators, m31.addPacked(m31.loadPacked(numerators), addend));
            }
        }
        while (position < block_end) : (position += 1) {
            const parity = position & 1;
            inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
                const numerator = scratch.numerator(batch, coordinate, position - start);
                numerator.* = numerator.add(products[coordinate][parity]);
            }
        }
    }
}

/// Accumulates one direct-column contribution across a tile in native packed
/// row lanes. Contribution order is unchanged for every output cell; only the
/// four independent coordinate planes are traversed separately.
fn accumulateDirectPacked(
    scratch: *Scratch,
    values: []const M31,
    batch: usize,
    coefficients: [qm31.SECURE_EXTENSION_DEGREE]M31,
) void {
    std.debug.assert(values.len <= scratch.row_capacity);
    var coefficient_vectors: [qm31.SECURE_EXTENSION_DEGREE]m31.PackedM31 = undefined;
    var numerator_planes: [qm31.SECURE_EXTENSION_DEGREE][*]M31 = undefined;
    inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
        coefficient_vectors[coordinate] = m31.splatPacked(coefficients[coordinate]);
        const plane = batch * qm31.SECURE_EXTENSION_DEGREE + coordinate;
        numerator_planes[coordinate] = scratch.numerators.ptr + plane * scratch.row_capacity;
    }

    var row: usize = 0;
    while (row + m31.PACK_WIDTH <= values.len) : (row += m31.PACK_WIDTH) {
        const base = m31.loadPacked(values.ptr + row);
        inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
            const numerators = numerator_planes[coordinate] + row;
            const accumulated = m31.loadPacked(numerators);
            m31.storePacked(
                numerators,
                m31.addPacked(accumulated, m31.mulPacked(base, coefficient_vectors[coordinate])),
            );
        }
    }
    while (row < values.len) : (row += 1) {
        const base = values[row];
        inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
            const numerator = numerator_planes[coordinate] + row;
            numerator[0] = numerator[0].add(base.mul(coefficients[coordinate]));
        }
    }
}

fn executeScalar(work: *Work) !void {
    var tile_start = work.start;
    var walk = domain_walk.BitReversedCosetWalk.init(
        work.domain,
        work.lifting_log_size,
        work.start,
    );
    while (tile_start < work.end) {
        const tile_end = @min(work.end, tile_start + tile_sink.DEFAULT_TILE_ROWS);
        for (tile_start..tile_end) |position| {
            const domain_point = walk.next();
            try work.workspace.beginRow(domain_point);
            for (work.column_views, work.contribution_ranges) |view, contribution_range| {
                const source_index = if (view.is_direct)
                    position
                else
                    ((position >> view.shift_amt) << 1) + (position & 1);
                const base = view.values[source_index];
                for (work.contributions[contribution_range.start..][0..contribution_range.len]) |contribution| {
                    work.workspace.batch_numerators[contribution.batch_index] =
                        work.workspace.batch_numerators[contribution.batch_index].add(
                            contribution.value_coeff.mulM31(base),
                        );
                }
            }
            for (work.compact_groups) |group| {
                work.workspace.batch_numerators[group.batch_index] =
                    work.workspace.batch_numerators[group.batch_index].add(
                        compact_groups.scalarValueAt(group, position),
                    );
            }
            try writeRow(work, position, domain_point.y, work.workspace.denominator_inverses);
        }
        try emitTile(work, tile_start, tile_end);
        tile_start = tile_end;
    }
}

/// Karatsuba CM31 multiply over four packed rows. Identical field
/// operations to the scalar CM31.mul, one row per lane.
inline fn mulCM31Vec4(
    lhs_re: m31.Vec4u32,
    lhs_im: m31.Vec4u32,
    rhs_re: m31.Vec4u32,
    rhs_im: m31.Vec4u32,
) struct { re: m31.Vec4u32, im: m31.Vec4u32 } {
    const ac = m31.mulVec4(lhs_re, rhs_re);
    const bd = m31.mulVec4(lhs_im, rhs_im);
    const cross = m31.mulVec4(
        m31.addVec4(lhs_re, lhs_im),
        m31.addVec4(rhs_re, rhs_im),
    );
    return .{
        .re = m31.subVec4(ac, bd),
        .im = m31.subVec4(m31.subVec4(cross, ac), bd),
    };
}

/// Finalizes one quotient for VEC_WIDTH rows in packed lanes.
///
/// Computes, per row, sum over batches of
/// `(numerator_batch - linear_term_batch(y)) * denominator_inverse_batch`,
/// reading numerator coordinate planes directly (no per-row QM31 repack).
/// Every operation is the same exact field arithmetic as
/// `quotients.finalizeRowQuotients`, so each output cell is byte-identical
/// to the scalar row loop.
fn finalizeGroupVec4(
    quotient_constants: *const quotients.QuotientConstants,
    ys: m31.Vec4u32,
    scratch: *const Scratch,
    row: usize,
) [qm31.SECURE_EXTENSION_DEGREE]m31.Vec4u32 {
    var acc: [qm31.SECURE_EXTENSION_DEGREE]m31.Vec4u32 = @splat(@splat(0));
    for (quotient_constants.batch_linear_terms, 0..) |linear_term, batch| {
        const a_coords = linear_term.sum_a.toM31Array();
        const b_coords = linear_term.sum_b.toM31Array();
        var diff: [qm31.SECURE_EXTENSION_DEGREE]m31.Vec4u32 = undefined;
        inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
            const lt = m31.addVec4(
                m31.mulVec4(@as(m31.Vec4u32, @splat(a_coords[coordinate].v)), ys),
                @as(m31.Vec4u32, @splat(b_coords[coordinate].v)),
            );
            const plane = batch * qm31.SECURE_EXTENSION_DEGREE + coordinate;
            diff[coordinate] = m31.subVec4(
                m31.loadVec4(scratch.numerators.ptr + plane * scratch.row_capacity + row),
                lt,
            );
        }
        const inverse_words: [*]const M31 = @ptrCast(
            scratch.row_scratch.batchMajorInversePtr(batch, row),
        );
        const inverse_lo = m31.loadVec4(inverse_words);
        const inverse_hi = m31.loadVec4(inverse_words + m31.VEC_WIDTH);
        const inv_re = @shuffle(
            u32,
            inverse_lo,
            inverse_hi,
            @Vector(4, i32){ 0, 2, -1, -3 },
        );
        const inv_im = @shuffle(
            u32,
            inverse_lo,
            inverse_hi,
            @Vector(4, i32){ 1, 3, -2, -4 },
        );
        const q0 = mulCM31Vec4(diff[0], diff[1], inv_re, inv_im);
        const q1 = mulCM31Vec4(diff[2], diff[3], inv_re, inv_im);
        acc[0] = m31.addVec4(acc[0], q0.re);
        acc[1] = m31.addVec4(acc[1], q0.im);
        acc[2] = m31.addVec4(acc[2], q1.re);
        acc[3] = m31.addVec4(acc[3], q1.im);
    }
    return acc;
}

fn writeRow(work: *Work, position: usize, domain_y: M31, inverses: []const CM31) !void {
    const quotient = try quotients.finalizeRowQuotients(
        work.quotient_constants,
        domain_y,
        work.workspace.batch_numerators,
        inverses,
    );
    const coordinates = quotient.toM31Array();
    inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
        work.out_columns[coordinate][position - work.output_start] = coordinates[coordinate];
    }
}

fn emitTile(work: *Work, start: usize, end: usize) !void {
    const writer = work.tile_writer orelse return;
    const local_start = start - work.output_start;
    const local_end = end - work.output_start;
    var coordinates: [qm31.SECURE_EXTENSION_DEGREE][]const M31 = undefined;
    inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
        coordinates[coordinate] = work.out_columns[coordinate][local_start..local_end];
    }
    try writer.absorb(.{ .start = start, .coordinates = coordinates });
    work.completed_tiles += 1;
}

pub fn worker(work: *Work) void {
    execute(work) catch |err| {
        work.failure = err;
    };
}

pub const ParallelRequest = struct {
    out_columns: [qm31.SECURE_EXTENSION_DEGREE][]M31,
    domain_size: usize,
    sample_batches: []const quotients.ColumnSampleBatch,
    use_batched_inversion: bool,
    allow_parallel_scalar: bool,
    domain: CircleDomain,
    compact_groups: []const compact_groups.Group = &.{},
    column_views: []const row_executor.LiftingColumnView,
    contribution_ranges: []const row_executor.ColumnContributionRange,
    contributions: []const row_executor.ColumnContribution,
    quotient_constants: *const quotients.QuotientConstants,
    lifting_log_size: u32,
    factory: ?tile_sink.Factory,
    combined_intermediate_bytes: usize = 0,
};

pub fn executeParallel(
    allocator: std.mem.Allocator,
    request: ParallelRequest,
) !?tile_sink.ExecutionStats {
    if (!request.use_batched_inversion and !request.allow_parallel_scalar) return null;
    const pool = work_pool_mod.getGlobalPool() orelse return null;
    const worker_count = @min(
        pool.workerCount(),
        request.domain_size / MIN_POSITIONS_PER_WORKER,
    );
    if (worker_count <= 1) return null;

    const workspaces = try allocator.alloc(quotients.RowQuotientWorkspace, worker_count);
    defer allocator.free(workspaces);
    var initialized_workspaces: usize = 0;
    defer for (workspaces[0..initialized_workspaces]) |*workspace| workspace.deinit(allocator);
    for (workspaces) |*workspace| {
        workspace.* = try quotients.RowQuotientWorkspace.init(
            allocator,
            request.sample_batches,
        );
        initialized_workspaces += 1;
    }

    const worker_span = try row_executor.workerSpan(request.domain_size, worker_count);
    var scratches: ?[]Scratch = null;
    var initialized_scratches: usize = 0;
    defer if (scratches) |values| {
        for (values[0..initialized_scratches]) |*scratch| scratch.deinit(allocator);
        allocator.free(values);
    };
    if (request.use_batched_inversion) {
        scratches = try allocator.alloc(Scratch, worker_count);
        for (scratches.?) |*scratch| {
            scratch.* = initParallelScratch(
                allocator,
                request.sample_batches.len,
                @min(worker_span, tile_sink.DEFAULT_TILE_ROWS),
                request.domain_size,
            ) catch |err| switch (err) {
                error.ParallelUnavailable => return null,
                else => return err,
            };
            initialized_scratches += 1;
        }
    }

    var work_items: [work_pool_mod.MAX_WORKERS]Work = undefined;
    for (0..worker_count) |worker_index| {
        const range = try row_executor.workerRange(
            request.domain_size,
            worker_span,
            worker_index,
        );
        const writer = if (request.factory) |factory|
            try factory.prepareWriter(worker_index, .{ .start = range.start, .end = range.end })
        else
            null;
        work_items[worker_index] = .{
            .out_columns = request.out_columns,
            .start = range.start,
            .end = range.end,
            .workspace = &workspaces[worker_index],
            .scratch = if (scratches) |values| &values[worker_index] else null,
            .domain = request.domain,
            .compact_groups = request.compact_groups,
            .column_views = request.column_views,
            .contribution_ranges = request.contribution_ranges,
            .contributions = request.contributions,
            .quotient_constants = request.quotient_constants,
            .lifting_log_size = request.lifting_log_size,
            .tile_writer = writer,
        };
    }

    var wait_group: std.Thread.WaitGroup = .{};
    for (work_items[1..worker_count]) |*work| {
        pool.spawnWg(&wait_group, worker, .{work});
    }
    worker(&work_items[0]);
    wait_group.wait();
    for (work_items[0..worker_count]) |work| {
        if (work.failure) |err| return err;
    }
    if (request.factory) |factory| try factory.finishWriters(worker_count);

    var tile_count: usize = 0;
    for (work_items[0..worker_count]) |work| tile_count += work.completed_tiles;
    var total_scratch_bytes: usize = 0;
    var peak_scratch_bytes: usize = 0;
    var peak_numerator_bytes: usize = 0;
    if (scratches) |values| {
        for (values) |scratch| {
            const retained = scratch.retainedBytes();
            total_scratch_bytes = std.math.add(usize, total_scratch_bytes, retained) catch
                return error.ScratchSizeOverflow;
            peak_scratch_bytes = @max(peak_scratch_bytes, retained);
            peak_numerator_bytes = @max(peak_numerator_bytes, scratch.numeratorBytes());
        }
    }
    return .{
        .tile_pipeline_selected = request.factory != null,
        .worker_count = worker_count,
        .tile_row_limit = tile_sink.DEFAULT_TILE_ROWS,
        .tile_count = tile_count,
        .peak_scratch_bytes_per_worker = peak_scratch_bytes,
        .total_scratch_bytes = total_scratch_bytes,
        .bounded_numerator_tile_bytes_per_worker = peak_numerator_bytes,
        .complete_column_combined_intermediate_bytes = request.combined_intermediate_bytes,
        .post_compute_leaf_pass_count = if (request.factory == null) 1 else 0,
    };
}

test "quotient tile scratch is bounded and rejects overflowing geometry" {
    var scratch = try Scratch.init(std.testing.allocator, 3, tile_sink.DEFAULT_TILE_ROWS);
    defer scratch.deinit(std.testing.allocator);
    try std.testing.expect(scratch.row_capacity <= tile_sink.DEFAULT_TILE_ROWS);
    try std.testing.expect(scratch.retainedBytes() <= MAX_SCRATCH_BYTES_PER_WORKER);
    try std.testing.expect(scratch.numeratorBytes() > 0);
    try std.testing.expectError(
        error.ScratchMemoryLimitExceeded,
        rowCapacityForBatchCount(MAX_SCRATCH_BYTES_PER_WORKER, 1),
    );
    try std.testing.expectError(
        error.ScratchSizeOverflow,
        rowCapacityForBatchCount(std.math.maxInt(usize), 1),
    );
}

test "quotient tile input policy selects only the measured batched domain" {
    try std.testing.expect(!shouldUseBoundedInput(12));
    try std.testing.expect(shouldUseBoundedInput(13));
    try std.testing.expect(shouldUseBoundedInput(14));
}

test "lifted run accumulation matches scalar lifting across boundaries" {
    var scratch = try Scratch.init(std.testing.allocator, 1, 37);
    defer scratch.deinit(std.testing.allocator);
    var values: [64]M31 = undefined;
    for (&values, 0..) |*value, i| value.* = M31.fromCanonical(@intCast(i * 97 + 11));
    const coefficients = [qm31.SECURE_EXTENSION_DEGREE]M31{
        M31.fromCanonical(3), M31.fromCanonical(5),
        M31.fromCanonical(7), M31.fromCanonical(11),
    };
    const Case = struct { shift: u6, start: usize, len: usize };
    for ([_]Case{
        .{ .shift = 2, .start = 0, .len = 37 },
        .{ .shift = 3, .start = 3, .len = 31 },
        .{ .shift = 7, .start = 5, .len = 29 },
    }) |case| {
        @memset(scratch.numerators, M31.zero());
        accumulateLiftedRuns(&scratch, &values, case.shift, case.start, case.len, 0, coefficients);
        for (0..case.len) |row| {
            const position = case.start + row;
            const source_index = ((position >> case.shift) << 1) + (position & 1);
            inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
                try std.testing.expectEqual(
                    values[source_index].mul(coefficients[coordinate]).v,
                    scratch.numerator(0, coordinate, row).v,
                );
            }
        }
    }
}

test "packed finalize matches scalar finalizeRowQuotients for all batch counts" {
    const allocator = std.testing.allocator;
    var rng_state: u64 = 0x9e3779b97f4a7c15;
    const nextM31 = struct {
        fn next(state: *u64) M31 {
            state.* ^= state.* << 13;
            state.* ^= state.* >> 7;
            state.* ^= state.* << 17;
            return M31.fromCanonical(@intCast(state.* % 2147483647));
        }
    }.next;

    for ([_]usize{ 1, 2, 3 }) |batch_count| {
        const line_coeffs = try allocator.alloc([]constraints.LineCoeffs, batch_count);
        defer allocator.free(line_coeffs);
        for (line_coeffs) |*lc| lc.* = &[_]constraints.LineCoeffs{};
        var constants: quotients.QuotientConstants = undefined;
        constants.line_coeffs = line_coeffs;
        constants.batch_linear_terms = try allocator.alloc(
            std.meta.Child(@TypeOf(constants.batch_linear_terms)),
            batch_count,
        );
        defer allocator.free(constants.batch_linear_terms);
        for (constants.batch_linear_terms) |*term| {
            term.* = .{
                .sum_a = QM31.fromM31(nextM31(&rng_state), nextM31(&rng_state), nextM31(&rng_state), nextM31(&rng_state)),
                .sum_b = QM31.fromM31(nextM31(&rng_state), nextM31(&rng_state), nextM31(&rng_state), nextM31(&rng_state)),
            };
        }

        const row_capacity: usize = 8;
        var scratch = try Scratch.init(allocator, batch_count, row_capacity);
        defer scratch.deinit(allocator);
        for (scratch.numerators) |*v| v.* = nextM31(&rng_state);

        var ys: [row_capacity]M31 = undefined;
        var inverses: [row_capacity][]CM31 = undefined;
        var inverse_storage: [row_capacity * 3]CM31 = undefined;
        for (0..row_capacity) |row| {
            ys[row] = nextM31(&rng_state);
            inverses[row] = inverse_storage[row * batch_count ..][0..batch_count];
            for (0..batch_count) |batch| {
                inverses[row][batch] = CM31.fromM31(nextM31(&rng_state), nextM31(&rng_state));
            }
        }
        scratch.row_scratch.prepared_rows = row_capacity;
        scratch.row_scratch.inverse_layout = .batch_major;
        for (0..batch_count) |batch| {
            for (0..row_capacity) |row| {
                scratch.row_scratch.denominator_inverses[batch * row_capacity + row] =
                    inverses[row][batch];
            }
        }

        for ([_]usize{ 0, 4 }) |row| {
            const packed_q = finalizeGroupVec4(
                &constants,
                m31.loadVec4(ys[row..].ptr),
                &scratch,
                row,
            );
            inline for (0..m31.VEC_WIDTH) |lane| {
                var numerators: [3]QM31 = undefined;
                for (0..batch_count) |batch| {
                    numerators[batch] = QM31.fromM31(
                        scratch.numerator(batch, 0, row + lane).*,
                        scratch.numerator(batch, 1, row + lane).*,
                        scratch.numerator(batch, 2, row + lane).*,
                        scratch.numerator(batch, 3, row + lane).*,
                    );
                }
                const scalar_q = try quotients.finalizeRowQuotients(
                    &constants,
                    ys[row + lane],
                    numerators[0..batch_count],
                    inverses[row + lane],
                );
                const scalar_coords = scalar_q.toM31Array();
                inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
                    try std.testing.expectEqual(
                        scalar_coords[coordinate].v,
                        packed_q[coordinate][lane],
                    );
                }
            }
        }
    }
}
