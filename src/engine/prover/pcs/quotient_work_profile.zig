//! Exact logical-work geometry for PCS quotient preparation and row execution.
//!
//! This module mirrors whole-operation schedules, never scalar field methods.
//! The ordinary prover passes no recorder and therefore performs no tally
//! walk. Profiled paths derive one checked receipt only after the corresponding
//! preparation/range/device transaction succeeds.

const std = @import("std");
const builtin = @import("builtin");
const core = @import("stwo_core");
const work_profile = @import("stwo_prover_api").work_profile;

const CircleDomain = core.poly.circle.domain.CircleDomain;

pub const WorkRecorder = work_profile.Recorder(true);

const ArithmeticError = error{CounterOverflow};

fn add(lhs: u64, rhs: u64) ArithmeticError!u64 {
    return std.math.add(u64, lhs, rhs) catch error.CounterOverflow;
}

fn mul(lhs: u64, rhs: u64) ArithmeticError!u64 {
    return std.math.mul(u64, lhs, rhs) catch error.CounterOverflow;
}

fn usizeToU64(value: usize) ArithmeticError!u64 {
    return std.math.cast(u64, value) orelse error.CounterOverflow;
}

/// Derives transcript/sample geometry independently, then binds it to the
/// sample batches and contribution plan that preparation actually produced.
pub fn preparationExecution(
    column_log_sizes: anytype,
    sampled_points: anytype,
    lifting_log_size: u32,
    actual_batch_count: usize,
    actual_contribution_count: usize,
) !work_profile.QuotientPreparationExecution {
    if (column_log_sizes.items.len != sampled_points.items.len)
        return error.ShapeMismatch;

    var column_count: u64 = 0;
    var sampled_column_count: u64 = 0;
    var input_sample_count: u64 = 0;
    var periodic_sample_count: u64 = 0;
    var periodicity_doubles: u64 = 0;
    for (sampled_points.items, column_log_sizes.items) |tree_points, tree_logs| {
        if (tree_points.len != tree_logs.len) return error.ShapeMismatch;
        column_count = try add(column_count, try usizeToU64(tree_points.len));
        for (tree_points, tree_logs) |points, log_size| {
            if (points.len == 0) continue;
            if (log_size > lifting_log_size) return error.InvalidColumnLogSize;
            sampled_column_count = try add(sampled_column_count, 1);
            input_sample_count = try add(
                input_sample_count,
                try usizeToU64(points.len),
            );
            if (points.len == 2) {
                periodic_sample_count = try add(periodic_sample_count, 1);
                periodicity_doubles = try add(periodicity_doubles, @intCast(log_size));
            }
        }
    }

    const execution = work_profile.QuotientPreparationExecution{
        .lifting_log_size = lifting_log_size,
        .tree_count = try usizeToU64(sampled_points.items.len),
        .column_count = column_count,
        .sampled_column_count = sampled_column_count,
        .input_sample_count = input_sample_count,
        .periodic_sample_count = periodic_sample_count,
        .expanded_sample_count = try usizeToU64(actual_contribution_count),
        .distinct_batch_count = try usizeToU64(actual_batch_count),
        .periodicity_doubles = periodicity_doubles,
    };
    try execution.validate();
    return execution;
}

pub fn recordPreparation(
    recorder: ?*WorkRecorder,
    execution: work_profile.QuotientPreparationExecution,
) !void {
    const active = recorder orelse return;
    try active.recordCompletedDelta(.{
        .site = .quotient_sample_preparation,
        .producer = work_profile.boundaryForSite(.quotient_sample_preparation),
        .source_mask = fieldSourceMask(),
        .counters = try execution.exactWork(),
    });
    // work-profile-complete:quotient-sample-preparation
}

pub fn recordRows(
    recorder: ?*WorkRecorder,
    execution: work_profile.QuotientRowExecution,
) !void {
    const active = recorder orelse return;
    try active.recordCompletedDelta(.{
        .site = .quotient_row_execution,
        .producer = work_profile.boundaryForSite(.quotient_row_execution),
        .source_mask = fieldSourceMask(),
        .counters = try execution.exactWork(),
    });
    // work-profile-complete:quotient-row-execution
}

fn fieldSourceMask() work_profile.SourceMask {
    return .{ .bits = work_profile.SourceMask.one(.field_additions).bits |
        work_profile.SourceMask.one(.field_multiplications).bits |
        work_profile.SourceMask.one(.field_inversions).bits };
}

pub const Tally = struct {
    numerator_additions: u64 = 0,
    numerator_multiplications: u64 = 0,
    combined_plan_source_cells: u64 = 0,
    domain_circle_additions: u64 = 0,
    batch_inverse_multiplications: u64 = 0,
    batch_inverse_calls: u64 = 0,

    pub fn merge(self: *Tally, other: Tally) !void {
        const next = Tally{
            .numerator_additions = try add(
                self.numerator_additions,
                other.numerator_additions,
            ),
            .numerator_multiplications = try add(
                self.numerator_multiplications,
                other.numerator_multiplications,
            ),
            .combined_plan_source_cells = try add(
                self.combined_plan_source_cells,
                other.combined_plan_source_cells,
            ),
            .domain_circle_additions = try add(
                self.domain_circle_additions,
                other.domain_circle_additions,
            ),
            .batch_inverse_multiplications = try add(
                self.batch_inverse_multiplications,
                other.batch_inverse_multiplications,
            ),
            .batch_inverse_calls = try add(
                self.batch_inverse_calls,
                other.batch_inverse_calls,
            ),
        };
        self.* = next;
    }
};

pub const InverseSchedule = union(enum) {
    /// One CM31 batch inverse over `rows * sample_batches` per execution chunk.
    batched_rows: usize,
    /// `quotient_scalar_executor` uses 32-row inversion chunks inside each
    /// 256-row output tile while the sample-batch count fits its stack bound.
    scalar_chunked,
    /// Bounded scalar fallback and large-batch streaming invert once per row.
    scalar_per_row,
};

/// Exact selected CM31 batch-inverse schedule on this compilation target.
pub fn batchInverseTally(element_count: usize) !Tally {
    if (element_count == 0) return .{};
    const n = try usizeToU64(element_count);
    var width: u64 = 0;
    if (builtin.cpu.arch == .aarch64 and builtin.zig_backend != .stage2_c) {
        if (element_count >= 32 and element_count & 31 == 0)
            width = 32
        else if (element_count >= 16 and element_count & 15 == 0)
            width = 16
        else if (element_count >= 8 and element_count & 7 == 0)
            width = 8;
    }
    if (width == 0) {
        if (element_count > 8 and element_count & 7 == 0)
            width = 8
        else if (element_count > 4 and element_count & 3 == 0)
            width = 4;
    }
    const multiplications = if (width == 0)
        try mul(n - 1, 3)
    else
        try add(try mul(n, 3), width - 3);
    return .{
        .batch_inverse_multiplications = multiplications,
        .batch_inverse_calls = 1,
    };
}

fn tallyInverseRange(
    tally: *Tally,
    start: usize,
    end: usize,
    sample_batch_count: usize,
    schedule: InverseSchedule,
) !void {
    if (start >= end or sample_batch_count == 0) return error.InvalidRowGeometry;
    switch (schedule) {
        .batched_rows => |capacity| {
            if (capacity == 0) return error.InvalidRowGeometry;
            var at = start;
            while (at < end) {
                const rows = @min(capacity, end - at);
                try tally.merge(try batchInverseTally(
                    try std.math.mul(usize, rows, sample_batch_count),
                ));
                at += rows;
            }
        },
        .scalar_chunked => {
            const tile_rows: usize = 256;
            const inverse_rows: usize = 32;
            var tile_start = start;
            while (tile_start < end) {
                const tile_end = @min(end, tile_start + tile_rows);
                var at = tile_start;
                while (at < tile_end) {
                    const rows = @min(inverse_rows, tile_end - at);
                    try tally.merge(try batchInverseTally(
                        try std.math.mul(usize, rows, sample_batch_count),
                    ));
                    at += rows;
                }
                tile_start = tile_end;
            }
        },
        .scalar_per_row => {
            const one_row = try batchInverseTally(sample_batch_count);
            const rows = try usizeToU64(end - start);
            tally.batch_inverse_multiplications = try add(
                tally.batch_inverse_multiplications,
                try mul(one_row.batch_inverse_multiplications, rows),
            );
            tally.batch_inverse_calls = try add(
                tally.batch_inverse_calls,
                rows,
            );
        },
    }
}

/// Counts all M31 circle additions executed by one bit-reversed walk range:
/// initial point construction, the fixed delta table, and successful advances.
pub fn bitReversedWalkCircleAdditions(
    domain: CircleDomain,
    log_size: u32,
    start: usize,
    end: usize,
) !u64 {
    if (log_size == 0 or log_size >= @bitSizeOf(usize) or
        start >= end or end > (@as(usize, 1) << @intCast(log_size)))
    {
        return error.InvalidRowGeometry;
    }
    const size = @as(usize, 1) << @intCast(log_size);
    const mask = size - 1;
    const initial_position = core.utils.bitReverseIndex(start, log_size);
    const initial_index = domain.indexAt(initial_position).v;
    var circle_additions: u64 = @popCount(initial_index);
    const step = domain.half_coset.step_size;
    for (0..log_size) |c| {
        const hi = @as(usize, 1) << @intCast(log_size - c);
        const lo = @as(usize, 1) << @intCast(log_size - 1 - c);
        const delta = (hi +% lo -% size) & mask;
        circle_additions = try add(
            circle_additions,
            @popCount(step.mul(delta).v),
        );
    }
    for (start..end) |position| {
        if (@ctz(~position) < log_size)
            circle_additions = try add(circle_additions, 1);
    }
    return circle_additions;
}

/// Host materialization used by the small Metal path calls
/// `domain.at(bitReverse(row))` independently for every row.
pub fn materializedDomainCircleAdditions(
    domain: CircleDomain,
    log_size: u32,
) !u64 {
    if (log_size == 0 or log_size >= @bitSizeOf(usize))
        return error.InvalidRowGeometry;
    const rows = @as(usize, 1) << @intCast(log_size);
    var additions: u64 = 0;
    for (0..rows) |row| {
        const position = core.utils.bitReverseIndex(row, log_size);
        additions = try add(additions, @popCount(domain.indexAt(position).v));
    }
    return additions;
}

pub fn streamingRangeTally(
    domain: CircleDomain,
    log_size: u32,
    start: usize,
    end: usize,
    sample_batch_count: usize,
    combined_view_count: usize,
    inverse_schedule: InverseSchedule,
) !Tally {
    if (start >= end) return error.InvalidRowGeometry;
    var result = Tally{
        .numerator_additions = try mul(
            try usizeToU64(end - start),
            try usizeToU64(combined_view_count),
        ),
        .domain_circle_additions = try bitReversedWalkCircleAdditions(
            domain,
            log_size,
            start,
            end,
        ),
    };
    try tallyInverseRange(
        &result,
        start,
        end,
        sample_batch_count,
        inverse_schedule,
    );
    return result;
}

fn sourceBlockCount(start: usize, end: usize, shift: u6) !u64 {
    if (start >= end or shift == 0 or shift >= @bitSizeOf(usize))
        return error.InvalidRowGeometry;
    const first = start >> shift;
    const last = (end - 1) >> shift;
    return try usizeToU64(last - first + 1);
}

/// Exact bounded-input numerator schedule for one successful CPU work range.
/// `column_views` exclude contributions owned by `compact_groups`.
pub fn boundedRangeTally(
    domain: CircleDomain,
    log_size: u32,
    start: usize,
    end: usize,
    sample_batch_count: usize,
    compact_groups: anytype,
    column_views: anytype,
    contribution_ranges: anytype,
    inverse_schedule: InverseSchedule,
) !Tally {
    if (start >= end or column_views.len != contribution_ranges.len)
        return error.InvalidRowGeometry;
    var result = Tally{
        .domain_circle_additions = try bitReversedWalkCircleAdditions(
            domain,
            log_size,
            start,
            end,
        ),
    };
    try tallyInverseRange(
        &result,
        start,
        end,
        sample_batch_count,
        inverse_schedule,
    );

    switch (inverse_schedule) {
        .scalar_per_row => {
            const rows = try usizeToU64(end - start);
            var direct_contributions: u64 = 0;
            for (contribution_ranges) |range|
                direct_contributions = try add(
                    direct_contributions,
                    try usizeToU64(range.len),
                );
            var compact_members: u64 = 0;
            for (compact_groups) |group|
                compact_members = try add(
                    compact_members,
                    try usizeToU64(group.members.len),
                );
            result.numerator_multiplications = try mul(
                rows,
                try add(direct_contributions, try mul(compact_members, 4)),
            );
            result.numerator_additions = try mul(
                rows,
                try add(
                    direct_contributions,
                    try add(compact_members, try usizeToU64(compact_groups.len)),
                ),
            );
        },
        .batched_rows => |capacity| {
            if (capacity == 0) return error.InvalidRowGeometry;
            var chunk_start = start;
            while (chunk_start < end) {
                const chunk_end = @min(end, chunk_start + capacity);
                const rows = try usizeToU64(chunk_end - chunk_start);
                for (column_views, contribution_ranges) |view, range| {
                    const contributions = try usizeToU64(range.len);
                    result.numerator_additions = try add(
                        result.numerator_additions,
                        try mul(try mul(rows, contributions), 4),
                    );
                    const products = if (view.is_direct)
                        try mul(try mul(rows, contributions), 4)
                    else
                        try mul(
                            try mul(
                                try sourceBlockCount(
                                    chunk_start,
                                    chunk_end,
                                    view.shift_amt,
                                ),
                                contributions,
                            ),
                            8,
                        );
                    result.numerator_multiplications = try add(
                        result.numerator_multiplications,
                        products,
                    );
                }
                for (compact_groups) |group| {
                    const blocks = try sourceBlockCount(
                        chunk_start,
                        chunk_end,
                        group.shift_amt,
                    );
                    const members = try usizeToU64(group.members.len);
                    const reduction = try mul(try mul(blocks, members), 8);
                    result.numerator_multiplications = try add(
                        result.numerator_multiplications,
                        reduction,
                    );
                    result.numerator_additions = try add(
                        result.numerator_additions,
                        try add(reduction, try mul(rows, 4)),
                    );
                }
                chunk_start = chunk_end;
            }
        },
        .scalar_chunked => return error.InvalidRowGeometry,
    }
    return result;
}

pub fn combinedPlanSourceCells(
    flat_columns: anytype,
    active_column_indices: []const usize,
    contribution_ranges: anytype,
    nonzero_columns: []const bool,
) !u64 {
    if (active_column_indices.len != contribution_ranges.len or
        flat_columns.len != nonzero_columns.len)
    {
        return error.ShapeMismatch;
    }
    var cells: u64 = 0;
    for (active_column_indices, contribution_ranges) |column_index, range| {
        if (column_index >= flat_columns.len) return error.ShapeMismatch;
        if (!nonzero_columns[column_index]) continue;
        cells = try add(
            cells,
            try mul(
                try usizeToU64(flat_columns[column_index].values.len),
                try usizeToU64(range.len),
            ),
        );
    }
    return cells;
}

pub fn activeContributionCount(
    active_column_indices: []const usize,
    contribution_ranges: anytype,
    nonzero_columns: []const bool,
) !usize {
    if (active_column_indices.len != contribution_ranges.len)
        return error.ShapeMismatch;
    var count: usize = 0;
    for (active_column_indices, contribution_ranges) |column_index, range| {
        if (column_index >= nonzero_columns.len) return error.ShapeMismatch;
        if (!nonzero_columns[column_index]) continue;
        count = std.math.add(usize, count, range.len) catch
            return error.CounterOverflow;
    }
    return count;
}

pub fn executionFromTally(
    path: work_profile.QuotientRowPath,
    lifting_log_size: u32,
    sample_batch_count: usize,
    contribution_count: usize,
    combined_view_count: usize,
    grouped_partial_count: usize,
    tally: Tally,
) !work_profile.QuotientRowExecution {
    if (lifting_log_size >= @bitSizeOf(usize)) return error.InvalidRowGeometry;
    const execution = work_profile.QuotientRowExecution{
        .path = path,
        .lifting_log_size = lifting_log_size,
        .row_count = try usizeToU64(@as(usize, 1) << @intCast(lifting_log_size)),
        .sample_batch_count = try usizeToU64(sample_batch_count),
        .contribution_count = try usizeToU64(contribution_count),
        .combined_view_count = try usizeToU64(combined_view_count),
        .grouped_partial_count = try usizeToU64(grouped_partial_count),
        .numerator_additions = tally.numerator_additions,
        .numerator_multiplications = tally.numerator_multiplications,
        .combined_plan_source_cells = tally.combined_plan_source_cells,
        .domain_circle_additions = tally.domain_circle_additions,
        .batch_inverse_multiplications = tally.batch_inverse_multiplications,
        .batch_inverse_calls = tally.batch_inverse_calls,
    };
    try execution.validate();
    return execution;
}

test "CM31 batch inverse tally follows selected AArch64 widths" {
    const expected_8: u64 = if (builtin.cpu.arch == .aarch64 and
        builtin.zig_backend != .stage2_c) 29 else 25;
    try std.testing.expectEqual(
        expected_8,
        (try batchInverseTally(8)).batch_inverse_multiplications,
    );
    try std.testing.expectEqual(
        @as(u64, 3 * 37 - 3),
        (try batchInverseTally(37)).batch_inverse_multiplications,
    );
}

test "bit-reversed walk tally matches the documented full-walk law" {
    const canonic = core.poly.circle.canonic;
    const log_size: u32 = 6;
    const domain = canonic.CanonicCoset.new(log_size).circleDomain();
    const rows = @as(usize, 1) << @intCast(log_size);
    const actual = try bitReversedWalkCircleAdditions(domain, log_size, 0, rows);

    var expected: u64 = @popCount(domain.indexAt(0).v);
    const step = domain.half_coset.step_size;
    const mask = rows - 1;
    for (0..log_size) |c| {
        const hi = @as(usize, 1) << @intCast(log_size - c);
        const lo = @as(usize, 1) << @intCast(log_size - 1 - c);
        expected += @popCount(step.mul((hi +% lo -% rows) & mask).v);
    }
    expected += rows - 1;
    try std.testing.expectEqual(expected, actual);
}
