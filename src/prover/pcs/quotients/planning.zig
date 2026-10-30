//! Quotient input planning and lifted-column construction.
//!
//! This module owns the allocation-backed plans shared by eager and lazy FRI
//! quotient evaluation. Execution remains in the row and tile executors.

const std = @import("std");
const circle = @import("stwo_core").circle;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const quotients = @import("stwo_core").pcs.quotients;
const pcs_utils = @import("stwo_core").pcs.utils;
const column_geometry = @import("../quotient_column_geometry.zig");
const row_executor = @import("../quotient_row_executor.zig");

const CirclePointQM31 = circle.CirclePointQM31;
const M31 = m31.M31;
const QM31 = qm31.QM31;
const TreeVec = pcs_utils.TreeVec;
const ColumnEvaluation = column_geometry.ColumnEvaluation;
const ColumnContribution = row_executor.ColumnContribution;
const ColumnContributionRange = row_executor.ColumnContributionRange;
const CombinedContributionView = row_executor.CombinedContributionView;
const LiftingColumnView = row_executor.LiftingColumnView;
const QuotientOpsError = column_geometry.QuotientOpsError;

const materialize_lifted_threshold_bytes: usize = 48 * 1024 * 1024;
const streaming_domain_threshold: usize = 1 << 12;
const streaming_active_column_threshold: usize = 1024;

pub const CombinedContributionPlan = struct {
    views: []CombinedContributionView,

    pub fn deinit(self: *CombinedContributionPlan, allocator: std.mem.Allocator) void {
        for (self.views) |view| {
            view.deinitCoordinates(allocator);
        }
        allocator.free(self.views);
        self.* = undefined;
    }
};

/// Inputs remain borrowed until the backend has synchronously joined the fold.
/// Coordinate planes share one owner on the native coefficient path.
pub const CoefficientFoldJob = struct {
    source: []const M31,
    coordinates: [qm31.SECURE_EXTENSION_DEGREE][]M31,
    coefficients: [qm31.SECURE_EXTENSION_DEGREE]M31,
};

/// A pointer borrows the original immutable values; the length is shared by
/// the group. The coefficient index borrows the already-owned sample plan.
/// This halves metadata without retaining temporary flattened column headers.
pub const CompactContributionMember = struct {
    values: [*]const M31,
    contribution_index: u32,
};

pub const CompactContributionGroup = struct {
    members: []const CompactContributionMember,
    value_count: usize,
    contributions: []const ColumnContribution,

    batch_index: usize,
    shift_amt: std.math.Log2Int(usize),

    pub fn member(self: @This(), index: usize) struct { values: []const M31, coefficients: [4]M31 } {
        const entry = self.members[index];
        return .{ .values = entry.values[0..self.value_count], .coefficients = self.contributions[entry.contribution_index].value_coeff.toM31Array() };
    }
};

pub const CompactContributionPlan = struct {
    groups: []CompactContributionGroup,
    members: []CompactContributionMember,
    minimum_shift: std.math.Log2Int(usize) = 2,
    /// Exact original contribution indices owned by groups. Empty on the
    /// historical whole-tier plan. Charged to the same metadata cap.
    selected: []u8 = &.{},

    pub fn deinit(self: *CompactContributionPlan, allocator: std.mem.Allocator) void {
        allocator.free(self.groups);
        allocator.free(self.members);
        allocator.free(self.selected);
        self.* = undefined;
    }

    pub fn retainedBytes(self: CompactContributionPlan) usize {
        return self.groups.len * @sizeOf(CompactContributionGroup) +
            self.members.len * @sizeOf(CompactContributionMember) + self.selected.len;
    }
};

pub const ColumnContributionPlan = struct {
    active_column_indices: []usize,
    ranges: []ColumnContributionRange,
    contributions: []ColumnContribution,

    pub fn deinit(self: *ColumnContributionPlan, allocator: std.mem.Allocator) void {
        allocator.free(self.active_column_indices);
        allocator.free(self.ranges);
        allocator.free(self.contributions);
        self.* = undefined;
    }

    pub fn activeColumnCount(self: ColumnContributionPlan) usize {
        return self.active_column_indices.len;
    }

    pub fn totalContributions(self: ColumnContributionPlan) usize {
        return self.contributions.len;
    }
};

pub const ConstructionStrategy = enum {
    materialized,
    streaming,
};

pub const PreparedContext = struct {
    sample_batches: []quotients.ColumnSampleBatch,
    quotient_constants: quotients.QuotientConstants,
    contribution_plan: ColumnContributionPlan,

    pub fn deinit(self: *PreparedContext, allocator: std.mem.Allocator) void {
        self.contribution_plan.deinit(allocator);
        self.quotient_constants.deinit(allocator);
        quotients.ColumnSampleBatch.deinitSlice(allocator, self.sample_batches);
        self.* = undefined;
    }
};

pub const MaterializedLiftedColumns = struct {
    storage: []M31,
    columns: [][]M31,

    pub fn deinit(self: *MaterializedLiftedColumns, allocator: std.mem.Allocator) void {
        allocator.free(self.columns);
        allocator.free(self.storage);
        self.* = undefined;
    }
};

pub fn prepareContext(
    allocator: std.mem.Allocator,
    column_log_sizes: TreeVec([]u32),
    sampled_points: TreeVec([][]CirclePointQM31),
    sampled_values: TreeVec([][]QM31),
    random_coeff: QM31,
    lifting_log_size: u32,
    flat_column_count: usize,
) !PreparedContext {
    const sample_batches = try quotients.buildColumnSampleBatchesFromParallelInputs(
        allocator,
        sampled_points,
        sampled_values,
        column_log_sizes,
        lifting_log_size,
        random_coeff,
    );
    errdefer quotients.ColumnSampleBatch.deinitSlice(allocator, sample_batches);

    var quotient_constants = try quotients.quotientConstants(allocator, sample_batches);
    errdefer quotient_constants.deinit(allocator);

    try validateSampleBatchColumnIndices(sample_batches, flat_column_count);
    var contribution_plan = try buildColumnContributionPlan(
        allocator,
        sample_batches,
        &quotient_constants,
        flat_column_count,
    );
    errdefer contribution_plan.deinit(allocator);

    return .{
        .sample_batches = sample_batches,
        .quotient_constants = quotient_constants,
        .contribution_plan = contribution_plan,
    };
}

fn buildColumnContributionPlan(
    allocator: std.mem.Allocator,
    sample_batches: []const quotients.ColumnSampleBatch,
    quotient_constants: *const quotients.QuotientConstants,
    column_count: usize,
) !ColumnContributionPlan {
    const counts = try allocator.alloc(usize, column_count);
    defer allocator.free(counts);
    @memset(counts, 0);

    var total_contributions: usize = 0;
    var active_column_count: usize = 0;
    for (sample_batches) |batch| {
        for (batch.cols_vals_randpows) |sample_data| {
            if (sample_data.column_index >= column_count) return QuotientOpsError.ShapeMismatch;
            if (counts[sample_data.column_index] == 0) active_column_count += 1;
            counts[sample_data.column_index] += 1;
            total_contributions += 1;
        }
    }

    const active_column_indices = try allocator.alloc(usize, active_column_count);
    errdefer allocator.free(active_column_indices);
    const ranges = try allocator.alloc(ColumnContributionRange, active_column_count);
    errdefer allocator.free(ranges);

    const invalid_active_index = std.math.maxInt(usize);
    const column_to_active = try allocator.alloc(usize, column_count);
    defer allocator.free(column_to_active);
    @memset(column_to_active, invalid_active_index);

    var at: usize = 0;
    var active_idx: usize = 0;
    for (counts, 0..) |count, col_idx| {
        if (count == 0) continue;
        active_column_indices[active_idx] = col_idx;
        column_to_active[col_idx] = active_idx;
        ranges[active_idx] = .{ .start = at, .len = count };
        at += count;
        active_idx += 1;
    }
    std.debug.assert(at == total_contributions);
    std.debug.assert(active_idx == active_column_count);

    const next_offsets = try allocator.alloc(usize, active_column_count);
    defer allocator.free(next_offsets);
    for (ranges, 0..) |range, idx| next_offsets[idx] = range.start;

    const contributions = try allocator.alloc(ColumnContribution, total_contributions);
    errdefer allocator.free(contributions);
    for (sample_batches, 0..) |batch, batch_idx| {
        const line_coeffs = quotient_constants.line_coeffs[batch_idx];
        if (line_coeffs.len != batch.cols_vals_randpows.len) return QuotientOpsError.ShapeMismatch;
        for (batch.cols_vals_randpows, 0..) |sample_data, coeff_idx| {
            const mapped_active_idx = column_to_active[sample_data.column_index];
            if (mapped_active_idx == invalid_active_index) return QuotientOpsError.ShapeMismatch;
            const write_idx = next_offsets[mapped_active_idx];
            contributions[write_idx] = .{
                .batch_index = batch_idx,
                .value_coeff = line_coeffs[coeff_idx].c,
            };
            next_offsets[mapped_active_idx] = write_idx + 1;
        }
    }

    return .{
        .active_column_indices = active_column_indices,
        .ranges = ranges,
        .contributions = contributions,
    };
}

pub fn chooseConstructionStrategy(
    active_column_count: usize,
    domain_size: usize,
) ConstructionStrategy {
    if (domain_size >= streaming_domain_threshold and
        active_column_count > streaming_active_column_threshold)
    {
        return .streaming;
    }

    const lifted_cells = std.math.mul(usize, active_column_count, domain_size) catch return .streaming;
    const lifted_bytes = std.math.mul(usize, lifted_cells, @sizeOf(M31)) catch return .streaming;
    return if (lifted_bytes > materialize_lifted_threshold_bytes)
        .streaming
    else
        .materialized;
}

fn buildActiveLiftingColumnViews(
    allocator: std.mem.Allocator,
    flat_columns: []const ColumnEvaluation,
    active_column_indices: []const usize,
    lifting_log_size: u32,
) ![]LiftingColumnView {
    const views = try allocator.alloc(LiftingColumnView, active_column_indices.len);
    errdefer allocator.free(views);

    for (active_column_indices, 0..) |column_idx, active_idx| {
        if (column_idx >= flat_columns.len) return QuotientOpsError.ShapeMismatch;
        const column = flat_columns[column_idx];
        if (column.log_size > lifting_log_size) return QuotientOpsError.InvalidColumnLogSize;
        const log_shift = lifting_log_size - column.log_size;
        if (log_shift >= @bitSizeOf(usize)) return QuotientOpsError.InvalidColumnLogSize;
        views[active_idx] = .{
            .values = column.values,
            .shift_amt = @intCast(log_shift + 1),
            .is_direct = column.log_size == lifting_log_size,
        };
    }

    return views;
}

pub fn markNonzeroColumnsAndSamples(
    allocator: std.mem.Allocator,
    columns: TreeVec([]const ColumnEvaluation),
    sampled_values: TreeVec([][]QM31),
) ![]bool {
    const nonzero = try allocator.alloc(bool, column_geometry.countColumns(columns));
    errdefer allocator.free(nonzero);

    var flat_idx: usize = 0;
    for (columns.items, sampled_values.items) |tree_columns, tree_samples| {
        if (tree_columns.len != tree_samples.len) return QuotientOpsError.ShapeMismatch;
        for (tree_columns, tree_samples) |column, samples| {
            var has_nonzero = false;
            for (column.coefficient_values orelse column.values) |value| {
                if (!value.isZero()) {
                    has_nonzero = true;
                    break;
                }
            }
            if (!has_nonzero) {
                for (samples) |value| {
                    if (!value.eql(QM31.zero())) {
                        has_nonzero = true;
                        break;
                    }
                }
            }
            nonzero[flat_idx] = has_nonzero;
            flat_idx += 1;
        }
    }
    std.debug.assert(flat_idx == nonzero.len);
    return nonzero;
}

pub fn buildCombinedContributionPlan(
    allocator: std.mem.Allocator,
    flat_columns: []const ColumnEvaluation,
    active_column_indices: []const usize,
    contribution_ranges: []const ColumnContributionRange,
    contributions: []const ColumnContribution,
    nonzero_columns: []const bool,
    lifting_log_size: u32,
) !CombinedContributionPlan {
    return buildCombinedContributionPlanForBackend(void, allocator, flat_columns, active_column_indices, contribution_ranges, contributions, nonzero_columns, lifting_log_size);
}

pub fn buildCombinedContributionPlanForBackend(
    comptime B: type,
    allocator: std.mem.Allocator,
    flat_columns: []const ColumnEvaluation,
    active_column_indices: []const usize,
    contribution_ranges: []const ColumnContributionRange,
    contributions: []const ColumnContribution,
    nonzero_columns: []const bool,
    lifting_log_size: u32,
) !CombinedContributionPlan {
    if (active_column_indices.len != contribution_ranges.len or
        flat_columns.len != nonzero_columns.len)
    {
        return QuotientOpsError.ShapeMismatch;
    }

    var coefficient_groups = std.ArrayList(bool).empty;
    defer coefficient_groups.deinit(allocator);
    const native_fold = comptime B != void and @hasDecl(B, "foldCoefficientContributions");
    var fold_jobs = std.ArrayList(CoefficientFoldJob).empty;
    defer fold_jobs.deinit(allocator);
    var views = std.ArrayList(CombinedContributionView).empty;
    defer views.deinit(allocator);
    errdefer for (views.items) |view| {
        view.deinitCoordinates(allocator);
    };

    for (active_column_indices, contribution_ranges) |column_idx, contribution_range| {
        if (column_idx >= nonzero_columns.len or column_idx >= flat_columns.len) {
            return QuotientOpsError.ShapeMismatch;
        }
        if (!nonzero_columns[column_idx]) continue;
        const column = flat_columns[column_idx];
        try column.validateRetained();
        const source = column.coefficient_values orelse column.values;
        const size = try column_geometry.checkedPow2(column.log_size);
        const coefficient_basis = column.coefficient_values != null;
        if (column.log_size > lifting_log_size) return QuotientOpsError.InvalidColumnLogSize;
        const log_shift = lifting_log_size - column.log_size;
        if (log_shift >= @bitSizeOf(usize)) return QuotientOpsError.InvalidColumnLogSize;
        const shift_amt: std.math.Log2Int(usize) = @intCast(log_shift + 1);

        const column_contributions = contributions[contribution_range.start .. contribution_range.start + contribution_range.len];
        for (column_contributions) |contribution| {
            var view_index: ?usize = null;
            var created = false;
            for (views.items, 0..) |view, i| {
                if (view.batch_index == contribution.batch_index and
                    view.coordinates[0].len == size and coefficient_groups.items[i] == coefficient_basis)
                {
                    view_index = i;
                    break;
                }
            }

            if (view_index == null) {
                var coordinates: [qm31.SECURE_EXTENSION_DEGREE][]M31 = undefined;
                var backing: ?[]align(std.heap.page_size_max) M31 = null;
                var initialized: usize = 0;
                errdefer if (backing) |owner| allocator.free(owner) else for (coordinates[0..initialized]) |coordinate| allocator.free(coordinate);
                const native_fft = comptime B != void and @hasDecl(B, "evaluateCircleBuffers");
                if (native_fft and coefficient_basis) {
                    backing = try allocator.alignedAlloc(M31, comptime std.mem.Alignment.fromByteUnits(std.heap.page_size_max), try std.math.mul(usize, size, qm31.SECURE_EXTENSION_DEGREE));
                    inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coord| coordinates[coord] = backing.?[coord * size ..][0..size];
                } else inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coord| {
                    coordinates[coord] = try allocator.alloc(M31, size);
                    initialized += 1;
                }
                try coefficient_groups.append(allocator, coefficient_basis);
                try views.append(allocator, .{
                    .coordinates = coordinates,
                    .coordinate_backing = backing,
                    .batch_index = contribution.batch_index,
                    .shift_amt = shift_amt,
                    .is_direct = column.log_size == lifting_log_size,
                });
                view_index = views.items.len - 1;
                created = true;
            }

            const coeffs = contribution.value_coeff.toM31Array();
            const view = &views.items[view_index.?];
            if (native_fold and coefficient_basis) {
                try fold_jobs.append(allocator, .{ .source = source, .coordinates = view.coordinates, .coefficients = coeffs });
                continue;
            }
            inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coord| {
                if (created) {
                    @memset(view.coordinates[coord][source.len..], M31.zero());
                    scaleColumn(
                        view.coordinates[coord][0..source.len],
                        source,
                        coeffs[coord],
                    );
                } else {
                    addScaledColumn(
                        view.coordinates[coord][0..source.len],
                        source,
                        coeffs[coord],
                    );
                }
            }
        }
    }

    if (native_fold and fold_jobs.items.len != 0) try B.foldCoefficientContributions(allocator, fold_jobs.items);

    // Fold in the native basis first: four FFTs per (sample, domain) group,
    // instead of materializing an LDE for every committed column.
    const poly = @import("../../poly/circle/mod.zig");
    const twiddles = @import("../../poly/twiddles.zig");
    for (views.items, coefficient_groups.items) |view, coefficient_basis| {
        if (!coefficient_basis) continue;
        const log: u32 = @intCast(std.math.log2_int(usize, view.coordinates[0].len));
        const domain = poly.CanonicCoset.new(log).circleDomain();
        var transform = try twiddles.precomputeM31(allocator, domain.half_coset);
        defer twiddles.deinitM31(allocator, &transform);
        const borrowed = twiddles.TwiddleTree([]const M31){ .root_coset = transform.root_coset, .twiddles = transform.twiddles, .itwiddles = transform.itwiddles };
        if (comptime B != void and @hasDecl(B, "evaluateCircleBuffers")) {
            _ = try B.evaluateCircleBuffers(allocator, &view.coordinates, domain, borrowed);
        } else try poly.poly.evaluateBuffersWithTwiddles(&view.coordinates, domain, borrowed);
    }
    return .{ .views = try views.toOwnedSlice(allocator) };
}

fn scaleColumn(destination: []M31, source: []const M31, coefficient: M31) void {
    std.debug.assert(destination.len == source.len);
    const coefficient_lanes: m31.Vec4u32 = @splat(coefficient.v);
    var index: usize = 0;
    while (index + m31.VEC_WIDTH <= source.len) : (index += m31.VEC_WIDTH) {
        m31.storeVec4(
            destination.ptr + index,
            m31.mulVec4(m31.loadVec4(source.ptr + index), coefficient_lanes),
        );
    }
    while (index < source.len) : (index += 1) {
        destination[index] = source[index].mul(coefficient);
    }
}

fn addScaledColumn(destination: []M31, source: []const M31, coefficient: M31) void {
    std.debug.assert(destination.len == source.len);
    const coefficient_lanes: m31.Vec4u32 = @splat(coefficient.v);
    var index: usize = 0;
    while (index + m31.VEC_WIDTH <= source.len) : (index += m31.VEC_WIDTH) {
        const product = m31.mulVec4(
            m31.loadVec4(source.ptr + index),
            coefficient_lanes,
        );
        m31.storeVec4(
            destination.ptr + index,
            m31.addVec4(m31.loadVec4(destination.ptr + index), product),
        );
    }
    while (index < source.len) : (index += 1) {
        destination[index] = destination[index].add(source[index].mul(coefficient));
    }
}

test "combined contribution vector kernels preserve scalar tails" {
    const source = [_]M31{
        M31.fromCanonical(1),
        M31.fromCanonical(2),
        M31.fromCanonical(3),
        M31.fromCanonical(4),
        M31.fromCanonical(5),
        M31.fromCanonical(6),
        M31.fromCanonical(7),
        M31.fromCanonical(8),
        M31.fromCanonical(9),
    };
    const coefficient = M31.fromCanonical(17);
    const initial = M31.fromCanonical(23);

    for (0..source.len + 1) |len| {
        var scaled = [_]M31{M31.zero()} ** source.len;
        scaleColumn(scaled[0..len], source[0..len], coefficient);
        for (source[0..len], scaled[0..len]) |value, actual| {
            try std.testing.expectEqual(value.mul(coefficient), actual);
        }

        var accumulated = [_]M31{initial} ** source.len;
        addScaledColumn(accumulated[0..len], source[0..len], coefficient);
        for (source[0..len], accumulated[0..len]) |value, actual| {
            try std.testing.expectEqual(initial.add(value.mul(coefficient)), actual);
        }
    }
}

/// Builds a lightweight grouping plan without materializing coefficient-weighted
/// columns. Workers reduce each group's borrowed compact members in parallel.
/// Optional-plan allocation or byte-budget failure selects the direct fallback;
/// malformed quotient geometry still fails closed.
pub fn buildCompactContributionPlan(
    allocator: std.mem.Allocator,
    flat_columns: []const ColumnEvaluation,
    active_column_indices: []const usize,
    contribution_ranges: []const ColumnContributionRange,
    contributions: []const ColumnContribution,
    nonzero_columns: []const bool,
    lifting_log_size: u32,
    min_shift_amt: std.math.Log2Int(usize),
    max_bytes: usize,
) !?CompactContributionPlan {
    // Keep the highest-reuse lifted groups when a wide roster exceeds the
    // cap. The caller excludes exactly this admitted threshold from its direct
    // path. If even the highest-reuse tier cannot fit, retain the direct
    // fallback; no term may disappear merely to satisfy this optional budget.
    if (lifting_log_size >= @bitSizeOf(usize) - 1) return QuotientOpsError.InvalidColumnLogSize;
    var minimum: u32 = min_shift_amt;
    while (minimum <= lifting_log_size + 1) : (minimum += 1) {
        const plan = buildCompactContributionPlanInner(
            allocator,
            flat_columns,
            active_column_indices,
            contribution_ranges,
            contributions,
            nonzero_columns,
            lifting_log_size,
            @intCast(minimum),
            max_bytes,
            false,
        ) catch |err| switch (err) {
            error.CompactContributionBudgetExceeded => continue,
            error.OutOfMemory => return null,
            else => return err,
        };
        if (plan.groups.len == 0) {
            var empty = plan;
            empty.deinit(allocator);
            return null;
        }
        return plan;
    }
    return null;
}

/// Admit exact members instead of abandoning a whole lift tier. A group may
/// own a prefix of its members; every other contribution stays in the direct
/// plan. The bitset is preparation metadata, never read in the tile hot loop.
pub fn buildPartialCompactContributionPlan(
    allocator: std.mem.Allocator,
    flat_columns: []const ColumnEvaluation,
    active_column_indices: []const usize,
    contribution_ranges: []const ColumnContributionRange,
    contributions: []const ColumnContribution,
    nonzero_columns: []const bool,
    lifting_log_size: u32,
    min_shift_amt: std.math.Log2Int(usize),
    max_bytes: usize,
) !?CompactContributionPlan {
    if (lifting_log_size >= @bitSizeOf(usize) - 1) return QuotientOpsError.InvalidColumnLogSize;
    // The selection bit identifies one occurrence. Require the canonical,
    // disjoint range inventory rather than silently collapsing multiplicity.
    var next: usize = 0;
    for (contribution_ranges) |range| {
        if (range.start != next) return QuotientOpsError.ShapeMismatch;
        next = std.math.add(usize, next, range.len) catch return QuotientOpsError.ShapeMismatch;
    }
    if (next != contributions.len) return QuotientOpsError.ShapeMismatch;
    var plan = buildCompactContributionPlanInner(allocator, flat_columns, active_column_indices, contribution_ranges, contributions, nonzero_columns, lifting_log_size, min_shift_amt, max_bytes, true) catch |err| switch (err) {
        error.CompactContributionBudgetExceeded, error.OutOfMemory => return null,
        else => return err,
    };
    if (plan.groups.len == 0) {
        plan.deinit(allocator);
        return null;
    }
    return plan;
}

const CompactGroupSpec = struct {
    batch_index: usize,
    value_count: usize,
    shift_amt: std.math.Log2Int(usize),
    member_count: usize,
};

fn compactGroupIndex(
    specs: []const CompactGroupSpec,
    batch_index: usize,
    value_count: usize,
    shift_amt: std.math.Log2Int(usize),
) ?usize {
    for (specs, 0..) |spec, index| {
        if (spec.batch_index == batch_index and
            spec.value_count == value_count and
            spec.shift_amt == shift_amt)
        {
            return index;
        }
    }
    return null;
}

fn buildCompactContributionPlanInner(
    allocator: std.mem.Allocator,
    flat_columns: []const ColumnEvaluation,
    active_column_indices: []const usize,
    contribution_ranges: []const ColumnContributionRange,
    contributions: []const ColumnContribution,
    nonzero_columns: []const bool,
    lifting_log_size: u32,
    min_shift_amt: std.math.Log2Int(usize),
    max_bytes: usize,
    partial: bool,
) !CompactContributionPlan {
    if (active_column_indices.len != contribution_ranges.len or
        flat_columns.len != nonzero_columns.len)
    {
        return QuotientOpsError.ShapeMismatch;
    }

    var specs = std.ArrayList(CompactGroupSpec).empty;
    defer specs.deinit(allocator);
    var total_members: usize = 0;
    for (active_column_indices, contribution_ranges) |column_idx, contribution_range| {
        if (column_idx >= flat_columns.len or column_idx >= nonzero_columns.len) {
            return QuotientOpsError.ShapeMismatch;
        }
        if (!nonzero_columns[column_idx]) continue;
        const column = flat_columns[column_idx];
        if (column.log_size > lifting_log_size) return QuotientOpsError.InvalidColumnLogSize;
        const log_shift = lifting_log_size - column.log_size;
        if (log_shift >= @bitSizeOf(usize)) return QuotientOpsError.InvalidColumnLogSize;
        const shift_amt: std.math.Log2Int(usize) = @intCast(log_shift + 1);
        if (shift_amt < min_shift_amt) continue;
        const contribution_end = std.math.add(
            usize,
            contribution_range.start,
            contribution_range.len,
        ) catch return QuotientOpsError.ShapeMismatch;
        if (contribution_end > contributions.len) return QuotientOpsError.ShapeMismatch;
        for (contributions[contribution_range.start..contribution_end]) |contribution| {
            if (compactGroupIndex(
                specs.items,
                contribution.batch_index,
                column.values.len,
                shift_amt,
            )) |index| {
                specs.items[index].member_count = std.math.add(
                    usize,
                    specs.items[index].member_count,
                    1,
                ) catch return error.CompactContributionBudgetExceeded;
            } else {
                try specs.append(allocator, .{
                    .batch_index = contribution.batch_index,
                    .value_count = column.values.len,
                    .shift_amt = shift_amt,
                    .member_count = 1,
                });
            }
            total_members = std.math.add(usize, total_members, 1) catch
                return error.CompactContributionBudgetExceeded;
        }
    }

    const selection_bytes = if (partial) std.math.divCeil(usize, contributions.len, 8) catch return error.CompactContributionBudgetExceeded else 0;
    if (partial) {
        if (selection_bytes > max_bytes) return error.CompactContributionBudgetExceeded;
        // Each admitted term removes a full lifted output sweep. Prefer the
        // greatest reuse; stable tie order makes budget boundary tests exact.
        std.mem.sort(CompactGroupSpec, specs.items, {}, struct {
            fn less(_: void, left: CompactGroupSpec, right: CompactGroupSpec) bool {
                if (left.shift_amt != right.shift_amt) return left.shift_amt > right.shift_amt;
                if (left.batch_index != right.batch_index) return left.batch_index < right.batch_index;
                return left.value_count < right.value_count;
            }
        }.less);
        var remaining = max_bytes - selection_bytes;
        var kept: usize = 0;
        total_members = 0;
        for (specs.items) |spec| {
            if (remaining < @sizeOf(CompactContributionGroup) + @sizeOf(CompactContributionMember)) break;
            const count = @min(spec.member_count, (remaining - @sizeOf(CompactContributionGroup)) / @sizeOf(CompactContributionMember));
            specs.items[kept] = spec;
            specs.items[kept].member_count = count;
            kept += 1;
            total_members += count;
            remaining -= @sizeOf(CompactContributionGroup) + count * @sizeOf(CompactContributionMember);
        }
        specs.shrinkRetainingCapacity(kept);
    }
    const group_bytes = std.math.mul(
        usize,
        specs.items.len,
        @sizeOf(CompactContributionGroup),
    ) catch return error.CompactContributionBudgetExceeded;
    const member_bytes = std.math.mul(
        usize,
        total_members,
        @sizeOf(CompactContributionMember),
    ) catch return error.CompactContributionBudgetExceeded;
    const payload_bytes = std.math.add(usize, group_bytes, member_bytes) catch
        return error.CompactContributionBudgetExceeded;
    const retained_bytes = std.math.add(usize, payload_bytes, selection_bytes) catch return error.CompactContributionBudgetExceeded;
    if (retained_bytes > max_bytes) return error.CompactContributionBudgetExceeded;

    const groups = try allocator.alloc(CompactContributionGroup, specs.items.len);
    errdefer allocator.free(groups);
    const members = try allocator.alloc(CompactContributionMember, total_members);
    errdefer allocator.free(members);
    const selected = try allocator.alloc(u8, selection_bytes);
    errdefer allocator.free(selected);
    @memset(selected, 0);
    const next_offsets = try allocator.alloc(usize, specs.items.len);
    defer allocator.free(next_offsets);

    var member_offset: usize = 0;
    for (specs.items, 0..) |spec, index| {
        const member_end = member_offset + spec.member_count;
        groups[index] = .{
            .members = members[member_offset..member_end],
            .value_count = spec.value_count,
            .contributions = contributions,
            .batch_index = spec.batch_index,
            .shift_amt = spec.shift_amt,
        };
        next_offsets[index] = member_offset;
        member_offset = member_end;
    }
    std.debug.assert(member_offset == total_members);

    for (active_column_indices, contribution_ranges) |column_idx, contribution_range| {
        if (!nonzero_columns[column_idx]) continue;
        const column = flat_columns[column_idx];
        const log_shift = lifting_log_size - column.log_size;
        const shift_amt: std.math.Log2Int(usize) = @intCast(log_shift + 1);
        if (shift_amt < min_shift_amt) continue;
        const contribution_end = contribution_range.start + contribution_range.len;
        for (contributions[contribution_range.start..contribution_end], contribution_range.start..) |contribution, contribution_index| {
            const group_index = compactGroupIndex(
                specs.items,
                contribution.batch_index,
                column.values.len,
                shift_amt,
            ) orelse {
                std.debug.assert(partial);
                continue;
            };
            const write_index = next_offsets[group_index];
            const group_end = (@intFromPtr(groups[group_index].members.ptr) - @intFromPtr(members.ptr)) / @sizeOf(CompactContributionMember) + groups[group_index].members.len;
            if (partial and write_index >= group_end) continue;
            members[write_index] = .{
                .values = column.values.ptr,
                .contribution_index = std.math.cast(u32, contribution_index) orelse return QuotientOpsError.ShapeMismatch,
            };
            next_offsets[group_index] = write_index + 1;
            if (partial) selected[contribution_index / 8] |= @as(u8, 1) << @as(u3, @intCast(contribution_index % 8));
        }
    }

    const minimum = if (partial and groups.len != 0) groups[groups.len - 1].shift_amt else min_shift_amt;
    return .{ .groups = groups, .members = members, .minimum_shift = minimum, .selected = selected };
}

pub fn materializeActiveLiftedColumns(
    allocator: std.mem.Allocator,
    flat_columns: []const ColumnEvaluation,
    active_column_indices: []const usize,
    lifting_log_size: u32,
) !MaterializedLiftedColumns {
    const domain_size = try column_geometry.checkedPow2(lifting_log_size);
    const total_cells = std.math.mul(usize, active_column_indices.len, domain_size) catch
        return QuotientOpsError.ShapeMismatch;
    const storage = try allocator.alloc(M31, total_cells);
    errdefer allocator.free(storage);
    const columns = try allocator.alloc([]M31, active_column_indices.len);
    errdefer allocator.free(columns);

    for (active_column_indices, 0..) |column_idx, active_idx| {
        if (column_idx >= flat_columns.len) return QuotientOpsError.ShapeMismatch;
        const column = flat_columns[column_idx];
        if (column.log_size > lifting_log_size) return QuotientOpsError.InvalidColumnLogSize;
        const dest = storage[active_idx * domain_size ..][0..domain_size];
        columns[active_idx] = dest;

        if (column.log_size == lifting_log_size) {
            @memcpy(dest, column.values);
            continue;
        }

        const log_shift = lifting_log_size - column.log_size;
        if (log_shift >= @bitSizeOf(usize)) return QuotientOpsError.InvalidColumnLogSize;
        const shift_amt: std.math.Log2Int(usize) = @intCast(log_shift + 1);
        for (0..domain_size) |position| {
            const idx = ((position >> shift_amt) << 1) + (position & 1);
            std.debug.assert(idx < column.values.len);
            dest[position] = column.values[idx];
        }
    }

    return .{
        .storage = storage,
        .columns = columns,
    };
}

fn validateSampleBatchColumnIndices(
    sample_batches: []const quotients.ColumnSampleBatch,
    queried_values_cols: usize,
) !void {
    for (sample_batches) |batch| {
        for (batch.cols_vals_randpows) |sample_data| {
            if (sample_data.column_index >= queried_values_cols) return error.ColumnIndexOutOfBounds;
        }
    }
}

test "compact contribution plan groups lifted geometry and fails back on budget" {
    const values_a = [_]M31{
        M31.fromCanonical(1), M31.fromCanonical(2),
        M31.fromCanonical(3), M31.fromCanonical(4),
    };
    const values_b = [_]M31{
        M31.fromCanonical(5), M31.fromCanonical(6),
        M31.fromCanonical(7), M31.fromCanonical(8),
    };
    const direct_values = [_]M31{M31.one()} ** 16;
    const columns = [_]ColumnEvaluation{
        .{ .log_size = 2, .values = &values_a },
        .{ .log_size = 2, .values = &values_b },
        .{ .log_size = 4, .values = &direct_values },
    };
    const active_indices = [_]usize{ 0, 1, 2 };
    const ranges = [_]ColumnContributionRange{
        .{ .start = 0, .len = 1 },
        .{ .start = 1, .len = 1 },
        .{ .start = 2, .len = 1 },
    };
    const contributions = [_]ColumnContribution{
        .{ .batch_index = 0, .value_coeff = QM31.fromU32Unchecked(1, 2, 3, 4) },
        .{ .batch_index = 0, .value_coeff = QM31.fromU32Unchecked(5, 6, 7, 8) },
        .{ .batch_index = 1, .value_coeff = QM31.one() },
    };
    const nonzero = [_]bool{ true, true, true };

    var admitted = (try buildCompactContributionPlan(
        std.testing.allocator,
        &columns,
        &active_indices,
        &ranges,
        &contributions,
        &nonzero,
        4,
        2,
        1024,
    )).?;
    defer admitted.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), admitted.groups.len);
    try std.testing.expectEqual(@as(usize, 2), admitted.groups[0].members.len);
    try std.testing.expectEqual(@as(usize, 0), admitted.groups[0].batch_index);
    try std.testing.expectEqual(@as(std.math.Log2Int(usize), 3), admitted.groups[0].shift_amt);
    try std.testing.expect(admitted.retainedBytes() <= 1024);

    try std.testing.expect((try buildCompactContributionPlan(
        std.testing.allocator,
        &columns,
        &active_indices,
        &ranges,
        &contributions,
        &nonzero,
        4,
        2,
        0,
    )) == null);
}

test "compact admission keeps high-reuse groups and partitions every contribution" {
    const a = std.testing.allocator;
    const small = [_]M31{M31.one()} ** 4;
    const medium = [_]M31{M31.one()} ** 8;
    const large = [_]M31{M31.one()} ** 16;
    const columns = [_]ColumnEvaluation{
        .{ .log_size = 2, .values = &small },
        .{ .log_size = 3, .values = &medium },
        .{ .log_size = 4, .values = &large },
    };
    const indices = [_]usize{ 0, 1, 2 };
    const ranges = [_]ColumnContributionRange{ .{ .start = 0, .len = 2 }, .{ .start = 2, .len = 1 }, .{ .start = 3, .len = 1 } };
    const terms = [_]ColumnContribution{
        .{ .batch_index = 0, .value_coeff = QM31.fromU32Unchecked(1, 2, 3, 4) },
        .{ .batch_index = 1, .value_coeff = QM31.fromU32Unchecked(5, 6, 7, 8) },
        .{ .batch_index = 0, .value_coeff = QM31.one() },
        .{ .batch_index = 1, .value_coeff = QM31.zero() },
    };
    const active = [_]bool{true} ** 3;
    const cap = 2 * (@sizeOf(CompactContributionGroup) + @sizeOf(CompactContributionMember));
    var grouped = (try buildCompactContributionPlan(a, &columns, &indices, &ranges, &terms, &active, 5, 2, cap)).?;
    defer grouped.deinit(a);
    try std.testing.expectEqual(@as(u6, 4), grouped.minimum_shift);
    try std.testing.expectEqual(cap, grouped.retainedBytes());
    var direct = try @import("../quotient_direct_plan.zig").build(a, &columns, &indices, &ranges, &active, 5, grouped.minimum_shift);
    defer direct.deinit(a);
    var seen = [_]u8{0} ** terms.len;
    for (grouped.groups) |group| for (group.members, 0..) |member_index, i| {
        seen[member_index.contribution_index] += 1;
        const value = group.member(i);
        try std.testing.expect(value.values.ptr == columns[0].values.ptr);
        try std.testing.expectEqualDeep(terms[member_index.contribution_index].value_coeff.toM31Array(), value.coefficients);
        try std.testing.expectEqual(terms[member_index.contribution_index].batch_index, group.batch_index);
    };
    for (direct.ranges) |range| for (seen[range.start..][0..range.len]) |*count| {
        count.* += 1;
    };
    try std.testing.expectEqualSlices(u8, &.{ 1, 1, 1, 1 }, &seen);
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(CompactContributionMember));
    try std.testing.expect((try buildCompactContributionPlan(a, &columns, &indices, &ranges, &terms, &active, 5, 2, cap - 1)) == null);
}

test "partial compact admission fills its cap and splits exact contribution runs" {
    const a = std.testing.allocator;
    const values = [_]M31{ M31.one(), M31.fromCanonical(7), M31.fromCanonical(9), M31.fromCanonical(11) };
    const columns = [_]ColumnEvaluation{.{ .log_size = 2, .values = &values }};
    const indices = [_]usize{0};
    const ranges = [_]ColumnContributionRange{.{ .start = 0, .len = 9 }};
    var terms: [9]ColumnContribution = undefined;
    for (&terms, 0..) |*term, i| term.* = .{ .batch_index = i % 2, .value_coeff = QM31.fromU32Unchecked(@intCast(i), 3, 5, 7) };
    const active = [_]bool{true};
    // Group0 takes five even indices; group1 takes only its first odd index.
    // The remainder is three separated direct runs in the same source column.
    const cap = 2 + 2 * @sizeOf(CompactContributionGroup) + 6 * @sizeOf(CompactContributionMember);
    var plan = (try buildPartialCompactContributionPlan(a, &columns, &indices, &ranges, &terms, &active, 7, 2, cap)).?;
    defer plan.deinit(a);
    try std.testing.expectEqual(cap, plan.retainedBytes());
    try std.testing.expectEqual(@as(usize, 6), plan.members.len);
    var direct = try @import("../quotient_direct_plan.zig").buildExcludingSelected(a, &columns, &indices, &ranges, &active, 7, plan.selected);
    defer direct.deinit(a);
    try std.testing.expectEqual(@as(usize, 3), direct.ranges.len);
    var seen = [_]u8{0} ** terms.len;
    for (plan.groups) |group| for (group.members, 0..) |member_index, i| {
        seen[member_index.contribution_index] += 1;
        try std.testing.expectEqualDeep(terms[member_index.contribution_index].value_coeff.toM31Array(), group.member(i).coefficients);
        try std.testing.expectEqual(terms[member_index.contribution_index].batch_index, group.batch_index);
    };
    for (direct.ranges) |range| for (seen[range.start..][0..range.len]) |*hit| {
        hit.* += 1;
    };
    for (seen) |hit| try std.testing.expectEqual(@as(u8, 1), hit);
    const malformed = [_]ColumnContributionRange{.{ .start = 1, .len = 8 }};
    try std.testing.expectError(error.ShapeMismatch, buildPartialCompactContributionPlan(a, &columns, &indices, &malformed, &terms, &active, 7, 2, cap));
    try std.testing.expectError(error.ShapeMismatch, @import("../quotient_direct_plan.zig").buildExcludingSelected(a, &columns, &indices, &ranges, &active, 7, &.{}));
    try std.testing.expect((try buildPartialCompactContributionPlan(a, &columns, &indices, &ranges, &terms, &active, 7, 2, 2 + @sizeOf(CompactContributionGroup) + @sizeOf(CompactContributionMember) - 1)) == null);
}

test "wide compact indexed roster survives the previous one MiB metadata cliff" {
    const a = std.testing.allocator;
    const count = 33_000;
    const values = [_]M31{ M31.one(), M31.fromCanonical(3), M31.fromCanonical(7), M31.fromCanonical(11) };
    const columns = try a.alloc(ColumnEvaluation, count);
    defer a.free(columns);
    const indices = try a.alloc(usize, count);
    defer a.free(indices);
    const ranges = try a.alloc(ColumnContributionRange, count);
    defer a.free(ranges);
    const terms = try a.alloc(ColumnContribution, count);
    defer a.free(terms);
    const active = try a.alloc(bool, count);
    defer a.free(active);
    for (columns, indices, ranges, terms, active, 0..) |*column, *index, *range, *term, *nonzero, i| {
        column.* = .{ .log_size = 2, .values = &values };
        index.* = i;
        range.* = .{ .start = i, .len = 1 };
        term.* = .{ .batch_index = i % 3, .value_coeff = QM31.fromU32Unchecked(@intCast(i), 2, 3, 4) };
        nonzero.* = true;
    }
    const cap = 1 << 20;
    try std.testing.expect(count * 32 > cap);
    var grouped = (try buildCompactContributionPlan(a, columns, indices, ranges, terms, active, 18, 2, cap)).?;
    defer grouped.deinit(a);
    try std.testing.expectEqual(@as(usize, count), grouped.members.len);
    try std.testing.expectEqual(@as(usize, 3), grouped.groups.len);
    try std.testing.expect(grouped.retainedBytes() < cap * 2 / 3);
    var expected: [3]QM31 = @splat(QM31.zero());
    var actual: [3]QM31 = @splat(QM31.zero());
    for (terms) |term| expected[term.batch_index] = expected[term.batch_index].add(term.value_coeff);
    for (grouped.groups) |group| for (group.members) |member_index| {
        try std.testing.expect(member_index.values == &values);
        actual[group.batch_index] = actual[group.batch_index].add(terms[member_index.contribution_index].value_coeff);
    };
    try std.testing.expectEqualDeep(expected, actual);
}
